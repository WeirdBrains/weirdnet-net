//! The libp2p node: TCP and QUIC (or an in-memory transport for tests) with Noise and
//! Yamux; mDNS on the local network; Kademlia, identify and ping; relay client and
//! (opt-in) relay server with DCUtR hole punching; AutoNAT; and request-response on
//! the profile's protocol id, carrying the application's own request and response types
//! (CBOR).
//!
//! The swarm runs on its own thread with a small Tokio runtime. [`Node`] is a blocking
//! handle (the CLI and TUI are synchronous): requests wait for their answer. Requests
//! that come in are answered by a [`Handler`] on Tokio's blocking pool.
use crate::addr::{addr_peer, circuit_relay, reach_rank, routable, shareable};
use crate::app::{AppError, AppHandler, AppRequest, AppResponse};
use crate::error::{NetError, Result};
use crate::events::{Event, Events, Hub, StatusWatch};
use crate::names::{Entry, Lookup, Names, NamesRequest, NamesResponse};
use crate::peers::{DiscoveryMode, PeerHint};
use crate::profile::Profile;
use crate::stream::transport::Control;
use crate::stream::{Incoming, Limits, Path, Stream};
use crate::wss::WssTls;
use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, MemoryTransport, Transport};
use libp2p::core::upgrade::Version;
use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore, store::RecordStore};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, autonat, dcutr, identify, mdns, noise, ping, relay, yamux};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Request-response defaults ([`NodeConfig::request_max`] and the rest, when left at zero).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
pub const REQUEST_MAX: u64 = 8 * 1024 * 1024;
pub const RESPONSE_MAX: u64 = 256 * 1024 * 1024;

/// How a node runs.
#[derive(Debug, Clone, Default)]
pub struct NodeConfig {
    /// Addresses to listen on (none: only dial out).
    pub listen: Vec<Multiaddr>,
    /// Find and announce peers on the local network (only when [`NodeConfig::discovery`] is
    /// enabled, and never on the in-memory transport).
    pub mdns: bool,
    /// Peer discovery (mDNS when [`NodeConfig::mdns`] is set, and Kademlia). Enabled by
    /// default. Disabled: no LAN announcements or DHT; configured relays, [`NodeConfig::peers`]
    /// and explicit dials (including serving apps and content) still work.
    pub discovery: DiscoveryMode,
    /// Peers to dial without discovering them (addresses plus a peer id). Adding a peer
    /// does not grant trust; certificates do. The application persists this list.
    pub peers: Vec<PeerHint>,
    /// Relay traffic for other nodes (and say so).
    pub relay_server: bool,
    /// Kademlia bootstrap nodes (`/ip4/…/tcp/…/p2p/…`).
    pub bootstrap: Vec<Multiaddr>,
    /// Relays to reserve a slot on (`/…/p2p/RELAY`); reachable through them behind NAT.
    pub relays: Vec<Multiaddr>,
    /// The in-memory transport (tests) instead of TCP and QUIC.
    pub memory: bool,
    /// This node's label (in identify; empty: none).
    pub label: String,
    /// Addresses others reach us at from outside (a DNS name or public IP forwarded to
    /// this node), announced and put in invites before the local ones.
    pub external: Vec<Multiaddr>,
    /// The application's version, in the identify agent (`NAME/VERSION`); empty: this
    /// crate's version.
    pub version: String,
    /// What the relay server (`relay_server`) allows; the default is libp2p's.
    pub relay_limits: RelayLimits,
    /// Serve the names protocol (rendezvous for signed peer records) from this store.
    pub names_server: Option<Names>,
    /// Names servers to register with and look users up on (`…/p2p/ID`), besides the
    /// relays this node holds a reservation on.
    pub names_servers: Vec<Multiaddr>,
    /// Largest request on the profile's request-response protocol (0: [`REQUEST_MAX`]).
    /// Bulk data belongs on a [stream](crate::stream) instead.
    pub request_max: u64,
    /// Largest response (0: [`RESPONSE_MAX`]).
    pub response_max: u64,
    /// How long a request waits for its response (zero: [`REQUEST_TIMEOUT`]).
    pub request_timeout: Duration,
    /// WebSocket over TLS: the certificate to listen with (put `/…/tcp/443/tls/ws` in
    /// `listen`) and extra roots to trust when dialing. Without it the node still dials WSS.
    pub wss: Option<WssTls>,
    /// DNS servers for `/dns` and `/dnsaddr` addresses (empty: the system's, or public
    /// resolvers where the system has none to read, as on Android).
    pub dns_servers: Vec<std::net::SocketAddr>,
    /// App calls: the cap on a request or response head, in bytes (0: 16 KiB).
    pub app_header_max: usize,
    /// App calls: the cap on one body, in bytes (0: none, the default).
    pub app_body_max: u64,
    /// App calls: how long a call may go without a byte either way (zero: 60 seconds).
    pub app_idle_timeout: Duration,
}

impl NodeConfig {
    fn req_max(&self) -> u64 {
        if self.request_max == 0 { REQUEST_MAX } else { self.request_max }
    }

    fn resp_max(&self) -> u64 {
        if self.response_max == 0 { RESPONSE_MAX } else { self.response_max }
    }

    fn req_timeout(&self) -> Duration {
        if self.request_timeout.is_zero() { REQUEST_TIMEOUT } else { self.request_timeout }
    }

    pub(crate) fn app_limits(&self) -> crate::app::AppLimits {
        crate::app::AppLimits {
            header_max: if self.app_header_max == 0 { crate::app::DEFAULT_HEADER_MAX } else { self.app_header_max },
            body_max: self.app_body_max,
            idle: if self.app_idle_timeout.is_zero() { crate::app::DEFAULT_IDLE_TIMEOUT } else { self.app_idle_timeout },
        }
    }
}

/// Limits of the relay server: how many reservations and circuits it holds, and how long
/// and how much one circuit may carry. [`RelayLimits::default`] keeps libp2p's defaults
/// (circuits for hole punching and small requests: 2 minutes, 128 KiB);
/// [`RelayLimits::unlimited`] caps nothing, so circuits carry data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Reservations held at once, and per peer.
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    /// How long a reservation lasts before the client renews it.
    pub reservation_duration: Duration,
    /// Circuits open at once, and per peer.
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    /// How long one circuit may stay open (at most `u32::MAX` seconds).
    pub max_circuit_duration: Duration,
    /// How many bytes one circuit may carry in each direction; 0: no limit.
    pub max_circuit_bytes: u64,
    /// libp2p's rate limiters on new reservations and circuits (per peer and per IP).
    pub rate_limits: bool,
}

impl Default for RelayLimits {
    /// libp2p's defaults.
    fn default() -> Self {
        let c = relay::Config::default();
        RelayLimits {
            max_reservations: c.max_reservations,
            max_reservations_per_peer: c.max_reservations_per_peer,
            reservation_duration: c.reservation_duration,
            max_circuits: c.max_circuits,
            max_circuits_per_peer: c.max_circuits_per_peer,
            max_circuit_duration: c.max_circuit_duration,
            max_circuit_bytes: c.max_circuit_bytes,
            rate_limits: true,
        }
    }
}

impl RelayLimits {
    /// Longest circuit duration libp2p accepts.
    pub const MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(u32::MAX as u64);

    /// No caps: as many reservations and circuits as clients ask for, no byte limit, the
    /// longest circuit libp2p accepts, and no rate limiters. Reservations still last an hour
    /// before the client renews them.
    pub fn unlimited() -> Self {
        RelayLimits {
            max_reservations: usize::MAX,
            max_reservations_per_peer: usize::MAX,
            max_circuits: usize::MAX,
            max_circuits_per_peer: usize::MAX,
            max_circuit_duration: Self::MAX_CIRCUIT_DURATION,
            max_circuit_bytes: 0,
            rate_limits: false,
            ..Self::default()
        }
    }

    /// Whether nothing is capped (see [`RelayLimits::unlimited`]).
    pub fn is_unlimited(&self) -> bool {
        *self == Self::unlimited()
    }

    /// Refuse limits libp2p cannot apply (a zero count or duration, or a circuit duration
    /// over `u32::MAX` seconds).
    pub fn check(&self) -> Result<()> {
        if self.max_reservations == 0 || self.max_reservations_per_peer == 0 || self.max_circuits == 0 || self.max_circuits_per_peer == 0 {
            return Err(NetError::invalid("relay limits", "reservation and circuit counts must be at least 1"));
        }
        if self.reservation_duration.is_zero() || self.max_circuit_duration.is_zero() {
            return Err(NetError::invalid("relay limits", "durations must be longer than zero"));
        }
        if self.max_circuit_duration > Self::MAX_CIRCUIT_DURATION {
            return Err(NetError::invalid("relay limits", "a circuit may last at most u32::MAX seconds"));
        }
        Ok(())
    }

    fn config(&self) -> relay::Config {
        let mut c = relay::Config {
            max_reservations: self.max_reservations,
            max_reservations_per_peer: self.max_reservations_per_peer,
            reservation_duration: self.reservation_duration,
            max_circuits: self.max_circuits,
            max_circuits_per_peer: self.max_circuits_per_peer,
            max_circuit_duration: self.max_circuit_duration,
            max_circuit_bytes: self.max_circuit_bytes,
            ..relay::Config::default()
        };
        if !self.rate_limits {
            c.reservation_rate_limiters.clear();
            c.circuit_src_rate_limiters.clear();
        }
        c
    }
}

impl NodeConfig {
    /// TCP and QUIC on every interface, IPv4 and IPv6, on `port`.
    pub fn default_listen(port: u16) -> Vec<Multiaddr> {
        [
            format!("/ip4/0.0.0.0/tcp/{port}"),
            format!("/ip4/0.0.0.0/udp/{port}/quic-v1"),
            format!("/ip6/::/tcp/{port}"),
            format!("/ip6/::/udp/{port}/quic-v1"),
        ]
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect()
    }
}

/// A peer seen by the node, for the handler to remember.
#[derive(Debug, Clone)]
pub struct Sighting {
    pub peer: PeerId,
    pub addrs: Vec<String>,
    pub caps: Option<Vec<String>>,
    pub agent: Option<String>,
    pub source: &'static str,
}

/// What a node carries: the application's request and response types (sent as CBOR).
pub trait Message: Serialize + DeserializeOwned + std::fmt::Debug + Clone + Send + 'static {}
impl<T: Serialize + DeserializeOwned + std::fmt::Debug + Clone + Send + 'static> Message for T {}

/// Answers requests from peers. The peer id is the one Noise authenticated.
pub trait Handler<Q, R>: Send + Sync + 'static {
    fn request(&self, from: &PeerId, req: Q) -> R;
    /// A peer was discovered or identified.
    fn seen(&self, _s: Sighting) {}
}

/// What the node is doing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub peer_id: String,
    pub listening: Vec<String>,
    pub external: Vec<String>,
    pub connected: Vec<String>,
    /// AutoNAT: `public`, `private` or `unknown`.
    pub nat: String,
    /// Relays holding a reservation for us.
    pub reservations: Vec<String>,
    pub relay_server: bool,
    pub mdns: bool,
    /// Whether peer discovery (mDNS, Kademlia) is on.
    #[serde(default)]
    pub discovery: bool,
    pub started_at: i64,
    /// Paused by the app ([`Node::pause`]).
    #[serde(default)]
    pub paused: bool,
}

// rustc 1.100 flags code the `NetworkBehaviour` derive generates (matches on
// uninhabited events) as unreachable; the allow has to sit on a module to reach it.
#[allow(unreachable_code)]
mod wire {
    use super::*;

    #[derive(NetworkBehaviour)]
    pub(super) struct Behaviour<Q: Message, R: Message> {
        pub(super) rr: request_response::cbor::Behaviour<Q, R>,
        pub(super) names: request_response::cbor::Behaviour<NamesRequest, NamesResponse>,
        pub(super) identify: identify::Behaviour,
        pub(super) ping: ping::Behaviour,
        pub(super) kad: kad::Behaviour<MemoryStore>,
        pub(super) mdns: Toggle<mdns::tokio::Behaviour>,
        pub(super) relay_client: relay::client::Behaviour,
        pub(super) relay_server: Toggle<relay::Behaviour>,
        pub(super) dcutr: dcutr::Behaviour,
        pub(super) autonat: autonat::Behaviour,
        pub(super) streams: crate::stream::transport::Behaviour,
    }
}
use wire::{Behaviour, BehaviourEvent};

enum Cmd<Q, R> {
    Request { peer: PeerId, addrs: Vec<Multiaddr>, wire: Q, reply: oneshot::Sender<Result<R>> },
    Names { peer: PeerId, addrs: Vec<Multiaddr>, req: NamesRequest, reply: oneshot::Sender<Result<NamesResponse>> },
    PutEntry { entry: Entry, reply: oneshot::Sender<Result<()>> },
    GetEntries { user: String, reply: oneshot::Sender<Result<Vec<Entry>>> },
    FindPeer { peer: PeerId, reply: oneshot::Sender<Result<Vec<Multiaddr>>> },
    KnownAddrs { reply: oneshot::Sender<Result<Vec<(PeerId, Multiaddr)>>> },
    PeerApps { peer: PeerId, reply: oneshot::Sender<Result<Option<Vec<String>>>> },
    Dial { addr: Multiaddr, reply: oneshot::Sender<Result<PeerId>> },
    Connect { peer: PeerId, addrs: Vec<Multiaddr>, reply: oneshot::Sender<Result<PeerId>> },
    DropPath { peer: PeerId, path: Path, reply: oneshot::Sender<Result<usize>> },
    Paths { peer: PeerId, reply: oneshot::Sender<Result<Vec<Path>>> },
    Pause { reply: oneshot::Sender<Result<()>> },
    Resume { reply: oneshot::Sender<Result<()>> },
    NetworkChanged { reply: oneshot::Sender<Result<()>> },
    Listen { addr: Multiaddr, reply: oneshot::Sender<Result<Multiaddr>> },
    AddRelay { addr: Multiaddr },
    AddPeer { hint: PeerHint, reply: oneshot::Sender<Result<()>> },
    RemovePeer { peer: PeerId, reply: oneshot::Sender<Result<()>> },
    ListPeers { reply: oneshot::Sender<Result<Vec<PeerHint>>> },
    Provide { key: Vec<u8>, reply: oneshot::Sender<Result<()>> },
    PutLocator { rec: crate::locator::LocatorRecord, reply: oneshot::Sender<Result<()>> },
    GetLocators { key: Vec<u8>, reply: oneshot::Sender<Result<Vec<crate::locator::LocatorRecord>>> },
    StopProviding { key: Vec<u8> },
    Providers { key: Vec<u8>, reply: oneshot::Sender<Result<Vec<PeerId>>> },
    Stop,
}

type Providing = (Vec<PeerId>, oneshot::Sender<Result<Vec<PeerId>>>);

/// A running node.
pub struct Node<Q: Message, R: Message> {
    peer_id: PeerId,
    profile: &'static Profile,
    names_list: Vec<Multiaddr>,
    tx: mpsc::UnboundedSender<Cmd<Q, R>>,
    status: Arc<Mutex<Status>>,
    request_timeout: Duration,
    streams: (tokio::runtime::Handle, Control),
    hub: Hub,
    status_rx: tokio::sync::watch::Receiver<Status>,
    thread: Option<std::thread::JoinHandle<()>>,
    apps: Arc<crate::app::Server>,
    app_limits: crate::app::AppLimits,
    /// Where peers found by [`Node::resolve_app`] are.
    app_addrs: Mutex<HashMap<PeerId, Vec<Multiaddr>>>,
    dns_servers: Vec<std::net::SocketAddr>,
}

fn net_err(e: impl std::fmt::Display) -> NetError {
    NetError::net(e)
}

fn stopped() -> NetError {
    NetError::Network("the node has stopped".into())
}

fn behaviour<Q: Message, R: Message>(
    p: &Profile,
    key: &Keypair,
    relay_client: relay::client::Behaviour,
    cfg: &NodeConfig,
) -> Result<Behaviour<Q, R>> {
    let peer = key.public().to_peer_id();
    let rr = request_response::cbor::Behaviour::with_codec(
        request_response::cbor::codec::Codec::default().set_request_size_maximum(cfg.req_max()).set_response_size_maximum(cfg.resp_max()),
        [(StreamProtocol::new(p.protocol), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(cfg.req_timeout()),
    );
    let version = if cfg.version.is_empty() { env!("CARGO_PKG_VERSION") } else { cfg.version.as_str() };
    let agent = p.agent(version, &cfg.label);
    // A relay with explicit external addresses announces only those, not every
    // interface it listens on (private VPC and loopback ones are useless to clients).
    let hide = cfg.relay_server && !cfg.external.is_empty();
    let identify =
        identify::Behaviour::new(identify::Config::new(p.identify.into(), key.public()).with_agent_version(agent).with_hide_listen_addrs(hide));
    let mut kcfg = kad::Config::new(StreamProtocol::new(p.kad));
    kcfg.set_query_timeout(Duration::from_secs(30));
    // every record and provider a peer puts is checked first (peer records, relay keys)
    kcfg.set_record_filtering(kad::StoreInserts::FilterBoth);
    let names = request_response::cbor::Behaviour::with_codec(
        request_response::cbor::codec::Codec::default().set_request_size_maximum(64 * 1024).set_response_size_maximum(64 * 1024),
        [(StreamProtocol::new(p.names), if cfg.names_server.is_some() { ProtocolSupport::Full } else { ProtocolSupport::Outbound })],
        request_response::Config::default().with_request_timeout(Duration::from_secs(20)),
    );
    let kad = kad::Behaviour::with_config(peer, MemoryStore::new(peer), kcfg);
    let mdns = if cfg.discovery.is_enabled() && cfg.mdns && !cfg.memory {
        Some(mdns::tokio::Behaviour::new(mdns::Config::default(), peer).map_err(net_err)?)
    } else {
        None
    };
    let relay_server = cfg.relay_server.then(|| relay::Behaviour::new(peer, cfg.relay_limits.config()));
    let autonat = autonat::Behaviour::new(peer, autonat::Config { only_global_ips: !cfg.memory, ..Default::default() });
    Ok(Behaviour {
        rr,
        names,
        identify,
        ping: ping::Behaviour::new(ping::Config::new()),
        kad,
        mdns: mdns.into(),
        relay_client,
        relay_server: relay_server.into(),
        dcutr: dcutr::Behaviour::new(peer),
        autonat,
        streams: crate::stream::transport::Behaviour::new(),
    })
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

fn memory_transport(key: &Keypair) -> std::result::Result<Boxed<(PeerId, StreamMuxerBox)>, BoxErr> {
    Ok(MemoryTransport::default()
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key).map_err(|e| Box::new(e) as BoxErr)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed())
}

fn build_swarm<Q: Message, R: Message>(p: &'static Profile, key: Keypair, cfg: &NodeConfig) -> Result<Swarm<Behaviour<Q, R>>> {
    let idle = |c: libp2p::swarm::Config| c.with_idle_connection_timeout(Duration::from_secs(120));
    let swarm = if cfg.memory {
        let cfg2 = cfg.clone();
        libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_other_transport(memory_transport)
            .map_err(net_err)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(net_err)?
            .with_behaviour(move |key, relay| behaviour(p, key, relay, &cfg2).map_err(|e| Box::new(e) as BoxErr))
            .map_err(net_err)?
            .with_swarm_config(idle)
            .build()
    } else {
        let cfg2 = cfg.clone();
        let wss_tls = cfg.wss.clone().unwrap_or_default();
        let dns = dns_config(&cfg.dns_servers);
        wss_tls.config()?;
        libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_other_transport(|key| crate::wss::transport(key, &wss_tls, dns))
            .map_err(net_err)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(net_err)?
            .with_behaviour(move |key, relay| behaviour(p, key, relay, &cfg2).map_err(|e| Box::new(e) as BoxErr))
            .map_err(net_err)?
            .with_swarm_config(idle)
            .build()
    };
    Ok(swarm)
}

impl<Q: Message, R: Message> Node<Q, R> {
    /// Start a node speaking `profile`; returns once its listeners are up (or failed).
    pub fn start(profile: &'static Profile, key: Keypair, cfg: NodeConfig, handler: Arc<dyn Handler<Q, R>>) -> Result<Self> {
        if cfg.relay_server {
            cfg.relay_limits.check()?;
        }
        let peer_id = key.public().to_peer_id();
        let status = Arc::new(Mutex::new(Status {
            peer_id: peer_id.to_string(),
            nat: "unknown".into(),
            relay_server: cfg.relay_server,
            mdns: cfg.discovery.is_enabled() && cfg.mdns && !cfg.memory,
            discovery: cfg.discovery.is_enabled(),
            started_at: crate::now_ms(),
            ..Default::default()
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let st = status.clone();
        let names_list = cfg.names_servers.clone();
        let request_timeout = cfg.req_timeout();
        let app_limits = cfg.app_limits();
        let dns_servers = cfg.dns_servers.clone();
        let serving = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let serving2 = serving.clone();
        let (streams_tx, streams_rx) = std::sync::mpsc::channel::<(tokio::runtime::Handle, Control)>();
        let hub = Hub::default();
        let (status_tx, status_rx) = tokio::sync::watch::channel(status.lock().map(|s| s.clone()).unwrap_or_default());
        let hub2 = hub.clone();
        let thread = std::thread::Builder::new()
            .name(profile.thread.into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .thread_name(format!("{}-rt", profile.thread))
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(net_err(e)));
                        return;
                    }
                };
                rt.block_on(async move {
                    let swarm = match build_swarm(profile, key, &cfg) {
                        Ok(mut s) => {
                            for a in &cfg.external {
                                s.add_external_address(a.clone());
                            }
                            let _ = streams_tx.send((tokio::runtime::Handle::current(), s.behaviour().streams.control()));
                            s
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let mut l = Loop::new(profile, swarm, cfg, handler, st);
                    l.hub = hub2;
                    l.serving = serving2;
                    l.status_tx = Some(status_tx);
                    l.run(rx, ready_tx).await;
                });
                rt.shutdown_timeout(Duration::from_secs(2));
            })
            .map_err(net_err)?;
        match ready_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(())) => {
                let streams = streams_rx.recv().map_err(|_| stopped())?;
                Ok(Node {
                    peer_id,
                    profile,
                    names_list,
                    tx,
                    status,
                    request_timeout,
                    streams,
                    hub,
                    status_rx,
                    thread: Some(thread),
                    apps: Arc::new(crate::app::Server::new(serving)),
                    app_limits,
                    app_addrs: Mutex::new(HashMap::new()),
                    dns_servers,
                })
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err(NetError::Network("the node did not start in time".into())),
        }
    }

    /// The identifier profile the node speaks.
    pub fn profile(&self) -> &'static Profile {
        self.profile
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn status(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Addresses others can use to reach this node (with `/p2p/ID`).
    pub fn reachable_addrs(&self) -> Vec<String> {
        let s = self.status();
        let mut v: Vec<String> = vec![];
        for a in s.external.iter().chain(s.listening.iter()) {
            // a circuit through a relay is only useful if the relay's own address is routable
            if let Ok(m) = a.parse::<Multiaddr>()
                && shareable(&m)
                && (!m.iter().any(|p| p == Protocol::P2pCircuit) || routable(&m))
            {
                let full = if addr_peer(&m).is_some() { m } else { m.with(Protocol::P2p(self.peer_id)) };
                let t = full.to_string();
                if !v.contains(&t) {
                    v.push(t);
                }
            }
        }
        v
    }

    fn call<T>(&self, make: impl FnOnce(oneshot::Sender<Result<T>>) -> Cmd<Q, R>, wait: Duration) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).map_err(|_| stopped())?;
        let deadline = std::time::Instant::now() + wait;
        let mut rx = rx;
        loop {
            match rx.try_recv() {
                Ok(r) => return r,
                Err(oneshot::error::TryRecvError::Closed) => return Err(stopped()),
                Err(oneshot::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() > deadline {
                        return Err(NetError::Network("timed out".into()));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    /// Send a request and wait for the answer. `addrs` are tried if not connected yet.
    pub fn request(&self, peer: PeerId, addrs: &[Multiaddr], wire: Q) -> Result<R> {
        let addrs = addrs.to_vec();
        self.call(|reply| Cmd::Request { peer, addrs, wire, reply }, self.request_timeout + Duration::from_secs(5))
    }

    /// Ask a names server (a relay, usually) something; `addrs` are tried if not connected.
    pub fn names_request(&self, server: PeerId, addrs: &[Multiaddr], req: NamesRequest) -> Result<NamesResponse> {
        let addrs = addrs.to_vec();
        self.call(|reply| Cmd::Names { peer: server, addrs, req, reply }, Duration::from_secs(30))
    }

    /// Register a record or withdrawal on a names server.
    pub fn register(&self, server: PeerId, addrs: &[Multiaddr], entry: Entry) -> Result<()> {
        match self.names_request(server, addrs, NamesRequest::Register(Box::new(entry)))? {
            NamesResponse::Registered => Ok(()),
            NamesResponse::Refused(why) => Err(NetError::Network(format!("the names server refused: {why}"))),
            NamesResponse::Found(_) => Err(NetError::Network("unexpected answer from the names server".into())),
        }
    }

    /// A user's entry on one names server.
    pub fn discover(&self, server: PeerId, addrs: &[Multiaddr], user: &str) -> Result<Option<Entry>> {
        match self.names_request(server, addrs, NamesRequest::Discover { user_id: user.into() })? {
            NamesResponse::Found(e) => Ok(e.map(|e| *e)),
            NamesResponse::Refused(why) => Err(NetError::Network(format!("the names server refused: {why}"))),
            NamesResponse::Registered => Err(NetError::Network("unexpected answer from the names server".into())),
        }
    }

    /// Put a record or withdrawal in the DHT (checked first, like every storing node does).
    /// Records belong in the DHT only while the device hosts something public or private.
    pub fn put_entry(&self, entry: Entry) -> Result<()> {
        self.call(|reply| Cmd::PutEntry { entry, reply }, Duration::from_secs(40))
    }

    /// Put a private site's locator record in the DHT (checked first, as storing nodes do).
    pub fn put_locator(&self, rec: crate::locator::LocatorRecord) -> Result<()> {
        self.call(|reply| Cmd::PutLocator { rec, reply }, Duration::from_secs(40))
    }

    /// The locator records the DHT holds for `locator` today and yesterday (checked but not
    /// opened; see [`LocatorKeys::open`](crate::locator::LocatorKeys::open)).
    pub fn get_locators(&self, locator: &crate::PublicKey) -> Result<Vec<crate::locator::LocatorRecord>> {
        let mut out = vec![];
        for key in crate::locator::lookup_keys(locator, crate::now_ms()) {
            out.extend(self.call(|reply| Cmd::GetLocators { key, reply }, Duration::from_secs(40))?);
        }
        Ok(out)
    }

    /// Every entry the DHT returns for a user (unchecked; see [`Profile::newest`]).
    pub fn get_entries(&self, user: &str) -> Result<Vec<Entry>> {
        let user = user.to_string();
        self.call(|reply| Cmd::GetEntries { user, reply }, Duration::from_secs(40))
    }

    /// Where a peer is, by its key alone: what the DHT knows of it.
    pub fn find_peer(&self, peer: PeerId) -> Result<Vec<Multiaddr>> {
        self.call(|reply| Cmd::FindPeer { peer, reply }, Duration::from_secs(40))
    }

    /// Announce in the DHT that this node provides `key` (see
    /// [`content::provider_key`](crate::content::provider_key)); kept and re-announced until
    /// [`stop_providing`](Self::stop_providing) or the node stops.
    pub fn provide(&self, key: &[u8]) -> Result<()> {
        let key = key.to_vec();
        self.call(|reply| Cmd::Provide { key, reply }, Duration::from_secs(5))
    }

    pub fn stop_providing(&self, key: &[u8]) -> Result<()> {
        self.tx.send(Cmd::StopProviding { key: key.to_vec() }).map_err(|_| stopped())
    }

    /// The peers the DHT knows to provide `key` (this node excluded).
    pub fn providers(&self, key: &[u8]) -> Result<Vec<PeerId>> {
        let key = key.to_vec();
        self.call(|reply| Cmd::Providers { key, reply }, Duration::from_secs(40))
    }

    /// Names servers to ask: the configured ones and the relays holding our reservation.
    fn names_servers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        let known = self.call(|reply| Cmd::KnownAddrs { reply }, Duration::from_secs(5)).unwrap_or_default();
        let mut out: Vec<(PeerId, Vec<Multiaddr>)> = vec![];
        let reserved: Vec<PeerId> = self.status().reservations.iter().filter_map(|r| r.parse().ok()).collect();
        for (p, a) in known.into_iter() {
            if reserved.contains(&p) || self.names_list.iter().any(|n| addr_peer(n) == Some(p)) {
                match out.iter_mut().find(|(q, _)| *q == p) {
                    Some((_, v)) => v.push(a),
                    None => out.push((p, vec![a])),
                }
            }
        }
        for n in &self.names_list {
            if let Some(p) = addr_peer(n)
                && !out.iter().any(|(q, _)| *q == p)
            {
                out.push((p, vec![n.clone()]));
            }
        }
        out
    }

    /// Register an entry with every names server this node uses (its relays and the
    /// configured ones); returns how many took it.
    pub fn register_everywhere(&self, entry: &Entry) -> usize {
        self.names_servers().into_iter().filter(|(p, a)| self.register(*p, a, entry.clone()).is_ok()).count()
    }

    /// Find a user's freshest valid record: on this node's names servers, then in the DHT.
    pub fn lookup(&self, user: &str) -> Lookup {
        let mut found: Vec<Entry> = vec![];
        for (p, a) in self.names_servers() {
            if let Ok(Some(e)) = self.discover(p, &a, user) {
                found.push(e);
            }
        }
        if let Ok(v) = self.get_entries(user) {
            found.extend(v);
        }
        self.profile.newest(user, &found, crate::now_ms())
    }

    /// Send a request to a peer known only by its key: when not connected, find its
    /// addresses in the DHT and try circuits through this node's relays and names servers.
    pub fn request_key(&self, peer: PeerId, wire: Q) -> Result<R> {
        if self.status().connected.contains(&peer.to_string()) {
            return self.request(peer, &[], wire);
        }
        let mut addrs = self.find_peer(peer).unwrap_or_default();
        for (_, a) in self.names_servers() {
            for base in a {
                let base: Multiaddr = base.iter().take_while(|p| *p != Protocol::P2pCircuit).collect();
                addrs.push(base.with(Protocol::P2pCircuit).with(Protocol::P2p(peer)));
            }
        }
        self.request(peer, &addrs, wire)
    }

    /// Send a request to a user's node: look up its record and dial its addresses
    /// (circuits and direct ones together). Returns the node that answered.
    pub fn request_user(&self, user: &str, wire: Q) -> Result<(PeerId, R)> {
        match self.lookup(user) {
            Lookup::Found(r) => {
                let peer: PeerId = r.cert.peer_id.parse().map_err(|_| NetError::invalid("peer record", "bad peer id"))?;
                let addrs = crate::addr::parse_addrs(&r.addrs);
                Ok((peer, self.request(peer, &addrs, wire)?))
            }
            Lookup::Withdrawn(_) => Err(NetError::Network(format!("{user} withdrew its record"))),
            Lookup::NotFound => Err(NetError::Network(format!("no record for {user}"))),
        }
    }

    /// Connect to an address; returns the peer there.
    pub fn dial(&self, addr: Multiaddr) -> Result<PeerId> {
        self.call(|reply| Cmd::Dial { addr, reply }, Duration::from_secs(30))
    }

    /// Connect to `peer` if not connected yet, trying `addrs` (or the addresses the node knows).
    pub fn connect(&self, peer: PeerId, addrs: &[Multiaddr]) -> Result<()> {
        let addrs = addrs.to_vec();
        self.call(|reply| Cmd::Connect { peer, addrs, reply }, Duration::from_secs(30)).map(|_| ())
    }

    /// Remember `hint` and dial it. This does not certify the peer.
    pub fn add_peer(&self, hint: PeerHint) -> Result<()> {
        self.call(|reply| Cmd::AddPeer { hint, reply }, Duration::from_secs(30))
    }

    /// Forget a manual peer (open connections stay until dropped).
    pub fn remove_peer(&self, peer: PeerId) -> Result<()> {
        self.call(|reply| Cmd::RemovePeer { peer, reply }, Duration::from_secs(5))
    }

    /// The manual peer list (from config and [`Node::add_peer`]).
    pub fn peers(&self) -> Result<Vec<PeerHint>> {
        self.call(|reply| Cmd::ListPeers { reply }, Duration::from_secs(5))
    }

    /// Close this node's direct or relayed connections to `peer`; returns how many. Streams on
    /// them move to another path (or wait for one to come back).
    pub fn drop_path(&self, peer: PeerId, path: Path) -> Result<usize> {
        self.call(|reply| Cmd::DropPath { peer, path, reply }, Duration::from_secs(5))
    }

    /// Events from now on (connections, listeners, reservations, NAT, lifecycle).
    pub fn events(&self) -> Events {
        self.hub.subscribe()
    }

    /// The status, and a way to wait for it to change.
    pub fn watch_status(&self) -> StatusWatch {
        StatusWatch { rx: self.status_rx.clone() }
    }

    /// The app goes to the background: close every connection and listener and give up relay
    /// reservations. Requests and streams opened while paused still dial out.
    pub fn pause(&self) -> Result<()> {
        self.call(|reply| Cmd::Pause { reply }, Duration::from_secs(5))
    }

    /// Back in the foreground: listen again, reserve on the relays again, rejoin the DHT.
    pub fn resume(&self) -> Result<()> {
        self.call(|reply| Cmd::Resume { reply }, Duration::from_secs(5))
    }

    /// The device moved to another network (Wi-Fi to cellular, a new address): drop the
    /// connections made on the old one and make them again. Streams carry on once a path is back.
    pub fn network_changed(&self) -> Result<()> {
        self.call(|reply| Cmd::NetworkChanged { reply }, Duration::from_secs(5))
    }

    /// [`Node::request`] for async callers (any executor).
    pub async fn request_async(&self, peer: PeerId, addrs: &[Multiaddr], wire: Q) -> Result<R> {
        let addrs = addrs.to_vec();
        self.call_async(|reply| Cmd::Request { peer, addrs, wire, reply }, self.request_timeout + Duration::from_secs(5)).await
    }

    /// [`Node::connect`] for async callers.
    pub async fn connect_async(&self, peer: PeerId, addrs: &[Multiaddr]) -> Result<()> {
        let addrs = addrs.to_vec();
        self.call_async(|reply| Cmd::Connect { peer, addrs, reply }, Duration::from_secs(30)).await.map(|_| ())
    }

    /// [`Node::dial`] for async callers.
    pub async fn dial_async(&self, addr: Multiaddr) -> Result<PeerId> {
        self.call_async(|reply| Cmd::Dial { addr, reply }, Duration::from_secs(30)).await
    }

    async fn call_async<T: Send + 'static>(&self, make: impl FnOnce(oneshot::Sender<Result<T>>) -> Cmd<Q, R>, wait: Duration) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).map_err(|_| stopped())?;
        let rt = self.streams.0.clone();
        rt.spawn(async move { tokio::time::timeout(wait, rx).await })
            .await
            .map_err(|_| stopped())?
            .map_err(|_| NetError::Network("timed out".into()))?
            .map_err(|_| stopped())?
    }

    /// The connections to `peer` now, by kind (one entry per connection).
    pub fn paths(&self, peer: PeerId) -> Result<Vec<Path>> {
        self.call(|reply| Cmd::Paths { peer, reply }, Duration::from_secs(5))
    }

    /// Accept streams of `protocol` (an id of the application's, such as `/myapp/sync/1`).
    /// Other peers' streams of protocols nobody accepts are refused.
    pub fn accept_streams(&self, protocol: &str, limits: Limits) -> Result<Incoming> {
        let p = StreamProtocol::try_from_owned(protocol.to_string()).map_err(|e| NetError::Network(format!("bad protocol id {protocol}: {e}")))?;
        let (rt, control) = &self.streams;
        crate::stream::accept(control.clone(), p, limits, rt)
    }

    /// Open a stream of `protocol` to `peer` (connecting through `addrs` if needed). It starts
    /// on a direct connection when there is one and moves there later if one comes up.
    pub fn open_stream(&self, peer: PeerId, addrs: &[Multiaddr], protocol: &str, limits: Limits) -> Result<Stream> {
        futures::executor::block_on(self.open_stream_async(peer, addrs, protocol, limits))
    }

    /// Forwarded HTTPS connections for this node's sites ([`crate::ingress`]).
    pub fn accept_ingress(&self) -> Result<crate::ingress::IngressIncoming> {
        Ok(crate::ingress::IngressIncoming { inc: self.accept_streams(crate::ingress::INGRESS_PROTOCOL, Limits::default())? })
    }

    /// Register this node's sites with an ingress peer: `reg` carries the user's grants for
    /// that ingress, the user's certificate for this node and where the ingress reaches it.
    pub fn register_ingress(&self, ingress: PeerId, addrs: &[Multiaddr], reg: &crate::ingress::Registration) -> Result<crate::ingress::Registered> {
        use futures::AsyncWriteExt;
        let body = serde_json::to_vec(reg).map_err(|e| NetError::invalid("registration", e.to_string()))?;
        let mut s = self.open_stream(ingress, addrs, crate::ingress::GRANT_PROTOCOL, Limits::default())?;
        let rt = self.streams.0.clone();
        rt.block_on(async move {
            crate::ingress::write_msg(&mut s, &body).await.map_err(NetError::net)?;
            let _ = s.close().await;
            let b = tokio::time::timeout(Duration::from_secs(60), crate::ingress::read_msg(&mut s, crate::ingress::MAX_REGISTRATION))
                .await
                .map_err(|_| NetError::Network("no answer from the ingress".into()))?
                .map_err(NetError::net)?;
            serde_json::from_slice(&b).map_err(|e| NetError::invalid("registration answer", e.to_string()))
        })
    }

    pub(crate) fn runtime(&self) -> tokio::runtime::Handle {
        self.streams.0.clone()
    }

    pub(crate) fn opener(&self, protocol: &str, limits: Limits) -> Opener {
        let tx = self.tx.clone();
        let control = self.streams.1.clone();
        let p = StreamProtocol::try_from_owned(protocol.to_string()).expect("a valid protocol id");
        Arc::new(move |peer, addrs| {
            let (tx, control, p) = (tx.clone(), control.clone(), p.clone());
            Box::pin(async move {
                let (rtx, rrx) = oneshot::channel();
                tx.send(Cmd::<Q, R>::Connect { peer, addrs, reply: rtx }).map_err(|_| stopped())?;
                tokio::time::timeout(Duration::from_secs(30), rrx)
                    .await
                    .map_err(|_| NetError::Network(format!("cannot reach {peer} in time")))?
                    .map_err(|_| stopped())??;
                crate::stream::open(control, peer, p, limits).await
            })
        })
    }

    /// [`Node::open_stream`] for async callers (any executor).
    pub async fn open_stream_async(&self, peer: PeerId, addrs: &[Multiaddr], protocol: &str, limits: Limits) -> Result<Stream> {
        let p = StreamProtocol::try_from_owned(protocol.to_string()).map_err(|e| NetError::Network(format!("bad protocol id {protocol}: {e}")))?;
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Connect { peer, addrs: addrs.to_vec(), reply: tx }).map_err(|_| stopped())?;
        let (rt, control) = &self.streams;
        let control = control.clone();
        rt.spawn(async move {
            tokio::time::timeout(Duration::from_secs(30), rx)
                .await
                .map_err(|_| NetError::Network(format!("cannot reach {peer} in time")))?
                .map_err(|_| stopped())??;
            crate::stream::open(control, peer, p, limits).await
        })
        .await
        .map_err(|_| stopped())?
    }

    /// Serve app calls for `app` (`a-z`, `0-9`, `-`; up to 64 characters): calls to it go to
    /// `handler`, and peers learn (through identify) that this node serves it. Serving
    /// again replaces the handler. While a node serves any app it keeps its relay
    /// reservations, even paused.
    pub fn serve_app(&self, app: &str, handler: Arc<dyn AppHandler>) -> std::result::Result<(), AppError> {
        let (rt, control) = &self.streams;
        self.apps.serve(rt, control, app, handler, self.app_limits)
    }

    /// Stop serving `app`; returns whether it was served. Calls under way carry on.
    pub fn stop_serving_app(&self, app: &str) -> bool {
        self.apps.unserve(app)
    }

    /// The apps this node serves.
    pub fn served_apps(&self) -> Vec<String> {
        self.apps.apps()
    }

    /// The apps a connected peer announced (`None`: not connected, or not identified yet).
    pub fn peer_apps(&self, peer: PeerId) -> Option<Vec<String>> {
        self.call(|reply| Cmd::PeerApps { peer, reply }, Duration::from_secs(5)).ok().flatten()
    }

    /// The peers that serve `app` for `locator`: a peer id, a user id (32 hex digits) or a
    /// name bound to a user by a `_weirdnet.<name>` TXT record. Users are found through the
    /// names servers (relays this node holds a reservation on, and the configured ones) and
    /// the DHT. Connects to each peer (directly first, then through the relay circuits in its
    /// record) to learn what it serves; the addresses are kept for [`Node::app_call`].
    pub fn resolve_app(&self, app: &str, locator: &str) -> std::result::Result<Vec<(PeerId, Vec<Multiaddr>)>, AppError> {
        crate::app::Server::check_app(app)?;
        let locator = locator.trim();
        let mut found: Vec<(PeerId, Vec<Multiaddr>)> = vec![];
        if let Ok(peer) = locator.parse::<PeerId>() {
            let mut addrs = self.find_peer(peer).unwrap_or_default();
            for (_, a) in self.names_servers() {
                for base in a {
                    let base: Multiaddr = base.iter().take_while(|p| *p != Protocol::P2pCircuit).collect();
                    addrs.push(base.with(Protocol::P2pCircuit).with(Protocol::P2p(peer)));
                }
            }
            found.push((peer, addrs));
        } else {
            let user = if is_user_id(locator) { locator.to_string() } else { self.resolve_name(locator)? };
            match self.lookup(&user) {
                Lookup::Found(rec) => {
                    let peer: PeerId = rec.cert.peer_id.parse().map_err(|_| AppError::Protocol("a record with a bad peer id".into()))?;
                    let mut addrs: Vec<Multiaddr> = rec.addrs.iter().filter_map(|a| a.parse().ok()).collect();
                    if let Some(home) = rec.home_relay.as_deref().and_then(|a| a.parse::<Multiaddr>().ok()) {
                        let c = home.with(Protocol::P2pCircuit).with(Protocol::P2p(peer));
                        if !addrs.contains(&c) {
                            addrs.push(c);
                        }
                    }
                    found.push((peer, addrs));
                }
                Lookup::Withdrawn(_) | Lookup::NotFound => return Err(AppError::NotFound),
            }
        }
        let mut out = vec![];
        let mut reached = false;
        let mut last = AppError::NotFound;
        for (peer, addrs) in found {
            if peer == self.peer_id {
                if self.apps.serves(app) {
                    out.push((peer, vec![]));
                } else {
                    last = AppError::NoHandler;
                }
                continue;
            }
            let wait = self.request_timeout;
            let rt = self.streams.0.clone();
            let tx = self.tx.clone();
            let a2 = addrs.clone();
            let r = futures::executor::block_on(rt.spawn(async move { connect_phased(tx, peer, a2, tokio::time::Instant::now() + wait).await }));
            match r.unwrap_or_else(|_| Err(AppError::Unreachable("the node stopped".into()))) {
                Ok(()) => reached = true,
                Err(e) => {
                    last = e;
                    continue;
                }
            }
            // identify comes right after connecting
            let until = std::time::Instant::now() + Duration::from_secs(5);
            let apps = loop {
                if let Some(a) = self.peer_apps(peer) {
                    break a;
                }
                if std::time::Instant::now() > until {
                    break vec![];
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            self.app_addrs.lock().unwrap().insert(peer, addrs.clone());
            if apps.iter().any(|a| a == app) {
                out.push((peer, addrs));
            } else {
                last = AppError::NoHandler;
            }
        }
        if out.is_empty() {
            return Err(if reached { AppError::NoHandler } else { last });
        }
        Ok(out)
    }

    /// The user a name is bound to (`_weirdnet.<name>` TXT, through the node's DNS servers).
    fn resolve_name(&self, name: &str) -> std::result::Result<String, AppError> {
        let servers = self.dns_servers.clone();
        let q = crate::names::binding_name(name);
        let rt = self.streams.0.clone();
        futures::executor::block_on(rt.spawn(async move { txt_records(&servers, &q).await }))
            .map_err(|_| AppError::Unreachable("the node stopped".into()))??
            .iter()
            .find_map(|t| crate::names::parse_binding(t).ok())
            .ok_or(AppError::NotFound)
    }

    /// Call `app` on `peer`: connect if needed (directly first, then through the relay
    /// circuits [`Node::resolve_app`] found), open a stream and send `req`. `timeout` covers
    /// getting the response head; the bodies then may go on as long as bytes keep flowing
    /// (see [`NodeConfig::app_idle_timeout`]). Dropping the future or the response body
    /// cancels the call. Works on any executor.
    pub async fn app_call(&self, peer: PeerId, req: AppRequest, timeout: Duration) -> std::result::Result<AppResponse, AppError> {
        let addrs = self.app_addrs.lock().unwrap().get(&peer).cloned().unwrap_or_default();
        self.app_call_via(peer, &addrs, req, timeout).await
    }

    /// [`Node::app_call`] trying `addrs` (direct addresses and circuits) to reach the peer.
    pub async fn app_call_via(
        &self,
        peer: PeerId,
        addrs: &[Multiaddr],
        req: AppRequest,
        timeout: Duration,
    ) -> std::result::Result<AppResponse, AppError> {
        if peer == self.peer_id {
            return Err(AppError::Unreachable("this node".into()));
        }
        let (rt, control) = &self.streams;
        let (rt, control, tx, limits, addrs) = (rt.clone(), control.clone(), self.tx.clone(), self.app_limits, addrs.to_vec());
        let rt2 = rt.clone();
        let task = rt.spawn(async move {
            let deadline = tokio::time::Instant::now() + timeout;
            connect_phased(tx, peer, addrs, deadline).await?;
            crate::app::call(rt2, control, peer, req, limits, deadline).await
        });
        let _guard = crate::app::AbortOnDrop(task.abort_handle());
        task.await.map_err(|_| AppError::Unreachable("the node stopped".into()))?
    }

    /// [`Node::app_call`] for blocking callers.
    pub fn app_call_blocking(&self, peer: PeerId, req: AppRequest, timeout: Duration) -> std::result::Result<AppResponse, AppError> {
        futures::executor::block_on(self.app_call(peer, req, timeout))
    }

    /// Listen on one more address; returns the address it got.
    pub fn listen(&self, addr: Multiaddr) -> Result<Multiaddr> {
        self.call(|reply| Cmd::Listen { addr, reply }, Duration::from_secs(20))
    }

    /// Reserve a slot on a relay (`…/p2p/RELAY`).
    pub fn add_relay(&self, addr: Multiaddr) -> Result<()> {
        self.tx.send(Cmd::AddRelay { addr }).map_err(|_| stopped())
    }

    /// Whether the node thread still runs.
    pub fn running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Ask the node to stop without waiting (others may still hold it).
    pub fn halt(&self) {
        let _ = self.tx.send(Cmd::Stop);
    }

    fn shutdown(&mut self) {
        let _ = self.tx.send(Cmd::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl<Q: Message, R: Message> Drop for Node<Q, R> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The resolver: the given servers, else the system's, else Cloudflare's and Google's.
/// A user id: 32 lowercase hex digits.
fn is_user_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The TXT records of `name` (none if it has none).
async fn txt_records(servers: &[std::net::SocketAddr], name: &str) -> std::result::Result<Vec<String>, AppError> {
    use hickory_resolver::proto::rr::{RData, RecordType};
    let (config, opts) = dns_config(servers);
    let r = hickory_resolver::Resolver::builder_with_config(config, hickory_resolver::net::runtime::TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| AppError::Unreachable(format!("dns: {e}")))?;
    let l = match r.lookup(name, RecordType::TXT).await {
        Ok(l) => l,
        Err(e) if e.is_no_records_found() || e.is_nx_domain() => return Ok(vec![]),
        Err(e) => return Err(AppError::Unreachable(format!("dns: {e}"))),
    };
    Ok(l.answers()
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::TXT(t) => Some(t.txt_data.iter().map(|b| String::from_utf8_lossy(b)).collect::<String>()),
            _ => None,
        })
        .collect())
}

/// Connect to `peer` by `addrs`: the direct ones first (a few seconds when circuits are
/// left), then the relay circuits (the relay is dialed on all its addresses).
async fn connect_phased<Q: Message, R: Message>(
    tx: mpsc::UnboundedSender<Cmd<Q, R>>,
    peer: PeerId,
    addrs: Vec<Multiaddr>,
    deadline: tokio::time::Instant,
) -> std::result::Result<(), AppError> {
    let (circuits, direct): (Vec<Multiaddr>, Vec<Multiaddr>) = addrs.into_iter().partition(|a| a.iter().any(|p| p == Protocol::P2pCircuit));
    let connect = |addrs: Vec<Multiaddr>, until: tokio::time::Instant| {
        let tx = tx.clone();
        async move {
            let (rtx, rrx) = oneshot::channel();
            tx.send(Cmd::Connect { peer, addrs, reply: rtx }).map_err(|_| AppError::Unreachable("the node stopped".into()))?;
            match tokio::time::timeout_at(until, rrx).await {
                Err(_) => Err(AppError::TimedOut),
                Ok(Err(_)) => Err(AppError::Unreachable("the node stopped".into())),
                Ok(Ok(Err(e))) => Err(AppError::Unreachable(e.to_string())),
                Ok(Ok(Ok(_))) => Ok(()),
            }
        }
    };
    if circuits.is_empty() {
        return connect(direct, deadline).await;
    }
    let first = (tokio::time::Instant::now() + DIRECT_FIRST).min(deadline);
    let direct_err = match connect(direct, first).await {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(direct_err);
    }
    connect(circuits, deadline).await
}

/// How long app calls try a peer's direct addresses before its relay circuits.
const DIRECT_FIRST: Duration = Duration::from_secs(4);

fn dns_config(servers: &[std::net::SocketAddr]) -> (libp2p::dns::ResolverConfig, libp2p::dns::ResolverOpts) {
    use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, ResolverConfig};
    if !servers.is_empty() {
        let ns = servers
            .iter()
            .map(|a| {
                let mut n = NameServerConfig::udp_and_tcp(a.ip());
                for c in &mut n.connections {
                    c.port = a.port();
                }
                n
            })
            .collect();
        return (ResolverConfig::from_name_servers(ns), Default::default());
    }
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((c, o)) if !c.name_servers().is_empty() => (c, o),
        _ => {
            let ns = CLOUDFLARE.udp_and_tcp().chain(GOOGLE.udp_and_tcp()).collect();
            (ResolverConfig::from_name_servers(ns), Default::default())
        }
    }
}

/// Opens a stream of one protocol to a peer, connecting first (held by services like the ingress).
pub(crate) type Opener = Arc<dyn Fn(PeerId, Vec<Multiaddr>) -> futures::future::BoxFuture<'static, Result<Stream>> + Send + Sync>;

/// A DHT lookup collecting entries, and who waits for them.
type Locating = (Vec<crate::locator::LocatorRecord>, oneshot::Sender<Result<Vec<crate::locator::LocatorRecord>>>);
type Gathering = (Vec<Entry>, oneshot::Sender<Result<Vec<Entry>>>);
/// A DHT search for one peer's addresses.
type Finding = (PeerId, oneshot::Sender<Result<Vec<Multiaddr>>>);

struct Loop<Q: Message, R: Message> {
    profile: &'static Profile,
    swarm: Swarm<Behaviour<Q, R>>,
    cfg: NodeConfig,
    handler: Arc<dyn Handler<Q, R>>,
    status: Arc<Mutex<Status>>,
    pending: HashMap<OutboundRequestId, oneshot::Sender<Result<R>>>,
    dials: Vec<(Multiaddr, Option<PeerId>, oneshot::Sender<Result<PeerId>>)>,
    listens: HashMap<libp2p::core::transport::ListenerId, oneshot::Sender<Result<Multiaddr>>>,
    relays: HashSet<PeerId>,
    relay_listening: HashSet<PeerId>,
    /// Each relay's circuit listener and when it was asked for (to retry a stuck one).
    relay_listeners: HashMap<PeerId, (Multiaddr, libp2p::core::transport::ListenerId, std::time::Instant)>,
    resp_tx: mpsc::UnboundedSender<(request_response::ResponseChannel<R>, R)>,
    resp_rx: mpsc::UnboundedReceiver<(request_response::ResponseChannel<R>, R)>,
    names_pending: HashMap<OutboundRequestId, oneshot::Sender<Result<NamesResponse>>>,
    names_tx: mpsc::UnboundedSender<(request_response::ResponseChannel<NamesResponse>, NamesResponse)>,
    names_rx: mpsc::UnboundedReceiver<(request_response::ResponseChannel<NamesResponse>, NamesResponse)>,
    puts: HashMap<kad::QueryId, oneshot::Sender<Result<()>>>,
    gets: HashMap<kad::QueryId, Gathering>,
    finds: HashMap<kad::QueryId, Finding>,
    provs: HashMap<kad::QueryId, Providing>,
    lgets: HashMap<kad::QueryId, Locating>,
    addr_book: HashMap<PeerId, Vec<Multiaddr>>,
    /// What connected peers say they listen on (identify), for provider records without addresses.
    heard: HashMap<PeerId, Vec<Multiaddr>>,
    /// Commands that go through a relay we are still connecting to (a bootstrap dial to the
    /// same relay under way makes libp2p's relay transport skip its own dial and fail).
    deferred: Vec<(PeerId, std::time::Instant, Cmd<Q, R>)>,
    /// Open connections: whose, and whether through a relay.
    conns: HashMap<libp2p::swarm::ConnectionId, (PeerId, bool)>,
    hub: Hub,
    status_tx: Option<tokio::sync::watch::Sender<Status>>,
    /// Listeners up now (paused nodes close them).
    listeners: HashSet<libp2p::core::transport::ListenerId>,
    paused: bool,
    /// Relays whose reservation went away, and when to ask again.
    relay_retry: Vec<(Multiaddr, std::time::Instant, Duration)>,
    /// How long to wait before asking a relay again; reset when it accepts.
    relay_backoff: HashMap<PeerId, Duration>,
    /// Every address of each relay (all dialed at once).
    relay_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    /// Relays being dialed; reserve once connected.
    relay_pending: HashSet<PeerId>,
    /// The node serves apps: keep relay reservations, even paused.
    serving: Arc<std::sync::atomic::AtomicBool>,
    /// The apps each connected peer announces (identify).
    peer_apps: HashMap<PeerId, Vec<String>>,
}

fn path_of(relayed: bool) -> Path {
    if relayed { Path::Relayed } else { Path::Direct }
}

fn endpoint_relayed(e: &libp2p::core::ConnectedPoint) -> bool {
    let circuit = |a: &Multiaddr| a.iter().any(|p| p == Protocol::P2pCircuit);
    match e {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => circuit(address),
        libp2p::core::ConnectedPoint::Listener { local_addr, send_back_addr } => circuit(local_addr) || circuit(send_back_addr),
    }
}

/// How long a command waits for its relay connection before it is tried anyway.
const RELAY_WAIT: Duration = Duration::from_secs(10);

impl<Q: Message, R: Message> Loop<Q, R> {
    fn new(
        profile: &'static Profile,
        swarm: Swarm<Behaviour<Q, R>>,
        cfg: NodeConfig,
        handler: Arc<dyn Handler<Q, R>>,
        status: Arc<Mutex<Status>>,
    ) -> Self {
        let (resp_tx, resp_rx) = mpsc::unbounded_channel();
        let (names_tx, names_rx) = mpsc::unbounded_channel();
        Loop {
            profile,
            swarm,
            cfg,
            handler,
            status,
            pending: HashMap::new(),
            dials: vec![],
            listens: HashMap::new(),
            relays: HashSet::new(),
            relay_listening: HashSet::new(),
            relay_listeners: HashMap::new(),
            resp_tx,
            resp_rx,
            names_pending: HashMap::new(),
            names_tx,
            names_rx,
            puts: HashMap::new(),
            gets: HashMap::new(),
            finds: HashMap::new(),
            provs: HashMap::new(),
            lgets: HashMap::new(),
            addr_book: HashMap::new(),
            heard: HashMap::new(),
            deferred: vec![],
            conns: HashMap::new(),
            hub: Hub::default(),
            status_tx: None,
            listeners: HashSet::new(),
            paused: false,
            relay_retry: vec![],
            relay_backoff: HashMap::new(),
            relay_addrs: HashMap::new(),
            relay_pending: HashSet::new(),
            serving: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            peer_apps: HashMap::new(),
        }
    }

    fn update(&self, f: impl FnOnce(&mut Status)) {
        if let Ok(mut s) = self.status.lock() {
            f(&mut s);
            if let Some(tx) = &self.status_tx {
                tx.send_if_modified(|old| {
                    let changed = *old != *s;
                    if changed {
                        *old = s.clone();
                    }
                    changed
                });
            }
        }
    }

    fn refresh(&self) {
        let connected: Vec<String> = self.swarm.connected_peers().map(|p| p.to_string()).collect();
        let listening: Vec<String> = self.swarm.listeners().map(|a| a.to_string()).collect();
        let external: Vec<String> = self.swarm.external_addresses().map(|a| a.to_string()).collect();
        self.update(|s| {
            s.connected = connected;
            s.listening = listening;
            s.external = external;
        });
    }

    fn seen(&self, s: Sighting) {
        let h = self.handler.clone();
        tokio::task::spawn_blocking(move || h.seen(s));
    }

    async fn run(&mut self, mut rx: mpsc::UnboundedReceiver<Cmd<Q, R>>, ready: std::sync::mpsc::Sender<Result<()>>) {
        // listen
        let mut waiting = 0usize;
        let mut ready = Some(ready);
        for a in self.cfg.listen.clone() {
            match self.swarm.listen_on(a.clone()) {
                Ok(_) => waiting += 1,
                Err(e) => tracing::warn!("network: cannot listen on {a}: {e}"),
            }
        }
        if !self.cfg.listen.is_empty() && waiting == 0 {
            if let Some(r) = ready.take() {
                let _ = r.send(Err(NetError::Network("could not listen on any address".into())));
            }
            return;
        }
        // relays first: a reservation dials its relay, and a second dial to the same peer
        // already under way would make the relay client skip its own
        for r in &self.cfg.relays {
            if let Some(p) = addr_peer(r) {
                let v = self.relay_addrs.entry(p).or_default();
                if !v.contains(r) {
                    v.push(r.clone());
                }
            }
        }
        for r in self.cfg.relays.clone() {
            self.add_relay(r);
        }
        if self.cfg.discovery.is_enabled() {
            for b in self.cfg.bootstrap.clone() {
                if let Some(p) = addr_peer(&b) {
                    self.swarm.behaviour_mut().kad.add_address(&p, b.clone());
                    if !self.relay_listening.contains(&p) {
                        let _ = self.swarm.dial(b);
                    }
                }
            }
        }
        for hint in self.cfg.peers.clone() {
            self.dial_hint(&hint);
        }
        if self.cfg.relay_server && self.cfg.discovery.is_enabled() {
            self.swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
        }
        if waiting == 0
            && let Some(r) = ready.take()
        {
            let _ = r.send(Ok(()));
        }
        let ready_deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(ready_deadline);
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut check = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    None | Some(Cmd::Stop) => break,
                    Some(c) => self.command(c),
                },
                Some((ch, resp)) = self.resp_rx.recv() => {
                    let _ = self.swarm.behaviour_mut().rr.send_response(ch, resp);
                }
                Some((ch, resp)) = self.names_rx.recv() => {
                    let _ = self.swarm.behaviour_mut().names.send_response(ch, resp);
                }
                ev = self.swarm.select_next_some() => {
                    let new_listen = matches!(ev, SwarmEvent::NewListenAddr { .. });
                    self.event(ev);
                    if new_listen && waiting > 0 {
                        waiting -= 1;
                        if waiting == 0 && let Some(r) = ready.take() {
                            let _ = r.send(Ok(()));
                        }
                    }
                }
                _ = &mut ready_deadline, if ready.is_some() => {
                    if let Some(r) = ready.take() {
                        let _ = r.send(Ok(()));
                    }
                }
                _ = tick.tick() => self.periodic(),
                _ = check.tick() => {
                    self.retry_stuck_reservations();
                    self.retry_lost_reservations();
                    self.release_deferred(None);
                }
            }
        }
        for (_, tx) in self.pending.drain() {
            let _ = tx.send(Err(NetError::Network("the node stopped".into())));
        }
        for (_, tx) in self.names_pending.drain() {
            let _ = tx.send(Err(NetError::Network("the node stopped".into())));
        }
    }

    fn periodic(&mut self) {
        if let Some(n) = &self.cfg.names_server {
            n.0.prune(crate::now_ms());
        }
        if self.paused {
            return;
        }
        if !self.cfg.discovery.is_enabled() {
            return;
        }
        let k = &mut self.swarm.behaviour_mut().kad;
        // With an empty routing table there is no one to bootstrap from; asking
        // anyway only makes libp2p warn "No known peers" every tick.
        if routing_empty(k) {
            return;
        }
        if k.bootstrap().is_ok() {
            k.get_providers(kad::RecordKey::new(&self.profile.relay_key));
            if self.cfg.relay_server {
                let _ = k.start_providing(kad::RecordKey::new(&self.profile.relay_key));
            }
        }
    }

    fn add_relay(&mut self, addr: Multiaddr) {
        let Some(peer) = addr_peer(&addr) else {
            tracing::warn!("network: relay address {addr} has no /p2p/ peer id");
            return;
        };
        if peer == *self.swarm.local_peer_id() {
            return;
        }
        let known = self.relay_addrs.entry(peer).or_default();
        if !known.contains(&addr) {
            known.push(addr.clone());
        }
        self.swarm.add_peer_address(peer, addr.clone());
        if !self.relay_listening.insert(peer) {
            return;
        }
        self.relays.insert(peer);
        if self.swarm.is_connected(&peer) {
            return self.reserve_on(peer);
        }
        // dial every address of the relay at once (TCP, QUIC, WSS…) and reserve once one
        // connects: the relay client would dial only the one address it was given
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        let addrs = self.relay_addrs.get(&peer).cloned().unwrap_or_default();
        match self.swarm.dial(DialOpts::peer_id(peer).addresses(addrs).condition(PeerCondition::DisconnectedAndNotDialing).build()) {
            Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
                self.relay_pending.insert(peer);
            }
            Err(e) => {
                tracing::warn!("network: cannot dial relay {peer}: {e}");
                self.relay_listening.remove(&peer);
                self.retry_relay_later(peer, addr);
            }
        }
    }

    /// Ask a connected relay for a reservation (listen through it).
    fn reserve_on(&mut self, peer: PeerId) {
        let Some(addr) = self.relay_addrs.get(&peer).and_then(|v| v.first().cloned()) else { return };
        let circuit = addr.with(Protocol::P2pCircuit);
        match self.swarm.listen_on(circuit.clone()) {
            Ok(id) => {
                self.relay_listeners.insert(peer, (circuit, id, std::time::Instant::now()));
            }
            Err(e) => {
                tracing::warn!("network: cannot listen through relay {circuit}: {e}");
                self.relay_listening.remove(&peer);
            }
        }
    }

    /// Dial a relay again later, backing off to a minute.
    fn retry_relay_later(&mut self, relay: PeerId, addr: Multiaddr) {
        let wait = self.relay_backoff.get(&relay).copied().unwrap_or(Duration::from_secs(1));
        self.relay_backoff.insert(relay, (wait * 2).min(Duration::from_secs(60)));
        self.relay_retry.retain(|(a, _, _)| addr_peer(a) != Some(relay));
        self.relay_retry.push((addr, std::time::Instant::now() + wait, wait));
    }

    fn keeps_relays(&self) -> bool {
        self.serving.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A relay's circuit listener closed (its connection went away, or we paused): the
    /// reservation is gone; ask again later unless paused.
    fn relay_listener_closed(&mut self, id: libp2p::core::transport::ListenerId) {
        let Some(relay) = self.relay_listeners.iter().find(|(_, (_, l, _))| *l == id).map(|(p, _)| *p) else { return };
        let Some((mut circuit, _, _)) = self.relay_listeners.remove(&relay) else { return };
        self.relay_listening.remove(&relay);
        let r = relay.to_string();
        self.update(|s| s.reservations.retain(|x| *x != r));
        self.hub.send(Event::ReservationLost { relay });
        circuit.pop();
        if !self.paused || self.keeps_relays() {
            let wait = self.relay_backoff.get(&relay).copied().unwrap_or(Duration::from_secs(1));
            self.relay_backoff.insert(relay, (wait * 2).min(Duration::from_secs(60)));
            self.relay_retry.retain(|(a, _, _)| *a != circuit);
            self.relay_retry.push((circuit, std::time::Instant::now() + wait, wait));
        }
    }

    fn retry_lost_reservations(&mut self) {
        if self.paused && !self.keeps_relays() {
            return;
        }
        let now = std::time::Instant::now();
        let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.relay_retry).into_iter().partition(|(_, at, _)| *at <= now);
        self.relay_retry = keep;
        for (addr, _, wait) in due {
            let peer = addr_peer(&addr);
            self.add_relay(addr.clone());
            // not listening through it (couldn't ask): try again, backing off to a minute
            if peer.is_some_and(|p| !self.relay_listening.contains(&p)) {
                let wait = (wait * 2).min(Duration::from_secs(60));
                self.relay_retry.push((addr, now + wait, wait));
            }
        }
    }

    /// Close every connection and listener (relay circuits too).
    fn go_quiet(&mut self) {
        // a node serving apps stays reachable through its relays
        let keep = self.keeps_relays();
        let kept: HashSet<_> = if keep { self.relay_listeners.values().map(|(_, id, _)| *id).collect() } else { HashSet::new() };
        for id in self.listeners.clone() {
            if !kept.contains(&id) {
                self.swarm.remove_listener(id);
            }
        }
        if !keep {
            for (_, (_, id, _)) in self.relay_listeners.clone() {
                self.swarm.remove_listener(id);
            }
        }
        let peers: Vec<PeerId> = self.swarm.connected_peers().copied().filter(|p| !(keep && self.relays.contains(p))).collect();
        for p in peers {
            let _ = self.swarm.disconnect_peer_id(p);
        }
    }

    /// Listen, reserve and bootstrap again.
    fn wake(&mut self, listen: bool) {
        if listen {
            for a in self.cfg.listen.clone() {
                if let Err(e) = self.swarm.listen_on(a.clone()) {
                    tracing::warn!("network: cannot listen on {a}: {e}");
                }
            }
        }
        let relays: Vec<Multiaddr> = self.cfg.relays.iter().cloned().chain(self.relay_retry.drain(..).map(|(a, _, _)| a)).collect();
        for r in relays {
            self.add_relay(r);
        }
        if self.cfg.discovery.is_enabled() {
            for b in self.cfg.bootstrap.clone() {
                if let Some(p) = addr_peer(&b)
                    && !self.relay_listening.contains(&p)
                {
                    let _ = self.swarm.dial(b);
                }
            }
            let k = &mut self.swarm.behaviour_mut().kad;
            if !routing_empty(k) {
                let _ = k.bootstrap();
            }
        }
        for hint in self.cfg.peers.clone() {
            self.dial_hint(&hint);
        }
    }

    /// A reservation asked for while another dial to the relay was under way is never sent
    /// (libp2p's relay client skips its own dial then); once connected, ask again.
    fn retry_stuck_reservations(&mut self) {
        let reserved = self.status.lock().map(|s| s.reservations.clone()).unwrap_or_default();
        let stuck: Vec<PeerId> = self
            .relay_listeners
            .iter()
            .filter(|(p, (_, _, at))| at.elapsed() > Duration::from_secs(3) && !reserved.contains(&p.to_string()) && self.swarm.is_connected(p))
            .map(|(p, _)| *p)
            .collect();
        for p in stuck {
            if let Some((circuit, id, _)) = self.relay_listeners.remove(&p) {
                tracing::debug!("network: asking relay {p} for a reservation again");
                self.swarm.remove_listener(id);
                match self.swarm.listen_on(circuit.clone()) {
                    Ok(id) => {
                        self.relay_listeners.insert(p, (circuit, id, std::time::Instant::now()));
                    }
                    Err(e) => tracing::warn!("network: cannot listen through relay {circuit}: {e}"),
                }
            }
        }
    }

    fn command(&mut self, c: Cmd<Q, R>) {
        let addrs: Vec<Multiaddr> = match &c {
            Cmd::Request { addrs, .. } | Cmd::Names { addrs, .. } => addrs.clone(),
            Cmd::Dial { addr, .. } => vec![addr.clone()],
            Cmd::Connect { peer, addrs, .. } if !self.swarm.is_connected(peer) => addrs.clone(),
            _ => vec![],
        };
        // through a relay we aren't connected to yet: connect to it first (or wait for the
        // dial already under way), then send
        let waiting = addrs.iter().filter_map(circuit_relay).find(|(r, _)| *r != *self.swarm.local_peer_id() && !self.swarm.is_connected(r));
        if let Some((relay, raddr)) = waiting {
            use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
            let mut all = vec![raddr];
            for a in self.relay_addrs.get(&relay).into_iter().flatten() {
                if !all.contains(a) {
                    all.push(a.clone());
                }
            }
            let _ = self.swarm.dial(DialOpts::peer_id(relay).addresses(all).condition(PeerCondition::DisconnectedAndNotDialing).build());
            self.deferred.push((relay, std::time::Instant::now(), c));
            return;
        }
        self.execute(c);
    }

    /// Send the commands that waited for `relay` (connected, or its dial failed), or every
    /// one that waited too long (`None`).
    fn release_deferred(&mut self, relay: Option<PeerId>) {
        let (ready, keep): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.deferred).into_iter().partition(|(r, at, _)| relay.map_or(at.elapsed() > RELAY_WAIT, |p| p == *r));
        self.deferred = keep;
        for (_, _, c) in ready {
            self.execute(c);
        }
    }

    fn require_discovery(&self) -> Result<()> {
        if self.cfg.discovery.is_enabled() { Ok(()) } else { Err(NetError::Network("peer discovery is disabled".into())) }
    }

    /// Remember addresses and dial; does not reserve a relay or grant trust.
    fn dial_hint(&mut self, hint: &PeerHint) {
        let Ok(peer) = hint.peer_id() else {
            tracing::warn!("network: invalid manual peer id {}", hint.peer_id);
            return;
        };
        if peer == *self.swarm.local_peer_id() {
            return;
        }
        let Ok(addrs) = hint.multiaddrs() else {
            tracing::warn!("network: invalid manual peer addresses for {peer}");
            return;
        };
        for a in &addrs {
            self.swarm.add_peer_address(peer, a.clone());
            if self.cfg.discovery.is_enabled() {
                self.swarm.behaviour_mut().kad.add_address(&peer, a.clone());
            }
        }
        if self.paused || self.swarm.is_connected(&peer) {
            return;
        }
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        let _ = self.swarm.dial(DialOpts::peer_id(peer).addresses(addrs).condition(PeerCondition::DisconnectedAndNotDialing).build());
    }

    fn remember_peer(&mut self, hint: PeerHint) -> Result<()> {
        hint.multiaddrs()?;
        if let Some(existing) = self.cfg.peers.iter_mut().find(|p| p.peer_id == hint.peer_id) {
            for a in &hint.addrs {
                if !existing.addrs.contains(a) {
                    existing.addrs.push(a.clone());
                }
            }
            let merged = existing.clone();
            self.dial_hint(&merged);
        } else {
            self.dial_hint(&hint);
            self.cfg.peers.push(hint);
        }
        Ok(())
    }

    fn execute(&mut self, c: Cmd<Q, R>) {
        match c {
            Cmd::Request { peer, addrs, wire, reply } => {
                for a in addrs {
                    self.swarm.add_peer_address(peer, a);
                }
                let id = self.swarm.behaviour_mut().rr.send_request(&peer, wire);
                self.pending.insert(id, reply);
            }
            Cmd::Names { peer, addrs, req, reply } => {
                for a in addrs {
                    self.swarm.add_peer_address(peer, a);
                }
                let id = self.swarm.behaviour_mut().names.send_request(&peer, req);
                self.names_pending.insert(id, reply);
            }
            Cmd::PutEntry { entry, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let key = kad::RecordKey::new(&self.profile.record_key(entry.user_id()));
                let existing = self.swarm.behaviour_mut().kad.store_mut().get(&key).and_then(|r| Entry::decode(&r.value).ok());
                if let Err(e) = self.profile.accept(existing.as_ref(), &entry, crate::now_ms()) {
                    let _ = reply.send(Err(e));
                    return;
                }
                let rec = record_of(key, &entry);
                match self.swarm.behaviour_mut().kad.put_record(rec, kad::Quorum::One) {
                    Ok(q) => {
                        self.puts.insert(q, reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(net_err(e)));
                    }
                }
            }
            Cmd::PutLocator { rec, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let now = crate::now_ms();
                let key = match rec.key() {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return;
                    }
                };
                let rkey = kad::RecordKey::new(&key);
                let existing =
                    self.swarm.behaviour_mut().kad.store_mut().get(&rkey).and_then(|r| crate::locator::LocatorRecord::decode(&r.value).ok());
                if let Err(e) = crate::locator::accept_locator(&key, existing.as_ref(), &rec, now) {
                    let _ = reply.send(Err(e));
                    return;
                }
                match self.swarm.behaviour_mut().kad.put_record(locator_record_of(rkey, &rec), kad::Quorum::One) {
                    Ok(q) => {
                        self.puts.insert(q, reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(net_err(e)));
                    }
                }
            }
            Cmd::GetLocators { key, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let q = self.swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&key));
                self.lgets.insert(q, (vec![], reply));
            }
            Cmd::GetEntries { user, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let q = self.swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&self.profile.record_key(&user)));
                self.gets.insert(q, (vec![], reply));
            }
            Cmd::FindPeer { peer, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let q = self.swarm.behaviour_mut().kad.get_closest_peers(peer);
                self.finds.insert(q, (peer, reply));
            }
            Cmd::PeerApps { peer, reply } => {
                let _ = reply.send(Ok(self.peer_apps.get(&peer).cloned()));
            }
            Cmd::KnownAddrs { reply } => {
                let v = self.addr_book.iter().flat_map(|(p, a)| a.iter().map(|a| (*p, a.clone()))).collect();
                let _ = reply.send(Ok(v));
            }
            Cmd::Dial { addr, reply } => {
                let peer = addr_peer(&addr);
                match self.swarm.dial(addr.clone()) {
                    Ok(()) => self.dials.push((addr, peer, reply)),
                    Err(e) => {
                        let _ = reply.send(Err(net_err(e)));
                    }
                }
            }
            Cmd::Connect { peer, addrs, reply } => {
                use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
                if self.swarm.is_connected(&peer) {
                    let _ = reply.send(Ok(peer));
                    return;
                }
                for a in &addrs {
                    self.swarm.add_peer_address(peer, a.clone());
                }
                let first = addrs.first().cloned().unwrap_or_else(|| Multiaddr::empty().with(Protocol::P2p(peer)));
                match self.swarm.dial(DialOpts::peer_id(peer).addresses(addrs).condition(PeerCondition::DisconnectedAndNotDialing).build()) {
                    Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => self.dials.push((first, Some(peer), reply)),
                    Err(e) => {
                        let _ = reply.send(Err(net_err(e)));
                    }
                }
            }
            Cmd::DropPath { peer, path, reply } => {
                let ids: Vec<_> =
                    self.conns.iter().filter(|(_, (p, relayed))| *p == peer && (*relayed == (path == Path::Relayed))).map(|(c, _)| *c).collect();
                let n = ids.iter().filter(|c| self.swarm.close_connection(**c)).count();
                let _ = reply.send(Ok(n));
            }
            Cmd::Pause { reply } => {
                if !self.paused {
                    self.paused = true;
                    // relays to come back to
                    let keep = self.keeps_relays();
                    let mut back: Vec<Multiaddr> = self
                        .relay_listeners
                        .values()
                        .filter(|_| !keep)
                        .map(|(c, _, _)| {
                            let mut c = c.clone();
                            c.pop();
                            c
                        })
                        .collect();
                    back.extend(self.relay_retry.drain(..).map(|(a, _, _)| a));
                    self.go_quiet();
                    let now = std::time::Instant::now();
                    self.relay_retry = back.into_iter().map(|a| (a, now, Duration::from_secs(1))).collect();
                    self.update(|s| s.paused = true);
                    self.hub.send(Event::Paused);
                }
                let _ = reply.send(Ok(()));
            }
            Cmd::Resume { reply } => {
                if self.paused {
                    self.paused = false;
                    self.update(|s| s.paused = false);
                    self.wake(true);
                    self.hub.send(Event::Resumed);
                }
                let _ = reply.send(Ok(()));
            }
            Cmd::NetworkChanged { reply } => {
                if !self.paused {
                    let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
                    for p in peers {
                        let _ = self.swarm.disconnect_peer_id(p);
                    }
                    self.wake(false);
                }
                self.hub.send(Event::NetworkChanged);
                let _ = reply.send(Ok(()));
            }
            Cmd::Paths { peer, reply } => {
                let v = self.conns.values().filter(|(p, _)| *p == peer).map(|(_, r)| if *r { Path::Relayed } else { Path::Direct }).collect();
                let _ = reply.send(Ok(v));
            }
            Cmd::Listen { addr, reply } => match self.swarm.listen_on(addr) {
                Ok(id) => {
                    self.listens.insert(id, reply);
                }
                Err(e) => {
                    let _ = reply.send(Err(net_err(e)));
                }
            },
            Cmd::AddRelay { addr } => self.add_relay(addr),
            Cmd::AddPeer { hint, reply } => {
                let _ = reply.send(self.remember_peer(hint));
            }
            Cmd::RemovePeer { peer, reply } => {
                let id = peer.to_string();
                self.cfg.peers.retain(|p| p.peer_id != id);
                let _ = reply.send(Ok(()));
            }
            Cmd::ListPeers { reply } => {
                let _ = reply.send(Ok(self.cfg.peers.clone()));
            }
            Cmd::Provide { key, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let r = self.swarm.behaviour_mut().kad.start_providing(kad::RecordKey::new(&key)).map(|_| ()).map_err(net_err);
                let _ = reply.send(r);
            }
            Cmd::StopProviding { key } => {
                if self.cfg.discovery.is_enabled() {
                    self.swarm.behaviour_mut().kad.stop_providing(&kad::RecordKey::new(&key));
                }
            }
            Cmd::Providers { key, reply } => {
                if let Err(e) = self.require_discovery() {
                    let _ = reply.send(Err(e));
                    return;
                }
                let q = self.swarm.behaviour_mut().kad.get_providers(kad::RecordKey::new(&key));
                self.provs.insert(q, (vec![], reply));
            }
            Cmd::Stop => {}
        }
    }

    fn event(&mut self, ev: SwarmEvent<BehaviourEvent<Q, R>>) {
        match ev {
            SwarmEvent::NewListenAddr { listener_id, address } => {
                tracing::info!("network: listening on {address}");
                self.listeners.insert(listener_id);
                self.hub.send(Event::Listening(address.clone()));
                // a relay announces where it listens: reservations carry those addresses
                if self.cfg.relay_server && self.cfg.external.is_empty() && routable(&address) && !address.iter().any(|p| p == Protocol::P2pCircuit) {
                    self.swarm.add_external_address(address.clone());
                }
                if let Some(tx) = self.listens.remove(&listener_id) {
                    let _ = tx.send(Ok(address));
                }
                self.refresh();
            }
            SwarmEvent::ListenerClosed { listener_id, addresses, .. } => {
                self.listeners.remove(&listener_id);
                for a in addresses {
                    self.hub.send(Event::ListenClosed(a));
                }
                if let Some(tx) = self.listens.remove(&listener_id) {
                    let _ = tx.send(Err(NetError::Network("listener closed".into())));
                }
                self.relay_listener_closed(listener_id);
                self.refresh();
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                // a relay keeps to its configured addresses (or at least routable ones)
                if self.cfg.relay_server && (!routable(&address) || (!self.cfg.external.is_empty() && !self.cfg.external.contains(&address))) {
                    self.swarm.remove_external_address(&address);
                } else {
                    self.hub.send(Event::External { addr: address, confirmed: true });
                }
                self.refresh()
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                self.hub.send(Event::External { addr: address, confirmed: false });
                self.refresh()
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                self.hub.send(Event::ListenClosed(address));
                self.refresh()
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, .. } => {
                self.release_deferred(Some(peer_id));
                if self.relay_pending.remove(&peer_id) {
                    if !self.paused || self.keeps_relays() {
                        self.reserve_on(peer_id);
                    } else if let Some(a) = self.relay_addrs.get(&peer_id).and_then(|v| v.first().cloned()) {
                        // paused meanwhile: reserve when the app comes back
                        self.relay_listening.remove(&peer_id);
                        self.relay_retry.push((a, std::time::Instant::now(), Duration::from_secs(1)));
                    }
                }
                let relayed = endpoint_relayed(&endpoint);
                self.conns.insert(connection_id, (peer_id, relayed));
                self.hub.send(Event::Connected { peer: peer_id, path: path_of(relayed) });
                let addr = endpoint.get_remote_address().clone();
                if endpoint.is_dialer() {
                    let a = if addr_peer(&addr) == Some(peer_id) { addr.clone() } else { addr.clone().with(Protocol::P2p(peer_id)) };
                    let book = self.addr_book.entry(peer_id).or_default();
                    if !book.contains(&a) {
                        book.push(a);
                    }
                }
                let mut i = 0;
                while i < self.dials.len() {
                    let (a, p, _) = &self.dials[i];
                    if *a == addr || p.is_some_and(|p| p == peer_id) {
                        let (_, _, tx) = self.dials.remove(i);
                        let _ = tx.send(Ok(peer_id));
                    } else {
                        i += 1;
                    }
                }
                self.refresh();
            }
            SwarmEvent::ConnectionClosed { connection_id, peer_id, num_established, .. } => {
                if let Some((_, relayed)) = self.conns.remove(&connection_id) {
                    self.hub.send(Event::Disconnected { peer: peer_id, path: path_of(relayed), remaining: num_established });
                }
                if num_established == 0 {
                    self.heard.remove(&peer_id);
                    self.peer_apps.remove(&peer_id);
                }
                self.refresh()
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(p) = peer_id
                    && !self.swarm.is_connected(&p)
                {
                    self.release_deferred(Some(p));
                    if self.relay_pending.remove(&p) {
                        self.relay_listening.remove(&p);
                        if let Some(a) = self.relay_addrs.get(&p).and_then(|v| v.first().cloned()) {
                            self.retry_relay_later(p, a);
                        }
                    }
                }
                let msg = error.to_string();
                let mut i = 0;
                while i < self.dials.len() {
                    if peer_id.is_some() && self.dials[i].1 == peer_id {
                        let (_, _, tx) = self.dials.remove(i);
                        let _ = tx.send(Err(net_err(&msg)));
                    } else {
                        i += 1;
                    }
                }
                if peer_id.is_none() && !self.dials.is_empty() {
                    // an address without /p2p/: the oldest dial failed
                    let (_, _, tx) = self.dials.remove(0);
                    let _ = tx.send(Err(net_err(&msg)));
                }
            }
            SwarmEvent::Behaviour(b) => self.behaviour(b),
            _ => {}
        }
    }

    fn behaviour(&mut self, ev: BehaviourEvent<Q, R>) {
        match ev {
            BehaviourEvent::Rr(request_response::Event::Message { peer, message, .. }) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let h = self.handler.clone();
                    let tx = self.resp_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        let resp = h.request(&peer, request);
                        let _ = tx.send((channel, resp));
                    });
                }
                request_response::Message::Response { request_id, response } => {
                    if let Some(tx) = self.pending.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            BehaviourEvent::Rr(request_response::Event::OutboundFailure { request_id, error, peer, .. }) => {
                if let Some(tx) = self.pending.remove(&request_id) {
                    let _ = tx.send(Err(NetError::Network(format!("{} could not be reached ({error})", crate::short_peer_id(&peer)))));
                }
            }
            BehaviourEvent::Rr(request_response::Event::InboundFailure { peer, error, .. }) => {
                tracing::debug!("network: inbound request from {peer} failed: {error}");
            }
            BehaviourEvent::Names(request_response::Event::Message { peer, message, .. }) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let Some(store) = self.cfg.names_server.clone() else { return };
                    let tx = self.names_tx.clone();
                    let profile = self.profile;
                    tokio::task::spawn_blocking(move || {
                        let resp = crate::names::serve(profile, &*store.0, &peer, request, crate::now_ms());
                        let _ = tx.send((channel, resp));
                    });
                }
                request_response::Message::Response { request_id, response } => {
                    if let Some(tx) = self.names_pending.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            BehaviourEvent::Names(request_response::Event::OutboundFailure { request_id, error, peer, .. }) => {
                if let Some(tx) = self.names_pending.remove(&request_id) {
                    let _ = tx.send(Err(NetError::Network(format!("names server {} could not be reached ({error})", crate::short_peer_id(&peer)))));
                }
            }
            BehaviourEvent::Kad(kad::Event::InboundRequest { request }) => match request {
                kad::InboundRequest::PutRecord { record: Some(rec), source, .. } => self.inbound_put(rec, source),
                kad::InboundRequest::AddProvider { record: Some(rec) } => {
                    // nodes announce the relay key and content roots, nothing else
                    if rec.key.as_ref() == self.profile.relay_key.as_bytes() || crate::content::is_provider_key(rec.key.as_ref()) {
                        let mut rec = rec;
                        // a provider that sent no addresses is answered with the ones we know,
                        // or others could not reach it
                        if rec.addresses.is_empty() {
                            rec.addresses = self.heard.get(&rec.provider).or_else(|| self.addr_book.get(&rec.provider)).cloned().unwrap_or_default();
                        }
                        let _ = self.swarm.behaviour_mut().kad.store_mut().add_provider(rec);
                    }
                }
                _ => {}
            },
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::PutRecord(r), .. }) => {
                if let Some(tx) = self.puts.remove(&id) {
                    let _ = tx.send(r.map(|_| ()).map_err(net_err));
                }
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetRecord(r), step, .. }) => {
                let now = crate::now_ms();
                let done = match r {
                    Ok(kad::GetRecordOk::FoundRecord(pr)) => {
                        if let Some((v, _)) = self.lgets.get_mut(&id)
                            && let Ok(l) = crate::locator::LocatorRecord::decode(&pr.record.value)
                            && crate::locator::accept_locator(pr.record.key.as_ref(), None, &l, now).is_ok()
                        {
                            v.push(l);
                        }
                        if let Some((v, _)) = self.gets.get_mut(&id)
                            && let Ok(e) = Entry::decode(&pr.record.value)
                        {
                            v.push(e);
                        }
                        step.last
                    }
                    _ => true,
                };
                if done && let Some((v, tx)) = self.lgets.remove(&id) {
                    let _ = tx.send(Ok(v));
                    if let Some(mut q) = self.swarm.behaviour_mut().kad.query_mut(&id) {
                        q.finish();
                    }
                }
                if done && let Some((v, tx)) = self.gets.remove(&id) {
                    let _ = tx.send(Ok(v));
                    if let Some(mut q) = self.swarm.behaviour_mut().kad.query_mut(&id) {
                        q.finish();
                    }
                }
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetClosestPeers(r), .. }) => {
                if let Some((peer, tx)) = self.finds.remove(&id) {
                    let addrs = match r {
                        Ok(ok) => ok.peers,
                        Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                    }
                    .into_iter()
                    .filter(|i| i.peer_id == peer)
                    .flat_map(|i| i.addrs)
                    .map(|a| if addr_peer(&a) == Some(peer) { a } else { a.with(Protocol::P2p(peer)) })
                    .collect();
                    let _ = tx.send(Ok(addrs));
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                let mut by_peer: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                for (p, a) in list {
                    by_peer.entry(p).or_default().push(a);
                }
                for (p, addrs) in by_peer {
                    for a in &addrs {
                        self.swarm.add_peer_address(p, a.clone());
                        if self.cfg.discovery.is_enabled() {
                            self.swarm.behaviour_mut().kad.add_address(&p, a.clone());
                        }
                    }
                    if self.cfg.discovery.is_enabled() && !self.paused && !self.swarm.is_connected(&p) {
                        let _ = self.swarm.dial(p);
                    }
                    self.seen(Sighting { peer: p, addrs: addrs.iter().map(|a| a.to_string()).collect(), caps: None, agent: None, source: "mdns" });
                }
            }
            BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let protos: Vec<String> = info.protocols.iter().map(|p| p.to_string()).collect();
                let mut caps = vec![];
                if protos.iter().any(|p| p == self.profile.protocol) {
                    caps.push(self.profile.name.to_string());
                }
                if protos.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME.to_string()) {
                    caps.push("relay".to_string());
                }
                if protos.iter().any(|p| p == self.profile.kad) {
                    caps.push("kad".to_string());
                    if self.cfg.discovery.is_enabled() {
                        for a in &info.listen_addrs {
                            self.swarm.behaviour_mut().kad.add_address(&peer_id, a.clone());
                        }
                    }
                }
                let apps: Vec<String> = protos.iter().filter_map(|p| crate::app::announced(p)).map(str::to_string).collect();
                caps.extend(apps.iter().map(|a| format!("app:{a}")));
                self.peer_apps.insert(peer_id, apps);
                let is_relay = caps.iter().any(|c| c == "relay");
                let addrs: Vec<String> = info.listen_addrs.iter().filter(|a| shareable(a)).map(|a| a.to_string()).collect();
                self.heard.insert(peer_id, info.listen_addrs.iter().filter(|a| shareable(a)).take(8).cloned().collect());
                self.seen(Sighting { peer: peer_id, addrs, caps: Some(caps), agent: Some(info.agent_version), source: "identify" });
                // behind NAT: use relays we meet
                let private = self.status.lock().map(|s| s.nat == "private").unwrap_or(false);
                if self.cfg.discovery.is_enabled()
                    && is_relay
                    && private
                    && !self.paused
                    && self.relay_listening.is_empty()
                    && let Some(a) = info.listen_addrs.iter().filter(|a| shareable(a)).min_by_key(|a| reach_rank(a))
                {
                    self.add_relay(a.clone().with(Protocol::P2p(peer_id)));
                }
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetProviders(r), step, .. })
                if self.provs.contains_key(&id) =>
            {
                let me = *self.swarm.local_peer_id();
                let done = step.last || !matches!(r, Ok(kad::GetProvidersOk::FoundProviders { .. }));
                if let Some((found, _)) = self.provs.get_mut(&id)
                    && let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = r
                {
                    for p in providers {
                        if p != me && !found.contains(&p) {
                            found.push(p);
                        }
                    }
                }
                if done && let Some((found, reply)) = self.provs.remove(&id) {
                    let _ = reply.send(Ok(found));
                }
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })),
                ..
            }) => {
                for p in providers {
                    if p != *self.swarm.local_peer_id() {
                        self.seen(Sighting { peer: p, addrs: vec![], caps: Some(vec!["relay".into(), "kad".into()]), agent: None, source: "kad" });
                    }
                }
            }
            BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. }) => {
                let nat = match new {
                    autonat::NatStatus::Public(_) => "public",
                    autonat::NatStatus::Private => "private",
                    autonat::NatStatus::Unknown => "unknown",
                };
                self.update(|s| s.nat = nat.into());
                self.hub.send(Event::Nat(nat.into()));
                if nat == "private" {
                    let relays: Vec<PeerId> = self.relays.iter().copied().collect();
                    tracing::info!("network: behind NAT; {} relay(s) known", relays.len());
                }
            }
            BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted { relay_peer_id, .. }) => {
                tracing::info!("network: reservation on relay {relay_peer_id}");
                self.hub.send(Event::Reserved { relay: relay_peer_id });
                self.relay_backoff.remove(&relay_peer_id);
                self.update(|s| {
                    let r = relay_peer_id.to_string();
                    if !s.reservations.contains(&r) {
                        s.reservations.push(r);
                    }
                });
            }
            BehaviourEvent::Streams(e) => match e {},
            BehaviourEvent::Dcutr(e) => {
                tracing::debug!("network: hole punch with {}: {}", e.remote_peer_id, if e.result.is_ok() { "direct" } else { "failed" });
            }
            _ => {}
        }
    }
}

/// A Kademlia record holding a names entry, expiring with it.
fn record_of(key: kad::RecordKey, entry: &Entry) -> kad::Record {
    let mut rec = kad::Record::new(key, entry.encode());
    let left = (entry.expires() - crate::now_ms()).max(0) as u64;
    rec.expires = Some(std::time::Instant::now() + Duration::from_millis(left));
    rec
}

/// A Kademlia record holding a locator record, expiring with it.
fn locator_record_of(key: kad::RecordKey, l: &crate::locator::LocatorRecord) -> kad::Record {
    let mut rec = kad::Record::new(key, l.encode());
    let left = (l.expires - crate::now_ms()).max(0) as u64;
    rec.expires = Some(std::time::Instant::now() + Duration::from_millis(left));
    rec
}

impl<Q: Message, R: Message> Loop<Q, R> {
    /// A peer put a locator record: keep it only if it checks out under its key.
    fn inbound_locator(&mut self, rec: kad::Record, l: crate::locator::LocatorRecord, source: PeerId) {
        let store = self.swarm.behaviour_mut().kad.store_mut();
        let existing = store.get(&rec.key).and_then(|r| crate::locator::LocatorRecord::decode(&r.value).ok());
        match crate::locator::accept_locator(rec.key.as_ref(), existing.as_ref(), &l, crate::now_ms()) {
            Ok(()) => {
                let mut r = locator_record_of(rec.key.clone(), &l);
                r.publisher = rec.publisher;
                let _ = store.put(r);
            }
            Err(e) => tracing::debug!("network: refused a locator record from {source}: {e}"),
        }
    }

    /// A peer put a record: keep it only if it is a valid names entry under its own key
    /// that supersedes what we hold (see [`Profile::accept`]).
    fn inbound_put(&mut self, rec: kad::Record, source: PeerId) {
        let Ok(entry) = Entry::decode(&rec.value) else {
            if let Ok(l) = crate::locator::LocatorRecord::decode(&rec.value) {
                return self.inbound_locator(rec, l, source);
            }
            tracing::debug!("network: refused a DHT record from {source}: not a names entry");
            return;
        };
        let key = kad::RecordKey::new(&self.profile.record_key(entry.user_id()));
        if rec.key != key {
            tracing::debug!("network: refused a DHT record from {source}: wrong key");
            return;
        }
        let store = self.swarm.behaviour_mut().kad.store_mut();
        let existing = store.get(&key).and_then(|r| Entry::decode(&r.value).ok());
        match self.profile.accept(existing.as_ref(), &entry, crate::now_ms()) {
            Ok(()) => {
                let mut r = record_of(key, &entry);
                r.publisher = rec.publisher;
                let _ = store.put(r);
            }
            Err(e) => tracing::debug!("network: refused a DHT record from {source}: {e}"),
        }
    }
}

/// True when the Kademlia routing table holds no peers yet.
fn routing_empty<S: kad::store::RecordStore + Send + 'static>(k: &mut kad::Behaviour<S>) -> bool {
    k.kbuckets().all(|b| b.num_entries() == 0)
}
