//! Raw libp2p substreams by protocol, adapted from `libp2p-stream` 0.5.0-alpha
//! (<https://github.com/libp2p/rust-libp2p>, MIT, Copyright 2018 Parity Technologies (UK) Ltd.
//! and Protocol Labs). Changes: a new stream goes over a direct connection when there is one
//! (the newest), else the newest relayed one; each stream says whether its connection is
//! relayed; watchers hear when connections come and go; and a peer with open logical streams
//! keeps its connections alive (so the relayed path stays warm behind a direct one).
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy of this
//! software and associated documentation files (the "Software"), to deal in the Software
//! without restriction, including without limitation the rights to use, copy, modify, merge,
//! publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
//! to whom the Software is furnished to do so, subject to the following conditions: The above
//! copyright notice and this permission notice shall be included in all copies or substantial
//! portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
//! FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//! HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
//! CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
//! USE OR OTHER DEALINGS IN THE SOFTWARE.
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use libp2p::PeerId;
use libp2p::core::transport::PortUse;
use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound};
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, DialError, DialFailure, FromSwarm, NetworkBehaviour,
    Stream, StreamProtocol, StreamUpgradeError, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use std::collections::{HashMap, hash_map};
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Instant;

/// A stream, whether its connection goes through a relay, and which connection it is.
pub(crate) type Opened = (Stream, bool, ConnectionId);
/// An inbound stream: who opened it, the stream, whether it is relayed, its connection.
pub(crate) type Inbound = (PeerId, Stream, bool, ConnectionId);

/// A connection to `peer` came up or went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathEvent {
    pub(crate) peer: PeerId,
    pub(crate) conn: ConnectionId,
    pub(crate) relayed: bool,
    pub(crate) up: bool,
}

#[derive(Debug)]
pub(crate) enum OpenError {
    /// The peer doesn't accept this protocol.
    Unsupported(StreamProtocol),
    Io(io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Unsupported(p) => write!(f, "the peer does not accept {p}"),
            OpenError::Io(e) => write!(f, "cannot open a stream: {e}"),
        }
    }
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

struct Conn {
    peer: PeerId,
    relayed: bool,
    since: Instant,
}

pub(crate) struct NewStream {
    protocol: StreamProtocol,
    sender: oneshot::Sender<Result<Opened, OpenError>>,
}

struct Shared {
    inbound: HashMap<StreamProtocol, mpsc::Sender<Inbound>>,
    connections: HashMap<ConnectionId, Conn>,
    senders: HashMap<ConnectionId, mpsc::Sender<NewStream>>,
    pending: HashMap<PeerId, (mpsc::Sender<NewStream>, mpsc::Receiver<NewStream>)>,
    dial: mpsc::Sender<PeerId>,
    watchers: Vec<mpsc::UnboundedSender<PathEvent>>,
    warm: HashMap<PeerId, usize>,
}

fn lock(s: &Arc<Mutex<Shared>>) -> MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn protocols(&mut self) -> Vec<StreamProtocol> {
        self.inbound.retain(|_, s| !s.is_closed());
        self.inbound.keys().cloned().collect()
    }

    fn on_inbound(&mut self, remote: PeerId, stream: Stream, protocol: StreamProtocol, relayed: bool, conn: ConnectionId) {
        if let hash_map::Entry::Occupied(mut e) = self.inbound.entry(protocol.clone()) {
            match e.get_mut().try_send((remote, stream, relayed, conn)) {
                Ok(()) => {}
                Err(err) if err.is_disconnected() => {
                    e.remove();
                }
                Err(_) => tracing::debug!(%protocol, "network: too many streams waiting, dropping one"),
            }
        }
    }

    fn notify(&mut self, ev: PathEvent) {
        self.watchers.retain(|w| w.unbounded_send(ev).is_ok());
    }

    /// A direct connection's channel if there is one (the newest), else the newest relayed one.
    fn sender(&mut self, peer: PeerId) -> mpsc::Sender<NewStream> {
        let best = self
            .connections
            .iter()
            .filter(|(c, k)| k.peer == peer && self.senders.contains_key(*c))
            .max_by_key(|(_, k)| (!k.relayed, k.since))
            .map(|(c, _)| *c);
        if let Some(s) = best.and_then(|c| self.senders.get(&c)) {
            return s.clone();
        }
        let (s, _) = self.pending.entry(peer).or_insert_with(|| mpsc::channel(0));
        let _ = self.dial.try_send(peer);
        s.clone()
    }

    fn receiver(&mut self, peer: PeerId, conn: ConnectionId) -> mpsc::Receiver<NewStream> {
        if let Some((s, r)) = self.pending.remove(&peer) {
            self.senders.insert(conn, s);
            return r;
        }
        let (s, r) = mpsc::channel(0);
        self.senders.insert(conn, s);
        r
    }

    fn on_dial_failure(&mut self, peer: PeerId, reason: String) {
        let Some((_, mut r)) = self.pending.remove(&peer) else { return };
        while let Ok(n) = r.try_recv() {
            let _ = n.sender.send(Err(OpenError::Io(io::Error::new(io::ErrorKind::NotConnected, reason.clone()))));
        }
    }
}

fn relayed(addrs: &[&Multiaddr]) -> bool {
    addrs.iter().any(|a| a.iter().any(|p| p == Protocol::P2pCircuit))
}

/// The network behaviour; [`Control`] opens and accepts its streams.
pub(crate) struct Behaviour {
    shared: Arc<Mutex<Shared>>,
    dials: mpsc::Receiver<PeerId>,
}

impl Behaviour {
    pub(crate) fn new() -> Self {
        let (dial, dials) = mpsc::channel(0);
        let shared = Shared {
            inbound: HashMap::new(),
            connections: HashMap::new(),
            senders: HashMap::new(),
            pending: HashMap::new(),
            dial,
            watchers: vec![],
            warm: HashMap::new(),
        };
        Behaviour { shared: Arc::new(Mutex::new(shared)), dials }
    }

    pub(crate) fn control(&self) -> Control {
        Control { shared: self.shared.clone() }
    }

    fn handler(&self, peer: PeerId, conn: ConnectionId, relayed: bool) -> Handler {
        let mut s = lock(&self.shared);
        let receiver = s.receiver(peer, conn);
        s.connections.insert(conn, Conn { peer, relayed, since: Instant::now() });
        Handler { remote: peer, conn, relayed, shared: self.shared.clone(), receiver, pending: None }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.handler(peer, conn, relayed(&[local, remote])))
    }

    fn handle_established_outbound_connection(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.handler(peer, conn, relayed(&[addr])))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, connection_id, .. }) => {
                let mut s = lock(&self.shared);
                if let Some(c) = s.connections.get(&connection_id) {
                    let ev = PathEvent { peer: peer_id, conn: connection_id, relayed: c.relayed, up: true };
                    s.notify(ev);
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, peer_id, .. }) => {
                let mut s = lock(&self.shared);
                s.senders.remove(&connection_id);
                if let Some(c) = s.connections.remove(&connection_id) {
                    s.notify(PathEvent { peer: peer_id, conn: connection_id, relayed: c.relayed, up: false });
                }
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer),
                error: error @ (DialError::Transport(_) | DialError::Denied { .. } | DialError::NoAddresses | DialError::WrongPeerId { .. }),
                ..
            }) => lock(&self.shared).on_dial_failure(peer, error.to_string()),
            _ => {}
        }
    }

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: THandlerOutEvent<Self>) {
        match event {}
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Poll::Ready(Some(peer)) = self.dials.poll_next_unpin(cx) {
            return Poll::Ready(ToSwarm::Dial { opts: DialOpts::peer_id(peer).condition(PeerCondition::DisconnectedAndNotDialing).build() });
        }
        Poll::Pending
    }
}

/// Opens streams, accepts them by protocol, and reports connections coming and going.
#[derive(Clone)]
pub(crate) struct Control {
    shared: Arc<Mutex<Shared>>,
}

impl Control {
    /// A stream to `peer` (dialing it if not connected), direct when possible.
    pub(crate) async fn open(&self, peer: PeerId, protocol: StreamProtocol) -> Result<Opened, OpenError> {
        let mut tx = lock(&self.shared).sender(peer);
        let (sender, receiver) = oneshot::channel();
        tx.send(NewStream { protocol, sender }).await.map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;
        receiver.await.map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?
    }

    /// Inbound streams of `protocol`; `None` if something accepts it already.
    pub(crate) fn accept(&self, protocol: StreamProtocol, backlog: usize) -> Option<mpsc::Receiver<Inbound>> {
        let mut s = lock(&self.shared);
        s.inbound.retain(|_, x| !x.is_closed());
        if s.inbound.contains_key(&protocol) {
            return None;
        }
        let (tx, rx) = mpsc::channel(backlog);
        s.inbound.insert(protocol, tx);
        Some(rx)
    }

    pub(crate) fn watch(&self) -> mpsc::UnboundedReceiver<PathEvent> {
        let (tx, rx) = mpsc::unbounded();
        lock(&self.shared).watchers.push(tx);
        rx
    }

    pub(crate) fn has_direct(&self, peer: PeerId) -> bool {
        lock(&self.shared).connections.values().any(|c| c.peer == peer && !c.relayed)
    }

    /// Keep every connection to `peer` open while the guard lives.
    pub(crate) fn warm(&self, peer: PeerId) -> Warm {
        *lock(&self.shared).warm.entry(peer).or_default() += 1;
        Warm { peer, shared: self.shared.clone() }
    }
}

pub(crate) struct Warm {
    peer: PeerId,
    shared: Arc<Mutex<Shared>>,
}

impl Drop for Warm {
    fn drop(&mut self) {
        let mut s = lock(&self.shared);
        if let Some(n) = s.warm.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                s.warm.remove(&self.peer);
            }
        }
    }
}

pub(crate) struct Handler {
    remote: PeerId,
    conn: ConnectionId,
    relayed: bool,
    shared: Arc<Mutex<Shared>>,
    receiver: mpsc::Receiver<NewStream>,
    pending: Option<(StreamProtocol, oneshot::Sender<Result<Opened, OpenError>>)>,
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Infallible;
    type ToBehaviour = Infallible;
    type InboundProtocol = Upgrade;
    type OutboundProtocol = Upgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Upgrade> {
        SubstreamProtocol::new(Upgrade { protocols: lock(&self.shared).protocols() }, ())
    }

    fn connection_keep_alive(&self) -> bool {
        lock(&self.shared).warm.contains_key(&self.remote)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Upgrade, (), Infallible>> {
        if self.pending.is_some() {
            return Poll::Pending;
        }
        if let Poll::Ready(Some(n)) = self.receiver.poll_next_unpin(cx) {
            self.pending = Some((n.protocol.clone(), n.sender));
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(Upgrade { protocols: vec![n.protocol] }, ()),
            });
        }
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Infallible) {
        match event {}
    }

    fn on_connection_event(&mut self, event: ConnectionEvent<Upgrade, Upgrade>) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound { protocol: (stream, protocol), .. }) => {
                lock(&self.shared).on_inbound(self.remote, stream, protocol, self.relayed, self.conn);
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound { protocol: (stream, _), .. }) => {
                if let Some((_, tx)) = self.pending.take() {
                    let _ = tx.send(Ok((stream, self.relayed, self.conn)));
                }
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => {
                if let Some((p, tx)) = self.pending.take() {
                    let e = match error {
                        StreamUpgradeError::Timeout => OpenError::Io(io::ErrorKind::TimedOut.into()),
                        StreamUpgradeError::Apply(v) => match v {},
                        StreamUpgradeError::NegotiationFailed => OpenError::Unsupported(p),
                        StreamUpgradeError::Io(e) => OpenError::Io(e),
                    };
                    let _ = tx.send(Err(e));
                }
            }
            _ => {}
        }
    }
}

pub(crate) struct Upgrade {
    protocols: Vec<StreamProtocol>,
}

impl UpgradeInfo for Upgrade {
    type Info = StreamProtocol;
    type InfoIter = std::vec::IntoIter<StreamProtocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl InboundUpgrade<Stream> for Upgrade {
    type Output = (Stream, StreamProtocol);
    type Error = Infallible;
    type Future = Ready<Result<Self::Output, Infallible>>;

    fn upgrade_inbound(self, s: Stream, p: StreamProtocol) -> Self::Future {
        ready(Ok((s, p)))
    }
}

impl OutboundUpgrade<Stream> for Upgrade {
    type Output = (Stream, StreamProtocol);
    type Error = Infallible;
    type Future = Ready<Result<Self::Output, Infallible>>;

    fn upgrade_outbound(self, s: Stream, p: StreamProtocol) -> Self::Future {
        ready(Ok((s, p)))
    }
}
