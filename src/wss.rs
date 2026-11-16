//! WebSocket over TLS (W6): a transport for networks that only let HTTPS out, usually on 443.
//! Every node dials `/dns/<name>/tcp/443/tls/ws/p2p/<id>` (or `/wss`) trusting the web PKI;
//! a node with a [`WssTls`] certificate also listens on `/…/tcp/443/tls/ws`.
//! Noise and Yamux run inside the WebSocket as on TCP, so the peer id is checked the same way.
use crate::error::{NetError, Result};
use libp2p::websocket::tls;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The certificate a node serves WebSocket-over-TLS with, and extra roots it trusts when
/// dialing (for private CAs and tests; the web PKI is always trusted).
#[derive(Debug, Clone, Default)]
pub struct WssTls {
    /// The certificate chain (DER), leaf first; empty: dial only.
    pub chain: Vec<Vec<u8>>,
    /// The private key (DER: PKCS#8, PKCS#1 or SEC1).
    pub key: Vec<u8>,
    /// Extra trust anchors for dialing (DER).
    pub trust: Vec<Vec<u8>>,
}

impl WssTls {
    /// From PEM text, as certbot or `weirdnet-tls` write it (`fullchain.pem`, `privkey.pem`).
    pub fn from_pem(chain_pem: &str, key_pem: &str) -> Result<Self> {
        let chain: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
            .map(|c| c.map(|c| c.to_vec()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| NetError::invalid("certificate PEM", e.to_string()))?;
        if chain.is_empty() {
            return Err(NetError::invalid("certificate PEM", "no certificate"));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| NetError::invalid("key PEM", e.to_string()))?;
        Ok(WssTls { chain, key: key.secret_der().to_vec(), trust: vec![] })
    }

    /// Read `chain` and `key` PEM files.
    pub fn from_pem_files(chain: &std::path::Path, key: &std::path::Path) -> Result<Self> {
        let read = |p: &std::path::Path| std::fs::read_to_string(p).map_err(|e| NetError::invalid("PEM file", format!("{}: {e}", p.display())));
        Self::from_pem(&read(chain)?, &read(key)?)
    }

    pub(crate) fn config(&self) -> Result<tls::Config> {
        let mut b = tls::Config::builder();
        for t in &self.trust {
            b.add_trust(&tls::Certificate::new(t.clone())).map_err(|e| NetError::invalid("trust anchor", e.to_string()))?;
        }
        if !self.chain.is_empty() {
            b.server(tls::PrivateKey::new(self.key.clone()), self.chain.iter().cloned().map(tls::Certificate::new))
                .map_err(|e| NetError::invalid("WSS certificate", e.to_string()))?;
        }
        Ok(b.finish())
    }
}

/// Whether `a` is a WebSocket-over-TLS address.
pub fn is_wss(a: &libp2p::Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    let v: Vec<Protocol> = a.iter().collect();
    v.iter().any(|p| matches!(p, Protocol::Wss(_))) || v.windows(2).any(|w| matches!(w[0], Protocol::Tls) && matches!(w[1], Protocol::Ws(_)))
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// TCP, QUIC and WebSocket over TLS (each with Noise and Yamux, QUIC with its own TLS) under
/// DNS resolution. DNS names in WSS addresses are kept as the TLS server name (`/tls/sni/…`)
/// before they are resolved, so certificates are checked against the name, not the IP.
pub(crate) fn transport(
    key: &libp2p::identity::Keypair,
    tls: &WssTls,
    dns: (libp2p::dns::ResolverConfig, libp2p::dns::ResolverOpts),
) -> std::result::Result<libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>, BoxErr> {
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::upgrade::Version;
    use libp2p::{Transport, noise, quic, tcp, yamux};
    let tcp_cfg = || tcp::Config::default().nodelay(true);
    let tcp = tcp::tokio::Transport::new(tcp_cfg())
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
    let quic = quic::tokio::Transport::new(quic::Config::new(key)).map(|(p, c), _| (p, StreamMuxerBox::new(c)));
    let mut ws = libp2p::websocket::Config::new(tcp::tokio::Transport::new(tcp_cfg()));
    ws.set_tls_config(tls.config()?);
    let ws = ws
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
    let all = ws.or_transport(quic).map(|e, _| e.into_inner()).or_transport(tcp).map(|e, _| e.into_inner());
    let dns = libp2p::dns::tokio::Transport::custom(all, dns.0, dns.1);
    Ok(SniFirst(dns).boxed())
}

/// Adds `/sni/<name>` to WSS addresses dialed by DNS name (see [`with_sni`]).
struct SniFirst<T>(T);

impl<T: libp2p::core::Transport + Unpin> libp2p::core::Transport for SniFirst<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: libp2p::core::transport::ListenerId,
        addr: libp2p::Multiaddr,
    ) -> std::result::Result<(), libp2p::core::transport::TransportError<Self::Error>> {
        self.0.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: libp2p::core::transport::ListenerId) -> bool {
        self.0.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: libp2p::Multiaddr,
        opts: libp2p::core::transport::DialOpts,
    ) -> std::result::Result<Self::Dial, libp2p::core::transport::TransportError<Self::Error>> {
        self.0.dial(with_sni(&addr), opts)
    }

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

/// `/dns…/<name>/tcp/<port>/tls/ws` (or `/wss`) becomes `…/tls/sni/<name>/ws`, so the name
/// survives DNS resolution as the TLS server name. Other addresses are left alone.
pub fn with_sni(a: &libp2p::Multiaddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let v: Vec<Protocol> = a.iter().collect();
    let mut out = libp2p::Multiaddr::empty();
    let mut name: Option<String> = None;
    let mut i = 0;
    while i < v.len() {
        match &v[i] {
            Protocol::Dns(n) | Protocol::Dns4(n) | Protocol::Dns6(n) => {
                name = Some(n.to_string());
                out.push(v[i].clone());
            }
            Protocol::Tls if name.is_some() && matches!(v.get(i + 1), Some(Protocol::Ws(_))) => {
                out.push(Protocol::Tls);
                out.push(Protocol::Sni(name.take().unwrap_or_default().into()));
            }
            Protocol::Wss(path) if name.is_some() => {
                out.push(Protocol::Tls);
                out.push(Protocol::Sni(name.take().unwrap_or_default().into()));
                out.push(Protocol::Ws(path.clone()));
            }
            p => out.push(p.clone()),
        }
        i += 1;
    }
    out
}
