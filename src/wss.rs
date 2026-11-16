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
