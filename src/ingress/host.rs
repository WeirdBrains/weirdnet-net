//! The host's side: forwarded connections arriving on `/weirdnet/ingress/1`.
use super::proxy;
use crate::stream::{Incoming, Stream};
use futures::AsyncReadExt;
use std::net::SocketAddr;
use std::time::Duration;

/// One forwarded connection: who it's from and for which name, then the client's raw bytes
/// (the TLS ClientHello first, or the HTTP request on port 80) on `stream`.
#[derive(Debug)]
pub struct IngressConn {
    pub name: String,
    /// The client's address, as the ingress saw it.
    pub client: Option<SocketAddr>,
    /// The ingress address the client connected to.
    pub ingress: Option<SocketAddr>,
    /// A plain-HTTP request (port 80: an ACME HTTP-01 challenge) rather than TLS.
    pub http: bool,
    /// The PROXY v2 header as received, for a local server that speaks the PROXY protocol.
    pub header: Vec<u8>,
    pub stream: Stream,
}

/// Forwarded connections, as they come.
pub struct IngressIncoming {
    pub(crate) inc: Incoming,
}

impl IngressIncoming {
    /// The next forwarded connection (`None` once the node stopped).
    pub async fn next(&mut self) -> Option<IngressConn> {
        loop {
            let s = self.inc.next().await?;
            if let Some(c) = read_header(s).await {
                return Some(c);
            }
        }
    }

    pub fn accept(&mut self) -> Option<IngressConn> {
        futures::executor::block_on(self.next())
    }

    pub fn accept_timeout(&mut self, d: Duration) -> Option<IngressConn> {
        let end = std::time::Instant::now() + d;
        loop {
            let s = self.inc.accept_timeout(end.saturating_duration_since(std::time::Instant::now()))?;
            if let Some(c) = futures::executor::block_on(read_header(s)) {
                return Some(c);
            }
        }
    }
}

async fn read_header(mut s: Stream) -> Option<IngressConn> {
    let mut head = vec![0u8; 16];
    s.read_exact(&mut head).await.ok()?;
    let len = u16::from_be_bytes([head[14], head[15]]) as usize;
    head.resize(16 + len, 0);
    s.read_exact(&mut head[16..]).await.ok()?;
    let (h, _) = proxy::decode(&head).ok()??;
    let name = h.authority?;
    Some(IngressConn { name, client: h.source, ingress: h.dest, http: h.http, header: head, stream: s })
}
