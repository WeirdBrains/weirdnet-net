//! SNI-passthrough ingress (W12): public HTTPS for hosts without a public address.
//!
//! An ingress peer (a relay, or a peer that opts in) listens on TCP 443, reads only the
//! server name from the TLS ClientHello and looks it up among the names hosts registered with
//! a signed [`IngressGrant`]. It then opens a `/weirdnet/ingress/1` stream to the host (direct
//! or through a relay circuit), writes a PROXY v2 header (the client's address, the name) and
//! splices the bytes both ways. TLS ends on the host; the ingress never holds a key or sees
//! plaintext. Port 80 forwards only ACME HTTP-01 requests for granted names and redirects
//! everything else to HTTPS.
//!
//! A host registers on `/weirdnet/ingress-grant/1` ([`Node::register_ingress`]) with its
//! user's certificate for the node and the grants; the ingress checks each grant's signature
//! and lifetime, that it names this ingress, that the certificate is the user's, and that DNS
//! binds the name to that user (`_weirdnet.<name> TXT "v=1 user=<id>"`). Registrations last
//! until the grant expires or the ingress restarts, so hosts register again now and then.
//! Every ingress can refuse a name ([`Ingress::revoke`]) or stop forwarding ([`Ingress::set_enabled`]).
//! Names the device serves itself on the same port (a relay's own WebSocket-over-TLS
//! listener behind 443) go to a local address untouched ([`IngressConfig::local`]).
//! HTTP/3 isn't passed through (QUIC hides the SNI). Per-grant byte and connection limits
//! come later.
//!
//! [`Node::register_ingress`]: crate::Node::register_ingress
mod grant;
mod host;
pub mod proxy;
mod server;
pub mod sni;

pub use grant::{Binding, DnsBinding, IngressGrant, MAX_GRANT_TTL_MS, Registered, Registration, StaticBinding};
pub use host::{IngressConn, IngressIncoming};
pub use server::{Ingress, IngressConfig, Site};

/// The stream an ingress opens to the host for each forwarded connection.
pub const INGRESS_PROTOCOL: &str = "/weirdnet/ingress/1";
/// The stream a host registers its grants on.
pub const GRANT_PROTOCOL: &str = "/weirdnet/ingress-grant/1";
/// The largest registration message.
pub const MAX_REGISTRATION: usize = 256 * 1024;

pub(crate) async fn write_msg<W: futures::AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    use futures::AsyncWriteExt;
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await
}

pub(crate) async fn read_msg<Rd: futures::AsyncRead + Unpin>(r: &mut Rd, max: usize) -> std::io::Result<Vec<u8>> {
    use futures::AsyncReadExt;
    let mut n = [0u8; 4];
    r.read_exact(&mut n).await?;
    let n = u32::from_be_bytes(n) as usize;
    if n > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}
