//! W12: a browser-like TLS client reaches a host with no public address through an ingress
//! peer that never sees plaintext; grants, bindings, revocation and port 80.
use crate::ingress::{Ingress, IngressConfig, IngressGrant, Registration, StaticBinding, proxy, sni};
use crate::node::{Handler, Node, NodeConfig};
use crate::user::user_id;
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Q;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R;
struct H;
impl Handler<Q, R> for H {
    fn request(&self, _: &PeerId, _: Q) -> R {
        R
    }
}
type N = Node<Q, R>;
const SITE: &str = "site.example.com";

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn mem_addr(n: &N) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")).unwrap().parse().unwrap()
}

struct World {
    ingress_node: N,
    ingress: Ingress,
    host: N,
    user: Keypair,
    rt: tokio::runtime::Runtime,
}

fn world(bind: bool) -> World {
    let ingress_node = start(mem(true));
    let user = Keypair::generate_ed25519();
    let mut b = StaticBinding::default();
    if bind {
        b.0.insert(SITE.into(), user_id(&user.public()));
    }
    let cfg = IngressConfig { https: Some("127.0.0.1:0".parse().unwrap()), http: Some("127.0.0.1:0".parse().unwrap()), ..Default::default() };
    let ingress = Ingress::start(&ingress_node, cfg, Arc::new(b)).unwrap();
    let host = start(mem(false));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    World { ingress_node, ingress, host, user, rt }
}

impl World {
    fn registration(&self, name: &str, ttl: i64) -> Registration {
        let now = crate::now_ms();
        let uid = user_id(&self.user.public());
        let cert = WEIRDNET.certify(&self.user, &uid, &self.host.peer_id().to_string(), "host", now).unwrap();
        let g = IngressGrant::sign(&self.user, name, &self.ingress_node.peer_id(), now, ttl).unwrap();
        Registration { grants: vec![g], cert, addrs: vec![] }
    }

    fn register(&self, reg: &Registration) -> crate::ingress::Registered {
        self.host.register_ingress(self.ingress_node.peer_id(), &[mem_addr(&self.ingress_node)], reg).unwrap()
    }
}

fn certs() -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec![SITE.into()]).unwrap();
    (c.cert.der().clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(c.key_pair.serialize_der().into()))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The host's site: TLS with its own certificate, answering `hello <client ip>`.
fn serve_site(
    host: &N,
    rt: &tokio::runtime::Runtime,
) -> (rustls::pki_types::CertificateDer<'static>, std::sync::mpsc::Receiver<crate::ingress::IngressConn>) {
    let (cert, key) = certs();
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let mut inc = host.accept_ingress().unwrap();
    let (http_tx, http_rx) = std::sync::mpsc::channel();
    rt.spawn(async move {
        while let Some(c) = inc.next().await {
            if c.http {
                let _ = http_tx.send(c);
                continue;
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let who = c.client.map(|a| a.ip().to_string()).unwrap_or_default();
                let mut tls = acceptor.accept(c.stream.compat()).await.unwrap();
                let mut line = [0u8; 4];
                tls.read_exact(&mut line).await.unwrap();
                assert_eq!(&line, b"ping");
                tls.write_all(format!("hello {who} via {}", c.name).as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            });
        }
    });
    (cert, http_rx)
}

async fn browse(addr: std::net::SocketAddr, cert: rustls::pki_types::CertificateDer<'static>, name: &str) -> std::io::Result<String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name.to_string().try_into().unwrap(), tcp).await?;
    tls.write_all(b"ping").await?;
    let mut out = String::new();
    tls.read_to_string(&mut out).await?;
    Ok(out)
}

#[test]
fn https_reaches_a_host_through_the_ingress() {
    let w = world(true);
    let (cert, _) = serve_site(&w.host, &w.rt);
    let r = w.register(&w.registration(SITE, 3_600_000));
    assert_eq!(r.accepted, vec![SITE.to_string()], "{r:?}");
    let sites = w.ingress.sites();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].host, w.host.peer_id());
    let got =
        w.rt.block_on(async { tokio::time::timeout(Duration::from_secs(20), browse(w.ingress.https_addr().unwrap(), cert, SITE)).await })
            .unwrap()
            .unwrap();
    assert_eq!(got, format!("hello 127.0.0.1 via {SITE}"));
}

#[test]
fn a_name_dns_does_not_bind_to_the_user_is_refused() {
    let w = world(false);
    let r = w.register(&w.registration(SITE, 3_600_000));
    assert!(r.accepted.is_empty());
    assert!(r.refused[0].1.contains("DNS"), "{r:?}");
    assert!(w.ingress.sites().is_empty());
}

#[test]
fn a_grant_for_another_user_or_ingress_is_refused() {
    let w = world(true);
    // the certificate is from another user
    let mut reg = w.registration(SITE, 3_600_000);
    let other = Keypair::generate_ed25519();
    reg.cert = WEIRDNET.certify(&other, &user_id(&other.public()), &w.host.peer_id().to_string(), "x", crate::now_ms()).unwrap();
    let r = w.register(&reg);
    assert!(r.accepted.is_empty() && r.refused[0].1.contains("certificate"), "{r:?}");
    // the grant names another ingress
    let mut reg = w.registration(SITE, 3_600_000);
    reg.grants[0] = IngressGrant::sign(&w.user, SITE, &PeerId::random(), crate::now_ms(), 3_600_000).unwrap();
    let r = w.register(&reg);
    assert!(r.accepted.is_empty() && r.refused[0].1.contains("another ingress"), "{r:?}");
    // tampered
    let mut reg = w.registration(SITE, 3_600_000);
    reg.grants[0].expires += 1;
    assert!(w.register(&reg).accepted.is_empty());
}

#[test]
fn a_revoked_site_stops_being_forwarded() {
    let w = world(true);
    let (cert, _) = serve_site(&w.host, &w.rt);
    assert_eq!(w.register(&w.registration(SITE, 3_600_000)).accepted.len(), 1);
    w.ingress.revoke("Site.Example.com.");
    assert!(w.ingress.sites().is_empty());
    assert_eq!(w.ingress.revoked(), vec![SITE.to_string()]);
    let addr = w.ingress.https_addr().unwrap();
    assert!(w.rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), browse(addr, cert.clone(), SITE)).await }).unwrap().is_err());
    // and it can't come back by registering again
    let r = w.register(&w.registration(SITE, 3_600_000));
    assert!(r.accepted.is_empty(), "{r:?}");
    // until unrevoked; forwarding off refuses everything
    w.ingress.unrevoke(SITE);
    w.ingress.set_enabled(false);
    assert!(w.register(&w.registration(SITE, 3_600_000)).accepted.is_empty());
    w.ingress.set_enabled(true);
    assert_eq!(w.register(&w.registration(SITE, 3_600_000)).accepted.len(), 1);
    let got = w.rt.block_on(async { tokio::time::timeout(Duration::from_secs(20), browse(addr, cert, SITE)).await }).unwrap().unwrap();
    assert!(got.starts_with("hello"));
}

#[test]
fn port_80_forwards_acme_and_redirects_the_rest() {
    let w = world(true);
    let (_, http_rx) = serve_site(&w.host, &w.rt);
    assert_eq!(w.register(&w.registration(SITE, 3_600_000)).accepted.len(), 1);
    let addr = w.ingress.http_addr().unwrap();
    let get = |path: &str, host: &str| {
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:80\r\n\r\n");
        w.rt.block_on(async move {
            let mut t = tokio::net::TcpStream::connect(addr).await.unwrap();
            t.write_all(req.as_bytes()).await.unwrap();
            let mut out = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), t.read(&mut out)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
            String::from_utf8_lossy(&out[..n]).to_string()
        })
    };
    let r = get("/a/b?c", SITE);
    assert!(r.starts_with("HTTP/1.1 301") && r.contains("Location: https://site.example.com/a/b?c\r\n"), "{r}");
    // a challenge for an unregistered name is only redirected
    assert!(get("/.well-known/acme-challenge/tok", "other.example.com").starts_with("HTTP/1.1 301"));
    let _ = get("/.well-known/acme-challenge/tok", SITE);
    let c = http_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(c.http && c.name == SITE);
}

#[test]
fn grants_check_their_fields() {
    let user = Keypair::generate_ed25519();
    let ing = PeerId::random();
    let now = crate::now_ms();
    let g = IngressGrant::sign(&user, "Site.Example.COM.", &ing, now, 1000).unwrap();
    assert_eq!(g.name, SITE);
    g.verify(&ing, now).unwrap();
    assert!(g.verify(&ing, now + 2000).is_err());
    assert!(g.verify(&PeerId::random(), now).is_err());
    assert!(IngressGrant::sign(&user, SITE, &ing, now, crate::ingress::MAX_GRANT_TTL_MS + 1).is_err());
    assert!(IngressGrant::sign(&user, "bad name!", &ing, now, 1000).is_err());
    let mut t = g.clone();
    t.name = "evil.example.com".into();
    assert!(t.verify(&ing, now).is_err());
}

#[test]
fn proxy_headers_round_trip() {
    for (s, d) in [("1.2.3.4:5678", "10.0.0.1:443"), ("[2001:db8::1]:40000", "[2001:db8::2]:443"), ("1.2.3.4:1", "[2001:db8::2]:443")] {
        let (s, d) = (s.parse().unwrap(), d.parse().unwrap());
        let h = proxy::encode(s, d, SITE, true);
        let (got, n) = proxy::decode(&h).unwrap().unwrap();
        assert_eq!(n, h.len());
        assert_eq!(got.source, Some(s));
        assert_eq!(got.dest, Some(d));
        assert_eq!(got.authority.as_deref(), Some(SITE));
        assert!(got.http);
        assert_eq!(proxy::decode(&h[..10]).unwrap(), None);
    }
    assert!(proxy::decode(b"GET / HTTP/1.1\r\n\r\n").is_err());
}

#[test]
fn sni_is_read_from_a_real_client_hello_in_pieces() {
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut c = rustls::ClientConnection::new(Arc::new(cfg), SITE.try_into().unwrap()).unwrap();
    let mut hello = vec![];
    c.write_tls(&mut hello).unwrap();
    for cut in [0, 3, 5, 40, hello.len() - 1] {
        assert_eq!(sni::peek(&hello[..cut]), sni::Hello::More);
    }
    assert_eq!(sni::peek(&hello), sni::Hello::Name(SITE.into()));
    // the same handshake split over two records
    let body = &hello[5..];
    let (a, b) = body.split_at(100);
    let mut two = vec![0x16, 3, 1];
    two.extend_from_slice(&(a.len() as u16).to_be_bytes());
    two.extend_from_slice(a);
    two.extend_from_slice(&[0x16, 3, 1]);
    two.extend_from_slice(&(b.len() as u16).to_be_bytes());
    two.extend_from_slice(b);
    assert_eq!(sni::peek(&two), sni::Hello::Name(SITE.into()));
    assert_eq!(sni::peek(b"GET / HTTP/1.1\r\n"), sni::Hello::Bad);
}

#[test]
fn a_name_served_here_goes_to_its_local_listener() {
    // a local TLS-less "listener" that just records the first bytes
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = l.local_addr().unwrap();
    let ingress_node = start(mem(true));
    let cfg = IngressConfig { https: Some("127.0.0.1:0".parse().unwrap()), local: vec![("Relay.Example.com".into(), local)], ..Default::default() };
    let ingress = Ingress::start(&ingress_node, cfg, Arc::new(StaticBinding::default())).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let addr = ingress.https_addr().unwrap();
    let (cert, _) = certs();
    let t = std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let n = std::io::Read::read(&mut c, &mut buf).unwrap();
        sni::peek(&buf[..n])
    });
    // the client's handshake goes nowhere (no TLS on the local side); only the routing matters
    let _ = rt.block_on(async { tokio::time::timeout(Duration::from_secs(3), browse(addr, cert, "relay.example.com")).await });
    assert_eq!(t.join().unwrap(), sni::Hello::Name("relay.example.com".into()));
}
