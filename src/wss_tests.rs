//! WebSocket over TLS on loopback TCP: a node with a certificate listens on `/tls/ws`, another
//! dials it there trusting that certificate; the wrong certificate or peer id is refused.
use crate::node::{Handler, Node, NodeConfig};
use crate::wss::{WssTls, is_wss};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Q(u32);
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct R(u32);
struct H;
impl Handler<Q, R> for H {
    fn request(&self, _: &PeerId, q: Q) -> R {
        R(q.0 * 2)
    }
}
type N = Node<Q, R>;

fn cert() -> (WssTls, Vec<u8>) {
    cert_for(vec!["localhost".into(), "127.0.0.1".into()])
}

fn cert_for(names: Vec<String>) -> (WssTls, Vec<u8>) {
    let c = rcgen::generate_simple_self_signed(names).unwrap();
    let tls = WssTls::from_pem(&c.cert.pem(), &c.key_pair.serialize_pem()).unwrap();
    let der = tls.chain[0].clone();
    (tls, der)
}

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn server() -> (N, Multiaddr, Vec<u8>) {
    let (tls, der) = cert();
    let b = start(NodeConfig { listen: vec!["/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap()], wss: Some(tls), ..Default::default() });
    let addr: Multiaddr = b.status().listening.iter().find(|a| a.contains("/tls/ws")).expect("a wss listener").parse().unwrap();
    assert!(is_wss(&addr));
    (b, addr, der)
}

#[test]
fn a_request_over_websocket_tls() {
    let (b, addr, der) = server();
    let a = start(NodeConfig { wss: Some(WssTls { trust: vec![der], ..Default::default() }), ..Default::default() });
    assert_eq!(a.dial(addr.clone()).unwrap(), b.peer_id());
    assert_eq!(a.request(b.peer_id(), &[addr], Q(21)).unwrap(), R(42));
    let paths = a.paths(b.peer_id()).unwrap();
    assert_eq!(paths.len(), 1);
}

#[test]
fn an_untrusted_certificate_is_refused() {
    let (b, addr, _) = server();
    let (other, _) = cert();
    let a = start(NodeConfig {
        wss: Some(WssTls { trust: other.chain, ..Default::default() }),
        request_timeout: Duration::from_secs(5),
        ..Default::default()
    });
    assert!(a.request(b.peer_id(), &[addr], Q(1)).is_err());
}

#[test]
fn the_dns_name_form_works_too() {
    let (b, addr, der) = server();
    let port = addr.iter().find_map(|p| if let libp2p::multiaddr::Protocol::Tcp(p) = p { Some(p) } else { None }).unwrap();
    let a = start(NodeConfig { wss: Some(WssTls { trust: vec![der], ..Default::default() }), ..Default::default() });
    let dns: Multiaddr = format!("/dns4/localhost/tcp/{port}/wss/p2p/{}", b.peer_id()).parse().unwrap();
    assert_eq!(a.request(b.peer_id(), &[dns], Q(5)).unwrap(), R(10));
}

#[test]
fn bad_pem_is_an_error() {
    assert!(WssTls::from_pem("nope", "nope").is_err());
}

#[test]
fn a_dns_name_is_checked_against_the_certificate_not_the_ip() {
    // the certificate names only `localhost`: dialing by name must still verify
    let (tls, der) = cert_for(vec!["localhost".into()]);
    let b = start(NodeConfig { listen: vec!["/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap()], wss: Some(tls), ..Default::default() });
    let addr: Multiaddr = b.status().listening.iter().find(|a| a.contains("/tls/ws")).unwrap().parse().unwrap();
    let port = addr.iter().find_map(|p| if let libp2p::multiaddr::Protocol::Tcp(p) = p { Some(p) } else { None }).unwrap();
    let trust = || NodeConfig {
        wss: Some(WssTls { trust: vec![der.clone()], ..Default::default() }),
        request_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    for form in ["tls/ws", "wss"] {
        let a = start(trust());
        let dns: Multiaddr = format!("/dns4/localhost/tcp/{port}/{form}/p2p/{}", b.peer_id()).parse().unwrap();
        assert_eq!(a.request(b.peer_id(), &[dns], Q(4)).unwrap(), R(8), "{form}");
    }
    // by IP the name doesn't match
    let a = start(trust());
    assert!(a.request(b.peer_id(), &[addr], Q(4)).is_err());
}

#[test]
fn sni_is_added_only_to_wss_by_name() {
    use crate::wss::with_sni;
    let m = |s: &str| -> Multiaddr { s.parse().unwrap() };
    assert_eq!(with_sni(&m("/dns4/a.example/tcp/443/tls/ws")), m("/dns4/a.example/tcp/443/tls/sni/a.example/ws"));
    assert_eq!(with_sni(&m("/dns/a.example/tcp/443/wss")), m("/dns/a.example/tcp/443/tls/sni/a.example/ws"));
    for same in [
        "/dns4/a.example/tcp/443/tls/sni/b.example/ws",
        "/ip4/1.2.3.4/tcp/443/tls/ws",
        "/dns4/a.example/tcp/4747",
        "/dns4/a.example/udp/4747/quic-v1",
    ] {
        assert_eq!(with_sni(&m(same)), m(same));
    }
}
