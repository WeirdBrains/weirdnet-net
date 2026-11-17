//! Peer discovery can be turned off without stopping listen, relays, manual peers,
//! request-response, or serving apps and content to a connected peer.
use crate::app::{AppRequest, AppResponse};
use crate::node::{Handler, Node, NodeConfig};
use crate::peers::{DiscoveryMode, PeerHint};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Q(String);
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R(String);
struct Echo;
impl Handler<Q, R> for Echo {
    fn request(&self, _: &PeerId, req: Q) -> R {
        R(req.0)
    }
}

type N = Node<Q, R>;
const T: Duration = Duration::from_secs(20);

fn quiet(listen: bool) -> NodeConfig {
    NodeConfig {
        listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] },
        memory: true,
        discovery: DiscoveryMode::Disabled,
        ..Default::default()
    }
}

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(Echo)).unwrap()
}

fn mem_addr(n: &N) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")).unwrap().parse().unwrap()
}

fn wait_for(what: &str, d: Duration, f: impl Fn() -> bool) {
    let end = Instant::now() + d;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run<T>(f: impl Future<Output = T>) -> T {
    futures::executor::block_on(f)
}

fn discovery_off(e: &crate::NetError) -> bool {
    e.to_string().contains("peer discovery is disabled")
}

#[test]
fn node_config_enables_discovery_by_default() {
    let cfg = NodeConfig::default();
    assert_eq!(cfg.discovery, DiscoveryMode::Enabled);
    assert!(cfg.peers.is_empty());
}

#[test]
fn a_disabled_node_reports_it_and_rejects_dht_calls() {
    let n = start(NodeConfig { mdns: true, ..quiet(true) });
    let s = n.status();
    assert!(!s.discovery);
    assert!(!s.mdns);
    let other = Keypair::generate_ed25519().public().to_peer_id();
    assert!(discovery_off(&n.find_peer(other).unwrap_err()));
    assert!(discovery_off(&n.provide(b"key").unwrap_err()));
    assert!(discovery_off(&n.providers(b"key").unwrap_err()));
    assert!(discovery_off(&n.get_entries("anyone").unwrap_err()));
}

#[test]
fn discovery_off_still_serves_an_app_over_an_explicit_dial() {
    let b = start(quiet(true));
    b.serve_app("echo", Arc::new(|_: PeerId, req: AppRequest| async move { Ok(AppResponse::new(200).body(req.body)) })).unwrap();
    let a = start(quiet(false));
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("echo", "POST", "/").body(b"hi".to_vec()), T)).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(run(resp.body.collect()).unwrap(), b"hi");
    let r = a.request(b.peer_id(), &[mem_addr(&b)], Q("ping".into())).unwrap();
    assert_eq!(r.0, "ping");
}

#[test]
fn a_manual_peer_is_dialed_with_discovery_off() {
    let b = start(quiet(true));
    let hint = PeerHint::from_addr(&mem_addr(&b).to_string()).unwrap();
    let a = start(NodeConfig { peers: vec![hint.clone()], ..quiet(false) });
    assert_eq!(a.peers().unwrap(), vec![hint.clone()]);
    wait_for("manual peer connected", T, || a.status().connected.contains(&b.peer_id().to_string()));
    assert_eq!(a.request(b.peer_id(), &[], Q("via-hint".into())).unwrap().0, "via-hint");
}

#[test]
fn add_and_remove_peers_and_their_addresses() {
    let b = start(quiet(true));
    let a = start(quiet(false));
    let hint = PeerHint::from_addr(&mem_addr(&b).to_string()).unwrap();
    a.add_peer(hint.clone()).unwrap();
    assert_eq!(a.peers().unwrap(), vec![hint.clone()]);
    // a second address for the same peer is merged
    let again = PeerHint::parse(&b.peer_id().to_string(), [mem_addr(&b).to_string()]).unwrap();
    a.add_peer(again).unwrap();
    assert_eq!(a.peers().unwrap().len(), 1);
    wait_for("added peer connected", T, || a.status().connected.contains(&b.peer_id().to_string()));
    assert_eq!(a.request(b.peer_id(), &[], Q("added".into())).unwrap().0, "added");
    a.remove_peer(b.peer_id()).unwrap();
    assert!(a.peers().unwrap().is_empty());
    // forgetting the hint does not drop the open connection
    assert_eq!(a.request(b.peer_id(), &[], Q("still".into())).unwrap().0, "still");
    assert!(a.add_peer(PeerHint { peer_id: "nope".into(), addrs: vec!["/memory/1".into()] }).is_err());
}
