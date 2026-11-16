//! A relay between two nodes over the in-memory transport: B is reachable only through
//! the relay's circuit, and how much an answer may carry is the relay's limits.
use crate::node::{Handler, Node, NodeConfig, RelayLimits};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Q {
    Get(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum R {
    Blob(Vec<u8>),
}

struct Blobs;

impl Handler<Q, R> for Blobs {
    fn request(&self, _: &PeerId, req: Q) -> R {
        let Q::Get(n) = req;
        R::Blob(vec![7; n])
    }
}

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

type Line = (Node<Q, R>, Node<Q, R>, Node<Q, R>, Multiaddr);

/// Relay R, B reserved on R (no listener of its own), A dialing B through R's circuit.
fn line_up(limits: RelayLimits) -> Line {
    let relay =
        Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { relay_server: true, relay_limits: limits, ..mem(true) }, Arc::new(Blobs))
            .unwrap();
    let raddr: Multiaddr = relay.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap();
    let b = Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { relays: vec![raddr.clone()], ..mem(false) }, Arc::new(Blobs)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !b.status().reservations.contains(&relay.peer_id().to_string()) {
        assert!(Instant::now() < deadline, "no reservation on the relay");
        std::thread::sleep(Duration::from_millis(20));
    }
    let a = Node::start(&WEIRDNET, Keypair::generate_ed25519(), mem(false), Arc::new(Blobs)).unwrap();
    let circuit = format!("{raddr}/p2p-circuit/p2p/{}", b.peer_id()).parse().unwrap();
    (relay, b, a, circuit)
}

#[test]
fn default_relay_limits_are_libp2ps() {
    let d = RelayLimits::default();
    assert_eq!((d.max_circuit_duration, d.max_circuit_bytes), (Duration::from_secs(120), 1 << 17));
    assert_eq!((d.max_reservations, d.max_circuits), (128, 16));
    assert!(d.check().is_ok());
    let u = RelayLimits::unlimited();
    assert_eq!((u.max_circuit_bytes, u.max_circuit_duration), (0, RelayLimits::MAX_CIRCUIT_DURATION));
    assert!(u.check().is_ok() && u.is_unlimited() && !d.is_unlimited());
}

#[test]
fn bad_relay_limits_are_refused() {
    let bad = [
        RelayLimits { max_circuits: 0, ..RelayLimits::default() },
        RelayLimits { max_reservations_per_peer: 0, ..RelayLimits::default() },
        RelayLimits { reservation_duration: Duration::ZERO, ..RelayLimits::default() },
        RelayLimits { max_circuit_duration: RelayLimits::MAX_CIRCUIT_DURATION + Duration::from_secs(1), ..RelayLimits::default() },
    ];
    for l in bad {
        assert!(l.check().is_err(), "{l:?}");
        let cfg = NodeConfig { relay_server: true, relay_limits: l, ..mem(true) };
        assert!(Node::<Q, R>::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(Blobs)).is_err());
    }
    // a node that relays nothing ignores them
    let cfg = NodeConfig { relay_limits: bad[0], ..mem(true) };
    assert!(Node::<Q, R>::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(Blobs)).is_ok());
}

#[test]
fn small_answers_cross_a_default_relay_and_large_ones_do_not() {
    let (_relay, b, a, circuit) = line_up(RelayLimits::default());
    match a.request(b.peer_id(), std::slice::from_ref(&circuit), Q::Get(1024)).unwrap() {
        R::Blob(v) => assert_eq!(v.len(), 1024),
    }
    assert!(a.request(b.peer_id(), std::slice::from_ref(&circuit), Q::Get(512 * 1024)).is_err());
}

#[test]
fn an_unlimited_relay_carries_large_answers() {
    let (_relay, b, a, circuit) = line_up(RelayLimits::unlimited());
    for _ in 0..2 {
        match a.request(b.peer_id(), std::slice::from_ref(&circuit), Q::Get(2 * 1024 * 1024)).unwrap() {
            R::Blob(v) => assert_eq!(v.len(), 2 * 1024 * 1024),
        }
    }
}

#[test]
fn the_first_request_through_a_relay_waits_for_the_bootstrap_dial() {
    // A bootstraps from the relay and asks B through the relay's circuit straight away,
    // while its bootstrap dial to the same relay is still under way.
    for _ in 0..5 {
        let (relay, b, _a, circuit) = line_up(RelayLimits::unlimited());
        let raddr: Multiaddr = relay.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap();
        let a = Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { bootstrap: vec![raddr], ..mem(false) }, Arc::new(Blobs)).unwrap();
        match a.request(b.peer_id(), std::slice::from_ref(&circuit), Q::Get(16)).unwrap() {
            R::Blob(v) => assert_eq!(v.len(), 16),
        }
        // and a plain dial of the circuit too
        let a2 = Node::<Q, R>::start(
            &WEIRDNET,
            Keypair::generate_ed25519(),
            NodeConfig { bootstrap: vec![crate::addr::circuit_relay(&circuit).unwrap().1], ..mem(false) },
            Arc::new(Blobs),
        )
        .unwrap();
        assert_eq!(a2.dial(circuit.clone()).unwrap(), b.peer_id());
    }
}

#[test]
fn request_caps_come_from_the_config() {
    let small = NodeConfig { response_max: 4096, ..mem(true) };
    let b = Node::start(&WEIRDNET, Keypair::generate_ed25519(), small, Arc::new(Blobs)).unwrap();
    let addr: Multiaddr = b.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap();
    let a = Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { response_max: 4096, ..mem(false) }, Arc::new(Blobs)).unwrap();
    assert!(a.request(b.peer_id(), std::slice::from_ref(&addr), Q::Get(1000)).is_ok());
    assert!(a.request(b.peer_id(), std::slice::from_ref(&addr), Q::Get(100_000)).is_err());
}
