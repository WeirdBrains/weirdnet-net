//! W5 over the in-memory transport: events, the status watch, pause/resume, a network change,
//! reservations that come back, and the async calls.
use crate::events::Event;
use crate::node::{Handler, Node, NodeConfig, RelayLimits};
use crate::stream::Path;
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use futures::StreamExt;
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
        R(q.0 + 1)
    }
}

type N = Node<Q, R>;
const T: Duration = Duration::from_secs(20);

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn mem_addr(n: &N) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")).unwrap().parse().unwrap()
}

fn relay_and_client() -> (N, N) {
    let relay = start(NodeConfig { relay_server: true, relay_limits: RelayLimits::unlimited(), ..mem(true) });
    let raddr = mem_addr(&relay);
    let b = start(NodeConfig { relays: vec![raddr], ..mem(true) });
    let rp = relay.peer_id().to_string();
    let mut w = b.watch_status();
    while !w.get().reservations.contains(&rp) {
        w.wait_change(T).expect("a reservation");
    }
    (relay, b)
}

#[test]
fn connections_show_up_as_events() {
    let b = start(mem(true));
    let a = start(mem(false));
    let mut ev = a.events();
    a.connect(b.peer_id(), &[mem_addr(&b)]).unwrap();
    let bp = b.peer_id();
    assert!(ev.wait_for(T, |e| *e == Event::Connected { peer: bp, path: Path::Direct }).is_some());
    b.stop();
    let e = ev.wait_for(T, |e| matches!(e, Event::Disconnected { .. })).unwrap();
    assert_eq!(e, Event::Disconnected { peer: bp, path: Path::Direct, remaining: 0 });
}

#[test]
fn the_status_watch_sees_a_new_connection() {
    let b = start(mem(true));
    let a = start(mem(false));
    let mut w = a.watch_status();
    assert!(w.get().connected.is_empty());
    a.connect(b.peer_id(), &[mem_addr(&b)]).unwrap();
    let bp = b.peer_id().to_string();
    let mut seen = w.get();
    while !seen.connected.contains(&bp) {
        seen = w.wait_change(T).expect("a change");
    }
}

#[test]
fn a_lost_reservation_is_made_again() {
    let (relay, b) = relay_and_client();
    let mut ev = b.events();
    assert!(b.drop_path(relay.peer_id(), Path::Direct).unwrap() >= 1);
    let rp = relay.peer_id();
    assert!(ev.wait_for(T, |e| *e == Event::ReservationLost { relay: rp }).is_some());
    assert!(ev.wait_for(T, |e| *e == Event::Reserved { relay: rp }).is_some());
    assert!(b.status().reservations.contains(&rp.to_string()));
}

#[test]
fn pause_goes_quiet_and_resume_comes_back() {
    let (relay, b) = relay_and_client();
    let mut ev = b.events();
    b.pause().unwrap();
    assert!(ev.wait_for(T, |e| *e == Event::Paused).is_some());
    let mut w = b.watch_status();
    let mut s = w.get();
    while !(s.paused && s.listening.is_empty() && s.connected.is_empty() && s.reservations.is_empty()) {
        s = w.wait_change(T).unwrap_or_else(|| panic!("still busy: {s:?}"));
    }
    // nothing comes back on its own while paused
    std::thread::sleep(Duration::from_secs(3));
    let s = b.status();
    assert!(s.reservations.is_empty() && s.listening.is_empty(), "{s:?}");

    b.resume().unwrap();
    let rp = relay.peer_id();
    assert!(ev.wait_for(T, |e| *e == Event::Reserved { relay: rp }).is_some());
    assert!(!b.status().paused);
    assert!(b.reachable_addrs().iter().any(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")));
    // reachable through the relay again
    let a = start(mem(false));
    let circuit: Multiaddr = format!("{}/p2p-circuit/p2p/{}", mem_addr(&relay), b.peer_id()).parse().unwrap();
    assert_eq!(a.request(b.peer_id(), &[circuit], Q(1)).unwrap(), R(2));
}

#[test]
fn a_network_change_reconnects_to_the_relay() {
    let (relay, b) = relay_and_client();
    let mut ev = b.events();
    b.network_changed().unwrap();
    let rp = relay.peer_id();
    assert!(ev.wait_for(T, |e| matches!(e, Event::Disconnected { peer, .. } if *peer == rp)).is_some());
    assert!(ev.wait_for(T, |e| *e == Event::Reserved { relay: rp }).is_some());
}

#[test]
fn async_calls_and_the_event_stream() {
    let b = start(mem(true));
    let a = start(mem(false));
    let mut ev = a.events();
    let addr = mem_addr(&b);
    futures::executor::block_on(async {
        assert_eq!(a.dial_async(addr.clone()).await.unwrap(), b.peer_id());
        a.connect_async(b.peer_id(), std::slice::from_ref(&addr)).await.unwrap();
        assert_eq!(a.request_async(b.peer_id(), &[addr], Q(41)).await.unwrap(), R(42));
        let first = ev.next().await.unwrap();
        assert!(matches!(first, Event::Connected { .. }), "{first:?}");
    });
}
