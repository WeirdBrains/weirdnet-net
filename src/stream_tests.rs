//! Streams over the in-memory transport: direct, through a relay, moving from the relay to a
//! direct connection and back without losing or repeating a byte, refusals and resets.
use crate::node::{Handler, Node, NodeConfig, RelayLimits};
use crate::stream::{Limits, Path, Stream};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const P: &str = "/weirdnet-test/echo/1";

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn mem_addr(n: &N) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")).unwrap().parse().unwrap()
}

/// An echo server on `n`: every stream gets back what it sends, then the end.
fn echo(n: &N, limits: Limits) {
    let mut inc = n.accept_streams(P, limits).unwrap();
    std::thread::spawn(move || {
        while let Some(s) = inc.accept() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = vec![0u8; 50_000];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => {
                            if s.write_all(&buf[..k]).is_err() {
                                break;
                            }
                        }
                    }
                }
                s.close_write();
                std::thread::sleep(Duration::from_secs(3));
            });
        }
    });
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// Write `data` on one thread while reading the echo on another; returns what came back.
fn round_trip(s: Stream, data: Vec<u8>, mid: impl FnOnce(&Stream) + Send + 'static) -> (Vec<u8>, Stream) {
    let s = Arc::new(std::sync::Mutex::new(s));
    // reads and writes on one handle: split by taking the stream out for each turn is clumsy;
    // instead write in chunks and read back in between.
    let mut s = Arc::try_unwrap(s).unwrap().into_inner().unwrap();
    let mut got = Vec::with_capacity(data.len());
    let mut buf = vec![0u8; 64 * 1024];
    let chunk = 16 * 1024;
    let mut mid = Some(mid);
    for (i, c) in data.chunks(chunk).enumerate() {
        s.write_all(c).unwrap();
        if i == data.len() / chunk / 3 {
            if let Some(f) = mid.take() {
                f(&s);
            }
        }
        // keep the echo flowing so neither window fills
        while got.len() + 2 * chunk < (i + 1) * chunk {
            let k = s.read(&mut buf).unwrap();
            assert!(k > 0, "early end");
            got.extend_from_slice(&buf[..k]);
        }
    }
    s.close_write();
    loop {
        let k = s.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        got.extend_from_slice(&buf[..k]);
    }
    (got, s)
}

fn wait_for(what: &str, d: Duration, f: impl Fn() -> bool) {
    let end = Instant::now() + d;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_direct_stream_carries_more_than_any_request_cap() {
    let b = start(mem(true));
    echo(&b, Limits::default());
    let a = start(mem(false));
    let s = a.open_stream(b.peer_id(), &[mem_addr(&b)], P, Limits::default()).unwrap();
    assert_eq!(s.path(), Path::Direct);
    let data = pattern(12 * 1024 * 1024);
    let (got, s) = round_trip(s, data.clone(), |_| {});
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    assert_eq!(s.moves(), 0);
}

/// Relay R; B reserved on R and listening on its own memory address too; A has only the circuit.
fn line_up() -> (N, N, N, Multiaddr) {
    let relay = start(NodeConfig { relay_server: true, relay_limits: RelayLimits::unlimited(), ..mem(true) });
    let raddr = mem_addr(&relay);
    let b = start(NodeConfig { relays: vec![raddr.clone()], ..mem(true) });
    wait_for("a reservation", Duration::from_secs(20), || b.status().reservations.contains(&relay.peer_id().to_string()));
    let a = start(mem(false));
    let circuit = format!("{raddr}/p2p-circuit/p2p/{}", b.peer_id()).parse().unwrap();
    (relay, b, a, circuit)
}

#[test]
fn a_stream_moves_to_a_direct_connection_and_back_to_the_relay() {
    let (_relay, b, a, circuit) = line_up();
    echo(&b, Limits::default());
    let s = a.open_stream(b.peer_id(), std::slice::from_ref(&circuit), P, Limits::default()).unwrap();
    assert_eq!(s.path(), Path::Relayed);
    let data = pattern(6 * 1024 * 1024);
    let a = Arc::new(a);
    let (a2, baddr, bp) = (a.clone(), mem_addr(&b), b.peer_id());
    let (got, s) = round_trip(s, data.clone(), move |s| {
        // a direct connection comes up (as after hole punching): the stream moves there
        a2.dial(baddr).unwrap();
        wait_for("the move to direct", Duration::from_secs(10), || s.path() == Path::Direct);
        // and goes away again: back through the relay, nothing lost
        assert!(a2.drop_path(bp, Path::Direct).unwrap() >= 1);
        wait_for("the move back to the relay", Duration::from_secs(10), || s.path() == Path::Relayed);
    });
    assert_eq!(got.len(), data.len());
    assert!(got == data, "bytes changed in the moves");
    assert!(s.moves() >= 2, "moves {}", s.moves());
}

#[test]
fn unknown_protocols_and_full_servers_are_refused() {
    let b = start(mem(true));
    let a = start(mem(false));
    let e = a.open_stream(b.peer_id(), &[mem_addr(&b)], "/nobody/1", Limits::default()).unwrap_err();
    assert!(e.to_string().contains("does not accept"), "{e}");
    let _inc = b.accept_streams(P, Limits { backlog: 1, ..Limits::default() }).unwrap();
    assert!(b.accept_streams(P, Limits::default()).is_err(), "a protocol is accepted once");
    // nobody calls accept: the second waiting stream is refused
    let _s1 = a.open_stream(b.peer_id(), &[], P, Limits::default()).unwrap();
    let e = a.open_stream(b.peer_id(), &[], P, Limits::default()).unwrap_err();
    assert!(e.to_string().contains("too many"), "{e}");
}

#[test]
fn a_reset_fails_the_peers_reads() {
    let b = start(mem(true));
    let mut inc = b.accept_streams(P, Limits::default()).unwrap();
    let a = start(mem(false));
    let mut s = a.open_stream(b.peer_id(), &[mem_addr(&b)], P, Limits::default()).unwrap();
    s.write_all(b"hello").unwrap();
    let mut t = inc.accept_timeout(Duration::from_secs(10)).unwrap();
    let mut buf = [0u8; 5];
    t.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    s.reset();
    assert!(t.read(&mut buf).is_err());
}
