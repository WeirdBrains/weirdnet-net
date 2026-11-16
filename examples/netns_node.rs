//! A node for the multi-host harness (`harness/netns.sh`): each runs in its own network
//! namespace, behind its own NAT or on the "internet". Keys come from a seed byte, so the
//! script knows every peer id up front.
//!
//! ```text
//! netns_node id SEED
//! netns_node relay SEED IP              relay + bootstrap + names, TCP and QUIC on 4747
//! netns_node host SEED [RELAY_ADDR]     echo streams and a 3 MiB file; mDNS on
//! netns_node client SEED PEER [RELAY_ADDR] [--expect direct|relay]
//! ```
//! `client` reaches PEER (through the relay's circuit, or on the LAN by mDNS without one),
//! streams 2 MiB through echo while waiting for the path it expects, fetches the file, and
//! prints a JSON verdict (exit status 0 on success).
use libp2p::multiaddr::Protocol;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use weirdnet_net::content::{self, ChunkStore, MemoryStore, Source};
use weirdnet_net::node::RelayLimits;
use weirdnet_net::{Handler, Keypair, Limits, Multiaddr, Node, NodeConfig, Path, PeerId, WEIRDNET};

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

const ECHO: &str = "/weirdnet-harness/echo/1";

fn key(seed: &str) -> Keypair {
    let s: u8 = seed.parse().expect("seed: 1 to 255");
    Keypair::ed25519_from_bytes([s; 32]).unwrap()
}

fn file() -> Vec<u8> {
    let mut x = 0x2545F4914F6CDD1Du64;
    (0..3 << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn ma(s: &str) -> Multiaddr {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

fn report(n: &N) {
    let s = n.status();
    eprintln!("status: nat={} reservations={:?} external={:?} connected={}", s.nat, s.reservations, s.external, s.connected.len());
}

fn run_forever(n: &N) -> ! {
    let mut ev = n.events();
    let mut last = Instant::now();
    loop {
        if let Some(e) = ev.next_timeout(Duration::from_secs(5)) {
            eprintln!("event: {e:?}");
        }
        if last.elapsed() > Duration::from_secs(5) {
            report(n);
            last = Instant::now();
        }
    }
}

fn listen_all(port: u16) -> Vec<Multiaddr> {
    vec![ma(&format!("/ip4/0.0.0.0/tcp/{port}")), ma(&format!("/ip4/0.0.0.0/udp/{port}/quic-v1"))]
}

fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    match a(0) {
        "id" => println!("{}", key(a(1)).public().to_peer_id()),
        "relay" => {
            let ip = a(2);
            let cfg = NodeConfig {
                listen: listen_all(4747),
                external: vec![ma(&format!("/ip4/{ip}/tcp/4747")), ma(&format!("/ip4/{ip}/udp/4747/quic-v1"))],
                relay_server: true,
                relay_limits: RelayLimits::unlimited(),
                names_server: Some(weirdnet_net::names::Names::memory()),
                label: "harness-relay".into(),
                ..Default::default()
            };
            let n: N = Node::start(&WEIRDNET, key(a(1)), cfg, Arc::new(H)).unwrap();
            eprintln!("relay {} on {:?}", n.peer_id(), n.reachable_addrs());
            run_forever(&n)
        }
        "host" => {
            let relay: Vec<Multiaddr> = args.get(2).map(|s| vec![ma(s)]).unwrap_or_default();
            let cfg = NodeConfig {
                listen: listen_all(4001),
                mdns: true,
                relays: relay.clone(),
                bootstrap: relay,
                label: "harness-host".into(),
                ..Default::default()
            };
            let n: N = Node::start(&WEIRDNET, key(a(1)), cfg, Arc::new(H)).unwrap();
            let store: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
            let idx = content::add_bytes(&*store, &file()).unwrap();
            let _srv = content::serve(&n, store, Arc::new(|_, _| true)).unwrap();
            let mut inc = n.accept_streams(ECHO, Limits::default()).unwrap();
            std::thread::spawn(move || {
                while let Some(mut s) = inc.accept() {
                    std::thread::spawn(move || {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(k) = s.read(&mut buf) {
                            if k == 0 || s.write_all(&buf[..k]).is_err() {
                                break;
                            }
                        }
                        s.close_write();
                        std::thread::sleep(Duration::from_secs(5));
                    });
                }
            });
            eprintln!("host {} file {}", n.peer_id(), idx.root_hex());
            run_forever(&n)
        }
        "client" => std::process::exit(client(&args)),
        _ => {
            eprintln!("usage: see the source");
            std::process::exit(2)
        }
    }
}

fn client(args: &[String]) -> i32 {
    let peer: PeerId = args[2].parse().expect("peer id");
    let mut relay: Option<Multiaddr> = None;
    let mut expect = "any".to_string();
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--expect" => {
                expect = args[i + 1].clone();
                i += 1;
            }
            s => relay = Some(ma(s)),
        }
        i += 1;
    }
    let relays: Vec<Multiaddr> = relay.iter().cloned().collect();
    let cfg = NodeConfig {
        listen: listen_all(4002),
        mdns: true,
        relays: relays.clone(),
        bootstrap: relays,
        label: "harness-client".into(),
        ..Default::default()
    };
    let n: N = Node::start(&WEIRDNET, key(&args[1]), cfg, Arc::new(H)).unwrap();
    let started = Instant::now();
    let addrs: Vec<Multiaddr> = relay.iter().map(|r| r.clone().with(Protocol::P2pCircuit).with(Protocol::P2p(peer))).collect();
    let verdict = |ok: bool, what: &str, extra: serde_json::Value| {
        let s = n.status();
        println!(
            "{}",
            serde_json::json!({"ok": ok, "what": what, "nat": s.nat, "reservations": s.reservations, "secs": started.elapsed().as_secs_f32(), "extra": extra})
        );
        if ok { 0 } else { 1 }
    };
    // reach the peer: through the relay, or by mDNS on the LAN
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut stream = loop {
        match n.open_stream(peer, &addrs, ECHO, Limits::default()) {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                eprintln!("open: {e}; retrying");
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => return verdict(false, "open", serde_json::json!(e.to_string())),
        }
    };
    eprintln!("stream open on {:?} after {:?}", stream.path(), started.elapsed());
    let first_path = stream.path();
    // 2 MiB in 64 KiB pieces, each echoed back before the next, slowly at first so the
    // path can change midway
    let data: Vec<u8> = (0..2u32 << 20).map(|i| (i % 251) as u8).collect();
    let mut got = Vec::with_capacity(data.len());
    let mut saw_direct = first_path == Path::Direct;
    for (k, piece) in data.chunks(64 * 1024).enumerate() {
        let mut back = vec![0u8; piece.len()];
        if stream.write_all(piece).and_then(|_| stream.read_exact(&mut back)).is_err() {
            return verdict(false, "echo", serde_json::json!(k));
        }
        got.extend_from_slice(&back);
        if expect == "direct" && !saw_direct {
            std::thread::sleep(Duration::from_millis(300));
            saw_direct = stream.path() == Path::Direct;
        }
    }
    // keep waiting for a direct path for a while if it is expected
    let until = Instant::now() + Duration::from_secs(30);
    while expect == "direct" && stream.path() != Path::Direct && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
    let echo_ok = got == data;
    let path = stream.path();
    let moves = stream.moves();
    let mut f = content::fetch(
        &n,
        &[Source { peer, addrs: addrs.clone() }],
        &content::add_bytes(&MemoryStore::default(), &file()).unwrap().root(),
        Arc::new(MemoryStore::default()),
    );
    if f.is_err() {
        std::thread::sleep(Duration::from_secs(1));
        f = content::fetch(
            &n,
            &[Source { peer, addrs }],
            &content::add_bytes(&MemoryStore::default(), &file()).unwrap().root(),
            Arc::new(MemoryStore::default()),
        );
    }
    let fetched = f.as_ref().map(|(_, st)| st.bytes).unwrap_or(0);
    let path_ok = match expect.as_str() {
        "direct" => path == Path::Direct,
        "relay" => path == Path::Relayed,
        _ => true,
    };
    let ok = echo_ok && path_ok && f.is_ok();
    verdict(
        ok,
        "done",
        serde_json::json!({"echo": echo_ok, "first_path": format!("{first_path:?}"), "path": format!("{path:?}"), "moves": moves, "fetched": fetched, "fetch_error": f.err().map(|e| e.to_string())}),
    )
}
