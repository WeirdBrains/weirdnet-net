//! App calls between in-process nodes: direct and through a relay, streamed bodies both ways,
//! no handler, timeouts, cancellation and the caps.
use crate::app::{AppError, AppRequest, AppResponse, Body};
use crate::names::{Entry, Names};
use crate::node::{Handler, Node, NodeConfig, RelayLimits};
use crate::user::{NodeCert, user_id};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET, now_ms};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

const T: Duration = Duration::from_secs(20);

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

fn start(cfg: NodeConfig) -> N {
    start_with(Keypair::generate_ed25519(), cfg)
}

fn start_with(key: Keypair, cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, key, cfg, Arc::new(H)).unwrap()
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

/// Echoes the request: status 200, the method and path as headers, the body streamed back as it comes.
fn serve_echo(n: &N, app: &str) {
    n.serve_app(
        app,
        Arc::new(|peer: PeerId, req: AppRequest| async move {
            Ok(AppResponse::new(200)
                .header("x-method", &req.method)
                .header("x-path", &req.path_with_query)
                .header("x-peer", &peer.to_string())
                .header("x-in", req.headers.iter().find(|(k, _)| k == "x-in").map(|(_, v)| v.as_str()).unwrap_or(""))
                .body(req.body))
        }),
    )
    .unwrap();
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// `data` as a body of `chunk`-sized pieces.
fn chunked(data: &[u8], chunk: usize) -> Body {
    let parts: Vec<Result<Vec<u8>, AppError>> = data.chunks(chunk).map(|c| Ok(c.to_vec())).collect();
    Body::stream(futures::stream::iter(parts))
}

#[test]
fn a_direct_call_streams_large_bodies_both_ways() {
    let b = start(mem(true));
    serve_echo(&b, "echo");
    let a = start(mem(false));
    let data = pattern(5 * 1024 * 1024 + 17);
    let req = AppRequest::new("echo", "POST", "/up?x=1").header("x-in", "hi").body(chunked(&data, 100_000));
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], req, T)).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header_value("x-method"), Some("POST"));
    assert_eq!(resp.header_value("x-path"), Some("/up?x=1"));
    assert_eq!(resp.header_value("x-in"), Some("hi"));
    assert_eq!(resp.header_value("x-peer"), Some(a.peer_id().to_string().as_str()));
    let got = run(resp.body.collect()).unwrap();
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    // a second call on the same connection, empty bodies
    let resp = run(a.app_call(b.peer_id(), AppRequest::new("echo", "GET", "/"), T)).unwrap();
    assert!(run(resp.body.collect()).unwrap().is_empty());
    // the app is announced
    assert_eq!(a.peer_apps(b.peer_id()), Some(vec!["echo".to_string()]));
    assert_eq!(b.served_apps(), vec!["echo".to_string()]);
}

#[test]
fn a_response_streams_before_the_request_body_ends() {
    // the handler answers at once and streams its body while the request body still flows
    let b = start(mem(true));
    serve_echo(&b, "echo");
    let a = start(mem(false));
    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Vec<u8>, AppError>>();
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("echo", "POST", "/").body(Body::stream(rx)), T)).unwrap();
    let mut body = resp.body;
    for i in 0..5u8 {
        tx.unbounded_send(Ok(vec![i; 1000])).unwrap();
        let mut got = vec![];
        while got.len() < 1000 {
            got.extend(run(body.next()).unwrap().unwrap());
        }
        assert_eq!(got, vec![i; 1000]);
    }
    drop(tx);
    assert!(run(body.next()).is_none(), "the end follows the request's end");
}

#[test]
fn no_handler_for_an_app_or_a_node_serving_none() {
    let b = start(mem(true));
    serve_echo(&b, "echo");
    let a = start(mem(false));
    let e = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("other", "GET", "/"), T)).unwrap_err();
    assert_eq!(e, AppError::NoHandler);
    let c = start(mem(true));
    let e = run(a.app_call_via(c.peer_id(), &[mem_addr(&c)], AppRequest::new("echo", "GET", "/"), T)).unwrap_err();
    assert_eq!(e, AppError::NoHandler);
    // stopped serving: no handler either
    assert!(b.stop_serving_app("echo"));
    let e = run(a.app_call(b.peer_id(), AppRequest::new("echo", "GET", "/"), T)).unwrap_err();
    assert_eq!(e, AppError::NoHandler);
    assert!(b.serve_app("Bad_Name", Arc::new(|_: PeerId, _: AppRequest| async { Ok(AppResponse::new(200)) })).is_err());
}

#[test]
fn handler_errors_and_refusals_reach_the_caller() {
    let b = start(mem(true));
    b.serve_app("gate", Arc::new(|_: PeerId, req: AppRequest| async move { Err(AppError::Refused(format!("not {}", req.path_with_query))) }))
        .unwrap();
    let a = start(mem(false));
    let e = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("gate", "GET", "/x"), T)).unwrap_err();
    assert_eq!(e, AppError::Refused("not /x".into()));
}

#[test]
fn a_handler_that_never_answers_times_out() {
    let b = start(mem(true));
    b.serve_app("slow", Arc::new(|_: PeerId, _: AppRequest| futures::future::pending())).unwrap();
    let a = start(mem(false));
    let t0 = Instant::now();
    let e = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("slow", "GET", "/"), Duration::from_millis(700))).unwrap_err();
    assert_eq!(e, AppError::TimedOut);
    assert!(t0.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_body_that_stops_flowing_times_out() {
    let b = start(mem(true));
    b.serve_app(
        "drip",
        Arc::new(|_: PeerId, _: AppRequest| async {
            let s = futures::stream::iter([Ok(b"first".to_vec())]).chain(futures::stream::pending());
            Ok(AppResponse::new(200).body(Body::stream(s)))
        }),
    )
    .unwrap();
    let a = start(NodeConfig { app_idle_timeout: Duration::from_millis(500), ..mem(false) });
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("drip", "GET", "/"), T)).unwrap();
    let mut body = resp.body;
    assert_eq!(run(body.next()).unwrap().unwrap(), b"first");
    let t0 = Instant::now();
    assert_eq!(run(body.next()).unwrap().unwrap_err(), AppError::TimedOut);
    assert!(t0.elapsed() < Duration::from_secs(5));
}

struct Flag(Arc<AtomicBool>);
impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn dropping_the_response_body_cancels_the_call_on_the_server() {
    let b = start(mem(true));
    let dropped = Arc::new(AtomicBool::new(false));
    let d2 = dropped.clone();
    b.serve_app(
        "forever",
        Arc::new(move |_: PeerId, _: AppRequest| {
            let flag = Flag(d2.clone());
            async move {
                // an endless body; the flag drops with the stream
                let s = futures::stream::unfold(flag, |f| async move {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    Some((Ok(vec![1u8; 4096]), f))
                });
                Ok(AppResponse::new(200).body(Body::stream(s)))
            }
        }),
    )
    .unwrap();
    let a = start(mem(false));
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("forever", "GET", "/"), T)).unwrap();
    let mut body = resp.body;
    for _ in 0..3 {
        run(body.next()).unwrap().unwrap();
    }
    assert!(!dropped.load(Ordering::SeqCst));
    drop(body);
    wait_for("the server's body to drop", Duration::from_secs(10), || dropped.load(Ordering::SeqCst));
}

#[test]
fn dropping_the_call_cancels_the_handler() {
    let b = start(mem(true));
    let dropped = Arc::new(AtomicBool::new(false));
    let d2 = dropped.clone();
    b.serve_app(
        "hang",
        Arc::new(move |_: PeerId, req: AppRequest| {
            let flag = Flag(d2.clone());
            async move {
                // reads the request body (which never ends) and holds the flag meanwhile
                let _f = flag;
                let _ = req.body.collect().await;
                Ok(AppResponse::new(200))
            }
        }),
    )
    .unwrap();
    let a = start(mem(false));
    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Vec<u8>, AppError>>();
    tx.unbounded_send(Ok(vec![0; 10])).unwrap();
    let e =
        run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("hang", "POST", "/").body(Body::stream(rx)), Duration::from_millis(500)))
            .unwrap_err();
    assert_eq!(e, AppError::TimedOut);
    // the stream closes with the call: the handler's body read ends and the handler with it
    wait_for("the handler to end", Duration::from_secs(10), || dropped.load(Ordering::SeqCst));
    drop(tx);
}

#[test]
fn heads_over_the_cap_are_too_large_on_either_side() {
    let b = start(mem(true));
    serve_echo(&b, "echo");
    b.serve_app("big", Arc::new(|_: PeerId, _: AppRequest| async { Ok(AppResponse::new(200).header("x-big", &"y".repeat(20_000))) })).unwrap();
    let big = "z".repeat(20_000);
    // the caller's own cap
    let a = start(mem(false));
    let e = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("echo", "GET", "/").header("x-big", &big), T)).unwrap_err();
    assert_eq!(e, AppError::TooLarge);
    // a caller with a bigger cap: the server's cap
    let c = start(NodeConfig { app_header_max: 1 << 20, ..mem(false) });
    let e = run(c.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("echo", "GET", "/").header("x-big", &big), T)).unwrap_err();
    assert_eq!(e, AppError::TooLarge);
    // a response head over the server's cap
    let e = run(c.app_call(b.peer_id(), AppRequest::new("big", "GET", "/"), T)).unwrap_err();
    assert_eq!(e, AppError::TooLarge);
    // just under the cap goes through
    let ok = "w".repeat(15_000);
    let resp = run(a.app_call(b.peer_id(), AppRequest::new("echo", "GET", "/").header("x-in", &ok), T)).unwrap();
    assert_eq!(resp.header_value("x-in"), Some(ok.as_str()));
}

#[test]
fn a_body_cap_when_set() {
    let b = start(NodeConfig { app_body_max: 10_000, ..mem(true) });
    b.serve_app(
        "sink",
        Arc::new(|_: PeerId, req: AppRequest| async move {
            let got = req.body.collect().await?;
            Ok(AppResponse::new(200).body(got.len().to_string()))
        }),
    )
    .unwrap();
    let a = start(mem(false));
    let resp = run(a.app_call_via(b.peer_id(), &[mem_addr(&b)], AppRequest::new("sink", "POST", "/").body(vec![0u8; 10_000]), T)).unwrap();
    assert_eq!(run(resp.body.collect()).unwrap(), b"10000");
    let e = run(a.app_call(b.peer_id(), AppRequest::new("sink", "POST", "/").body(chunked(&pattern(30_000), 3000)), T)).unwrap_err();
    assert_eq!(e, AppError::TooLarge);
}

// ---------- through a relay, found by user id or name ----------

struct User {
    key: Keypair,
    id: String,
}

fn cert(u: &User, node: &Keypair) -> NodeCert {
    WEIRDNET.certify(&u.key, &u.id, &node.public().to_peer_id().to_string(), "phone", now_ms() - 1000).unwrap()
}

/// Relay R (a names server too); B serves "echo", listens nowhere of its own, holds a
/// reservation on R and has its record there; A knows R as a names server only.
fn relayed() -> (N, N, N, User) {
    let relay = start(NodeConfig { relay_server: true, relay_limits: RelayLimits::unlimited(), names_server: Some(Names::memory()), ..mem(true) });
    let raddr = mem_addr(&relay);
    let bkey = Keypair::generate_ed25519();
    let b = start_with(bkey.clone(), NodeConfig { relays: vec![raddr.clone()], ..mem(false) });
    serve_echo(&b, "echo");
    wait_for("a reservation", T, || b.status().reservations.contains(&relay.peer_id().to_string()));
    let ukey = Keypair::generate_ed25519();
    let u = User { id: user_id(&ukey.public()), key: ukey };
    let circuit: Multiaddr = format!("{raddr}/p2p-circuit/p2p/{}", b.peer_id()).parse().unwrap();
    let rec = WEIRDNET.peer_record(&bkey, &u.key.public(), &cert(&u, &bkey), &[circuit], Some(&raddr), 1, now_ms(), 3600 * 1000).unwrap();
    assert_eq!(b.register_everywhere(&Entry::Record(rec)), 1);
    let dns = crate::dnsaddr_tests::dns_server([("_weirdnet.ann.test".to_string(), vec![crate::names::binding_txt(&u.id)])].into_iter().collect());
    let a = start(NodeConfig { names_servers: vec![raddr], dns_servers: vec![dns], ..mem(false) });
    (relay, b, a, u)
}

#[test]
fn a_call_through_a_relay_to_a_user_found_by_id_or_name() {
    let (_relay, b, a, u) = relayed();
    let found = a.resolve_app("echo", &u.id).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, b.peer_id());
    assert!(found[0].1.iter().any(|a| a.to_string().contains("p2p-circuit")));
    let data = pattern(2 * 1024 * 1024);
    let resp = run(a.app_call(b.peer_id(), AppRequest::new("echo", "PUT", "/f").body(chunked(&data, 50_000)), T)).unwrap();
    assert_eq!(resp.status, 200);
    assert!(run(resp.body.collect()).unwrap() == data);
    // by name, and by peer id
    assert_eq!(a.resolve_app("echo", "ann.test").unwrap()[0].0, b.peer_id());
    assert_eq!(a.resolve_app("echo", &b.peer_id().to_string()).unwrap()[0].0, b.peer_id());
    // what it doesn't serve, and who isn't there
    assert_eq!(a.resolve_app("other", &u.id).unwrap_err(), AppError::NoHandler);
    assert_eq!(a.resolve_app("echo", "nobody.test").unwrap_err(), AppError::NotFound);
    assert_eq!(a.resolve_app("echo", &"0".repeat(32)).unwrap_err(), AppError::NotFound);
}

#[test]
fn a_serving_node_keeps_its_reservation_when_paused() {
    let (relay, b, a, u) = relayed();
    b.pause().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(b.status().reservations.contains(&relay.peer_id().to_string()), "reservation kept while serving");
    let found = a.resolve_app("echo", &u.id).unwrap();
    let resp = run(a.app_call(found[0].0, AppRequest::new("echo", "POST", "/").body("ping"), T)).unwrap();
    assert_eq!(run(resp.body.collect()).unwrap(), b"ping");
    b.resume().unwrap();
}

#[test]
fn add_relay_dials_every_address_of_the_relay() {
    let relay = start(NodeConfig { relay_server: true, relay_limits: RelayLimits::unlimited(), ..mem(true) });
    let raddr = mem_addr(&relay);
    // an address that doesn't answer comes first: the good one is dialed along with it
    let dead: Multiaddr = format!("/memory/{}/p2p/{}", 4_000_000_000u64 + rand_port(), relay.peer_id()).parse().unwrap();
    let b = start(NodeConfig { relays: vec![dead, raddr], ..mem(false) });
    wait_for("a reservation", Duration::from_secs(10), || b.status().reservations.contains(&relay.peer_id().to_string()));
}

fn rand_port() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as u64 % 1_000_000
}
