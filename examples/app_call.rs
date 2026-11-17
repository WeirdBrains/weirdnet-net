//! Serve an app and call it over TCP.
//!
//! ```text
//! app_call serve [PORT]                     serve "echo" on 0.0.0.0:PORT (default 4748)
//! app_call call ADDR/p2p/PEER [PATH]        call it and print the answer
//! ```
//! The server answers every call with its method and path and streams the request body back.
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use weirdnet_net::addr::addr_peer;
use weirdnet_net::{AppRequest, AppResponse, Keypair, Multiaddr, Node, NodeConfig, PeerId, WEIRDNET};

struct NoRequests;
impl weirdnet_net::Handler<(), ()> for NoRequests {
    fn request(&self, _: &PeerId, _: ()) {}
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(args.get(1).and_then(|p| p.parse().ok()).unwrap_or(4748)),
        Some("call") if args.len() >= 2 => call(&args[1], args.get(2).map(String::as_str).unwrap_or("/")),
        _ => {
            eprintln!("usage: app_call serve [PORT] | app_call call ADDR/p2p/PEER [PATH]");
            std::process::exit(2);
        }
    }
}

fn serve(port: u16) {
    let cfg = NodeConfig { listen: NodeConfig::default_listen(port), ..Default::default() };
    let node = Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(NoRequests)).expect("start");
    node.serve_app(
        "echo",
        Arc::new(|peer: PeerId, req: AppRequest| async move {
            println!("{peer}: {} {}", req.method, req.path_with_query);
            Ok(AppResponse::new(200).header("x-method", &req.method).header("x-path", &req.path_with_query).body(req.body))
        }),
    )
    .expect("serve");
    println!("serving echo as {}", node.peer_id());
    std::thread::sleep(Duration::from_secs(1));
    for a in node.reachable_addrs() {
        println!("  {a}");
    }
    loop {
        std::thread::park();
    }
}

fn call(addr: &str, path: &str) {
    let addr: Multiaddr = addr.parse().expect("an address");
    let peer = addr_peer(&addr).expect("an address ending in /p2p/PEER");
    let node = Node::<(), ()>::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig::default(), Arc::new(NoRequests)).expect("start");
    let req = AppRequest::new("echo", "POST", path).header("content-type", "text/plain").body("hello over weirdnet");
    let resp = futures::executor::block_on(node.app_call_via(peer, &[addr], req, Duration::from_secs(30))).expect("call");
    println!("{} {:?}", resp.status, resp.headers);
    let mut body = resp.body;
    while let Some(chunk) = futures::executor::block_on(body.next()) {
        print!("{}", String::from_utf8_lossy(&chunk.expect("body")));
    }
    println!();
}
