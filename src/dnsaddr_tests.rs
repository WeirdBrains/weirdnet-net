//! W7: the `_dnsaddr` record helper, and a node dialing `/dnsaddr/<name>` through a DNS
//! server (a tiny one on loopback) that serves exactly that record.
use crate::addr::{dnsaddr_dial, dnsaddr_record, dnsaddr_txt};
use crate::node::{Handler, Node, NodeConfig};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Q(u8);
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct R(u8);
struct H;
impl Handler<Q, R> for H {
    fn request(&self, _: &PeerId, q: Q) -> R {
        R(q.0 + 1)
    }
}
type N = Node<Q, R>;

fn start(cfg: NodeConfig) -> N {
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

/// Answers TXT queries from `txt` and A queries with 127.0.0.1; nothing else.
fn dns_server(txt: HashMap<String, Vec<String>>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let q = &buf[..n];
            if q.len() < 12 {
                continue;
            }
            // the question: labels, then type and class
            let mut i = 12;
            let mut labels = vec![];
            while i < q.len() && q[i] != 0 {
                let l = q[i] as usize;
                labels.push(String::from_utf8_lossy(&q[i + 1..i + 1 + l]).to_ascii_lowercase());
                i += 1 + l;
            }
            let qend = i + 5;
            if qend > q.len() {
                continue;
            }
            let qtype = u16::from_be_bytes([q[i + 1], q[i + 2]]);
            let name = labels.join(".");
            let mut answers: Vec<(u16, Vec<u8>)> = vec![];
            match qtype {
                16 => {
                    for t in txt.get(&name).into_iter().flatten() {
                        let mut r = vec![t.len() as u8];
                        r.extend_from_slice(t.as_bytes());
                        answers.push((16, r));
                    }
                }
                1 if txt.keys().any(|k| k.ends_with(&name)) => answers.push((1, vec![127, 0, 0, 1])),
                _ => {}
            }
            let mut out = vec![q[0], q[1], 0x81, 0x80, 0, 1, 0, answers.len() as u8, 0, 0, 0, 0];
            out.extend_from_slice(&q[12..qend]);
            for (t, rdata) in answers {
                out.extend_from_slice(&[0xC0, 0x0C]);
                out.extend_from_slice(&t.to_be_bytes());
                out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                out.extend_from_slice(&rdata);
            }
            let _ = sock.send_to(&out, from);
        }
    });
    addr
}

#[test]
fn the_record_says_what_libp2p_reads() {
    let p = PeerId::random();
    let (name, value) = dnsaddr_record("Home.Example.com.", 4747, &p).unwrap();
    assert_eq!(name, "_dnsaddr.home.example.com");
    assert_eq!(value, format!("dnsaddr=/dns/home.example.com/tcp/4747/p2p/{p}"));
    assert_eq!(dnsaddr_dial("home.example.com", &p).to_string(), format!("/dnsaddr/home.example.com/p2p/{p}"));
    assert!(dnsaddr_record("not a name", 1, &p).is_err());
    assert!(dnsaddr_txt(&"/ip4/1.2.3.4/tcp/1".parse().unwrap()).is_err());
}

#[test]
fn a_node_is_dialed_by_its_dnsaddr() {
    let b = start(NodeConfig { listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], ..Default::default() });
    let port = b
        .status()
        .listening
        .iter()
        .find_map(|a| a.parse::<Multiaddr>().ok()?.iter().find_map(|p| if let libp2p::multiaddr::Protocol::Tcp(p) = p { Some(p) } else { None }))
        .unwrap();
    let host = "node.weirdnet-test.example";
    let (name, value) = dnsaddr_record(host, port, &b.peer_id()).unwrap();
    // a stale record for another node sits beside it: libp2p skips it by peer id
    let other = format!("dnsaddr=/dns/{host}/tcp/1/p2p/{}", PeerId::random());
    let dns = dns_server(HashMap::from([(name, vec![other, value])]));
    let a = start(NodeConfig { dns_servers: vec![dns], ..Default::default() });
    let to = dnsaddr_dial(host, &b.peer_id());
    assert_eq!(a.request(b.peer_id(), &[to], Q(1)).unwrap(), R(2));
}
