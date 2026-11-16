//! Sealed streams between two nodes: the exchange checks on the receiving side and an echo.
use crate::node::{Handler, Node, NodeConfig};
use crate::sealed::{self, Exchanges};
use crate::stream::Limits;
use crate::{Keypair, Multiaddr, NetError, PeerId, WEIRDNET};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use weirdnet_keys::Key32;

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
const P: &str = "/weirdnet-test/sealed/1";

struct Book {
    id: String,
    peer: String,
    key: Key32,
    active: bool,
}
impl Exchanges for Book {
    type Exchange = (String, String, bool);
    type Error = NetError;
    fn exchange(&self, id: &str) -> crate::Result<Option<Self::Exchange>> {
        Ok((id == self.id).then(|| (self.id.clone(), self.peer.clone(), self.active)))
    }
    fn active(x: &Self::Exchange) -> bool {
        x.2
    }
    fn peer(x: &Self::Exchange) -> Option<&str> {
        Some(&x.1)
    }
    fn key(&self, _: &Self::Exchange) -> crate::Result<Option<Key32>> {
        Ok(Some(self.key.clone()))
    }
}

fn start(listen: bool) -> N {
    let cfg = NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() };
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn mem_addr(n: &N) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/") && !a.contains("p2p-circuit")).unwrap().parse().unwrap()
}

#[test]
fn sealed_streams_echo_and_refuse_strangers() {
    let b = start(true);
    let a = start(false);
    let m = start(false);
    let key = Key32::random().unwrap();
    let book = Arc::new(Book { id: "ex1".into(), peer: a.peer_id().to_string(), key: key.clone(), active: true });
    let mut inc = b.accept_streams(P, Limits::default()).unwrap();
    let (bp, book2) = (b.peer_id(), book.clone());
    let errors = Arc::new(std::sync::Mutex::new(Vec::new()));
    let errs = errors.clone();
    std::thread::spawn(move || {
        while let Some(s) = inc.accept() {
            let (book, errs) = (book2.clone(), errs.clone());
            std::thread::spawn(move || {
                let from = s.peer();
                block_on(async {
                    match sealed::serve_stream(&WEIRDNET, &*book, s, &bp, &from).await {
                        Ok((mut ss, x)) => {
                            assert_eq!(x.0, "ex1");
                            let got = ss.read_to_end().await.unwrap();
                            ss.send(b"echo:").await.unwrap();
                            ss.send(&got).await.unwrap();
                            ss.finish().await.unwrap();
                        }
                        Err(e) => errs.lock().unwrap().push(e.to_string()),
                    }
                });
            });
        }
    });
    let addr = mem_addr(&b);
    let open = |n: &N, id: &str, k: &Key32| {
        let s = n.open_stream(bp, std::slice::from_ref(&addr), P, Limits::default()).unwrap();
        block_on(sealed::open_stream(&WEIRDNET, s, &n.peer_id(), &sealed::Exchange { id, key: k, peer: bp }))
    };
    let big: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let mut ss = open(&a, "ex1", &key).unwrap();
    block_on(async {
        ss.send(&big).await.unwrap();
        ss.finish().await.unwrap();
        let back = ss.read_to_end().await.unwrap();
        assert_eq!(&back[..5], b"echo:");
        assert!(back[5..] == big[..]);
    });
    // Unknown exchange, someone else's exchange: refused before any data.
    assert!(open(&a, "nope", &key).unwrap_err().to_string().contains("refused"));
    assert!(open(&m, "ex1", &key).unwrap_err().to_string().contains("refused"));
    // The right exchange with the wrong key gets through the handshake but no frame opens.
    let wrong = Key32::random().unwrap();
    let mut ss = open(&a, "ex1", &wrong).unwrap();
    block_on(async {
        ss.send(b"hi").await.unwrap();
        ss.finish().await.unwrap();
        assert!(ss.recv().await.is_err());
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    let e = errors.lock().unwrap().clone();
    assert!(e.iter().any(|x| x.contains("unknown exchange")), "{e:?}");
    assert!(e.iter().any(|x| x.contains("another node")), "{e:?}");
}
