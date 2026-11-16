//! Content: chunking that survives edits, indexes, manifests, and fetching over the
//! in-memory transport from one and several peers, by delta, by range and after interruption.
use crate::content::{self, ChunkStore, DirStore, FileIndex, Manifest, ManifestDraft, ManifestEntry, MemoryStore, Source};
use crate::node::{Handler, Node, NodeConfig};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

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

fn start() -> N {
    let cfg = NodeConfig { listen: vec!["/memory/0".parse().unwrap()], memory: true, ..Default::default() };
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn src(n: &N) -> Source {
    let a: Multiaddr = n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap();
    Source { peer: n.peer_id(), addrs: vec![a] }
}

/// Deterministic noise.
fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn hashes(i: &FileIndex) -> HashSet<[u8; 32]> {
    i.chunks.iter().map(|c| c.1).collect()
}

fn everyone() -> content::Allow {
    Arc::new(|_, _| true)
}

#[test]
fn chunks_survive_an_insertion() {
    let a = data(3 << 20, 1);
    let mut b = a.clone();
    b.splice(1_500_000..1_500_000, b"an edit in the middle".iter().copied());
    let (sa, sb) = (MemoryStore::default(), MemoryStore::default());
    let (ia, ib) = (content::add_bytes(&sa, &a).unwrap(), content::add_bytes(&sb, &b).unwrap());
    assert_eq!(ia.size, a.len() as u64);
    assert!(ia.chunks.iter().all(|c| (c.0 as usize) <= content::MAX_CHUNK));
    assert!(ia.chunks.len() > 10, "{} chunks", ia.chunks.len());
    let changed = hashes(&ib).difference(&hashes(&ia)).count();
    assert!(changed <= 3, "{changed} of {} chunks changed", ib.chunks.len());
    let mut out = vec![];
    content::write_to(&sb, &ib, &mut out).unwrap();
    assert_eq!(out, b);
    assert_eq!(content::index(&sb, &ib.root()).unwrap(), ib);
}

#[test]
fn index_round_trips_and_rejects_garbage() {
    let s = MemoryStore::default();
    let i = content::add_bytes(&s, &data(700_000, 2)).unwrap();
    assert_eq!(FileIndex::decode(&i.encode()).unwrap(), i);
    let mut bad = i.encode();
    bad[9] ^= 1;
    assert!(FileIndex::decode(&bad).is_err());
    assert!(FileIndex::decode(b"nope").is_err());
    let empty = content::add_bytes(&s, b"").unwrap();
    assert_eq!(empty.size, 0);
    assert!(empty.chunks.is_empty());
}

#[test]
fn range_reads_cut_at_any_offset() {
    let d = data(1 << 20, 3);
    let s = MemoryStore::default();
    let i = content::add_bytes(&s, &d).unwrap();
    for (o, l) in [(0, 10), (12_345, 300_000), (d.len() as u64 - 5, 100), (d.len() as u64 + 5, 10), (0, u64::MAX)] {
        let end = (o.saturating_add(l)).min(d.len() as u64) as usize;
        let want = if (o as usize) < d.len() { &d[o as usize..end] } else { &[][..] };
        assert_eq!(content::read_range(&s, &i, o, l).unwrap(), want, "{o}+{l}");
    }
}

#[test]
fn dir_store_keeps_chunks() {
    let dir = std::env::temp_dir().join(format!("wn-content-{}", std::process::id()));
    let s = DirStore::new(&dir).unwrap();
    let d = data(400_000, 4);
    let i = content::add_bytes(&s, &d).unwrap();
    let s2 = DirStore::new(&dir).unwrap();
    let mut out = vec![];
    content::write_to(&s2, &content::index(&s2, &i.root()).unwrap(), &mut out).unwrap();
    assert_eq!(out, d);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn manifests_are_signed_and_checked() {
    let user = Keypair::generate_ed25519();
    let s = MemoryStore::default();
    let r = content::add_bytes(&s, b"<h1>hi</h1>").unwrap().root_hex();
    let e = |p: &str| ManifestEntry { path: p.into(), root: r.clone(), size: 11, meta: b"text/html".to_vec() };
    let d = |version, entries, revoked| ManifestDraft { id: "site".into(), version, entries, revoked, ..Default::default() };
    let now = crate::now_ms();
    let m = Manifest::sign(&user, d(2, vec![e("index.html"), e("a/b.html")], vec![]), now).unwrap();
    m.verify(now).unwrap();
    assert_eq!(m.entries[0].path, "a/b.html");
    assert_eq!(m.entry("index.html").unwrap().meta, b"text/html");
    let back: Manifest = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    back.verify(now).unwrap();

    let mut t = m.clone();
    t.entries[1].size = 12;
    assert!(t.verify(now).is_err(), "tampered");
    let mut t = m.clone();
    t.user_key = Keypair::generate_ed25519().public().encode_protobuf();
    assert!(t.verify(now).is_err(), "someone else's key");
    for bad in ["../x", "/etc", "a//b", "", "a/./b"] {
        assert!(Manifest::sign(&user, d(1, vec![e(bad)], vec![]), now).is_err(), "{bad}");
    }
    assert!(Manifest::sign(&user, d(1, vec![e("x"), e("x")], vec![]), now).is_err(), "repeated path");

    let newer = Manifest::sign(&user, d(3, vec![e("index.html")], vec![r.clone()]), now).unwrap();
    assert!(newer.supersedes(&m) && !m.supersedes(&newer));
    assert!(newer.is_revoked(&content::parse_hash(&r).unwrap()));
}

#[test]
fn fetch_gets_a_file_then_only_what_changed() {
    let (host, me) = (start(), start());
    let hs: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let _srv = content::serve(&host, hs.clone(), everyone()).unwrap();

    let v1 = data(2 << 20, 5);
    let i1 = content::add_bytes(&*hs, &v1).unwrap();
    let mine: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let (got, st) = content::fetch(&me, &[src(&host)], &i1.root(), mine.clone()).unwrap();
    assert_eq!(got, i1);
    assert_eq!(st.chunks as usize, i1.chunks.len() + 1);
    let mut out = vec![];
    content::write_to(&*mine, &got, &mut out).unwrap();
    assert_eq!(out, v1);

    // version 2: an edit near the end
    let mut v2 = v1.clone();
    v2[1_900_000..1_900_100].copy_from_slice(&[7u8; 100]);
    let i2 = content::add_bytes(&*hs, &v2).unwrap();
    let (_, st) = content::fetch(&me, &[src(&host)], &i2.root(), mine.clone()).unwrap();
    assert!(st.chunks <= 4, "{} chunks for a 100-byte edit", st.chunks);
    assert!(st.bytes < 1 << 20);
    let mut out = vec![];
    content::write_to(&*mine, &i2, &mut out).unwrap();
    assert_eq!(out, v2);

    // already here: nothing moves
    let (_, st) = content::fetch(&me, &[src(&host)], &i2.root(), mine.clone()).unwrap();
    assert_eq!(st.chunks, 0);
}

#[test]
fn fetch_spreads_over_peers_and_survives_a_missing_one() {
    let me = start();
    let d = data(3 << 20, 6);
    let hosts: Vec<N> = (0..3).map(|_| start()).collect();
    let mut servers = vec![];
    let mut root = [0u8; 32];
    for (k, h) in hosts.iter().enumerate() {
        let s: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
        let i = content::add_bytes(&*s, &d).unwrap();
        root = i.root();
        // the third host lacks every other chunk
        let allow: content::Allow = if k == 2 {
            let odd: HashSet<[u8; 32]> = i.chunks.iter().skip(1).step_by(2).map(|c| c.1).collect();
            Arc::new(move |_, h| !odd.contains(h))
        } else {
            everyone()
        };
        servers.push(content::serve(h, s, allow).unwrap());
    }
    let sources: Vec<Source> = hosts.iter().map(src).collect();
    let mine: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let (i, st) = content::fetch(&me, &sources, &root, mine.clone()).unwrap();
    assert!(st.from.len() >= 2, "from {:?}", st.from);
    let mut out = vec![];
    content::write_to(&*mine, &i, &mut out).unwrap();
    assert_eq!(out, d);
}

#[test]
fn fetch_fails_cleanly_when_no_one_has_it_and_resumes_later() {
    let (host, me) = (start(), start());
    let d = data(1 << 20, 7);
    let hs: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let i = content::add_bytes(&*hs, &d).unwrap();
    let withheld = i.chunks[3].1;
    let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let g = gate.clone();
    let _srv = content::serve(&host, hs.clone(), Arc::new(move |_, h| *h != withheld || g.load(std::sync::atomic::Ordering::SeqCst))).unwrap();
    let mine: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let e = content::fetch(&me, &[src(&host)], &i.root(), mine.clone()).unwrap_err();
    assert!(e.to_string().contains("could not be fetched"), "{e}");
    assert!(content::fetch(&me, &[src(&host)], &[9u8; 32], mine.clone()).is_err());

    gate.store(true, std::sync::atomic::Ordering::SeqCst);
    let (_, st) = content::fetch(&me, &[src(&host)], &i.root(), mine.clone()).unwrap();
    assert_eq!(st.chunks, 1, "only the missing chunk");
    assert!(content::complete(&*mine, &i));
}

#[test]
fn fetch_range_gets_only_the_covering_chunks() {
    let (host, me) = (start(), start());
    let d = data(4 << 20, 8);
    let hs: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let i = content::add_bytes(&*hs, &d).unwrap();
    let _srv = content::serve(&host, hs, everyone()).unwrap();
    let mine: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let (b, st) = content::fetch_range(&me, &[src(&host)], &i.root(), 2_000_000, 50_000, mine).unwrap();
    assert_eq!(b, &d[2_000_000..2_050_000]);
    assert!(st.chunks <= 4 && (st.chunks as usize) < i.chunks.len() / 4, "{} of {}", st.chunks, i.chunks.len());
}

#[test]
fn the_server_refuses_what_allow_refuses() {
    let (host, me) = (start(), start());
    let hs: Arc<dyn ChunkStore> = Arc::new(MemoryStore::default());
    let i = content::add_bytes(&*hs, b"secret").unwrap();
    let mp = me.peer_id();
    let _srv = content::serve(&host, hs, Arc::new(move |p, _| *p != mp)).unwrap();
    assert!(content::fetch(&me, &[src(&host)], &i.root(), Arc::new(MemoryStore::default())).is_err());
}
