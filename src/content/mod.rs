//! Content (W2): files split into content-defined chunks, addressed by BLAKE3, signed into
//! manifests, served and fetched over streams from one or several peers.
//!
//! - [`add_reader`] chunks a file with an rsync-style rolling checksum ([`chunk`]) into a
//!   [`ChunkStore`] the application provides, and returns its [`FileIndex`]; the file's root
//!   is the BLAKE3 hash of that index. An edit only changes the chunks around it.
//! - [`Manifest`]: paths → roots, sizes and app metadata, signed by a user key, versioned,
//!   with roots it revokes.
//! - [`serve`] answers `/weirdnet/content/1` streams from the store (the application decides
//!   who may have what). [`fetch`] gets a file's index and every chunk the store lacks from
//!   one or more peers, checking each hash as it arrives: a peer holding an older version
//!   already has the unchanged chunks, so only the changed ones cross the network, and an
//!   interrupted fetch resumes from the chunks already stored. [`fetch_range`] gets only the
//!   chunks covering a byte range (media). No size caps.
//! - Public content can be announced in the DHT: [`provider_key`] with
//!   [`Node::provide`](crate::Node::provide) and [`Node::providers`](crate::Node::providers).
pub mod chunk;
mod index;
mod manifest;
mod store;

pub use chunk::{MAX_CHUNK, MIN_CHUNK};
pub use index::FileIndex;
pub use manifest::{Manifest, ManifestDraft, ManifestEntry};
pub use store::{ChunkStore, DirStore, MemoryStore};

use crate::error::{NetError, Result};
use crate::node::{Message, Node, Opener};
use crate::stream::{Limits, Stream};
use futures::{AsyncReadExt as AR, AsyncWriteExt as AW};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A BLAKE3 hash.
pub type Hash = [u8; 32];
/// The stream protocol chunks are fetched on.
pub const CONTENT_PROTOCOL: &str = "/weirdnet/content/1";
/// The largest chunk accepted from others (this crate makes at most [`MAX_CHUNK`]).
pub const MAX_CHUNK_ACCEPTED: usize = 1024 * 1024;
/// The largest index accepted from others (about 100 GiB of chunks at the average size).
pub const MAX_INDEX: usize = 64 * 1024 * 1024;
const BATCH: usize = 16;
const PROVIDER_PREFIX: &[u8] = b"/weirdnet/content/1/";

pub fn hex(b: &[u8]) -> String {
    ::hex::encode(b)
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    ::hex::decode(s).ok()
}

/// A root from hex.
pub fn parse_hash(s: &str) -> Result<Hash> {
    unhex(s).and_then(|v| v.try_into().ok()).ok_or_else(|| NetError::invalid("hash", "64 hex characters"))
}

/// The DHT key peers announce a root under.
pub fn provider_key(root: &Hash) -> Vec<u8> {
    let mut k = PROVIDER_PREFIX.to_vec();
    k.extend_from_slice(root);
    k
}

/// Whether `key` is a [`provider_key`].
pub fn is_provider_key(key: &[u8]) -> bool {
    key.len() == PROVIDER_PREFIX.len() + 32 && key.starts_with(PROVIDER_PREFIX)
}

/// Chunk `r` into `store`; returns the index (also stored, under its root).
pub fn add_reader<R: Read>(store: &dyn ChunkStore, r: R) -> Result<FileIndex> {
    let mut chunks = vec![];
    let size = chunk::chunks(r, |c| {
        let h = *blake3::hash(c).as_bytes();
        if !store.has(&h) {
            store.put(&h, c)?;
        }
        chunks.push((c.len() as u32, h));
        Ok(())
    })
    .map_err(NetError::net)?;
    let idx = FileIndex { size, chunks };
    store.put(&idx.root(), &idx.encode()).map_err(NetError::net)?;
    Ok(idx)
}

pub fn add_bytes(store: &dyn ChunkStore, b: &[u8]) -> Result<FileIndex> {
    add_reader(store, b)
}

/// The index of `root` from the store.
pub fn index(store: &dyn ChunkStore, root: &Hash) -> Result<FileIndex> {
    let b = store.get(root).ok_or_else(|| NetError::invalid("content", format!("{} is not here", hex(root))))?;
    let i = FileIndex::decode(&b)?;
    if i.root() != *root {
        return Err(NetError::invalid("content", "the stored index does not match its root"));
    }
    Ok(i)
}

/// Whether every chunk of the file is in the store.
pub fn complete(store: &dyn ChunkStore, idx: &FileIndex) -> bool {
    idx.chunks.iter().all(|(_, h)| store.has(h))
}

/// Write the whole file out.
pub fn write_to<W: Write>(store: &dyn ChunkStore, idx: &FileIndex, mut w: W) -> Result<()> {
    for (_, h) in &idx.chunks {
        let c = store.get(h).ok_or_else(|| NetError::invalid("content", format!("chunk {} is missing", hex(h))))?;
        w.write_all(&c).map_err(NetError::net)?;
    }
    Ok(())
}

/// Bytes `offset..offset + len` of the file, from the store.
pub fn read_range(store: &dyn ChunkStore, idx: &FileIndex, offset: u64, len: u64) -> Result<Vec<u8>> {
    let end = offset.saturating_add(len).min(idx.size);
    let mut out = Vec::with_capacity(end.saturating_sub(offset) as usize);
    for (i, at) in idx.covering(offset, len) {
        let h = &idx.chunks[i].1;
        let c = store.get(h).ok_or_else(|| NetError::invalid("content", format!("chunk {} is missing", hex(h))))?;
        let from = offset.saturating_sub(at) as usize;
        let to = ((end - at) as usize).min(c.len());
        out.extend_from_slice(&c[from..to]);
    }
    Ok(out)
}

/// Who decides whether a peer may have a chunk or index (`true`: serve it).
pub type Allow = Arc<dyn Fn(&PeerId, &Hash) -> bool + Send + Sync>;

/// Serving `/weirdnet/content/1`; dropping it stops.
pub struct Server(tokio::task::JoinHandle<()>);

impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Answer chunk and index requests from `store`, for what `allow` lets each peer have.
pub fn serve<Q: Message, R: Message>(node: &Node<Q, R>, store: Arc<dyn ChunkStore>, allow: Allow) -> Result<Server> {
    let mut inc = node.accept_streams(CONTENT_PROTOCOL, Limits::default())?;
    let rt = node.runtime();
    Ok(Server(rt.spawn(async move {
        while let Some(s) = inc.next().await {
            let (store, allow) = (store.clone(), allow.clone());
            tokio::spawn(async move {
                let _ = answer(s, store, allow).await;
            });
        }
    })))
}

async fn answer(mut s: Stream, store: Arc<dyn ChunkStore>, allow: Allow) -> std::io::Result<()> {
    let peer = s.peer();
    loop {
        let mut tag = [0u8; 1];
        if AR::read(&mut s, &mut tag).await? == 0 || tag[0] == 0 {
            break;
        }
        let mut h = [0u8; 32];
        AR::read_exact(&mut s, &mut h).await?;
        let found = if allow(&peer, &h) { tokio::task::block_in_place(|| store.get(&h)) } else { None };
        match found {
            Some(b) => {
                AW::write_all(&mut s, &[1]).await?;
                AW::write_all(&mut s, &(b.len() as u32).to_be_bytes()).await?;
                AW::write_all(&mut s, &b).await?;
            }
            None => AW::write_all(&mut s, &[0]).await?,
        }
    }
    AW::close(&mut s).await
}

/// A peer to fetch from.
#[derive(Debug, Clone)]
pub struct Source {
    pub peer: PeerId,
    /// Where to reach it (empty: already connected, or known to the node).
    pub addrs: Vec<Multiaddr>,
}

impl From<PeerId> for Source {
    fn from(peer: PeerId) -> Self {
        Source { peer, addrs: vec![] }
    }
}

/// What a fetch moved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchStats {
    /// Chunks (and indexes) received.
    pub chunks: u64,
    pub bytes: u64,
    /// Chunks per peer.
    pub from: HashMap<PeerId, u64>,
}

/// Fetch the file `root` into `store` from `sources`: its index, then the chunks the store
/// lacks, spread over the sources. Blocks; use [`fetch_async`] from async code.
pub fn fetch<Q: Message, R: Message>(
    node: &Node<Q, R>,
    sources: &[Source],
    root: &Hash,
    store: Arc<dyn ChunkStore>,
) -> Result<(FileIndex, FetchStats)> {
    let fut = fetch_with(node.opener(CONTENT_PROTOCOL, Limits::default()), sources.to_vec(), *root, store, None);
    futures::executor::block_on(node.runtime().spawn(fut)).map_err(|_| NetError::Network("the node stopped".into()))?
}

pub async fn fetch_async<Q: Message, R: Message>(
    node: &Node<Q, R>,
    sources: &[Source],
    root: &Hash,
    store: Arc<dyn ChunkStore>,
) -> Result<(FileIndex, FetchStats)> {
    let fut = fetch_with(node.opener(CONTENT_PROTOCOL, Limits::default()), sources.to_vec(), *root, store, None);
    node.runtime().spawn(fut).await.map_err(|_| NetError::Network("the node stopped".into()))?
}

/// Fetch only the chunks covering `offset..offset + len` and return those bytes.
pub fn fetch_range<Q: Message, R: Message>(
    node: &Node<Q, R>,
    sources: &[Source],
    root: &Hash,
    offset: u64,
    len: u64,
    store: Arc<dyn ChunkStore>,
) -> Result<(Vec<u8>, FetchStats)> {
    let fut = fetch_with(node.opener(CONTENT_PROTOCOL, Limits::default()), sources.to_vec(), *root, store.clone(), Some((offset, len)));
    let (idx, stats) = futures::executor::block_on(node.runtime().spawn(fut)).map_err(|_| NetError::Network("the node stopped".into()))??;
    Ok((read_range(&*store, &idx, offset, len)?, stats))
}

#[derive(Default)]
struct Work {
    queue: VecDeque<Hash>,
    tried: HashMap<Hash, HashSet<usize>>,
    failed: Vec<Hash>,
    inflight: usize,
    stats: FetchStats,
}

async fn fetch_with(
    open: Opener,
    sources: Vec<Source>,
    root: Hash,
    store: Arc<dyn ChunkStore>,
    range: Option<(u64, u64)>,
) -> Result<(FileIndex, FetchStats)> {
    if sources.is_empty() && !store.has(&root) {
        return Err(NetError::invalid("fetch", "no one to fetch from"));
    }
    let work = Arc::new(Mutex::new(Work::default()));
    // the index first (it is small next to the file)
    if !store.has(&root) {
        run(&open, &sources, &store, &work, vec![root], MAX_INDEX).await;
        if !store.has(&root) {
            return Err(NetError::Network(format!("no source has {}", hex(&root))));
        }
    }
    let idx = index(&*store, &root)?;
    let wanted: Vec<usize> = match range {
        Some((o, l)) => idx.covering(o, l).into_iter().map(|(i, _)| i).collect(),
        None => (0..idx.chunks.len()).collect(),
    };
    let mut seen = HashSet::new();
    let missing: Vec<Hash> = wanted.into_iter().map(|i| idx.chunks[i].1).filter(|h| seen.insert(*h) && !store.has(h)).collect();
    if !missing.is_empty() {
        run(&open, &sources, &store, &work, missing, MAX_CHUNK_ACCEPTED).await;
    }
    let w = work.lock().unwrap_or_else(|e| e.into_inner());
    if !w.failed.is_empty() || !w.queue.is_empty() {
        return Err(NetError::Network(format!("{} chunk(s) of {} could not be fetched", w.failed.len() + w.queue.len(), hex(&root))));
    }
    Ok((idx, w.stats.clone()))
}

/// Fetch `hashes` with one worker per source until each is stored or every source lacks it.
async fn run(open: &Opener, sources: &[Source], store: &Arc<dyn ChunkStore>, work: &Arc<Mutex<Work>>, hashes: Vec<Hash>, max: usize) {
    {
        let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
        w.queue.extend(hashes);
    }
    let n = sources.len();
    let workers = sources.iter().enumerate().map(|(i, src)| worker(i, n, open.clone(), src.clone(), store.clone(), work.clone(), max));
    futures::future::join_all(workers).await;
}

async fn worker(me: usize, n: usize, open: Opener, src: Source, store: Arc<dyn ChunkStore>, work: Arc<Mutex<Work>>, max: usize) {
    let mut stream: Option<Stream> = None;
    loop {
        // take a batch this source hasn't been asked for
        let batch: Vec<Hash> = {
            let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
            let mut b = vec![];
            let mut rest = VecDeque::new();
            while let Some(h) = w.queue.pop_front() {
                if b.len() < BATCH && !w.tried.get(&h).is_some_and(|t| t.contains(&me)) {
                    b.push(h);
                } else {
                    rest.push_back(h);
                }
            }
            w.queue = rest;
            w.inflight += b.len();
            if b.is_empty() && w.inflight == 0 {
                return;
            }
            b
        };
        if batch.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        if stream.is_none() {
            match open(src.peer, src.addrs.clone()).await {
                Ok(s) => stream = Some(s),
                Err(e) => {
                    tracing::debug!("content: cannot reach {}: {e}", src.peer);
                    give_back(&work, me, n, batch, &[]);
                    // this source is out: everything left is someone else's
                    mark_all(&work, me, n);
                    return;
                }
            }
        }
        let s = stream.as_mut().expect("opened");
        match ask(s, &batch, max).await {
            Ok(got) => {
                let mut ok = vec![];
                for (h, b) in batch.iter().zip(got) {
                    if let Some(b) = b
                        && *blake3::hash(&b).as_bytes() == *h
                        && tokio::task::block_in_place(|| store.put(h, &b)).is_ok()
                    {
                        let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
                        w.stats.chunks += 1;
                        w.stats.bytes += b.len() as u64;
                        *w.stats.from.entry(src.peer).or_default() += 1;
                        ok.push(*h);
                    }
                }
                give_back(&work, me, n, batch, &ok);
            }
            Err(e) => {
                tracing::debug!("content: {} failed: {e}", src.peer);
                give_back(&work, me, n, batch, &[]);
                mark_all(&work, me, n);
                return;
            }
        }
    }
}

/// Hashes not in `ok` go back to the queue, or to `failed` once every source lacked them.
fn give_back(work: &Mutex<Work>, me: usize, n: usize, batch: Vec<Hash>, ok: &[Hash]) {
    let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
    w.inflight -= batch.len();
    for h in batch {
        if ok.contains(&h) {
            continue;
        }
        let t = w.tried.entry(h).or_default();
        t.insert(me);
        if t.len() >= n {
            w.failed.push(h);
        } else {
            w.queue.push_back(h);
        }
    }
}

/// A source that dropped out counts as having been asked for everything still queued.
fn mark_all(work: &Mutex<Work>, me: usize, n: usize) {
    let mut w = work.lock().unwrap_or_else(|e| e.into_inner());
    let queued: Vec<Hash> = w.queue.drain(..).collect();
    for h in queued {
        let t = w.tried.entry(h).or_default();
        t.insert(me);
        if t.len() >= n {
            w.failed.push(h);
        } else {
            w.queue.push_back(h);
        }
    }
}

async fn ask(s: &mut Stream, batch: &[Hash], max: usize) -> std::io::Result<Vec<Option<Vec<u8>>>> {
    let mut req = Vec::with_capacity(batch.len() * 33);
    for h in batch {
        req.push(1);
        req.extend_from_slice(h);
    }
    AW::write_all(&mut *s, &req).await?;
    let mut out = Vec::with_capacity(batch.len());
    for _ in batch {
        let mut st = [0u8; 1];
        AR::read_exact(&mut *s, &mut st).await?;
        if st[0] == 0 {
            out.push(None);
            continue;
        }
        let mut l = [0u8; 4];
        AR::read_exact(&mut *s, &mut l).await?;
        let l = u32::from_be_bytes(l) as usize;
        if l > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk too large"));
        }
        let mut b = vec![0u8; l];
        AR::read_exact(&mut *s, &mut b).await?;
        out.push(Some(b));
    }
    Ok(out)
}
