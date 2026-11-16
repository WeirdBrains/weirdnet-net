//! Where the bytes live: the application's [`ChunkStore`]. Chunks and file indexes are kept
//! under their BLAKE3 hashes and are checked before they're stored.
use super::{Hash, hex};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub trait ChunkStore: Send + Sync + 'static {
    fn get(&self, h: &Hash) -> Option<Vec<u8>>;
    /// Keep `bytes` under `h` (the caller has checked `h` is their hash).
    fn put(&self, h: &Hash, bytes: &[u8]) -> std::io::Result<()>;
    fn has(&self, h: &Hash) -> bool {
        self.get(h).is_some()
    }
}

/// Chunks in memory.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<Hash, Vec<u8>>>);

impl MemoryStore {
    pub fn len(&self) -> usize {
        self.0.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ChunkStore for MemoryStore {
    fn get(&self, h: &Hash) -> Option<Vec<u8>> {
        self.0.lock().ok()?.get(h).cloned()
    }
    fn put(&self, h: &Hash, bytes: &[u8]) -> std::io::Result<()> {
        if let Ok(mut m) = self.0.lock() {
            m.entry(*h).or_insert_with(|| bytes.to_vec());
        }
        Ok(())
    }
    fn has(&self, h: &Hash) -> bool {
        self.0.lock().map(|m| m.contains_key(h)).unwrap_or(false)
    }
}

/// Chunks as files under a directory (`ab/abcdef…`), written to a temporary name and renamed,
/// so a crash leaves no half chunk.
pub struct DirStore(PathBuf);

impl DirStore {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let d = dir.into();
        std::fs::create_dir_all(&d)?;
        Ok(DirStore(d))
    }

    fn path(&self, h: &Hash) -> PathBuf {
        let x = hex(h);
        self.0.join(&x[..2]).join(x)
    }
}

impl ChunkStore for DirStore {
    fn get(&self, h: &Hash) -> Option<Vec<u8>> {
        std::fs::read(self.path(h)).ok()
    }
    fn put(&self, h: &Hash, bytes: &[u8]) -> std::io::Result<()> {
        let p = self.path(h);
        if p.exists() {
            return Ok(());
        }
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension(format!("tmp{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, p)
    }
    fn has(&self, h: &Hash) -> bool {
        self.path(h).exists()
    }
}
