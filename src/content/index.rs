//! A file's index: its size and its chunks' lengths and hashes. The file's root is the BLAKE3
//! hash of the encoded index, and the index is itself stored and fetched under that root.
use super::{Hash, hex};
use crate::error::{NetError, Result};

const MAGIC: &[u8; 8] = b"WNCIDX01";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIndex {
    pub size: u64,
    /// Each chunk's length and BLAKE3 hash, in order.
    pub chunks: Vec<(u32, Hash)>,
}

impl FileIndex {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24 + self.chunks.len() * 36);
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&self.size.to_be_bytes());
        v.extend_from_slice(&(self.chunks.len() as u64).to_be_bytes());
        for (len, h) in &self.chunks {
            v.extend_from_slice(&len.to_be_bytes());
            v.extend_from_slice(h);
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<FileIndex> {
        let bad = |m: &str| NetError::invalid("file index", m.to_string());
        if b.len() < 24 || &b[..8] != MAGIC {
            return Err(bad("not an index"));
        }
        let size = u64::from_be_bytes(b[8..16].try_into().unwrap_or_default());
        let n = u64::from_be_bytes(b[16..24].try_into().unwrap_or_default()) as usize;
        if b.len() != 24 + n.checked_mul(36).ok_or_else(|| bad("too many chunks"))? {
            return Err(bad("wrong length"));
        }
        let mut chunks = Vec::with_capacity(n);
        let mut sum = 0u64;
        for c in b[24..].as_chunks::<36>().0 {
            let len = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
            if len == 0 || len as usize > super::MAX_CHUNK_ACCEPTED {
                return Err(bad("bad chunk length"));
            }
            sum += len as u64;
            let mut h = [0u8; 32];
            h.copy_from_slice(&c[4..]);
            chunks.push((len, h));
        }
        if sum != size {
            return Err(bad("chunk lengths do not add up to the size"));
        }
        Ok(FileIndex { size, chunks })
    }

    /// The file's root: the BLAKE3 hash of the encoded index.
    pub fn root(&self) -> Hash {
        *blake3::hash(&self.encode()).as_bytes()
    }

    pub fn root_hex(&self) -> String {
        hex(&self.root())
    }

    /// The chunks covering `offset..offset + len`: (index, the chunk's offset in the file).
    pub fn covering(&self, offset: u64, len: u64) -> Vec<(usize, u64)> {
        let end = offset.saturating_add(len).min(self.size);
        let mut out = vec![];
        let mut at = 0u64;
        for (i, (l, _)) in self.chunks.iter().enumerate() {
            let next = at + *l as u64;
            if next > offset && at < end {
                out.push((i, at));
            }
            if at >= end {
                break;
            }
            at = next;
        }
        out
    }
}
