//! Content-defined chunking with an rsync-style rolling checksum: a boundary falls where the
//! rolling sum over the last [`WINDOW`] bytes hits a pattern, so an edit only moves the
//! boundaries around it and the other chunks keep their BLAKE3 hashes.
use std::io::Read;

/// Bytes the rolling checksum covers.
pub const WINDOW: usize = 64;
/// No chunk is smaller (except a file's last) ...
pub const MIN_CHUNK: usize = 16 * 1024;
/// ... or larger.
pub const MAX_CHUNK: usize = 256 * 1024;
/// Boundaries average about this far apart past the minimum.
const MASK: u32 = (1 << 16) - 1;

/// rsync's weak checksum over a sliding window, updated a byte at a time.
struct Rolling {
    a: u32,
    b: u32,
    win: [u8; WINDOW],
    pos: usize,
    full: bool,
}

impl Default for Rolling {
    fn default() -> Self {
        Rolling { a: 0, b: 0, win: [0; WINDOW], pos: 0, full: false }
    }
}

impl Rolling {
    fn push(&mut self, x: u8) -> u32 {
        let out = if self.full { self.win[self.pos] as u32 } else { 0 };
        self.win[self.pos] = x;
        self.pos = (self.pos + 1) % WINDOW;
        if self.pos == 0 {
            self.full = true;
        }
        self.a = self.a.wrapping_sub(out).wrapping_add(x as u32) & 0xffff;
        self.b = self.b.wrapping_sub((WINDOW as u32).wrapping_mul(out)).wrapping_add(self.a) & 0xffff;
        (self.b << 16) | self.a
    }
}

fn boundary(weak: u32) -> bool {
    // spread the sum's bits before testing them
    (weak.wrapping_mul(0x9E37_79B1) >> 16) & MASK == MASK
}

/// Split a reader into chunks, calling `f` with each; returns the total size.
pub fn chunks<R: Read>(mut r: R, mut f: impl FnMut(&[u8]) -> std::io::Result<()>) -> std::io::Result<u64> {
    let mut cur: Vec<u8> = Vec::with_capacity(MAX_CHUNK);
    let mut roll = Rolling::default();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total += n as u64;
        for &x in &buf[..n] {
            cur.push(x);
            let w = roll.push(x);
            if (cur.len() >= MIN_CHUNK && boundary(w)) || cur.len() >= MAX_CHUNK {
                f(&cur)?;
                cur.clear();
                roll = Rolling::default();
            }
        }
    }
    if !cur.is_empty() {
        f(&cur)?;
    }
    Ok(total)
}
