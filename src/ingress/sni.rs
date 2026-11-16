//! The server name from a TLS ClientHello, read without decrypting anything.

/// What the first bytes of a connection say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// Not enough bytes yet.
    More,
    /// A ClientHello for this (lowercase) name.
    Name(String),
    /// A ClientHello without a server name.
    NoName,
    /// Not TLS, or a malformed or oversized ClientHello.
    Bad,
}

/// The largest ClientHello accepted (post-quantum key shares make them a few KiB).
pub const MAX_HELLO: usize = 32 * 1024;

/// Look for the SNI in `buf`, the first bytes a client sent. The ClientHello may span records.
pub fn peek(buf: &[u8]) -> Hello {
    // gather the handshake bytes out of the records
    let mut hs = Vec::new();
    let mut i = 0;
    loop {
        if buf.len() < i + 5 {
            return if buf.len() > MAX_HELLO { Hello::Bad } else { Hello::More };
        }
        if buf[i] != 0x16 || buf[i + 1] != 3 {
            return Hello::Bad;
        }
        let len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
        if len == 0 || len > 16384 + 2048 {
            return Hello::Bad;
        }
        if buf.len() < i + 5 + len {
            return if i + 5 + len > MAX_HELLO { Hello::Bad } else { Hello::More };
        }
        hs.extend_from_slice(&buf[i + 5..i + 5 + len]);
        i += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Hello::Bad;
            }
            let want = 4 + u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            if want > MAX_HELLO {
                return Hello::Bad;
            }
            if hs.len() >= want {
                return client_hello(&hs[4..want]);
            }
        }
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| b[0] as usize)
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    }
}

fn client_hello(body: &[u8]) -> Hello {
    fn go(body: &[u8]) -> Option<Hello> {
        let mut r = R(body);
        r.take(2 + 32)?; // version, random
        let n = r.u8()?;
        r.take(n)?; // session id
        let n = r.u16()?;
        r.take(n)?; // cipher suites
        let n = r.u8()?;
        r.take(n)?; // compression
        if r.0.is_empty() {
            return Some(Hello::NoName);
        }
        let n = r.u16()?;
        let mut ext = R(r.take(n)?);
        while !ext.0.is_empty() {
            let kind = ext.u16()?;
            let n = ext.u16()?;
            let data = ext.take(n)?;
            if kind != 0 {
                continue;
            }
            let mut d = R(data);
            let n = d.u16()?;
            let mut list = R(d.take(n)?);
            while !list.0.is_empty() {
                let t = list.u8()?;
                let n = list.u16()?;
                let name = list.take(n)?;
                if t == 0 {
                    return Some(match host_name(name) {
                        Some(h) => Hello::Name(h),
                        None => Hello::Bad,
                    });
                }
            }
            return Some(Hello::NoName);
        }
        Some(Hello::NoName)
    }
    go(body).unwrap_or(Hello::Bad)
}

/// A DNS host name, lowercased without a trailing dot; `None` if it isn't one.
pub fn host_name(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return None;
        }
    }
    Some(s)
}
