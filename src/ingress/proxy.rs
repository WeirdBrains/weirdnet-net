//! PROXY protocol v2 headers: the client's address, and the site name and kind as TLVs.
use std::net::{IpAddr, SocketAddr};

const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
/// PP2_TYPE_AUTHORITY: the host name the client asked for (the SNI or HTTP `Host`).
pub const TLV_AUTHORITY: u8 = 0x02;
/// A custom TLV (`0xE0`, the first of the custom range): `http` for a port 80 request.
pub const TLV_KIND: u8 = 0xE0;

/// What a header says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub source: Option<SocketAddr>,
    pub dest: Option<SocketAddr>,
    pub authority: Option<String>,
    pub http: bool,
}

/// A PROXY v2 `PROXY` header (TCP) from `source` to `dest`, with the name and kind.
pub fn encode(source: SocketAddr, dest: SocketAddr, authority: &str, http: bool) -> Vec<u8> {
    let mut body = vec![];
    let fam = match (source.ip(), dest.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            body.extend_from_slice(&s.octets());
            body.extend_from_slice(&d.octets());
            0x11
        }
        (s, d) => {
            let six = |ip: IpAddr| match ip {
                IpAddr::V4(v) => v.to_ipv6_mapped(),
                IpAddr::V6(v) => v,
            };
            body.extend_from_slice(&six(s).octets());
            body.extend_from_slice(&six(d).octets());
            0x21
        }
    };
    body.extend_from_slice(&source.port().to_be_bytes());
    body.extend_from_slice(&dest.port().to_be_bytes());
    tlv(&mut body, TLV_AUTHORITY, authority.as_bytes());
    if http {
        tlv(&mut body, TLV_KIND, b"http");
    }
    let mut h = SIG.to_vec();
    h.push(0x21); // v2, PROXY
    h.push(fam);
    h.extend_from_slice(&(body.len() as u16).to_be_bytes());
    h.extend_from_slice(&body);
    h
}

fn tlv(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    out.push(t);
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
}

/// Parse a header at the start of `buf`: `Ok(None)` if more bytes are needed, else the header
/// and its length.
pub fn decode(buf: &[u8]) -> Result<Option<(Header, usize)>, &'static str> {
    if buf.len() < 16 {
        return if SIG.starts_with(&buf[..buf.len().min(12)]) { Ok(None) } else { Err("not a PROXY v2 header") };
    }
    if buf[..12] != SIG {
        return Err("not a PROXY v2 header");
    }
    if buf[12] >> 4 != 2 {
        return Err("not PROXY version 2");
    }
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if buf.len() < 16 + len {
        return Ok(None);
    }
    let body = &buf[16..16 + len];
    let mut h = Header { source: None, dest: None, authority: None, http: false };
    let rest = match (buf[12] & 0x0f, buf[13]) {
        (0, _) => body, // LOCAL
        (1, 0x11) if body.len() >= 12 => {
            let ip = |b: &[u8]| IpAddr::from([b[0], b[1], b[2], b[3]]);
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            h.source = Some(SocketAddr::new(ip(&body[0..4]), port(&body[8..10])));
            h.dest = Some(SocketAddr::new(ip(&body[4..8]), port(&body[10..12])));
            &body[12..]
        }
        (1, 0x21) if body.len() >= 36 => {
            let ip = |b: &[u8]| {
                let a: [u8; 16] = b.try_into().unwrap_or([0; 16]);
                let v6 = std::net::Ipv6Addr::from(a);
                v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
            };
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            h.source = Some(SocketAddr::new(ip(&body[0..16]), port(&body[32..34])));
            h.dest = Some(SocketAddr::new(ip(&body[16..32]), port(&body[34..36])));
            &body[36..]
        }
        (1, _) => return Err("unsupported address family"),
        _ => return Err("unknown PROXY command"),
    };
    let mut r = rest;
    while r.len() >= 3 {
        let t = r[0];
        let n = u16::from_be_bytes([r[1], r[2]]) as usize;
        if r.len() < 3 + n {
            return Err("truncated TLV");
        }
        let v = &r[3..3 + n];
        match t {
            TLV_AUTHORITY => h.authority = std::str::from_utf8(v).ok().map(str::to_string),
            TLV_KIND => h.http = v == b"http",
            _ => {}
        }
        r = &r[3 + n..];
    }
    Ok(Some((h, 16 + len)))
}
