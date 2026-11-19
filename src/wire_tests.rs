use crate::names::{Entry, NamesRequest, Withdrawal};
use crate::user::NodeCert;
use crate::wire::{from_slice, to_vec};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Like `PeerId` and `Multiaddr` off human-readable formats: `serialize_bytes`, and only
/// `visit_bytes` back.
#[derive(Debug, Clone, PartialEq)]
struct Raw(Vec<u8>);

impl Serialize for Raw {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Raw {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Raw, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Raw;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Raw, E> {
                Ok(Raw(v.to_vec()))
            }
        }
        d.deserialize_bytes(V)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Blob {
    data: Vec<u8>,
}

#[test]
fn a_byte_vec_is_one_byte_string() {
    let data = noise(1024);
    let b = to_vec(&data).unwrap();
    assert_eq!(b[0] >> 5, 2, "major type 2 (byte string)");
    assert_eq!(b.len(), 1024 + 3, "0x59, a two-byte length, the bytes");
    assert_eq!(&b[3..], &data[..]);
    assert_eq!(from_slice::<Vec<u8>>(&b).unwrap(), data);

    let small = to_vec(&Blob { data: vec![1, 2, 3, 4, 5] }).unwrap();
    assert_eq!(small, [0xa1, 0x64, b'd', b'a', b't', b'a', 0x45, 1, 2, 3, 4, 5]);
    assert_eq!(small[6] >> 5, 2);
}

#[test]
fn the_stock_codec_spent_almost_twice_as_much() {
    // a sync-sized page body: sync's PAGE_MAX (256 KiB) less its 16 KiB of room
    let page = Blob { data: noise(240 * 1024) };
    let stock = cbor4ii::serde::to_vec(Vec::new(), &page).unwrap();
    let ours = to_vec(&page).unwrap();
    assert_eq!(ours.len(), 240 * 1024 + 1 + 5 + 5, "map head, key, 0x5a and a 4-byte length");
    assert!(stock.len() > ours.len() * 18 / 10, "stock {} vs {}", stock.len(), ours.len());
    assert_eq!(stock[6] >> 5, 4, "the stock codec wrote an array");
    assert_eq!(ours[6] >> 5, 2);
    eprintln!("240 KiB page: stock {} bytes, wire {} bytes", stock.len(), ours.len());
    assert_eq!(from_slice::<Blob>(&ours).unwrap(), page);
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum Tagged {
    Put { key: Vec<u8>, at: i64 },
    Drop { key: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum Loose {
    Bytes(Vec<u8>),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum Kind {
    Unit,
    New(Vec<u8>),
    Pair(u8, Vec<u8>),
    Rec { sig: [u8; 32], ok: bool },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Everything {
    sig: Vec<u8>,
    key: [u8; 32],
    empty: Vec<u8>,
    maybe: Option<Vec<u8>>,
    none: Option<Vec<u8>>,
    nested: Vec<Vec<u8>>,
    wide: Vec<u16>,
    small: u8,
    neg: i64,
    big: u64,
    f: f64,
    text: String,
    raw: Raw,
    raw_empty: Raw,
    kinds: Vec<Kind>,
    tagged: Vec<Tagged>,
    loose: Vec<Loose>,
    map: BTreeMap<String, Vec<u8>>,
    unit: (),
    pair: (u8, String),
}

#[test]
fn every_shape_comes_back() {
    let e = Everything {
        sig: noise(64),
        key: [7; 32],
        empty: vec![],
        maybe: Some(vec![0, 255]),
        none: None,
        nested: vec![vec![1], vec![], noise(40)],
        wide: vec![1, 2, 300],
        small: 200,
        neg: -1_000_000_000_000,
        big: u64::MAX,
        f: -2.5,
        text: "ravens".into(),
        raw: Raw(PeerId::random().to_bytes()),
        raw_empty: Raw(vec![]),
        kinds: vec![Kind::Unit, Kind::New(vec![9; 3]), Kind::Pair(1, vec![2]), Kind::Rec { sig: [3; 32], ok: true }],
        tagged: vec![Tagged::Put { key: vec![1, 2], at: -5 }, Tagged::Drop { key: noise(33) }],
        loose: vec![Loose::Bytes(vec![4, 5]), Loose::Text("t".into())],
        map: BTreeMap::from([("a".into(), vec![1]), ("b".into(), vec![])]),
        unit: (),
        pair: (1, "x".into()),
    };
    let b = to_vec(&e).unwrap();
    assert_eq!(from_slice::<Everything>(&b).unwrap(), e);
    assert_eq!(to_vec(&Raw(vec![1, 2])).unwrap(), [0x42, 1, 2]);
    // the wide integers stay an array
    assert_eq!(to_vec(&vec![1u16, 2]).unwrap(), [0x82, 1, 2]);
    assert_eq!(to_vec(&Vec::<u8>::new()).unwrap(), [0x80]);
}

#[test]
fn a_names_entry_travels_as_bytes() {
    let cert = NodeCert {
        user_id: "u".into(),
        peer_id: PeerId::random().to_string(),
        label: "l".into(),
        cert: noise(100),
        issued_at: 1,
        revoked_at: None,
        revocation: Some(noise(70)),
    };
    let w =
        Withdrawal { v: 1, user_id: "u".into(), user_key: noise(36), cert, node_key: noise(36), seq: 3, issued_at: 1, expires: 2, sig: noise(64) };
    let q = NamesRequest::Register(Box::new(Entry::Withdrawn(w.clone())));
    let b = to_vec(&q).unwrap();
    let stock = cbor4ii::serde::to_vec(Vec::new(), &q).unwrap();
    assert!(b.len() + 100 < stock.len(), "{} vs {}", b.len(), stock.len());
    match from_slice::<NamesRequest>(&b).unwrap() {
        NamesRequest::Register(e) => assert_eq!(*e, Entry::Withdrawn(w)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn bad_input_is_refused() {
    let good = to_vec(&Blob { data: vec![1, 2, 3] }).unwrap();
    for n in 0..good.len() {
        assert!(from_slice::<Blob>(&good[..n]).is_err(), "truncated at {n}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(from_slice::<Blob>(&trailing).is_err());
    // a length far past the end allocates nothing
    assert!(from_slice::<Vec<u8>>(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(from_slice::<Vec<u32>>(&[0x9b, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
    // nesting bombs stop at MAX_DEPTH
    let bomb = vec![0x81u8; 100_000];
    assert!(from_slice::<serde_json::Value>(&bomb).is_err());
    // indefinite lengths and tags are not part of the format
    assert!(from_slice::<Vec<u8>>(&[0x5f, 0x41, 1, 0xff]).is_err());
    assert!(from_slice::<u64>(&[0xc1, 0x01]).is_err());
    assert!(from_slice::<String>(&[0x62, 0xff, 0xfe]).is_err());
}
