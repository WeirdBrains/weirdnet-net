//! The request-response wire codec: CBOR in which every byte field is a byte string.
//!
//! libp2p's stock CBOR codec writes a `Vec<u8>` (and `[u8; N]`, and any other sequence of
//! `u8`) the way serde hands it over, as an array of integers: one to two bytes per byte
//! plus the array head. This codec writes any non-empty sequence of `u8` as one CBOR
//! byte string (major type 2) instead, whether or not the field is marked `serde_bytes`,
//! so a 1 MiB blob costs 1 MiB and a few bytes on the wire. Everything else (maps for
//! structs, text for unit variants, a one-entry map for other variants, null for `None`
//! and `()`) is laid out as before.
//!
//! On reading, a byte string fills a `Vec<u8>`, an array of `u8`, a `serde_bytes` field,
//! a `Multiaddr` or a `PeerId`. Where serde buffers a value first (internally tagged,
//! adjacently tagged and untagged enums, `flatten`) a byte string is handed over as a
//! sequence of `u8`, which suits `Vec<u8>`, `serde_bytes` and `Multiaddr`, but not a
//! `PeerId` (keep those as strings, or out of such enums).
//!
//! Both ends must use it: it is not readable by the stock codec for such fields. Weirdnet
//! profiles bumped their request-response ids when it came in (`/weirdnet/net/2`).

use futures::prelude::*;
use libp2p::StreamProtocol;
use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer, Visitor};
use serde::{Serialize, ser};
use std::fmt;
use std::io;
use std::marker::PhantomData;

/// Nesting deeper than this is refused when reading.
pub const MAX_DEPTH: usize = 128;

/// A value that could not be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire: {}", self.0)
    }
}
impl std::error::Error for WireError {}
impl ser::Error for WireError {
    fn custom<T: fmt::Display>(m: T) -> Self {
        WireError(m.to_string())
    }
}
impl de::Error for WireError {
    fn custom<T: fmt::Display>(m: T) -> Self {
        WireError(m.to_string())
    }
}

fn bad<T>(m: impl Into<String>) -> Result<T, WireError> {
    Err(WireError(m.into()))
}

/// Encode `v`.
pub fn to_vec<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, WireError> {
    let val = v.serialize(ValSer)?;
    let mut out = Vec::new();
    encode(&val, &mut out);
    Ok(out)
}

/// Decode one value that fills all of `b`.
pub fn from_slice<T: DeserializeOwned>(b: &[u8]) -> Result<T, WireError> {
    let mut r = Reader { b, pos: 0 };
    let v = r.value(0)?;
    if r.pos != b.len() {
        return bad(format!("{} trailing bytes", b.len() - r.pos));
    }
    T::deserialize(ValDe(v))
}

// ---------------------------------------------------------------- the value tree

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    /// A `u8` as serde handed it over (sequences of these become byte strings).
    U8(u8),
    Uint(u64),
    /// -1 - n
    Nint(u64),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Val>),
    Map(Vec<(Val, Val)>),
}

fn int(v: i64) -> Val {
    if v >= 0 { Val::Uint(v as u64) } else { Val::Nint((-1 - v) as u64) }
}

// ---------------------------------------------------------------- writing

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend([m | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

fn encode(v: &Val, out: &mut Vec<u8>) {
    match v {
        Val::Null => out.push(0xf6),
        Val::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Val::U8(n) => head(out, 0, *n as u64),
        Val::Uint(n) => head(out, 0, *n),
        Val::Nint(n) => head(out, 1, *n),
        Val::F32(f) => {
            out.push(0xfa);
            out.extend(f.to_be_bytes());
        }
        Val::F64(f) => {
            out.push(0xfb);
            out.extend(f.to_be_bytes());
        }
        Val::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend(b);
        }
        Val::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend(s.as_bytes());
        }
        Val::Array(items) if !items.is_empty() && items.iter().all(|i| matches!(i, Val::U8(_))) => {
            head(out, 2, items.len() as u64);
            out.extend(items.iter().map(|i| if let Val::U8(b) = i { *b } else { 0 }));
        }
        Val::Array(items) => {
            head(out, 4, items.len() as u64);
            items.iter().for_each(|i| encode(i, out));
        }
        Val::Map(kv) => {
            head(out, 5, kv.len() as u64);
            for (k, v) in kv {
                encode(k, out);
                encode(v, out);
            }
        }
    }
}

struct ValSer;

struct SeqSer {
    items: Vec<Val>,
    variant: Option<&'static str>,
}

struct MapSer {
    kv: Vec<(Val, Val)>,
    key: Option<Val>,
    variant: Option<&'static str>,
}

fn wrap(variant: Option<&'static str>, v: Val) -> Val {
    match variant {
        Some(name) => Val::Map(vec![(Val::Text(name.into()), v)]),
        None => v,
    }
}

impl ser::Serializer for ValSer {
    type Ok = Val;
    type Error = WireError;
    type SerializeSeq = SeqSer;
    type SerializeTuple = SeqSer;
    type SerializeTupleStruct = SeqSer;
    type SerializeTupleVariant = SeqSer;
    type SerializeMap = MapSer;
    type SerializeStruct = MapSer;
    type SerializeStructVariant = MapSer;

    fn is_human_readable(&self) -> bool {
        false
    }
    fn serialize_bool(self, v: bool) -> Result<Val, WireError> {
        Ok(Val::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Val, WireError> {
        Ok(int(v as i64))
    }
    fn serialize_i16(self, v: i16) -> Result<Val, WireError> {
        Ok(int(v as i64))
    }
    fn serialize_i32(self, v: i32) -> Result<Val, WireError> {
        Ok(int(v as i64))
    }
    fn serialize_i64(self, v: i64) -> Result<Val, WireError> {
        Ok(int(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Val, WireError> {
        if v >= 0 {
            self.serialize_u128(v as u128)
        } else if -1 - v <= u64::MAX as i128 {
            Ok(Val::Nint((-1 - v) as u64))
        } else {
            bad("i128 out of range")
        }
    }
    fn serialize_u8(self, v: u8) -> Result<Val, WireError> {
        Ok(Val::U8(v))
    }
    fn serialize_u16(self, v: u16) -> Result<Val, WireError> {
        Ok(Val::Uint(v as u64))
    }
    fn serialize_u32(self, v: u32) -> Result<Val, WireError> {
        Ok(Val::Uint(v as u64))
    }
    fn serialize_u64(self, v: u64) -> Result<Val, WireError> {
        Ok(Val::Uint(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Val, WireError> {
        u64::try_from(v).map(Val::Uint).or_else(|_| bad("u128 out of range"))
    }
    fn serialize_f32(self, v: f32) -> Result<Val, WireError> {
        Ok(Val::F32(v))
    }
    fn serialize_f64(self, v: f64) -> Result<Val, WireError> {
        Ok(Val::F64(v))
    }
    fn serialize_char(self, v: char) -> Result<Val, WireError> {
        Ok(Val::Text(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Val, WireError> {
        Ok(Val::Text(v.into()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Val, WireError> {
        Ok(Val::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Val, WireError> {
        Ok(Val::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<Val, WireError> {
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<Val, WireError> {
        Ok(Val::Null)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Val, WireError> {
        Ok(Val::Null)
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, variant: &'static str) -> Result<Val, WireError> {
        Ok(Val::Text(variant.into()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _: &'static str, v: &T) -> Result<Val, WireError> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(self, _: &'static str, _: u32, variant: &'static str, v: &T) -> Result<Val, WireError> {
        Ok(wrap(Some(variant), v.serialize(self)?))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer, WireError> {
        Ok(SeqSer { items: Vec::with_capacity(len.unwrap_or(0).min(4096)), variant: None })
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSer, WireError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _: &'static str, len: usize) -> Result<SeqSer, WireError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(self, _: &'static str, _: u32, variant: &'static str, len: usize) -> Result<SeqSer, WireError> {
        Ok(SeqSer { items: Vec::with_capacity(len.min(4096)), variant: Some(variant) })
    }
    fn serialize_map(self, _: Option<usize>) -> Result<MapSer, WireError> {
        Ok(MapSer { kv: vec![], key: None, variant: None })
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<MapSer, WireError> {
        self.serialize_map(None)
    }
    fn serialize_struct_variant(self, _: &'static str, _: u32, variant: &'static str, _: usize) -> Result<MapSer, WireError> {
        Ok(MapSer { kv: vec![], key: None, variant: Some(variant) })
    }
}

impl ser::SerializeSeq for SeqSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        self.items.push(v.serialize(ValSer)?);
        Ok(())
    }
    fn end(self) -> Result<Val, WireError> {
        Ok(wrap(self.variant, Val::Array(self.items)))
    }
}
impl ser::SerializeTuple for SeqSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        ser::SerializeSeq::serialize_element(self, v)
    }
    fn end(self) -> Result<Val, WireError> {
        ser::SerializeSeq::end(self)
    }
}
impl ser::SerializeTupleStruct for SeqSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        ser::SerializeSeq::serialize_element(self, v)
    }
    fn end(self) -> Result<Val, WireError> {
        ser::SerializeSeq::end(self)
    }
}
impl ser::SerializeTupleVariant for SeqSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        ser::SerializeSeq::serialize_element(self, v)
    }
    fn end(self) -> Result<Val, WireError> {
        ser::SerializeSeq::end(self)
    }
}
impl ser::SerializeMap for MapSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), WireError> {
        self.key = Some(k.serialize(ValSer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        let Some(k) = self.key.take() else { return bad("map value without a key") };
        self.kv.push((k, v.serialize(ValSer)?));
        Ok(())
    }
    fn end(self) -> Result<Val, WireError> {
        Ok(wrap(self.variant, Val::Map(self.kv)))
    }
}
impl ser::SerializeStruct for MapSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, v: &T) -> Result<(), WireError> {
        self.kv.push((Val::Text(key.into()), v.serialize(ValSer)?));
        Ok(())
    }
    fn end(self) -> Result<Val, WireError> {
        ser::SerializeMap::end(self)
    }
}
impl ser::SerializeStructVariant for MapSer {
    type Ok = Val;
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, v: &T) -> Result<(), WireError> {
        ser::SerializeStruct::serialize_field(self, key, v)
    }
    fn end(self) -> Result<Val, WireError> {
        ser::SerializeMap::end(self)
    }
}

// ---------------------------------------------------------------- reading

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], WireError> {
        if self.b.len() - self.pos < n {
            return bad("truncated");
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn left(&self) -> usize {
        self.b.len() - self.pos
    }
    fn arg(&mut self, ai: u8) -> Result<u64, WireError> {
        Ok(match ai {
            0..=23 => ai as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap_or_default()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap_or_default()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap_or_default()),
            31 => return bad("indefinite lengths are not used"),
            _ => return bad("reserved additional information"),
        })
    }
    fn len(&mut self, ai: u8) -> Result<usize, WireError> {
        let n = self.arg(ai)?;
        // every item takes at least one byte, so a longer count cannot be real
        if n > self.left() as u64 {
            return bad("length past the end");
        }
        Ok(n as usize)
    }
    fn value(&mut self, depth: usize) -> Result<Val, WireError> {
        if depth > MAX_DEPTH {
            return bad("nested too deeply");
        }
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        Ok(match major {
            0 => Val::Uint(self.arg(ai)?),
            1 => Val::Nint(self.arg(ai)?),
            2 => {
                let n = self.len(ai)?;
                Val::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.len(ai)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| WireError("text is not UTF-8".into()))?;
                Val::Text(s.into())
            }
            4 => {
                let n = self.len(ai)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.value(depth + 1)?);
                }
                Val::Array(v)
            }
            5 => {
                let n = self.len(ai)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    v.push((k, self.value(depth + 1)?));
                }
                Val::Map(v)
            }
            6 => return bad("tags are not used"),
            _ => match ai {
                20 => Val::Bool(false),
                21 => Val::Bool(true),
                22 | 23 => Val::Null,
                25 => Val::F32(half(u16::from_be_bytes(self.take(2)?.try_into().unwrap_or_default()))),
                26 => Val::F32(f32::from_be_bytes(self.take(4)?.try_into().unwrap_or_default())),
                27 => Val::F64(f64::from_be_bytes(self.take(8)?.try_into().unwrap_or_default())),
                _ => return bad("unsupported simple value"),
            },
        })
    }
}

fn half(h: u16) -> f32 {
    let (sign, exp, man) = ((h >> 15) as u32, ((h >> 10) & 0x1f) as i32, (h & 0x3ff) as f32);
    let v = match exp {
        0 => man * 2f32.powi(-24),
        31 if man == 0.0 => f32::INFINITY,
        31 => f32::NAN,
        e => (1.0 + man / 1024.0) * 2f32.powi(e - 15),
    };
    if sign == 1 { -v } else { v }
}

struct ValDe(Val);

struct SeqDe<I>(I);

impl<'de, I: Iterator<Item = Val> + ExactSizeIterator> de::SeqAccess<'de> for SeqDe<I> {
    type Error = WireError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, WireError> {
        self.0.next().map(|v| seed.deserialize(ValDe(v))).transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

struct MapDe {
    it: std::vec::IntoIter<(Val, Val)>,
    value: Option<Val>,
}

impl<'de> de::MapAccess<'de> for MapDe {
    type Error = WireError;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, WireError> {
        match self.it.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(ValDe(k)).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, WireError> {
        match self.value.take() {
            Some(v) => seed.deserialize(ValDe(v)),
            None => bad("map value without a key"),
        }
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.it.len())
    }
}

struct EnumDe {
    variant: Val,
    value: Option<Val>,
}

impl<'de> de::EnumAccess<'de> for EnumDe {
    type Error = WireError;
    type Variant = VariantDe;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, VariantDe), WireError> {
        Ok((seed.deserialize(ValDe(self.variant))?, VariantDe(self.value)))
    }
}

struct VariantDe(Option<Val>);

impl<'de> de::VariantAccess<'de> for VariantDe {
    type Error = WireError;
    fn unit_variant(self) -> Result<(), WireError> {
        match self.0 {
            None | Some(Val::Null) => Ok(()),
            Some(_) => bad("expected a unit variant"),
        }
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, WireError> {
        seed.deserialize(ValDe(self.0.unwrap_or(Val::Null)))
    }
    fn tuple_variant<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, WireError> {
        de::Deserializer::deserialize_seq(ValDe(self.0.unwrap_or(Val::Array(vec![]))), visitor)
    }
    fn struct_variant<V: Visitor<'de>>(self, _: &'static [&'static str], visitor: V) -> Result<V::Value, WireError> {
        de::Deserializer::deserialize_map(ValDe(self.0.unwrap_or(Val::Map(vec![]))), visitor)
    }
}

impl<'de> IntoDeserializer<'de, WireError> for ValDe {
    type Deserializer = ValDe;
    fn into_deserializer(self) -> ValDe {
        self
    }
}

impl<'de> de::Deserializer<'de> for ValDe {
    type Error = WireError;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        match self.0 {
            Val::Null => visitor.visit_unit(),
            Val::Bool(b) => visitor.visit_bool(b),
            Val::U8(n) => visitor.visit_u8(n),
            Val::Uint(n) => visitor.visit_u64(n),
            Val::Nint(n) if n <= i64::MAX as u64 => visitor.visit_i64(-1 - n as i64),
            Val::Nint(n) => visitor.visit_i128(-1 - n as i128),
            Val::F32(f) => visitor.visit_f32(f),
            Val::F64(f) => visitor.visit_f64(f),
            // a byte string is a sequence of u8 to whatever asks for anything (see the module doc)
            Val::Bytes(b) => visitor.visit_seq(SeqDe(b.into_iter().map(Val::U8))),
            Val::Text(s) => visitor.visit_string(s),
            Val::Array(v) => visitor.visit_seq(SeqDe(v.into_iter())),
            Val::Map(kv) => visitor.visit_map(MapDe { it: kv.into_iter(), value: None }),
        }
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        match self.0 {
            Val::Bytes(b) => visitor.visit_byte_buf(b),
            v => ValDe(v).deserialize_any(visitor),
        }
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        match self.0 {
            Val::Null => visitor.visit_none(),
            v => visitor.visit_some(ValDe(v)),
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, visitor: V) -> Result<V::Value, WireError> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_enum<V: Visitor<'de>>(self, _: &'static str, _: &'static [&'static str], visitor: V) -> Result<V::Value, WireError> {
        match self.0 {
            v @ Val::Text(_) => visitor.visit_enum(EnumDe { variant: v, value: None }),
            Val::Map(mut kv) if kv.len() == 1 => {
                let (k, v) = kv.remove(0);
                visitor.visit_enum(EnumDe { variant: k, value: Some(v) })
            }
            _ => bad("expected an enum variant"),
        }
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, WireError> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        unit unit_struct seq tuple tuple_struct map struct
    }
}

// ---------------------------------------------------------------- the libp2p codec

/// libp2p request-response codec over [`to_vec`] / [`from_slice`], with size limits.
pub struct Codec<Q, R> {
    request_max: u64,
    response_max: u64,
    _t: PhantomData<fn() -> (Q, R)>,
}

impl<Q, R> Codec<Q, R> {
    pub fn new(request_max: u64, response_max: u64) -> Self {
        Codec { request_max, response_max, _t: PhantomData }
    }
}

impl<Q, R> Clone for Codec<Q, R> {
    fn clone(&self) -> Self {
        Codec::new(self.request_max, self.response_max)
    }
}

fn io_err(e: WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

async fn read_all<T: AsyncRead + Unpin + Send>(io: &mut T, max: u64) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    io.take(max).read_to_end(&mut v).await?;
    Ok(v)
}

impl<Q, R> libp2p::request_response::Codec for Codec<Q, R>
where
    Q: Send + Serialize + DeserializeOwned,
    R: Send + Serialize + DeserializeOwned,
{
    type Protocol = StreamProtocol;
    type Request = Q;
    type Response = R;

    async fn read_request<T: AsyncRead + Unpin + Send>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Q> {
        from_slice(&read_all(io, self.request_max).await?).map_err(io_err)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<R> {
        from_slice(&read_all(io, self.response_max).await?).map_err(io_err)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(&mut self, _: &StreamProtocol, io: &mut T, q: Q) -> io::Result<()> {
        io.write_all(&to_vec(&q).map_err(io_err)?).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(&mut self, _: &StreamProtocol, io: &mut T, r: R) -> io::Result<()> {
        io.write_all(&to_vec(&r).map_err(io_err)?).await
    }
}
