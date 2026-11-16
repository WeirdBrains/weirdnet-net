//! Sealed exchange messaging over a node: a request sealed under an exchange key goes out
//! inside the application's own envelope, and the answer comes back sealed the other way.
//!
//! The receiving side ([`serve`]) opens a message only when the exchange is known, active,
//! and belongs to the Noise-authenticated sender; the exchange id, both peer ids and the
//! direction are bound as associated data. What is inside (the application's request and
//! answer types, what each may reach) stays the application's.
use crate::error::{NetError, Result};
use crate::node::{Message, Node};
use crate::profile::Profile;
use libp2p::{Multiaddr, PeerId};
use weirdnet_keys::{Key32, Sealed};
use zeroize::Zeroizing;

/// The application's request envelope: how a sealed request travels.
pub trait Envelope: Message {
    fn sealed(exchange: String, sealed: Sealed) -> Self;
}

/// The application's answer envelope: a sealed answer, or something else (an error, say)
/// handed back as it is.
pub trait Reply: Message {
    fn sealed(sealed: Sealed) -> Self;
    fn into_sealed(self) -> std::result::Result<Sealed, Self>;
}

/// What came back from [`call`].
pub enum Answered<R> {
    /// The opened answer.
    Opened(Zeroizing<Vec<u8>>),
    /// Not a sealed answer; the application reads it.
    Other(R),
}

/// One side's view of an exchange it sends over.
pub struct Exchange<'a> {
    pub id: &'a str,
    pub key: &'a Key32,
    pub peer: PeerId,
}

/// Seal `plain` for the exchange's peer, send it, and open the sealed answer.
pub fn call<Q: Envelope, R: Reply>(p: &Profile, node: &Node<Q, R>, x: &Exchange, addrs: &[Multiaddr], plain: &[u8]) -> Result<Answered<R>> {
    let me = node.peer_id();
    let sealed = p.seal_msg(x.key, x.id, &me, &x.peer, plain)?;
    Ok(match node.request(x.peer, addrs, Q::sealed(x.id.to_string(), sealed))?.into_sealed() {
        Ok(s) => Answered::Opened(p.open_msg(x.key, x.id, &x.peer, &me, &s)?),
        Err(other) => Answered::Other(other),
    })
}

/// Where the receiving side looks exchanges up.
pub trait Exchanges {
    /// The application's exchange record.
    type Exchange;
    type Error: From<NetError>;
    fn exchange(&self, id: &str) -> std::result::Result<Option<Self::Exchange>, Self::Error>;
    /// Completed and not revoked.
    fn active(x: &Self::Exchange) -> bool;
    /// The peer id on the other side.
    fn peer(x: &Self::Exchange) -> Option<&str>;
    fn key(&self, x: &Self::Exchange) -> std::result::Result<Option<Key32>, Self::Error>;
}

/// Answer a sealed request from `from` (the Noise-authenticated peer): look the exchange
/// up, refuse unknown, inactive or someone else's, open, let `answer` make the reply (with
/// the store, the exchange and the opened bytes), and seal that back. Errors are the caller's to put
/// in its own envelope.
pub fn serve<S: Exchanges>(
    p: &Profile,
    store: &mut S,
    local: &PeerId,
    from: &PeerId,
    exchange: &str,
    sealed: &Sealed,
    answer: impl FnOnce(&mut S, &S::Exchange, &[u8]) -> std::result::Result<Vec<u8>, S::Error>,
) -> std::result::Result<Sealed, S::Error> {
    let x = store.exchange(exchange)?.ok_or_else(|| NetError::invalid("exchange", "unknown exchange"))?;
    if !S::active(&x) {
        return Err(NetError::invalid("exchange", "this exchange is not active (revoked or never completed)").into());
    }
    if S::peer(&x) != Some(&from.to_string()) {
        return Err(NetError::invalid("exchange", "this exchange belongs to another node").into());
    }
    let id = exchange.to_string();
    let key = store.key(&x)?.ok_or_else(|| NetError::invalid("exchange", "no key"))?;
    let plain = p.open_msg(&key, &id, from, local, sealed)?;
    let out = answer(store, &x, &plain)?;
    Ok(p.seal_msg(&key, &id, local, from, &out)?)
}

// ---- Sealed streams -------------------------------------------------------------------------

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 5] = b"WNSS1";
const OK: u8 = 0;
const REFUSED: u8 = 1;
const KIND_DATA: u8 = 0;
const KIND_FIN: u8 = 1;
const TAG: usize = 16;

/// The largest plaintext in one sealed frame; longer writes are split.
pub const MAX_SEALED_FRAME: usize = 64 * 1024;

/// A stream sealed with an exchange key ([`open_stream`], [`serve_stream`]).
///
/// Both sides add a random 16-byte nonce at the start, and each direction gets its own key,
/// derived (HKDF-SHA256) from the exchange key, both nonces, the exchange id and both peer ids
/// in order. Every frame is XChaCha20-Poly1305 with the stream id (both nonces), its sequence
/// number and its kind as associated data, so frames can't be reordered, replayed, moved to
/// another stream or turned around. The end is a sealed `fin` frame, so a cut-off stream reads
/// as an error, not as a short one.
pub struct SealedStream<S> {
    inner: S,
    id: [u8; 32],
    label: String,
    send: XChaCha20Poly1305,
    recv: XChaCha20Poly1305,
    sent: u64,
    got: u64,
    done_writing: bool,
    done_reading: bool,
}

impl<S> std::fmt::Debug for SealedStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedStream").field("sent", &self.sent).field("got", &self.got).finish()
    }
}

fn stream_label(p: &Profile) -> String {
    format!("{}/stream", p.msg_aad)
}

fn direction_key(label: &str, key: &Key32, id: &[u8; 32], exchange: &str, from: &PeerId, to: &PeerId) -> Result<XChaCha20Poly1305> {
    let info = format!("{label}/key|{exchange}|{from}|{to}");
    let k = weirdnet_keys::kdf::hkdf(&key.0, Some(id), info.as_bytes())?;
    Ok(XChaCha20Poly1305::new((&k.0).into()))
}

fn io_err(e: std::io::Error) -> NetError {
    NetError::Network(format!("sealed stream: {e}"))
}

fn crypto(m: &str) -> NetError {
    NetError::Crypto(format!("sealed stream: {m}"))
}

impl<S> SealedStream<S> {
    fn new(p: &Profile, inner: S, key: &Key32, id: [u8; 32], exchange: &str, local: &PeerId, peer: &PeerId) -> Result<Self> {
        let label = stream_label(p);
        Ok(Self {
            send: direction_key(&label, key, &id, exchange, local, peer)?,
            recv: direction_key(&label, key, &id, exchange, peer, local)?,
            inner,
            id,
            label,
            sent: 0,
            got: 0,
            done_writing: false,
            done_reading: false,
        })
    }

    fn aad(&self, seq: u64, kind: u8) -> Vec<u8> {
        let mut a = Vec::with_capacity(self.label.len() + 42);
        a.extend_from_slice(self.label.as_bytes());
        a.push(b'|');
        a.extend_from_slice(&self.id);
        a.extend_from_slice(&seq.to_be_bytes());
        a.push(kind);
        a
    }

    fn nonce(seq: u64, kind: u8) -> XNonce {
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&seq.to_be_bytes());
        n[8] = kind;
        *XNonce::from_slice(&n)
    }

    /// The stream id both sides bound into every frame.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The stream underneath.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SealedStream<S> {
    async fn frame(&mut self, kind: u8, plain: &[u8]) -> Result<()> {
        let seq = self.sent;
        let aad = self.aad(seq, kind);
        let ct = self.send.encrypt(&Self::nonce(seq, kind), Payload { msg: plain, aad: &aad }).map_err(|_| crypto("sealing failed"))?;
        let mut out = Vec::with_capacity(ct.len() + 5);
        out.push(kind);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        self.inner.write_all(&out).await.map_err(io_err)?;
        self.inner.flush().await.map_err(io_err)?;
        self.sent += 1;
        Ok(())
    }

    /// Seals and sends `data` (in frames of at most [`MAX_SEALED_FRAME`] bytes).
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.done_writing {
            return Err(NetError::Network("sealed stream: already finished".into()));
        }
        for c in data.chunks(MAX_SEALED_FRAME) {
            self.frame(KIND_DATA, c).await?;
        }
        Ok(())
    }

    /// Sends the sealed end and closes the sending side.
    pub async fn finish(&mut self) -> Result<()> {
        if !self.done_writing {
            self.frame(KIND_FIN, &[]).await?;
            self.done_writing = true;
            let _ = self.inner.close().await;
        }
        Ok(())
    }

    /// The next frame's bytes, or `None` after the peer's sealed end. A stream that ends
    /// without it, or any frame that fails to open, is an error.
    pub async fn recv(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if self.done_reading {
            return Ok(None);
        }
        let mut head = [0u8; 5];
        match self.inner.read_exact(&mut head).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(crypto("the stream ended without its sealed end (truncated)")),
            Err(e) => return Err(io_err(e)),
        }
        let kind = head[0];
        let n = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
        if kind > KIND_FIN || !(TAG..=MAX_SEALED_FRAME + TAG).contains(&n) {
            return Err(crypto("bad frame"));
        }
        let mut ct = vec![0u8; n];
        self.inner.read_exact(&mut ct).await.map_err(io_err)?;
        let seq = self.got;
        let aad = self.aad(seq, kind);
        let plain = self
            .recv
            .decrypt(&Self::nonce(seq, kind), Payload { msg: &ct, aad: &aad })
            .map_err(|_| crypto("a frame failed to authenticate (tampered, reordered or replayed)"))?;
        self.got += 1;
        if kind == KIND_FIN {
            if !plain.is_empty() {
                return Err(crypto("bad end frame"));
            }
            self.done_reading = true;
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(plain)))
    }

    /// Reads every frame up to the sealed end.
    pub async fn read_to_end(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut all = Zeroizing::new(Vec::new());
        while let Some(b) = self.recv().await? {
            all.extend_from_slice(&b);
        }
        Ok(all)
    }
}

async fn read_hello<S: AsyncRead + Unpin>(s: &mut S) -> Result<(String, [u8; 16])> {
    let mut m = [0u8; 7];
    s.read_exact(&mut m).await.map_err(io_err)?;
    if &m[..5] != MAGIC {
        return Err(NetError::invalid("sealed stream", "not a sealed stream"));
    }
    let n = u16::from_be_bytes([m[5], m[6]]) as usize;
    if n == 0 || n > 256 {
        return Err(NetError::invalid("sealed stream", "bad exchange id"));
    }
    let mut id = vec![0u8; n];
    s.read_exact(&mut id).await.map_err(io_err)?;
    let mut nonce = [0u8; 16];
    s.read_exact(&mut nonce).await.map_err(io_err)?;
    let id = String::from_utf8(id).map_err(|_| NetError::invalid("sealed stream", "bad exchange id"))?;
    Ok((id, nonce))
}

fn stream_id(opener: &[u8; 16], acceptor: &[u8; 16]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..16].copy_from_slice(opener);
    id[16..].copy_from_slice(acceptor);
    id
}

/// Seals an opened stream to the exchange's peer: says which exchange, and agrees the stream
/// id. Fails if the peer refuses (unknown, inactive or someone else's exchange).
pub async fn open_stream<S: AsyncRead + AsyncWrite + Unpin>(p: &Profile, mut s: S, local: &PeerId, x: &Exchange<'_>) -> Result<SealedStream<S>> {
    if x.id.is_empty() || x.id.len() > 256 {
        return Err(NetError::invalid("sealed stream", "bad exchange id"));
    }
    let mine: [u8; 16] = weirdnet_keys::random_bytes()?;
    let mut hello = Vec::with_capacity(23 + x.id.len());
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&(x.id.len() as u16).to_be_bytes());
    hello.extend_from_slice(x.id.as_bytes());
    hello.extend_from_slice(&mine);
    s.write_all(&hello).await.map_err(io_err)?;
    s.flush().await.map_err(io_err)?;
    let mut st = [0u8; 1];
    s.read_exact(&mut st).await.map_err(io_err)?;
    if st[0] != OK {
        return Err(NetError::invalid("sealed stream", "the peer refused the exchange"));
    }
    let mut theirs = [0u8; 16];
    s.read_exact(&mut theirs).await.map_err(io_err)?;
    SealedStream::new(p, s, x.key, stream_id(&mine, &theirs), x.id, local, &x.peer)
}

/// The receiving side of [`open_stream`]: reads which exchange the stream is for, refuses
/// unknown, inactive or someone else's exchanges (`from` is the Noise-authenticated peer, such
/// as [`crate::stream::Stream::peer`]), and returns the sealed stream with the exchange.
pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin, X: Exchanges>(
    p: &Profile,
    store: &X,
    mut s: S,
    local: &PeerId,
    from: &PeerId,
) -> std::result::Result<(SealedStream<S>, X::Exchange), X::Error> {
    let (exchange, theirs) = read_hello(&mut s).await?;
    let refuse = |m: &'static str| NetError::invalid("exchange", m);
    let check = || -> std::result::Result<(X::Exchange, Key32), X::Error> {
        let x = store.exchange(&exchange)?.ok_or_else(|| refuse("unknown exchange"))?;
        if !X::active(&x) {
            return Err(refuse("this exchange is not active (revoked or never completed)").into());
        }
        if X::peer(&x) != Some(&from.to_string()) {
            return Err(refuse("this exchange belongs to another node").into());
        }
        let key = store.key(&x)?.ok_or_else(|| refuse("no key"))?;
        Ok((x, key))
    };
    match check() {
        Ok((x, key)) => {
            let mine: [u8; 16] = weirdnet_keys::random_bytes().map_err(NetError::from)?;
            let mut out = vec![OK];
            out.extend_from_slice(&mine);
            s.write_all(&out).await.map_err(io_err)?;
            s.flush().await.map_err(io_err)?;
            let ss = SealedStream::new(p, s, &key, stream_id(&theirs, &mine), &exchange, local, from)?;
            Ok((ss, x))
        }
        Err(e) => {
            let _ = s.write_all(&[REFUSED]).await;
            let _ = s.close().await;
            Err(e)
        }
    }
}
