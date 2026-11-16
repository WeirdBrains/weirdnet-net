//! Streams (W1) that survive path changes (W15).
//!
//! An application accepts streams of its own protocol ids ([`Node::accept_streams`]) and opens
//! them to a peer ([`Node::open_stream`]). A [`Stream`] is an ordered, reliable byte stream with
//! no size cap and backpressure (a sender has at most [`Limits::window`] bytes unacknowledged).
//! It is a logical stream: underneath, a libp2p substream carries it, over a direct connection
//! when there is one, else through a relay.
//!
//! Path switching: when a direct connection to the peer comes up (DCUtR hole punching, or a
//! dial), the side that opened the stream moves it there; when the connection under a stream
//! goes away, the opener re-opens it over whatever path is left (the relay, kept warm while
//! streams are open) and both sides carry on where the other stopped. Nothing is lost or
//! repeated: every data frame carries its byte offset, each side acknowledges what it has, and
//! after a move the sender sends again what wasn't acknowledged. A stream fails only when no
//! path comes back within [`Limits::resume`].
//!
//! Wire format, on every substream of the application's protocol: the opener sends `Hello`
//! (new or resume, the stream id, bytes received so far) and the acceptor answers `Welcome`
//! (bytes received so far) or `Refuse`; then `Data` (offset, bytes), `Ack` (bytes received),
//! `Fin` (total bytes) and `Reset` frames, each one a type byte and big-endian fields.
//! Traffic is end-to-end encrypted by the connection (Noise), relayed or not.
//!
//! [`Node::accept_streams`]: crate::Node::accept_streams
//! [`Node::open_stream`]: crate::Node::open_stream
pub(crate) mod transport;

use futures::channel::mpsc;
use futures::io::{ReadHalf, WriteHalf};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, SinkExt, StreamExt};
use libp2p::{PeerId, StreamProtocol};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use transport::{Control, OpenError, PathEvent, Warm};

/// How streams of one protocol behave.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Bytes a sender may have in flight unacknowledged (and a receiver buffers).
    pub window: usize,
    /// Largest data frame.
    pub max_frame: usize,
    /// Streams of this protocol open at once from others (more are refused).
    pub max_streams: usize,
    /// New inbound streams waiting for [`Incoming::accept`] (more are refused).
    pub backlog: usize,
    /// How long a stream waits for a path to come back before it fails.
    pub resume: Duration,
    /// Reset a stream after this long with nothing sent or received (`None`: never).
    pub idle: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { window: 1 << 20, max_frame: 64 * 1024, max_streams: 1024, backlog: 64, resume: Duration::from_secs(30), idle: None }
    }
}

/// The kind of connection a stream is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Path {
    Direct,
    Relayed,
}

const HELLO: u8 = 1;
const WELCOME: u8 = 2;
const REFUSE: u8 = 3;
const DATA: u8 = 16;
const ACK: u8 = 17;
const FIN: u8 = 18;
const RESET: u8 = 19;

const REFUSE_BUSY: u8 = 1;
const REFUSE_UNKNOWN: u8 = 2;
const RESET_APP: u8 = 1;
const RESET_IDLE: u8 = 2;

const HANDSHAKE: Duration = Duration::from_secs(10);
const LINGER: Duration = Duration::from_secs(2);
const ACK_EVERY: Duration = Duration::from_millis(50);

#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Hello { resume: bool, id: u64, recv: u64 },
    Welcome { recv: u64 },
    Refuse(u8),
    Data { off: u64, bytes: Vec<u8> },
    Ack(u64),
    Fin(u64),
    Reset(u8),
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

async fn u64_of<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).await?;
    Ok(u64::from_be_bytes(b))
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max_frame: usize) -> io::Result<Frame> {
    let mut t = [0u8; 1];
    r.read_exact(&mut t).await?;
    Ok(match t[0] {
        HELLO => {
            let mut f = [0u8; 1];
            r.read_exact(&mut f).await?;
            Frame::Hello { resume: f[0] & 1 == 1, id: u64_of(r).await?, recv: u64_of(r).await? }
        }
        WELCOME => Frame::Welcome { recv: u64_of(r).await? },
        REFUSE | RESET => {
            let mut c = [0u8; 1];
            r.read_exact(&mut c).await?;
            if t[0] == REFUSE { Frame::Refuse(c[0]) } else { Frame::Reset(c[0]) }
        }
        DATA => {
            let off = u64_of(r).await?;
            let mut l = [0u8; 4];
            r.read_exact(&mut l).await?;
            let n = u32::from_be_bytes(l) as usize;
            if n > max_frame {
                return Err(bad("data frame too large"));
            }
            let mut bytes = vec![0u8; n];
            r.read_exact(&mut bytes).await?;
            Frame::Data { off, bytes }
        }
        ACK => Frame::Ack(u64_of(r).await?),
        FIN => Frame::Fin(u64_of(r).await?),
        _ => return Err(bad("unknown frame")),
    })
}

fn encode(f: &Frame, out: &mut Vec<u8>) {
    match f {
        Frame::Hello { resume, id, recv } => {
            out.extend([HELLO, *resume as u8]);
            out.extend(id.to_be_bytes());
            out.extend(recv.to_be_bytes());
        }
        Frame::Welcome { recv } => {
            out.push(WELCOME);
            out.extend(recv.to_be_bytes());
        }
        Frame::Refuse(c) => out.extend([REFUSE, *c]),
        Frame::Reset(c) => out.extend([RESET, *c]),
        Frame::Data { off, bytes } => {
            out.push(DATA);
            out.extend(off.to_be_bytes());
            out.extend((bytes.len() as u32).to_be_bytes());
            out.extend(bytes);
        }
        Frame::Ack(n) => {
            out.push(ACK);
            out.extend(n.to_be_bytes());
        }
        Frame::Fin(n) => {
            out.push(FIN);
            out.extend(n.to_be_bytes());
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    let mut b = Vec::new();
    encode(f, &mut b);
    w.write_all(&b).await?;
    w.flush().await
}

type Sub = (ReadHalf<libp2p::Stream>, WriteHalf<libp2p::Stream>);

/// What a [`Stream`] reads: bytes, or why the stream failed.
type Chunk = Result<Vec<u8>, String>;

#[derive(Default)]
struct Info {
    relayed: AtomicBool,
    moves: AtomicU32,
}

/// A reliable byte stream to a peer that moves between relayed and direct connections without
/// losing anything. Use it as a `futures` `AsyncRead`/`AsyncWrite`, or with the blocking
/// `std::io::Read`/`Write` (not from inside an async task). Closing (or dropping) it ends the
/// sending side; reads return 0 once the peer has closed its side and everything has arrived.
pub struct Stream {
    peer: PeerId,
    protocol: String,
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: mpsc::Receiver<Chunk>,
    buf: Vec<u8>,
    pos: usize,
    info: Arc<Info>,
    reset: mpsc::UnboundedSender<()>,
    max_frame: usize,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("peer", &self.peer).field("protocol", &self.protocol).field("path", &self.path()).finish()
    }
}

impl Stream {
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The kind of connection the stream is on now.
    pub fn path(&self) -> Path {
        if self.info.relayed.load(Ordering::Relaxed) { Path::Relayed } else { Path::Direct }
    }

    /// How many times the stream has moved to another connection.
    pub fn moves(&self) -> u32 {
        self.info.moves.load(Ordering::Relaxed)
    }

    /// End the sending side (the peer reads to the end of what was written).
    pub fn close_write(&mut self) {
        self.tx = None;
    }

    /// Abort the stream both ways; the peer's reads fail.
    pub fn reset(self) {
        let _ = self.reset.unbounded_send(());
    }
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            if this.pos < this.buf.len() {
                let n = out.len().min(this.buf.len() - this.pos);
                out[..n].copy_from_slice(&this.buf[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(n));
            }
            match this.rx.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(v))) => {
                    this.buf = v;
                    this.pos = 0;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e))),
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let max = self.max_frame;
        let Some(tx) = self.tx.as_mut() else { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())) };
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let n = buf.len().min(max);
                match tx.start_send(buf[..n].to_vec()) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx = None;
        Poll::Ready(Ok(()))
    }
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        futures::executor::block_on(AsyncReadExt::read(self, buf))
    }
}

impl io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        futures::executor::block_on(AsyncWriteExt::write(self, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Inbound streams of one protocol. Dropping it stops accepting them.
pub struct Incoming {
    protocol: String,
    rx: mpsc::Receiver<Stream>,
    _task: Abort,
}

struct Abort(tokio::task::AbortHandle);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Incoming {
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The next stream (blocking; `None` once the node stops).
    pub fn accept(&mut self) -> Option<Stream> {
        futures::executor::block_on(self.rx.next())
    }

    /// The next stream, waiting at most `d`.
    pub fn accept_timeout(&mut self, d: Duration) -> Option<Stream> {
        let deadline = Instant::now() + d;
        loop {
            match self.rx.try_next() {
                Ok(s) => return s,
                Err(_) if Instant::now() >= deadline => return None,
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    /// The next stream (async).
    pub async fn next(&mut self) -> Option<Stream> {
        self.rx.next().await
    }
}

impl futures::Stream for Incoming {
    type Item = Stream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Stream>> {
        self.rx.poll_next_unpin(cx)
    }
}

/// A substream that resumes a stream, handed to its driver.
struct Resume {
    sub: Sub,
    relayed: bool,
    recv: u64,
}

type Registry = Arc<Mutex<HashMap<(PeerId, u64), mpsc::UnboundedSender<Resume>>>>;

fn stream_err(e: OpenError) -> crate::NetError {
    crate::NetError::Network(e.to_string())
}

fn app_side(peer: PeerId, protocol: &StreamProtocol, limits: &Limits, relayed: bool) -> (Stream, AppEnds, Arc<Info>) {
    let (tx, app_in) = mpsc::channel(4);
    let (app_out, rx) = mpsc::channel(4);
    let (reset, reset_rx) = mpsc::unbounded();
    let info = Arc::new(Info::default());
    info.relayed.store(relayed, Ordering::Relaxed);
    let s = Stream {
        peer,
        protocol: protocol.to_string(),
        tx: Some(tx),
        rx,
        buf: vec![],
        pos: 0,
        info: info.clone(),
        reset,
        max_frame: limits.max_frame,
    };
    (s, AppEnds { app_in, app_out, reset_rx }, info)
}

struct AppEnds {
    app_in: mpsc::Receiver<Vec<u8>>,
    app_out: mpsc::Sender<Chunk>,
    reset_rx: mpsc::UnboundedReceiver<()>,
}

/// Open a stream of `protocol` to `peer` (already connected or dialable by peer id).
pub(crate) async fn open(control: Control, peer: PeerId, protocol: StreamProtocol, limits: Limits) -> crate::Result<Stream> {
    let id = u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap_or_default());
    let (sub, relayed, _) = handshake(&control, peer, &protocol, id, false, 0, &limits).await?;
    let (s, ends, info) = app_side(peer, &protocol, &limits, relayed);
    let warm = control.watch();
    let d = Driver::new(peer, protocol, id, true, limits, control, ends, info, warm, None);
    tokio::spawn(d.run(sub, relayed));
    Ok(s)
}

/// The opener's handshake on a new substream: `Hello`, then the peer's `Welcome`.
async fn handshake(
    control: &Control,
    peer: PeerId,
    protocol: &StreamProtocol,
    id: u64,
    resume: bool,
    recv: u64,
    limits: &Limits,
) -> crate::Result<(Sub, bool, u64)> {
    let opened = tokio::time::timeout(HANDSHAKE, control.open(peer, protocol.clone()))
        .await
        .map_err(|_| crate::NetError::Network(format!("no stream to {peer} in time")))?
        .map_err(stream_err)?;
    let (s, relayed) = opened;
    let (mut r, mut w) = s.split();
    let shake = async {
        write_frame(&mut w, &Frame::Hello { resume, id, recv }).await?;
        read_frame(&mut r, limits.max_frame).await
    };
    match tokio::time::timeout(HANDSHAKE, shake).await {
        Ok(Ok(Frame::Welcome { recv })) => Ok(((r, w), relayed, recv)),
        Ok(Ok(Frame::Refuse(REFUSE_BUSY))) => Err(crate::NetError::Network(format!("{peer} has too many {protocol} streams"))),
        Ok(Ok(Frame::Refuse(_))) => Err(crate::NetError::Network(format!("{peer} refused the {protocol} stream"))),
        Ok(Ok(_)) => Err(crate::NetError::Network("unexpected stream frame".into())),
        Ok(Err(e)) => Err(crate::NetError::Network(format!("stream handshake: {e}"))),
        Err(_) => Err(crate::NetError::Network("stream handshake timed out".into())),
    }
}

/// Accept streams of `protocol`: answer handshakes, hand new streams to the returned
/// [`Incoming`] and resumes to their drivers.
pub(crate) fn accept(control: Control, protocol: StreamProtocol, limits: Limits, rt: &tokio::runtime::Handle) -> crate::Result<Incoming> {
    let Some(mut inbound) = control.accept(protocol.clone(), limits.backlog.max(1)) else {
        return Err(crate::NetError::Network(format!("{protocol} streams are accepted already")));
    };
    let (tx, rx) = mpsc::channel(limits.backlog.max(1));
    let registry: Registry = Arc::default();
    let p = protocol.clone();
    let task = rt.spawn(async move {
        while let Some((peer, s, relayed)) = inbound.next().await {
            let (control, protocol, registry, mut tx) = (control.clone(), p.clone(), registry.clone(), tx.clone());
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let hello = tokio::time::timeout(HANDSHAKE, read_frame(&mut r, limits.max_frame)).await;
                let Ok(Ok(Frame::Hello { resume, id, recv })) = hello else { return };
                if resume {
                    let to = registry.lock().ok().and_then(|m| m.get(&(peer, id)).cloned());
                    match to {
                        Some(to) => {
                            let _ = to.unbounded_send(Resume { sub: (r, w), relayed, recv });
                        }
                        None => {
                            let _ = write_frame(&mut w, &Frame::Refuse(REFUSE_UNKNOWN)).await;
                        }
                    }
                    return;
                }
                let full = registry.lock().map(|m| m.len() >= limits.max_streams || m.contains_key(&(peer, id))).unwrap_or(true);
                if full {
                    let _ = write_frame(&mut w, &Frame::Refuse(REFUSE_BUSY)).await;
                    return;
                }
                let (s, ends, info) = app_side(peer, &protocol, &limits, relayed);
                if tx.try_send(s).is_err() {
                    let _ = write_frame(&mut w, &Frame::Refuse(REFUSE_BUSY)).await;
                    return;
                }
                if write_frame(&mut w, &Frame::Welcome { recv: 0 }).await.is_err() {
                    return;
                }
                let (rtx, rrx) = mpsc::unbounded();
                if let Ok(mut m) = registry.lock() {
                    m.insert((peer, id), rtx);
                }
                let watch = control.watch();
                let d = Driver::new(peer, protocol, id, false, limits, control, ends, info, watch, Some(rrx));
                d.run((r, w), relayed).await;
                if let Ok(mut m) = registry.lock() {
                    m.remove(&(peer, id));
                }
            });
        }
        let _ = tx.close().await;
    });
    Ok(Incoming { protocol: protocol.to_string(), rx, _task: Abort(task.abort_handle()) })
}

/// Carries one logical stream over its current substream, and moves it.
struct Driver {
    peer: PeerId,
    protocol: StreamProtocol,
    id: u64,
    opener: bool,
    limits: Limits,
    control: Control,
    _warm: Warm,
    info: Arc<Info>,
    watch: mpsc::UnboundedReceiver<PathEvent>,
    resumes: Option<mpsc::UnboundedReceiver<Resume>>,
    // the current substream's writer and generation; frames from every reader
    writer: Option<WriteHalf<libp2p::Stream>>,
    relayed: bool,
    generation: u64,
    frames_tx: mpsc::Sender<(u64, Option<Frame>)>,
    frames: mpsc::Receiver<(u64, Option<Frame>)>,
    // sending: bytes from `acked` on, the next offset to write, the total once closed
    out: VecDeque<u8>,
    acked: u64,
    sent: u64,
    app_in: Option<mpsc::Receiver<Vec<u8>>>,
    fin: Option<u64>,
    fin_sent: Option<u64>,
    // receiving
    inbox: VecDeque<Vec<u8>>,
    inbox_bytes: usize,
    recv: u64,
    ack_sent: u64,
    peer_fin: Option<u64>,
    app_out: Option<mpsc::Sender<Chunk>>,
    reset_rx: mpsc::UnboundedReceiver<()>,
    last: Instant,
}

enum Step {
    Go,
    Lost,
    Fail(String),
    Done,
}

impl Driver {
    #[allow(clippy::too_many_arguments)]
    fn new(
        peer: PeerId,
        protocol: StreamProtocol,
        id: u64,
        opener: bool,
        limits: Limits,
        control: Control,
        ends: AppEnds,
        info: Arc<Info>,
        watch: mpsc::UnboundedReceiver<PathEvent>,
        resumes: Option<mpsc::UnboundedReceiver<Resume>>,
    ) -> Self {
        let (frames_tx, frames) = mpsc::channel(16);
        Driver {
            peer,
            protocol,
            id,
            opener,
            limits,
            _warm: control.warm(peer),
            control,
            info,
            watch,
            resumes,
            writer: None,
            relayed: false,
            generation: 0,
            frames_tx,
            frames,
            out: VecDeque::new(),
            acked: 0,
            sent: 0,
            app_in: Some(ends.app_in),
            fin: None,
            fin_sent: None,
            inbox: VecDeque::new(),
            inbox_bytes: 0,
            recv: 0,
            ack_sent: 0,
            peer_fin: None,
            app_out: Some(ends.app_out),
            reset_rx: ends.reset_rx,
            last: Instant::now(),
        }
    }

    /// Make `sub` the stream's substream; the peer has `peer_recv` bytes of ours.
    fn adopt(&mut self, sub: Sub, relayed: bool, peer_recv: u64) {
        let (mut r, w) = sub;
        if let Some(mut old) = self.writer.replace(w) {
            tokio::spawn(async move {
                let _ = old.close().await;
            });
        }
        if self.generation > 0 {
            self.info.moves.fetch_add(1, Ordering::Relaxed);
        }
        self.generation += 1;
        self.relayed = relayed;
        self.info.relayed.store(relayed, Ordering::Relaxed);
        self.on_ack(peer_recv);
        self.sent = self.acked;
        self.fin_sent = None;
        // what we have counts as acknowledged: the handshake carried it
        self.ack_sent = self.ack_sent.max(self.recv);
        let (g, mut tx, max) = (self.generation, self.frames_tx.clone(), self.limits.max_frame);
        tokio::spawn(async move {
            loop {
                match read_frame(&mut r, max).await {
                    Ok(f) => {
                        if tx.send((g, Some(f))).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send((g, None)).await;
                        break;
                    }
                }
            }
        });
        tracing::debug!(peer = %self.peer, id = self.id, relayed, "network: stream on a new path");
    }

    fn on_ack(&mut self, n: u64) {
        if n > self.acked {
            let k = ((n - self.acked) as usize).min(self.out.len());
            self.out.drain(..k);
            self.acked += k as u64;
        }
    }

    async fn run(mut self, sub: Sub, relayed: bool) {
        self.adopt(sub, relayed, 0);
        let mut done_at: Option<Instant> = None;
        let mut tick = tokio::time::interval(ACK_EVERY);
        loop {
            let step = if self.writer.is_some() { self.flush().await } else { Step::Lost };
            let step = match step {
                Step::Go => self.select(&mut tick, done_at).await,
                s => s,
            };
            match step {
                Step::Go => {}
                Step::Done => return,
                Step::Fail(e) => return self.fail(e).await,
                Step::Lost => {
                    if done_at.is_some() {
                        return;
                    }
                    self.writer = None;
                    if let Err(e) = self.recover().await {
                        return self.fail(e).await;
                    }
                }
            }
            if done_at.is_none() && self.finished() {
                done_at = Some(Instant::now());
            }
        }
    }

    fn finished(&self) -> bool {
        self.fin.is_some_and(|f| self.acked == f && self.fin_sent.is_some())
            && self.peer_fin.is_some_and(|f| f == self.recv)
            && self.inbox.is_empty()
            && self.app_out.is_none()
            && self.ack_sent == self.recv
    }

    async fn fail(mut self, why: String) {
        tracing::debug!(peer = %self.peer, id = self.id, "network: stream failed: {why}");
        if let Some(w) = self.writer.as_mut() {
            let _ = write_frame(w, &Frame::Reset(RESET_APP)).await;
        }
        if let Some(mut tx) = self.app_out.take() {
            let _ = tx.try_send(Err(why));
        }
    }

    /// Write what hasn't been written on this substream (data, then the end).
    async fn flush(&mut self) -> Step {
        let Some(w) = self.writer.as_mut() else { return Step::Lost };
        let end = self.acked + self.out.len() as u64;
        let mut batch = Vec::new();
        while self.sent < end && batch.len() < 4 * self.limits.max_frame {
            let from = (self.sent - self.acked) as usize;
            let n = (self.out.len() - from).min(self.limits.max_frame);
            let bytes: Vec<u8> = self.out.range(from..from + n).copied().collect();
            encode(&Frame::Data { off: self.sent, bytes }, &mut batch);
            self.sent += n as u64;
        }
        if let Some(f) = self.fin
            && self.sent == f
            && self.fin_sent != Some(self.generation)
        {
            encode(&Frame::Fin(f), &mut batch);
            self.fin_sent = Some(self.generation);
        }
        if self.recv > self.ack_sent && (self.recv - self.ack_sent >= (self.limits.window / 4) as u64 || self.peer_fin.is_some()) {
            encode(&Frame::Ack(self.recv), &mut batch);
            self.ack_sent = self.recv;
        }
        if batch.is_empty() {
            return Step::Go;
        }
        self.last = Instant::now();
        match async {
            w.write_all(&batch).await?;
            w.flush().await
        }
        .await
        {
            Ok(()) => Step::Go,
            Err(_) => Step::Lost,
        }
    }

    async fn select(&mut self, tick: &mut tokio::time::Interval, done_at: Option<Instant>) -> Step {
        let window = self.limits.window;
        let can_read = self.inbox_bytes < window;
        let can_take = self.app_in.is_some() && self.out.len() < window;
        let deliver = !self.inbox.is_empty() || (self.peer_fin.is_some_and(|f| f == self.recv) && self.app_out.is_some());
        let idle = self.limits.idle.map(|d| self.last + d);
        let linger = done_at.map(|t| t + LINGER);
        tokio::select! {
            f = self.frames.next(), if can_read => match f {
                Some((g, Some(f))) => self.frame(g, f),
                Some((g, None)) if g == self.generation => Step::Lost,
                _ => Step::Go,
            },
            c = async { self.app_in.as_mut().unwrap().next().await }, if can_take => {
                match c {
                    Some(v) => self.out.extend(v),
                    None => {
                        self.app_in = None;
                        self.fin = Some(self.acked + self.out.len() as u64);
                    }
                }
                self.last = Instant::now();
                Step::Go
            }
            r = futures::future::poll_fn(|cx| match self.app_out.as_mut() {
                Some(tx) => tx.poll_ready(cx).map(|r| r.is_ok()),
                None => Poll::Ready(false),
            }), if deliver => {
                self.deliver(r);
                Step::Go
            }
            ev = self.watch.next() => {
                match ev {
                    Some(ev) if self.opener && ev.up && !ev.relayed && ev.peer == self.peer && self.relayed => self.migrate().await,
                    _ => {}
                }
                Step::Go
            }
            r = async { self.resumes.as_mut().unwrap().next().await }, if self.resumes.is_some() => {
                if let Some(r) = r {
                    self.take_resume(r).await;
                }
                Step::Go
            }
            _ = self.reset_rx.next() => Step::Fail("reset".into()),
            _ = tick.tick() => {
                if self.recv > self.ack_sent && let Some(w) = self.writer.as_mut() {
                    self.ack_sent = self.recv;
                    if write_frame(w, &Frame::Ack(self.recv)).await.is_err() {
                        return Step::Lost;
                    }
                }
                Step::Go
            }
            _ = async { tokio::time::sleep_until(idle.unwrap().into()).await }, if idle.is_some() && done_at.is_none() => {
                if let Some(w) = self.writer.as_mut() {
                    let _ = write_frame(w, &Frame::Reset(RESET_IDLE)).await;
                }
                Step::Fail("idle".into())
            }
            _ = async { tokio::time::sleep_until(linger.unwrap().into()).await }, if linger.is_some() => Step::Done,
        }
    }

    fn frame(&mut self, _g: u64, f: Frame) -> Step {
        self.last = Instant::now();
        match f {
            Frame::Data { off, bytes } => {
                let end = off + bytes.len() as u64;
                if off <= self.recv && end > self.recv {
                    let tail = bytes[(self.recv - off) as usize..].to_vec();
                    self.recv = end;
                    self.inbox_bytes += tail.len();
                    self.inbox.push_back(tail);
                }
                Step::Go
            }
            Frame::Ack(n) => {
                self.on_ack(n);
                Step::Go
            }
            Frame::Fin(n) => {
                self.peer_fin = Some(n);
                Step::Go
            }
            Frame::Reset(c) => Step::Fail(if c == RESET_IDLE { "the peer reset the idle stream".into() } else { "the peer reset the stream".into() }),
            _ => Step::Go,
        }
    }

    fn deliver(&mut self, ready: bool) {
        if !ready {
            // the reader is gone: what arrives is dropped
            self.app_out = None;
            self.inbox.clear();
            self.inbox_bytes = 0;
            return;
        }
        let Some(tx) = self.app_out.as_mut() else { return };
        match self.inbox.pop_front() {
            Some(v) => {
                self.inbox_bytes -= v.len();
                if tx.start_send(Ok(v)).is_err() {
                    self.app_out = None;
                }
            }
            None => self.app_out = None, // the peer's end: reads return 0
        }
    }

    /// The opener moves the stream to a new direct connection.
    async fn migrate(&mut self) {
        if !self.control.has_direct(self.peer) {
            return;
        }
        match handshake(&self.control, self.peer, &self.protocol, self.id, true, self.recv, &self.limits).await {
            Ok((sub, false, peer_recv)) => self.adopt(sub, false, peer_recv),
            Ok(_) => {}
            Err(e) => tracing::debug!(peer = %self.peer, "network: stream stays relayed: {e}"),
        }
    }

    async fn take_resume(&mut self, r: Resume) {
        let Resume { sub: (rd, mut w), relayed, recv } = r;
        if write_frame(&mut w, &Frame::Welcome { recv: self.recv }).await.is_ok() {
            self.adopt((rd, w), relayed, recv);
        }
    }

    /// The substream went away: the opener opens another, the acceptor waits for one.
    async fn recover(&mut self) -> std::result::Result<(), String> {
        let deadline = tokio::time::Instant::now() + self.limits.resume;
        let mut wait = Duration::from_millis(100);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("no path to the peer came back".into());
            }
            if self.opener {
                match handshake(&self.control, self.peer, &self.protocol, self.id, true, self.recv, &self.limits).await {
                    Ok((sub, relayed, peer_recv)) => {
                        self.adopt(sub, relayed, peer_recv);
                        return Ok(());
                    }
                    Err(e) if e.to_string().contains("refused") => return Err(e.to_string()),
                    Err(e) => tracing::debug!(peer = %self.peer, "network: stream resume: {e}"),
                }
                tokio::time::sleep(wait.min(deadline.saturating_duration_since(tokio::time::Instant::now()))).await;
                wait = (wait * 2).min(Duration::from_secs(2));
            } else {
                let next = async { self.resumes.as_mut().unwrap().next().await };
                match tokio::time::timeout_at(deadline, next).await {
                    Ok(Some(r)) => {
                        self.take_resume(r).await;
                        if self.writer.is_some() {
                            return Ok(());
                        }
                    }
                    Ok(None) => return Err("closed".into()),
                    Err(_) => return Err("the peer did not come back".into()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame::Hello { resume: true, id: 7, recv: 1 << 40 },
            Frame::Welcome { recv: 3 },
            Frame::Refuse(REFUSE_BUSY),
            Frame::Data { off: 9, bytes: vec![1, 2, 3] },
            Frame::Ack(12),
            Frame::Fin(12),
            Frame::Reset(RESET_APP),
        ];
        for f in frames {
            let mut b = vec![];
            encode(&f, &mut b);
            let got = futures::executor::block_on(read_frame(&mut &b[..], 1024)).unwrap();
            assert_eq!(got, f);
        }
        let mut b = vec![];
        encode(&Frame::Data { off: 0, bytes: vec![0; 2048] }, &mut b);
        assert!(futures::executor::block_on(read_frame(&mut &b[..], 1024)).is_err());
        assert!(futures::executor::block_on(read_frame(&mut &[99u8][..], 1024)).is_err());
    }
}
