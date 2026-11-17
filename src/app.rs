//! App calls: request/response exchanges with streamed bodies between nodes, for apps that
//! speak HTTP-like methods and paths over Weirdnet (Morph's `weirdnet-<app>://` URLs).
//!
//! One libp2p stream per call on [`APP_PROTOCOL`]:
//!
//! - the caller writes a head, CBOR `{v: 1, app, method, path, headers}` prefixed with its
//!   unsigned-varint length (at most the header cap), then the body as varint-length frames
//!   ending with a zero-length frame;
//! - the server answers with CBOR `{v: 1, status, headers}` the same way, then the response
//!   body frames and a zero-length frame; on an error, CBOR `{v: 1, error, message}` takes
//!   the place of the response head (`error` is an [`AppError::code`]);
//! - either side cancels by closing or resetting the stream. The zero-length frame ends a
//!   body, so the caller never half-closes: when it drops a call the stream is reset and the
//!   server's handler and body stop. The server closes its side after its last frame.
//!
//! Frames this crate writes are at most [`WRITE_FRAME`] bytes; it reads frames up to
//! [`MAX_FRAME`]. The caps come from [`NodeConfig`](crate::NodeConfig): `app_header_max`
//! (16 KiB by default) for each head, `app_body_max` (none by default) for each body, and
//! `app_idle_timeout` (60 s by default), how long a call may go without a byte. There are no
//! rate or bandwidth limits; relays forward the bytes under their own circuit limits.
//!
//! A node serving app `X` also accepts `/weirdnet/app/1/X`, so identify tells peers which
//! apps it serves (`app:X` in a [`Sighting`](crate::Sighting)'s caps, and
//! [`Node::peer_apps`](crate::Node::peer_apps)); nothing is ever sent on that protocol.
//!
//! ```no_run
//! use std::{sync::Arc, time::Duration};
//! use weirdnet_net::{AppRequest, AppResponse, Node, PeerId};
//! # fn demo(server: &Node<(), ()>, client: &Node<(), ()>, user_id: &str) -> Result<(), weirdnet_net::AppError> {
//! server.serve_app("notes", Arc::new(|peer: PeerId, req: AppRequest| async move {
//!     let body = req.body.collect().await?; // or read it chunk by chunk
//!     Ok(AppResponse::new(200).header("content-type", "text/plain").body(format!("{peer} sent {} bytes", body.len())))
//! }))?;
//!
//! let peers = client.resolve_app("notes", user_id)?; // a peer id, user id or bound name
//! let req = AppRequest::new("notes", "POST", "/inbox?draft=1").header("content-type", "text/plain").body("hello");
//! let resp = futures::executor::block_on(client.app_call(peers[0].0, req, Duration::from_secs(30)))?;
//! let text = futures::executor::block_on(resp.body.collect())?;
//! # Ok(()) }
//! ```
use crate::stream::transport::{Control, OpenError};
use futures::channel::mpsc;
use futures::io::{ReadHalf, WriteHalf};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, SinkExt, StreamExt};
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

/// The protocol app calls run on.
pub const APP_PROTOCOL: &str = "/weirdnet/app/1";
/// What a node serving app `X` announces through identify: this prefix and `X`.
pub const ANNOUNCE_PREFIX: &str = "/weirdnet/app/1/";
/// The default cap on a request or response head (its CBOR bytes).
pub const DEFAULT_HEADER_MAX: usize = 16 * 1024;
/// The default time a call may go without a byte before it is given up.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest body frame a reader accepts (writers send at most [`WRITE_FRAME`]).
pub const MAX_FRAME: usize = 1 << 20;
/// The longest body frame this crate writes.
pub const WRITE_FRAME: usize = 64 * 1024;
const VERSION: u8 = 1;
/// Calls a server holds before refusing new streams.
const BACKLOG: usize = 64;
/// Body chunks buffered between the network and the app, each way.
const CHANNEL: usize = 8;

/// Why an app call or lookup failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    /// No record, binding or peer for that locator.
    #[error("not found")]
    NotFound,
    /// The peer does not serve that app.
    #[error("the peer does not serve this app")]
    NoHandler,
    /// No path to the peer, or the connection went away.
    #[error("unreachable: {0}")]
    Unreachable(String),
    /// The call took longer than its timeout, or went idle.
    #[error("timed out")]
    TimedOut,
    /// The app said no.
    #[error("refused: {0}")]
    Refused(String),
    /// A head over the header cap, or a body over the body cap.
    #[error("too large")]
    TooLarge,
    /// The peer broke the wire format.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl AppError {
    /// Its code on the wire.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::NotFound => "not_found",
            AppError::NoHandler => "no_handler",
            AppError::Unreachable(_) => "unreachable",
            AppError::TimedOut => "timed_out",
            AppError::Refused(_) => "refused",
            AppError::TooLarge => "too_large",
            AppError::Protocol(_) => "protocol",
        }
    }

    fn message(&self) -> String {
        match self {
            AppError::Unreachable(m) | AppError::Refused(m) | AppError::Protocol(m) => m.clone(),
            _ => String::new(),
        }
    }

    fn from_wire(code: &str, message: String) -> Self {
        match code {
            "not_found" => AppError::NotFound,
            "no_handler" => AppError::NoHandler,
            "unreachable" => AppError::Unreachable(message),
            "timed_out" => AppError::TimedOut,
            "refused" => AppError::Refused(message),
            "too_large" => AppError::TooLarge,
            _ => AppError::Protocol(if message.is_empty() { format!("error {code}") } else { message }),
        }
    }
}

fn io_err(e: std::io::Error) -> AppError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof => AppError::Protocol("the stream ended early".into()),
        _ => AppError::Unreachable(e.to_string()),
    }
}

/// A streamed body: chunks of bytes, or an error that ends it.
pub struct Body(Pin<Box<dyn futures::Stream<Item = Result<Vec<u8>, AppError>> + Send>>);

impl Body {
    /// No bytes.
    pub fn empty() -> Body {
        Body(Box::pin(futures::stream::empty()))
    }

    /// These bytes, in one chunk.
    pub fn bytes(b: impl Into<Vec<u8>>) -> Body {
        let b = b.into();
        if b.is_empty() { Body::empty() } else { Body(Box::pin(futures::stream::once(async move { Ok(b) }))) }
    }

    /// Chunks from a stream (an error ends the body: the peer sees the stream reset).
    pub fn stream(s: impl futures::Stream<Item = Result<Vec<u8>, AppError>> + Send + 'static) -> Body {
        Body(Box::pin(s))
    }

    /// Everything, in one buffer.
    pub async fn collect(mut self) -> Result<Vec<u8>, AppError> {
        let mut out = vec![];
        while let Some(c) = self.0.next().await {
            out.extend_from_slice(&c?);
        }
        Ok(out)
    }
}

impl futures::Stream for Body {
    type Item = Result<Vec<u8>, AppError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Body")
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::empty()
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Self {
        Body::bytes(b)
    }
}

impl From<&str> for Body {
    fn from(b: &str) -> Self {
        Body::bytes(b.as_bytes().to_vec())
    }
}

impl From<String> for Body {
    fn from(b: String) -> Self {
        Body::bytes(b.into_bytes())
    }
}

/// A call to an app on a peer.
#[derive(Debug, Default)]
pub struct AppRequest {
    /// The app (`morph`, `muninn`, …), as in `weirdnet-<app>://`.
    pub app: String,
    /// `GET`, `POST`, … (the app decides what they mean).
    pub method: String,
    /// The path and query, such as `/notes/1?full=1`.
    pub path_with_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl AppRequest {
    pub fn new(app: &str, method: &str, path_with_query: &str) -> AppRequest {
        AppRequest { app: app.into(), method: method.into(), path_with_query: path_with_query.into(), ..Default::default() }
    }

    pub fn header(mut self, name: &str, value: &str) -> AppRequest {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Body>) -> AppRequest {
        self.body = body.into();
        self
    }
}

/// An app's answer.
#[derive(Debug)]
pub struct AppResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl AppResponse {
    pub fn new(status: u16) -> AppResponse {
        AppResponse { status, headers: vec![], body: Body::empty() }
    }

    pub fn header(mut self, name: &str, value: &str) -> AppResponse {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Body>) -> AppResponse {
        self.body = body.into();
        self
    }

    /// The first header called `name` (case-insensitive).
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// What [`AppHandler::handle`] returns.
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<AppResponse, AppError>> + Send>>;

/// Serves one app's calls. A closure `Fn(PeerId, AppRequest) -> impl Future<Output =
/// Result<AppResponse, AppError>>` is one. An `Err` goes back as an error head
/// (`Refused(why)` for "no").
pub trait AppHandler: Send + Sync + 'static {
    fn handle(&self, peer: PeerId, req: AppRequest) -> HandlerFuture;
}

impl<F, Fut> AppHandler for F
where
    F: Fn(PeerId, AppRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<AppResponse, AppError>> + Send + 'static,
{
    fn handle(&self, peer: PeerId, req: AppRequest) -> HandlerFuture {
        Box::pin(self(peer, req))
    }
}

/// The caps of app calls (from [`NodeConfig`](crate::NodeConfig)).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AppLimits {
    pub(crate) header_max: usize,
    /// 0: no cap.
    pub(crate) body_max: u64,
    pub(crate) idle: Duration,
}

// ---------- wire ----------

#[derive(Debug, Serialize, Deserialize)]
struct ReqHead {
    v: u8,
    app: String,
    method: String,
    path: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RespHead {
    v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

fn cbor<T: Serialize>(v: &T) -> Result<Vec<u8>, AppError> {
    cbor4ii::serde::to_vec(Vec::new(), v).map_err(|e| AppError::Protocol(e.to_string()))
}

fn uncbor<'a, T: Deserialize<'a>>(b: &'a [u8]) -> Result<T, AppError> {
    cbor4ii::serde::from_slice(b).map_err(|e| AppError::Protocol(format!("bad head: {e}")))
}

/// Appends `n` as an unsigned varint (LEB128, as multiformats).
pub(crate) fn put_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Reads an unsigned varint; `None` at a clean end before its first byte.
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<u64>> {
    let mut n: u64 = 0;
    for i in 0..10 {
        let mut b = [0u8; 1];
        if r.read(&mut b).await? == 0 {
            return if i == 0 { Ok(None) } else { Err(std::io::ErrorKind::UnexpectedEof.into()) };
        }
        n |= u64::from(b[0] & 0x7f) << (7 * i);
        if b[0] & 0x80 == 0 {
            return Ok(Some(n));
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "varint too long"))
}

async fn idle<T>(d: Duration, f: impl Future<Output = Result<T, AppError>>) -> Result<T, AppError> {
    tokio::time::timeout(d, f).await.map_err(|_| AppError::TimedOut)?
}

/// A head: its length (at most `max`), then its bytes.
async fn read_head<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, AppError> {
    let n = read_varint(r).await.map_err(io_err)?.ok_or_else(|| AppError::Protocol("the stream closed before the head".into()))?;
    if n > max as u64 {
        return Err(AppError::TooLarge);
    }
    let mut b = vec![0u8; n as usize];
    r.read_exact(&mut b).await.map_err(io_err)?;
    Ok(b)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<(), AppError> {
    let mut b = Vec::with_capacity(data.len() + 4);
    put_varint(data.len() as u64, &mut b);
    b.extend_from_slice(data);
    w.write_all(&b).await.map_err(io_err)
}

async fn write_error<W: AsyncWrite + Unpin>(w: &mut W, e: &AppError) {
    let head = RespHead { v: VERSION, error: Some(e.code().into()), message: Some(e.message()).filter(|m| !m.is_empty()), ..Default::default() };
    if let Ok(b) = cbor(&head) {
        let _ = write_frame(w, &b).await;
        let _ = w.close().await;
    }
}

/// Sends a body as frames, then the zero-length frame.
async fn send_body<W: AsyncWrite + Unpin>(w: &mut W, mut body: Body, idle_for: Duration) -> Result<(), AppError> {
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        for piece in chunk.chunks(WRITE_FRAME) {
            idle(idle_for, write_frame(w, piece)).await?;
        }
    }
    idle(idle_for, write_frame(w, &[])).await?;
    idle(idle_for, async { w.flush().await.map_err(io_err) }).await
}

/// Aborts a task when dropped.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A body read from `r` frame by frame (on the node's runtime) into a channel. `guard` lives
/// as long as the reading does: dropping the body stops both.
fn read_body<R: AsyncRead + Unpin + Send + 'static>(rt: &tokio::runtime::Handle, mut r: R, limits: AppLimits, guard: Option<AbortOnDrop>) -> Body {
    let (mut tx, rx) = mpsc::channel::<Result<Vec<u8>, AppError>>(CHANNEL);
    rt.spawn(async move {
        let _guard = guard;
        let mut total: u64 = 0;
        loop {
            let frame = idle(limits.idle, async {
                let n =
                    read_varint(&mut r).await.map_err(io_err)?.ok_or_else(|| AppError::Protocol("the body ended without its last frame".into()))?;
                if n == 0 {
                    return Ok(None);
                }
                if n > MAX_FRAME as u64 {
                    return Err(AppError::Protocol(format!("a {n}-byte frame")));
                }
                total += n;
                if limits.body_max > 0 && total > limits.body_max {
                    return Err(AppError::TooLarge);
                }
                let mut b = vec![0u8; n as usize];
                r.read_exact(&mut b).await.map_err(io_err)?;
                Ok(Some(b))
            })
            .await;
            match frame {
                Ok(Some(b)) => {
                    if tx.send(Ok(b)).await.is_err() {
                        return; // the app dropped the body: cancel
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });
    Body(Box::pin(rx))
}

// ---------- calling ----------

async fn within<T>(deadline: tokio::time::Instant, f: impl Future<Output = Result<T, AppError>>) -> Result<T, AppError> {
    tokio::time::timeout_at(deadline, f).await.map_err(|_| AppError::TimedOut)?
}

fn split(s: libp2p::Stream) -> (ReadHalf<libp2p::Stream>, WriteHalf<libp2p::Stream>) {
    s.split()
}

/// One call on an open connection to `peer`, on the node's runtime; `deadline` covers opening
/// the stream, sending the head and getting the response head.
pub(crate) async fn call(
    rt: tokio::runtime::Handle,
    control: Control,
    peer: PeerId,
    req: AppRequest,
    limits: AppLimits,
    deadline: tokio::time::Instant,
) -> Result<AppResponse, AppError> {
    let head = cbor(&ReqHead {
        v: VERSION,
        app: req.app.clone(),
        method: req.method.clone(),
        path: req.path_with_query.clone(),
        headers: req.headers.clone(),
    })?;
    if head.len() > limits.header_max {
        return Err(AppError::TooLarge);
    }
    let (stream, _, _) = within(deadline, async {
        control.open(peer, StreamProtocol::new(APP_PROTOCOL)).await.map_err(|e| match e {
            OpenError::Unsupported(_) => AppError::NoHandler,
            OpenError::Io(e) => AppError::Unreachable(e.to_string()),
        })
    })
    .await?;
    let (mut r, mut w) = split(stream);
    within(deadline, write_frame(&mut w, &head)).await?;
    // the request body goes out while the response comes in
    let body = req.body;
    let idle_for = limits.idle;
    let sender = rt.spawn(async move {
        // no FIN after the body (its last frame ends it): dropping a stream that is still
        // open resets it, and a reset is how the server learns the caller went away
        if send_body(&mut w, body, idle_for).await.is_ok() {
            // keep the write half until the read side is done with the stream
            futures::future::pending::<()>().await;
        }
    });
    let guard = AbortOnDrop(sender.abort_handle());
    let bytes = within(deadline, read_head(&mut r, limits.header_max)).await?;
    let h: RespHead = uncbor(&bytes)?;
    if h.v != VERSION {
        return Err(AppError::Protocol(format!("version {}", h.v)));
    }
    if let Some(code) = h.error {
        return Err(AppError::from_wire(&code, h.message.unwrap_or_default()));
    }
    let status = h.status.ok_or_else(|| AppError::Protocol("a head with no status".into()))?;
    Ok(AppResponse { status, headers: h.headers, body: read_body(&rt, r, limits, Some(guard)) })
}

// ---------- serving ----------

/// The apps a node serves.
pub(crate) struct Server {
    handlers: RwLock<HashMap<String, Arc<dyn AppHandler>>>,
    /// The announcement acceptors, by app (dropping one stops the announcement).
    markers: Mutex<HashMap<String, AbortOnDrop>>,
    started: Mutex<bool>,
    pub(crate) serving: Arc<std::sync::atomic::AtomicBool>,
}

impl Server {
    pub(crate) fn new(serving: Arc<std::sync::atomic::AtomicBool>) -> Server {
        Server { handlers: RwLock::new(HashMap::new()), markers: Mutex::new(HashMap::new()), started: Mutex::new(false), serving }
    }

    pub(crate) fn check_app(app: &str) -> Result<(), AppError> {
        let ok =
            (1..=64).contains(&app.len()) && app.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !app.starts_with('-');
        if ok { Ok(()) } else { Err(AppError::Protocol(format!("bad app name {app:?} (a-z, 0-9 and -)"))) }
    }

    pub(crate) fn serve(
        self: &Arc<Self>,
        rt: &tokio::runtime::Handle,
        control: &Control,
        app: &str,
        h: Arc<dyn AppHandler>,
        limits: AppLimits,
    ) -> Result<(), AppError> {
        Self::check_app(app)?;
        {
            let mut started = self.started.lock().unwrap();
            if !*started {
                let mut inc = control
                    .accept(StreamProtocol::new(APP_PROTOCOL), BACKLOG)
                    .ok_or_else(|| AppError::Protocol(format!("{APP_PROTOCOL} is accepted elsewhere")))?;
                let me = self.clone();
                let rt2 = rt.clone();
                rt.spawn(async move {
                    while let Some((peer, stream, _, _)) = inc.next().await {
                        let me = me.clone();
                        let rt3 = rt2.clone();
                        rt2.spawn(async move { me.serve_one(rt3, peer, stream, limits).await });
                    }
                });
                *started = true;
            }
        }
        self.handlers.write().unwrap().insert(app.to_string(), h);
        let mut markers = self.markers.lock().unwrap();
        if !markers.contains_key(app) {
            let p = StreamProtocol::try_from_owned(format!("{ANNOUNCE_PREFIX}{app}")).map_err(|e| AppError::Protocol(e.to_string()))?;
            let mut rx = control.accept(p, 1).ok_or_else(|| AppError::Protocol(format!("{app} is announced elsewhere")))?;
            let t = rt.spawn(async move { while rx.next().await.is_some() {} });
            markers.insert(app.to_string(), AbortOnDrop(t.abort_handle()));
        }
        self.serving.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Stop serving `app`; true if it was served.
    pub(crate) fn unserve(&self, app: &str) -> bool {
        let had = self.handlers.write().unwrap().remove(app).is_some();
        self.markers.lock().unwrap().remove(app);
        if self.handlers.read().unwrap().is_empty() {
            self.serving.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        had
    }

    pub(crate) fn serves(&self, app: &str) -> bool {
        self.handlers.read().unwrap().contains_key(app)
    }

    pub(crate) fn apps(&self) -> Vec<String> {
        let mut v: Vec<String> = self.handlers.read().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    async fn serve_one(self: Arc<Self>, rt: tokio::runtime::Handle, peer: PeerId, stream: libp2p::Stream, limits: AppLimits) {
        let (mut r, mut w) = split(stream);
        let head = match idle(limits.idle, read_head(&mut r, limits.header_max)).await.and_then(|b| uncbor::<ReqHead>(&b)) {
            Ok(h) if h.v == VERSION => h,
            Ok(h) => return write_error(&mut w, &AppError::Protocol(format!("version {}", h.v))).await,
            Err(e) => return write_error(&mut w, &e).await,
        };
        let Some(h) = self.handlers.read().unwrap().get(&head.app).cloned() else {
            return write_error(&mut w, &AppError::NoHandler).await;
        };
        let req = AppRequest {
            app: head.app,
            method: head.method,
            path_with_query: head.path,
            headers: head.headers,
            body: read_body(&rt, r, limits, None),
        };
        match h.handle(peer, req).await {
            Err(e) => write_error(&mut w, &e).await,
            Ok(resp) => {
                let head = RespHead { v: VERSION, status: Some(resp.status), headers: resp.headers, ..Default::default() };
                let Ok(b) = cbor(&head) else { return };
                if b.len() > limits.header_max {
                    return write_error(&mut w, &AppError::TooLarge).await;
                }
                if idle(limits.idle, write_frame(&mut w, &b)).await.is_err() {
                    return;
                }
                if send_body(&mut w, resp.body, limits.idle).await.is_ok() {
                    let _ = w.close().await;
                }
                // on an error the halves drop here and the stream resets
            }
        }
    }
}

/// An app announced in identify protocols (`/weirdnet/app/1/X` → `X`).
pub(crate) fn announced(protocol: &str) -> Option<&str> {
    protocol.strip_prefix(ANNOUNCE_PREFIX).filter(|a| Server::check_app(a).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip() {
        for n in [0u64, 1, 127, 128, 300, 16_384, u32::MAX as u64, u64::MAX] {
            let mut b = vec![];
            put_varint(n, &mut b);
            let got = futures::executor::block_on(read_varint(&mut &b[..])).unwrap();
            assert_eq!(got, Some(n));
        }
        let mut b = vec![];
        put_varint(300, &mut b);
        assert_eq!(b, [0xac, 0x02]);
        assert_eq!(futures::executor::block_on(read_varint(&mut &[][..])).unwrap(), None);
        assert!(futures::executor::block_on(read_varint(&mut &[0x80][..])).is_err(), "cut short");
        assert!(futures::executor::block_on(read_varint(&mut &[0xff; 11][..])).is_err(), "too long");
    }

    #[test]
    fn heads_are_cbor_maps_with_the_spec_keys() {
        let b =
            cbor(&ReqHead { v: 1, app: "morph".into(), method: "GET".into(), path: "/a?b=1".into(), headers: vec![("accept".into(), "*/*".into())] })
                .unwrap();
        // a map of five entries whose first key is "v"
        assert_eq!(b[0], 0xa5);
        assert_eq!(&b[1..3], &[0x61, b'v']);
        let h: ReqHead = uncbor(&b).unwrap();
        assert_eq!((h.app.as_str(), h.path.as_str()), ("morph", "/a?b=1"));
        let e = RespHead { v: 1, error: Some("no_handler".into()), ..Default::default() };
        let back: RespHead = uncbor(&cbor(&e).unwrap()).unwrap();
        assert_eq!(back.error.as_deref(), Some("no_handler"));
        assert!(back.status.is_none());
        assert!(uncbor::<RespHead>(b"\xff").is_err());
    }

    #[test]
    fn error_codes_round_trip() {
        for e in [
            AppError::NotFound,
            AppError::NoHandler,
            AppError::Unreachable("x".into()),
            AppError::TimedOut,
            AppError::Refused("no".into()),
            AppError::TooLarge,
            AppError::Protocol("bad".into()),
        ] {
            assert_eq!(AppError::from_wire(e.code(), e.message()), e);
        }
        assert!(matches!(AppError::from_wire("new_code", String::new()), AppError::Protocol(_)));
    }

    #[test]
    fn app_names_and_announcements() {
        assert!(Server::check_app("morph").is_ok() && Server::check_app("my-app2").is_ok());
        for bad in ["", "Morph", "a/b", "-x", "a b"] {
            assert!(Server::check_app(bad).is_err(), "{bad:?}");
        }
        assert_eq!(announced("/weirdnet/app/1/morph"), Some("morph"));
        assert_eq!(announced("/weirdnet/app/1"), None);
        assert_eq!(announced("/weirdnet/app/1/Bad"), None);
    }

    #[test]
    fn bodies_collect_and_frames_are_capped() {
        let b = Body::stream(futures::stream::iter(vec![Ok(b"ab".to_vec()), Ok(b"cd".to_vec())]));
        assert_eq!(futures::executor::block_on(b.collect()).unwrap(), b"abcd");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let limits = AppLimits { header_max: 16, body_max: 5, idle: Duration::from_secs(5) };
        let frames = |parts: &[&[u8]]| {
            let mut v = vec![];
            for p in parts {
                put_varint(p.len() as u64, &mut v);
                v.extend_from_slice(p);
            }
            futures::io::Cursor::new(v)
        };
        let ok = read_body(rt.handle(), frames(&[b"abc", b"de", b""]), limits, None);
        assert_eq!(rt.block_on(ok.collect()).unwrap(), b"abcde");
        let big = read_body(rt.handle(), frames(&[b"abc", b"def", b""]), limits, None);
        assert_eq!(rt.block_on(big.collect()), Err(AppError::TooLarge));
        let cut = read_body(rt.handle(), frames(&[b"abc"]), limits, None);
        assert!(matches!(rt.block_on(cut.collect()), Err(AppError::Protocol(_))));
        let mut huge = vec![];
        put_varint(MAX_FRAME as u64 + 1, &mut huge);
        let huge = read_body(rt.handle(), futures::io::Cursor::new(huge), AppLimits { body_max: 0, ..limits }, None);
        assert!(matches!(rt.block_on(huge.collect()), Err(AppError::Protocol(_))));
        let mut head = vec![];
        put_varint(17, &mut head);
        assert_eq!(rt.block_on(read_head(&mut futures::io::Cursor::new(head), 16)), Err(AppError::TooLarge));
    }
}
