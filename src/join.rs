//! Request to join (W3+): a user asks an owner's host for membership of a gated resource.
//!
//! The requester signs a [`JoinRequest`] (resource, its card, an optional message, a time)
//! with its user key and sends it on `/weirdnet/join/1` ([`request_join`]). The host
//! ([`serve_joins`]) checks the signature and that the card certifies the sending node,
//! applies per-requester and per-peer rate limits and a per-resource cap on pending
//! requests, and puts it in the application's [`JoinQueue`]. The owner approves ([`approve`]:
//! a [`Membership`]) or denies ([`deny`]: a signed [`Denial`]) and stores the answer in the
//! queue; sending the same request again returns it.
use crate::error::{NetError, Result};
use crate::member::{CLOCK_SKEW_MS, Membership, issuer, read_frame_async, sign_with, signed_bytes, write_frame_async};
use crate::node::{Message, Node};
use crate::profile::Profile;
use crate::stream::{Limits, Stream};
use crate::user::{Card, user_id};
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const JOIN_PROTOCOL: &str = "/weirdnet/join/1";
const REQUEST_DOMAIN: &str = "weirdnet/member/join-request/1";
const DENIAL_DOMAIN: &str = "weirdnet/member/join-denial/1";
/// How long a request may be re-sent to ask for its answer.
pub const MAX_REQUEST_AGE_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub v: u8,
    pub resource: String,
    /// The requester's card (its user id, key and node certificates).
    pub card: Card,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub at: i64,
    pub sig: Vec<u8>,
}

impl JoinRequest {
    pub fn new(user: &Keypair, card: Card, resource: &str, message: Option<String>, now: i64) -> Result<JoinRequest> {
        if card.key != user.public().encode_protobuf() {
            return Err(NetError::invalid("join request", "the card is not this user's"));
        }
        let mut r = JoinRequest { v: 1, resource: resource.into(), card, message, at: now, sig: vec![] };
        r.check_fields()?;
        r.sig = sign_with(user, REQUEST_DOMAIN, &r)?;
        Ok(r)
    }

    fn check_fields(&self) -> Result<()> {
        if self.v != 1 {
            return Err(NetError::invalid("join request", "unknown version"));
        }
        if self.resource.is_empty() || self.resource.len() > 256 {
            return Err(NetError::invalid("join request", "resource: 1 to 256 bytes"));
        }
        if self.message.as_ref().is_some_and(|m| m.len() > 2000) {
            return Err(NetError::invalid("join request", "message: at most 2000 bytes"));
        }
        Ok(())
    }

    /// The requester's user id.
    pub fn user_id(&self) -> &str {
        &self.card.id
    }

    /// The signature and dates, and that the card certifies `from` (the sending node).
    pub fn verify(&self, profile: &Profile, from: &PeerId, now: i64) -> Result<()> {
        self.check_fields()?;
        let key = profile.check_card(&from.to_string(), &self.card)?;
        let mut body = self.clone();
        body.sig = vec![];
        if !key.verify(&signed_bytes(REQUEST_DOMAIN, &body), &self.sig) {
            return Err(NetError::Crypto("join request: bad signature".into()));
        }
        if self.at > now + CLOCK_SKEW_MS || self.at < now - MAX_REQUEST_AGE_MS {
            return Err(NetError::invalid("join request", "too old or in the future"));
        }
        Ok(())
    }

    /// Names this request in a denial.
    pub fn digest(&self) -> String {
        hex::encode(&blake3::hash(&self.sig).as_bytes()[..16])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub v: u8,
    pub resource: String,
    pub user_id: String,
    /// The denied request's [`digest`](JoinRequest::digest).
    pub request: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub at: i64,
    pub issuer_id: String,
    pub issuer_key: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinAnswer {
    Approved(Membership),
    Denied(Denial),
}

impl JoinAnswer {
    /// Requester side: an answer from `owner` to `req`, signed and current.
    pub fn verify(&self, owner: &str, req: &JoinRequest, now: i64) -> Result<()> {
        match self {
            JoinAnswer::Approved(m) => {
                m.verify_for(owner, &req.resource, now)?;
                if m.user_id != req.card.id {
                    return Err(NetError::invalid("join answer", "for someone else"));
                }
                Ok(())
            }
            JoinAnswer::Denied(d) => {
                if d.issuer_id != owner || d.resource != req.resource || d.user_id != req.card.id || d.request != req.digest() {
                    return Err(NetError::invalid("join answer", "not an answer to this request"));
                }
                let k = issuer(&d.issuer_key, &d.issuer_id)?;
                let mut body = d.clone();
                body.sig = vec![];
                if !k.verify(&signed_bytes(DENIAL_DOMAIN, &body), &d.sig) {
                    return Err(NetError::Crypto("join denial: bad signature".into()));
                }
                Ok(())
            }
        }
    }
}

/// The owner approves: a membership with `role`.
pub fn approve(owner: &Keypair, req: &JoinRequest, role: &str, expires_at: Option<i64>, now: i64) -> Result<JoinAnswer> {
    Ok(JoinAnswer::Approved(Membership::issue(owner, &req.resource, &req.card.id, role, now, expires_at)?))
}

/// The owner denies, optionally saying why.
pub fn deny(owner: &Keypair, req: &JoinRequest, reason: Option<String>, now: i64) -> Result<JoinAnswer> {
    let mut d = Denial {
        v: 1,
        resource: req.resource.clone(),
        user_id: req.card.id.clone(),
        request: req.digest(),
        reason,
        at: now,
        issuer_id: user_id(&owner.public()),
        issuer_key: owner.public().encode_protobuf(),
        sig: vec![],
    };
    d.sig = sign_with(owner, DENIAL_DOMAIN, &d)?;
    Ok(JoinAnswer::Denied(d))
}

/// What the host says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinReply {
    /// Waiting for the owner; send the same request later for the answer.
    Queued,
    Answered(JoinAnswer),
    /// Too many requests; try again after this long.
    Limited {
        retry_after_ms: u64,
    },
    /// Not accepted (an unknown resource, a bad request, a full queue).
    Refused(String),
}

/// Where the host keeps requests and answers; the application owns it (and can show the
/// pending requests to the owner).
pub trait JoinQueue: Send + Sync + 'static {
    /// Keep a request (replacing an earlier one from the same user for the same resource).
    fn push(&self, req: JoinRequest) -> Result<()>;
    fn pending(&self, resource: &str) -> Vec<JoinRequest>;
    /// The owner's answer to a user's request, once there is one.
    fn answer(&self, resource: &str, user: &str) -> Option<JoinAnswer>;
    /// Store the owner's answer (the request leaves the pending list).
    fn set_answer(&self, resource: &str, user: &str, answer: JoinAnswer) -> Result<()>;
}

/// A [`JoinQueue`] in memory.
#[derive(Default)]
pub struct MemoryJoinQueue {
    pending: Mutex<Vec<JoinRequest>>,
    answers: Mutex<HashMap<(String, String), JoinAnswer>>,
}

impl JoinQueue for MemoryJoinQueue {
    fn push(&self, req: JoinRequest) -> Result<()> {
        let mut p = self.pending.lock().map_err(|_| NetError::Network("queue poisoned".into()))?;
        p.retain(|r| !(r.resource == req.resource && r.card.id == req.card.id));
        p.push(req);
        Ok(())
    }
    fn pending(&self, resource: &str) -> Vec<JoinRequest> {
        self.pending.lock().map(|p| p.iter().filter(|r| r.resource == resource).cloned().collect()).unwrap_or_default()
    }
    fn answer(&self, resource: &str, user: &str) -> Option<JoinAnswer> {
        self.answers.lock().ok()?.get(&(resource.to_string(), user.to_string())).cloned()
    }
    fn set_answer(&self, resource: &str, user: &str, answer: JoinAnswer) -> Result<()> {
        if let Ok(mut p) = self.pending.lock() {
            p.retain(|r| !(r.resource == resource && r.card.id == user));
        }
        self.answers.lock().map_err(|_| NetError::Network("queue poisoned".into()))?.insert((resource.into(), user.into()), answer);
        Ok(())
    }
}

/// Rate limits for incoming requests.
#[derive(Debug, Clone)]
pub struct JoinLimits {
    /// Messages (new requests and re-sends) per requester user id per window.
    pub per_user: usize,
    /// Messages per sending node per window.
    pub per_peer: usize,
    pub window: Duration,
    /// Pending requests kept per resource.
    pub max_pending: usize,
}

impl Default for JoinLimits {
    fn default() -> Self {
        JoinLimits { per_user: 10, per_peer: 20, window: Duration::from_secs(3600), max_pending: 1000 }
    }
}

#[derive(Default)]
struct Limiter(Mutex<HashMap<String, VecDeque<i64>>>);

impl Limiter {
    /// Count a hit for `key`; `Err(wait)` when over `max` in `window`.
    fn hit(&self, key: &str, max: usize, window: i64, now: i64) -> std::result::Result<(), u64> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 100_000 {
            m.retain(|_, v| v.back().is_some_and(|t| *t > now - window));
        }
        let v = m.entry(key.to_string()).or_default();
        while v.front().is_some_and(|t| *t <= now - window) {
            v.pop_front();
        }
        if v.len() >= max {
            return Err((v.front().copied().unwrap_or(now) + window - now).max(1) as u64);
        }
        v.push_back(now);
        Ok(())
    }
}

/// The host's side of joining.
pub struct JoinHost {
    pub profile: &'static Profile,
    pub queue: Arc<dyn JoinQueue>,
    pub limits: JoinLimits,
    /// Which resources take requests (gated ones the host serves).
    pub accepts: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

/// Answering `/weirdnet/join/1`; dropping it stops.
pub struct JoinServer(tokio::task::JoinHandle<()>);

impl Drop for JoinServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl JoinHost {
    /// What to answer `req` from `peer` (the server does this for each stream).
    fn handle(&self, lim: &Limiter, peer: &PeerId, req: JoinRequest, now: i64) -> JoinReply {
        let w = self.limits.window.as_millis() as i64;
        if let Err(ms) = lim.hit(&format!("p:{peer}"), self.limits.per_peer, w, now) {
            return JoinReply::Limited { retry_after_ms: ms };
        }
        if let Err(e) = req.verify(self.profile, peer, now) {
            return JoinReply::Refused(e.to_string());
        }
        if let Err(ms) = lim.hit(&format!("u:{}", req.card.id), self.limits.per_user, w, now) {
            return JoinReply::Limited { retry_after_ms: ms };
        }
        if !(self.accepts)(&req.resource) {
            return JoinReply::Refused("no such resource here".into());
        }
        if let Some(a) = self.queue.answer(&req.resource, &req.card.id) {
            // a denial answers only the request it denied; a newer request is queued again
            let stale = matches!(&a, JoinAnswer::Denied(d) if d.request != req.digest());
            if !stale {
                return JoinReply::Answered(a);
            }
        }
        let pending = self.queue.pending(&req.resource);
        let known = pending.iter().any(|r| r.card.id == req.card.id);
        if !known && pending.len() >= self.limits.max_pending {
            return JoinReply::Refused("too many pending requests".into());
        }
        match self.queue.push(req) {
            Ok(()) => JoinReply::Queued,
            Err(e) => JoinReply::Refused(e.to_string()),
        }
    }
}

/// Take join requests on `node` into `host.queue`.
pub fn serve_joins<Q: Message, R: Message>(node: &Node<Q, R>, host: JoinHost) -> Result<JoinServer> {
    let mut inc = node.accept_streams(JOIN_PROTOCOL, Limits::default())?;
    let host = Arc::new(host);
    let lim = Arc::new(Limiter::default());
    Ok(JoinServer(node.runtime().spawn(async move {
        while let Some(s) = inc.next().await {
            let (host, lim) = (host.clone(), lim.clone());
            tokio::spawn(async move {
                let _ = answer_one(s, &host, &lim).await;
            });
        }
    })))
}

async fn answer_one(mut s: Stream, host: &JoinHost, lim: &Limiter) -> Result<()> {
    let peer = s.peer();
    let req: JoinRequest =
        tokio::time::timeout(Duration::from_secs(20), read_frame_async(&mut s)).await.map_err(|_| NetError::Network("join: timed out".into()))??;
    let reply = tokio::task::block_in_place(|| host.handle(lim, &peer, req, crate::now_ms()));
    write_frame_async(&mut s, &reply).await?;
    futures::AsyncWriteExt::close(&mut s).await.map_err(NetError::net)
}

/// Send a request (or send it again for the answer) to the owner's host.
pub fn request_join<Q: Message, R: Message>(node: &Node<Q, R>, host: PeerId, addrs: &[Multiaddr], req: &JoinRequest) -> Result<JoinReply> {
    let mut s = node.open_stream(host, addrs, JOIN_PROTOCOL, Limits::default())?;
    crate::member::write_frame(&mut s, req)?;
    let r = crate::member::read_frame(&mut s);
    s.close_write();
    r
}

pub async fn request_join_async<Q: Message, R: Message>(
    node: &Node<Q, R>,
    host: PeerId,
    addrs: &[Multiaddr],
    req: &JoinRequest,
) -> Result<JoinReply> {
    let mut s = node.open_stream_async(host, addrs, JOIN_PROTOCOL, Limits::default()).await?;
    write_frame_async(&mut s, req).await?;
    let r = read_frame_async(&mut s).await;
    let _ = futures::AsyncWriteExt::close(&mut s).await;
    r
}
