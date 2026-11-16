//! Names: where a peer is now, as signed records.
//!
//! A [`PeerRecord`] says "this node of this user is at these addresses" (direct ones and
//! relay circuits), signed by the node key and chained to the user key by the node's
//! certificate. Records carry a `seq` (a higher one wins) and expire within
//! [`MAX_RECORD_TTL_MS`]; a device republishes on network change. A [`Withdrawal`] removes a
//! record: it is signed by a node certified by the same user, has a higher `seq`, and is
//! kept until it expires, so stale copies can't come back.
//!
//! Records live, in lookup order, with trusted peers (the application pushes them), on the
//! home relay's names server (the `names` protocol, [`NamesRequest`]), and in the Kademlia
//! DHT under [`Profile::peer_key`] — the DHT only while the device hosts something. Every
//! storing node runs the same rule, [`Profile::accept`]. A `_weirdnet.<name>` DNS TXT
//! record ([`binding_txt`]) ties a domain to a user id.
//!
//! No DHT can force a deletion: a hostile node can keep serving an old record. Lookups
//! drop anything expired, unsigned, revoked or below the highest `seq` seen, so a stale
//! record leads to a failed dial, never a wrong peer (the dial is Noise-authenticated).
use crate::addr::addr_peer;
use crate::error::{NetError, Result};
use crate::profile::Profile;
use crate::user::{NodeCert, decode_public, user_id};
use libp2p::identity::{Keypair, PublicKey};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The longest a peer record may live.
pub const MAX_RECORD_TTL_MS: i64 = 24 * 3600 * 1000;
/// A withdrawal lives at least as long as the longest record, and at most a week.
pub const MIN_WITHDRAWAL_TTL_MS: i64 = MAX_RECORD_TTL_MS;
pub const MAX_WITHDRAWAL_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// Clocks may run this far ahead.
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
/// At most this many addresses in a record, and this many bytes in an encoded entry.
pub const MAX_ADDRS: usize = 32;
pub const MAX_ENTRY_BYTES: usize = 16 * 1024;
const VERSION: u8 = 1;

/// Where a user's node is, signed by the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub v: u8,
    pub user_id: String,
    /// The user's public key (protobuf).
    pub user_key: Vec<u8>,
    /// The user's certificate for the node.
    pub cert: NodeCert,
    /// The node's public key (protobuf); its peer id is `cert.peer_id`.
    pub node_key: Vec<u8>,
    /// Direct addresses and relay circuits, each ending in `/p2p/<node>`.
    pub addrs: Vec<String>,
    /// The relay the node keeps a reservation on (`…/p2p/<relay>`), if any.
    pub home_relay: Option<String>,
    pub seq: u64,
    pub issued_at: i64,
    pub expires: i64,
    pub sig: Vec<u8>,
}

/// The removal of a user's record, signed by one of the user's nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub v: u8,
    pub user_id: String,
    pub user_key: Vec<u8>,
    pub cert: NodeCert,
    pub node_key: Vec<u8>,
    pub seq: u64,
    pub issued_at: i64,
    pub expires: i64,
    pub sig: Vec<u8>,
}

/// What is stored under a user's key: a record or its withdrawal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Entry {
    Record(PeerRecord),
    Withdrawn(Withdrawal),
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Found(PeerRecord),
    Withdrawn(Withdrawal),
    NotFound,
}

impl Entry {
    pub fn seq(&self) -> u64 {
        match self {
            Entry::Record(r) => r.seq,
            Entry::Withdrawn(w) => w.seq,
        }
    }
    pub fn user_id(&self) -> &str {
        match self {
            Entry::Record(r) => &r.user_id,
            Entry::Withdrawn(w) => &w.user_id,
        }
    }
    pub fn expires(&self) -> i64 {
        match self {
            Entry::Record(r) => r.expires,
            Entry::Withdrawn(w) => w.expires,
        }
    }
    /// The node that signed it.
    pub fn signer(&self) -> &str {
        match self {
            Entry::Record(r) => &r.cert.peer_id,
            Entry::Withdrawn(w) => &w.cert.peer_id,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Result<Entry> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(NetError::invalid("peer record", "too large"));
        }
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn lookup(self) -> Lookup {
        match self {
            Entry::Record(r) => Lookup::Found(r),
            Entry::Withdrawn(w) => Lookup::Withdrawn(w),
        }
    }
}

fn sign(node: &Keypair, bytes: &[u8]) -> Result<Vec<u8>> {
    node.sign(bytes).map_err(|e| NetError::Crypto(format!("sign: {e}")))
}

fn record_body(domain: &str, r: &PeerRecord) -> Vec<u8> {
    let mut r = r.clone();
    r.sig.clear();
    let mut b = format!("{domain}\n").into_bytes();
    b.extend(serde_json::to_vec(&r).unwrap_or_default());
    b
}

fn withdrawal_body(domain: &str, w: &Withdrawal) -> Vec<u8> {
    let mut w = w.clone();
    w.sig.clear();
    let mut b = format!("{domain}\n").into_bytes();
    b.extend(serde_json::to_vec(&w).unwrap_or_default());
    b
}

fn bad(msg: impl Into<String>) -> NetError {
    NetError::Crypto(format!("peer record: {}", msg.into()))
}

impl Profile {
    /// The Kademlia key of a user's record: `SHA-256(peer_key + user id)`.
    pub fn record_key(&self, user: &str) -> Vec<u8> {
        sha2::Sha256::digest(format!("{}{user}", self.peer_key).as_bytes()).to_vec()
    }

    /// Sign a record for `node`, certified by `cert` under `user_key`, valid `ttl_ms` from
    /// `now`. `seq` must grow with every record and withdrawal of this user (the time in
    /// milliseconds works across the user's devices).
    #[allow(clippy::too_many_arguments)]
    pub fn peer_record(
        &self,
        node: &Keypair,
        user_key: &PublicKey,
        cert: &NodeCert,
        addrs: &[Multiaddr],
        home_relay: Option<&Multiaddr>,
        seq: u64,
        now: i64,
        ttl_ms: i64,
    ) -> Result<PeerRecord> {
        let peer = node.public().to_peer_id();
        if cert.peer_id != peer.to_string() {
            return Err(NetError::invalid("peer record", "the certificate is for another node"));
        }
        if ttl_ms <= 0 || ttl_ms > MAX_RECORD_TTL_MS {
            return Err(NetError::invalid("peer record", "a record lives up to 24 hours"));
        }
        let addrs: Vec<String> = addrs
            .iter()
            .take(MAX_ADDRS)
            .map(|a| if addr_peer(a) == Some(peer) { a.to_string() } else { a.clone().with(Protocol::P2p(peer)).to_string() })
            .collect();
        let mut r = PeerRecord {
            v: VERSION,
            user_id: user_id(user_key),
            user_key: user_key.encode_protobuf(),
            cert: cert.clone(),
            node_key: node.public().encode_protobuf(),
            addrs,
            home_relay: home_relay.map(|a| a.to_string()),
            seq,
            issued_at: now,
            expires: now + ttl_ms,
            sig: vec![],
        };
        r.sig = sign(node, &record_body(self.peer_record, &r))?;
        self.verify_record(&r, now)?;
        Ok(r)
    }

    /// Sign the withdrawal of a user's record by one of the user's nodes; `seq` must be
    /// higher than the record's, and it lives `ttl_ms` (one day to a week).
    pub fn withdrawal(&self, node: &Keypair, user_key: &PublicKey, cert: &NodeCert, seq: u64, now: i64, ttl_ms: i64) -> Result<Withdrawal> {
        if cert.peer_id != node.public().to_peer_id().to_string() {
            return Err(NetError::invalid("withdrawal", "the certificate is for another node"));
        }
        if !(MIN_WITHDRAWAL_TTL_MS..=MAX_WITHDRAWAL_TTL_MS).contains(&ttl_ms) {
            return Err(NetError::invalid("withdrawal", "a withdrawal lives one day to a week"));
        }
        let mut w = Withdrawal {
            v: VERSION,
            user_id: user_id(user_key),
            user_key: user_key.encode_protobuf(),
            cert: cert.clone(),
            node_key: node.public().encode_protobuf(),
            seq,
            issued_at: now,
            expires: now + ttl_ms,
            sig: vec![],
        };
        w.sig = sign(node, &withdrawal_body(self.withdrawal, &w))?;
        self.verify_withdrawal(&w, now)?;
        Ok(w)
    }

    /// The user and node behind a record or withdrawal: the keys match the ids, and the
    /// user certified the node and has not revoked it.
    fn check_signer(&self, user: &str, user_key: &[u8], cert: &NodeCert, node_key: &[u8]) -> Result<(PublicKey, PeerId)> {
        let ukey = decode_public(user_key)?;
        if user_id(&ukey) != user || cert.user_id != user {
            return Err(bad("the user id does not match the key"));
        }
        let nkey = decode_public(node_key)?;
        let peer = nkey.to_peer_id();
        if cert.peer_id != peer.to_string() {
            return Err(bad("the certificate is for another node"));
        }
        if !cert.active() || !self.verify_cert(&ukey, cert) {
            return Err(bad("the node certificate does not verify or is revoked"));
        }
        Ok((nkey, peer))
    }

    /// Check a record: version, signer, signature, lifetime and addresses.
    pub fn verify_record(&self, r: &PeerRecord, now: i64) -> Result<PeerId> {
        if r.v != VERSION {
            return Err(bad(format!("version {} is not {VERSION}", r.v)));
        }
        let (nkey, peer) = self.check_signer(&r.user_id, &r.user_key, &r.cert, &r.node_key)?;
        if !nkey.verify(&record_body(self.peer_record, r), &r.sig) {
            return Err(bad("bad signature"));
        }
        if r.issued_at > now + CLOCK_SKEW_MS || r.expires <= now || r.expires - r.issued_at > MAX_RECORD_TTL_MS {
            return Err(bad("expired, from the future, or living too long"));
        }
        if r.addrs.len() > MAX_ADDRS {
            return Err(bad("too many addresses"));
        }
        for a in &r.addrs {
            let m: Multiaddr = a.parse().map_err(|_| bad(format!("`{a}` is not an address")))?;
            if addr_peer(&m) != Some(peer) {
                return Err(bad(format!("`{a}` is not the node's")));
            }
        }
        if let Some(h) = &r.home_relay {
            let m: Multiaddr = h.parse().map_err(|_| bad("bad home relay"))?;
            if addr_peer(&m).is_none() {
                return Err(bad("the home relay has no /p2p/"));
            }
        }
        Ok(peer)
    }

    /// Check a withdrawal: version, signer, signature and lifetime.
    pub fn verify_withdrawal(&self, w: &Withdrawal, now: i64) -> Result<PeerId> {
        if w.v != VERSION {
            return Err(bad(format!("version {} is not {VERSION}", w.v)));
        }
        let (nkey, peer) = self.check_signer(&w.user_id, &w.user_key, &w.cert, &w.node_key)?;
        if !nkey.verify(&withdrawal_body(self.withdrawal, w), &w.sig) {
            return Err(bad("bad signature"));
        }
        if w.issued_at > now + CLOCK_SKEW_MS || w.expires <= now || w.expires - w.issued_at > MAX_WITHDRAWAL_TTL_MS {
            return Err(bad("expired, from the future, or living too long"));
        }
        Ok(peer)
    }

    pub fn verify_entry(&self, e: &Entry, now: i64) -> Result<PeerId> {
        match e {
            Entry::Record(r) => self.verify_record(r, now),
            Entry::Withdrawn(w) => self.verify_withdrawal(w, now),
        }
    }

    /// The rule every storing node runs: keep `incoming` instead of `existing`? It must
    /// verify, and its `seq` must be higher than an unexpired existing entry's (so a
    /// withdrawal holds until it expires). Errors say why it was refused.
    pub fn accept(&self, existing: Option<&Entry>, incoming: &Entry, now: i64) -> Result<()> {
        self.verify_entry(incoming, now)?;
        if let Some(old) = existing.filter(|o| o.expires() > now) {
            if old.user_id() != incoming.user_id() {
                return Err(bad("another user's key"));
            }
            if incoming.seq() <= old.seq() {
                return Err(bad(format!("seq {} is not above {}", incoming.seq(), old.seq())));
            }
        }
        Ok(())
    }

    /// The freshest valid entry among `entries` for `user`, as a lookup result.
    pub fn newest<'a>(&self, user: &str, entries: impl IntoIterator<Item = &'a Entry>, now: i64) -> Lookup {
        entries
            .into_iter()
            .filter(|e| e.user_id() == user && self.verify_entry(e, now).is_ok())
            .max_by_key(|e| e.seq())
            .cloned()
            .map(Entry::lookup)
            .unwrap_or(Lookup::NotFound)
    }
}

/// The DNS name of a domain's binding: `_weirdnet.<name>`.
pub fn binding_name(name: &str) -> String {
    format!("_weirdnet.{}", name.trim().trim_end_matches('.'))
}

/// The TXT value binding a domain to a user: `v=1 user=<user id>`.
pub fn binding_txt(user: &str) -> String {
    format!("v=1 user={user}")
}

/// The user id in a binding TXT value.
pub fn parse_binding(txt: &str) -> Result<String> {
    let txt = txt.trim().trim_matches('"');
    let mut v = None;
    let mut user = None;
    for part in txt.split_whitespace() {
        match part.split_once('=') {
            Some(("v", x)) => v = Some(x),
            Some(("user", x)) => user = Some(x),
            _ => {}
        }
    }
    if v != Some("1") {
        return Err(NetError::invalid("name binding", "not `v=1`"));
    }
    match user {
        Some(u) if u.len() == 32 && u.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) => Ok(u.to_string()),
        _ => Err(NetError::invalid("name binding", "no user id")),
    }
}

/// The names protocol: register an entry on a names server, or look a user up there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamesRequest {
    /// Store a record (sent by the node it is about) or a withdrawal (by any of the user's nodes).
    Register(Box<Entry>),
    Discover {
        user_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamesResponse {
    Registered,
    Found(Option<Box<Entry>>),
    Refused(String),
}

/// Where a names server keeps entries. Entries arrive checked; the store only keeps them.
pub trait NameStore: Send + Sync + 'static {
    fn get(&self, user: &str) -> Option<Entry>;
    fn put(&self, entry: &Entry);
    /// Drop entries that expired before `now`.
    fn prune(&self, now: i64);
}

/// Entries in memory.
#[derive(Default)]
pub struct MemoryNames(Mutex<HashMap<String, Entry>>);

impl NameStore for MemoryNames {
    fn get(&self, user: &str) -> Option<Entry> {
        self.0.lock().ok()?.get(user).cloned()
    }
    fn put(&self, entry: &Entry) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(entry.user_id().to_string(), entry.clone());
        }
    }
    fn prune(&self, now: i64) {
        if let Ok(mut m) = self.0.lock() {
            m.retain(|_, e| e.expires() > now);
        }
    }
}

/// A names store handed to a node through [`crate::NodeConfig::names_server`].
#[derive(Clone)]
pub struct Names(pub Arc<dyn NameStore>);

impl Names {
    pub fn memory() -> Self {
        Names(Arc::new(MemoryNames::default()))
    }
}

impl std::fmt::Debug for Names {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Names(..)")
    }
}

/// How a names server answers: `from` is the Noise-authenticated sender.
pub fn serve(p: &Profile, store: &dyn NameStore, from: &PeerId, req: NamesRequest, now: i64) -> NamesResponse {
    match req {
        NamesRequest::Discover { user_id } => NamesResponse::Found(store.get(&user_id).filter(|e| e.expires() > now).map(Box::new)),
        NamesRequest::Register(e) => {
            let e = *e;
            if let Entry::Record(r) = &e
                && r.cert.peer_id != from.to_string()
            {
                return NamesResponse::Refused("a node registers only its own record".into());
            }
            if let Entry::Withdrawn(w) = &e
                && w.cert.peer_id != from.to_string()
            {
                return NamesResponse::Refused("a withdrawal comes from the node that signed it".into());
            }
            match p.accept(store.get(e.user_id()).as_ref(), &e, now) {
                Ok(()) => {
                    store.put(&e);
                    NamesResponse::Registered
                }
                Err(err) => NamesResponse::Refused(err.to_string()),
            }
        }
    }
}
