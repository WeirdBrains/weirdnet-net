//! `IngressGrant`: a user's signed permission for one ingress peer to forward one name to
//! the user's nodes, and the DNS binding that proves the user holds the name.
use crate::error::{NetError, Result};
use crate::profile::Profile;
use crate::user::{NodeCert, decode_public, user_id};
use libp2p::PeerId;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "weirdnet/ingress-grant/1";
/// The longest a grant lives (the owner renews it, the way certificates renew).
pub const MAX_GRANT_TTL_MS: i64 = 90 * 24 * 3600 * 1000;
const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressGrant {
    pub v: u8,
    /// The site's host name, lowercase.
    pub name: String,
    pub host_user: String,
    /// The user's public key (protobuf).
    pub user_key: Vec<u8>,
    /// The peer allowed to forward the name.
    pub ingress_peer: String,
    pub issued_at: i64,
    pub expires: i64,
    pub sig: Vec<u8>,
}

fn body(g: &IngressGrant) -> Vec<u8> {
    format!("{DOMAIN}\n{}\n{}\n{}\n{}\n{}", g.name, g.host_user, g.ingress_peer, g.issued_at, g.expires).into_bytes()
}

impl IngressGrant {
    /// Sign a grant with the user key for `name` through `ingress`, living `ttl_ms` from `now`.
    pub fn sign(user: &Keypair, name: &str, ingress: &PeerId, now: i64, ttl_ms: i64) -> Result<Self> {
        let name = super::sni::host_name(name.as_bytes()).ok_or_else(|| NetError::invalid("ingress grant", "not a host name"))?;
        if ttl_ms <= 0 || ttl_ms > MAX_GRANT_TTL_MS {
            return Err(NetError::invalid("ingress grant", "a grant lives up to 90 days"));
        }
        let mut g = IngressGrant {
            v: 1,
            name,
            host_user: user_id(&user.public()),
            user_key: user.public().encode_protobuf(),
            ingress_peer: ingress.to_string(),
            issued_at: now,
            expires: now + ttl_ms,
            sig: vec![],
        };
        g.sig = user.sign(&body(&g)).map_err(|e| NetError::Crypto(format!("ingress grant: {e}")))?;
        Ok(g)
    }

    /// Check the signature, the lifetime and that `ingress` is the peer it names.
    pub fn verify(&self, ingress: &PeerId, now: i64) -> Result<()> {
        let bad = |m: &str| NetError::invalid("ingress grant", m.to_string());
        if self.v != 1 {
            return Err(bad("unknown version"));
        }
        if super::sni::host_name(self.name.as_bytes()).as_deref() != Some(self.name.as_str()) {
            return Err(bad("not a lowercase host name"));
        }
        let key = decode_public(&self.user_key)?;
        if user_id(&key) != self.host_user {
            return Err(bad("the user id does not match the key"));
        }
        if self.ingress_peer != ingress.to_string() {
            return Err(bad("the grant is for another ingress"));
        }
        if self.issued_at > now + CLOCK_SKEW_MS || self.expires <= now || self.expires - self.issued_at > MAX_GRANT_TTL_MS {
            return Err(bad("expired, from the future, or living too long"));
        }
        if !key.verify(&body(self), &self.sig) {
            return Err(bad("bad signature"));
        }
        Ok(())
    }

    /// Whether `cert` lets `node` act for the grant's user.
    pub fn covers(&self, profile: &Profile, cert: &NodeCert, node: &PeerId) -> bool {
        let Ok(key) = decode_public(&self.user_key) else { return false };
        cert.user_id == self.host_user && cert.peer_id == node.to_string() && cert.active() && profile.verify_cert(&key, cert)
    }
}

/// What a host node sends an ingress peer on `/weirdnet/ingress-grant/1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub grants: Vec<IngressGrant>,
    /// The user's certificate for the registering node.
    pub cert: NodeCert,
    /// Where the ingress reaches the node (direct addresses and relay circuits).
    pub addrs: Vec<String>,
}

/// The ingress peer's answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub accepted: Vec<String>,
    /// Names refused, with why.
    pub refused: Vec<(String, String)>,
}

/// Who holds a name: a DNS TXT `_weirdnet.<name>` binding (`v=1 user=<id>`, see
/// [`crate::names::binding_txt`]) checked before a grant is taken.
pub trait Binding: Send + Sync + 'static {
    /// Whether `user` holds `name`.
    fn check(&self, name: &str, user: &str) -> futures::future::BoxFuture<'static, bool>;
}

/// Checks bindings in DNS (the system resolver).
pub struct DnsBinding(hickory_resolver::TokioResolver);

impl DnsBinding {
    pub fn system() -> Result<Self> {
        let r = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| NetError::Network(format!("resolver: {e}")))?
            .build()
            .map_err(|e| NetError::Network(format!("resolver: {e}")))?;
        Ok(DnsBinding(r))
    }
}

impl Binding for DnsBinding {
    fn check(&self, name: &str, user: &str) -> futures::future::BoxFuture<'static, bool> {
        let r = self.0.clone();
        let (q, user) = (crate::names::binding_name(name), user.to_string());
        Box::pin(async move {
            let Ok(txt) = r.txt_lookup(q).await else { return false };
            txt.answers().iter().any(|rec| match &rec.data {
                hickory_resolver::proto::rr::RData::TXT(t) => {
                    let s: Vec<u8> = t.txt_data.iter().flat_map(|c| c.iter().copied()).collect();
                    std::str::from_utf8(&s).ok().and_then(|s| crate::names::parse_binding(s).ok()).is_some_and(|u| u == user)
                }
                _ => false,
            })
        })
    }
}

/// A fixed table of bindings (tests, or names the operator vouches for).
#[derive(Default, Clone)]
pub struct StaticBinding(pub std::collections::HashMap<String, String>);

impl Binding for StaticBinding {
    fn check(&self, name: &str, user: &str) -> futures::future::BoxFuture<'static, bool> {
        let ok = self.0.get(name).is_some_and(|u| u == user);
        Box::pin(async move { ok })
    }
}
