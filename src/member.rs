//! Lasting membership (W3): a resource owner's signed [`Membership`] for a user, with a role
//! the application interprets, signed [`MemberRevocation`]s, and presenting a membership on
//! a stream so the host can check it against the Noise-authenticated peer.
//!
//! A membership names the resource, the member's user id, a role id, when it was issued and
//! optionally when it expires, and is signed by the owner's user key (the issuer). A
//! revocation, also signed by the owner, voids every membership of that user for that
//! resource issued at or before its `before` time, so re-admitting someone is issuing a newer
//! one. Revocations travel in the W2 [`Manifest`](crate::content::Manifest)
//! (`member_revocations`) or however the application likes; [`Revocations`] holds the checked
//! set. What a role may do is the application's (or `weirdnet-access`'s) business.
use crate::error::{NetError, Result};
use crate::profile::Profile;
use crate::user::{Card, decode_public, user_id};
use libp2p::PeerId;
use libp2p::identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MEMBERSHIP_DOMAIN: &str = "weirdnet/member/membership/1";
const REVOCATION_DOMAIN: &str = "weirdnet/member/revocation/1";
/// How far ahead of our clock a signed time may be.
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
/// The largest framed message read from a peer.
pub const MAX_FRAME: usize = 256 * 1024;

/// Sign `body` (with an empty `sig`) under `domain`.
pub(crate) fn signed_bytes<T: Serialize>(domain: &str, body: &T) -> Vec<u8> {
    let mut v = domain.as_bytes().to_vec();
    v.push(b'\n');
    v.extend(serde_json::to_vec(body).unwrap_or_default());
    v
}

pub(crate) fn sign_with(kp: &Keypair, domain: &str, body: &impl Serialize) -> Result<Vec<u8>> {
    kp.sign(&signed_bytes(domain, body)).map_err(|e| NetError::Crypto(format!("{domain}: {e}")))
}

/// The issuer's key, checked against its id.
pub(crate) fn issuer(key: &[u8], id: &str) -> Result<PublicKey> {
    let k = decode_public(key)?;
    if user_id(&k) != id {
        return Err(NetError::Crypto("the issuer id does not match its key".into()));
    }
    Ok(k)
}

fn check_text(what: &'static str, s: &str, max: usize) -> Result<()> {
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(NetError::invalid(what, format!("1 to {max} bytes, no control characters")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub v: u8,
    /// What the membership is of (a site, project or forum id the owner chose).
    pub resource: String,
    /// The member.
    pub user_id: String,
    /// The role id, interpreted by the application.
    pub role: String,
    pub issued_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The owner (issuer) user id and key.
    pub issuer_id: String,
    pub issuer_key: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Membership {
    /// The owner issues a membership.
    pub fn issue(owner: &Keypair, resource: &str, member: &str, role: &str, now: i64, expires_at: Option<i64>) -> Result<Membership> {
        check_text("resource", resource, 256)?;
        check_text("role", role, 64)?;
        check_text("user id", member, 64)?;
        let mut m = Membership {
            v: 1,
            resource: resource.into(),
            user_id: member.into(),
            role: role.into(),
            issued_at: now,
            expires_at,
            issuer_id: user_id(&owner.public()),
            issuer_key: owner.public().encode_protobuf(),
            sig: vec![],
        };
        m.sig = sign_with(owner, MEMBERSHIP_DOMAIN, &m)?;
        Ok(m)
    }

    /// The signature, the issuer's key and the dates.
    pub fn verify(&self, now: i64) -> Result<()> {
        if self.v != 1 {
            return Err(NetError::invalid("membership", "unknown version"));
        }
        let k = issuer(&self.issuer_key, &self.issuer_id)?;
        let mut body = self.clone();
        body.sig = vec![];
        if !k.verify(&signed_bytes(MEMBERSHIP_DOMAIN, &body), &self.sig) {
            return Err(NetError::Crypto("membership: bad signature".into()));
        }
        if self.issued_at > now + CLOCK_SKEW_MS {
            return Err(NetError::invalid("membership", "issued in the future"));
        }
        if self.expires_at.is_some_and(|e| e <= now) {
            return Err(NetError::invalid("membership", "expired"));
        }
        Ok(())
    }

    /// [`verify`](Self::verify), and that it is `owner`'s membership of `resource`.
    pub fn verify_for(&self, owner: &str, resource: &str, now: i64) -> Result<()> {
        if self.issuer_id != owner || self.resource != resource {
            return Err(NetError::invalid("membership", "not for this resource"));
        }
        self.verify(now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRevocation {
    pub v: u8,
    pub resource: String,
    pub user_id: String,
    /// Memberships issued at or before this time are void.
    pub before: i64,
    pub at: i64,
    pub issuer_id: String,
    pub issuer_key: Vec<u8>,
    pub sig: Vec<u8>,
}

impl MemberRevocation {
    /// The owner revokes `member`'s memberships of `resource` issued up to `before`.
    pub fn revoke(owner: &Keypair, resource: &str, member: &str, before: i64, now: i64) -> Result<MemberRevocation> {
        check_text("resource", resource, 256)?;
        check_text("user id", member, 64)?;
        let mut r = MemberRevocation {
            v: 1,
            resource: resource.into(),
            user_id: member.into(),
            before,
            at: now,
            issuer_id: user_id(&owner.public()),
            issuer_key: owner.public().encode_protobuf(),
            sig: vec![],
        };
        r.sig = sign_with(owner, REVOCATION_DOMAIN, &r)?;
        Ok(r)
    }

    pub fn verify(&self) -> Result<()> {
        if self.v != 1 {
            return Err(NetError::invalid("revocation", "unknown version"));
        }
        let k = issuer(&self.issuer_key, &self.issuer_id)?;
        let mut body = self.clone();
        body.sig = vec![];
        if !k.verify(&signed_bytes(REVOCATION_DOMAIN, &body), &self.sig) {
            return Err(NetError::Crypto("revocation: bad signature".into()));
        }
        Ok(())
    }

    /// Whether this voids `m`.
    pub fn voids(&self, m: &Membership) -> bool {
        self.issuer_id == m.issuer_id && self.resource == m.resource && self.user_id == m.user_id && m.issued_at <= self.before
    }
}

/// The checked revocations an owner has issued (any resources).
#[derive(Debug, Clone, Default)]
pub struct Revocations {
    owner: String,
    list: Vec<MemberRevocation>,
}

impl Revocations {
    pub fn new(owner: &str) -> Self {
        Revocations { owner: owner.into(), list: vec![] }
    }

    /// Add a revocation after checking it is the owner's and signed.
    pub fn add(&mut self, r: MemberRevocation) -> Result<()> {
        if r.issuer_id != self.owner {
            return Err(NetError::invalid("revocation", "not the owner's"));
        }
        r.verify()?;
        if let Some(old) = self.list.iter_mut().find(|o| o.resource == r.resource && o.user_id == r.user_id) {
            if r.before > old.before {
                *old = r;
            }
        } else {
            self.list.push(r);
        }
        Ok(())
    }

    /// Add all, failing on the first that does not check out.
    pub fn extend(&mut self, rs: impl IntoIterator<Item = MemberRevocation>) -> Result<()> {
        rs.into_iter().try_for_each(|r| self.add(r))
    }

    pub fn revokes(&self, m: &Membership) -> bool {
        self.list.iter().any(|r| r.voids(m))
    }

    pub fn list(&self) -> &[MemberRevocation] {
        &self.list
    }
}

/// What a member's node sends a host: the membership and the member's card, which must
/// certify the sending node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Presented {
    pub membership: Membership,
    pub card: Card,
}

/// Host side: check what `peer` presented for `resource` of `owner`: a valid, unexpired,
/// unrevoked membership whose member's card certifies `peer`. Returns the membership.
pub fn check_presented(
    profile: &Profile,
    p: &Presented,
    peer: &PeerId,
    owner: &str,
    resource: &str,
    revoked: &Revocations,
    now: i64,
) -> Result<Membership> {
    p.membership.verify_for(owner, resource, now)?;
    if p.card.id != p.membership.user_id {
        return Err(NetError::invalid("membership", "the card is someone else's"));
    }
    profile.check_card(&peer.to_string(), &p.card)?;
    if revoked.revokes(&p.membership) {
        return Err(NetError::invalid("membership", "revoked"));
    }
    Ok(p.membership.clone())
}

/// Write one length-prefixed JSON frame.
pub fn write_frame<W: std::io::Write>(w: &mut W, v: &impl Serialize) -> Result<()> {
    let b = serde_json::to_vec(v).map_err(NetError::net)?;
    w.write_all(&(b.len() as u32).to_be_bytes()).and_then(|_| w.write_all(&b)).and_then(|_| w.flush()).map_err(NetError::net)
}

/// Read one frame of at most [`MAX_FRAME`] bytes.
pub fn read_frame<T: DeserializeOwned, R: std::io::Read>(r: &mut R) -> Result<T> {
    let mut l = [0u8; 4];
    r.read_exact(&mut l).map_err(NetError::net)?;
    let l = u32::from_be_bytes(l) as usize;
    if l > MAX_FRAME {
        return Err(NetError::invalid("frame", "too large"));
    }
    let mut b = vec![0u8; l];
    r.read_exact(&mut b).map_err(NetError::net)?;
    serde_json::from_slice(&b).map_err(|e| NetError::invalid("frame", e.to_string()))
}

pub async fn write_frame_async<W: futures::AsyncWrite + Unpin>(w: &mut W, v: &impl Serialize) -> Result<()> {
    use futures::AsyncWriteExt;
    let b = serde_json::to_vec(v).map_err(NetError::net)?;
    let mut f = (b.len() as u32).to_be_bytes().to_vec();
    f.extend(b);
    w.write_all(&f).await.map_err(NetError::net)?;
    w.flush().await.map_err(NetError::net)
}

pub async fn read_frame_async<T: DeserializeOwned, R: futures::AsyncRead + Unpin>(r: &mut R) -> Result<T> {
    use futures::AsyncReadExt;
    let mut l = [0u8; 4];
    r.read_exact(&mut l).await.map_err(NetError::net)?;
    let l = u32::from_be_bytes(l) as usize;
    if l > MAX_FRAME {
        return Err(NetError::invalid("frame", "too large"));
    }
    let mut b = vec![0u8; l];
    r.read_exact(&mut b).await.map_err(NetError::net)?;
    serde_json::from_slice(&b).map_err(|e| NetError::invalid("frame", e.to_string()))
}

/// Member side: present a membership on a stream the application opened.
pub fn present<S: std::io::Write>(s: &mut S, p: &Presented) -> Result<()> {
    write_frame(s, p)
}

/// Host side: read what was presented on a stream and check it (see [`check_presented`]).
pub fn read_presented<S: std::io::Read>(
    s: &mut S,
    profile: &Profile,
    peer: &PeerId,
    owner: &str,
    resource: &str,
    revoked: &Revocations,
    now: i64,
) -> Result<Membership> {
    let p: Presented = read_frame(s)?;
    check_presented(profile, &p, peer, owner, resource, revoked, now)
}
