//! Locator records for private sites (W10): a record only trusted peers can find or read.
//!
//! Each private site gets a random Ed25519 locator key and a 32-byte locator secret
//! ([`LocatorKeys`]); the owner hands both only to trusted peers and members (sealed in the
//! exchange or with the membership). The DHT key is
//! `SHA-256("weirdnet/locator/v1" ‖ locator key ‖ epoch)` with the epoch the UTC day, so it
//! changes daily and a stranger cannot link records over time. The value is
//! `{ epoch, seq, expires, sealed }`, where `sealed` is the site id and its [`PeerRecord`]
//! under XChaCha20-Poly1305 (`weirdnet-keys`) with a key derived from the secret and the
//! epoch, the whole signed by the locator key, never the user key. Storing nodes check the
//! signature, the key, the expiry and `seq` ([`accept_locator`]) and learn nothing about the
//! owner, the site or the addresses. Trusted peers derive the same key, fetch, open and dial;
//! the host still checks who is calling.
use crate::error::{NetError, Result};
use crate::names::PeerRecord;
use crate::user::decode_public;
use libp2p::identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use weirdnet_keys::{Key32, Sealed};

const DOMAIN: &str = "weirdnet/locator/v1";
/// A UTC day in milliseconds: one epoch.
pub const EPOCH_MS: i64 = 24 * 3600 * 1000;
/// Records outlive their day by at most this much, so lookups around midnight still work.
pub const EPOCH_GRACE_MS: i64 = 2 * 3600 * 1000;

/// The epoch (UTC day) of a time in milliseconds.
pub fn epoch_of(now: i64) -> u64 {
    (now.max(0) / EPOCH_MS) as u64
}

/// A site's locator key and secret. Share both with those who may find the site.
pub struct LocatorKeys {
    pub key: Keypair,
    pub secret: Key32,
}

/// What the sealed part holds.
#[derive(Serialize, Deserialize)]
struct Inner {
    site: String,
    record: PeerRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocatorRecord {
    pub v: u8,
    pub epoch: u64,
    pub seq: u64,
    pub expires: i64,
    /// The locator public key (protobuf).
    pub locator_key: Vec<u8>,
    pub sealed: Sealed,
    pub sig: Vec<u8>,
}

/// The DHT key of a locator key's record in `epoch`.
pub fn dht_key(locator: &PublicKey, epoch: u64) -> Vec<u8> {
    let mut h = sha2::Sha256::new();
    h.update(DOMAIN.as_bytes());
    h.update(locator.encode_protobuf());
    h.update(epoch.to_be_bytes());
    h.finalize().to_vec()
}

/// The keys to look a site up under at `now`: today's, then yesterday's.
pub fn lookup_keys(locator: &PublicKey, now: i64) -> Vec<Vec<u8>> {
    let e = epoch_of(now);
    let mut v = vec![dht_key(locator, e)];
    if e > 0 {
        v.push(dht_key(locator, e - 1));
    }
    v
}

fn seal_key(secret: &Key32, locator: &PublicKey, epoch: u64) -> Result<Key32> {
    Ok(weirdnet_keys::kdf::hkdf(&secret.0, Some(&locator.encode_protobuf()), format!("{DOMAIN}/seal/{epoch}").as_bytes())?)
}

impl LocatorKeys {
    pub fn generate() -> Result<LocatorKeys> {
        Ok(LocatorKeys { key: Keypair::generate_ed25519(), secret: Key32::random()? })
    }

    /// The protobuf locator keypair and the secret, to hand to a trusted peer.
    pub fn to_bytes(&self) -> Result<(Vec<u8>, [u8; 32])> {
        Ok((self.key.to_protobuf_encoding().map_err(|e| NetError::Crypto(e.to_string()))?, self.secret.0))
    }

    pub fn from_bytes(key: &[u8], secret: [u8; 32]) -> Result<LocatorKeys> {
        Ok(LocatorKeys {
            key: Keypair::from_protobuf_encoding(key).map_err(|e| NetError::Crypto(format!("locator key: {e}")))?,
            secret: Key32(secret),
        })
    }

    /// The site's record for the epoch of `now`, expiring at `expires` (no later than the end
    /// of the day plus [`EPOCH_GRACE_MS`]; publish again each day).
    pub fn seal(&self, site: &str, record: &PeerRecord, seq: u64, now: i64, expires: i64) -> Result<LocatorRecord> {
        let epoch = epoch_of(now);
        let end = (epoch as i64 + 1) * EPOCH_MS + EPOCH_GRACE_MS;
        let expires = expires.min(end).min(record.expires);
        if expires <= now {
            return Err(NetError::invalid("locator record", "already expired"));
        }
        let pk = self.key.public();
        let k = seal_key(&self.secret, &pk, epoch)?;
        let inner = serde_json::to_vec(&Inner { site: site.into(), record: record.clone() }).map_err(NetError::net)?;
        let sealed = weirdnet_keys::seal(&k, &inner, &dht_key(&pk, epoch))?;
        let mut r = LocatorRecord { v: 1, epoch, seq, expires, locator_key: pk.encode_protobuf(), sealed, sig: vec![] };
        r.sig = self.key.sign(&r.body()).map_err(|e| NetError::Crypto(format!("locator: {e}")))?;
        Ok(r)
    }

    /// Open a record found for this locator: the site id and its peer record, checked.
    pub fn open(&self, profile: &crate::Profile, r: &LocatorRecord, now: i64) -> Result<(String, PeerRecord)> {
        let pk = self.key.public();
        if r.locator_key != pk.encode_protobuf() {
            return Err(NetError::invalid("locator record", "another locator"));
        }
        r.verify(now)?;
        let k = seal_key(&self.secret, &pk, r.epoch)?;
        let inner = weirdnet_keys::open(&k, &r.sealed, &dht_key(&pk, r.epoch))?;
        let inner: Inner = serde_json::from_slice(&inner).map_err(|e| NetError::invalid("locator record", e.to_string()))?;
        profile.verify_record(&inner.record, now)?;
        Ok((inner.site, inner.record))
    }
}

impl LocatorRecord {
    fn body(&self) -> Vec<u8> {
        let mut b = self.clone();
        b.sig = vec![];
        let mut v = DOMAIN.as_bytes().to_vec();
        v.push(b'\n');
        v.extend(serde_json::to_vec(&b).unwrap_or_default());
        v
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn decode(b: &[u8]) -> Result<LocatorRecord> {
        if b.len() > 64 * 1024 {
            return Err(NetError::invalid("locator record", "too large"));
        }
        serde_json::from_slice(b).map_err(|e| NetError::invalid("locator record", e.to_string()))
    }

    /// The DHT key this record belongs under.
    pub fn key(&self) -> Result<Vec<u8>> {
        Ok(dht_key(&decode_public(&self.locator_key)?, self.epoch))
    }

    /// What a storing node can check: the version, the locator signature, the expiry and
    /// that the epoch is current (yesterday, today or tomorrow).
    pub fn verify(&self, now: i64) -> Result<()> {
        if self.v != 1 {
            return Err(NetError::invalid("locator record", "unknown version"));
        }
        let today = epoch_of(now);
        if self.epoch + 1 < today || self.epoch > today + 1 {
            return Err(NetError::invalid("locator record", "not a current epoch"));
        }
        if self.expires <= now || self.expires > (self.epoch as i64 + 1) * EPOCH_MS + EPOCH_GRACE_MS {
            return Err(NetError::invalid("locator record", "expired or outlives its day"));
        }
        if self.sealed.ct.len() > 32 * 1024 {
            return Err(NetError::invalid("locator record", "too large"));
        }
        let pk = decode_public(&self.locator_key)?;
        if !pk.verify(&self.body(), &self.sig) {
            return Err(NetError::Crypto("locator record: bad signature".into()));
        }
        Ok(())
    }
}

/// The storing node's rule: keep `incoming` under `key` instead of `existing`? It must
/// verify and belong under `key`, and its `seq` must be above an unexpired existing one's.
pub fn accept_locator(key: &[u8], existing: Option<&LocatorRecord>, incoming: &LocatorRecord, now: i64) -> Result<()> {
    incoming.verify(now)?;
    if incoming.key()? != key {
        return Err(NetError::invalid("locator record", "wrong key"));
    }
    if let Some(old) = existing.filter(|o| o.expires > now)
        && incoming.seq <= old.seq
    {
        return Err(NetError::invalid("locator record", format!("seq {} is not above {}", incoming.seq, old.seq)));
    }
    Ok(())
}

/// The freshest record that opens among those found.
pub fn newest_open(keys: &LocatorKeys, profile: &crate::Profile, found: &[LocatorRecord], now: i64) -> Option<(String, PeerRecord)> {
    let mut v: Vec<&LocatorRecord> = found.iter().collect();
    v.sort_by_key(|r| std::cmp::Reverse((r.epoch, r.seq)));
    v.into_iter().find_map(|r| keys.open(profile, r, now).ok())
}
