//! Signed manifests: what a user publishes under an id, version by version: paths with their
//! file roots, sizes and the app's own metadata, and roots no longer to be served.
use super::{Hash, hex, unhex};
use crate::error::{NetError, Result};
use crate::user::{decode_public, user_id};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "weirdnet/content/manifest/1";
const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// A relative path with `/` separators (no `..`, no empty parts).
    pub path: String,
    /// The file's root (hex).
    pub root: String,
    pub size: u64,
    /// The application's metadata, opaque here.
    #[serde(default, with = "serde_bytes_vec")]
    pub meta: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u8,
    /// What the manifest is of (a site, a project, a folder), chosen by its owner.
    pub id: String,
    /// Grows with every new manifest of this id.
    pub version: u64,
    pub user_id: String,
    pub user_key: Vec<u8>,
    pub entries: Vec<ManifestEntry>,
    /// Roots that must no longer be served or fetched under this id.
    pub revoked: Vec<String>,
    pub issued_at: i64,
    pub sig: Vec<u8>,
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::hex(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::unhex(&s).ok_or_else(|| serde::de::Error::custom("not hex"))
    }
}

fn check_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.starts_with('/')
        && !p.contains('\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
}

impl Manifest {
    fn body(&self) -> Vec<u8> {
        let mut m = self.clone();
        m.sig = vec![];
        let mut v = DOMAIN.as_bytes().to_vec();
        v.push(b'\n');
        v.extend(serde_json::to_vec(&m).unwrap_or_default());
        v
    }

    /// Sign a manifest with the user key.
    pub fn sign(user: &Keypair, id: &str, version: u64, mut entries: Vec<ManifestEntry>, revoked: Vec<String>, now: i64) -> Result<Manifest> {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut m = Manifest {
            v: 1,
            id: id.to_string(),
            version,
            user_id: user_id(&user.public()),
            user_key: user.public().encode_protobuf(),
            entries,
            revoked,
            issued_at: now,
            sig: vec![],
        };
        m.check_fields()?;
        m.sig = user.sign(&m.body()).map_err(|e| NetError::Crypto(format!("manifest: {e}")))?;
        Ok(m)
    }

    fn check_fields(&self) -> Result<()> {
        let bad = |m: String| NetError::invalid("manifest", m);
        if self.v != 1 {
            return Err(bad("unknown version".into()));
        }
        if self.id.is_empty() || self.id.len() > 256 {
            return Err(bad("id: 1 to 256 bytes".into()));
        }
        let mut last: Option<&str> = None;
        for e in &self.entries {
            if !check_path(&e.path) {
                return Err(bad(format!("bad path `{}`", e.path)));
            }
            if last.is_some_and(|l| l >= e.path.as_str()) {
                return Err(bad(format!("`{}` repeated or out of order", e.path)));
            }
            last = Some(&e.path);
            if unhex(&e.root).is_none_or(|r| r.len() != 32) {
                return Err(bad(format!("`{}`: bad root", e.path)));
            }
        }
        if self.revoked.iter().any(|r| unhex(r).is_none_or(|r| r.len() != 32)) {
            return Err(bad("bad revoked root".into()));
        }
        Ok(())
    }

    /// Check the fields, the signature and that the key is the user id's.
    pub fn verify(&self, now: i64) -> Result<()> {
        self.check_fields()?;
        let key = decode_public(&self.user_key)?;
        if user_id(&key) != self.user_id {
            return Err(NetError::invalid("manifest", "the user id does not match the key"));
        }
        if self.issued_at > now + CLOCK_SKEW_MS {
            return Err(NetError::invalid("manifest", "from the future"));
        }
        if !key.verify(&self.body(), &self.sig) {
            return Err(NetError::invalid("manifest", "bad signature"));
        }
        Ok(())
    }

    /// Whether this replaces `older`: same id and user, a higher version.
    pub fn supersedes(&self, older: &Manifest) -> bool {
        self.id == older.id && self.user_id == older.user_id && self.version > older.version
    }

    pub fn entry(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.binary_search_by(|e| e.path.as_str().cmp(path)).ok().map(|i| &self.entries[i])
    }

    /// Whether `root` was revoked here.
    pub fn is_revoked(&self, root: &Hash) -> bool {
        let h = hex(root);
        self.revoked.contains(&h)
    }
}
