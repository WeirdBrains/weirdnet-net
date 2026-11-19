//! Identifier profiles: every protocol id, token prefix, link scheme, signature domain and
//! derivation label the crate puts on the wire or under a signature. [`WEIRDNET`] is the
//! default. An application with nodes already in the field passes its own profile with the
//! values those nodes use, so its bytes stay exactly as they were; two profiles never mix
//! on one connection, because nodes on different protocol ids don't talk at all.
use crate::error::{NetError, Result};
use serde_json::Value;

/// Checks an exchange scope (what an offer is for) before it is signed and when it is
/// verified. Unknown kinds must be refused, so a node never misreads a newer one.
pub type ScopeCheck = fn(&Value) -> Result<()>;

#[derive(Debug, Clone, Copy)]
pub struct Profile {
    /// The agent name (`NAME/VERSION` in identify) and the capability a peer speaking
    /// [`Profile::protocol`] is listed with.
    pub name: &'static str,
    /// Request-response protocol id.
    pub protocol: &'static str,
    /// Kademlia protocol id (nodes on another one end up in another DHT).
    pub kad: &'static str,
    /// The Kademlia key relays provide.
    pub relay_key: &'static str,
    /// The identify protocol id.
    pub identify: &'static str,
    /// Token prefixes, and the start every token of this profile shares.
    pub offer_prefix: &'static str,
    pub answer_prefix: &'static str,
    pub token_mark: &'static str,
    /// Link forms of offers (invitations) and answers, and the scheme both share. They are
    /// the application's own scheme (`weirdnet-<app>://join/`, `weirdnet-<app>://answer/`,
    /// `weirdnet-<app>://`). Empty means the profile has no link form: [`Profile::link`]
    /// refuses, and only tokens are read. The bare `weirdnet://` scheme is reserved
    /// ([`RESERVED_LINK_SCHEME`]): links on it are never made or read.
    pub join_link: &'static str,
    pub answer_link: &'static str,
    pub link_mark: &'static str,
    /// Signature domains of offers and answers, the transcript domain, and the HKDF infos
    /// of the exchange key and the short code.
    pub offer_domain: &'static str,
    pub answer_domain: &'static str,
    pub transcript_domain: &'static str,
    pub key_info: &'static str,
    pub sas_info: &'static str,
    /// Associated-data label of sealed exchange messages (`LABEL|exchange|from|to`).
    pub msg_aad: &'static str,
    /// Signature domains of node certificates and their revocations.
    pub cert: &'static str,
    pub revoke: &'static str,
    /// HKDF info of the linked-node sync key and the associated-data label of sync pages.
    pub sync_key: &'static str,
    pub sync_aad: &'static str,
    /// The names (rendezvous) protocol id: peers register and look up signed peer records
    /// on a relay or other names server.
    pub names: &'static str,
    /// Signature domains of peer records and their withdrawals, and the prefix of the
    /// Kademlia key a user's record is stored under (`SHA-256(PREFIX + user id)`).
    pub peer_record: &'static str,
    pub withdrawal: &'static str,
    pub peer_key: &'static str,
    /// The port nodes listen on unless told otherwise (TCP and QUIC).
    pub default_port: u16,
    /// The name of the node's thread (its runtime's threads add `-rt`).
    pub thread: &'static str,
    /// Which exchange scopes this profile signs and accepts.
    pub scopes: ScopeCheck,
}

/// The bare scheme reserved for internal Weirdnet messages. Nothing routes through it, so
/// [`Profile::link`] never makes a link on it and parsing refuses one.
pub const RESERVED_LINK_SCHEME: &str = "weirdnet://";

/// Weirdnet's own identifiers, the default for new applications. It has no link scheme:
/// an application that shows invitation links sets its own (see [`Profile::join_link`]).
pub const WEIRDNET: Profile = Profile {
    name: "weirdnet",
    protocol: "/weirdnet/net/2",
    kad: "/weirdnet/kad/1",
    relay_key: "/weirdnet/relay/1",
    identify: "/weirdnet/id/1",
    offer_prefix: "wnet-x1-offer:",
    answer_prefix: "wnet-x1-answer:",
    token_mark: "wnet-x1-",
    join_link: "",
    answer_link: "",
    link_mark: "",
    offer_domain: "weirdnet/net/offer/v1",
    answer_domain: "weirdnet/net/answer/v1",
    transcript_domain: "weirdnet/net/exchange/v1",
    key_info: "weirdnet/net/exchange/v1/key",
    sas_info: "weirdnet/net/exchange/v1/sas",
    msg_aad: "weirdnet/net/msg/v1",
    cert: "weirdnet-node-cert/1",
    revoke: "weirdnet-node-revoke/1",
    sync_key: "weirdnet/sync/v1/key",
    sync_aad: "weirdnet/sync/v1",
    names: "/weirdnet/names/2",
    peer_record: "weirdnet/peer-record/v1",
    withdrawal: "weirdnet/withdrawal/v1",
    peer_key: "weirdnet/peer/",
    default_port: 4747,
    thread: "weirdnet-net",
    scopes,
};

/// Two nodes (`{"kind":"node"}`).
pub fn node_scope() -> Value {
    serde_json::json!({ "kind": "node" })
}

/// A node asking to act for the user of the node it connects to (`{"kind":"link"}`).
pub fn link_scope() -> Value {
    serde_json::json!({ "kind": "link" })
}

/// An invitation into something the application names: `to` is what (at most 64
/// characters) and `as` the role asked for (at most 32). What it grants is up to the
/// application; the crate only signs it and checks its shape.
pub fn invite_scope(to: &str, role: &str) -> Value {
    serde_json::json!({ "kind": "invite", "to": to, "as": role })
}

/// The kind of a scope (empty when it has none).
pub fn scope_kind(scope: &Value) -> &str {
    scope.get("kind").and_then(|k| k.as_str()).unwrap_or("")
}

fn field<'a>(scope: &'a Value, k: &str) -> &'a str {
    scope.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The default scopes: `node`, `link` and `invite`; anything else is refused.
pub fn scopes(scope: &Value) -> Result<()> {
    match scope_kind(scope) {
        "node" | "link" => Ok(()),
        "invite" => {
            let (to, role) = (field(scope, "to"), field(scope, "as"));
            if to.is_empty() || to.len() > 64 || role.is_empty() || role.len() > 32 {
                return Err(NetError::invalid("exchange", "an invitation names what it is into (`to`) and the role (`as`)"));
            }
            Ok(())
        }
        _ => Err(NetError::invalid("exchange", "unknown scope")),
    }
}

impl Profile {
    /// The identify agent: `NAME/VERSION`, with ` (LABEL)` when there is a label.
    pub fn agent(&self, version: &str, label: &str) -> String {
        let mut a = format!("{}/{version}", self.name);
        if !label.trim().is_empty() {
            a += &format!(" ({})", label.trim());
        }
        a
    }

    /// The link form of a token (one address to pass on); anything else unchanged. Fails
    /// when the profile has no link scheme (as [`WEIRDNET`]) or uses the reserved bare
    /// `weirdnet://` one.
    pub fn link(&self, token: &str) -> Result<String> {
        let (scheme, body) = if let Some(b) = token.strip_prefix(self.offer_prefix) {
            (self.join_link, b)
        } else if let Some(b) = token.strip_prefix(self.answer_prefix) {
            (self.answer_link, b)
        } else {
            return Ok(token.to_string());
        };
        if scheme.is_empty() {
            return Err(NetError::invalid(
                "link",
                "this profile has no link scheme; set join_link and answer_link to the app's own (weirdnet-<app>://join/)",
            ));
        }
        if reserved_link(scheme) {
            return Err(NetError::invalid("link", "weirdnet:// is reserved; links use the app's own scheme (weirdnet-<app>://)"));
        }
        Ok(format!("{scheme}{body}"))
    }

    /// A token from a link or a token, with whitespace and line breaks dropped.
    pub fn unlink(&self, input: &str) -> String {
        let s: String = input.split_whitespace().collect();
        if let Some(b) = s.strip_prefix(self.join_link).filter(|_| !self.join_link.is_empty()) {
            format!("{}{}", self.offer_prefix, b.trim_end_matches('/'))
        } else if let Some(b) = s.strip_prefix(self.answer_link).filter(|_| !self.answer_link.is_empty()) {
            format!("{}{}", self.answer_prefix, b.trim_end_matches('/'))
        } else {
            s
        }
    }

    /// Does this look like one of this profile's tokens or links (rather than a name)?
    pub fn is_token(&self, input: &str) -> bool {
        let t = input.trim();
        t.starts_with(self.token_mark) || (!self.link_mark.is_empty() && t.starts_with(self.link_mark))
    }
}

/// Is this on the reserved bare `weirdnet://` scheme (any case)?
pub(crate) fn reserved_link(s: &str) -> bool {
    s.get(..RESERVED_LINK_SCHEME.len()).is_some_and(|h| h.eq_ignore_ascii_case(RESERVED_LINK_SCHEME))
}
