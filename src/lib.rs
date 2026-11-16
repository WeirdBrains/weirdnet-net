#![doc = include_str!("../README.md")]
pub mod addr;
pub mod content;
mod error;
pub mod events;
pub mod exchange;
pub mod identity;
pub mod ingress;
pub mod invite;
pub mod join;
pub mod locator;
pub mod member;
pub mod names;
pub mod node;
pub mod profile;
pub mod sealed;
pub mod shard;
pub mod stream;
pub mod sync;
pub mod user;
pub mod wss;

pub use error::{NetError, Result};
pub use events::{Event, Events, StatusWatch};
pub use exchange::{Answer, DEFAULT_TTL_MS, Derived, Offer, Token, normalize_code};
pub use libp2p::identity::{Keypair, PublicKey};
pub use libp2p::{Multiaddr, PeerId};
pub use node::{Handler, Message, Node, NodeConfig, RelayLimits, Sighting, Status};
pub use profile::{Profile, WEIRDNET};
pub use stream::{Incoming, Limits, Path, Stream};
pub use weirdnet_keys::{Key32, Sealed};
pub use wss::WssTls;

/// The last 8 characters of a peer id.
pub fn short_peer_id(p: &PeerId) -> String {
    identity::short_peer(&p.to_string()).to_string()
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod content_tests;
#[cfg(test)]
mod dnsaddr_tests;
#[cfg(test)]
mod events_tests;
#[cfg(test)]
mod ingress_tests;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod names_tests;
#[cfg(test)]
mod relay_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wss_tests;
