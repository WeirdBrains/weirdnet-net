//! Known peers to dial without discovery, and the discovery mode that turns
//! LAN and DHT finding off.
//!
//! A [`PeerHint`] is an address book entry: a peer id and one or more addresses
//! that reach it. Adding a hint does not grant trust. Whether a peer may act for
//! a user is decided by [`crate::user::NodeCert`] (and the application's roster),
//! not by this list. The application persists the list (JSON via [`encode_peers`]
//! / [`decode_peers`]); this crate does not write it to disk.
use crate::Multiaddr;
use crate::error::{NetError, Result};
use libp2p::PeerId;
use libp2p::multiaddr::Protocol;
use serde::{Deserialize, Serialize};

/// Peer discovery: mDNS on the LAN and Kademlia (bootstrap, learn peers from
/// identify, advertise and look up keys). The default is enabled, which keeps
/// today's behaviour (`mdns` still has to be turned on separately to announce
/// on the LAN).
///
/// Disabled: no mDNS listener, no DHT bootstrap or advertising, and identify
/// does not feed the routing table. Configured relays, [manual peers](PeerHint),
/// explicit dials, and serving apps or content to a connected peer still work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    #[default]
    Enabled,
    Disabled,
}

impl DiscoveryMode {
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    pub fn from_enabled(on: bool) -> Self {
        if on { Self::Enabled } else { Self::Disabled }
    }
}

/// A peer to dial without discovering it: its id and addresses that reach it
/// (direct or a relay circuit). Addresses should include `/p2p/<id>` or match
/// [`PeerHint::peer_id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHint {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

impl PeerHint {
    /// From a multiaddr that already ends in `/p2p/<id>`.
    pub fn from_addr(addr: &str) -> Result<Self> {
        let m: Multiaddr = addr.parse().map_err(|e| NetError::invalid("peer", format!("{addr}: {e}")))?;
        let Some(peer) = addr_peer_id(&m) else {
            return Err(NetError::invalid("peer", format!("{addr} has no /p2p/ peer id")));
        };
        Ok(Self { peer_id: peer.to_string(), addrs: vec![m.to_string()] })
    }

    /// From a peer id (or a `/p2p/<id>` address) and any extra addresses.
    pub fn parse(peer: &str, addrs: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self> {
        let peer_id = parse_peer_id(peer)?;
        let mut out = Vec::new();
        for a in addrs {
            let a = a.as_ref().trim();
            if a.is_empty() {
                continue;
            }
            let m: Multiaddr = a.parse().map_err(|e| NetError::invalid("peer", format!("{a}: {e}")))?;
            if let Some(p) = addr_peer_id(&m)
                && p != peer_id
            {
                return Err(NetError::invalid("peer", format!("{a} is for {p}, not {peer_id}")));
            }
            let full = if addr_peer_id(&m).is_some() { m } else { m.with(Protocol::P2p(peer_id)) };
            let s = full.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        if out.is_empty() {
            return Err(NetError::invalid("peer", "a peer needs at least one address"));
        }
        Ok(Self { peer_id: peer_id.to_string(), addrs: out })
    }

    pub fn peer_id(&self) -> Result<PeerId> {
        parse_peer_id(&self.peer_id)
    }

    pub fn multiaddrs(&self) -> Result<Vec<Multiaddr>> {
        let peer = self.peer_id()?;
        let mut out = Vec::new();
        for a in &self.addrs {
            let m: Multiaddr = a.parse().map_err(|e| NetError::invalid("peer", format!("{a}: {e}")))?;
            if let Some(p) = addr_peer_id(&m)
                && p != peer
            {
                return Err(NetError::invalid("peer", format!("{a} is for {p}, not {peer}")));
            }
            out.push(if addr_peer_id(&m).is_some() { m } else { m.with(Protocol::P2p(peer)) });
        }
        if out.is_empty() {
            return Err(NetError::invalid("peer", "a peer needs at least one address"));
        }
        Ok(out)
    }
}

/// JSON for the application to store (it writes the file).
pub fn encode_peers(peers: &[PeerHint]) -> Result<String> {
    Ok(serde_json::to_string_pretty(peers)?)
}

pub fn decode_peers(json: &str) -> Result<Vec<PeerHint>> {
    let peers: Vec<PeerHint> = serde_json::from_str(json)?;
    for p in &peers {
        p.multiaddrs()?;
    }
    Ok(peers)
}

pub fn parse_peer_id(s: &str) -> Result<PeerId> {
    let s = s.trim();
    if let Ok(m) = s.parse::<Multiaddr>()
        && let Some(p) = addr_peer_id(&m)
    {
        return Ok(p);
    }
    s.parse().map_err(|e| NetError::invalid("peer", format!("{s}: {e}")))
}

fn addr_peer_id(m: &Multiaddr) -> Option<PeerId> {
    m.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn id() -> (PeerId, String) {
        let p = Keypair::generate_ed25519().public().to_peer_id();
        (p, p.to_string())
    }

    #[test]
    fn discovery_defaults_to_enabled() {
        assert_eq!(DiscoveryMode::default(), DiscoveryMode::Enabled);
        assert!(DiscoveryMode::Enabled.is_enabled());
        assert!(!DiscoveryMode::Disabled.is_enabled());
    }

    #[test]
    fn from_addr_requires_a_peer_id() {
        let (p, s) = id();
        let addr = format!("/ip4/127.0.0.1/tcp/4747/p2p/{s}");
        let h = PeerHint::from_addr(&addr).unwrap();
        assert_eq!(h.peer_id, s);
        assert_eq!(h.multiaddrs().unwrap()[0].to_string(), addr);
        assert_eq!(h.peer_id().unwrap(), p);
        assert!(PeerHint::from_addr("/ip4/127.0.0.1/tcp/4747").is_err());
        assert!(PeerHint::from_addr("not-an-addr").is_err());
    }

    #[test]
    fn parse_rejects_a_mismatched_peer_and_empty_addrs() {
        let (_, a) = id();
        let (_, b) = id();
        let ok = "/ip4/127.0.0.1/tcp/1";
        let h = PeerHint::parse(&a, [&ok]).unwrap();
        assert!(h.addrs[0].ends_with(&format!("/p2p/{a}")));
        let other = format!("/ip4/127.0.0.1/tcp/1/p2p/{b}");
        assert!(PeerHint::parse(&a, [&other]).is_err());
        assert!(PeerHint::parse(&a, Vec::<&str>::new()).is_err());
        assert!(PeerHint::parse("nope", [&ok]).is_err());
    }

    #[test]
    fn peers_json_round_trips() {
        let (_, s) = id();
        let addr = format!("/memory/1/p2p/{s}");
        let list = vec![PeerHint::from_addr(&addr).unwrap()];
        let raw = encode_peers(&list).unwrap();
        assert_eq!(decode_peers(&raw).unwrap(), list);
        assert!(decode_peers("[]").unwrap().is_empty());
        assert!(decode_peers("{").is_err());
    }
}
