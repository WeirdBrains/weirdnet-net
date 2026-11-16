//! Memberships, revocations, presenting them, and requests to join over the in-memory
//! transport.
use crate::content::{Manifest, ManifestDraft};
use crate::join::{self, JoinAnswer, JoinHost, JoinLimits, JoinQueue, JoinReply, JoinRequest, MemoryJoinQueue};
use crate::member::{self, MemberRevocation, Membership, Presented, Revocations};
use crate::node::{Handler, Node, NodeConfig};
use crate::user::{Card, user_id};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

fn card(user: &Keypair, peer: &PeerId) -> Card {
    let id = user_id(&user.public());
    let cert = WEIRDNET.certify(user, &id, &peer.to_string(), "laptop", 1).unwrap();
    Card { id, label: "ben".into(), key: user.public().encode_protobuf(), nodes: vec![cert] }
}

#[test]
fn memberships_verify_expire_and_are_revoked() {
    let (owner, ben) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let (oid, bid) = (user_id(&owner.public()), user_id(&ben.public()));
    let m = Membership::issue(&owner, "garden", &bid, "member", 1000, Some(5000)).unwrap();
    m.verify_for(&oid, "garden", 2000).unwrap();
    assert!(m.verify(6000).is_err(), "expired");
    assert!(m.verify_for(&oid, "orchard", 2000).is_err(), "other resource");
    assert!(m.verify_for(&bid, "garden", 2000).is_err(), "other owner");
    let mut t = m.clone();
    t.role = "owner".into();
    assert!(t.verify(2000).is_err(), "role changed");
    let forged = Membership::issue(&ben, "garden", &bid, "owner", 1000, None).unwrap();
    assert!(forged.verify_for(&oid, "garden", 2000).is_err(), "self-issued");
    assert!(Membership::issue(&owner, "garden", &bid, "a\nb", 1, None).is_err());

    let mut rev = Revocations::new(&oid);
    assert!(rev.add(MemberRevocation::revoke(&ben, "garden", &bid, 9999, 1).unwrap()).is_err(), "not the owner's");
    rev.add(MemberRevocation::revoke(&owner, "garden", &bid, 1500, 1600).unwrap()).unwrap();
    assert!(rev.revokes(&m));
    let again = Membership::issue(&owner, "garden", &bid, "member", 1700, None).unwrap();
    assert!(!rev.revokes(&again), "re-admitted after the revocation");
    let mut bad = MemberRevocation::revoke(&owner, "garden", &bid, 1, 1).unwrap();
    bad.before = 99_999;
    assert!(rev.add(bad).is_err(), "tampered");
}

#[test]
fn manifests_carry_member_revocations() {
    let (owner, other) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let r = MemberRevocation::revoke(&owner, "site", "abcd", 10, 10).unwrap();
    let m = Manifest::sign(&owner, ManifestDraft { id: "site".into(), version: 1, member_revocations: vec![r.clone()], ..Default::default() }, 20)
        .unwrap();
    m.verify(20).unwrap();
    let mut rev = Revocations::new(&m.user_id);
    rev.extend(m.member_revocations.clone()).unwrap();
    assert_eq!(rev.list().len(), 1);
    let theirs = MemberRevocation::revoke(&other, "site", "abcd", 10, 10).unwrap();
    assert!(
        Manifest::sign(&owner, ManifestDraft { id: "site".into(), version: 2, member_revocations: vec![theirs], ..Default::default() }, 20).is_err()
    );
}

#[test]
fn a_presented_membership_must_be_the_sending_nodes() {
    let (owner, ben) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let oid = user_id(&owner.public());
    let (node, stranger) = (PeerId::random(), PeerId::random());
    let c = card(&ben, &node);
    let m = Membership::issue(&owner, "garden", &c.id, "member", 1, None).unwrap();
    let p = Presented { membership: m.clone(), card: c.clone() };
    let mut wire = vec![];
    member::present(&mut wire, &p).unwrap();
    let rev = Revocations::new(&oid);
    let got = member::read_presented(&mut &wire[..], &WEIRDNET, &node, &oid, "garden", &rev, 10).unwrap();
    assert_eq!(got, m);
    assert!(member::check_presented(&WEIRDNET, &p, &stranger, &oid, "garden", &rev, 10).is_err(), "another node");
    let eve = Keypair::generate_ed25519();
    let p2 = Presented { membership: m, card: card(&eve, &node) };
    assert!(member::check_presented(&WEIRDNET, &p2, &node, &oid, "garden", &rev, 10).is_err(), "someone else's card");
    let mut huge = (u32::MAX).to_be_bytes().to_vec();
    huge.extend([0u8; 8]);
    assert!(member::read_presented(&mut &huge[..], &WEIRDNET, &node, &oid, "garden", &rev, 10).is_err());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Q;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R;
struct H;
impl Handler<Q, R> for H {
    fn request(&self, _: &PeerId, _: Q) -> R {
        R
    }
}

fn start() -> Node<Q, R> {
    let cfg = NodeConfig { listen: vec!["/memory/0".parse().unwrap()], memory: true, ..Default::default() };
    Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(H)).unwrap()
}

fn addr(n: &Node<Q, R>) -> Multiaddr {
    n.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap()
}

#[test]
fn join_requests_are_queued_answered_and_limited() {
    let (host, me) = (start(), start());
    let (owner, ben) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let oid = user_id(&owner.public());
    let queue = Arc::new(MemoryJoinQueue::default());
    let limits = JoinLimits { per_user: 3, per_peer: 100, window: Duration::from_secs(60), max_pending: 1 };
    let _srv = join::serve_joins(
        &host,
        JoinHost { profile: &WEIRDNET, queue: queue.clone(), limits, accepts: Arc::new(|r| r == "garden" || r == "orchard") },
    )
    .unwrap();
    let a = [addr(&host)];
    let now = crate::now_ms();
    let req = JoinRequest::new(&ben, card(&ben, &me.peer_id()), "garden", Some("hi, I'm Ben".into()), now).unwrap();

    assert_eq!(join::request_join(&me, host.peer_id(), &a, &req).unwrap(), JoinReply::Queued);
    let pending = queue.pending("garden");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message.as_deref(), Some("hi, I'm Ben"));

    // the owner approves; asking again returns the membership
    queue.set_answer("garden", req.user_id(), join::approve(&owner, &pending[0], "member", None, now).unwrap()).unwrap();
    let JoinReply::Answered(ans) = join::request_join(&me, host.peer_id(), &a, &req).unwrap() else { panic!("no answer") };
    ans.verify(&oid, &req, now).unwrap();
    assert!(matches!(ans, JoinAnswer::Approved(ref m) if m.role == "member"));
    assert!(queue.pending("garden").is_empty());

    // unknown resource
    let other = JoinRequest::new(&ben, card(&ben, &me.peer_id()), "nowhere", None, now).unwrap();
    assert!(matches!(join::request_join(&me, host.peer_id(), &a, &other).unwrap(), JoinReply::Refused(_)));
    // a request signed for another node is refused
    let stolen = JoinRequest::new(&ben, card(&ben, &PeerId::random()), "orchard", None, now).unwrap();
    assert!(matches!(join::request_join(&me, host.peer_id(), &a, &stolen).unwrap(), JoinReply::Refused(_)));
    // ben has used his three messages (the refused forgery does not count) this window
    let orchard = JoinRequest::new(&ben, card(&ben, &me.peer_id()), "orchard", None, now).unwrap();
    assert!(matches!(join::request_join(&me, host.peer_id(), &a, &orchard).unwrap(), JoinReply::Limited { .. }));

    // the pending cap: one waiting request per resource
    let (cara, dan) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let rc = JoinRequest::new(&cara, card(&cara, &me.peer_id()), "orchard", None, now).unwrap();
    assert_eq!(join::request_join(&me, host.peer_id(), &a, &rc).unwrap(), JoinReply::Queued);
    let rd = JoinRequest::new(&dan, card(&dan, &me.peer_id()), "orchard", None, now).unwrap();
    assert!(matches!(join::request_join(&me, host.peer_id(), &a, &rd).unwrap(), JoinReply::Refused(_)));

    // a denial answers that request; it checks out for the requester
    let den = join::deny(&owner, &rc, Some("not now".into()), now).unwrap();
    queue.set_answer("orchard", rc.user_id(), den).unwrap();
    let JoinReply::Answered(ans) = join::request_join(&me, host.peer_id(), &a, &rc).unwrap() else { panic!("no answer") };
    ans.verify(&oid, &rc, now).unwrap();
    assert!(ans.verify(&oid, &rd, now).is_err(), "not dan's");
    // asking anew after a denial is queued again
    let rc2 = JoinRequest::new(&cara, card(&cara, &me.peer_id()), "orchard", Some("please".into()), now + 1).unwrap();
    assert_eq!(join::request_join(&me, host.peer_id(), &a, &rc2).unwrap(), JoinReply::Queued);
}
