//! Signed peer records, withdrawals, the names server and key-only dialing.
use crate::names::*;
use crate::node::{Handler, Node, NodeConfig, RelayLimits};
use crate::user::{NodeCert, user_id};
use crate::{Keypair, Multiaddr, PeerId, WEIRDNET, now_ms};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HOUR: i64 = 3600 * 1000;

struct User {
    key: Keypair,
    id: String,
}

fn user() -> User {
    let key = Keypair::generate_ed25519();
    let id = user_id(&key.public());
    User { key, id }
}

fn cert(u: &User, node: &Keypair) -> NodeCert {
    WEIRDNET.certify(&u.key, &u.id, &node.public().to_peer_id().to_string(), "phone", now_ms() - 1000).unwrap()
}

fn record(u: &User, node: &Keypair, seq: u64) -> PeerRecord {
    let addr: Multiaddr = "/ip4/203.0.113.7/udp/4747/quic-v1".parse().unwrap();
    WEIRDNET.peer_record(node, &u.key.public(), &cert(u, node), &[addr], None, seq, now_ms(), HOUR).unwrap()
}

#[test]
fn records_verify_and_tampering_does_not() {
    let (u, n) = (user(), Keypair::generate_ed25519());
    let r = record(&u, &n, 1);
    let now = now_ms();
    assert_eq!(WEIRDNET.verify_record(&r, now).unwrap(), n.public().to_peer_id());
    assert!(r.addrs[0].ends_with(&format!("/p2p/{}", n.public().to_peer_id())));
    assert_eq!(WEIRDNET.record_key(&u.id).len(), 32);

    let mut t = r.clone();
    t.addrs.push(format!("/ip4/198.51.100.1/tcp/1/p2p/{}", n.public().to_peer_id()));
    assert!(WEIRDNET.verify_record(&t, now).is_err(), "an added address breaks the signature");
    let mut t = r.clone();
    t.seq += 1;
    assert!(WEIRDNET.verify_record(&t, now).is_err());
    assert!(WEIRDNET.verify_record(&r, r.expires).is_err(), "expired");

    // another user's key under this user's id
    let mut t = r.clone();
    t.user_key = user().key.public().encode_protobuf();
    assert!(WEIRDNET.verify_record(&t, now).is_err());
    // a revoked node
    let mut c = cert(&u, &n);
    let at = now_ms();
    c.revocation = Some(WEIRDNET.revoke(&u.key, &u.id, &c.peer_id, at).unwrap());
    c.revoked_at = Some(at);
    assert!(WEIRDNET.peer_record(&n, &u.key.public(), &c, &[], None, 2, now, HOUR).is_err());
    // a node another user certified
    let other = user();
    assert!(WEIRDNET.peer_record(&n, &u.key.public(), &cert(&other, &n), &[], None, 2, now, HOUR).is_err());
    // too long-lived, or a certificate for another node
    assert!(WEIRDNET.peer_record(&n, &u.key.public(), &cert(&u, &n), &[], None, 2, now, MAX_RECORD_TTL_MS + 1).is_err());
    assert!(WEIRDNET.peer_record(&Keypair::generate_ed25519(), &u.key.public(), &cert(&u, &n), &[], None, 2, now, HOUR).is_err());
    // an address of another node
    let stranger: Multiaddr = format!("/ip4/1.2.3.4/tcp/1/p2p/{}", PeerId::random()).parse().unwrap();
    let mut t = WEIRDNET.peer_record(&n, &u.key.public(), &cert(&u, &n), &[], None, 3, now, HOUR).unwrap();
    t.addrs = vec![stranger.to_string()];
    assert!(WEIRDNET.verify_record(&t, now).is_err());

    let e = Entry::Record(r.clone());
    assert_eq!(Entry::decode(&e.encode()).unwrap(), e);
    assert!(Entry::decode(&vec![b' '; MAX_ENTRY_BYTES + 1]).is_err());
}

#[test]
fn a_higher_seq_wins_and_withdrawals_hold_until_they_expire() {
    let (u, phone, laptop) = (user(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let now = now_ms();
    let r1 = Entry::Record(record(&u, &phone, 10));
    let r2 = Entry::Record(record(&u, &laptop, 11));
    assert!(WEIRDNET.accept(None, &r1, now).is_ok());
    assert!(WEIRDNET.accept(Some(&r1), &r2, now).is_ok(), "the user's other device, later");
    assert!(WEIRDNET.accept(Some(&r2), &r1, now).is_err(), "lower seq");
    assert!(WEIRDNET.accept(Some(&r1), &r1, now).is_err(), "same seq");

    let w = WEIRDNET.withdrawal(&laptop, &u.key.public(), &cert(&u, &laptop), 12, now, MIN_WITHDRAWAL_TTL_MS).unwrap();
    let w = Entry::Withdrawn(w);
    assert!(WEIRDNET.accept(Some(&r2), &w, now).is_ok());
    assert!(WEIRDNET.accept(Some(&w), &r2, now).is_err(), "a stale republish can't bring it back");
    assert!(WEIRDNET.accept(Some(&w), &Entry::Record(record(&u, &phone, 13)), now).is_ok(), "re-hosting uses a higher seq");
    // once the withdrawal expired, it no longer blocks
    assert!(WEIRDNET.accept(Some(&w), &Entry::Record(record(&u, &phone, 5)), w.expires() + 1).is_err(), "and r expired too by then");
    // another user can't withdraw this user's record
    let mallory = user();
    let mw = WEIRDNET.withdrawal(&laptop, &mallory.key.public(), &cert(&mallory, &laptop), 99, now, MIN_WITHDRAWAL_TTL_MS).unwrap();
    assert!(WEIRDNET.accept(Some(&r2), &Entry::Withdrawn(mw), now).is_err());
    assert!(WEIRDNET.withdrawal(&laptop, &u.key.public(), &cert(&u, &laptop), 12, now, HOUR).is_err(), "too short-lived");

    match WEIRDNET.newest(&u.id, &[r1.clone(), r2.clone(), w.clone()], now) {
        Lookup::Withdrawn(x) => assert_eq!(x.seq, 12),
        other => panic!("{other:?}"),
    }
    match WEIRDNET.newest(&u.id, &[r1, r2], now) {
        Lookup::Found(x) => assert_eq!(x.seq, 11),
        other => panic!("{other:?}"),
    }
    assert_eq!(WEIRDNET.newest(&u.id, &[], now), Lookup::NotFound);
}

#[test]
fn name_bindings_round_trip() {
    let u = user();
    assert_eq!(binding_name("home.example.com."), "_weirdnet.home.example.com");
    assert_eq!(parse_binding(&binding_txt(&u.id)).unwrap(), u.id);
    assert_eq!(parse_binding(&format!("\"v=1 user={}\"", u.id)).unwrap(), u.id);
    assert!(parse_binding("v=2 user=00").is_err());
    assert!(parse_binding("v=1").is_err());
    assert!(parse_binding("v=1 user=NOTHEX").is_err());
}

#[test]
fn the_names_server_takes_only_a_nodes_own_record() {
    let (u, n) = (user(), Keypair::generate_ed25519());
    let store = MemoryNames::default();
    let e = Entry::Record(record(&u, &n, 1));
    let now = now_ms();
    assert!(matches!(serve(&WEIRDNET, &store, &PeerId::random(), NamesRequest::Register(Box::new(e.clone())), now), NamesResponse::Refused(_)));
    assert!(matches!(
        serve(&WEIRDNET, &store, &n.public().to_peer_id(), NamesRequest::Register(Box::new(e.clone())), now),
        NamesResponse::Registered
    ));
    match serve(&WEIRDNET, &store, &PeerId::random(), NamesRequest::Discover { user_id: u.id.clone() }, now) {
        NamesResponse::Found(Some(found)) => assert_eq!(*found, e),
        other => panic!("{other:?}"),
    }
    store.prune(e.expires() + 1);
    assert!(store.get(&u.id).is_none());
}

// over the in-memory transport

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello(String);

struct Greeter;
impl Handler<Hello, Hello> for Greeter {
    fn request(&self, from: &PeerId, Hello(s): Hello) -> Hello {
        Hello(format!("hello {s} from {}", crate::short_peer_id(from)))
    }
}

fn mem(listen: bool) -> NodeConfig {
    NodeConfig { listen: if listen { vec!["/memory/0".parse().unwrap()] } else { vec![] }, memory: true, ..Default::default() }
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn relay() -> (Node<Hello, Hello>, Multiaddr) {
    let cfg = NodeConfig { relay_server: true, relay_limits: RelayLimits::unlimited(), names_server: Some(Names::memory()), ..mem(true) };
    let r = Node::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(Greeter)).unwrap();
    let a = r.reachable_addrs().into_iter().find(|a| a.starts_with("/memory/")).unwrap().parse().unwrap();
    (r, a)
}

/// A phone with no listener of its own: a reservation on the relay, its record there.
fn phone(u: &User, raddr: &Multiaddr, relay: PeerId) -> (Node<Hello, Hello>, Keypair, Multiaddr) {
    let key = Keypair::generate_ed25519();
    let cfg = NodeConfig { relays: vec![raddr.clone()], ..mem(false) };
    let b = Node::start(&WEIRDNET, key.clone(), cfg, Arc::new(Greeter)).unwrap();
    wait("reservation", || b.status().reservations.contains(&relay.to_string()));
    let circuit: Multiaddr = format!("{raddr}/p2p-circuit/p2p/{}", b.peer_id()).parse().unwrap();
    let _ = u;
    (b, key, circuit)
}

#[test]
fn a_phone_registers_on_its_home_relay_and_is_reached_by_user_id() {
    let (r, raddr) = relay();
    let u = user();
    let (b, bkey, circuit) = phone(&u, &raddr, r.peer_id());
    let rec = WEIRDNET.peer_record(&bkey, &u.key.public(), &cert(&u, &bkey), &[circuit], Some(&raddr), now_ms() as u64, now_ms(), HOUR).unwrap();
    assert_eq!(b.register_everywhere(&Entry::Record(rec.clone())), 1);

    // a stranger who knows only the user id and a names server
    let a = Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { names_servers: vec![raddr.clone()], ..mem(false) }, Arc::new(Greeter))
        .unwrap();
    match a.lookup(&u.id) {
        Lookup::Found(found) => assert_eq!(found, rec),
        other => panic!("{other:?}"),
    }
    let (peer, Hello(answer)) = a.request_user(&u.id, Hello("ann".into())).unwrap();
    assert_eq!(peer, b.peer_id());
    assert!(answer.starts_with("hello ann"));

    // withdrawn: the lookup says so
    let w = WEIRDNET.withdrawal(&bkey, &u.key.public(), &cert(&u, &bkey), rec.seq + 1, now_ms(), MIN_WITHDRAWAL_TTL_MS).unwrap();
    assert_eq!(b.register_everywhere(&Entry::Withdrawn(w)), 1);
    assert!(matches!(a.lookup(&u.id), Lookup::Withdrawn(_)));
    assert!(a.request_user(&u.id, Hello("ann".into())).is_err());
    // and the old record can't be registered again
    assert!(b.register(r.peer_id(), std::slice::from_ref(&raddr), Entry::Record(rec)).is_err());
}

#[test]
fn key_only_dialing_reaches_a_peer_through_a_shared_relay() {
    let (r, raddr) = relay();
    let u = user();
    let (b, _, _) = phone(&u, &raddr, r.peer_id());
    let a = Node::start(&WEIRDNET, Keypair::generate_ed25519(), NodeConfig { names_servers: vec![raddr.clone()], ..mem(false) }, Arc::new(Greeter))
        .unwrap();
    let Hello(answer) = a.request_key(b.peer_id(), Hello("by key".into())).unwrap();
    assert!(answer.starts_with("hello by key"));
}

#[test]
fn records_in_the_dht_are_checked_superseded_and_withdrawn() {
    let (r, raddr) = relay();
    let u = user();
    let boot = || NodeConfig { bootstrap: vec![raddr.clone()], ..mem(false) };
    let (bkey, ckey) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let b = Node::start(&WEIRDNET, bkey.clone(), boot(), Arc::new(Greeter)).unwrap();
    let c = Node::start(&WEIRDNET, ckey, boot(), Arc::new(Greeter)).unwrap();
    wait("bootstrap", || b.status().connected.contains(&r.peer_id().to_string()) && c.status().connected.contains(&r.peer_id().to_string()));

    let rec = record(&u, &bkey, 100);
    b.put_entry(Entry::Record(rec.clone())).unwrap();
    match WEIRDNET.newest(&u.id, &c.get_entries(&u.id).unwrap(), now_ms()) {
        Lookup::Found(found) => assert_eq!(found, rec),
        other => panic!("{other:?}"),
    }
    // a forged record (another node's key under this user) is refused by the storing node
    let mut forged = record(&u, &bkey, 200);
    forged.addrs = vec![format!("/ip4/6.6.6.6/tcp/1/p2p/{}", bkey.public().to_peer_id())];
    assert!(c.put_entry(Entry::Record(forged)).is_err(), "checked locally first");

    let w = WEIRDNET.withdrawal(&bkey, &u.key.public(), &cert(&u, &bkey), 101, now_ms(), MIN_WITHDRAWAL_TTL_MS).unwrap();
    b.put_entry(Entry::Withdrawn(w)).unwrap();
    assert!(matches!(WEIRDNET.newest(&u.id, &c.get_entries(&u.id).unwrap(), now_ms()), Lookup::Withdrawn(_)));
    assert!(matches!(c.lookup(&u.id), Lookup::Withdrawn(_)));
    // the relay, a storing node, holds the withdrawal: a stale republish is refused there,
    // so a node that never saw the record finds only the withdrawal
    let _ = c.put_entry(Entry::Record(rec));
    let d = Node::start(&WEIRDNET, Keypair::generate_ed25519(), boot(), Arc::new(Greeter)).unwrap();
    wait("bootstrap", || d.status().connected.contains(&r.peer_id().to_string()));
    let seen = d.get_entries(&u.id).unwrap();
    assert!(!seen.is_empty() && seen.iter().all(|e| e.seq() >= 101), "{seen:?}");
    assert!(matches!(d.lookup(&u.id), Lookup::Withdrawn(_)));
}

#[test]
fn a_node_can_bootstrap_from_and_reserve_on_the_same_relay() {
    let (r, raddr) = relay();
    let cfg = NodeConfig { relays: vec![raddr.clone()], bootstrap: vec![raddr.clone()], ..mem(false) };
    let b = Node::<Hello, Hello>::start(&WEIRDNET, Keypair::generate_ed25519(), cfg, Arc::new(Greeter)).unwrap();
    wait("reservation", || b.status().reservations.contains(&r.peer_id().to_string()));
}
