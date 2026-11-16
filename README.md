# weirdnet-net

Peer-to-peer networking for applications that keep their own data: a libp2p node, key
exchanges with invitation tokens and links, sealed messaging over those exchanges, node
identities, and user certificates and cards. The application brings its own request and
response types, its own storage and its own policy; the crate brings the wire.

- `node`: a `Node<Q, R>` over TCP and QUIC (or an in-memory transport for tests) with Noise
  and Yamux, mDNS, Kademlia, identify, ping, a relay client and an opt-in relay server,
  DCUtR hole punching and AutoNAT. The swarm runs on its own thread; the handle is blocking.
  Requests are the application's `Q`, answers its `R` (CBOR), answered by a `Handler`.
  `NodeConfig::relay_limits` sets what the relay server allows: `RelayLimits::default()`
  keeps libp2p's (2-minute, 128 KiB circuits, enough for hole punching and small requests),
  `RelayLimits::unlimited()` caps nothing, so circuits carry data.
  Key-only dialing: `request_key(peer, …)` finds a peer by its key alone (the DHT, then
  circuits through this node's relays and names servers); `request_user(user_id, …)` looks
  the user's record up and dials it.
  Request and response caps and the request timeout are `NodeConfig` settings
  (`request_max`, `response_max`, `request_timeout`; 8 MiB, 256 MiB and 60 s by default).
- `stream`: byte streams with no size cap. An application accepts its own protocol ids
  (`Node::accept_streams("/myapp/sync/1", Limits)`) and opens them
  (`Node::open_stream(peer, addrs, protocol, Limits)`); one node carries any number of
  apps' protocols, and a protocol nobody accepts is refused. A `Stream` is `AsyncRead` +
  `AsyncWrite` (any executor) and blocking `Read` + `Write`, with backpressure (a window of
  unacknowledged bytes) and per-protocol `Limits` (window, frame size, open streams, backlog,
  idle reset, how long to wait for a path). Streams move between paths without losing or
  repeating a byte: when a direct connection comes up (hole punching or a dial) the opener
  moves its relayed streams there, and when a connection goes away the stream carries on over
  the path that is left (relays are kept warm while streams are open). `Stream::path`,
  `Stream::moves`, `Node::paths` and `Node::drop_path` show and steer that.
- `events`: what the node is doing. `Node::events()` is a stream (or `next_timeout`) of
  listeners, external addresses, connections with their path, relay reservations made and
  lost, and the NAT verdict; `Node::watch_status()` waits for the `Status` to change. Apps
  call `Node::pause` and `Node::resume` as they go to the background and back, and
  `Node::network_changed` when the device changes networks. Lost reservations are asked for
  again with backoff. `request_async`, `connect_async` and `dial_async` suit async callers on
  any executor. CI checks Android (aarch64-linux-android) and iOS (aarch64-apple-ios) builds and
  runs the tests on Linux, macOS and Windows.
- `wss`: WebSocket over TLS for networks that only let HTTPS out. Every node dials
  `/dns/<name>/tcp/443/tls/ws/p2p/<id>` (or `/wss`) trusting the web PKI; with
  `NodeConfig::wss` set to a `WssTls` (`from_pem_files("fullchain.pem", "privkey.pem")`) a node
  also listens on `/ip4/0.0.0.0/tcp/443/tls/ws`. Noise and Yamux run inside, so peer ids are
  checked as on TCP. A renewed certificate takes a restart for now.
- `ingress`: public HTTPS for hosts without a public address, by SNI passthrough. An
  ingress peer (`Ingress::start(&node, IngressConfig { https: 0.0.0.0:443, http: 0.0.0.0:80, .. },
  binding)`) reads only the ClientHello's server name, finds the host that registered it and
  splices the bytes over a `/weirdnet/ingress/1` stream behind a PROXY v2 header (client
  address, name). TLS ends on the host (`Node::accept_ingress`); the ingress holds no key. A
  host registers with `Node::register_ingress` and an `IngressGrant` signed by its user key;
  the ingress checks the grant, the user's certificate for the node and the DNS binding
  `_weirdnet.<name> TXT "v=1 user=<id>"` (`DnsBinding`). Port 80 forwards ACME HTTP-01 for
  registered names and redirects the rest to HTTPS. `Ingress::revoke(name)` stops a site on
  this device and `set_enabled(false)` stops forwarding altogether. No HTTP/3 passthrough
  and no per-grant byte limits yet.
- `names`: where a peer is now. A `PeerRecord` (addresses and relay circuits, home relay,
  `seq`, expiry of at most a day) is signed by the node key and chained to the user key by
  the node's certificate; a `Withdrawal`, signed by one of the user's nodes with a higher
  `seq`, removes it and holds until it expires. Records go to the home relay's names server
  (`/weirdnet/names/1`: `Node::register`, `discover`, `lookup`; a node serves it with
  `NodeConfig::names_server`) and, while the device hosts something, to the Kademlia DHT
  under `SHA-256("weirdnet/peer/" + user id)` (`put_entry`, `get_entries`), where every
  storing node runs `Profile::accept`: valid signature, unrevoked certificate, unexpired,
  higher `seq` wins. `_weirdnet.<name> TXT "v=1 user=<id>"` binds a domain to a user
  (`binding_txt`, `parse_binding`).
- `exchange`: signed offers and answers (Ed25519 node keys, fresh X25519 keys), the derived
  exchange key, a ten-digit short code and a fingerprint to compare out of band, tokens and
  links (invitations), scopes with an expiry, and sealed messages bound to the exchange and
  direction.
- `sealed`: send a sealed request through the application's envelope and open the answer
  (`call`), and answer one only for the exchange's own, Noise-authenticated peer (`serve`).
- `invite`: invitation automation over the application's records (`Host`) and messages
  (`Ask`, `Say`): `connect` (hello, then an offer delivered and answered on the spot or kept
  for the owner), answering on arrival when the host's `decide` says so, `poll` and
  `settle` for kept offers and undelivered answers, crossing offers settled on one exchange,
  trust on first use (`known`, `pinned`, `impostor`, names resolving to the pinned node),
  relay addresses for a peer and the addresses fit for invite links.
- `identity`, `user`, `sync`, `shard`, `addr`: node identities through an `IdentityStore`,
  user certificates, revocations, cards and link grants, the linked-node sync key, dark-shard
  blobs as custodians carry them, and address helpers.

Every identifier on the wire or under a signature comes from a `Profile`. `WEIRDNET` is the
default (`/weirdnet/net/1`, `wnet-x1-offer:`, `weirdnet://join/`, port 4747 and so on). An
application with nodes already in the field passes its own profile with the values those
nodes use, so nothing changes for them.

Key cryptography is not here: every derivation, seal and open goes through `weirdnet-keys`,
and key backups and recovery stay there. Shard blobs and backups cross the network as opaque
bytes. See `SECURITY.md` for the boundaries and what has not been checked.

```rust
use weirdnet_net::{WEIRDNET, Keypair, exchange::Token, profile::invite_scope};

let (anna, ben) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
let p = &WEIRDNET;
let (offer, secret) = p.offer(&anna, "anna", vec![], invite_scope("garden", "member"), 0, 60_000).unwrap();
let link = p.link(&p.offer_token(&offer).unwrap());
let Token::Offer(seen) = p.parse_token(&link).unwrap() else { unreachable!() };
p.verify_offer(&seen, 1).unwrap();
let (answer, on_ben) = p.answer(&ben, &seen, "ben", vec![], 1).unwrap();
let on_anna = p.complete(&answer, &offer, &secret[..]).unwrap();
assert_eq!(on_anna.short_code, on_ben.short_code);
```
