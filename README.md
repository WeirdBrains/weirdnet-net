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
  `NodeConfig::discovery` (`DiscoveryMode`, enabled by default) turns peer finding on or
  off: disabled, the node does not run mDNS or Kademlia, but still listens, uses configured
  relays, dials [`PeerHint`]s (`NodeConfig::peers`, `Node::add_peer`) and serves apps and
  content to peers it is connected to. A hint is an address book entry, not trust; the
  application's roster and `NodeCert` decide that. The application persists the list
  (`encode_peers` / `decode_peers`).
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
- `app`: app calls, HTTP-like requests between nodes with streamed bodies (Morph's
  `weirdnet-<app>://` URLs). A node serves an app with `Node::serve_app("notes", handler)`
  (an `AppHandler`, or a closure `|peer, AppRequest| async { Ok(AppResponse) }`) and peers
  learn through identify which apps it serves (`Node::peer_apps`). A caller finds the peers
  serving an app for a peer id, a user id or a name bound by `_weirdnet.<name>` TXT
  (`Node::resolve_app(app, locator)`: names servers, then the DHT), and calls one with
  `Node::app_call(peer, AppRequest, timeout)`: directly or by hole punching first, then
  through the relay circuits in the peer's record. One stream per call on `/weirdnet/app/1`:
  a CBOR head (`v`, `app`, `method`, `path`, `headers`, varint-length-prefixed), body frames
  ending with an empty one, and a CBOR response head (`status` and `headers`, or `error` and
  `message`). Bodies stream both ways with backpressure and no size cap unless
  `NodeConfig::app_body_max` sets one; heads are capped at `app_header_max` (16 KiB) and a
  call that goes `app_idle_timeout` (60 s) without a byte ends. Dropping the call or the
  response body resets the stream, which stops the server's handler. Errors are `AppError`:
  `NotFound`, `NoHandler`, `Unreachable`, `TimedOut`, `Refused`, `TooLarge`, `Protocol`. A node
  that serves an app keeps its relay reservations, even paused, and `add_relay` dials every
  address of a relay at once (TCP, QUIC, WSS) and reserves on whichever connects.
  `examples/app_call.rs` serves and calls an app over TCP.
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
- `addr::dnsaddr_record(name, port, peer)`: the `_dnsaddr.<name>` TXT record
  (`dnsaddr=/dns/<name>/tcp/<port>/p2p/<peer>`) for Grindvakt or any DNS provider to write, and
  `dnsaddr_dial(name, peer)` to reach the node by it. `NodeConfig::dns_servers` picks the
  resolver; without it the system's is used, or public resolvers where there is none (Android).
- `content`: files by content. `add_reader`/`add_bytes` split a file into content-defined
  chunks (an rsync-style rolling checksum, 16 to 256 KiB) in the application's `ChunkStore`
  (`MemoryStore`, `DirStore` or its own) and return a `FileIndex`; the file's root is the
  BLAKE3 hash of that index, and an edit changes only the chunks around it. A `Manifest` maps
  paths to roots, sizes and app metadata, versioned and signed by a user key, with roots it
  revokes. `serve(&node, store, allow)` answers `/weirdnet/content/1` for what `allow` lets
  each peer have; `fetch` (or `fetch_async`) gets a root's index and the chunks the store
  lacks from one or more `Source`s, checking every hash, so a newer version moves only its
  changed chunks and an interrupted fetch picks up where it stopped. `fetch_range` gets only
  the chunks under a byte range and `read_range` reads it. Public content goes in the DHT
  with `Node::provide(&provider_key(&root))` and is found with `Node::providers`.
- `member` and `join`: lasting membership. A `Membership` (resource, member's user id, a
  role id the application interprets, issued and optional expiry times) is signed by the
  owner's user key; a `MemberRevocation` voids a user's memberships of a resource issued up
  to a time, and travels in the content `Manifest` (`member_revocations`) or any way the app
  likes, collected in `Revocations`. A member's node presents the membership with its user's
  card on a stream (`present`); the host checks it is valid, unrevoked and the card's
  certificate is for the very node speaking (`read_presented`, `check_presented`). To ask for
  membership, a user signs a `JoinRequest` and sends it on `/weirdnet/join/1`
  (`request_join`); `serve_joins` checks it, applies per-user and per-node rate limits and a
  cap on pending requests, and keeps it in the app's `JoinQueue`. The owner `approve`s (a
  membership) or `deny`s (a signed `Denial`), and sending the same request again fetches the
  answer.
- `names`: where a peer is now. A `PeerRecord` (addresses and relay circuits, home relay,
  `seq`, expiry of at most a day) is signed by the node key and chained to the user key by
  the node's certificate; a `Withdrawal`, signed by one of the user's nodes with a higher
  `seq`, removes it and holds until it expires. Records go to the home relay's names server
  (`/weirdnet/names/1`: `Node::register`, `discover`, `lookup`; a node serves it with
  `NodeConfig::names_server`) and, while the device hosts something, to the Kademlia DHT
  under `SHA-256("weirdnet/peer/" + user id)` (`put_entry`, `get_entries`), where every
  storing node runs `Profile::accept`: valid signature, unrevoked certificate, unexpired,
  higher `seq` wins. `_weirdnet.<name> TXT "v=1 user=<id>"` binds a domain to a user
  (`binding_txt`, `parse_binding`). `EntryCache` is what a trusted peer keeps of records
  pushed to it, by the same rule.
- `locator`: private sites found only by those trusted with them. A site's `LocatorKeys`
  (an Ed25519 locator key and a secret) seal its peer record into a `LocatorRecord` under a
  DHT key that changes every UTC day (`SHA-256("weirdnet/locator/v1" ‖ key ‖ day)`), signed
  by the locator key, never the user key. Storing nodes check the signature, the day, the
  expiry and `seq` and learn nothing about the owner, the site or the addresses
  (`Node::put_locator`); holders of the keys fetch today's and yesterday's
  (`Node::get_locators`) and open them (`LocatorKeys::open`, `newest_open`).
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

`harness/netns.sh` runs nodes in Linux network namespaces behind iptables NAT routers
(`examples/netns_node.rs`), and CI runs it: reservations on a relay, a stream that starts
on the relay and moves to a hole-punched direct path across two NATs, a symmetric NAT that
stays on the relay, QUIC to the relay, mDNS on a LAN, and AutoNAT verdicts, each with a
content fetch. Run it with `sudo harness/netns.sh target/debug/examples/netns_node`.

Every identifier on the wire or under a signature comes from a `Profile`. `WEIRDNET` is the
default (`/weirdnet/net/1`, `wnet-x1-offer:`, port 4747 and so on). An application with nodes
already in the field passes its own profile with the values those nodes use, so nothing
changes for them.

Invitation and answer links go on the app's own scheme, `weirdnet-<app>://` (for example
`weirdnet-morph://join/`): set `join_link`, `answer_link` and `link_mark` in the app's
profile, as below. The bare `weirdnet://` scheme is reserved for internal Weirdnet messages;
it is not registered with the OS and nothing routes through it.

Key cryptography is not here: every derivation, seal and open goes through `weirdnet-keys`,
and key backups and recovery stay there. Shard blobs and backups cross the network as opaque
bytes. See `SECURITY.md` for the boundaries and what has not been checked.

```rust
use weirdnet_net::{WEIRDNET, Keypair, Profile, exchange::Token, profile::invite_scope};

// The Weirdnet profile, with invitation links on the app's own scheme.
const GARDEN: Profile = Profile {
    join_link: "weirdnet-garden://join/",
    answer_link: "weirdnet-garden://answer/",
    link_mark: "weirdnet-garden://",
    ..WEIRDNET
};

let (anna, ben) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
let p = &GARDEN;
let (offer, secret) = p.offer(&anna, "anna", vec![], invite_scope("garden", "member"), 0, 60_000).unwrap();
let link = p.link(&p.offer_token(&offer).unwrap());
assert!(link.starts_with("weirdnet-garden://join/"));
let Token::Offer(seen) = p.parse_token(&link).unwrap() else { unreachable!() };
p.verify_offer(&seen, 1).unwrap();
let (answer, on_ben) = p.answer(&ben, &seen, "ben", vec![], 1).unwrap();
let on_anna = p.complete(&answer, &offer, &secret[..]).unwrap();
assert_eq!(on_anna.short_code, on_ben.short_code);
```
