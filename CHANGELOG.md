# Changelog

All notable changes to weirdnet-net are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.1] - 2026-11-19

### Added

- Android: `android::init_context` and the `android_context_init!` macro, which exports an app's JNI init method, so every Weirdnet Android app sets up `ndk-context` (needed by hickory-resolver's system DNS) the same way instead of carrying its own copy. The macro expands to nothing on other targets.

## [0.8.0] - 2026-11-18

### Changed

- Breaking (wire): requests and responses (`Node<Q, R>` and the names protocol) are encoded
  by the new `wire` codec. Every byte field (`Vec<u8>`, `[u8; N]`, any non-empty sequence
  of `u8`) is one CBOR byte string (major type 2) instead of an array of integers, with or
  without `serde_bytes`; everything else is laid out as before. A 240 KiB byte field takes
  245,771 bytes on the wire instead of 468,352. Nodes on 0.8 and earlier versions cannot
  decode each other's requests.
- Breaking (wire): `WEIRDNET` uses `/weirdnet/net/2` and `/weirdnet/names/2` (were `/1`),
  so a 0.8 node and an older one fail to negotiate instead of failing to decode.

### Added

- `wire::{to_vec, from_slice, Codec}`. Reading refuses truncated input, trailing bytes,
  lengths past the end, indefinite lengths, tags, and nesting deeper than `MAX_DEPTH`.

### Migration

- Upgrade every node that talks to each other together. Apps with their own `Profile` bump
  its `protocol` and `names` ids (for example `/myapp/net/1` → `/myapp/net/2`) in the same
  release.
- Types that already used `serde_bytes` or a bytes visitor keep working. A `PeerId` (or
  another type that only accepts `visit_bytes`) inside an internally tagged, adjacently
  tagged or untagged enum, or a `flatten`ed struct, cannot be read: carry it as a string
  there.
- Nothing under a signature changes: certificates, records and tokens are signed over JSON.

## [0.7.0] - 2026-11-18

### Changed

- Breaking: `WEIRDNET` has no link scheme (`join_link`, `answer_link` and `link_mark` are
  empty), so the library never makes bare `weirdnet://join/` or `weirdnet://answer/` links.
- Breaking: `Profile::link` returns `Result<String>`. It fails when the profile has no link
  scheme or uses the reserved `weirdnet://`.
- `parse_token` refuses links on `weirdnet://` (`RESERVED_LINK_SCHEME`), in any profile.

### Migration

- Apps that show invitation links set their own scheme in their profile:
  `Profile { join_link: "weirdnet-<app>://join/", answer_link: "weirdnet-<app>://answer/",
  link_mark: "weirdnet-<app>://", ..WEIRDNET }`, and handle the `Result` from `link`.
  Tokens (`wnet-x1-offer:…`) are unchanged and still parse with `WEIRDNET`.

## [0.6.0] - 2026-11-17

### Added

- `DiscoveryMode` on `NodeConfig` (`Enabled` by default). `Disabled` turns off mDNS and
  Kademlia (bootstrap, advertising, and learning peers from identify). Configured relays,
  listen, request-response, app calls, content streams and manual peers still work. DHT
  APIs (`provide`, `find_peer`, `put_entry`, locators, and the rest) return
  "peer discovery is disabled".
- Manual peers: `PeerHint`, `NodeConfig::peers`, `Node::add_peer` / `remove_peer` /
  `peers`, and `encode_peers` / `decode_peers` for the application to persist. Address
  hints are not trust; `NodeCert` and the application's roster authorize a peer.

### Changed

- `Status` reports whether discovery is on (`discovery: bool`).

## [0.5.0] - 2026-11-17

### Added

- App calls: Node::serve_app, Node::resolve_app and Node::app_call, with streamed bodies on `/weirdnet/app/1`.
- AppError, AppRequest, AppResponse, AppBody and AppHandler.
- Peers announce the apps they serve through identify; Node::peer_apps reads them.
- `app_header_max`, `app_body_max` and `app_idle_timeout` node settings.
- An app call example.

### Changed

- add_relay dials every address of a relay at once and reserves on the first that connects.
- A node that serves an app keeps its relay reservations while paused.

## [0.4.0] - 2026-11-16

### Added

- Locator records for private sites: sealed, signed by a locator key, under a daily DHT key.
- EntryCache for peer records pushed to trusted peers.
- Sealed streams: stream frames sealed with the exchange key, in order, with a sealed end.

## [0.3.0] - 2026-11-16

### Added

- Streams with no size cap, backpressure and per-protocol limits, for any number of apps' protocols on one node.
- Streams move from a relay to a direct connection and back without losing data.
- Request and response caps and the request timeout are node settings.
- Node::connect, Node::paths and Node::drop_path.
- An event stream and a status watch: listeners, addresses, connections, reservations and NAT changes.
- Node::pause, Node::resume and Node::network_changed for app lifecycles and network moves.
- Async request, connect and dial.
- CI builds for Android and iOS and tests on macOS and Windows.
- WebSocket over TLS: dial `/tls/ws` and `/wss` addresses, and listen on them with a certificate. A DNS name is the TLS server name, so certificates are checked against it.
- SNI-passthrough ingress: signed grants, DNS-bound names, PROXY v2 headers, HTTP-01 on port 80, per-site revocation.
- Ingress names served on the device itself go to a local listener, so a relay's own WSS shares port 443.
- dnsaddr_record, dnsaddr_txt and dnsaddr_dial for `/dnsaddr` names, and a DNS servers setting.
- Content: content-defined chunks, BLAKE3 roots, signed manifests and chunk stores.
- Fetch files from one or more peers, by delta, by byte range, resuming after interruption.
- Node::provide, Node::stop_providing and Node::providers for content in the DHT.
- Memberships with roles, signed by the resource owner, and their revocations.
- Presenting a membership on a stream, checked against the sending node.
- Requests to join: signed requests, approvals and denials, rate limits and a host queue.
- A multi-host network harness in CI: NAT hole punching, relays, QUIC, mDNS and AutoNAT.

### Fixed

- A request or dial through a relay no longer fails while the node is still connecting to that relay.
- A relay reservation that is lost is asked for again.
- Dropping a stream ends it after what was written instead of resetting it.
- Nodes start where the system has no resolver configuration to read, as on Android.

## [0.2.0] - 2026-11-16

### Added

- Relay limits for nodes that relay, with an unlimited preset.
- Signed peer records and withdrawals for finding a user's devices.
- Names (rendezvous) protocol, client and server.
- DHT records are checked before they are stored.
- Dialing a peer by its key or user id alone.

### Fixed

- Relay reservations are made when a relay is also the bootstrap node.
- Stuck relay reservations are retried.

## [0.1.0] - 2026-11-11

### Added

- First release, extracted from Muninn: the Weirdnet libp2p node with identities, Kademlia,
  relays, hole punching and request-response protocols.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/WeirdBrains/weirdnet-net/releases/tag/v0.2.0
