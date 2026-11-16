# Changelog

All notable changes to weirdnet-net are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Streams with no size cap, backpressure and per-protocol limits, for any number of apps' protocols on one node.
- Streams move from a relay to a direct connection and back without losing data.
- Request and response caps and the request timeout are node settings.
- Node::connect, Node::paths and Node::drop_path.

### Fixed

- A request or dial through a relay no longer fails while the node is still connecting to that relay.

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

[Unreleased]: https://github.com/WeirdBrains/weirdnet-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/WeirdBrains/weirdnet-net/releases/tag/v0.2.0
