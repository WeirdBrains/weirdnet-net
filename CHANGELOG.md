# Changelog

All notable changes to weirdnet-net are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). The next release is 0.2.0: the changes below
break the 0.1 API.

## [Unreleased]

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
