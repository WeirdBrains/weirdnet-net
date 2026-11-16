# Security notes for weirdnet-net

This is a description of the boundaries, reviewed while extracting the crate. It is not an
audit; nobody has audited this crate.

What the crate enforces:

- Offers and answers are signed with the node's Ed25519 key under the profile's domains; a
  changed field, a key that is not the peer id's, a wrong version, an unknown scope or an
  expired offer is refused. An answer is bound to the offer's hash, and the node that made
  an offer can't answer it.
- Both sides derive the exchange key and the short code from the X25519 secret and the
  transcript of both signed messages (in `weirdnet-keys`). Only comparing the short code or
  fingerprint out of band rules out a man in the middle; the crate can't do that for you.
- Sealed messages (XChaCha20-Poly1305, in `weirdnet-keys`) bind the exchange id and both
  peer ids in order, so a message can't be moved to another exchange or turned around.
  `sealed::serve` opens only for a known, active exchange whose peer is the sender Noise
  authenticated.
- Certificates and revocations are checked against the user key; a revocation time without
  its signature fails. Cards must certify the very node that sends them.
- Invitation automation (`invite`): a delivered offer is kept only if the node that signed
  it is the Noise-authenticated sender, and after the host's `admit`; at most
  `Host::max_incoming` wait. It is answered on arrival only when the host's `decide` says so
  (the default host policy answers nothing by itself). An answer completes only an offer
  this node made and still has open, and only if signed by the peer it was sent to; only an
  offer's offerer may poll it. When both nodes offered at once and this one answers, its own
  offers of that kind are ended. A node using the name of another node whose key is pinned
  is flagged, and a name shared by several nodes resolves to the pinned one; the flag is a
  warning for the application to show, not a refusal.
- Profiles don't mix: tokens, signatures, sealed messages, certificates and the sync key of
  one profile don't verify or open under another, and nodes on different protocol ids don't
  talk.

What the crate leaves to the application:

- Whether to answer an offer on the spot (`decide`), which offers to let in (`admit`), and
  any bookkeeping of its own (`kept`, `completed`, `poll`).
- Who may do what over an exchange, which users are trusted, what an invitation grants,
  which offers to accept, and every limit on what peers may store or ask for.
- Keeping secrets: node identities, exchange keys and user keypairs are handed to the
  application's store and should live encrypted at rest.
- A link grant hands the user's signing key to the node being linked (sealed under the link
  exchange); that is by design and only for the user's own nodes.

Tested over libp2p's in-memory transport (real Noise, Yamux and request-response), including
a request answered through a relay circuit under the default and unlimited limits; TCP and
QUIC sockets, hole punching, mDNS and AutoNAT are not exercised by the tests.

Names: a storing node (names server or DHT peer) keeps an entry only if it verifies (node
signature, the user's unrevoked certificate for that node, ids matching the keys, an expiry
within a day for records and one day to a week for withdrawals, every address ending in the
node's peer id) and its `seq` is above the unexpired entry it holds. A names server takes a
record or withdrawal only from the node that signed it. Kademlia runs with
`StoreInserts::FilterBoth`: other values are refused, and only the relay key is accepted as
a provider key. No DHT can force deletion: a hostile node can keep serving an old record,
which lookups drop once expired or outranked, and a stale record leads to a failed dial,
not a wrong peer (dials are Noise-authenticated to the record's peer id). Records reveal
the user id and addresses to anyone who looks them up; private, blinded locator records are
not implemented yet. There is no cap on how many entries a names server holds; entries
expire and are pruned every minute.

Relay limits: `RelayLimits::unlimited()` removes every reservation, circuit, time and byte
cap and libp2p's rate limiters, so a relay running it carries whatever its clients send.
Bandwidth and abuse controls are the operator's.

Not verified: an audit, fuzzing, Windows, macOS, iOS and Android, an MSRV run and minimal
dependency versions. Requests up to 8 MiB and answers up to 256 MiB are accepted, with a
60-second timeout.
