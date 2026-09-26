# Changelog

All notable changes to this workspace's two published crates —
[`macula-rust`](https://crates.io/crates/macula-rust) (the core SDK) and
[`macula-rust-ffi`](https://crates.io/crates/macula-rust-ffi) (its UniFFI
Kotlin/Swift bindings) — are documented here, in two sections below. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
neither crate yet promises strict [SemVer](https://semver.org/) stability
(pre-1.0), so a minor version bump may include a small breaking change where
one was the right call. The two crates are versioned independently (they
always have been, even before either was published) — a given date's work
usually touches both, but their version numbers don't move in lockstep.

## macula-rust

### [0.4.0] - Unreleased

The macula 12 wire. **Breaking throughout**: a 0.3 node cannot reach a
macula 12 station, and nothing of the 0.3 API carries over. See the README's
"Coming from 0.3 and earlier".

#### Added

- `node_key::NodeKey`: macula 12 identities, ML-DSA-87 (`pq_pure`) or the
  LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512 (`pq_hybrid`, the fleet's),
  RSA-PSS-4096 from aws-lc-rs. Node and key ids, the admission puzzle
  (difficulty 8), owner-only key files in the seed form, the platform secure
  store through `keystore::KeyStore`, and `load_or_create`. The composite is
  held to the draft's own vector, and signatures crossed both ways with macula
  12.8.0 (`scripts/cross-verify-macula.sh`).
- `cbor`: macula 12's decoding rule v1 (depth 64, 131,072 elements, integers
  within ±2^63, text or integer map keys, no duplicates, finite floats, `null`
  the only simple value), with its refusal reasons.
- `binding`, `signed_object`: TLS and CONNECT bindings, status statements, and
  signed and held objects.
- `transport`: QUIC on macula-pqc 0.3, ML-KEM hybrid key exchange with the
  AES-256 Initial suite, every station pinned by its node_id through its TLS
  binding.
- `handshake`: the v4 handshake (opener, challenge, CONNECT with its member
  endorsement, HELLO, status).
- `frame`: version-2 frames: signed requests, replies, relay errors,
  publications and stream frames, and neighbour signatures with their seq in
  pq_hybrid.
- `record`: the DHT's records and storage keys, D25 authorization (a realm's
  org directory and an org's delegation) and a node's own namespace
  `~<node_id>/<name>`.
- `statement_issuer`: the CONNECT key bound to the identity key, its status
  statement reissued every 15 minutes, and the key rotated every 5 days.
- `station_link::Link`: one station, ported from macula-go v0.12.0's
  `stationlink`. Status statements both ways, a liveness probe, calls, the
  DHT, pubsub with per-node dedup, serving with request admission, and
  streaming sessions released on every path.
- `pool::Pool`: a node's links, ported from macula-go v0.12.0's `pool`. Pinned
  seeds redialed and given back their subscriptions and served procedures.
  Calls and streams reach a provider at its own station, trusted only under
  the pinned realm key. Publications are signed once, and records go through
  the pool.
- Tests against macula-go's in-process stations (`tests/teststation`, built by
  `scripts/build-teststation.sh`, which CI runs), and `tests/live.rs` against
  one real station, ignored unless asked.
- Examples: `quickstart`, `serve`, `publish_subscribe`.

#### Removed

- The 10.x wire and everything on it: `identity::KeyPair` (Ed25519),
  `connection::Session` and its telemetry facts, the 10.x `frame`, `dht`,
  `stream` and `pool`, `direct_dial`, `cert`, `cert_chain`, `ucan`, `bolt4`,
  `content` and `manifest`, and WebPki trust.
- `plans/`: the 10.x wire spec and leak survey, which describe code that is
  gone.

#### Changed

- `rust-version` is 1.89, the least the dependencies build with.
- `Cargo.lock` is committed and CI tests with `--locked`.

### [0.3.0] - 2026-09-05

#### Added

- **`pool` module: opt-in multi-station connection pool.** This crate had no
  concept of holding more than one connection at a time before this —
  `Pool::connect(seeds, trust, identity, options)` now dials several
  `Session`s concurrently and gives `Pool::call`/`Pool::publish` a choice of
  which connected one to use. Same station-discovery/link-rotation design
  already shipped in `macula-go` (v0.7.0) and `macula-dotnet` (v0.4.0), built
  from scratch here rather than ported, since no pool existed to extend:
  - `LinkSelection` (`Auto`/`FirstSuccess`/`Random`) orders `call`/`publish`'s
    connected-links list before their own first-match/`replication_factor`
    logic runs. `Auto` (the default) resolves to `FirstSuccess` when
    discovery is off (zero behavior change for any existing single-`Session`
    usage of this crate) or `Random` when it's on.
  - `StationDiscoveryOptions` (opt-in, off by default): resolves
    `hecate_stations.list_stations`'s realm via a DHT lookup and additively
    adds links for what it finds, capped at `max_links`, no removal path for
    a station simply missing from a later refresh. A discovery-added link
    (never a bootstrap seed) that fails to dial 5 times in a row gives up
    and frees its own slot for a different candidate at the next refresh —
    an exception go's and dotnet's ports don't have.
  - **Call/Publish only — Subscribe is deliberately not pooled.** `Session`'s
    control stream can't safely serve an in-flight Call's response-wait and
    an ongoing Subscribe EVENT loop at once; a caller needing Subscribe
    still uses the existing bare `Session::subscribe`/`run_subscriber`
    directly, unpooled, exactly as before this module existed.
  - Per-link trust selection: a discovered station with no `hostname` (only
    a bare-IP `host_advertised`) but a `node_id` dials under
    `Trust::Pinned(node_id)` instead of being skipped outright, closing a
    real gap the go/dotnet ports still carry (they skip every hostname-less
    row under `WebPki`, which can never validate a bare IP). `hostname`
    still wins unconditionally whenever present, so a normal
    Let's-Encrypt-backed station always dials `WebPki` regardless of
    whether it also has a `node_id` — checked explicitly against a live-
    verified precedent (`macula-cam2me`'s Android client) that got this
    priority order wrong for the common case before this crate's own design
    was finalized.
  - Verified against the real production mesh fleet, not just unit tests:
    single-seed connect+call, discovery finding and connecting additional
    real stations, `Random` selection actually spreading calls across two
    independently-dialed stations.
  - Two rounds of adversarial review against the full diff found and fixed:
    a `StationDiscoveryOptions::max_links` accounting bug that counted
    bootstrap seeds against the discovery budget (silently disabling
    discovery forever for any pool started with `>= max_links` bootstrap
    seeds — a realistic shape given this workspace's own 3-seed-minimum
    convention); a race where two concurrent `call`/`publish` failures on
    the same dead link could each independently spawn a redial task,
    leaking a connection and double-counting the give-up failure counter
    (fixed with a compare-exchange claim guard, its correctness verified to
    depend on `tokio::sync::Mutex`'s FIFO ordering — now documented
    explicitly); and a shutdown-ordering gap where a task mid-dial (no
    cooperation point inside `connection::connect`, whose own handshake
    timeout is up to 30s) could complete after `Pool::close()` already
    drained and closed everything, leaking a live session or resurrecting a
    link post-close (fixed with a `JoinSet` that hard-aborts and awaits
    every background task before the drain runs).

#### Changed

- `transport::Trust` now derives `Clone, Copy` (previously move-only) — a
  pool link may redial under a per-link trust that differs from the pool's
  own configured default (see above), which needs more than one dial per
  `Trust` value over a link's lifetime. All three variants are plain data
  with no invariant broken by permitting duplication.

#### Fixed

- **`tests/live_station.rs`'s `client_stream` test was vacuous — replaced
  with a real, asserted round trip.** The old
  `stream_open_round_trip_against_the_real_fleet` targeted a made-up,
  unregistered procedure with no real provider, and just `println!`'d
  whichever of the two possible outcomes occurred instead of asserting
  either — `send_reply`/`await_reply` had never actually been exercised
  against a real counterpart anywhere in this crate's test suite. Now
  `client_stream_reply_round_trip_against_the_real_fleet`: two independent
  connections to the same live station (one provider, one caller, same
  pattern as `streaming_provider_round_trip_against_the_real_fleet`), the
  caller pushes data and half-closes, the provider drains and sends a real
  `send_reply`, and the caller's `await_reply` is asserted against the
  actual payload and `responded_by`. This is also the regression proof for
  `macula-station`'s mode-aware half-close fix (commit `07db0d8`, same
  day): before that fix, a `client_stream` half-close tore down the whole
  relay route before the reply could flow back; this test now passes
  live against the real fleet, confirming the fix is deployed. The
  "Known limitations" entry this used to justify is removed from the
  README — it's fixed, not a documented gap anymore.

### [0.2.4] - 2026-09-05

#### Fixed

- **`keyring` dependency didn't actually build for iOS**, despite this
  crate's own Cargo.toml comment claiming `v1` covered it. `v1` only
  forwards `apple-native-keyring-store`'s `keychain` feature, and that
  backend is explicitly "Ignored on iOS" per its own docs — iOS has only
  the "protected data" store, no legacy keychain. Any consumer building
  this crate (or `macula-rust-ffi`) for an iOS target hit
  `apple-native-keyring-store`'s own
  `compile_error!("The \`protected\` feature is required on iOS")`.
  Surfaced by real iOS CI (macula-cam2me's `ios.yml`) the first time
  anything actually cross-compiled this crate for iOS since keyring 4 was
  adopted — no source change needed, keystore.rs is already backend-
  agnostic; fixed by unifying `apple-native-keyring-store`'s `protected`
  feature in via a matching `[target.'cfg(target_os = "ios")'.dependencies]`
  entry, the same pattern this crate already used for its Linux-only
  keyutils backend.

### [0.2.3] - 2026-09-05

A full adversarial security/correctness sweep of the whole crate, requested
independent of the dependency refresh above — every fix here closes a way a
malicious or malformed peer could crash or hang a node, not a feature change.

#### Fixed

- **CBOR decoder: unbounded recursion.** `cbor::decode` had no nesting-depth
  limit; a single crafted frame well under the 16 MiB wire-frame cap could
  crash the whole process via stack overflow, before any signature
  verification on the frame. Now capped at 128 levels
  (`cbor::MAX_NESTING_DEPTH`), returning `DecodeError::NestingTooDeep`
  instead.
- **CBOR decoder: O(n²) map decoding.** `decode_map`'s duplicate-key
  handling was a linear scan over every entry already seen — a crafted map
  with many distinct keys, still well under the frame cap, could peg a CPU
  core for tens of seconds per frame, and in the FFI bindings this also
  blocked every other call on that session (the decode ran under the
  session's own lock). Fixed by building each decoded value's canonical
  wire bytes bottom-up during decode and using them as an O(1) dedup key,
  computed only where a map key actually needs one.
- **`content::get`: eager allocation from an unverified size.** Fetching
  chunked content pre-allocated a buffer sized to the remote manifest's own
  `size` field, before a single chunk was fetched or hash-verified. A
  manifest lying about its size could trigger a large allocation attempt
  from a small message. Now grows only as genuinely-received, hash-verified
  chunks arrive.
- **`manifest::from_wire`: two ways a malformed manifest could panic.** A
  manifest claiming `chunk_size: 0` reached `[T]::chunks(0)` in `verify`,
  which panics unconditionally. A manifest whose `chunk_count` didn't match
  its actual `chunks` list let `content::get`'s fetch loop index past the
  end and panic. Both are now rejected as parse errors
  (`FromWireError::ZeroChunkSize` /
  `FromWireError::InconsistentChunkCount`).

#### Added

- `cbor::DecodeError::NestingTooDeep`, `cbor::MAX_NESTING_DEPTH` (`pub`).
- `manifest::FromWireError::ZeroChunkSize`,
  `manifest::FromWireError::InconsistentChunkCount`.

### [0.2.2] - 2026-09-05

#### Added

- `direct_dial::call_with_ucan` — direct-dial calls can now carry a UCAN,
  matching the gated-serving support `serve_one_call_gated` already had.

#### Changed

- Full dependency refresh: every dependency bumped to its latest release,
  including 7 across a semver-major line (`ed25519-dalek` 2→3, `rand`
  0.8→0.10, `sha2` 0.10→0.11, `webpki-roots` 0.26→1.0, `x509-parser`
  0.16→0.18, `base64` 0.22→0.23, dev-only `rcgen` 0.13→0.14). Identity
  generation's RNG source changed accordingly
  (`rand::rand_core::UnwrapErr(rand::rngs::SysRng)`, restoring the same
  fail-fast-on-OS-entropy-failure semantics `rand` 0.8's `OsRng` had) — no
  behavioral change for callers.
- Dropped the MIT license option; `macula-rust` is Apache-2.0 only.
- `Cargo.lock` is no longer tracked in this repository (library crate
  convention — a consuming project's own lock governs what actually
  builds).

#### Fixed

- `direct_dial::discovery_uri` now uses uppercase hex to match the live
  fleet's own DHT record encoding.

### [0.2.0] - 2026-08-30

Renamed from `macula-rust-sdk`/`macula-rust-sdk-ffi` to `macula-rust`/
`macula-rust-ffi`. Major feature push: direct-dial as a first-class path
alongside the advertise-gossip one, UCAN authorization, and org/realm
cert-chain verification.

#### Added

- Direct-dial: `direct_dial::{resolve,call,advertise_direct}` — reach a
  service without depending on advertise-gossip propagation, plus
  cert-chain-authorized variants (`*_with_cert_chain`) and streaming/content
  direct-dial (`open_stream_direct`, `put_direct`, `get_direct`).
- Periodic re-advertise: `Session::keep_advertised` /
  `direct_dial::keep_advertised_direct`, a cancellable loop (a station's
  registration doesn't survive its connection being replaced).
- UCAN support: `ucan::{create,verify,decode,get_*}`, plus
  `Session::call_with_ucan`/`serve_one_call_gated` for policy-gated serving.
- Cert-chain (org/realm authorization): `cert_chain::verify_advertisement_cert_chain`.
- Supervised pubsub pair: `Session::run_publisher`/`run_subscriber`,
  auto-publishing `pubsub.publish_*_v1` facts.
- RPC telemetry auto-facts: `rpc.sent_v1`/`rpc.completed_v1` (caller),
  `rpc.received_v1`/`rpc.replied_v1` (provider) — always-on, fire-and-forget.
- Overridable `KeyStore` trait (`keystore::KeyStore`,
  `KeyringStore`/`LinuxKeyutilsStore`) for platform-native identity
  persistence; `KeyPair::save_to_keystore`/`load_from_keystore`.
- `FfiValue` gained `List`/`Map` variants (as `Items`/`Fields`), closing a
  deferred recursive-enum gap in the mobile bindings.
- FFI coverage extended to match: direct-dial, UCAN, cert-chain,
  streaming/content direct-dial, `KeyStore`.

#### Fixed

- `publisher_sig` now implemented correctly; a `Session::close` data-loss
  race fixed.
- A stream-relay bug where cross-station `STREAM_DATA` frames weren't
  correctly signer-stamped.
- `call_direct_with_cert_chain` / `serve_one_call_gated` timeouts, both
  traced to the same premature-`Session`-drop race in the test harness (not
  an SDK defect).

### [0.1.0] - 2026-08-28

Initial implementation, built and live-verified against a real production
macula-station in a single day. Every wire primitive listed here was
confirmed against the real fleet, not just unit-tested — see each module's
own differential test fixtures (captured directly from the Erlang reference
via `rebar3 shell`).

#### Added

- Deterministic CBOR codec (`cbor`) — a from-scratch transcription of
  macula's own canonical wire codec, verified byte-for-byte against the
  Erlang/Rust NIF reference.
- Ed25519 identity + S/Kademlia puzzle hardening (`identity`).
- QUIC transport (`transport`) with both pubkey-pinned and WebPKI trust
  modes.
- Frame envelope construction, signing, and the length-prefixed wire codec
  (`frame`).
- CONNECT/HELLO handshake state machine (`connection`).
- Unary RPC: `Session::call` / `Session::serve_one_call` (CALL/RESULT/ERROR,
  full BOLT#4 error-code mapping), both caller and provider roles.
- PubSub: `Session::publish`/`subscribe` (PUBLISH/SUBSCRIBE/EVENT).
- Content transfer (`content`, `manifest`): content-addressed single-block
  and chunked storage, BLAKE3/SHA-256.
- Streaming RPC (`stream`): STREAM_OPEN/DATA/END/ERROR/REPLY, both caller
  and provider roles.
- RPC advertise/unadvertise.
- Mobile bindings crate `macula-rust-ffi` (UniFFI, Kotlin + Swift): covers
  every primitive above, including the streaming provider role via
  `FfiCallHandler` (a foreign-implemented async trait, not a closure).
- `unsafe_code = "forbid"` at the crate level.

[0.2.3]: https://github.com/macula-io/macula-rust/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/macula-io/macula-rust/compare/v0.2.1...v0.2.2
[0.2.0]: https://github.com/macula-io/macula-rust/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/macula-io/macula-rust/releases/tag/v0.1.0

## macula-rust-ffi

UniFFI (Kotlin + Swift) bindings over `macula-rust`. Wraps the core crate;
adds no wire-protocol logic of its own — every dated entry below tracks
this crate's own FFI-surface coverage of whatever `macula-rust` shipped the
same day, not a separate feature set. Independently versioned from the core
crate since day one (this crate started at 0.1.0 the same day the core crate
did, but the two have moved at different paces ever since).

### [ffi-0.4.0] - Unreleased

**Breaking throughout**: rewritten on `macula-rust` 0.4's pool, the macula 12
wire.

#### Added

- `FfiNodeKey`: `generate`, `load`, `load_or_create`, `save`,
  `load_from_keystore` and `save_to_keystore`, in `FfiProfile::PqPure` or
  `PqHybrid`.
- `FfiPool`: `connect` with pinned `FfiSeed`s and `FfiPoolOptions` (realm
  trust, timeouts, bounds). It offers `call`, `providers`, `publish`,
  `subscribe`, `serve`, `serve_stream`, `open_stream`, the DHT's
  `find_record`, `find_records`, `find_records_by_type` and `put_record`,
  `status` and `close`.
- `FfiCallHandler` and `FfiStreamHandler`, implemented by the app
  (`suspend fun` in Kotlin, `async throws` in Swift). A handler's thrown
  `FfiError` reaches the caller as a handler_error.
- `FfiSubscription` (`next` with a timeout, `unsubscribe`), `FfiStream` on
  either side, `FfiServed`, and `own_procedure`.
- `FfiError` maps the pool's errors, a provider's error with its code, and a
  foreign handler's unexpected throw.

#### Removed

- `FfiKeyPair`, `FfiSession`, `FfiTrust`, the UCAN functions, direct-dial and
  cert-chain calls, content transfer, and the live tests that used them.

#### Changed

- `rust-version` is 1.91, the least the dependencies build with.

### [ffi-0.3.1] - 2026-09-05

First publish to crates.io, alongside `macula-rust` v0.2.3 (whose security
fixes this crate's compiled output includes, being a normal dependent).

#### Changed

- Dev-dependency `rcgen` 0.13 → 0.14 (test-only cert fixtures in
  `tests/live_cert_chain_direct_dial.rs`; no change to this crate's own
  public API).
- `macula-rust` dependency now expressed as a real crates.io version
  requirement (`"0.2"`) alongside its workspace path, rather than a bare
  path — required to be publishable at all.

### [ffi-0.3.0] - 2026-08-30

Renamed from `macula-rust-sdk-ffi` to `macula-rust-ffi`, alongside the core
crate's own rename. FFI coverage extended to match the core crate's biggest
feature push (see `macula-rust`'s own 0.2.0 entry above): direct-dial, UCAN,
cert-chain, streaming/content direct-dial, the supervised pubsub pair, and
the overridable `KeyStore`.

#### Added

- `FfiSession` gained `resolveDirect`/`callDirect`/`advertiseDirect` (plus
  cert-chain-authorized variants) and streaming/content direct-dial.
- UCAN support: `FfiSession.callWithUcan`/`serveOneCallGated`.
- Cert-chain verification exposed at the FFI boundary.
- Supervised pubsub pair (`runPublisher`/`runSubscriber`).
- `KeyStore` trait exposed: `FfiKeyPair.saveToKeystore`/`loadFromKeystore`.

### [ffi-0.2.0] - 2026-08-29

#### Added

- `FfiValue` gained `List`/`Map` variants (as `Items`/`Fields`), closing a
  deferred recursive-enum gap — the mobile bindings can now round-trip any
  shape the core crate's own `cbor::Value` can, not just scalars.

### [ffi-0.1.0] - 2026-08-28

Initial UniFFI bindings, built the same day as the core crate. Covers every
primitive the core crate had by end of day: `FfiSession.connect`/`call`/
`serveOneCall` (unary RPC, provider role via `FfiCallHandler` — a
foreign-implemented async trait, not a closure), `publish`/`subscribe`,
`contentPut`/`contentGet`, `streamOpen`/`FfiStream`/`acceptStream`
(streaming RPC, both roles), and pubkey-pinned (`FfiTrust.Pinned`) plus
WebPKI trust.

[ffi-0.3.1]: https://github.com/macula-io/macula-rust/compare/ffi-v0.3.0...ffi-v0.3.1
[ffi-0.3.0]: https://github.com/macula-io/macula-rust/compare/ffi-v0.2.0...ffi-v0.3.0
[ffi-0.2.0]: https://github.com/macula-io/macula-rust/compare/ffi-v0.1.0...ffi-v0.2.0
[ffi-0.1.0]: https://github.com/macula-io/macula-rust/releases/tag/ffi-v0.1.0
