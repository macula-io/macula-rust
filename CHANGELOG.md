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

#### Changed

- **Direct dial tries every authorized provider.** `direct_dial::call`,
  `call_with_ucan`, `call_with_cert_chain`, `open_stream_direct`,
  `open_stream_direct_with_cert_chain` and `get_direct` try each advertised
  provider in the order the DHT returns them, instead of only the first. A
  provider that can't be reached before the request is sent is skipped for
  the next one, and a request that has been sent is never sent again.
  `get_direct` also retries while no provider has announced the content
  yet, and a DHT lookup that fails is retried within the timeout instead of
  ending the call.
- **Breaking: the timeout bounds the whole call**, finding the provider
  included. A timeout sized for the request alone can now run out during
  resolution. `resolve` and `resolve_with_cert_chain` give up after 10
  seconds, and `put_direct`'s timeout covers the endpoint lookup and the
  dial.
- **Breaking: new `GetDirectError::Timeout { last }`.** It reports a
  `get_direct` whose timeout ran out during a transfer, where `last`, also
  its `source()`, carries the failure before it, or before any provider
  lookup was answered. An exhaustive `match` on `GetDirectError` needs the
  new arm.
- **Breaking: new `ResolveError::Timeout`, and a call reports what it
  observed.** At its timeout a direct-dial call returns the last candidate
  failure, else why an answered DHT lookup found nothing, else a failed
  lookup's error, and `ResolveError::Timeout` only when nothing was
  observed at all, where it used to report `ProcedureNotAdvertised` or
  `StationEndpointNotFound`. A `station_endpoint` lookup follows the same
  rule, reporting `StationEndpointNotFound` only when a lookup was
  answered, and retries a lookup that fails within its budget. A record
  that names no dialable address is looked up again too, and when it is
  the latest answer the lookup reports the new
  `ResolveError::MalformedStationEndpoint`. An exhaustive `match` on
  `ResolveError` needs both new arms.
- **Breaking: direct dial reuses a session this process already has open
  to the provider's station under the same identity.** A station keeps one
  connection per identity and closes the older one when a newer one
  arrives, so a second dial used to close `resolve_via` or a `Pool` link.
  `open_stream_direct`, `open_stream_direct_with_cert_chain`, `put_direct`
  and `get_direct` now run on that open session, on a dedicated QUIC
  stream, and leave it open. The stream functions return
  `direct_dial::OpenedStream` (`stream`, `lease`) instead of a
  `(Session, StreamHandle)` tuple; release its `SessionLease` once the
  stream is done. `call`, `call_with_ucan` and `call_with_cert_chain` run
  on an open session the same way.
- **A direct call whose CALL was not sent tries the next candidate.** A call
  whose session had ended, or whose turn to write didn't come in time, moves
  on to the next candidate, and its station may be tried again on a later
  pass. A call that was or may have been sent is returned as before.
- **A CALL handler receives its caller.** A map payload reaches the handler
  with the caller's 32-byte node id under `"caller"`, the caller the CALL's
  signature was verified against, replacing any `"caller"` the sender put in
  the payload. A payload that isn't a map reaches the handler unchanged and
  carries no caller.
- **Breaking: `StreamHandle::accept` refuses a STREAM_OPEN not signed by its
  caller.** Stream handlers previously received the STREAM_OPEN's caller
  field unverified; upgrade if a stream handler relies on it. A stream whose
  first frame doesn't verify against the caller it names, has no signature
  or caller, is of another type, or doesn't decode is aborted in both
  directions with application error code 2 (`stream::REFUSED_STREAM`),
  with nothing written, and accept waits for the next stream within its
  timeout. `AcceptError::Parse` is removed. A provider that accepts a
  stream and won't serve it refuses it with `StreamHandle::refuse`, which
  writes a STREAM_ERROR, finishes the send half and stops reading with
  code 2.
- **A stream handler receives its caller.** Map args of an accepted
  STREAM_OPEN carry the verified caller under `"caller"`, replacing any
  `"caller"` the opener put there, as a CALL handler's payload does.
- **Drop warnings.** A session logs a dropped CALL (`dropped_call`), a
  RESULT or ERROR for no pending call (`dropped_reply`) and a refused stream
  (`refused_stream_open`) with its `count`, `reason`, and `procedure` or
  `call_id`. The first of a kind in an interval is logged at once, and the
  rest are counted into one closing line when the interval ends.
  `Session::set_drop_warning_interval` sets the interval, 60 seconds by
  default.
- **A frame that doesn't decode ends a session as `SessionEndReason::Malformed`**,
  where it used to end as `StreamFailed`. An exhaustive `match` on
  `SessionEndReason` needs the new arm.
- **A session direct dial dialed is shared until its last request is done.**
  A direct-dial request that finds it open uses it too, holding a lease of
  its own, and the session closes when the last lease is released instead
  of when the request that dialed it finishes. It is not reused once it is
  closing.
- **Breaking: a UCAN-gated procedure binds the token to its caller.**
  `ucan::Policy::check` takes the CALL's `caller` as well as its token, and
  a `Policy::required` procedure accepts a token only when its `aud` is
  that caller's 32-byte node id as lowercase hex, with no `did:` prefix. A
  token with another or no audience is refused as `unauthorized`
  (`UcanError::WrongAudience`, and `UcanError::NoCaller` when `check` gets
  no 32-byte caller; both new). Mint tokens for gated procedures with that
  audience.
- **An inbound CALL must be signed by the caller it names.**
  `Session::serve_one_call` and `serve_one_call_gated` drop a CALL whose
  signature doesn't verify against its `caller` field, without a reply and
  before any policy or handler runs, matching the Erlang station link.
- **Breaking: a `Session` is a cloneable handle with one reader.** Its
  methods take `&self`, so calls, subscriptions, publishing and serving on
  one session run at the same time. A reader task routes each RESULT or
  ERROR to its call by call id, each EVENT to the subscriptions it matches,
  and each inbound CALL to a queue of 64 that `serve_one_call` and
  `serve_one_call_gated` take from. A slow subscriber never delays a call's
  reply. The functions in `dht`, `content`, `stream` and `direct_dial` take
  `&Session` instead of `&mut Session`.
- **Breaking: `Session::subscribe` returns a `Subscription`** with its own
  queue of 256 events, read with `recv_event(timeout)` and ended with
  `close()`. A topic matches segment by segment on `/`, where `*` is exactly
  one segment, and the realm must be equal. Closing the last subscription
  for a realm and topic sends UNSUBSCRIBE. A subscription that falls more
  than 256 events behind returns its queued events and then
  `RecvEventError::Overflow`, and stays subscribed at the station until it
  is closed. `Session::recv_event`, `unsubscribe`, `recv_frame`,
  `recv_frame_timeout` and `leftover_bytes` are removed, and
  `run_subscriber` runs on a `Subscription`.
- **Breaking: new error types.** `Session::call` and `call_with_ucan`
  return `CallError`: `Timeout { write_started }`,
  `SessionEnded { reason, write_started }`, `SendTimeout`, `Encode`,
  `Write` or `MalformedReply`, where `not_sent()` tells whether the CALL
  can safely be sent again. `publish`, `advertise`, `unadvertise` and
  `subscribe` return `SendError`, `RecvEventError` is `Timeout`, `Overflow`
  or `SessionEnded`, `serve_one_call` returns `ServeCallError`, and
  `FrameStream`'s call error is renamed `StreamCallError`.
- **Writes are bounded.** A caller waits for its turn to write no longer
  than its deadline, a call's timeout or else 30 seconds. A write that
  takes longer than 30 seconds ends the session. The reader never waits on
  a write: an inbound CALL that finds the queue full is answered with
  `temporary_relay_failure` through a separate queue of 64 frames, and
  serving carries on.
- **How a session ends.** A GOODBYE, a HELLO or CONNECT after the handshake,
  a frame that doesn't decode, a stalled write or the end of the control
  stream ends the session: its pending calls fail with `SessionEnded`, its
  connection closes, direct dial no longer reuses it, and the end is logged
  once through the `log` crate, as a warning when the station or connection
  ended it and as info when it was closed here, with both node ids.
  `Session::end_reason` and `ended` report it. Frames no route claims are
  counted by type in `unrouted_frame_counts`, with a log line at most once
  a minute.
- **`Pool::call` publishes no RPC facts.** A pooled call goes through the
  link's session without the `rpc.sent_v1` and `rpc.completed_v1` facts
  that `Session::call` publishes.
- **Breaking: `Pool::call` tries another link only when the CALL was not
  sent.** It moves on to the next connected link only while a call fails
  before its CALL was written, so no CALL runs twice. A call that timed out
  after its write started, and an ERROR reply, are returned as they are.
  `PoolCallError::AllFailed` is replaced by `PoolCallError::Call`, the
  failure that stopped the call.
- **A pool link is dialed again when its session ends**, instead of when a
  call or publish on it fails, so a call that times out on a link that is
  still up no longer drops that link.

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

#### Changed

- Builds on `macula-rust` 0.4, with the dependency requirement moved to
  `"0.4"`. The direct-dial calls on `FfiSession` therefore try every
  authorized provider, and their `timeout_ms` now bounds finding the
  provider as well. A `get_direct` whose transfer the timeout cuts off
  reports `FfiError::Content` with the earlier failure in its reason.
- `FfiSession::serve_one_call_gated` refuses a UCAN token whose `aud` isn't
  the calling node's id as lowercase hex, and both serve calls drop a CALL
  that isn't signed by its caller. Mint tokens for gated procedures with
  `ucan_create` using that audience.
- **Breaking: `FfiOpenedDirectStream` carries a `lease` instead of a
  `session`.** The direct-dial stream and content calls on `FfiSession` run
  on a session this process already has open to the provider's station
  under the same identity, instead of dialing a second one that would close
  it. Call `FfiSessionLease::release` once the stream is done: a session
  direct dial dialed closes when no other direct-dial request still uses it.
- **Breaking: `FfiSession::subscribe` returns an `FfiSubscription`**, read
  with `recv_event(timeout_ms)` and ended with `close()`. Each subscription
  has its own queue of 256 events and receives only the events its topic
  and realm match. `FfiSession::recv_event` and `unsubscribe` are removed.
- Methods on one `FfiSession` no longer wait for each other:
  `serve_one_call`, `accept_stream`, calls and subscriptions on the same
  session run at the same time.

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
