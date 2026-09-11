# macula-rust

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-rust/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-rust-full-dark.svg">
    <img src="assets/macula-rust-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Rust port of the Macula SDK wire protocol — mobile first, not mobile-only</strong>
</p>

---

> **Status, 2026-08-30:** feature-complete for a leaf/edge client —
> the client/leaf side of the wire protocol is built and
> **live-verified against the production station fleet**
> (`station-de-frankfurt.macula.io`) — handshake (pinned or WebPki
> trust), unary RPC, PubSub, content transfer, and streaming RPC, every
> primitive in both caller and provider roles, plus direct-dial
> (DHT resolve/publish, both plain and cert-chain-authorized), periodic
> re-advertise, UCAN (mint/verify/introspect — policy-gated serving's
> live-network behavior needs a closer look, see Known limitations), a
> supervised PubSub pair, RPC telemetry auto-facts, and an
> overridable-per-platform `KeyStore` for identity persistence. Mobile
> bindings (Kotlin + Swift, via UniFFI) wrap almost the entire surface,
> generated and CI-checked on every push. See [Status](#status) for
> what's deliberately out of scope vs. genuinely separate future work,
> and [Known limitations](#known-limitations) for one real external bug
> this crate can't fix.

## What is this?

A ground-up Rust implementation of the client half of Macula's wire
protocol — the same protocol [`macula-io/macula`](https://github.com/macula-io/macula)
(the Erlang/OTP SDK) speaks, extracted directly from that source and
tracked in [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md).
Macula is a federated mesh for sovereign, end-to-end-encrypted
application networks; a **station** is the relay/DHT node, and this crate
is what a **leaf** — a phone, a desktop app, a CLI, anything that isn't
itself a station — uses to join it.

Mobile is the flagship consumer driving the work (hence the UniFFI
crate), not a ceiling on it: the core crate has zero UniFFI dependency
and zero FFI-shaped types, so it's exactly as usable from plain Rust, a
CLI, or WASM as any other Rust SDK.

## Features

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Handshake (CONNECT/HELLO) | ✅ | — | Ed25519 identity, S/Kademlia puzzle-hardened |
| One session, many uses | ✅ | ✅ | `Session` is a cloneable handle with one reader: calls, subscriptions and serving on it run at the same time, and a slow consumer never stalls a call's reply |
| Unary RPC (CALL/RESULT/ERROR) | ✅ | ✅ | `Session::serve_one_call`, BOLT#4 error mapping live-verified; a call that times out says whether its frame was sent |
| PubSub (PUBLISH/SUBSCRIBE/EVENT) | ✅ | ✅ | `Session::subscribe` returns a `Subscription` with its own queue of 256 events; a subscriber gets its own publish, verified live |
| Content transfer (single-block + chunked) | ✅ | ✅ | Content-addressed, BLAKE3/SHA-256 |
| Streaming RPC (STREAM_OPEN/DATA/END/REPLY) | ✅ | ✅ | Both roles live-verified against the real fleet; `ClientStream` mode's reply path is SDK-correct but currently blocked by a `macula-station` bug — see [Known limitations](#known-limitations) |
| RPC advertise/unadvertise | ✅ | — | |
| Direct-dial (DHT resolve/publish) | ✅ | ✅ | `direct_dial::{resolve,call,advertise_direct}` — reaches a service without depending on advertise-gossip having propagated a route; plain + cert-chain-authorized (`*_with_cert_chain`) |
| Direct-dial streaming/content | ✅ | ✅ | `direct_dial::{open_stream_direct,put_direct,get_direct}` — runs on a session already open to the same station under the same identity instead of dialing a second one, which the station would answer by closing the first; `get_direct` is correct but currently unreachable, see [Known limitations](#known-limitations) |
| Periodic re-advertise | — | ✅ | `Session::keep_advertised` / `direct_dial::keep_advertised_direct` — a ctx-cancellable loop, since a station's registration doesn't survive the connection that sent it being replaced |
| UCAN (mint/verify/introspect) | ✅ | ✅ | `ucan::{create,verify,decode,get_*}` are pure functions; `Session::call_with_ucan`/`serve_one_call_gated` live-verified end-to-end; a gated provider accepts a token only when its `aud` is the calling node's id as lowercase hex, and drops a CALL not signed by its caller (see [`examples/ucan.rs`](examples/ucan.rs) and [Known limitations](#known-limitations) for the resolved investigation) |
| Cert-chain (org/realm authorization) | ✅ | ✅ | `cert_chain::verify_advertisement_cert_chain` + `direct_dial::*_with_cert_chain` — opt-in, the plain direct-dial path is unaffected |
| Supervised PubSub pair | ✅ | ✅ | `Session::run_publisher`/`run_subscriber` — addressable/cancellable wrappers over bare publish/subscribe, auto-publishing `pubsub.publish_*_v1` facts |
| RPC telemetry auto-facts | ✅ | ✅ | `rpc.sent_v1`/`rpc.completed_v1` (caller), `rpc.received_v1`/`rpc.replied_v1` (provider) — always-on, fire-and-forget, fired automatically by `call`/`serve_one_call_gated` |
| Overridable `KeyStore` | ✅ | — | `keystore::KeyStore` trait + `KeyringStore`/`LinuxKeyutilsStore` — `KeyPair::save_to_keystore`/`load_from_keystore`; the raw-file `KeyPair::save` stays as a testing/parity convenience |
| Mobile bindings (Kotlin, Swift) | ✅ | ✅ | Via [UniFFI](#mobile-bindings-uniffi) — provider role serves via `FfiCallHandler`, a foreign-implemented async trait (`suspend fun`/`async throws`), not a closure. Covers direct-dial, UCAN, cert-chain, content/stream direct-dial reuse, and `KeyStore`; deliberately NOT `keep_advertised`/`run_subscriber` (see the FFI crate's own module doc for why) |
| Pubkey-pinned trust | ✅ | — | `Trust::Pinned` / `FfiTrust.Pinned` — the only mode that works at all for a station without a CA-issued cert |

`unsafe_code = "forbid"` at the crate level — the only unsafe in this
workspace lives inside its pinned dependencies (`quinn`, `ring`), not
here.

## Quick start

Also lives as a runnable example — `cargo run --example quickstart`.
Advertises and calls its own trivial echo procedure (two identities, a
provider and a caller, since a station kicks a connection the instant a
second one arrives under the same identity) rather than depending on any
particular procedure already being advertised on the fleet:

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use macula_rust::{
    cbor::Value,
    connection::{self, BoxFuture, CallHandler},
    frame::AdvertiseSpec,
    identity::KeyPair,
    transport::Trust,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Puzzle-hardened identities — required. An unhardened identity fails
    // the handshake silently (QUIC/TLS looks healthy, HELLO never accepts).
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        "station-de-frankfurt.macula.io",
        4433,
        Trust::WebPki,
        &provider_identity,
    )
    .await?;
    let caller_session = connection::connect(
        "station-de-frankfurt.macula.io",
        4433,
        Trust::WebPki,
        &caller_identity,
    )
    .await?;

    let realm = [0u8; 32];
    // Unique per run — reusing a fixed procedure name across rapid
    // repeated runs can hit stale DHT routing state from the prior run's
    // now-dead advertiser.
    let procedure = format!(
        "macula_rust.quickstart_echo.{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );

    let advertise_spec = AdvertiseSpec::new(realm, procedure.clone(), provider_identity.node_id());
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await; // ADVERTISE is fire-and-forget; give it a moment to land

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move { Ok(payload) }) as BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(lookup, &provider_identity, Duration::from_secs(10))
            .await;
        // Close explicitly instead of letting provider_session drop when
        // this task ends — see Session's own doc for why: dropping the
        // last handle closes the connection at once, which gives quinn's
        // send-scheduling no guarantee the RESULT just sent actually
        // reached the peer first.
        provider_session
            .close(
                "normal",
                Some("quickstart provider done"),
                &provider_identity,
            )
            .await;
        result
    });

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i128;
    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::Text("hello".into()),
            now_ms + 5_000, // deadline_ms
            &caller_identity,
            Duration::from_secs(5),
        )
        .await?;

    serve_task.await??;
    caller_session
        .close("normal", Some("quickstart caller done"), &caller_identity)
        .await;

    println!("{response:?}");
    Ok(())
}
```

## Mobile bindings (UniFFI)

`macula-rust-ffi` is a separate crate — not code bolted onto the
core one — wrapping every application primitive (`FfiSession::connect`/
`call`/`serve_one_call`/`publish`/`subscribe`/`content_put`/
`content_get`/`stream_open`/`advertise`/`accept_stream`) for Kotlin and
Swift, in the modern proc-macro UniFFI style (`#[uniffi::export]`,
native `async`/`await` and Kotlin coroutines, no `.udl` file). CI
rebuilds the `cdylib` and regenerates both language bindings on every
push as a codegen smoke test.

Serving an RPC from Kotlin or Swift means implementing `FfiCallHandler`
— a **foreign trait** (`#[uniffi::export(foreign)]`), not a callback
closure (UniFFI foreign traits can't carry a plain closure, so
`handle` receives the full inbound call and does its own procedure
routing if a session serves more than one):

```kotlin
class Doubler : FfiCallHandler {
    override suspend fun handle(procedure: String, realm: ByteArray, payload: FfiValue): FfiValue {
        val n = (payload as FfiValue.Int).v1
        return FfiValue.Int(n * 2)
    }
}

session.advertise("math.double", realm, identity)
session.serveOneCall(Doubler(), timeoutMs = 30_000u, identity)
```

(`FfiValue` currently covers `Null`/`Int`/`Bytes`/`Text`/`Float` — see
this crate's own module doc for why `List`/`Map` aren't there yet; a
handler needing a structured payload should encode it as `Bytes`
today.)

```bash
cargo build -p macula-rust-ffi --release
cargo run -p macula-rust-ffi --release --bin uniffi-bindgen -- generate \
    --library target/release/libmacula_rust_ffi.so \
    --language kotlin --out-dir bindings-kotlin
```

### Connecting and a basic call

Signatures cross-checked against real generated bindings (`uniffi-bindgen generate`, both languages), not guessed — `call` takes no separate deadline, only a timeout. Calls `math.double`, the procedure the [`Doubler`](#mobile-bindings-uniffi) example above this one advertises and serves — this SDK's own, not a fleet-wide service, so it only resolves while that example (or an equivalent provider) is actually running:

```kotlin
val identity = FfiKeyPair.generate()
val session = FfiSession.connect("station-de-frankfurt.macula.io", 4433.toUShort(), FfiTrust.WebPki, identity)
val response = session.call("math.double", realm, FfiValue.Int(21), 5_000uL, identity)
```

```swift
let identity = FfiKeyPair.generate()
let session = try await FfiSession.connect(host: "station-de-frankfurt.macula.io", port: 4433, trust: .webPki, identity: identity)
let response = try await session.call(procedure: "math.double", realm: realm, payload: .int(21), timeoutMs: 5_000, identity: identity)
```

### Persisting identity via platform secure storage

Real, working usage — this is `macula-apps/macula-cam2me`'s actual
Android identity persistence, not a contrived snippet. Android needs one
extra one-time call at app startup (Keystore has no NDK surface, so the
`android-native-keyring-store` crate ships its own JNI init export); iOS
needs nothing extra, since `apple-native-keyring-store` covers both
macOS and iOS as one backend. `saveToKeystore`/`loadFromKeystore` are
plain blocking calls, not `suspend`/`async` — note the `FfiError`
variant name is `KeystoreNotFound` (capitalized, mirroring the Rust
error type directly) in both languages, unlike `FfiTrust`/`FfiValue`'s
ordinary lower-camelCase Swift cases (`.webPki`, `.text`) — a real,
confirmed UniFFI codegen quirk, not a typo.

```kotlin
// Once, in Application.onCreate or MainActivity.onCreate:
Keyring.initializeNdkContext(applicationContext)

// Then anywhere:
val identity = try {
    FfiKeyPair.loadFromKeystore("io.macula.myapp", "node-identity")
} catch (e: FfiException.KeystoreNotFound) {
    FfiKeyPair.generate().also { it.saveToKeystore("io.macula.myapp", "node-identity") }
}
```

```swift
// No extra init needed on iOS.
let identity: FfiKeyPair
do {
    identity = try FfiKeyPair.loadFromKeystore(service: "io.macula.myapp", account: "node-identity")
} catch FfiError.KeystoreNotFound {
    identity = FfiKeyPair.generate()
    try identity.saveToKeystore(service: "io.macula.myapp", account: "node-identity")
}
```

## Testing

```bash
cargo test --workspace --all-features
```

100+ tests across the workspace, plus a separate live-verification suite
(`tests/live_station.rs`) that dials the real production fleet —
`#[ignore]`d by default since it depends on infrastructure this crate
doesn't control:

```bash
cargo test --test live_station -- --ignored --nocapture
```

## Status

**Live-verified, 2026-08-28 — full parity, both directions:** handshake,
CALL/RESULT/ERROR as both caller (`Session::call`) and provider
(`Session::serve_one_call`, BOLT#4 error mapping — `unknown_next_peer`
on a lookup miss, `temporary_relay_failure` on a handler panic (caught
via `tokio::spawn`, one task per call, the same shape
`macula_station_link.erl`'s one-process-per-call already uses),
`unknown_error` with detail on a handler-returned error, all ported
field-for-field from that module's `handle_inbound_call/2`), PUBLISH/
SUBSCRIBE/EVENT (a subscriber does receive its own publish), content
transfer, and streaming RPC in both the caller and provider roles — all
against `station-de-frankfurt.macula.io`, the real fleet, not a local
mock. Two independent connections to the same station (one advertising
and serving, the other calling in) is the pattern behind every
provider-role test — see `tests/live_station.rs`'s
`unary_call_provider_round_trip_against_the_real_fleet` for the unary
case. Three real protocol bugs were caught by differential-vector tests
before ever touching production.

Unary-RPC provider dispatch was the one gap left after the streaming
and content-transfer provider roles landed — a service built on this
crate could call RPCs and serve streams, but couldn't serve a
request/response procedure at all. It's now built here and in
[`macula-go`](https://github.com/macula-io/macula-go) in the
same pass, so both SDKs serve RPCs, not just call them, and wrapped in
the FFI layer the same day: [`FfiCallHandler`](#mobile-bindings-uniffi)
is a **foreign trait** (`#[uniffi::export(foreign)]`), not a callback
closure — UniFFI doesn't support passing a bare closure across the
boundary, so `handle` receives the full inbound call and a Kotlin/Swift
implementation does its own procedure routing if a session serves more
than one. Verified past "it compiles": rebuilt the release `cdylib`,
regenerated both Kotlin and Swift, and inspected the actual generated
code — `FfiCallHandler.handle` renders as `suspend fun ... : FfiValue`
in Kotlin and `func handle(...) async throws -> FfiValue` in Swift,
`FfiSession.serveOneCall`/`serveOneCall` takes it as a parameter in
both, not just as an exit-code smoke test.

Pubkey-pinned trust reached the FFI layer the same day too: `connect`
now takes an `FfiTrust` (`Pinned { node_id }` or `WebPki`) instead of
hardcoding WebPki. Not a nice-to-have — WebPki has no chain to validate
against a self-hosted station outside the public demo fleet, so a real
deployment off `station-de-frankfurt.macula.io` needs pinning to
connect at all. `Trust::Insecure` stays deliberately unexposed at the
FFI boundary (dev/diagnostic only in the core crate; a shipped mobile
app should never be able to select "skip TLS verification").

**2026-08-30: direct-dial, UCAN, cert-chain, periodic re-advertise, a
supervised PubSub pair, RPC telemetry facts, and an overridable
`KeyStore` all landed, live-verified, and FFI-wrapped the same day.**
Direct-dial exists because ordinary advertise/gossip routing depends on
a route having already propagated between the caller's and the
service's station — this fleet's gossip is best-effort and often hasn't,
so direct-dial resolves a signed DHT record naming the serving station
and dials it in one hop instead. `KeyStore` closes a real gap this
crate's own `KeyPair::save` doc comment had flagged since it was
written: raw-file persistence is fine for tests, but a real mobile app
needs Keychain/Keystore-backed storage — `KeyringStore` covers macOS,
iOS, Linux (D-Bus secret service) and Windows via one `keyring`-crate
backend (confirmed via its own `Cargo.toml`: `apple-native-keyring-store`
covers macOS *and* iOS with a single backend, no per-platform bridge
needed), `LinuxKeyutilsStore` is a second backend for sandboxes with no
secret-service daemon running. `macula-apps/macula-cam2me`'s Android app
migrated to it the same day (`NodeKeyPair.kt`), the first real consumer.

**This crate is feature-complete for its stated purpose — a leaf
client dialing a known macula-station — in both the core crate and the
FFI layer.** What's genuinely still outstanding is a different kind of
thing entirely, not an SDK gap:
- DHT/HyParView/Plumtree gossip primitives — deliberately **not**
  leaf-client scope; they're how *stations* gossip membership and
  broadcast to each other (§6.5-§6.7 say so explicitly). A leaf never
  needs them, so this was never a completeness gap to begin with.
- The actual Android demo app — real Kotlin/Android work outside this
  crate, needing a device/emulator and toolchain this repo's own CI
  doesn't have. The SDK surface it needs (`advertise`/`acceptStream`/
  `FfiStream`/`serveOneCall`, both pull and push streaming modes) is
  already complete and live-verified; nothing here is blocking it.
- Additional language ports (C#, Python) — a separate initiative, not
  a gap in this crate.

See [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md) for the
full wire-format spec this crate is built against, section by section,
traced directly to the Erlang SDK's source.

## Known limitations

- **`direct_dial::get_direct` can only resolve a `content_announcement`
  that something has actually published** — and nothing in this
  ecosystem currently does, since only a station/relay can legitimately
  publish one (a `content_announcement`'s endpoint is dialed with no
  relay indirection, unlike a `procedure_advertisement`, so a leaf SDK
  identity can't pass its own trust check). Correct but currently
  unreachable, not a bug.
- **RESOLVED**: an earlier draft of this section reported
  `call_direct_with_cert_chain` timing out waiting for a reply after a
  successful resolve+dial, narrowed but not root-caused across several
  investigation rounds. Root-caused: the same premature-`Session`-drop
  race as the `serve_one_call_gated` finding below — the FFI test's
  `serve_task` dropped the provider `Session` the instant
  `serve_until_procedure` returned, closing the QUIC connection before
  the reply frame reached the peer. Fixed by keeping the session alive
  300ms after the last reply, matching the identical fix already applied
  there. Confirmed with 5 consecutive clean passes (was failing reliably
  before). No SDK defect — the cert-chain mechanism itself was never
  broken. See `macula-rust-ffi/tests/live_cert_chain_direct_dial.rs`'s
  own comments for the ruled-out theories from the earlier rounds.
- The demo fleet's `station_endpoint` DHT records carry a short TTL and
  are not always freshly republished, so a station's record can be stale
  for a while. Direct dial tries every advertised provider in turn and
  keeps re-querying within the call's `timeout`; only when no provider's
  station has a usable record before it runs out does the call return
  `StationEndpointNotFound`. This is fleet infrastructure state, not a
  code defect.
- **RESOLVED**: an earlier draft of this section reported
  `serve_one_call_gated`/`call_with_ucan` failing 100% of live attempts
  while `serve_one_call` succeeded reliably in the same window, and left
  it as an open, unconfirmed question. Root-caused: it was a test-harness
  bug, not a real difference between gated and plain serving. The failing
  harness spawned the provider's `Session` into a task that dropped it
  the instant `serve_one_call`/`serve_one_call_gated` returned; dropping
  the last `Session` handle closes the underlying QUIC connection, which
  can happen before the just-sent reply frame is flushed to the peer — the exact
  same class of race already documented on [`Session::close`], just
  never hit by drop instead of an explicit close before now. Confirmed
  by direct A/B: 8/8 plain AND 8/8 gated calls succeeded once the
  provider session was kept alive briefly after serving, interleaved on
  the same station in the same window; the pre-existing
  `unary_call_provider_round_trip_against_the_real_fleet` test also
  passed 3/3 at the same moment, ruling out the fleet-degradation theory
  entirely for this specific finding. **Practical takeaway for any
  caller**: don't let a `Session` drop immediately after `serve_one_call`/
  `publish`/any send-then-return call — keep it alive briefly (or call
  [`Session::close`] explicitly) so in-flight writes have time to reach
  the wire. See `examples/ucan.rs` for a real, live-verified gated-serving
  example built once this was root-caused.

## Related projects

| Project | Description |
|---|---|
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) — the protocol this crate ports |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, SWIM, routing, peering |
| [macula-realm](https://github.com/macula-io/macula-realm) | Managed-realm identity + certificate authority |

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<http://www.apache.org/licenses/LICENSE-2.0>).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you shall be licensed as
above, without any additional terms or conditions.

---

<p align="center">
  <sub>Built with the BEAM's protocol, ported to Rust — <a href="https://github.com/sponsors/rgfaber">sponsor the work</a> if this saved you some time</sub>
</p>
