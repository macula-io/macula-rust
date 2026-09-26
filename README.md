# macula-rust

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-rust/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.89%2B-orange?logo=rust)](https://www.rust-lang.org)
[![memory safety](https://img.shields.io/badge/memory%20safety-100%25%20safe%20Rust-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-rust-full-dark.svg">
    <img src="assets/macula-rust-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Rust SDK for the Macula mesh, with Kotlin and Swift bindings</strong>
</p>

---

> **Status, 2026-09-26:** on the **macula 12** wire. That means post-quantum
> ML-DSA-87 identities (in pq_hybrid, the fleet's profile, the ML-DSA-87 +
> RSA-PSS-4096 composite), ML-KEM hybrid key exchange, and signed requests.
> Calls and streams by direct dial, serving (under an org or in a node's own
> namespace), publish/subscribe, node-served content and the DHT are tested
> against in-process macula 12 stations on every `cargo test`, and calls,
> pubsub and the DHT live against the fleet. Not here yet: UCAN-gated calls;
> see [Not yet implemented](#not-yet-implemented). Releases before 0.4.0 speak
> the retired 10.x wire and cannot reach the current fleet.

## What is this?

A native Rust implementation of a Macula node: its identity key, a pool of
links to the stations it pins by node_id, calls and streams that reach a
provider at its own station, serving procedures, publish/subscribe, and the
DHT. It speaks the same wire as [macula](https://github.com/macula-io/macula)
(the Erlang/OTP reference) and [macula-go](https://github.com/macula-io/macula-go),
over QUIC ([quinn](https://github.com/quinn-rs/quinn)) with the post-quantum
TLS of [macula-pqc](https://crates.io/crates/macula-pqc), ML-DSA-87 from
[macula-mldsa](https://crates.io/crates/macula-mldsa), and RSA-PSS-4096 from
aws-lc-rs.

[`macula-rust-ffi`](#mobile-bindings-kotlin-and-swift) wraps it for Kotlin and
Swift. The core crate has no FFI dependency and no FFI-shaped types.

## Quick start

```toml
[dependencies]
macula-rust = "0.5"
tokio = { version = "1", features = ["full"] }
```

A node needs a station to link to, **pinned by its node_id**, and the key of
each realm it trusts, which the realm publishes. Its own key is created on
first use and kept in a file its owner alone can read.

```rust
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use macula_rust::cbor::Value;
use macula_rust::node_key::NodeKey;
use macula_rust::pool::{Call, Opts, Pool, Seed};
use macula_rust::profile::Profile;
use macula_rust::station_link::Publication;

let key = NodeKey::load_or_create(Path::new("node.key"), Profile::PqHybrid)?;
let mut opts = Opts::new(Arc::new(key));
opts.realm_trust = HashMap::from([(realm, realm_key)]);
let pool = Pool::connect(
    vec![Seed { host: "station-fi-helsinki.macula.io".into(), port: 4433, node_id: station_id }],
    opts,
)
.await?;

// A call reaches a provider by direct dial: its advertisement from the DHT,
// trusted only when the realm key authorizes it, and its station dialed.
let answer = pool
    .call(Call { realm, procedure: "mcl-echo/echo".into(), payload: Value::text("hello"), ..Call::default() })
    .await?;

// Publish and subscribe; topics name a kind of fact, ids go in the payload.
let mut sub = pool.subscribe(&realm, "acme/demo/greeting_sent_v1").await?;
pool.publish(Publication {
    realm,
    topic: "acme/demo/greeting_sent_v1".into(),
    payload: Value::Map(vec![(Value::text("text"), Value::text("hi"))]),
    ttl_ms: None,
})
.await?;
let event = sub.recv().await;

pool.close().await;
```

Serving a procedure in the node's own namespace needs no org and no realm key:

```rust
use macula_rust::pool::Offer;
use macula_rust::record::own_procedure;
use macula_rust::station_link::handler;

let ring = own_procedure(&pool.node_id(), "ring"); // ~<node_id>/ring
let served = pool
    .serve(Offer::unary(realm, &ring, handler(|request| async move { Ok(request.payload) })))
    .await?;
```

Runnable versions are in [`examples/`](examples): `quickstart`, `serve`,
`publish_subscribe` and `content`, each reading the environment described at the top of
[`examples/common/mod.rs`](examples/common/mod.rs).

### Coming from 0.3 and earlier

Everything moved to the macula 12 wire, and the API with it. There is no
compatibility layer.

- **New identities.** A macula 12 node_id derives from an ML-DSA-87 key (or
  the LAMPS composite in `pq_hybrid`), so no Ed25519 identity carries over.
  `NodeKey::load_or_create` makes a new key file. **Re-join your realms and
  re-trust your agents**: anything that named your old node_id must be redone
  with the new one.
- `identity::KeyPair` is now `node_key::NodeKey`; `connection::Session` is
  `pool::Pool` (or `station_link::Link` for one station), whose seeds carry
  the station's node_id and whose `realm_trust` pins realm keys;
  `direct_dial::call` is simply `Pool::call`; `resolve` is `Pool::providers`;
  `serve_one_call` is `Pool::serve` with a handler; `Trust::WebPki` is gone:
  every station is pinned by its node_id.
- The 10.x content transfer (`content`, `manifest`, `put_direct`/`get_direct`)
  is replaced by node-served content: `Pool::share_content`/`get_content`, with
  macula 12's SHA-384 `manifest`. `ucan` and `cert_chain` are gone until macula
  12's own arrive (see [Not yet implemented](#not-yet-implemented)).
- Serving an org procedure needs the realm's org directory and the org's
  delegation to your node in the DHT: a realm admits orgs through a human.

## What's implemented

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Node keys (`node_key::NodeKey`) | ✅ | ✅ | `pq_hybrid` (the fleet's) or `pq_pure`; key files readable by the owner only, or the platform's secure store (`keystore`); pq_hybrid checked against the LAMPS draft's own vector and cross-verified with macula 12.8.0 |
| Pool of station links (`pool::Pool`) | ✅ | ✅ | Seeds pinned by node_id; realm keys pinned; links redialed with subscriptions and served procedures replayed |
| One station link (`station_link::Link`) | ✅ | ✅ | The v4 handshake, status statements both ways, neighbour signatures in pq_hybrid, a liveness probe |
| Calls by direct dial (`call`, `providers`) | ✅ | ✅ | Candidates tried freshest first; errors arrive as `LinkError::Provider` / `LinkError::Relay` |
| A node's own namespace (`record::own_procedure`) | ✅ | ✅ | `~<node_id>/<name>`: served and called with no org and no realm key |
| Streams (`open_stream`, `Offer::stream`) | ✅ | ✅ | Server, client and bidi; a QUIC stream per session, released on every path |
| Publish/subscribe | ✅ | ✅ | Signed publications, delivered once across links |
| Node-served content (`share_content`, `unshare_content`, `get_content`) | ✅ | ✅ | Shared on the node's own `~<node_id>/content_v1` and announced; a fetch checks the block, the manifest and every chunk against the content id, bounded (`ContentOptions`), with no realm key; manifests match macula's byte for byte (`manifest`) |
| DHT (`find_record`, `find_records`, `find_records_by_type`, `put_record`) | ✅ | — | Records verified before they are handed on |
| Mobile bindings (Kotlin, Swift) | ✅ | ✅ | `macula-rust-ffi`, below |

The link and the pool are ported from macula-go v0.12.0's `stationlink` and
`pool`, and every wire format is checked against macula-go's and macula's own
vectors (`tests/vectors/`). `unsafe_code = "forbid"` holds across the
workspace; the unsafe code is inside dependencies (quinn, aws-lc-rs).

## Payloads

A payload is what macula's wire CBOR carries: `Value::Null`, `Int`, `Float`,
`Text`, `Bytes`, `List` and `Map`. **There is no boolean**: write 1 or 0. A
decoded payload obeys macula 12's decoding rule (depth 64, 131,072 elements,
integers within ±2^63, text or integer map keys, no duplicates).

## Mobile bindings (Kotlin and Swift)

`macula-rust-ffi` wraps the pool with [UniFFI](https://mozilla.github.io/uniffi-rs/)
proc macros: `FfiNodeKey`, `FfiPool`, `FfiSubscription`, `FfiStream`, and two
handlers the app implements, `FfiCallHandler` and `FfiStreamHandler`
(`suspend fun` in Kotlin, `async throws` in Swift). `FfiPool` also shares and
fetches content (`shareContent`, `getContent`, `FfiContentOptions`). Every id
crosses as bytes and is checked for its length (32 bytes, or 50 for a content
id).

```bash
cargo build -p macula-rust-ffi --release
cargo run -p macula-rust-ffi --release --bin uniffi-bindgen -- generate \
    --library target/release/libmacula_rust_ffi.so \
    --language kotlin --out-dir bindings-kotlin
```

```kotlin
class Echo : FfiCallHandler {
    override suspend fun handle(request: FfiRequest): FfiValue = request.payload
}

val key = try {
    FfiNodeKey.loadFromKeystore("io.macula.myapp", "node-identity", FfiProfile.PQ_HYBRID)
} catch (e: FfiException.KeystoreNotFound) {
    FfiNodeKey.generate(FfiProfile.PQ_HYBRID).also { it.saveToKeystore("io.macula.myapp", "node-identity") }
}
val pool = FfiPool.connect(key, listOf(FfiSeed(host, 4433.toUShort(), stationId)),
    FfiPoolOptions(realmTrust = listOf(FfiRealmKey(realm, realmKey))))
pool.serve(realm, ownProcedure(pool.nodeId(), "ring"), Echo())
val answer = pool.call(realm, "mcl-echo/echo", FfiValue.Text("hello"), null, 5_000uL)
```

On Android the platform keystore needs one call at app start,
`Keyring.initializeNdkContext(applicationContext)`; see the `keystore`
module's documentation. iOS needs nothing extra.

CI generates both bindings on every push to master and every pull request;
the apps that use them compile them. The FFI crate needs Rust 1.91, the core
crate 1.89.

## Not yet implemented

- **UCAN-gated calls and serving.** macula 12 uses post-quantum UCANs; calls
  carry no token yet, and a gated procedure cannot be served.
- **Station discovery beyond the seeds.** macula's discovery call is not
  served by the fleet today (macula-io/macula#31); give the pool its seeds.

## Testing

```bash
./scripts/build-teststation.sh    # macula-go's in-process stations, to target/teststation
cargo test --workspace
```

The integration tests (`tests/station_link.rs`, `tests/pool.rs`,
`macula-rust-ffi/tests/pool_ffi.rs`) run against `tests/teststation`, a Go
helper around macula-go's `teststation`. It starts in-process macula 12
stations, realms and orgs as each test asks, and reports what a station sees
(who is connected, what is advertised or subscribed, how many streams it
relays). A test fails, not skips, when the helper is missing. No network is
needed. Go ≥ 1.27 builds the helper.

`tests/live.rs` runs against one real station and is ignored unless asked:

```bash
MACULA_RUST_LIVE_SEED=station-fi-helsinki.macula.io:4433 \
MACULA_RUST_LIVE_STATION_ID=<64 hex> MACULA_RUST_LIVE_REALM=<64 hex> \
MACULA_RUST_LIVE_REALM_KEY=<hex> cargo test --test live -- --ignored
```

With a key generated for the run and never saved, it reads the DHT, calls
`mcl-echo/echo` by direct dial and hears its own publication.
`scripts/cross-verify-macula.sh` renews the pq_hybrid signatures that crossed
both ways with macula (`tests/vectors/identity/macula_12_cross`).

## Sibling SDKs

| Repo | Approach |
|---|---|
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) |
| [macula-go](https://github.com/macula-io/macula-go) | Go port; this crate's link and pool follow it |
| [macula-ts](https://github.com/macula-io/macula-ts) | FFI binding over macula-go, for Node.js |
| [macula-php](https://github.com/macula-io/macula-php) | FFI binding over macula-go, for PHP |
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
