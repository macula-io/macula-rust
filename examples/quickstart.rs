//! Minimal end-to-end example: connect to a station, advertise a
//! trivial echo procedure, and call it. Dials the real fleet, so this
//! isn't run by CI — see README.md's "Quick start" section, which this
//! file backs (kept compiling by `cargo build --examples` in CI, run
//! manually with `cargo run --example quickstart`).
//!
//! Two identities are used (a provider and a caller) because a station
//! kicks a connection the instant a second one arrives under the same
//! identity — the same reason this crate's own live tests use separate
//! identities for each role (see `tests/live_station.rs`'s
//! `unary_call_provider_round_trip_against_the_real_fleet`). The
//! procedure name is unique per run (a station's DHT can hold stale
//! routing state for a fixed name from a prior run's now-dead
//! advertiser) — and it's this crate's own procedure, not a shared
//! fleet service, so this example never depends on anything else being
//! deployed.
//!
//! The provider `Session` is moved back OUT of its `tokio::spawn` task
//! and closed explicitly, rather than let it drop when the task ends --
//! see [`macula_rust::connection::Session`]'s own doc for why: dropping
//! the last handle closes the connection at once, which gives quinn's
//! send-scheduling no guarantee the RESULT this example just sent
//! actually reached the peer first. Confirmed live 2026-09-05:
//! under `#[tokio::main]`'s default multi-threaded runtime, a spawned
//! task with nothing after `serve_one_call().await` can complete (and
//! drop the session) within microseconds of the write, losing the reply
//! deterministically -- `tests/live_station.rs`'s own
//! `unary_call_provider_round_trip_multi_thread_runtime` reproduces this
//! and confirms the fix.
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
        // this task ends -- see this file's own doc comment.
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
