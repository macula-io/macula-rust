//! Proves `direct_dial::call_with_ucan` actually reaches a UCAN-gated
//! procedure that plain `direct_dial::call` cannot -- the gap this
//! function closes (PLAN_CLOSE_SERVICE_AUTH_GAPS.md Phase 0,
//! macula-io/macula-architecture): every hecate-om capability is
//! advertised via `advertise_direct`, and until this function existed,
//! nothing in this crate could attach a token to a direct-dial call at
//! all -- a `ucan_required` capability was reachable in name only. Three
//! assertions against the live fleet: an unauthorized plain `call` is
//! refused, a `call_with_ucan` presenting a token from the WRONG issuer is
//! refused too (not just "any non-empty token passes"), and a
//! correctly-issued token gets a real result.
//!
//! Not run by default CI -- `#[ignore]`d, matching this crate's other live
//! tests. Run explicitly with
//! `cargo test --test live_direct_dial_ucan -- --ignored --nocapture`.
//!
//! MUST use `flavor = "multi_thread"` -- found live building this test: a
//! provider `Session` moved into a spawned task blocking inside
//! `serve_one_call_gated` starves a CONCURRENT resolver session's own DHT
//! resolution on tokio's default single-threaded (current_thread) test
//! runtime, failing with `StationEndpointNotFound` even though the record
//! is real and freshly published (confirmed by isolating it: the identical
//! resolve succeeds instantly with no concurrent task, and with a
//! concurrent task that does nothing network-related; it only breaks once
//! a spawned task owns and blocks a `Session`). Not fleet flakiness --
//! reproduced identically against two different stations, while an
//! unrelated pre-existing test passed cleanly against both at the same
//! moment. This crate's other live tests never spawn a task holding a
//! `Session` alongside other concurrent network I/O, so this is the first
//! to hit it.

use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::connection::{self, CallHandler};
use macula_rust::direct_dial;
use macula_rust::frame::CallResponse;
use macula_rust::identity::KeyPair;
use macula_rust::transport::Trust;
use macula_rust::ucan;

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires network access to a live macula-station"]
async fn ucan_gated_capability_reachable_only_through_call_with_ucan() {
    // Arc'd: KeyPair isn't Clone, and the provider identity is needed
    // inside 3 separate spawned serve tasks below.
    let provider_id = std::sync::Arc::new(KeyPair::generate_with_default_puzzle());
    let caller_id = KeyPair::generate_with_default_puzzle();
    let issuer_id = KeyPair::generate_with_default_puzzle();
    let wrong_issuer_id = KeyPair::generate_with_default_puzzle();
    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "live_direct_dial_ucan.gated.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let valid_token = ucan::create(
        &hex::encode(issuer_id.node_id()),
        &hex::encode(caller_id.node_id()),
        vec![ucan::Capability {
            with: "mri:test:live".into(),
            can: "call".into(),
        }],
        &issuer_id,
        ucan::CreateOpts::default(),
    )
    .expect("mint valid token");
    let wrong_issuer_token = ucan::create(
        &hex::encode(wrong_issuer_id.node_id()),
        &hex::encode(caller_id.node_id()),
        vec![ucan::Capability {
            with: "mri:test:live".into(),
            can: "call".into(),
        }],
        &wrong_issuer_id,
        ucan::CreateOpts::default(),
    )
    .expect("mint wrong-issuer token");

    let provider = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &provider_id)
        .await
        .expect("provider handshake should succeed");
    direct_dial::advertise_direct(
        &provider,
        &provider_id,
        realm,
        &procedure,
        Duration::from_secs(3600),
    )
    .await
    .expect("advertise_direct should succeed");

    let required_policy = ucan::Policy::required(issuer_id.node_id());
    let echo: CallHandler = std::sync::Arc::new(|payload: Value| {
        Box::pin(async move { Ok(Value::Map(vec![]).with_field("echo", payload)) })
    });
    let lookup = {
        let procedure = procedure.clone();
        let echo = echo.clone();
        move |_realm: &[u8; 32], proc: &str| {
            if proc == procedure {
                Some(echo.clone())
            } else {
                None
            }
        }
    };
    let policy = {
        let procedure = procedure.clone();
        move |_realm: &[u8; 32], proc: &str| {
            if proc == procedure {
                required_policy.clone()
            } else {
                ucan::Policy::open()
            }
        }
    };

    // serve_one_call_gated blocks waiting for an inbound call, so it must
    // run CONCURRENTLY with the caller's own connect+call below, not
    // before it -- spawned as a task, handing `provider` back out (and
    // in again for the next round) via the JoinHandle, matching Go's
    // goroutine+channel `serve()` helper in the equivalent live test.
    //
    // The 300ms sleep after every round matches examples/ucan.rs's own
    // documented reason: `Session` has no `Drop` impl, so returning
    // (and dropping `provider`, here via the task's own scope on every
    // round including the reassignments below) immediately after a
    // reply is sent can tear down the QUIC connection before that reply
    // frame actually flushes to the peer. Found live while building this
    // test: an ungated `serve_one_call`/plain `call` round-trip 3x with
    // no delay was fine, but a GATED round's own RESULT reply (not its
    // rejection replies, which apparently take a different, already-
    // flushed path) was silently lost without this -- narrowed to
    // exactly this race by direct experiment, not assumed.
    let provider_id2 = provider_id.clone();
    let lookup1 = lookup.clone();
    let policy1 = policy.clone();
    let serve1 = tokio::spawn(async move {
        let r = provider
            .serve_one_call_gated(lookup1, policy1, &provider_id2, Duration::from_secs(15))
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        r.map(|_| provider)
    });

    // 1. Unauthorized: plain `call` cannot even attach a token.
    let resolver1 = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_id)
        .await
        .expect("caller handshake #1 should succeed");
    let resp = direct_dial::call(
        &resolver1,
        &caller_id,
        realm,
        &procedure,
        Value::text("no token"),
        Duration::from_secs(12),
    )
    .await
    .expect("plain call should get a BOLT#4 response, not a transport error");
    match resp {
        CallResponse::Error { .. } => {}
        CallResponse::Result { .. } => {
            panic!("plain call against a gated procedure unexpectedly SUCCEEDED")
        }
    }
    println!("OBSERVED: plain call against a gated procedure was refused, as expected");
    let provider = serve1
        .await
        .expect("serve task #1 should not panic")
        .expect("serve_one_call_gated (unauthorized tick) should not error");

    // 2. Wrong issuer.
    let provider_id2 = provider_id.clone();
    let lookup2 = lookup.clone();
    let policy2 = policy.clone();
    let serve2 = tokio::spawn(async move {
        let r = provider
            .serve_one_call_gated(lookup2, policy2, &provider_id2, Duration::from_secs(15))
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        r.map(|_| provider)
    });
    let resolver2 = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_id)
        .await
        .expect("caller handshake #2 should succeed");
    let resp = direct_dial::call_with_ucan(
        &resolver2,
        &caller_id,
        realm,
        &procedure,
        Value::text("wrong issuer"),
        Duration::from_secs(12),
        wrong_issuer_token,
    )
    .await
    .expect("call_with_ucan (wrong issuer) should get a BOLT#4 response, not a transport error");
    match resp {
        CallResponse::Error { .. } => {}
        CallResponse::Result { .. } => {
            panic!("call_with_ucan with a wrong-issuer token unexpectedly SUCCEEDED")
        }
    }
    println!(
        "OBSERVED: call_with_ucan with a token from the wrong issuer was refused, as expected"
    );
    let provider = serve2
        .await
        .expect("serve task #2 should not panic")
        .expect("serve_one_call_gated (wrong-issuer tick) should not error");

    // 3. Authorized: the actual fix under test.
    let provider_id2 = provider_id.clone();
    let serve3 = tokio::spawn(async move {
        let r = provider
            .serve_one_call_gated(lookup, policy, &provider_id2, Duration::from_secs(15))
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        r
    });
    let resolver3 = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_id)
        .await
        .expect("caller handshake #3 should succeed");
    let call_fut = direct_dial::call_with_ucan(
        &resolver3,
        &caller_id,
        realm,
        &procedure,
        Value::text("hello gated direct-dial"),
        Duration::from_secs(12),
        valid_token,
    );
    let (call_result, serve_result) = tokio::join!(call_fut, serve3);
    let resp = call_result
        .expect("call_with_ucan (authorized) should succeed -- this is the fix under test");
    match resp {
        CallResponse::Result { payload, .. } => {
            let echoed = payload
                .get("echo")
                .expect("reply payload missing echo field");
            assert_eq!(*echoed, Value::text("hello gated direct-dial"));
        }
        CallResponse::Error { code, name, .. } => {
            panic!("call_with_ucan (authorized) returned a BOLT#4 ERROR instead of a result: code={code} name={name}")
        }
    }
    println!(
        "OBSERVED: a UCAN-gated capability, advertised only via advertise_direct, was reached and answered through call_with_ucan end to end"
    );
    serve_result
        .expect("serve task #3 should not panic")
        .expect("serve_one_call_gated (authorized tick) should not error");
}
