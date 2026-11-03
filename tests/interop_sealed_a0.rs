//! Release A0 across SDKs: a Rust caller that has never seen a provider's key
//! recovers from an Erlang provider's signed refusal, and gets the answer.
//!
//! scripts/interop/sealed.sh starts a station and macula's
//! `erlang_sealed.escript serve_a0`: four procedures, `confidential =>
//! required` and `refusal_names_key => true`, so every clear request is
//! refused `sealed_required` carrying the key the provider holds
//! (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3, section 8.1). This file is the
//! caller that does not know that key: each program sends clear, is refused,
//! seals the same payload once more to the key in the refusal, and gets the
//! answer. macula-go runs the same four (`gosealed a0`); macula-rust#42
//! shipped the reading side, this is macula-rust#49's cross-SDK proof of it.
//!
//! Reads MACULA_RUST_SEALED_SEED (host:port),
//! MACULA_RUST_SEALED_STATION_ID, MACULA_RUST_SEALED_REALM,
//! MACULA_RUST_SEALED_PROFILE, MACULA_RUST_SEALED_PROVIDER (hex) and
//! MACULA_RUST_SEALED_KEM (the provider's own key, hex, as its serve printed
//! it).
//!
//! A required provider refuses every clear request, so an answer at all proves
//! the request reached it sealed to a key it holds. The call checks that key
//! against the provider's own, which this SDK hands up
//! (`Link::call_resealing`); the stream programs check the answer and the
//! stream's sealed state, since this SDK has no such report for a stream.

use std::sync::Arc;
use std::time::{Duration, Instant};

use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    Call, Called, Config, Link, LinkError, Seal, Stream, StreamCall, StreamEvent,
};
use macula_rust::transport::Target;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn hex32(name: &str) -> [u8; 32] {
    hex::decode(var(name))
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{name} must be 64 hex characters"))
}

fn hex_bytes(name: &str) -> Vec<u8> {
    hex::decode(var(name)).unwrap_or_else(|_| panic!("{name} must be hex"))
}

/// A link of its own to the interop station, as a caller that reads the
/// provider's advertisement itself: every request here names its target.
async fn dial() -> Link {
    let seed = var("MACULA_RUST_SEALED_SEED");
    let (host, port) = seed.rsplit_once(':').expect("host:port");
    let profile = Profile::parse(&var("MACULA_RUST_SEALED_PROFILE")).unwrap();
    let identity = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: host.to_string(),
        port: port.parse().unwrap(),
        profile,
        expected_node_id: hex32("MACULA_RUST_SEALED_STATION_ID"),
    };
    Link::dial(Config::new(target, identity, issuer))
        .await
        .unwrap()
}

/// A clear call to `procedure`, which a required provider refuses: seal it
/// once more to the key its refusal carries, and get the answer back. A call
/// that timed out is tried again until the deadline, as in
/// `tests/interop_sealed.rs`: the provider has advertised but its link may
/// still be warming up on a slow runner.
async fn clear_call(link: &Link, realm: [u8; 32], provider: [u8; 32], procedure: &str) -> Called {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let called = link
            .call_resealing(Call {
                realm,
                procedure: record::own_procedure(&provider, procedure),
                target: provider,
                payload: Value::Map(Vec::new()),
                timeout: Duration::from_secs(10),
                seal: Some(Seal::Clear),
                ..Call::default()
            })
            .await;
        println!(
            "a0 clear call: {:?}, key {:?} bytes",
            called.outcome,
            called.resealed_to.as_ref().map(Vec::len)
        );
        match &called.outcome {
            Err(LinkError::CallTimeout) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            _ => return called,
        }
    }
}

/// A clear open of `procedure`, `mode`, which a required provider refuses:
/// the stream reopens sealed behind the same handle, once the provider's
/// refusal has been read and answered. Until that first frame arrives the
/// open is still the clear one it was sent on.
async fn clear_open(
    link: &Link,
    realm: [u8; 32],
    provider: [u8; 32],
    procedure: &str,
    mode: StreamMode,
) -> Stream {
    let stream = link
        .open_stream(StreamCall {
            realm,
            procedure: record::own_procedure(&provider, procedure),
            target: provider,
            mode,
            payload: Value::Map(Vec::new()),
            deadline: Duration::from_secs(30),
            seal: Some(Seal::Clear),
            ..StreamCall::default()
        })
        .await
        .unwrap_or_else(|e| panic!("the clear open of {procedure}: {e}"));
    stream
}

/// The text a reply carries.
fn text(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        other => panic!("expected text, got {other:?}"),
    }
}

/// The bytes a data frame carries.
fn bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    }
}

/// The chunk a data frame carries, from `event`.
fn chunk_of(event: &StreamEvent) -> Vec<u8> {
    match event {
        StreamEvent::Data { body, .. } => bytes(body),
        other => panic!("expected a chunk, got {other:?}"),
    }
}

/// The text a reply carries, from `event`.
fn reply_of(event: &StreamEvent) -> String {
    match event {
        StreamEvent::Reply { payload } => text(payload),
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// Program 1, a clear call, resealed to the key its refusal carries: this
/// SDK hands that key up, so it is checked against the provider's own.
async fn a0_call(link: &Link, realm: [u8; 32], provider: [u8; 32], carried: &[u8]) {
    let called = clear_call(link, realm, provider, "vault").await;
    assert_eq!(
        called.outcome.expect("the clear call was not answered"),
        Value::text("kept by erlang")
    );
    assert_eq!(
        called.resealed_to.as_deref(),
        Some(carried),
        "the call resealed to a key other than the provider's own"
    );
}

/// Program 2, a clear open of a server stream, the same, the answer being the
/// proof.
async fn a0_open(link: &Link, realm: [u8; 32], provider: [u8; 32]) {
    let watch = clear_open(link, realm, provider, "watch", StreamMode::ServerStream).await;
    let chunk = watch.recv().await.expect("the server stream's chunk");
    assert_eq!(chunk_of(&chunk), b"chunk from erlang");
    assert!(watch.sealed(), "the server stream did not reopen sealed");
    let reply = watch.recv().await.expect("the server stream's reply");
    assert_eq!(reply_of(&reply), "streamed by erlang");
}

/// Program 3, a clear client stream that wrote its chunks and closed its side
/// before the refusal arrived: the sealed reopen replays them, in order, and
/// the provider's reply counts what it read.
async fn a0_client_stream(link: &Link, realm: [u8; 32], provider: [u8; 32]) {
    let count = clear_open(link, realm, provider, "count", StreamMode::ClientStream).await;
    for chunk in ["c1", "c2", "c3"] {
        count
            .send(chunk.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("the chunk {chunk}: {e}"));
    }
    count.close_send().await.expect("closing the caller's side");
    let counted = count.recv().await.expect("the counted reply");
    assert_eq!(
        reply_of(&counted),
        "c1,c2,c3",
        "the copy was not replayed in order"
    );
    assert!(count.sealed(), "the client stream did not reopen sealed");
}

/// Program 4, a clear bidi stream a provider answers only after the caller's
/// first chunk, which reaches it only through the sealed reopen.
async fn a0_bidi(link: &Link, realm: [u8; 32], provider: [u8; 32]) {
    let first = clear_open(link, realm, provider, "first", StreamMode::Bidi).await;
    first
        .send(b"hello")
        .await
        .expect("the caller's first chunk");
    let echo = first.recv().await.expect("the echoed chunk");
    assert_eq!(chunk_of(&echo), b"echo hello");
    let echoed = first.recv().await.expect("the bidi stream's reply");
    assert_eq!(reply_of(&echoed), "echoed");
    assert!(first.sealed(), "the bidi stream did not reopen sealed");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "interop: run by scripts/interop/sealed.sh"]
async fn a_clear_request_reaches_a_keyed_macula_provider_sealed() {
    let link = dial().await;
    let realm = hex32("MACULA_RUST_SEALED_REALM");
    let provider = hex32("MACULA_RUST_SEALED_PROVIDER");
    let carried = hex_bytes("MACULA_RUST_SEALED_KEM");

    a0_call(&link, realm, provider, &carried).await;
    a0_open(&link, realm, provider).await;
    a0_client_stream(&link, realm, provider).await;
    a0_bidi(&link, realm, provider).await;

    link.close("done").await.unwrap();
    println!("a0: all four clear requests came back sealed to the provider's key");
}
