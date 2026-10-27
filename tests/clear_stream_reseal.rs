//! A clear stream a keyed provider refuses sealed_required naming its KEM
//! key in the refusal's signed tbs reopens once, sealed to that key, behind
//! the same handle, and replays what it already sent, its end included, in
//! order (release A0, DESIGN_E2E_SEALED_BY_DEFAULT section 3,
//! macula-rust#42), against macula-go's in-process stations (tests/common).
//! The provider names its key only because the test sets it to; release A
//! makes it the rule. A refusal that names no key ends the stream as the
//! provider's own.

mod common;

use std::sync::Arc;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::seal::Keyring;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    stream_handler, Confidentiality, Config, Link, LinkError, Offer, Seal, Served, Stream,
    StreamCall, StreamEvent, StreamHandler,
};

/// A link as a new node; with `keyring`, it advertises its key and, when
/// `names_key`, names it in a sealed_required refusal.
async fn node(env: &TestStations, keyring: Option<Arc<Keyring>>, names_key: bool) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.refusal_names_key = names_key;
    cfg.keyring = keyring;
    Link::dial(cfg).await.unwrap()
}

/// Serves `procedure` as a required stream of `mode` run by `handler`.
async fn serve(
    env: &TestStations,
    provider: &Link,
    procedure: &str,
    mode: StreamMode,
    handler: StreamHandler,
) -> Served {
    let mut offer = Offer::stream(env.realm_id, procedure, mode, handler);
    offer.confidential = Confidentiality::Required;
    provider.serve(offer).await.unwrap()
}

fn clear_open(
    env: &TestStations,
    provider: &Link,
    procedure: &str,
    mode: StreamMode,
) -> StreamCall {
    StreamCall {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        mode,
        payload: Value::Bytes(b"one".to_vec()),
        seal: Some(Seal::Clear),
        ..StreamCall::default()
    }
}

fn raw(b: &[u8]) -> StreamEvent {
    StreamEvent::Data {
        encoding: StreamEncoding::Raw,
        body: Value::Bytes(b.to_vec()),
    }
}

/// Sends the open's payload and whether the stream came sealed.
async fn asked_and_sealed(stream: Stream) -> Result<(), String> {
    let Value::Bytes(asked) = stream.request().payload.clone() else {
        return Err("no payload".into());
    };
    let sealed = [u8::from(stream.sealed())];
    for chunk in [&asked[..], &sealed[..]] {
        stream.send(chunk).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Replies the bytes the caller sent and whether the stream came sealed,
/// once the caller has ended its sending.
async fn count_bytes(stream: Stream) -> Result<(), String> {
    let mut total = 0usize;
    while let Ok(event) = stream.recv().await {
        match event {
            StreamEvent::Data {
                body: Value::Bytes(b),
                ..
            } => total += b.len(),
            StreamEvent::End { .. } => break,
            _ => {}
        }
    }
    let answer = Value::Map(vec![
        (Value::text("total"), Value::Int(total as i128)),
        (
            Value::text("sealed"),
            Value::Int(i128::from(stream.sealed())),
        ),
    ]);
    stream.reply(answer).await.map_err(|e| e.to_string())
}

/// Waits for the caller's first chunk and sends it back.
async fn echo_first(stream: Stream) -> Result<(), String> {
    let first = stream.recv().await.map_err(|e| e.to_string())?;
    let StreamEvent::Data {
        body: Value::Bytes(b),
        ..
    } = first
    else {
        return Err("no chunk first".into());
    };
    stream.send(&b).await.map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_open_reseals_to_the_key_its_refusal_names() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let env = TestStations::start(profile);
        let keyring = Arc::new(Keyring::system(profile).unwrap());
        let provider = node(&env, Some(keyring.clone()), true).await;
        let caller = node(&env, None, false).await;
        let watch = record::own_procedure(&provider.node_id(), "watch");
        let handler = stream_handler(asked_and_sealed);
        let _served = serve(&env, &provider, &watch, StreamMode::ServerStream, handler).await;

        let open = clear_open(&env, &provider, &watch, StreamMode::ServerStream);
        let stream = caller.open_stream(open).await.unwrap();
        assert_eq!(stream.recv().await.unwrap(), raw(b"one"), "{profile:?}");
        assert_eq!(
            stream.recv().await.unwrap(),
            raw(&[1]),
            "{profile:?}: sealed"
        );
        assert!(stream.sealed());
        let report = stream.report().unwrap();
        assert_eq!(report.sealed, 1);
        assert_eq!(report.seal_key_id, Some(keyring.current_id()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_client_stream_that_wrote_and_closed_replays_it_all_sealed() {
    let env = TestStations::start(Profile::PqHybrid);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let count = record::own_procedure(&provider.node_id(), "count");
    let handler = stream_handler(count_bytes);
    let _served = serve(&env, &provider, &count, StreamMode::ClientStream, handler).await;

    let open = clear_open(&env, &provider, &count, StreamMode::ClientStream);
    let upload = caller.open_stream(open).await.unwrap();
    for chunk in ["ab", "cde", "f"] {
        upload.send(chunk.as_bytes()).await.unwrap();
    }
    upload.close_send().await.unwrap();
    let StreamEvent::Reply { payload } = upload.recv().await.unwrap() else {
        panic!("no reply");
    };
    assert_eq!(payload.get("total"), Some(&Value::Int(6)), "in order, once");
    assert_eq!(payload.get("sealed"), Some(&Value::Int(1)));
    assert!(upload.sealed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_bidi_stream_whose_provider_waits_for_its_first_chunk_completes() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let echo = record::own_procedure(&provider.node_id(), "echo");
    let _served = serve(
        &env,
        &provider,
        &echo,
        StreamMode::Bidi,
        stream_handler(echo_first),
    )
    .await;

    let open = clear_open(&env, &provider, &echo, StreamMode::Bidi);
    let stream = caller.open_stream(open).await.unwrap();
    stream.send(b"first").await.unwrap();
    assert_eq!(stream.recv().await.unwrap(), raw(b"first"));
    assert!(stream.sealed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_refusal_naming_no_key_stands_as_sealed_required() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), false).await;
    let caller = node(&env, None, false).await;
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let handler = stream_handler(asked_and_sealed);
    let _served = serve(&env, &provider, &watch, StreamMode::ServerStream, handler).await;

    let open = clear_open(&env, &provider, &watch, StreamMode::ServerStream);
    let stream = caller.open_stream(open).await.unwrap();
    match stream.recv().await {
        Err(LinkError::Stream { code, .. }) => assert_eq!(code, "sealed_required"),
        other => panic!("{other:?}"),
    }
    assert!(!stream.sealed());
}
