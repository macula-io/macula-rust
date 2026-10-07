//! A served handler learns who called only from the verified caller
//! (macula-rust#13). A caller that writes a text "caller" key into a map
//! payload, naming another node, has it removed before the handler runs, as
//! macula (12.11.1, `with_caller/2`) and macula-go remove it: for calls and
//! stream opens, clear and sealed. Every other key reaches the handler.

mod common;

use std::sync::Arc;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record::{self, read_procedure_advertisement, RecordType};
use macula_rust::seal::Keyring;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Call, Config, Link, LinkError, Offer, Seal, Served, Stream,
    StreamCall, StreamEvent,
};

/// A link as a new node, keyed with kem_advertise on when `keyring` is given.
async fn node(env: &TestStations, keyring: Option<Arc<Keyring>>) -> Result<Link, LinkError> {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.keyring = keyring;
    Link::dial(cfg).await
}

/// What a handler saw: the payload it was handed and the verified caller.
fn seen(payload: &Value, caller: [u8; 32]) -> Value {
    Value::Map(vec![
        (Value::text("payload"), payload.clone()),
        (Value::text("verified"), Value::Bytes(caller.to_vec())),
    ])
}

/// A payload whose "caller" names a node other than the sender.
fn forged(impostor: [u8; 32]) -> Value {
    Value::Map(vec![
        (Value::text("caller"), Value::Bytes(impostor.to_vec())),
        (Value::text("asked"), Value::text("hello")),
    ])
}

fn stripped() -> Value {
    Value::Map(vec![(Value::text("asked"), Value::text("hello"))])
}

async fn kem_key(link: &Link, procedure: &str) -> Vec<u8> {
    let (ads, _) = link
        .find_records_by_type(RecordType::PROCEDURE_ADVERTISEMENT)
        .await
        .unwrap();
    ads.iter()
        .map(|v| read_procedure_advertisement(v.record()).unwrap())
        .find(|ad| ad.procedure == procedure)
        .and_then(|ad| ad.kem_key)
        .map(|(key, _)| key)
        .expect("the advertisement names a KEM key")
}

/// The handler that answers what it saw, as a stream's one chunk.
async fn watch_seen(stream: Stream) -> Result<(), String> {
    let open = stream.request();
    let saw = seen(&open.payload, open.caller);
    let bytes = macula_rust::cbor::encode(&saw).map_err(|e| e.to_string())?;
    stream.send(&bytes).await.map_err(|e| e.to_string())
}

/// Serves "who" (unary) and "watch" (a server stream) on `provider`, each
/// answering what its handler saw; the handles and both procedure names.
async fn serve_seen(env: &TestStations, provider: &Link) -> ([Served; 2], String, String) {
    let who = record::own_procedure(&provider.node_id(), "who");
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let unary = handler(|r| async move { Ok(seen(&r.payload, r.caller)) });
    let served_who = provider
        .serve(Offer::unary(env.realm_id, &who, unary))
        .await
        .unwrap();
    let streamed = stream_handler(watch_seen);
    let served_watch = provider
        .serve(Offer::stream(
            env.realm_id,
            &watch,
            StreamMode::ServerStream,
            streamed,
        ))
        .await
        .unwrap();
    ([served_who, served_watch], who, watch)
}

/// What the "who" procedure answers `payload` sent under `seal`.
async fn call_who(
    env: &TestStations,
    caller: &Link,
    provider: [u8; 32],
    who: &str,
    payload: Value,
    seal: Seal,
) -> Value {
    caller
        .call(Call {
            realm: env.realm_id,
            procedure: who.to_string(),
            target: provider,
            payload,
            seal: Some(seal),
            ..Call::default()
        })
        .await
        .unwrap()
}

/// What the "watch" stream's handler saw of an open carrying `payload` under
/// `seal`, read back from its one chunk.
async fn open_watch(
    env: &TestStations,
    caller: &Link,
    provider: [u8; 32],
    watch: &str,
    payload: Value,
    seal: Seal,
) -> Value {
    let stream = caller
        .open_stream(StreamCall {
            realm: env.realm_id,
            procedure: watch.to_string(),
            target: provider,
            payload,
            seal: Some(seal.clone()),
            ..StreamCall::default()
        })
        .await
        .unwrap();
    match stream.recv().await {
        Ok(StreamEvent::Data {
            encoding: StreamEncoding::Raw,
            body: Value::Bytes(bytes),
        }) => macula_rust::cbor::decode(&bytes).unwrap(),
        other => panic!("a stream open, {seal:?}: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handler_never_sees_a_caller_the_sender_wrote() {
    let env = TestStations::start(Profile::PqHybrid);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring)).await.unwrap();
    let caller = node(&env, None).await.unwrap();
    let impostor = [9u8; 32];
    let (_served, who, watch) = serve_seen(&env, &provider).await;
    let key = kem_key(&caller, &who).await;
    let expected = seen(&stripped(), caller.node_id());
    let to = provider.node_id();

    for seal in [Seal::Clear, Seal::To(key.clone())] {
        let answered = call_who(&env, &caller, to, &who, forged(impostor), seal.clone()).await;
        assert_eq!(answered, expected, "a call, {seal:?}");
        let opened = open_watch(&env, &caller, to, &watch, forged(impostor), seal.clone()).await;
        assert_eq!(opened, expected, "a stream open, {seal:?}");
    }

    // Anything but a map payload reaches the handler as sent, and so does a
    // map without a text "caller" key.
    let untouched = [
        Value::text("caller"),
        Value::Map(vec![(Value::Int(1), Value::text("caller"))]),
    ];
    for payload in untouched {
        let answered = call_who(&env, &caller, to, &who, payload.clone(), Seal::Clear).await;
        assert_eq!(answered, seen(&payload, caller.node_id()), "{payload:?}");
    }
}
