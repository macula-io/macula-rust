//! The mobile bindings over the pool, as Kotlin and Swift reach them,
//! against macula-go's in-process stations (the core crate's
//! tests/common/lab.rs): node keys, a pool, calls to a handler the foreign
//! side implements, pubsub, streams, and records.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::lab::{Lab, LabStation};
use macula_rust::profile::Profile;
use macula_rust_ffi::{
    own_procedure, FfiCallHandler, FfiError, FfiNodeKey, FfiPool, FfiPoolOptions, FfiProfile,
    FfiRealmKey, FfiRequest, FfiSeed, FfiStream, FfiStreamEvent, FfiStreamHandler, FfiStreamMode,
    FfiValue,
};

const ORG_PROCEDURE: &str = "mcl-echo/echo";
const TOPIC: &str = "mcl-rust/ffi/greeting_sent_v1";

fn seed(s: &LabStation) -> FfiSeed {
    FfiSeed {
        host: s.host.clone(),
        port: s.port,
        node_id: s.node_id.to_vec(),
    }
}

fn options() -> FfiPoolOptions {
    FfiPoolOptions {
        respawn_delay_ms: 100,
        connect_timeout_ms: 15_000,
        ..FfiPoolOptions::default()
    }
}

async fn pool(key: &Arc<FfiNodeKey>, s: &LabStation, opts: FfiPoolOptions) -> Arc<FfiPool> {
    FfiPool::connect(key.clone(), vec![seed(s)], opts)
        .await
        .unwrap()
}

/// A foreign handler: echoes, or refuses "fail".
struct Echo;

#[async_trait::async_trait]
impl FfiCallHandler for Echo {
    async fn handle(&self, request: FfiRequest) -> Result<FfiValue, FfiError> {
        if request.payload == FfiValue::Text("fail".into()) {
            return Err(FfiError::Handler {
                message: "refused by the handler".into(),
            });
        }
        Ok(FfiValue::Fields(vec![
            macula_rust_ffi::FfiMapEntry {
                key: FfiValue::Text("echo".into()),
                value: request.payload,
            },
            macula_rust_ffi::FfiMapEntry {
                key: FfiValue::Text("caller".into()),
                value: FfiValue::Bytes(request.caller),
            },
        ]))
    }
}

/// A foreign stream handler: sends "a" then "b".
struct Chunks;

#[async_trait::async_trait]
impl FfiStreamHandler for Chunks {
    async fn handle(&self, stream: Arc<FfiStream>) -> Result<(), FfiError> {
        for chunk in ["a", "b"] {
            stream.send(chunk.as_bytes().to_vec()).await?;
        }
        Ok(())
    }
}

#[test]
fn a_node_key_is_made_in_either_profile_and_survives_its_key_file() {
    let dir = tempfile::tempdir().unwrap();
    for profile in [FfiProfile::PqPure, FfiProfile::PqHybrid] {
        let key = FfiNodeKey::generate(profile).unwrap();
        assert_eq!(key.profile(), profile);
        assert_eq!(key.node_id().len(), 32);
        assert_eq!(key.node_id()[0], 0, "the puzzle's leading zero bits");
        let path = dir.path().join(format!("{profile:?}.key"));
        key.save(path.to_string_lossy().into()).unwrap();
        let loaded = FfiNodeKey::load(path.to_string_lossy().into(), profile).unwrap();
        assert_eq!(loaded.node_id(), key.node_id());
    }
    let missing = FfiNodeKey::load(
        dir.path().join("none").to_string_lossy().into(),
        FfiProfile::PqPure,
    );
    assert!(matches!(missing, Err(FfiError::Key { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_reaches_a_foreign_handler_in_the_provider_s_own_namespace() {
    let lab = Lab::start(Profile::PqPure);
    let (serving, callers) = (lab.station("ffi serving"), lab.station("ffi callers"));
    lab.share(&[&serving, &callers]);
    let realm = vec![0x42; 32];
    let provider_key = FfiNodeKey::generate(FfiProfile::PqPure).unwrap();
    let provider = pool(&provider_key, &serving, options()).await;
    let ring = own_procedure(provider.node_id(), "ring".into()).unwrap();
    let served = provider
        .serve(realm.clone(), ring.clone(), Arc::new(Echo))
        .await
        .unwrap();

    let caller_key = FfiNodeKey::generate(FfiProfile::PqPure).unwrap();
    let caller = pool(&caller_key, &callers, options()).await;
    let answered = caller
        .call(
            realm.clone(),
            ring.clone(),
            FfiValue::Text("hi".into()),
            None,
            5_000,
        )
        .await
        .unwrap();
    let FfiValue::Fields(fields) = answered else {
        panic!("{answered:?}")
    };
    assert_eq!(fields[0].value, FfiValue::Text("hi".into()));
    assert_eq!(fields[1].value, FfiValue::Bytes(caller.node_id()));

    match caller
        .call(
            realm.clone(),
            ring.clone(),
            FfiValue::Text("fail".into()),
            None,
            5_000,
        )
        .await
    {
        Err(FfiError::Provider { code, detail, .. }) => {
            assert_eq!(code, "handler_error");
            assert!(detail
                .unwrap_or_default()
                .contains("refused by the handler"));
        }
        other => panic!("{other:?}"),
    }
    let providers = caller.providers(realm.clone(), ring.clone()).await.unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].node, provider.node_id());
    assert_eq!(providers[0].station, serving.node_id.to_vec());

    served.stop().await.unwrap();
    // An org procedure in a realm the pool pins no key for is refused.
    let unpinned = caller
        .call(realm, ORG_PROCEDURE.into(), FfiValue::Null, None, 2_000)
        .await;
    assert!(
        matches!(unpinned, Err(FfiError::NoRealmKey)),
        "{unpinned:?}"
    );
    caller.close().await;
    provider.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_org_procedure_is_served_under_the_pinned_realm_key() {
    let lab = Lab::start(Profile::PqHybrid);
    let s = lab.station("ffi org");
    let realm = lab.realm("ffi-org", "mcl-echo");
    let trust = FfiPoolOptions {
        realm_trust: vec![FfiRealmKey {
            realm: realm.id.to_vec(),
            key: realm.key.clone(),
        }],
        ..options()
    };
    let provider_key = FfiNodeKey::generate(FfiProfile::PqHybrid).unwrap();
    let provider_id: [u8; 32] = provider_key.node_id().try_into().unwrap();
    lab.admit(&realm, &s, &[provider_id]);
    let provider = pool(&provider_key, &s, trust.clone()).await;
    provider
        .serve(realm.id.to_vec(), ORG_PROCEDURE.into(), Arc::new(Echo))
        .await
        .unwrap();
    let caller = pool(
        &FfiNodeKey::generate(FfiProfile::PqHybrid).unwrap(),
        &s,
        trust,
    )
    .await;
    let answered = caller
        .call(
            realm.id.to_vec(),
            ORG_PROCEDURE.into(),
            FfiValue::Int(7),
            None,
            5_000,
        )
        .await
        .unwrap();
    let FfiValue::Fields(fields) = answered else {
        panic!("{answered:?}")
    };
    assert_eq!(fields[0].value, FfiValue::Int(7));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_hears_a_publication_once() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("ffi pubsub");
    let realm = vec![5; 32];
    let listener = pool(
        &FfiNodeKey::generate(FfiProfile::PqPure).unwrap(),
        &s,
        options(),
    )
    .await;
    let publisher = pool(
        &FfiNodeKey::generate(FfiProfile::PqPure).unwrap(),
        &s,
        options(),
    )
    .await;
    let sub = listener
        .subscribe(realm.clone(), TOPIC.into())
        .await
        .unwrap();
    let me: [u8; 32] = listener.node_id().try_into().unwrap();
    let r: [u8; 32] = realm.clone().try_into().unwrap();
    for _ in 0..200 {
        if lab.subscribed(&s, &me, &r, TOPIC) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    publisher
        .publish(
            realm.clone(),
            TOPIC.into(),
            FfiValue::Text("hello".into()),
            None,
        )
        .await
        .unwrap();
    let event = sub.next(5_000).await.unwrap().expect("the publication");
    assert_eq!(event.payload, FfiValue::Text("hello".into()));
    assert_eq!(event.publisher, publisher.node_id());
    assert_eq!(event.topic, TOPIC);
    assert!(sub.next(300).await.unwrap().is_none(), "heard once");
    sub.unsubscribe().await.unwrap();
    assert!(matches!(sub.next(100).await, Err(FfiError::Closed)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_from_a_foreign_handler_is_heard_and_released() {
    let lab = Lab::start(Profile::PqPure);
    let (serving, callers) = (
        lab.station("ffi stream serving"),
        lab.station("ffi stream callers"),
    );
    lab.share(&[&serving, &callers]);
    let realm = vec![6; 32];
    let provider = pool(
        &FfiNodeKey::generate(FfiProfile::PqPure).unwrap(),
        &serving,
        options(),
    )
    .await;
    let watch = own_procedure(provider.node_id(), "watch".into()).unwrap();
    provider
        .serve_stream(
            realm.clone(),
            watch.clone(),
            FfiStreamMode::ServerStream,
            Arc::new(Chunks),
        )
        .await
        .unwrap();
    let caller = pool(
        &FfiNodeKey::generate(FfiProfile::PqPure).unwrap(),
        &callers,
        options(),
    )
    .await;
    let stream = caller
        .open_stream(
            realm,
            watch,
            FfiStreamMode::ServerStream,
            FfiValue::Null,
            None,
            0,
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    loop {
        match stream.recv(5_000).await.unwrap() {
            FfiStreamEvent::Data {
                body: FfiValue::Bytes(b),
                ..
            } => got.push(b),
            FfiStreamEvent::End { .. } => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(got, vec![b"a".to_vec(), b"b".to_vec()]);
    assert!(matches!(
        stream.recv(1_000).await,
        Err(FfiError::EndOfStream)
    ));
    for _ in 0..100 {
        if lab.relayed(&serving) == 0 && lab.relayed(&callers) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the stream was not released within 2 s");
}

#[tokio::test(flavor = "multi_thread")]
async fn records_go_through_the_pool() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("ffi records");
    let p = pool(
        &FfiNodeKey::generate(FfiProfile::PqPure).unwrap(),
        &s,
        options(),
    )
    .await;
    let endpoints = p
        .find_records_by_type(macula_rust::record::RecordType::STATION_ENDPOINT.0)
        .await
        .unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].signer, s.node_id.to_vec());
    let missing = p.find_record(vec![0x22; 32]).await;
    assert!(
        matches!(missing, Err(FfiError::RecordNotFound)),
        "{missing:?}"
    );
    let refused = p.put_record(b"not a record".to_vec()).await;
    assert!(refused.is_err());
    let bad_id = p.find_record(vec![1; 3]).await;
    assert!(
        matches!(
            bad_id,
            Err(FfiError::WrongByteLength {
                expected: 32,
                actual: 3
            })
        ),
        "{bad_id:?}"
    );
}
