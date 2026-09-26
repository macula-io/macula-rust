//! A link to one macula 12 station, against macula-go's in-process stations
//! (tests/common, the Go teststation): the v4 handshake over QUIC, DHT calls,
//! pubsub, serving under an org and in a node's own namespace, and streams,
//! each stream released.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode, StreamRole};
use macula_rust::handshake::HandshakeError;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record::{self, new_node_record, NodeRecordOptions, RecordType};
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Call, Config, Link, LinkError, Offer, Publication, StreamCall,
    StreamEvent,
};

/// A link as a new node: its own identity key and issuer.
async fn node(env: &TestStations, station: usize) -> Link {
    let identity = NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap();
    link_as(env, station, identity).await.unwrap()
}

async fn link_as(env: &TestStations, station: usize, identity: NodeKey) -> Result<Link, LinkError> {
    let identity = Arc::new(identity);
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    Link::dial(Config::new(env.target(station), identity, issuer)).await
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..400 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("never: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_links_to_a_station_it_pinned_in_either_profile() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let env = TestStations::start(profile);
        let link = node(&env, 0).await;
        assert_eq!(link.station_node_id(), env.stations[0].node_id);
        link.close("done").await.unwrap();
        assert!(matches!(link.error(), Some(LinkError::Closed)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_station_that_is_not_the_node_pinned_is_refused() {
    let env = TestStations::start(Profile::PqPure);
    let mut target = env.target(0);
    target.expected_node_id = env.stations[1].node_id;
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let refused = Link::dial(Config::new(target, identity, issuer)).await;
    assert!(matches!(
        refused,
        Err(LinkError::Handshake(
            HandshakeError::PeerIdentityMismatch { .. }
        ))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dht_holds_verified_records() {
    let env = TestStations::start(Profile::PqPure);
    let identity = NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap();
    let node_id = identity.node_id().unwrap();
    let signed = record::sign(
        &new_node_record(&node_id, &[], 0, &NodeRecordOptions::default()).unwrap(),
        &identity,
    )
    .unwrap();
    let link = link_as(&env, 0, identity).await.unwrap();

    let (endpoints, dropped) = link
        .find_records_by_type(RecordType::STATION_ENDPOINT)
        .await
        .unwrap();
    assert_eq!(dropped, 0);
    let mut signers: Vec<[u8; 32]> = endpoints
        .iter()
        .map(|r| r.record().signed.as_ref().unwrap().key_id)
        .collect();
    signers.sort();
    let mut stations: Vec<[u8; 32]> = env.stations.iter().map(|s| s.node_id).collect();
    stations.sort();
    assert_eq!(signers, stations);

    assert!(matches!(
        link.find_record(&[0x22; 32]).await,
        Err(LinkError::RecordNotFound)
    ));
    link.put_record(&record::encode(&signed).unwrap())
        .await
        .unwrap();
    let found = link.find_record(&node_id).await.unwrap();
    assert_eq!(found.record().version, signed.version);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_nobody_serves_is_answered_with_the_station_s_relay_error() {
    let env = TestStations::start(Profile::PqPure);
    let link = node(&env, 0).await;
    let outcome = link
        .call(Call {
            realm: env.realm_id,
            procedure: format!("{}/nothing", env.org),
            target: [9; 32],
            payload: Value::Null,
            ..Call::default()
        })
        .await;
    match outcome {
        Err(LinkError::Relay { code, reported_by }) => {
            assert_eq!(code, "unknown_next_peer");
            assert_eq!(reported_by, env.stations[0].node_id);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_is_heard_once_by_each_subscriber() {
    let env = TestStations::start(Profile::PqHybrid);
    let listener = node(&env, 0).await;
    let publisher = node(&env, 0).await;
    let topic = "mcl-rust/tests/greeting_sent_v1";
    let mut sub = listener.subscribe(&env.realm_id, topic).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    publisher
        .publish(Publication {
            realm: env.realm_id,
            topic: topic.to_string(),
            payload: Value::text("hi"),
            ttl_ms: None,
        })
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.payload, Value::text("hi"));
    assert_eq!(event.publisher, publisher.node_id());
    assert_eq!(event.topic, topic);
    assert!(tokio::time::timeout(Duration::from_millis(300), sub.recv())
        .await
        .is_err());
    sub.unsubscribe().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_procedure_in_a_node_s_own_namespace_is_served_and_called() {
    let env = TestStations::start(Profile::PqPure);
    let provider = node(&env, 0).await;
    let caller = node(&env, 0).await;
    let ring = record::own_procedure(&provider.node_id(), "ring");
    let served = provider
        .serve(Offer::unary(
            env.realm_id,
            &ring,
            handler(|r| async move {
                if r.payload == Value::text("fail") {
                    return Err("refused by the handler".to_string());
                }
                Ok(Value::Map(vec![(
                    Value::text("rung_by"),
                    Value::Bytes(r.caller.to_vec()),
                )]))
            }),
        ))
        .await
        .unwrap();
    let call = |payload: Value| Call {
        realm: env.realm_id,
        procedure: ring.clone(),
        target: provider.node_id(),
        payload,
        ..Call::default()
    };
    let answered = caller.call(call(Value::Null)).await.unwrap();
    assert_eq!(
        answered.get("rung_by"),
        Some(&Value::Bytes(caller.node_id().to_vec()))
    );
    match caller.call(call(Value::text("fail"))).await {
        Err(LinkError::Provider { code, detail, .. }) => {
            assert_eq!(code, "handler_error");
            assert_eq!(detail.as_deref(), Some("refused by the handler"));
        }
        other => panic!("{other:?}"),
    }
    // Withdrawn, the procedure is no longer routed to the provider.
    served.stop().await.unwrap();
    assert!(matches!(
        caller.call(call(Value::Null)).await,
        Err(LinkError::Relay { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_org_procedure_is_served_once_the_org_delegates_to_the_node() {
    let env = TestStations::start(Profile::PqHybrid);
    let identity = NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap();
    env.admit(&identity.node_id().unwrap());
    let provider = link_as(&env, 0, identity).await.unwrap();
    let caller = node(&env, 0).await;
    let procedure = format!("{}/echo", env.org);
    let mut offer = Offer::unary(
        env.realm_id,
        &procedure,
        handler(|r| async move { Ok(r.payload) }),
    );
    offer.realm_key = Some(env.realm_key.clone());
    let served = provider.serve(offer).await.unwrap();
    let answered = caller
        .call(Call {
            realm: env.realm_id,
            procedure,
            target: provider.node_id(),
            payload: Value::text("hello"),
            ..Call::default()
        })
        .await
        .unwrap();
    assert_eq!(answered, Value::text("hello"));
    served.stop().await.unwrap();

    // Without the realm key, an org procedure is not offered at all.
    let bare = Offer::unary(
        env.realm_id,
        &format!("{}/other", env.org),
        handler(|r| async move { Ok(r.payload) }),
    );
    assert!(matches!(
        provider.serve(bare).await,
        Err(LinkError::InvalidOffer)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_deliver_their_frames_and_are_released() {
    let env = TestStations::start(Profile::PqPure);
    let provider = node(&env, 0).await;
    let caller = node(&env, 0).await;
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let count = record::own_procedure(&provider.node_id(), "count");
    let _watch = provider
        .serve(Offer::stream(
            env.realm_id,
            &watch,
            StreamMode::ServerStream,
            stream_handler(|stream| async move {
                for chunk in ["one", "two", "three"] {
                    stream
                        .send(chunk.as_bytes())
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            }),
        ))
        .await
        .unwrap();
    let _count = provider
        .serve(Offer::stream(
            env.realm_id,
            &count,
            StreamMode::ClientStream,
            stream_handler(|stream| async move {
                let mut total = 0i128;
                while let Ok(event) = stream.recv().await {
                    match event {
                        StreamEvent::Data {
                            body: Value::Bytes(b),
                            ..
                        } => total += b.len() as i128,
                        StreamEvent::End { .. } => break,
                        _ => {}
                    }
                }
                stream
                    .reply(Value::Int(total))
                    .await
                    .map_err(|e| e.to_string())
            }),
        ))
        .await
        .unwrap();

    let open = |procedure: &str, mode| StreamCall {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        mode,
        payload: Value::Null,
        ..StreamCall::default()
    };
    let stream = caller
        .open_stream(open(&watch, StreamMode::ServerStream))
        .await
        .unwrap();
    let mut got = Vec::new();
    loop {
        match stream.recv().await.unwrap() {
            StreamEvent::Data {
                body: Value::Bytes(b),
                encoding: StreamEncoding::Raw,
            } => got.push(b),
            StreamEvent::End { role } => {
                assert_eq!(role, StreamRole::Both);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        got,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );

    let upload = caller
        .open_stream(open(&count, StreamMode::ClientStream))
        .await
        .unwrap();
    for chunk in ["ab", "cde", "f"] {
        upload.send(chunk.as_bytes()).await.unwrap();
    }
    upload.close_send().await.unwrap();
    assert_eq!(
        upload.recv().await.unwrap(),
        StreamEvent::Reply {
            payload: Value::Int(6)
        }
    );

    // A mode the provider does not serve is refused.
    let wrong = caller
        .open_stream(open(&watch, StreamMode::Bidi))
        .await
        .unwrap();
    match wrong.recv().await {
        Err(LinkError::Stream { code, .. }) => assert_eq!(code, "mode_mismatch"),
        other => panic!("{other:?}"),
    }
    eventually("every stream released", || env.relayed() == 0).await;
}
