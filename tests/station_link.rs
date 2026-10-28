//! A link to one macula 12 station, against macula-go's in-process stations
//! (tests/common, the Go teststation): the v4 handshake over QUIC, DHT calls,
//! pubsub, serving under an org and in a node's own namespace, and streams,
//! each stream released.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::lab::{Lab, LabStation};
use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::RegisterKind;
use macula_rust::frame::{Payload, StreamEncoding, StreamMode, StreamRole};
use macula_rust::handshake::HandshakeError;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record::{self, new_node_record, NodeRecordOptions, RecordType};
use macula_rust::seal;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Admission, AdmissionLimits, Call, ConfidentialityError,
    ConfidentialityReason, Config, Link, LinkError, Offer, Publication, Request, Seal, Stream,
    StreamCall, StreamEvent,
};
use macula_rust::transport::Target;
use tokio::sync::Semaphore;

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
        // Wire 1.0 has one handshake version, 5, bound to the TLS session.
        assert_eq!(link.handshake_version(), 5, "{profile:?}");
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
            seal: Some(Seal::Clear),
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
    // subscribe returns once the station has accepted the SUBSCRIBE, so a
    // publication sent right after it is delivered, with no wait between.
    let mut sub = listener.subscribe(&env.realm_id, topic).await.unwrap();
    assert_eq!(
        listener.unrouted().get("register_ack_subscribe_accepted"),
        Some(&1)
    );
    publisher
        .publish(Publication {
            realm: env.realm_id,
            topic: topic.to_string(),
            payload: Payload::Clear(Value::text("hi")),
            ttl_ms: None,
        })
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.payload, Payload::Clear(Value::text("hi")));
    assert_eq!(event.publisher, publisher.node_id());
    assert_eq!(event.topic, topic);
    assert!(tokio::time::timeout(Duration::from_millis(300), sub.recv())
        .await
        .is_err());
    sub.unsubscribe().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_subscription_is_withdrawn_and_a_retry_can_succeed() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("refuse");
    let identity = Arc::new(NodeKey::generate_identity(lab.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: s.host.clone(),
        port: s.port,
        profile: lab.profile,
        expected_node_id: s.node_id,
    };
    let link = Link::dial(Config::new(target, identity, issuer))
        .await
        .unwrap();
    let me = link.node_id();
    let (realm, topic) = ([9; 32], "mcl-rust/tests/greeting_sent_v1");

    lab.judge(&s, "subscribe", "not_authorized");
    let refused = link.subscribe(&realm, topic).await.err();
    assert_eq!(
        refused,
        Some(LinkError::RegisterRefused {
            kind: RegisterKind::Subscribe,
            reason: "not_authorized".into(),
        })
    );
    assert!(!lab.subscribed(&s, &me, &realm, topic));
    assert!(link.error().is_none(), "a refusal leaves the link up");

    lab.judge(&s, "subscribe", "accept");
    let sub = link.subscribe(&realm, topic).await.unwrap();
    assert!(lab.subscribed(&s, &me, &realm, topic));
    drop(sub);
}

/// Answers who rang, and refuses "fail" with a handler error.
async fn ring_answer(r: Request) -> Result<Value, String> {
    if r.payload == Value::text("fail") {
        return Err("refused by the handler".to_string());
    }
    Ok(Value::Map(vec![(
        Value::text("rung_by"),
        Value::Bytes(r.caller.to_vec()),
    )]))
}

/// A clear call of `procedure` at `target` in the test realm.
fn clear_call(env: &TestStations, procedure: &str, target: [u8; 32], payload: Value) -> Call {
    Call {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target,
        payload,
        seal: Some(Seal::Clear),
        ..Call::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_procedure_in_a_node_s_own_namespace_is_served_and_called() {
    let env = TestStations::start(Profile::PqPure);
    let provider = node(&env, 0).await;
    let caller = node(&env, 0).await;
    let ring = record::own_procedure(&provider.node_id(), "ring");
    let served = provider
        .serve(Offer::unary(env.realm_id, &ring, handler(ring_answer)))
        .await
        .unwrap();
    let call = |payload: Value| clear_call(&env, &ring, provider.node_id(), payload);
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
    // A call to a provider states how it is kept, or nothing is sent.
    let unstated = caller
        .call(Call {
            seal: None,
            ..call(Value::Null)
        })
        .await;
    assert!(
        matches!(
            &unstated,
            Err(LinkError::Confidentiality(ConfidentialityError {
                reason: ConfidentialityReason::NoSignedState,
                ..
            }))
        ),
        "{unstated:?}"
    );
    // This provider opens no sealed payload: a call sealed to some key is
    // refused sealed_refused, naming no key, and its handler never runs on a
    // payload it cannot read.
    let key = seal::PrivateKey::generate(env.profile).unwrap();
    let sealed = caller
        .call(Call {
            seal: Some(Seal::To(key.public_key().carried().to_vec())),
            ..call(Value::text("fail"))
        })
        .await;
    assert_eq!(sealed, Err(LinkError::SealedRefused { named: None }));
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
            seal: Some(Seal::Clear),
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

/// Sends "one", "two" and "three", then returns, ending the stream.
async fn three_chunks(stream: Stream) -> Result<(), String> {
    for chunk in ["one", "two", "three"] {
        stream
            .send(chunk.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Counts the bytes the caller sends until its end, and replies the total.
async fn count_bytes(stream: Stream) -> Result<(), String> {
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
}

/// A clear stream of `procedure` at `target` in the test realm, in `mode`.
fn clear_stream_call(
    env: &TestStations,
    procedure: &str,
    target: [u8; 32],
    mode: StreamMode,
) -> StreamCall {
    StreamCall {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target,
        mode,
        payload: Value::Null,
        seal: Some(Seal::Clear),
        ..StreamCall::default()
    }
}

/// The raw chunks `stream` delivers until it ends on both sides.
async fn raw_chunks_until_both_end(stream: &Stream) -> Vec<Vec<u8>> {
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
    got
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
            stream_handler(three_chunks),
        ))
        .await
        .unwrap();
    let _count = provider
        .serve(Offer::stream(
            env.realm_id,
            &count,
            StreamMode::ClientStream,
            stream_handler(count_bytes),
        ))
        .await
        .unwrap();

    let open = |procedure: &str, mode| clear_stream_call(&env, procedure, provider.node_id(), mode);
    let stream = caller
        .open_stream(open(&watch, StreamMode::ServerStream))
        .await
        .unwrap();
    let got = raw_chunks_until_both_end(&stream).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_subscription_never_withdraws_a_later_one_of_its_topic() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("resubscribe");
    let identity = Arc::new(NodeKey::generate_identity(lab.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: s.host.clone(),
        port: s.port,
        profile: lab.profile,
        expected_node_id: s.node_id,
    };
    let link = Link::dial(Config::new(target, identity, issuer))
        .await
        .unwrap();
    let me = link.node_id();
    let (realm, topic) = ([9; 32], "mcl-rust/tests/greeting_sent_v1");

    // Drop's UNSUBSCRIBE goes out from a task of its own; the SUBSCRIBE
    // right after it must not overtake it, or the station ends up with no
    // subscription that the caller was told is accepted (macula-rust#34).
    // On a worker, the SUBSCRIBE's task, spawned last, is the one run first.
    tokio::spawn(resubscribe_rounds(lab, s, link, me, realm, topic))
        .await
        .unwrap();
}

/// Twenty rounds of a subscription dropped and its topic subscribed again
/// straight after, each checked at the station once it has settled.
async fn resubscribe_rounds(
    lab: Lab,
    s: LabStation,
    link: Link,
    me: [u8; 32],
    realm: [u8; 32],
    topic: &'static str,
) {
    for round in 0..20 {
        let sub = link.subscribe(&realm, topic).await.unwrap();
        drop(sub);
        let sub = link.subscribe(&realm, topic).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            lab.subscribed(&s, &me, &realm, topic),
            "round {round}: the later subscription was withdrawn"
        );
        sub.unsubscribe().await.unwrap();
    }
}

/// A link of a fresh node to the lab station `s`.
async fn lab_link(lab: &Lab, s: &LabStation) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(lab.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: s.host.clone(),
        port: s.port,
        profile: lab.profile,
        expected_node_id: s.node_id,
    };
    Link::dial(Config::new(target, identity, issuer))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_returns_once_the_station_has_answered_its_advertise() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("advertise");
    let link = lab_link(&lab, &s).await;
    let realm = [9; 32];
    let ring = record::own_procedure(&link.node_id(), "ring");
    let offer = || Offer::unary(realm, &ring, handler(ring_answer));

    // A refused ADVERTISE is serve's own error, and nothing is advertised.
    lab.judge(&s, "advertise", "advertiser_quota");
    let refused = link.serve(offer()).await.err();
    assert_eq!(
        refused,
        Some(LinkError::RegisterRefused {
            kind: RegisterKind::Advertise,
            reason: "advertiser_quota".into(),
        })
    );
    assert!(!lab.advertised(&s, &realm, &ring));
    assert!(link.error().is_none(), "a refusal leaves the link up");

    // One the station does not answer is withdrawn, so a late acceptance
    // routes nothing to a procedure no longer served.
    lab.judge(&s, "advertise", "silent");
    let unanswered = link.serve(offer()).await.err();
    assert_eq!(
        unanswered,
        Some(LinkError::RegisterUnacknowledged(RegisterKind::Advertise))
    );
    eventually_true(|| !lab.advertised(&s, &realm, &ring)).await;

    // An accepted one is advertised as serve returns, with no wait after.
    lab.judge(&s, "advertise", "accept");
    let served = link.serve(offer()).await.unwrap();
    assert!(lab.advertised(&s, &realm, &ring));
    served.stop().await.unwrap();
}

/// Waits up to 5 seconds for `ok` to hold.
async fn eventually_true(ok: impl Fn() -> bool) {
    for _ in 0..50 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never held");
}

/// A provider whose admission lets a caller hold one session at a time.
async fn one_session_provider(env: &TestStations) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    let limits = AdmissionLimits {
        sessions_per_caller: 1,
        ..AdmissionLimits::default()
    };
    cfg.admission = Some(Arc::new(Admission::new(limits)));
    Link::dial(cfg).await.unwrap()
}

/// Says it is in, reads to the caller's end, then waits for a permit of
/// `gate` before it returns.
fn held_after_end(
    realm: [u8; 32],
    procedure: &str,
    gate: Arc<Semaphore>,
    ended: Arc<AtomicUsize>,
) -> Offer {
    let handler = move |stream: Stream| {
        let (gate, ended) = (gate.clone(), ended.clone());
        async move {
            stream.send(b"in").await.map_err(|e| e.to_string())?;
            read_to_end(&stream).await;
            ended.fetch_add(1, Ordering::SeqCst);
            let _permit = gate.acquire().await.map_err(|e| e.to_string())?;
            Ok(())
        }
    };
    Offer::stream(realm, procedure, StreamMode::Bidi, stream_handler(handler))
}

/// Reads `stream` until the caller's end, or until it ends.
async fn read_to_end(stream: &Stream) {
    while let Ok(event) = stream.recv().await {
        if matches!(event, StreamEvent::End { .. }) {
            return;
        }
    }
}

/// A stream of `call` the provider admits, opened again until it does.
async fn admitted_eventually(caller: &Link, call: impl Fn() -> StreamCall) -> Stream {
    for _ in 0..40 {
        let s = caller.open_stream(call()).await.unwrap();
        if admitted(&s).await.is_ok() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never admitted");
}

/// Whether the provider admitted `stream`: its handler's first frame, or the
/// code it was refused with.
async fn admitted(stream: &Stream) -> Result<(), String> {
    match stream.recv().await {
        Ok(StreamEvent::Data { .. }) => Ok(()),
        Err(LinkError::Stream { code, .. }) => Err(code),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handler_draining_after_its_caller_ended_keeps_the_caller_s_session_place() {
    let env = TestStations::start(Profile::PqPure);
    let provider = one_session_provider(&env).await;
    let caller = node(&env, 0).await;
    let procedure = record::own_procedure(&provider.node_id(), "held");
    let gate = Arc::new(Semaphore::new(0));
    let ended = Arc::new(AtomicUsize::new(0));
    let offer = held_after_end(env.realm_id, &procedure, gate.clone(), ended.clone());
    let _served = provider.serve(offer).await.unwrap();
    let open = || clear_stream_call(&env, &procedure, provider.node_id(), StreamMode::Bidi);

    // The caller opens and ends at once; its handler still runs.
    let first = caller.open_stream(open()).await.unwrap();
    assert_eq!(admitted(&first).await, Ok(()));
    let _ = first.close().await;
    eventually("the handler read the caller's end", || {
        ended.load(Ordering::SeqCst) == 1
    })
    .await;

    // Its session place is still taken.
    let second = caller.open_stream(open()).await.unwrap();
    assert_eq!(
        admitted(&second).await,
        Err("too_many_sessions".to_string())
    );

    // Once the handler returns, the place is free again.
    gate.add_permits(2);
    let third = admitted_eventually(&caller, open).await;
    let _ = third.close().await;
    eventually("every stream released", || env.relayed() == 0).await;
}
