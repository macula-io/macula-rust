//! A node's pool of station links, against macula-go's in-process stations
//! (tests/common/lab.rs): one link per pinned seed, redialed when it drops
//! and given back its subscriptions and served procedures; calls and streams
//! that reach a provider at its own station, resolved from the DHT and
//! trusted only under the pinned realm key; and records through the pool.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::lab::{Lab, LabRealm, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{
    Call, Confidentiality, ConfidentialityError, ConfidentialityReason, Offer, Opts, Pool,
    PoolError, Seed, StreamCall,
};
use macula_rust::profile::Profile;
use macula_rust::record::{
    self, new_node_record, new_procedure_advertisement, new_station_endpoint,
};
use macula_rust::record::{
    NodeRecordOptions, ProcedureAdvertisementOptions, RecordType, StationEndpointOptions,
};
use macula_rust::station_link::{handler, stream_handler, LinkError, Publication, StreamEvent};

const ORG: &str = "mcl-echo";
const PROCEDURE: &str = "mcl-echo/echo";
const TOPIC: &str = "mcl-news/wire/news_item_reported_v1";

fn key(profile: Profile) -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap())
}

fn id(key: &NodeKey) -> [u8; 32] {
    key.node_id().unwrap()
}

/// A pool as `key` on `seeds`, trusting `realm` (none when `None`).
async fn connect(key: &Arc<NodeKey>, realm: Option<&LabRealm>, seeds: &[&LabStation]) -> Pool {
    let mut opts = Opts::new(key.clone());
    opts.realm_trust = realm
        .map(|r| HashMap::from([(r.id, r.key.clone())]))
        .unwrap_or_default();
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(seeds.iter().map(|s| s.seed()).collect(), opts)
        .await
        .unwrap()
}

fn echo() -> Offer {
    Offer::unary(
        [0; 32],
        PROCEDURE,
        handler(|r| async move { Ok(r.payload) }),
    )
}

fn offer_in(realm: &LabRealm, o: Offer) -> Offer {
    Offer {
        realm: realm.id,
        ..o
    }
}

async fn within(limit: Duration, what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("not within {limit:?}: {what}");
}

async fn eventually(what: &str, ok: impl FnMut() -> bool) {
    within(Duration::from_secs(10), what, ok).await;
}

fn call(realm: [u8; 32], procedure: &str, payload: Value) -> Call {
    Call {
        realm,
        procedure: procedure.to_string(),
        payload,
        ..Call::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_refuses_what_cannot_be_trusted() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("refusals");
    let key = key(Profile::PqPure);
    let unpinned = Seed {
        node_id: [0; 32],
        ..s.seed()
    };
    let refused = Pool::connect(vec![unpinned], Opts::new(key.clone())).await;
    assert!(
        matches!(refused, Err(PoolError::SeedNotPinned(_))),
        "{refused:?}"
    );

    let mut bad = Opts::new(key.clone());
    bad.realm_trust = HashMap::from([([1; 32], b"not a key".to_vec())]);
    let refused = Pool::connect(vec![s.seed()], bad).await;
    assert!(
        matches!(refused, Err(PoolError::RealmTrustInvalid(_))),
        "{refused:?}"
    );

    let mut few = Opts::new(key.clone());
    few.max_seeds = 2;
    let refused = Pool::connect(vec![s.seed(), s.seed(), s.seed()], few).await;
    assert!(
        matches!(refused, Err(PoolError::TooManySeeds { .. })),
        "{refused:?}"
    );

    let refused = Pool::connect(vec![], Opts::new(key.clone())).await;
    assert!(matches!(refused, Err(PoolError::NoSeeds)), "{refused:?}");

    let mut too_wide = Opts::new(key);
    too_wide.max_direct_links = 65;
    let refused = Pool::connect(vec![s.seed()], too_wide).await;
    assert!(
        matches!(refused, Err(PoolError::InvalidOpts(_))),
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pool_links_every_seed_and_redials_a_dropped_one() {
    let lab = Lab::start(Profile::PqPure);
    let (a, b) = (lab.station("seed a"), lab.station("seed b"));
    let k = key(Profile::PqPure);
    let p = connect(&k, None, &[&a, &b]).await;
    let me = p.node_id();
    eventually("both links up", || {
        lab.connected(&a, &me) && lab.connected(&b, &me)
    })
    .await;
    lab.drop_node(&a, &me);
    eventually("the dropped link redialed", || lab.connected(&a, &me)).await;
    eventually("both links up in the status", || {
        p.status().iter().filter(|l| l.up).count() == 2
    })
    .await;
    p.close().await;
    eventually("closed at both stations", || {
        !lab.connected(&a, &me) && !lab.connected(&b, &me)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_hears_once_and_survives_a_redial() {
    let lab = Lab::start(Profile::PqPure);
    let (a, b) = (lab.station("pubsub a"), lab.station("pubsub b"));
    let (lk, pk) = (key(Profile::PqPure), key(Profile::PqPure));
    let listener = connect(&lk, None, &[&a, &b]).await;
    let publisher = connect(&pk, None, &[&a, &b]).await;
    let realm = [7; 32];
    let mut sub = listener.subscribe(&realm, TOPIC).await.unwrap();
    let me = listener.node_id();
    eventually("subscribed at both stations", || {
        lab.subscribed(&a, &me, &realm, TOPIC) && lab.subscribed(&b, &me, &realm, TOPIC)
    })
    .await;

    async fn heard(
        publisher: &Pool,
        sub: &mut macula_rust::pool::Subscription,
        realm: [u8; 32],
        text: &str,
    ) -> usize {
        publisher
            .publish(Publication {
                realm,
                topic: TOPIC.to_string(),
                payload: Value::text(text),
                ttl_ms: None,
            })
            .await
            .unwrap();
        let mut n = 0;
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Some(event)) = tokio::time::timeout_at(until, sub.recv()).await {
            if event.payload == Value::text(text) {
                n += 1;
            }
        }
        n
    }

    assert_eq!(heard(&publisher, &mut sub, realm, "first").await, 1);
    lab.drop_node(&a, &me);
    lab.drop_node(&b, &me);
    eventually("the listener resubscribed at both stations", || {
        lab.subscribed(&a, &me, &realm, TOPIC) && lab.subscribed(&b, &me, &realm, TOPIC)
    })
    .await;
    assert_eq!(heard(&publisher, &mut sub, realm, "after").await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_dials_the_provider_s_station() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let lab = Lab::start(profile);
        let (serving, callers) = (lab.station("serving"), lab.station("callers"));
        lab.share(&[&serving, &callers]);
        let realm = lab.realm("direct", ORG);
        let pk = key(profile);
        lab.admit(&realm, &serving, &[id(&pk)]);
        let provider = connect(&pk, Some(&realm), &[&serving]).await;
        provider.serve(offer_in(&realm, echo())).await.unwrap();

        let ck = key(profile);
        let caller = connect(&ck, Some(&realm), &[&callers]).await;
        let answered = caller
            .call(call(realm.id, PROCEDURE, Value::text("hello")))
            .await
            .unwrap();
        assert_eq!(answered, Value::text("hello"));
        assert!(
            lab.connected(&serving, &caller.node_id()),
            "the caller dialed the serving station"
        );
        let providers = caller.providers(&realm.id, PROCEDURE).await.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].node, id(&pk));
        assert_eq!(providers[0].station, serving.node_id);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_trusts_only_the_pinned_realm() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("trust");
    let realm = lab.realm("trusted", ORG);
    let impostor = lab.impostor(&realm);
    let pk = key(Profile::PqPure);
    lab.admit(&impostor, &s, &[id(&pk)]);
    let provider = connect(&pk, Some(&impostor), &[&s]).await;
    provider.serve(offer_in(&impostor, echo())).await.unwrap();

    let caller = connect(&key(Profile::PqPure), Some(&realm), &[&s]).await;
    let mut c = call(realm.id, PROCEDURE, Value::Map(vec![]));
    c.timeout = Duration::from_secs(2);
    let untrusted = caller.call(c.clone()).await;
    assert!(
        matches!(untrusted, Err(PoolError::NoProvider(_))),
        "{untrusted:?}"
    );
    let unpinned = caller
        .call(Call {
            realm: [9; 32],
            ..c
        })
        .await;
    assert!(
        matches!(unpinned, Err(PoolError::NoRealmKey)),
        "{unpinned:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_served_procedure_survives_a_redial_until_stopped() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("replay");
    let realm = lab.realm("replay", ORG);
    let pk = key(Profile::PqPure);
    lab.admit(&realm, &s, &[id(&pk)]);
    let provider = connect(&pk, Some(&realm), &[&s]).await;
    let served = provider.serve(offer_in(&realm, echo())).await.unwrap();
    eventually("advertised", || lab.advertised(&s, &realm.id, PROCEDURE)).await;
    lab.drop_node(&s, &provider.node_id());
    eventually("advertised again after the redial", || {
        lab.connected(&s, &provider.node_id()) && lab.advertised(&s, &realm.id, PROCEDURE)
    })
    .await;
    served.stop().await.unwrap();
    eventually("withdrawn", || !lab.advertised(&s, &realm.id, PROCEDURE)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_tries_the_next_candidate() {
    let lab = Lab::start(Profile::PqPure);
    let (gone, live) = (lab.station("gone"), lab.station("live"));
    lab.share(&[&gone, &live]);
    let realm = lab.realm("candidates", ORG);
    let (lost_key, live_key) = (key(Profile::PqPure), key(Profile::PqPure));
    lab.admit(&realm, &gone, &[id(&lost_key), id(&live_key)]);
    let live_provider = connect(&live_key, Some(&realm), &[&live]).await;
    live_provider
        .serve(Offer::unary(
            realm.id,
            PROCEDURE,
            handler(|_| async { Err("no".to_string()) }),
        ))
        .await
        .unwrap();
    // The lost provider advertises last, so its candidate is the freshest and
    // is tried first.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let lost = connect(&lost_key, Some(&realm), &[&gone]).await;
    lost.serve(offer_in(&realm, echo())).await.unwrap();

    let caller = connect(&key(Profile::PqPure), Some(&realm), &[&live]).await;
    let providers = caller.providers(&realm.id, PROCEDURE).await.unwrap();
    assert_eq!(providers.len(), 2);
    assert_eq!(providers[0].node, id(&lost_key), "freshest first");
    lab.stop(&gone);
    let mut c = call(realm.id, PROCEDURE, Value::Map(vec![]));
    c.timeout = Duration::from_secs(5);
    match caller.call(c).await {
        Err(PoolError::Link(LinkError::Provider {
            code, responded_by, ..
        })) => {
            assert_eq!(code, "handler_error");
            assert_eq!(responded_by, id(&live_key));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_station_endpoint_must_be_the_station_s_own() {
    let lab = Lab::start(Profile::PqPure);
    let (liar, victim) = (lab.station("liar"), lab.station("victim"));
    let p = connect(&key(Profile::PqPure), None, &[&liar]).await;
    // An endpoint record for the liar's address, signed by a key that is not
    // the victim's, stored in the victim's slot.
    let forger = key(Profile::PqPure);
    let forged = new_station_endpoint(
        liar.port,
        &StationEndpointOptions {
            host_advertised: vec![liar.host.clone()],
            ..StationEndpointOptions::default()
        },
    )
    .unwrap();
    let wire = record::encode(&record::sign(&forged, &forger).unwrap()).unwrap();
    lab.forge(&liar, &record::station_endpoint_key(&victim.node_id), &wire);
    let refused = p.station_target(&victim.node_id).await;
    assert!(
        matches!(refused, Err(PoolError::NoStationEndpoint(_))),
        "{refused:?}"
    );
    let own = p.station_target(&liar.node_id).await.unwrap();
    assert_eq!(own.expected_node_id, liar.node_id);
    assert_eq!(
        (own.host.as_str(), own.port),
        (liar.host.as_str(), liar.port)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreached_direct_station_is_not_kept() {
    let lab = Lab::start(Profile::PqPure);
    let (s, gone) = (lab.station("keeps"), lab.station("never reached"));
    lab.share(&[&s, &gone]);
    lab.stop(&gone);
    let p = connect(&key(Profile::PqPure), None, &[&s]).await;
    let reached = tokio::time::timeout(Duration::from_secs(10), p.link_to(&gone.node_id)).await;
    assert!(
        matches!(reached, Ok(Err(_))),
        "a stopped station was linked or never refused"
    );
    assert!(
        p.status().iter().all(|l| l.station != gone.node_id),
        "the unreached station is still held: {:?}",
        p.status()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unsubscribe_ends_the_subscription_everywhere() {
    let lab = Lab::start(Profile::PqPure);
    let (a, b) = (lab.station("unsubscribe a"), lab.station("unsubscribe b"));
    let p = connect(&key(Profile::PqPure), None, &[&a, &b]).await;
    let me = p.node_id();
    eventually("both links up", || {
        lab.connected(&a, &me) && lab.connected(&b, &me)
    })
    .await;
    let realm = [3; 32];
    let mut sub = p.subscribe(&realm, TOPIC).await.unwrap();
    eventually("subscribed at both stations", || {
        lab.subscribed(&a, &me, &realm, TOPIC) && lab.subscribed(&b, &me, &realm, TOPIC)
    })
    .await;
    sub.unsubscribe().await.unwrap();
    assert_eq!(sub.recv().await, None, "the subscription's events end");
    eventually("unsubscribed at both stations", || {
        !lab.subscribed(&a, &me, &realm, TOPIC) && !lab.subscribed(&b, &me, &realm, TOPIC)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_put_through_the_pool_is_found_by_type() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("records");
    let k = key(Profile::PqPure);
    let p = connect(&k, None, &[&s]).await;
    let unsigned = new_node_record(
        &p.node_id(),
        &[],
        0,
        &NodeRecordOptions {
            display_name: "recorder".into(),
            ..NodeRecordOptions::default()
        },
    )
    .unwrap();
    let wire = record::encode(&record::sign(&unsigned, &k).unwrap()).unwrap();
    p.put_record(&wire).await.unwrap();
    let (found, dropped) = p
        .find_records_by_type(RecordType::NODE_RECORD)
        .await
        .unwrap();
    assert_eq!(dropped, 0);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].record().signed.as_ref().unwrap().key_id,
        p.node_id()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_dials_the_provider_s_station_and_is_released_promptly() {
    let lab = Lab::start(Profile::PqPure);
    let (serving, callers) = (lab.station("stream serving"), lab.station("stream callers"));
    lab.share(&[&serving, &callers]);
    let realm = lab.realm("streams", ORG);
    let pk = key(Profile::PqPure);
    lab.admit(&realm, &serving, &[id(&pk)]);
    let provider = connect(&pk, Some(&realm), &[&serving]).await;
    provider
        .serve(Offer::stream(
            realm.id,
            PROCEDURE,
            StreamMode::ServerStream,
            stream_handler(|s| async move {
                for chunk in ["a", "b"] {
                    s.send(chunk.as_bytes()).await.map_err(|e| e.to_string())?;
                }
                s.close().await.map_err(|e| e.to_string())
            }),
        ))
        .await
        .unwrap();
    let caller = connect(&key(Profile::PqPure), Some(&realm), &[&callers]).await;
    let stream = caller
        .open_stream(StreamCall {
            realm: realm.id,
            procedure: PROCEDURE.to_string(),
            mode: StreamMode::ServerStream,
            ..StreamCall::default()
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .unwrap()
            .unwrap()
        {
            StreamEvent::Data {
                body: Value::Bytes(b),
                ..
            } => got.push(b),
            StreamEvent::End { .. } => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(got, vec![b"a".to_vec(), b"b".to_vec()]);
    // macula-io/macula-rust#3: a stream ended on both sides is released at
    // once, not after a timeout, without its handle being dropped.
    within(
        Duration::from_secs(2),
        "every relayed stream released",
        || lab.relayed(&serving) == 0 && lab.relayed(&callers) == 0,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_procedure_in_the_node_s_own_namespace_needs_no_realm_key() {
    let lab = Lab::start(Profile::PqPure);
    let (serving, callers) = (lab.station("own serving"), lab.station("own callers"));
    lab.share(&[&serving, &callers]);
    let realm = [0x42; 32];
    let pk = key(Profile::PqPure);
    let provider = connect(&pk, None, &[&serving]).await;
    let ring = record::own_procedure(&provider.node_id(), "ring");
    provider
        .serve(Offer::unary(
            realm,
            &ring,
            handler(|r| async move { Ok(r.payload) }),
        ))
        .await
        .unwrap();

    // Another node's advertisement for the provider's namespace.
    let mallory = key(Profile::PqPure);
    let forged = new_procedure_advertisement(
        &id(&mallory),
        &realm,
        &ring,
        &callers.node_id,
        &ProcedureAdvertisementOptions::default(),
    )
    .unwrap();
    lab.put(
        &callers,
        &record::encode(&record::sign(&forged, &mallory).unwrap()).unwrap(),
    );

    let caller = connect(&key(Profile::PqPure), None, &[&callers]).await;
    let answered = caller
        .call(call(realm, &ring, Value::text("ring ring")))
        .await
        .unwrap();
    assert_eq!(answered, Value::text("ring ring"));
    let providers = caller.providers(&realm, &ring).await.unwrap();
    assert_eq!(providers.len(), 1, "the provider alone: {providers:?}");
    assert_eq!(providers[0].node, provider.node_id());
    let org = caller
        .call(call(realm, PROCEDURE, Value::Map(vec![])))
        .await;
    assert!(matches!(org, Err(PoolError::NoRealmKey)), "{org:?}");
}

/// Two providers of PROCEDURE with `offer`'s handler, each serving from its
/// own station, the stations sharing a DHT, so a caller finds two
/// candidates; and a caller linked to the first station. Answers the caller
/// and the providers, which must outlive the test's calls.
async fn two_station_providers(
    lab: &Lab,
    name: &str,
    offer: impl Fn() -> Offer,
) -> (Pool, LabRealm, Vec<Pool>) {
    let (a, b) = (
        lab.station(&format!("{name} a")),
        lab.station(&format!("{name} b")),
    );
    lab.share(&[&a, &b]);
    let realm = lab.realm(name, ORG);
    let mut providers = Vec::new();
    for s in [&a, &b] {
        let pk = key(Profile::PqPure);
        lab.admit(&realm, s, &[id(&pk)]);
        let provider = connect(&pk, Some(&realm), &[s]).await;
        provider.serve(offer_in(&realm, offer())).await.unwrap();
        providers.push(provider);
    }
    let caller = connect(&key(Profile::PqPure), Some(&realm), &[&a]).await;
    let mut found = 0;
    for _ in 0..500 {
        found = caller
            .providers(&realm.id, PROCEDURE)
            .await
            .map(|p| p.len())
            .unwrap_or(0);
        if found == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(found, 2, "both candidates");
    (caller, realm, providers)
}

// macula-io/macula-rust#6: a CALL that has gone out is never sent again. A
// handler slower than one candidate's share of the deadline is entered once
// and its answer returned, for the share bounds reaching a station, not the
// call (macula's call_work and failure_scope/1; macula-go#8). A retry would
// run a handler that is not idempotent twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_went_out_is_never_sent_again() {
    let lab = Lab::start(Profile::PqPure);
    let entered = Arc::new(AtomicUsize::new(0));
    let counted = entered.clone();
    let (caller, realm, _providers) = two_station_providers(&lab, "once", move || {
        let counted = counted.clone();
        Offer::unary(
            [0; 32],
            PROCEDURE,
            handler(move |r| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2500)).await;
                    Ok(r.payload)
                }
            }),
        )
    })
    .await;
    let mut c = call(realm.id, PROCEDURE, Value::text("hello"));
    c.timeout = Duration::from_secs(4);
    let answered = caller.call(c).await;
    assert!(
        matches!(&answered, Ok(v) if *v == Value::text("hello")),
        "the one provider's answer: {answered:?}"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "the handler entered once"
    );
}

// A stream the link refuses is not walked to the next candidate: every
// candidate would refuse it alike, as macula scopes open_too_large to the
// request.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_the_link_refuses_is_not_walked() {
    let lab = Lab::start(Profile::PqPure);
    let entered = Arc::new(AtomicUsize::new(0));
    let counted = entered.clone();
    let (caller, realm, _providers) = two_station_providers(&lab, "once-stream", move || {
        let counted = counted.clone();
        Offer::stream(
            [0; 32],
            PROCEDURE,
            StreamMode::ServerStream,
            stream_handler(move |s| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    s.close().await.map_err(|e| e.to_string())
                }
            }),
        )
    })
    .await;
    let opened = caller
        .open_stream(StreamCall {
            realm: realm.id,
            procedure: PROCEDURE.to_string(),
            mode: StreamMode::ServerStream,
            payload: Value::text("x".repeat(2 << 20)),
            ..StreamCall::default()
        })
        .await;
    assert!(
        matches!(
            opened,
            Err(PoolError::Link(LinkError::StreamOpenTooLarge(_)))
        ),
        "the link's refusal alone: {:?}",
        opened.map(|_| ())
    );
    assert_eq!(entered.load(Ordering::SeqCst), 0, "no handler entered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_required_call_reaches_no_provider_that_names_no_kem_key() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("required");
    let realm = [0x43; 32];
    let pk = key(Profile::PqPure);
    let provider = connect(&pk, None, &[&s]).await;
    let ring = record::own_procedure(&provider.node_id(), "ring");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    provider
        .serve(Offer::unary(
            realm,
            &ring,
            handler(move |r| {
                let tx = tx.clone();
                async move {
                    tx.send(()).unwrap();
                    Ok(r.payload)
                }
            }),
        ))
        .await
        .unwrap();
    let caller = connect(&key(Profile::PqPure), None, &[&s]).await;

    let required = caller
        .call(Call {
            confidential: Confidentiality::Required,
            ..call(realm, &ring, Value::text("kept"))
        })
        .await;
    assert!(
        matches!(
            &required,
            Err(PoolError::Confidentiality(ConfidentialityError {
                reason: ConfidentialityReason::NoKemKey,
                advertised,
            })) if advertised.is_empty()
        ),
        "{required:?}"
    );
    let opened = caller
        .open_stream(StreamCall {
            realm,
            procedure: ring.clone(),
            confidential: Confidentiality::Required,
            ..StreamCall::default()
        })
        .await;
    assert!(
        matches!(opened, Err(PoolError::Confidentiality(_))),
        "{:?}",
        opened.err()
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused call reached the provider"
    );

    let preferred = caller
        .call(call(realm, &ring, Value::text("clear")))
        .await
        .unwrap();
    assert_eq!(preferred, Value::text("clear"));
    assert!(rx.try_recv().is_ok());
}
