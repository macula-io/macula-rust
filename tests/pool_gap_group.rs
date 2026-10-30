//! A link's end reaches a sealed group's subscription while its forwarder is
//! still opening an event (macula-station#129): the forwarder waits on the
//! epoch's key, the link ends, and the subscription is told at once, then
//! told of the gap when a station accepts it again, without waiting for the
//! key. Against macula-go's in-process stations (tests/common).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::group::{
    chain_bound, Distributor, DistributorOptions, Group, Membership, MembershipCheck, Policy,
};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Delivery, Opts, Pool, Seed, Served, Subscription};
use macula_rust::profile::Profile;

/// How long the test group's epochs publish.
const ROTATION_MS: i64 = 1_000;

/// A pool for a new node seeding `stations`, trusting the test realm, with
/// kem_advertise on so it may serve a sealed-only distributor.
async fn pool(env: &TestStations, key: Arc<NodeKey>, stations: &[usize]) -> Pool {
    let mut opts = Opts::new(key);
    opts.realm_trust = HashMap::from([(env.realm_id, env.realm_key.clone())]);
    opts.kem_advertise = true;
    opts.respawn_delay = Duration::from_millis(100);
    let seeds = stations
        .iter()
        .map(|&i| Seed {
            host: env.stations[i].host.clone(),
            port: env.stations[i].port,
            node_id: env.stations[i].node_id,
        })
        .collect();
    Pool::connect(seeds, opts).await.unwrap()
}

fn key(env: &TestStations) -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap())
}

/// Every caller is a member, but once `slow` is set the `stalled` node's
/// key pulls wait a minute for their answer.
fn stalling(stalled: Arc<OnceLock<[u8; 32]>>, slow: Arc<AtomicBool>) -> MembershipCheck {
    Arc::new(move |_prefix: String, caller: [u8; 32]| {
        let stall = slow.load(Ordering::SeqCst) && stalled.get() == Some(&caller);
        Box::pin(member_after(stall)) as _
    })
}

/// In, after a minute when `stall`.
async fn member_after(stall: bool) -> Membership {
    let wait = if stall { 60 } else { 0 };
    tokio::time::sleep(Duration::from_secs(wait)).await;
    Membership::In
}

/// Waits for the next notice, passing over events.
async fn next_notice(sub: &mut Subscription, limit: Duration) -> Delivery {
    let until = tokio::time::Instant::now() + limit;
    loop {
        match tokio::time::timeout_at(until, sub.recv()).await {
            Ok(Some(Delivery::Event(_))) => continue,
            Ok(Some(notice)) => return notice,
            Ok(None) => panic!("the subscription ended"),
            Err(_) => panic!("no notice within {limit:?}"),
        }
    }
}

/// A reader whose subscription only station 0's link carries, while its key
/// pulls run over station 1's, with an event it is waiting on the key for:
/// the pools, the distributor's serving and the subscription, kept alive
/// for the test.
struct Stalled {
    _host: Pool,
    _served: Served,
    reader: Pool,
    _writer: Pool,
    sub: Subscription,
}

async fn stalled_reader(env: &TestStations) -> Stalled {
    let stalled = Arc::new(OnceLock::new());
    let slow = Arc::new(AtomicBool::new(false));

    let host_key = key(env);
    env.admit(&host_key.node_id().unwrap());
    let host = pool(env, host_key, &[0, 1]).await;
    let mut options = DistributorOptions::new(
        &env.org,
        Policy::Required,
        stalling(stalled.clone(), slow.clone()),
    );
    options.rotate_after_ms = ROTATION_MS;
    options.caps.epochs = chain_bound(ROTATION_MS);
    let distributor = Distributor::new(options).unwrap();
    let served = host
        .serve(distributor.offer(env.realm_id, env.org_key_id))
        .await
        .unwrap();

    let prefix = format!("{}/{}/notes", env.realm_name, env.org);
    let topic = format!("{prefix}/note_written_v1");
    let group = |pool: &Pool| Group {
        prefix: prefix.clone(),
        ucan: env.grant(&pool.node_id()).into_bytes(),
        distributor: Some(host.node_id()),
    };
    // The reader calls over station 1's link first, so its key pulls go on
    // there, while only station 0's carries its subscription.
    env.judge(1, "subscribe", "not_authorized");
    let reader = pool(env, key(env), &[1, 0]).await;
    stalled.set(reader.node_id()).unwrap();
    let writer = pool(env, key(env), &[0, 1]).await;
    let (reader_group, writer_group) = (group(&reader), group(&writer));
    let mut sub = reader
        .subscribe_group(&env.realm_id, &topic, &reader_group)
        .await
        .expect("the reader joins and subscribes");
    writer
        .publish_group(&env.realm_id, &topic, &writer_group, Value::text("opened"))
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), sub.recv()).await;
    assert!(
        matches!(&first, Ok(Some(Delivery::Event(e))) if e.unopened.is_none()),
        "the reader opens an event before the stall: {first:?}"
    );

    // Past a few rotations, the next event names an epoch the reader has no
    // key for, and its pull stalls.
    slow.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(3 * ROTATION_MS as u64)).await;
    writer
        .publish_group(&env.realm_id, &topic, &writer_group, Value::text("stalled"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    Stalled {
        _host: host,
        _served: served,
        reader,
        _writer: writer,
        sub,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_ending_while_an_event_waits_on_its_key_is_interrupted_then_a_gap() {
    let env = TestStations::start(Profile::PqPure);
    let Stalled {
        reader, mut sub, ..
    } = stalled_reader(&env).await;

    // The subscription's only link ends; the pull goes on over station 1's.
    env.drop_node(0, &reader.node_id());
    // Well inside the key pull's own timeout: the notices do not wait for it.
    match next_notice(&mut sub, Duration::from_secs(5)).await {
        Delivery::Interrupted(i) => assert_eq!(i.reason, "closed_by_station"),
        other => panic!("not an Interrupted: {other:?}"),
    }
    match next_notice(&mut sub, Duration::from_secs(5)).await {
        Delivery::Gap(g) => assert_eq!(g.reason, "closed_by_station"),
        other => panic!("not a Gap: {other:?}"),
    }
}

/// No station takes the subscription back, so no new link folds the old
/// one's end: the Interrupted is the link's end alone, not a wait on the
/// stalled key pull.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_ending_while_an_event_waits_on_its_key_with_no_station_taking_it_back_is_interrupted(
) {
    let env = TestStations::start(Profile::PqPure);
    let Stalled {
        reader, mut sub, ..
    } = stalled_reader(&env).await;

    env.judge(0, "subscribe", "not_authorized");
    env.drop_node(0, &reader.node_id());
    // Ahead of the stalled pull giving up, which lets the forwarder finish
    // a couple of seconds on.
    match next_notice(&mut sub, Duration::from_secs(1)).await {
        Delivery::Interrupted(i) => assert_eq!(i.reason, "closed_by_station"),
        other => panic!("not an Interrupted: {other:?}"),
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    while let Ok(Some(d)) = tokio::time::timeout_at(until, sub.recv()).await {
        assert!(
            matches!(d, Delivery::Event(_)),
            "no Gap while refused: {d:?}"
        );
    }
}
