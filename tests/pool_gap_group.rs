//! A link's end reaches a sealed group's subscription while its forwarder is
//! still opening an event (macula-station#129): the forwarder waits on the
//! epoch's key, the link ends, and the subscription is told at once, then
//! told of the gap when a station accepts it again, without waiting for the
//! key. Against macula-go's in-process stations (tests/common).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use tokio::sync::futures::Notified;
use tokio::sync::Notify;

/// How long a stalled pull waits for its answer: far past any notice, well
/// inside the pool's own pull timeout.
const STALL: Duration = Duration::from_secs(5);

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

/// The stalled node, whether its pulls stall yet, and each pull that did.
#[derive(Default)]
struct Stall {
    node: OnceLock<[u8; 32]>,
    on: AtomicBool,
    pulls: AtomicUsize,
    pulled: Notify,
}

impl Stall {
    /// Returns once a pull has stalled.
    async fn first_stalled(&self) {
        while self.pulls.load(Ordering::SeqCst) == 0 {
            let pulled = self.pulled.notified();
            let stalled = self.pulls.load(Ordering::SeqCst) > 0;
            pulled_unless(pulled, stalled).await;
        }
    }
}

/// Waits on `pulled`, unless a pull `stalled` already.
async fn pulled_unless(pulled: Notified<'_>, stalled: bool) {
    if !stalled {
        pulled.await;
    }
}

/// Every caller is a member, but once the stall is on its node's key pulls
/// wait [`STALL`] for their answer, each one counted as it starts waiting.
fn stalling(stall: Arc<Stall>) -> MembershipCheck {
    Arc::new(move |_prefix: String, caller: [u8; 32]| {
        let stalls = stall.on.load(Ordering::SeqCst) && stall.node.get() == Some(&caller);
        if stalls {
            stall.pulls.fetch_add(1, Ordering::SeqCst);
            stall.pulled.notify_waiters();
        }
        Box::pin(member_after(stalls)) as _
    })
}

/// In, after [`STALL`] when `stall`.
async fn member_after(stall: bool) -> Membership {
    let wait = if stall { STALL } else { Duration::ZERO };
    tokio::time::sleep(wait).await;
    Membership::In
}

/// Waits for the next event a plain subscription hears of a sealed group:
/// unopened, as it holds no group.
async fn heard_sealed(heard: &mut Subscription) {
    match next(heard, BOUND).await {
        Delivery::Event(e) => assert!(e.unopened.is_some(), "a plain subscription opened {e:?}"),
        other => panic!("not an event: {other:?}"),
    }
}

/// The next delivery, within `limit`.
async fn next(sub: &mut Subscription, limit: Duration) -> Delivery {
    match tokio::time::timeout(limit, sub.recv()).await {
        Ok(Some(d)) => d,
        Ok(None) => panic!("the subscription ended"),
        Err(_) => panic!("nothing delivered within {limit:?}"),
    }
}

/// The bound on a wait the test expects to end, the stalled pull's answer at
/// the latest: never a timing the test relies on.
const BOUND: Duration = Duration::from_secs(30);

/// A reader whose subscription only station 0's link carries, while its key
/// pulls run over station 1's, with an event it is waiting on the key for:
/// the pools, the distributor's serving and the subscription, kept alive
/// for the test.
struct Stalled {
    _host: Pool,
    _served: Served,
    reader: Pool,
    _writer: Pool,
    _heard: Subscription,
    sub: Subscription,
}

/// The org's distributor, rotating every [`ROTATION_MS`] and stalling as
/// `stall` says. It serves at station 1 alone, so every key pull goes to
/// station 1 and none rides the link the test ends.
async fn distributing(env: &TestStations, stall: Arc<Stall>) -> (Pool, Served) {
    let host_key = key(env);
    env.admit(&host_key.node_id().unwrap());
    let host = pool(env, host_key, &[1]).await;
    let mut options = DistributorOptions::new(&env.org, Policy::Required, stalling(stall));
    options.rotate_after_ms = ROTATION_MS;
    options.caps.epochs = chain_bound(ROTATION_MS);
    let distributor = Distributor::new(options).unwrap();
    let served = host
        .serve(distributor.offer(env.realm_id, env.org_key_id))
        .await
        .unwrap();
    (host, served)
}

async fn stalled_reader(env: &TestStations) -> Stalled {
    let stall = Arc::new(Stall::default());

    let (host, served) = distributing(env, stall.clone()).await;

    let prefix = format!("{}/{}/notes", env.realm_name, env.org);
    let topic = format!("{prefix}/note_written_v1");
    let group = |pool: &Pool| Group {
        prefix: prefix.clone(),
        ucan: env.grant(&pool.node_id()).into_bytes(),
        distributor: Some(host.node_id()),
    };
    // Only station 0's link carries the reader's subscription.
    env.judge(1, "subscribe", "not_authorized");
    let reader = pool(env, key(env), &[1, 0]).await;
    stall.node.set(reader.node_id()).unwrap();
    let writer = pool(env, key(env), &[0, 1]).await;
    let (reader_group, writer_group) = (group(&reader), group(&writer));
    let mut sub = reader
        .subscribe_group(&env.realm_id, &topic, &reader_group)
        .await
        .expect("the reader joins and subscribes");
    // A plain subscription beside it hears each sealed event unopened, with
    // no pull: the moment it does, the group subscription has the event too.
    let mut heard = reader.subscribe(&env.realm_id, &topic).await.unwrap();
    writer
        .publish_group(&env.realm_id, &topic, &writer_group, Value::text("opened"))
        .await
        .unwrap();
    let first = tokio::time::timeout(BOUND, sub.recv()).await;
    assert!(
        matches!(&first, Ok(Some(Delivery::Event(e))) if e.unopened.is_none()),
        "the reader opens an event before the stall: {first:?}"
    );

    // Once the epochs rotate past the keys the reader holds, an event names
    // one it has to pull, and the pull stalls: publish until one does, so the
    // test goes on with a pull in flight.
    // Once the reader's own refresh pull stalls, it holds no key it does
    // not hold now, and an event published after that waits on its pull.
    stall.on.store(true, Ordering::SeqCst);
    tokio::time::timeout(BOUND, stall.first_stalled())
        .await
        .expect("the reader's pull stalls");
    writer
        .publish_group(&env.realm_id, &topic, &writer_group, Value::text("waiting"))
        .await
        .unwrap();
    // The plain subscription hears "opened", then "waiting": the group
    // subscription has "waiting" now, and waits on its key.
    heard_sealed(&mut heard).await;
    heard_sealed(&mut heard).await;

    Stalled {
        _host: host,
        _served: served,
        reader,
        _writer: writer,
        _heard: heard,
        sub,
    }
}

/// What arrives after the drop: the Interrupted first, ahead of the event
/// still waiting on its key, which comes once the stalled pull answers. An event first means the notice waited on the forwarder.
async fn interrupted_ahead_of_the_waiting_event(sub: &mut Subscription) -> Vec<Delivery> {
    match next(sub, BOUND).await {
        Delivery::Interrupted(i) => assert_eq!(i.reason, "closed_by_station"),
        other => panic!("not the Interrupted first: {other:?}"),
    }
    let mut after = Vec::new();
    loop {
        let d = next(sub, BOUND).await;
        let event = matches!(d, Delivery::Event(_));
        after.push(d);
        if event {
            return after;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_ending_while_an_event_waits_on_its_key_is_interrupted_then_a_gap() {
    let env = TestStations::start(Profile::PqPure);
    let Stalled {
        reader, mut sub, ..
    } = stalled_reader(&env).await;

    // The subscription's only link ends; the pull goes on at station 1.
    env.drop_node(0, &reader.node_id());
    let mut after = interrupted_ahead_of_the_waiting_event(&mut sub).await;
    // The station takes the subscription back, before or after the waiting
    // event comes.
    while !after.iter().any(|d| matches!(d, Delivery::Gap(_))) {
        after.push(next(&mut sub, BOUND).await);
    }
    let gaps: Vec<_> = after
        .iter()
        .filter(|d| !matches!(d, Delivery::Event(_)))
        .collect();
    assert!(
        matches!(gaps.as_slice(), [Delivery::Gap(g)] if g.reason == "closed_by_station"),
        "one Gap: {after:?}"
    );
}

/// No station takes the subscription back, so no new link folds the old
/// one's end: the Interrupted is the link's end alone, not the forwarder
/// finishing the event it waits on.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_ending_while_an_event_waits_on_its_key_with_no_station_taking_it_back_is_interrupted(
) {
    let env = TestStations::start(Profile::PqPure);
    let Stalled {
        reader, mut sub, ..
    } = stalled_reader(&env).await;

    env.judge(0, "subscribe", "not_authorized");
    env.drop_node(0, &reader.node_id());
    let after = interrupted_ahead_of_the_waiting_event(&mut sub).await;
    assert!(
        after.iter().all(|d| matches!(d, Delivery::Event(_))),
        "no Gap while refused: {after:?}"
    );
}
