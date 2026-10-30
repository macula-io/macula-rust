//! A subscription is told when it may have missed events (macula-station#129,
//! phase 1): one Interrupted when the last link carrying it ends, one Gap when
//! a station accepts it again, and nothing while another link carries it, for
//! an outage a link survives, or after it is unsubscribed. Against macula-go's
//! in-process stations (tests/common/lab.rs).

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::blackhole::BlackHole;
use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Delivery, Gap, Interruption, Opts, Pool, Seed, Subscription};
use macula_rust::profile::Profile;
use macula_rust::station_link::Publication;

const TOPIC: &str = "mcl-craft/wire/edit_made_v1";
const REALM: [u8; 32] = [7; 32];

fn key() -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).unwrap())
}

async fn connect(seeds: Vec<Seed>) -> Pool {
    let mut opts = Opts::new(key());
    opts.realm_trust = HashMap::new();
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(seeds, opts).await.unwrap()
}

fn seeds(stations: &[&LabStation]) -> Vec<Seed> {
    stations.iter().map(|s| s.seed()).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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

/// A listener subscribed on `stations`, subscribed at each of them.
async fn listening(lab: &Lab, stations: &[&LabStation]) -> (Pool, Subscription) {
    let listener = connect(seeds(stations)).await;
    let sub = listener.subscribe(&REALM, TOPIC).await.unwrap();
    let me = listener.node_id();
    within(Duration::from_secs(10), "subscribed everywhere", || {
        stations
            .iter()
            .all(|s| lab.subscribed(s, &me, &REALM, TOPIC))
    })
    .await;
    (listener, sub)
}

async fn publish(publisher: &Pool, text: &str) {
    publisher
        .publish(Publication {
            realm: REALM,
            topic: TOPIC.to_string(),
            payload: Payload::Clear(Value::text(text)),
            ttl_ms: None,
        })
        .await
        .unwrap();
}

/// Everything `sub` delivers within `limit`, in order: `text` for an
/// event, the notice as it is otherwise.
async fn delivered(sub: &mut Subscription, limit: Duration) -> Vec<Delivery> {
    let until = tokio::time::Instant::now() + limit;
    let mut out = Vec::new();
    while let Ok(Some(d)) = tokio::time::timeout_at(until, sub.recv()).await {
        out.push(d);
    }
    out
}

fn notices(ds: &[Delivery]) -> Vec<&Delivery> {
    ds.iter()
        .filter(|d| !matches!(d, Delivery::Event(_)))
        .collect()
}

fn heard(ds: &[Delivery], text: &str) -> usize {
    ds.iter()
        .filter(
            |d| matches!(d, Delivery::Event(e) if e.payload == Payload::Clear(Value::text(text))),
        )
        .count()
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

fn interruption(d: Delivery) -> Interruption {
    match d {
        Delivery::Interrupted(i) => i,
        other => panic!("not an Interrupted: {other:?}"),
    }
}

fn gap(d: Delivery) -> Gap {
    match d {
        Delivery::Gap(g) => g,
        other => panic!("not a Gap: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_only_link_ending_is_one_interrupted_then_one_gap() {
    let lab = Lab::start(Profile::PqPure);
    let a = lab.station("gap single");
    let (listener, mut sub) = listening(&lab, &[&a]).await;
    let subscribed = now_ms();
    let publisher = connect(seeds(&[&a])).await;

    let dropped = now_ms();
    lab.drop_node(&a, &listener.node_id());
    let i = interruption(next_notice(&mut sub, Duration::from_secs(10)).await);
    assert_eq!(i.reason, "closed_by_station");
    assert!(
        (subscribed..=dropped).contains(&i.from_ms),
        "from {} is between the accepting ack {subscribed} and the end {dropped}",
        i.from_ms
    );
    let g = gap(next_notice(&mut sub, Duration::from_secs(10)).await);
    assert_eq!(
        (g.from_ms, g.reason.as_str()),
        (i.from_ms, "closed_by_station")
    );
    assert!(g.to_ms >= dropped);

    within(Duration::from_secs(10), "resubscribed", || {
        lab.subscribed(&a, &listener.node_id(), &REALM, TOPIC)
    })
    .await;
    publish(&publisher, "after").await;
    let after = delivered(&mut sub, Duration::from_secs(1)).await;
    assert_eq!(heard(&after, "after"), 1);
    assert!(notices(&after).is_empty(), "one of each: {after:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_of_two_links_ending_is_no_notice() {
    let lab = Lab::start(Profile::PqPure);
    let (a, b) = (lab.station("gap two a"), lab.station("gap two b"));
    let (listener, mut sub) = listening(&lab, &[&a, &b]).await;
    let publisher = connect(seeds(&[&a, &b])).await;

    lab.drop_node(&a, &listener.node_id());
    publish(&publisher, "still carried").await;
    let ds = delivered(&mut sub, Duration::from_secs(3)).await;
    assert_eq!(heard(&ds, "still carried"), 1);
    assert!(notices(&ds).is_empty(), "the other link carried it: {ds:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn both_links_ending_and_one_returning_is_one_of_each() {
    let lab = Lab::start(Profile::PqPure);
    let (a, b) = (lab.station("gap both a"), lab.station("gap both b"));
    let (listener, mut sub) = listening(&lab, &[&a, &b]).await;
    let me = listener.node_id();

    lab.stop(&b);
    within(Duration::from_secs(10), "b's link down", || {
        listener.status().iter().filter(|l| l.up).count() == 1
    })
    .await;
    lab.drop_node(&a, &me);
    let i = interruption(next_notice(&mut sub, Duration::from_secs(10)).await);
    let g = gap(next_notice(&mut sub, Duration::from_secs(10)).await);
    assert_eq!(g.from_ms, i.from_ms);
    let rest = delivered(&mut sub, Duration::from_secs(3)).await;
    assert!(notices(&rest).is_empty(), "one of each: {rest:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_outage_the_link_survives_is_no_notice() {
    let lab = Lab::start(Profile::PqPure);
    let a = lab.station("gap short");
    let station: SocketAddr = format!("{}:{}", a.host, a.port).parse().unwrap();
    let relay = BlackHole::in_front_of(station);
    let through_relay = Seed {
        host: relay.addr().ip().to_string(),
        port: relay.addr().port(),
        node_id: a.node_id,
    };
    let listener = connect(vec![through_relay]).await;
    let mut sub = listener.subscribe(&REALM, TOPIC).await.unwrap();
    let publisher = connect(seeds(&[&a])).await;

    relay.close();
    tokio::time::sleep(Duration::from_secs(10)).await;
    relay.open();
    publish(&publisher, "after a short outage").await;
    let ds = delivered(&mut sub, Duration::from_secs(5)).await;
    assert!(notices(&ds).is_empty(), "the link survived: {ds:?}");
    assert_eq!(heard(&ds, "after a short outage"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_resubscribe_is_interrupted_and_no_gap() {
    let lab = Lab::start(Profile::PqPure);
    let a = lab.station("gap refused");
    let (listener, mut sub) = listening(&lab, &[&a]).await;

    lab.judge(&a, "subscribe", "not_authorized");
    lab.drop_node(&a, &listener.node_id());
    interruption(next_notice(&mut sub, Duration::from_secs(10)).await);
    within(Duration::from_secs(10), "the link back", || {
        listener.status().iter().any(|l| l.up)
    })
    .await;
    let ds = delivered(&mut sub, Duration::from_secs(3)).await;
    assert!(notices(&ds).is_empty(), "no gap while refused: {ds:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsubscribed_interruption_delivers_nothing_more() {
    let lab = Lab::start(Profile::PqPure);
    let a = lab.station("gap unsubscribe");
    let (_listener, mut sub) = listening(&lab, &[&a]).await;

    lab.stop(&a);
    interruption(next_notice(&mut sub, Duration::from_secs(10)).await);
    sub.unsubscribe().await.unwrap();
    assert_eq!(sub.recv().await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closing_pool_ends_its_subscriptions_without_a_notice() {
    let lab = Lab::start(Profile::PqPure);
    let a = lab.station("gap close");
    let (listener, mut sub) = listening(&lab, &[&a]).await;

    listener.close().await;
    let ds = delivered(&mut sub, Duration::from_secs(3)).await;
    assert!(ds.is_empty(), "the pool closed, nothing was lost: {ds:?}");
    assert_eq!(sub.recv().await, None);
}
