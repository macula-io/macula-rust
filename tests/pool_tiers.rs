//! The public and fallback station tiers (macula-io/macula#201 step 3).
//!
//! A pool is given its public seeds and, beside them, fallback seeds: the LAN
//! stations a node keeps for when no public station is up. Originating traffic
//! — a publication, a station procedure, a content announcement — goes to the
//! active tier only, and standing registrations go to every link of both. The
//! scenarios here are the design's §9, in Rust.

mod common;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use common::blackhole::BlackHole;
use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Delivery, Opts, Pool, PoolError, Seed, Subscription, Tier};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::station_link::Publication;

const TOPIC: &str = "mcl-craft/wire/edit_made_v1";
const REALM: [u8; 32] = [7; 32];

fn key() -> std::sync::Arc<NodeKey> {
    std::sync::Arc::new(NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).unwrap())
}

/// macula's defaults, with the delays a test can wait out.
fn opts() -> Opts {
    let mut opts = Opts::new(key());
    opts.realm_trust = HashMap::new();
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    opts
}

/// A pool on the two lists.
async fn connect_tiered(public: &[Seed], fallback: &[Seed]) -> Pool {
    let mut opts = opts();
    opts.fallback_seeds = fallback.to_vec();
    Pool::connect(public.to_vec(), opts).await.unwrap()
}

/// A pool linked to `seed` only, and a subscription on it standing at its
/// station by the time this returns.
async fn listener(lab: &Lab, s: &LabStation, seed: Seed) -> (Pool, Subscription) {
    let pool = connect_tiered(&[seed], &[]).await;
    let sub = pool.subscribe(&REALM, TOPIC).await.unwrap();
    let them = pool.node_id();
    within(Duration::from_secs(10), "subscribed at the station", || {
        lab.subscribed(s, &them, &REALM, TOPIC)
    })
    .await;
    (pool, sub)
}

/// Waits until `ok` holds, or fails the test naming what was awaited.
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

/// How many times `sub` hears `text` before `limit` passes.
async fn heard(sub: &mut Subscription, text: &str, limit: Duration) -> usize {
    let until = tokio::time::Instant::now() + limit;
    let mut n = 0;
    while let Ok(Some(delivery)) = tokio::time::timeout_at(until, sub.recv()).await {
        let Delivery::Event(event) = delivery else {
            continue;
        };
        if event.payload == Payload::Clear(Value::text(text)) {
            n += 1;
        }
    }
    n
}

fn edit(text: &str) -> Publication {
    Publication {
        realm: REALM,
        topic: TOPIC.to_string(),
        payload: Payload::Clear(Value::text(text)),
        ttl_ms: None,
    }
}

/// `up all` once every link the pool holds is up.
fn all_up(p: &Pool) -> bool {
    p.status().iter().all(|l| l.up)
}

/// A relay in front of `s`, and `s` as a seed reached through it, with every
/// datagram the node sends held for `delay`: the link measures a longer round
/// trip than one dialed directly.
fn relayed_after(s: &LabStation, delay: Duration) -> (BlackHole, Seed) {
    let station: std::net::SocketAddr = format!("{}:{}", s.host, s.port).parse().unwrap();
    let relay = BlackHole::in_front_of_after(station, delay);
    let seed = Seed {
        host: relay.addr().ip().to_string(),
        port: relay.addr().port(),
        node_id: s.node_id,
    };
    (relay, seed)
}

/// A publication reaches the active tier's links only: while a public link is
/// up, the fallback station carries none of it (§9 scenario 1).
#[tokio::test(flavor = "multi_thread")]
async fn a_publication_reaches_only_the_active_tiers_links() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("tier public");
    let fallback = lab.station("tier fallback");
    let (_public_listener, mut public_sub) = listener(&lab, &public, public.seed()).await;
    let (_fallback_listener, mut fallback_sub) = listener(&lab, &fallback, fallback.seed()).await;
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    assert_eq!(p.active_tier(), Tier::Public, "both tiers up");

    p.publish(edit("on the public tier")).await.unwrap();
    assert_eq!(
        heard(
            &mut public_sub,
            "on the public tier",
            Duration::from_secs(5)
        )
        .await,
        1,
        "the public listener hears it once"
    );
    assert_eq!(
        heard(
            &mut fallback_sub,
            "on the public tier",
            Duration::from_millis(500)
        )
        .await,
        0,
        "the fallback station carries nothing while the public tier is up"
    );
}

/// A subscription is standing state, on every link of both tiers: a
/// subscription taken while the public tier is up still hears a node whose
/// only link is the fallback station (§9 scenarios 2 and 5).
#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_on_both_tiers_hears_the_other_one() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("standing public");
    let fallback = lab.station("standing fallback");
    let subscriber = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || {
        all_up(&subscriber)
    })
    .await;
    let mut sub = subscriber.subscribe(&REALM, TOPIC).await.unwrap();
    let them = subscriber.node_id();
    within(
        Duration::from_secs(10),
        "subscribed at both stations",
        || {
            lab.subscribed(&public, &them, &REALM, TOPIC)
                && lab.subscribed(&fallback, &them, &REALM, TOPIC)
        },
    )
    .await;

    // The publisher's public tier is down, so everything it sends goes to the
    // fallback station: the one the subscriber's subscription has to be at too.
    let publisher = connect_tiered(&[fallback.seed()], &[]).await;
    publisher
        .publish(edit("from the fallback tier"))
        .await
        .unwrap();
    assert_eq!(
        heard(&mut sub, "from the fallback tier", Duration::from_secs(5)).await,
        1,
        "a subscription on the active tier alone never hears the other tier"
    );
}

/// The last public link ends: the next operation uses the fallback within one
/// selection, succeeds, and needs no restart (§9 scenario 3).
#[tokio::test(flavor = "multi_thread")]
async fn the_last_public_link_ends_and_the_next_operation_uses_the_fallback() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("outage public");
    let fallback = lab.station("outage fallback");
    let (_listener, mut sub) = listener(&lab, &fallback, fallback.seed()).await;
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    lab.stop(&public);
    within(
        Duration::from_secs(10),
        "the pool on the fallback tier",
        || p.active_tier() == Tier::Fallback,
    )
    .await;
    p.publish(edit("after the public station went"))
        .await
        .expect("the next publication succeeds on the fallback");
    assert_eq!(
        heard(
            &mut sub,
            "after the public station went",
            Duration::from_secs(5)
        )
        .await,
        1
    );
}

/// A station procedure goes to the active tier: with the public tier down, the
/// record the fallback station holds is the one found (§9 scenario 3, the DHT
/// half).
#[tokio::test(flavor = "multi_thread")]
async fn a_station_procedure_uses_the_fallback_when_no_public_link_is_up() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("dht public");
    let fallback = lab.station("dht fallback");
    let found = StationRecord::put_only_at(&lab, &fallback, "tier/dht/lookup");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    lab.stop(&public);
    within(
        Duration::from_secs(10),
        "the pool on the fallback tier",
        || p.active_tier() == Tier::Fallback,
    )
    .await;
    let record = p
        .find_record(&found.key)
        .await
        .expect("the fallback station holds it and answers");
    let read = record::read_procedure_advertisement(record.record()).expect("an advertisement");
    assert_eq!(read.procedure, found.procedure);
}

/// With no public station up, Connect itself comes up on the fallback tier and
/// the pool says so (§9 scenario 4, the connect half).
#[tokio::test(flavor = "multi_thread")]
async fn connect_comes_up_on_the_fallback_when_no_public_station_is_up() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("fallback connect public");
    let fallback = lab.station("fallback connect fallback");
    lab.stop(&public);
    let (_listener, mut sub) = listener(&lab, &fallback, fallback.seed()).await;
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    assert_eq!(p.active_tier(), Tier::Fallback);
    p.publish(edit("only the fallback")).await.unwrap();
    assert_eq!(
        heard(&mut sub, "only the fallback", Duration::from_secs(5)).await,
        1
    );
}

/// The pool reports the tier it is on, and a pool with no fallback list is
/// public even with every link down, so "no link up" fails as it did before
/// there were tiers (§9 scenario 7).
#[tokio::test(flavor = "multi_thread")]
async fn the_status_names_the_tier_the_pool_is_on() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("tier status public");
    let fallback = lab.station("tier status fallback");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    assert_eq!(p.active_tier(), Tier::Public);

    lab.stop(&public);
    within(
        Duration::from_secs(10),
        "the pool on the fallback tier",
        || p.active_tier() == Tier::Fallback,
    )
    .await;

    let solo = lab.station("tier status solo");
    let only = connect_tiered(&[solo.seed()], &[]).await;
    lab.stop(&solo);
    within(
        Duration::from_secs(10),
        "every link of the solo pool down",
        || only.status().iter().all(|l| !l.up),
    )
    .await;
    assert_eq!(
        only.active_tier(),
        Tier::Public,
        "a pool with no fallback list is public with every link down"
    );
}

/// Every link the pool holds names the tier its station was named in (§9
/// scenario 1, the reporting half).
#[tokio::test(flavor = "multi_thread")]
async fn every_link_names_its_configured_tier() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("tier names public");
    let fallback = lab.station("tier names fallback");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    let tiers: HashMap<[u8; 32], Tier> = p
        .status()
        .into_iter()
        .map(|l| (l.station, l.tier))
        .collect();
    assert_eq!(tiers.get(&public.node_id), Some(&Tier::Public));
    assert_eq!(tiers.get(&fallback.node_id), Some(&Tier::Fallback));
}

/// One station holding two roles has no defined behaviour, so the connect is
/// refused (§9 scenario 10).
#[tokio::test(flavor = "multi_thread")]
async fn a_station_in_both_lists_refuses_the_connect() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("twice public");
    let fallback = lab.station("twice fallback");
    let mut opts = opts();
    opts.fallback_seeds = vec![public.seed()];
    let refused = Pool::connect(vec![public.seed(), fallback.seed()], opts)
        .await
        .expect_err("the same station in both lists");
    assert!(
        matches!(refused, PoolError::StationInBothTiers { station } if station == public.node_id),
        "{refused:?}"
    );
}

/// A link event names the tier its station was named in.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_event_names_the_tier() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("event public");
    let fallback = lab.station("event fallback");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let heard_by = std::sync::Arc::clone(&seen);
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.on_link_event = Some(std::sync::Arc::new(move |event| {
        heard_by.lock().unwrap_or_else(|p| p.into_inner()).push((
            event.station,
            event.tier,
            event.up,
        ));
    }));
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    let events = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(
        events.contains(&(public.node_id, Tier::Public, true)),
        "{events:?}"
    );
    assert!(
        events.contains(&(fallback.node_id, Tier::Fallback, true)),
        "{events:?}"
    );
}

/// The fastest measured link goes first: a publish's first replica lands on
/// the lower round trip, whatever the seed order says (§9 scenario 6).
#[tokio::test(flavor = "multi_thread")]
async fn the_fastest_measured_link_takes_the_first_replica() {
    let lab = Lab::start(Profile::PqPure);
    let slow = lab.station("rtt slow");
    let fast = lab.station("rtt fast");
    let (_slow_listener, mut slow_sub) = listener(&lab, &slow, slow.seed()).await;
    let (_fast_listener, mut fast_sub) = listener(&lab, &fast, fast.seed()).await;
    let (_relay, slow_seed) = relayed_after(&slow, Duration::from_millis(40));
    let mut opts = opts();
    opts.replication_factor = 1;
    // The slow station first, so seed order alone would pick it.
    let p = Pool::connect(vec![slow_seed, fast.seed()], opts)
        .await
        .unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    // A handshake measures the path; a moment more lets both estimates settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    p.publish(edit("fastest first")).await.unwrap();
    assert_eq!(
        heard(&mut fast_sub, "fastest first", Duration::from_secs(5)).await,
        1,
        "the lower round trip takes the first replica"
    );
    assert_eq!(
        heard(&mut slow_sub, "fastest first", Duration::from_millis(500)).await,
        0,
        "seed order would have put it on the slow station"
    );
}

/// A redial schedule that cannot back off is a malformed option.
#[tokio::test(flavor = "multi_thread")]
async fn an_impossible_redial_override_is_refused() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("redial refused");
    let mut opts = opts();
    opts.redial.factor = 1;
    let refused = Pool::connect(vec![s.seed()], opts)
        .await
        .expect_err("a factor of 1 never backs off");
    assert!(matches!(refused, PoolError::InvalidOpts(_)), "{refused:?}");
}

/// A fallback seed that was waiting out a long backoff is retried at once when
/// the public tier dies: leaving the public tier is immediate, not a timer
/// (§9 scenario 4, the re-arm half).
#[tokio::test(flavor = "multi_thread")]
async fn a_fallback_retry_rearms_when_the_public_tier_dies() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("rearm public");
    let fallback = lab.station("rearm fallback");
    let (relay, fallback_seed) = relayed_after(&fallback, Duration::ZERO);
    relay.close();
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback_seed];
    opts.redial.base = Duration::from_millis(200);
    opts.redial.factor = 8;
    opts.redial.cap = Duration::from_secs(60);
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    within(Duration::from_secs(10), "the public link up", || {
        p.status().iter().any(|l| l.up && l.tier == Tier::Public)
    })
    .await;
    // Two failed fallback dials take ~200 ms and ~1.6 s; the third waits ~12.8 s.
    tokio::time::sleep(Duration::from_secs(3)).await;

    lab.stop(&public);
    within(
        Duration::from_secs(10),
        "the pool on the fallback tier",
        || p.active_tier() == Tier::Fallback,
    )
    .await;
    relay.open();
    within(
        Duration::from_secs(6),
        "the fallback link, re-armed at the floor",
        || p.status().iter().any(|l| l.up && l.tier == Tier::Fallback),
    )
    .await;
}

/// A record put at one station and nowhere else, with the key it is found
/// under: for the DHT half of scenario 3, where only the station holding it
/// can answer, so a find that succeeds proves which tier was asked.
struct StationRecord {
    key: [u8; 32],
    procedure: String,
}

impl StationRecord {
    /// Puts one node's advertisement of `procedure` at `s` alone.
    fn put_only_at(lab: &Lab, s: &LabStation, procedure: &str) -> StationRecord {
        let owner = key();
        let advertised = record::new_procedure_advertisement(
            &owner.node_id().unwrap(),
            &REALM,
            procedure,
            &[[9_u8; 32]],
            &record::ProcedureAdvertisementOptions::default(),
        )
        .expect("an advertisement to put");
        let signed = record::sign(&advertised, &owner).expect("signed by its advertiser");
        lab.put(s, &record::encode(&signed).expect("its wire"));
        StationRecord {
            key: record::procedure_key(&REALM, procedure),
            procedure: procedure.to_string(),
        }
    }
}
