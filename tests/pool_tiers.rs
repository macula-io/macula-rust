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
use macula_rust::pool::{
    Call, Delivery, Jitter, LinkSelection, Offer, Opts, Pool, PoolError, Seed, Subscription, Tier,
};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::station_link::{handler, Publication};

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

/// Waits until the pool reports a link up on the public tier.
async fn until_a_public_link_is_up(p: &Pool) {
    within(Duration::from_secs(15), "the public link up", || {
        p.status().iter().any(|l| l.up && l.tier == Tier::Public)
    })
    .await;
}

/// Waits until `s` takes an arrival past `before`: the redial landing there.
async fn until_the_redial(lab: &Lab, s: &LabStation, before: u64) {
    within(Duration::from_secs(10), "the redial", || {
        lab.arrivals(s) > before
    })
    .await;
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

/// How many events `sub` hears before `limit` passes, whatever they say.
async fn heard_any(sub: &mut Subscription, limit: Duration) -> usize {
    let until = tokio::time::Instant::now() + limit;
    let mut n = 0;
    while let Ok(Some(_)) = tokio::time::timeout_at(until, sub.recv()).await {
        n += 1;
    }
    n
}

/// When each connection reached `s`, sampled every few milliseconds for `d`:
/// a test's read of the redial schedule as the station saw it.
async fn arrivals_over(lab: &Lab, s: &LabStation, d: Duration) -> Vec<Instant> {
    let mut seen = 0;
    let mut at = Vec::new();
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        let arrived = lab.arrivals(s) as usize;
        while seen < arrived {
            seen += 1;
            at.push(Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    at
}

/// The gaps between one arrival and the next.
fn gaps(at: &[Instant]) -> Vec<Duration> {
    at.windows(2).map(|w| w[1].duration_since(w[0])).collect()
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

/// Neither tier up: the connect fails as it always has, with `NoLink`
/// carrying each link's own error once the connect timeout passes, rather
/// than a pool that waits for a tier that may never come (§9 scenario 7).
#[tokio::test(flavor = "multi_thread")]
async fn neither_tier_up_fails_the_connect_as_it_always_has() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("nowhere public");
    let fallback = lab.station("nowhere fallback");
    // Both stations refuse the handshake, so each link fails on its own error
    // rather than on a dial that waits out its timeout.
    lab.refuse(&public, Duration::from_secs(10));
    lab.refuse(&fallback, Duration::from_secs(10));
    let mut opts = opts();
    opts.connect_timeout = Duration::from_secs(1);
    opts.fallback_seeds = vec![fallback.seed()];
    let started = Instant::now();
    let connecting = tokio::time::timeout(
        Duration::from_secs(10),
        Pool::connect(vec![public.seed()], opts),
    );
    match connecting
        .await
        .expect("the failure is the connect timeout's")
    {
        Err(PoolError::NoLink(errors)) => {
            assert_eq!(errors.len(), 2, "both tiers are dialed and both failed");
        }
        other => panic!("expected NoLink, got {:?}", other.map(|_| ())),
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the failure is the connect timeout's, not a stall"
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

/// The fastest measured link goes first for a station procedure too, not only
/// for a publish: the first call of a walk reaches the lower round trip
/// whatever the seed order says, and its answer is final (§9 scenario 6, the
/// call half — macula#201's contract names the first call, not only the
/// replica).
#[tokio::test(flavor = "multi_thread")]
async fn the_fastest_measured_link_takes_the_first_call() {
    let lab = Lab::start(Profile::PqPure);
    let slow = lab.station("call rtt slow");
    let fast = lab.station("call rtt fast");
    let found = StationRecord::put_only_at(&lab, &slow, "tier/call/lookup");
    StationRecord::put_only_at(&lab, &fast, "tier/call/lookup");
    let (_relay, slow_seed) = relayed_after(&slow, Duration::from_millis(40));
    // The slow station first, so seed order alone would ask it.
    let p = Pool::connect(vec![slow_seed, fast.seed()], opts())
        .await
        .unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    // A handshake measures the path; a moment more lets both estimates settle.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let them = p.node_id();

    p.find_record(&found.key)
        .await
        .expect("the find is answered");
    assert_eq!(
        lab.asked(&fast, &them, "_dht.find_record"),
        1,
        "the lower round trip is asked first, and its answer is final"
    );
    assert_eq!(
        lab.asked(&slow, &them, "_dht.find_record"),
        0,
        "seed order would have asked the slow station"
    );
}

/// A factor of one is a schedule that never grows, not a malformed option:
/// macula's own refusal set takes out a factor below one, not one itself
/// (macula-go `pool/redial.go`). The connect succeeds and the schedule stays
/// at the floor (§9 scenario 4, the shape of the schedule).
#[tokio::test(flavor = "multi_thread")]
async fn a_redial_that_never_grows_is_accepted() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("redial flat");
    let mut opts = opts();
    opts.redial.factor = 1;
    opts.redial.base = Duration::from_millis(100);
    let p = Pool::connect(vec![s.seed()], opts)
        .await
        .expect("a factor of one connects");
    assert!(
        p.status().iter().any(|l| l.up),
        "the link is up, so nothing about the schedule was refused"
    );
}

/// A fallback seed that was waiting out a long backoff is retried at once when
/// the public tier dies: leaving the public tier is immediate, not a timer
/// (§9 scenario 4, the re-arm half).
///
/// The draw is pinned at the ceiling of each wait, and the fallback station
/// closes every arriving connection, so the fallback seed's dials fail at once
/// and by three seconds it is asleep in its third wait — its whole ~12.8 s.
/// A station that merely drops the seed's datagrams instead would leave its
/// first dial in flight, and that dial finishes the moment the station is
/// reachable, with no re-arm sent at all: the test then passes either way
/// (macula-rust#68 r=2).
#[tokio::test(flavor = "multi_thread")]
async fn a_fallback_retry_rearms_when_the_public_tier_dies() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("rearm public");
    let fallback = lab.station("rearm fallback");
    lab.refuse(&fallback, Duration::from_secs(30));
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.redial.base = Duration::from_millis(200);
    opts.redial.factor = 8;
    opts.redial.cap = Duration::from_secs(60);
    opts.redial.jitter = Jitter::Ceiling;
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    within(Duration::from_secs(10), "the public link up", || {
        p.status().iter().any(|l| l.up && l.tier == Tier::Public)
    })
    .await;
    // Two refused fallback dials take ~200 ms and ~1.6 s; the third waits
    // ~12.8 s. Nothing arriving at the station for two seconds after three
    // means the seed is asleep in that third wait, not looping over a shorter
    // one.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let dialed = lab.arrivals(&fallback);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let still = lab.arrivals(&fallback);
    assert!(
        still == dialed,
        "the fallback seed dialed {still} times, not {dialed}, while it should be asleep in its third wait"
    );

    lab.stop(&public);
    lab.allow(&fallback);
    within(
        Duration::from_secs(6),
        "the fallback link, re-armed at the floor",
        || p.status().iter().any(|l| l.up && l.tier == Tier::Fallback),
    )
    .await;
}

/// The re-arm the other way, from the link that comes back: a public seed
/// asleep in its third wait is cut to the floor the moment another public
/// seed's handshake lands, and dials then, not at its step (macula-rust#68
/// r=2). The draw is pinned at the ceiling of each wait, so the waiting seed's
/// third step is its whole ~12.8 s.
///
/// The seed that comes back is behind a relay that holds each of its datagrams
/// a tenth of a second, so its one dial is still running when the waiting
/// seed's third wait starts: measured, a link through that relay comes up in
/// about 2.8 s, and the waiting seed is asleep from 1.8 s. The falling tier is
/// what makes that seed's failed dials count; its station closes every arriving
/// connection until the other link is up, so it is asleep, not looping, when
/// the tier moves.
#[tokio::test(flavor = "multi_thread")]
async fn a_returning_public_link_rearms_a_public_seed_that_is_waiting() {
    let lab = Lab::start(Profile::PqPure);
    let returning = lab.station("rearm returning public");
    let waiting = lab.station("rearm waiting public");
    let fallback = lab.station("rearm fallback");
    // Never reachable: it is here only so that no public link up means the
    // fallback tier, which is what makes the waiting seed's dials count.
    let (fallback_relay, fallback_seed) = relayed_after(&fallback, Duration::ZERO);
    fallback_relay.close();
    let (_slow_relay, returning_seed) = relayed_after(&returning, Duration::from_millis(100));
    lab.refuse(&waiting, Duration::from_secs(30));
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback_seed];
    opts.redial.base = Duration::from_millis(200);
    opts.redial.factor = 8;
    opts.redial.cap = Duration::from_secs(60);
    opts.redial.jitter = Jitter::Ceiling;
    let started = Instant::now();
    let p = Pool::connect(vec![returning_seed, waiting.seed()], opts)
        .await
        .unwrap();
    // Three refused dials — 200 ms, 1.6 s, then the 12.8 s one — and the
    // waiting seed is asleep. Exactly three: a fourth would mean it dialed
    // inside a step it should be asleep for, and a link back inside its third
    // wait would pass with the re-arm removed, on the respawn delay or on its
    // own timer.
    let dialed = lab.arrivals(&waiting);
    assert_eq!(
        dialed, 3,
        "the waiting seed should be asleep in its third wait after three dials, not dialing: {dialed} arrivals"
    );
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(10),
        "the returning link took {waited:?}, too near the waiting seed's own 12.8 s step"
    );
    lab.allow(&waiting);
    within(
        Duration::from_secs(3),
        "the waiting public seed up at the floor",
        || {
            p.status()
                .iter()
                .filter(|l| l.tier == Tier::Public)
                .all(|l| l.up)
        },
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
    /// A signed advertisement of `procedure`, and its wire bytes: the record a
    /// test puts itself, at whichever station the assertion is about.
    fn signed(procedure: &str) -> (StationRecord, Vec<u8>) {
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
        let wire = record::encode(&signed).expect("its wire");
        (
            StationRecord {
                key: record::procedure_key(&REALM, procedure),
                procedure: procedure.to_string(),
            },
            wire,
        )
    }

    /// Puts one node's advertisement of `procedure` at `s` alone.
    fn put_only_at(lab: &Lab, s: &LabStation, procedure: &str) -> StationRecord {
        let (found, wire) = StationRecord::signed(procedure);
        lab.put(s, &wire);
        found
    }
}

/// A station procedure — a DHT put, then a DHT find — reaches the active
/// tier's links only: the fallback station is never asked (§9 scenario 1, the
/// station-procedure half).
#[tokio::test(flavor = "multi_thread")]
async fn a_station_procedure_reaches_only_the_active_tier() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("procedure public");
    let fallback = lab.station("procedure fallback");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    let them = p.node_id();

    let (found, wire) = StationRecord::signed("tier/procedure/lookup");
    p.put_record(&wire)
        .await
        .expect("the put lands on the active tier");
    assert_eq!(
        lab.asked(&public, &them, "_dht.put_record"),
        1,
        "the active tier's station kept it"
    );
    assert_eq!(
        lab.asked(&fallback, &them, "_dht.put_record"),
        0,
        "the fallback station was never asked to keep anything"
    );

    let record = p
        .find_record(&found.key)
        .await
        .expect("the active tier answers the find");
    assert_eq!(
        record::read_procedure_advertisement(record.record())
            .expect("an advertisement")
            .procedure,
        found.procedure
    );
    assert_eq!(
        lab.asked(&fallback, &them, "_dht.find_record"),
        0,
        "the fallback station was never asked to look anything up"
    );
}

/// A content announcement reaches the active tier only: the announcement
/// record is under the content id's key at the public station alone. The
/// content *procedure's* advertisement is standing state and is on both links;
/// the announcement of the content id is not (§9 scenario 1, the content
/// half).
#[tokio::test(flavor = "multi_thread")]
async fn a_content_announcement_reaches_only_the_active_tier() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("content public");
    let fallback = lab.station("content fallback");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    let mcid = p
        .share_content(&REALM, b"the smallest content there is", "tiny")
        .await
        .expect("shared");
    let key = record::content_key(&mcid).expect("a content key");

    // The active tier's station holds the announcement...
    let on_public = p
        .link_to(&public.node_id)
        .await
        .expect("a direct link to the public station");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut announced = false;
    while !announced && Instant::now() < deadline {
        announced = on_public.find_record(&key).await.is_ok();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        announced,
        "the active tier's station holds the content announcement"
    );

    // ...and the fallback station holds nothing under that key.
    let on_fallback = p
        .link_to(&fallback.node_id)
        .await
        .expect("a direct link to the fallback station");
    assert!(
        on_fallback.find_record(&key).await.is_err(),
        "the fallback station carries no announcement"
    );
}

/// The announcement names a station of the active tier, and the tier's order
/// is the measurement's, not the seed list's: with the slower public station
/// seeded first, the announcement names the faster one (§9 scenario 1's
/// content half, read off §4's RTT order). A selection that took the links in
/// seed order — `links()` rather than `targets()` — names the slow station.
#[tokio::test(flavor = "multi_thread")]
async fn the_content_announcement_names_the_fastest_public_station() {
    let lab = Lab::start(Profile::PqPure);
    let slow = lab.station("content rtt slow");
    let fast = lab.station("content rtt fast");
    let (_relay, slow_seed) = relayed_after(&slow, Duration::from_millis(40));
    let p = Pool::connect(vec![slow_seed, fast.seed()], opts())
        .await
        .unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    // A handshake measures the path; a moment more lets both estimates settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mcid = p
        .share_content(&REALM, b"the announcement names a station", "tiny")
        .await
        .expect("shared");
    let key = record::content_key(&mcid).expect("a content key");
    let link = p
        .link_to(&fast.node_id)
        .await
        .expect("a direct link to the fast station");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut announced = None;
    while announced.is_none() && Instant::now() < deadline {
        announced = link.find_record(&key).await.ok();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let verified = announced.expect("the active tier's station holds the announcement");
    let read = record::read_content_announcement(verified.record()).expect("an announcement");
    assert_eq!(
        read.serving_station, fast.node_id,
        "the announcement names the fastest station of the active tier"
    );
}

/// Replication is a maximum within the active tier, never a reason to reach
/// into the other one: `replication_factor` 2 with one live public link sends
/// one copy, and the fallback station carries none (§9 scenario 1, the case
/// that catches a copy count padded from the fallback).
#[tokio::test(flavor = "multi_thread")]
async fn a_second_copy_is_not_taken_from_the_fallback() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("copy public");
    let fallback = lab.station("copy fallback");
    let (_public_listener, mut public_sub) = listener(&lab, &public, public.seed()).await;
    let (_fallback_listener, mut fallback_sub) = listener(&lab, &fallback, fallback.seed()).await;
    let mut opts = opts();
    opts.replication_factor = 2;
    opts.fallback_seeds = vec![fallback.seed()];
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    p.publish(edit("one public link, two copies"))
        .await
        .unwrap();
    assert_eq!(
        heard(
            &mut public_sub,
            "one public link, two copies",
            Duration::from_secs(5)
        )
        .await,
        1,
        "the one live public link carries the copy"
    );
    assert_eq!(
        heard(
            &mut fallback_sub,
            "one public link, two copies",
            Duration::from_millis(500)
        )
        .await,
        0,
        "the second replica is not taken from the fallback"
    );
}

/// The walk of a station procedure re-reads the tier at each attempt and
/// reaches the other tier when the active one has nothing unasked left: a
/// public station that answers nothing on the link it holds sends the find to
/// the fallback, which answers (§9 scenario 3, the mid-walk half). Go's "the
/// active tier is empty" condition stops the walk here instead — the dead
/// link is still the one the tier lists.
#[tokio::test(flavor = "multi_thread")]
async fn the_walk_reaches_the_fallback_when_the_public_station_stops_answering() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("walk public");
    let fallback = lab.station("walk fallback");
    let found = StationRecord::put_only_at(&lab, &fallback, "tier/walk/lookup");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;
    let them = p.node_id();

    // The station holds the link open and answers nothing on it for longer
    // than a call waits: the ask fails there while the active tier still
    // lists that link as the one to use.
    lab.silence(&public, &them, Duration::from_secs(12));

    let record = p
        .find_record(&found.key)
        .await
        .expect("the walk reaches the fallback station");
    assert_eq!(
        record::read_procedure_advertisement(record.record())
            .expect("an advertisement")
            .procedure,
        found.procedure
    );
    assert_eq!(
        lab.asked(&fallback, &them, "_dht.find_record"),
        1,
        "the fallback station answered the walk"
    );
    assert_eq!(
        lab.asked(&public, &them, "_dht.find_record"),
        0,
        "the station that answered nothing answered nothing"
    );
}

/// A body signed on a public link names no fallback station: the
/// advertisement the public station holds names the station it was signed on
/// and no other (§9 scenario 8, the first half). The registration is standing
/// state, so the fallback station holds an advertisement of its own — and each
/// names one station only.
#[tokio::test(flavor = "multi_thread")]
async fn a_public_body_names_no_fallback_station() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("body public");
    let fallback = lab.station("body fallback");
    let p = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    let procedure = record::own_procedure(&p.node_id(), "tier_body");
    let _served = p
        .serve(Offer::unary(
            REALM,
            &procedure,
            handler(|_| async move { Ok(Value::text("served")) }),
        ))
        .await
        .expect("served on both tiers");

    let key = record::procedure_key(&REALM, &procedure);
    let link = p
        .link_to(&public.node_id)
        .await
        .expect("a direct link to the public station");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut advert = None;
    while advert.is_none() && Instant::now() < deadline {
        advert = link.find_record(&key).await.ok();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let verified = advert.expect("the public station holds the advertisement");
    let read = record::read_procedure_advertisement(verified.record()).expect("an advertisement");
    assert_eq!(
        read.serving_stations,
        vec![public.node_id],
        "the body names the station it was signed on, and no fallback station"
    );
}

/// Scenario 8's other half: with the public tier down, a LAN caller resolves
/// the provider through the fallback station's advertisement and its call
/// completes, dialled through that station (§9 scenario 8).
#[tokio::test(flavor = "multi_thread")]
async fn a_lan_caller_reaches_a_provider_through_the_fallback_station() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("lan public");
    let fallback = lab.station("lan fallback");
    let provider = connect_tiered(&[public.seed()], &[fallback.seed()]).await;
    within(Duration::from_secs(15), "both links up", || {
        all_up(&provider)
    })
    .await;

    let procedure = record::own_procedure(&provider.node_id(), "tier_lan_answer");
    let _served = provider
        .serve(Offer::unary(
            REALM,
            &procedure,
            handler(|_| async move { Ok(Value::text("the LAN answer")) }),
        ))
        .await
        .expect("served on both tiers");
    within(
        Duration::from_secs(10),
        "the advertisement at the fallback station",
        || lab.advertised(&fallback, &REALM, &procedure),
    )
    .await;

    // The provider's public station goes away: it is on its LAN fallback now,
    // and that station's advertisement is all a LAN caller has to find it by.
    lab.stop(&public);
    within(
        Duration::from_secs(10),
        "the provider on the fallback tier",
        || provider.active_tier() == Tier::Fallback,
    )
    .await;

    let caller = connect_tiered(&[fallback.seed()], &[]).await;
    let answer = caller
        .call(Call {
            realm: REALM,
            procedure: procedure.clone(),
            ..Call::default()
        })
        .await
        .expect("the call completes through the fallback station");
    assert_eq!(answer, Value::text("the LAN answer"));
    assert!(
        lab.asked(&fallback, &caller.node_id(), "_dht.find_records") >= 1,
        "the caller resolved the provider through the fallback station's advertisement"
    );
}

/// `random` is still there for a caller who asks for it: with the selection
/// set, the RTT order is discarded and both public links take a share (§9
/// scenario 6, the second half).
#[tokio::test(flavor = "multi_thread")]
async fn the_random_selection_the_caller_asks_for_still_shuffles() {
    let lab = Lab::start(Profile::PqPure);
    let first = lab.station("random first");
    let second = lab.station("random second");
    let (_first_listener, mut first_sub) = listener(&lab, &first, first.seed()).await;
    let (_second_listener, mut second_sub) = listener(&lab, &second, second.seed()).await;
    let mut opts = opts();
    opts.replication_factor = 1;
    opts.link_selection = LinkSelection::Random;
    let p = Pool::connect(vec![first.seed(), second.seed()], opts)
        .await
        .unwrap();
    within(Duration::from_secs(15), "both links up", || all_up(&p)).await;

    // One copy each, twenty-four times: an order that never shuffles puts
    // every one of them on the same station (a chance of 2^-23).
    for i in 0..24 {
        p.publish(edit(&format!("shuffled {i}"))).await.unwrap();
    }
    let on_first = heard_any(&mut first_sub, Duration::from_secs(2)).await;
    let on_second = heard_any(&mut second_sub, Duration::from_secs(2)).await;
    assert!(
        on_first >= 1 && on_second >= 1,
        "random reaches both links: {on_first} and {on_second}"
    );
}

/// The schedule as the station sees it: a failed retry waits further along
/// the backoff each time, from a first retry that is the base, up to the cap.
/// The draw is pinned at the ceiling, so what is measured is the schedule
/// rather than luck (§9 scenario 4).
///
/// The first arrival is the dial `connect` made, sampled a little after it
/// happened, so the first gap can read slightly short of the base but never
/// long; the gaps after it are between two sampled arrivals and are exact to
/// the sampler's few milliseconds.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_redial_waits_the_base_and_each_after_it_waits_longer() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("schedule public");
    let fallback = lab.station("schedule fallback");
    let base = Duration::from_millis(400);
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.redial.base = base;
    opts.redial.factor = 2;
    opts.redial.jitter = Jitter::Ceiling;
    // Every dial of the public member arrives at, and is refused by, a station
    // that is up but takes no connection: the arrivals are the schedule.
    lab.refuse(&public, Duration::from_secs(10));
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    assert_eq!(p.active_tier(), Tier::Fallback, "no public link is up");

    let at = arrivals_over(&lab, &public, Duration::from_millis(4600)).await;
    let gaps = gaps(&at);
    assert!(gaps.len() >= 3, "three redials, got {gaps:?}");
    // The schedule's own shape, as §9 states it: every wait at or above the
    // base, longer each attempt, and not past the step after it. A measured
    // gap carries the dial and the handshake on top of the wait, so a whole
    // base of room is allowed above each step — CI measures these in a
    // coverage build, where that overhead is not the one of a fast laptop.
    // The first gap has no floor here: the arrival `connect` made is already
    // in the station's count when sampling starts, so that gap reads short by
    // however long the sampling missed. The floor is pinned in-crate, on the
    // wait itself (pool::member::tests::the_first_retry_waits_exactly_the_base).
    assert!(
        gaps[0] <= base * 2,
        "the first redial waits at most the base, got {:?}",
        gaps[0]
    );
    assert!(
        gaps[1] > gaps[0] && gaps[1] >= base * 2 && gaps[1] <= base * 3,
        "the second redial waits the next ceiling, got {:?}",
        gaps[1]
    );
    assert!(
        gaps[2] > gaps[1] && gaps[2] >= base * 4 && gaps[2] <= base * 5,
        "the third waits the ceiling after that, got {:?}",
        gaps[2]
    );
}

/// A link that completes a handshake and dies before the steady-up window
/// does not reset its backoff: the retry after it waits longer than the one
/// before (§9 scenario 4, connect-then-die).
#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_dies_before_the_steady_up_waits_longer_each_time() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("dies public");
    let fallback = lab.station("dies fallback");
    let base = Duration::from_millis(400);
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.redial.base = base;
    opts.redial.factor = 2;
    opts.redial.steady_up = Duration::from_secs(30);
    opts.redial.jitter = Jitter::Ceiling;
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    until_a_public_link_is_up(&p).await;
    let me = p.node_id();

    let mut waits = Vec::new();
    for _ in 0..2 {
        let before = lab.arrivals(&public);
        let died = Instant::now();
        lab.drop_node(&public, &me);
        until_the_redial(&lab, &public, before).await;
        waits.push(died.elapsed());
        until_a_public_link_is_up(&p).await;
    }
    // Same bound as the schedule test: at or above each step of the schedule,
    // longer each time, and short of the step after it (the gap carries the
    // dial and the handshake as well as the wait).
    assert!(
        waits[0] >= base && waits[0] <= base * 2,
        "the retry after the first death waits the base, got {:?}",
        waits[0]
    );
    assert!(
        waits[1] > waits[0] && waits[1] >= base * 2 && waits[1] <= base * 3,
        "the retry after a death before the steady-up window waits further along, got {:?}",
        waits[1]
    );
}

/// A link that stays up the steady-up window proves itself: its count resets,
/// so a later failure starts again from the base (§9 scenario 4, steady-up).
#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_proves_itself_starts_again_from_the_base() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("steady public");
    let fallback = lab.station("steady fallback");
    let base = Duration::from_millis(400);
    let steady_up = Duration::from_millis(200);
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.redial.base = base;
    opts.redial.factor = 2;
    opts.redial.steady_up = steady_up;
    opts.redial.jitter = Jitter::Ceiling;
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    within(Duration::from_secs(15), "the public link up", || {
        p.status().iter().any(|l| l.up && l.tier == Tier::Public)
    })
    .await;
    let me = p.node_id();

    // A death at once leaves the count where it was: the retry waits the base.
    let before = lab.arrivals(&public);
    lab.drop_node(&public, &me);
    within(Duration::from_secs(10), "the redial", || {
        lab.arrivals(&public) > before
    })
    .await;
    within(Duration::from_secs(10), "the public link up again", || {
        p.status().iter().any(|l| l.up && l.tier == Tier::Public)
    })
    .await;

    // That one stays up past the window, so its count resets: the death after
    // it waits the base again, not two steps along the schedule.
    tokio::time::sleep(steady_up + Duration::from_millis(200)).await;
    let before = lab.arrivals(&public);
    let died = Instant::now();
    lab.drop_node(&public, &me);
    within(
        Duration::from_secs(10),
        "the redial after it proved itself",
        || lab.arrivals(&public) > before,
    )
    .await;
    let waited = died.elapsed();
    // A reset count waits the base; one that kept its count waits the next
    // step, which no amount of dial overhead brings back under this bound.
    assert!(
        waited >= base && waited <= base * 2,
        "a link that proved itself starts again from the base, but the retry waited {waited:?}"
    );
}

/// The tier returns on the handshake and not before: while the public station
/// refuses connections the pool is on its fallback, and the moment a public
/// link completes its handshake the next operation takes it (§9 scenario 4,
/// the handshake half).
#[tokio::test(flavor = "multi_thread")]
async fn the_tier_returns_on_the_handshake_and_not_before() {
    let lab = Lab::start(Profile::PqPure);
    let public = lab.station("handshake public");
    let fallback = lab.station("handshake fallback");
    let (_fallback_listener, mut fallback_sub) = listener(&lab, &fallback, fallback.seed()).await;
    let mut opts = opts();
    opts.fallback_seeds = vec![fallback.seed()];
    opts.redial.base = Duration::from_millis(200);
    lab.refuse(&public, Duration::from_secs(2));
    let p = Pool::connect(vec![public.seed()], opts).await.unwrap();
    assert_eq!(
        p.active_tier(),
        Tier::Fallback,
        "no public link completed a handshake yet"
    );

    within(
        Duration::from_secs(15),
        "the public tier back on the handshake",
        || p.active_tier() == Tier::Public,
    )
    .await;
    assert!(
        p.status().iter().any(|l| l.up && l.tier == Tier::Public),
        "the tier moved on the link that completed it"
    );
    p.publish(edit("back on the public tier"))
        .await
        .expect("the next operation takes the public link");
    assert_eq!(
        heard(
            &mut fallback_sub,
            "back on the public tier",
            Duration::from_millis(500)
        )
        .await,
        0,
        "the fallback carries nothing once the public tier is back"
    );
}
