//! A publication sent on a link that ends before the station read it is sent
//! again on the next link, or counted unsent, never lost silently
//! (macula-rust#57). The publisher reaches its station through a relay
//! (tests/common/blackhole.rs) that loses every packet while closed: what the
//! node writes then leaves it and never arrives, and the link ends when QUIC's
//! idle timeout or the liveness probe gives up on it.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::blackhole::BlackHole;
use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Delivery, Opts, Pool, Seed, Subscription};
use macula_rust::profile::Profile;
use macula_rust::station_link::Publication;

const TOPIC: &str = "mcl-craft/wire/edit_made_v1";
const REALM: [u8; 32] = [7; 32];

/// Longer than the link takes to end on a black-holed path: the station's
/// idle timeout, or two missed liveness probes once that is macula's 300 s.
const LINK_ENDS_WITHIN: Duration = Duration::from_secs(150);

fn key() -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).unwrap())
}

async fn connect(seed: Seed) -> Pool {
    let mut opts = Opts::new(key());
    opts.realm_trust = HashMap::new();
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(vec![seed], opts).await.unwrap()
}

/// A relay in front of `s`, and `s` as a seed reached through it.
fn relayed(s: &LabStation) -> (BlackHole, Seed) {
    let station: SocketAddr = format!("{}:{}", s.host, s.port).parse().unwrap();
    let relay = BlackHole::in_front_of(station);
    let seed = Seed {
        host: relay.addr().ip().to_string(),
        port: relay.addr().port(),
        node_id: s.node_id,
    };
    (relay, seed)
}

async fn within(limit: Duration, what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within {limit:?}: {what}");
}

fn edit(text: &str) -> Publication {
    Publication {
        realm: REALM,
        topic: TOPIC.to_string(),
        payload: Payload::Clear(Value::text(text)),
        ttl_ms: None,
    }
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

/// Publishes `text` while the relay is closed and waits for the link that
/// carried it to end, the publication still unread by the station.
async fn publish_into_the_gap(lab: &Lab, s: &LabStation, relay: &BlackHole, p: &Pool, text: &str) {
    let me = p.node_id();
    within(Duration::from_secs(10), "the publisher's link up", || {
        lab.connected(s, &me) && p.status().iter().any(|l| l.up)
    })
    .await;
    relay.close();
    p.publish(edit(text)).await.unwrap();
    within(LINK_ENDS_WITHIN, "the black-holed link ended", || {
        !p.status().iter().any(|l| l.up)
    })
    .await;
    assert!(
        relay.lost_to_station() > 0,
        "the publication left the node and was lost on the way"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_an_ended_link_lost_arrives_on_the_next_link_once() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("resend");
    let listener = connect(s.seed()).await;
    let mut sub = listener.subscribe(&REALM, TOPIC).await.unwrap();
    let them = listener.node_id();
    within(Duration::from_secs(10), "subscribed", || {
        lab.subscribed(&s, &them, &REALM, TOPIC)
    })
    .await;
    let (relay, seed) = relayed(&s);
    let publisher = connect(seed).await;

    publish_into_the_gap(&lab, &s, &relay, &publisher, "made offline").await;
    assert_eq!(heard(&mut sub, "made offline", Duration::ZERO).await, 0);

    relay.open();
    assert_eq!(
        heard(&mut sub, "made offline", Duration::from_secs(20)).await,
        1
    );
    assert_eq!(publisher.unsent_publications(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_no_link_carried_is_counted_unsent() {
    let lab = Lab::start(Profile::PqPure);
    let s = lab.station("unsent");
    let (relay, seed) = relayed(&s);
    let publisher = connect(seed).await;

    publish_into_the_gap(&lab, &s, &relay, &publisher, "never sent").await;
    assert_eq!(
        publisher.unsent_publications(),
        0,
        "it still waits for a link"
    );
    publisher.close().await;
    assert_eq!(publisher.unsent_publications(), 1);
}
