//! Sealed groups between this SDK and macula's own distributor, end to end.
//! `scripts/interop/groups.sh` starts a station, runs macula's
//! `macula_group_keys` distributor in Erlang from macula's pinned CI image,
//! and then has an Erlang member and the Rust member here subscribe under one
//! group, each pulling the epoch from that distributor over a sealed call
//! with the org's grant, and each publishing sealed under it: each must open
//! the other's event. Last, a node the distributor's removed set names must
//! be refused `not_a_member` at this crate's public subscribe.
//!
//! Both read MACULA_RUST_GROUPS_SEED (host:port), MACULA_RUST_GROUPS_STATION_ID,
//! MACULA_RUST_GROUPS_REALM, MACULA_RUST_GROUPS_REALM_KEY, MACULA_RUST_GROUPS_PROFILE,
//! MACULA_RUST_GROUPS_WORK, MACULA_RUST_GROUPS_PREFIX and MACULA_RUST_GROUPS_TOPIC.
//!
//! The Rust member is the peer the Erlang member's escript waits for: it
//! writes `ready.go` when it is subscribed and waits for `ready.erlang`.
//! Its grant is written by the script, as the Erlang member's is, once each
//! has printed the node id it is.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::group::{Group, Reason};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Opts, Pool, Seed};
use macula_rust::profile::Profile;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(name: &str) -> [u8; 32] {
    hex::decode(var(name))
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{name} must be 64 hex characters"))
}

fn work() -> PathBuf {
    PathBuf::from(var("MACULA_RUST_GROUPS_WORK"))
}

/// A pool on the interop station, with the realm key pinned so the org's
/// distributor advertisement is trusted.
async fn pool() -> (Pool, [u8; 32]) {
    let seed = var("MACULA_RUST_GROUPS_SEED");
    let (host, port) = seed.rsplit_once(':').expect("host:port");
    let profile = Profile::parse(&var("MACULA_RUST_GROUPS_PROFILE")).unwrap();
    let realm = hex32("MACULA_RUST_GROUPS_REALM");
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.connect_timeout = Duration::from_secs(60);
    opts.realm_trust = HashMap::from([(
        realm,
        hex::decode(var("MACULA_RUST_GROUPS_REALM_KEY")).unwrap(),
    )]);
    let pool = Pool::connect(
        vec![Seed {
            host: host.to_string(),
            port: port.parse().unwrap(),
            node_id: hex32("MACULA_RUST_GROUPS_STATION_ID"),
        }],
        opts,
    )
    .await
    .unwrap();
    (pool, realm)
}

/// Waits for the grant the script writes for this node, once the node id it
/// reads from this peer's own output is known.
async fn granted_here(node: &[u8; 32]) -> String {
    let path = work().join(format!("grant.{}", hex_of(node)));
    let deadline = Instant::now() + Duration::from_secs(180);
    while !path.exists() {
        assert!(Instant::now() < deadline, "no grant at {}", path.display());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    std::fs::read_to_string(path).unwrap().trim().to_string()
}

/// The group this peer joins, with the org's grant.
fn group(ucan: String) -> Group {
    Group {
        prefix: var("MACULA_RUST_GROUPS_PREFIX"),
        ucan: ucan.into_bytes(),
        distributor: None,
    }
}

/// Waits for a file the other member writes, up to `secs`.
async fn wait_for(name: &str, secs: u64) {
    let path = work().join(name);
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !path.exists() {
        assert!(Instant::now() < deadline, "no {}", path.display());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The Rust member: subscribes under the group, publishes "from rust" sealed,
/// and must hear the Erlang member's "from erlang" opened under the same
/// epoch. Its output is the peer's, read by the script: the node id first,
/// then what it heard.
#[tokio::test]
#[ignore]
async fn a_rust_member_and_macula_open_each_others_events_under_one_epoch() {
    let (pool, realm) = pool().await;
    let node = pool.node_id();
    println!("node {}", hex_of(&node));
    let grant = granted_here(&node).await;
    let group = group(grant);
    let topic = var("MACULA_RUST_GROUPS_TOPIC");

    let mut sub = pool
        .subscribe_group(&realm, &topic, &group)
        .await
        .expect("the member subscribes under the group");
    println!("subscribed");
    // A SUBSCRIBE is sent, not acknowledged: the station registers it in its
    // own time. This peer writes the barrier the other member publishes on,
    // so it waits here rather than let the other publish into a subscription
    // the station does not have yet, which is what the crate's own tests do
    // after subscribing too.
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(work().join("ready.go"), b"").unwrap();
    wait_for("ready.erlang", 180).await;

    pool.publish_group(&realm, &topic, &group, Value::text("from rust"))
        .await
        .expect("the member publishes sealed under the group");
    println!("published");

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut heard = None;
    while heard.is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "nothing from erlang (dropped {}, refused {})",
            sub.dropped(),
            sub.refused()
        );
        heard = tokio::time::timeout(left, sub.recv())
            .await
            .ok()
            .flatten()
            .and_then(|event| opened_text(&event, "from erlang"));
    }
    let epoch = heard.expect("an event from erlang");
    println!("opened from erlang under {}", hex_of(&epoch));
}

/// The epoch an event opened under, when it opened to `wanted`. `None` for an
/// event that is not that one, which is what the member's own publication is:
/// a station hands it back to the node that made it, as macula's go peer
/// skips it too. An event that could not be opened fails the test rather than
/// being passed over.
fn opened_text(event: &macula_rust::station_link::Event, wanted: &str) -> Option<[u8; 8]> {
    if let Some(reason) = event.unopened {
        panic!("an event did not open: {reason}");
    }
    let Payload::Clear(Value::Text(text)) = &event.payload else {
        return None;
    };
    if text != wanted {
        return None;
    }
    Some(event.seal_key_id.expect("a sealed event names its epoch"))
}

/// A node the distributor's removed set names: it is granted like any other,
/// and its subscribe must be refused `not_a_member` at this crate's public
/// API, not only by the distributor's own answer.
#[tokio::test]
#[ignore]
async fn a_removed_node_is_refused_at_the_public_subscribe() {
    let (pool, realm) = pool().await;
    println!("node {}", hex_of(&pool.node_id()));
    let grant = granted_here(&pool.node_id()).await;
    let group = group(grant);

    match pool
        .subscribe_group(&realm, &var("MACULA_RUST_GROUPS_TOPIC"), &group)
        .await
    {
        Ok(_) => panic!("a removed node subscribed under the group"),
        Err(e) => {
            println!("stranger subscribe: {e}");
            assert!(e.is(Reason::NotAMember), "refused with {e}");
        }
    }
}
