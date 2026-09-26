//! A live run against one macula 12 station: the pool connects pinned with a
//! key generated for the run and never saved, reads the DHT, calls
//! mcl-echo/echo by direct dial, and hears its own publication. The tests
//! are ignored by default and run with `cargo test --test live -- --ignored`;
//! they need every one of MACULA_RUST_LIVE_SEED (host:port, [v6]:port for
//! IPv6), MACULA_RUST_LIVE_STATION_ID, MACULA_RUST_LIVE_REALM and
//! MACULA_RUST_LIVE_REALM_KEY (hex), and an unset one fails the run, naming
//! it. They put nothing in the DHT, and publish once.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Call, Opts, Pool, Seed};
use macula_rust::profile::Profile;
use macula_rust::record::RecordType;
use macula_rust::station_link::Publication;

const VARIABLES: [&str; 4] = [
    "MACULA_RUST_LIVE_SEED",
    "MACULA_RUST_LIVE_STATION_ID",
    "MACULA_RUST_LIVE_REALM",
    "MACULA_RUST_LIVE_REALM_KEY",
];

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn hex32(name: &str) -> [u8; 32] {
    hex::decode(var(name))
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{name} must be 64 hex characters"))
}

/// A pool on the live seed as a pq_hybrid key made for this run, and the
/// realm it trusts.
async fn live() -> (Pool, [u8; 32]) {
    let missing: Vec<&str> = VARIABLES
        .iter()
        .copied()
        .filter(|v| var(v).is_empty())
        .collect();
    assert!(missing.is_empty(), "live tests need {}", missing.join(", "));
    let seed = var("MACULA_RUST_LIVE_SEED");
    let (host, port) = seed
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("MACULA_RUST_LIVE_SEED must be host:port, got {seed}"));
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let realm = hex32("MACULA_RUST_LIVE_REALM");
    let key = Arc::new(NodeKey::generate_identity(Profile::PqHybrid, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.realm_trust = HashMap::from([(
        realm,
        hex::decode(var("MACULA_RUST_LIVE_REALM_KEY")).unwrap(),
    )]);
    opts.connect_timeout = Duration::from_secs(60);
    let pool = Pool::connect(
        vec![Seed {
            host,
            port: port.parse().expect("the seed's port"),
            node_id: hex32("MACULA_RUST_LIVE_STATION_ID"),
        }],
        opts,
    )
    .await
    .unwrap();
    (pool, realm)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: needs MACULA_RUST_LIVE_* and a macula 12 station"]
async fn the_station_holds_verified_node_records() {
    let (pool, _) = live().await;
    let (records, _) = pool
        .find_records_by_type(RecordType::NODE_RECORD)
        .await
        .unwrap();
    assert!(!records.is_empty());
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: needs MACULA_RUST_LIVE_* and a macula 12 station"]
async fn mcl_echo_is_reached_by_direct_dial() {
    let (pool, realm) = live().await;
    let answered = pool
        .call(Call {
            realm,
            procedure: "mcl-echo/echo".into(),
            payload: Value::text("hello"),
            timeout: Duration::from_secs(15),
            ..Call::default()
        })
        .await
        .unwrap();
    assert_eq!(answered, Value::text("hello"));
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: needs MACULA_RUST_LIVE_* and a macula 12 station"]
async fn the_pool_hears_its_own_publication() {
    let (pool, realm) = live().await;
    let mut suffix = [0u8; 8];
    aws_lc_rs::rand::fill(&mut suffix).unwrap();
    let topic = format!(
        "mcl-rust/live/check/publication_heard_v1/{}",
        hex::encode(suffix)
    );
    let mut sub = pool.subscribe(&realm, &topic).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.publish(Publication {
        realm,
        topic,
        payload: Value::text("heard"),
        ttl_ms: None,
    })
    .await
    .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(10), sub.recv()).await;
    let _ = sub.unsubscribe().await;
    pool.close().await;
    assert_eq!(event.unwrap().unwrap().payload, Value::text("heard"));
}
