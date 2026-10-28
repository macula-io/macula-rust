//! A group's epoch rotating live (macula-rust#52): a distributor of this
//! crate serving at a one-second rotation, and two members of its group,
//! against macula-go's in-process stations (tests/common). A member never
//! sets its rotation: it reads it from the epochs the distributor hands out,
//! so the interval a test shortens is the distributor's
//! [`DistributorOptions::rotate_after_ms`], with [`Caps::epochs`] raised to
//! the [`chain_bound`] that rotation needs.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::group::{
    chain_bound, Distributor, DistributorOptions, Group, Membership, MembershipCheck, Policy,
};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Opts, Pool, Seed, Subscription};
use macula_rust::profile::Profile;

/// How long the test group's epochs publish.
const ROTATION_MS: i64 = 1_000;

/// A pool for a new node on both stations, trusting the test realm, with
/// kem_advertise on so it may serve a sealed-only distributor.
async fn pool(env: &TestStations, key: Arc<NodeKey>) -> Pool {
    let mut opts = Opts::new(key);
    opts.realm_trust = HashMap::from([(env.realm_id, env.realm_key.clone())]);
    opts.kem_advertise = true;
    let seeds = env
        .stations
        .iter()
        .map(|s| Seed {
            host: s.host.clone(),
            port: s.port,
            node_id: s.node_id,
        })
        .collect();
    Pool::connect(seeds, opts).await.unwrap()
}

/// A new node key in the stations' profile.
fn key(env: &TestStations) -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap())
}

/// Every caller is a member: membership is not what this test is about.
fn everyone() -> MembershipCheck {
    Arc::new(|_prefix: String, _caller: [u8; 32]| Box::pin(std::future::ready(Membership::In)) as _)
}

/// The org's distributor, rotating every [`ROTATION_MS`], served by a node
/// the org delegated its procedures to.
async fn host(env: &TestStations) -> (Pool, macula_rust::pool::Served) {
    let key = key(env);
    env.admit(&key.node_id().unwrap());
    let host = pool(env, key).await;
    let mut options = DistributorOptions::new(&env.org, Policy::Required, everyone());
    options.rotate_after_ms = ROTATION_MS;
    options.caps.epochs = chain_bound(ROTATION_MS);
    let distributor = Distributor::new(options).unwrap();
    let served = host
        .serve(distributor.offer(env.realm_id, env.org_key_id))
        .await
        .unwrap();
    (host, served)
}

/// A member of `prefix` granted by the org, pulling from `distributor`.
async fn member(env: &TestStations, prefix: &str, distributor: [u8; 32]) -> (Pool, Group) {
    let pool = pool(env, key(env)).await;
    let group = Group {
        prefix: prefix.to_string(),
        ucan: env.grant(&pool.node_id()).into_bytes(),
        distributor: Some(distributor),
    };
    (pool, group)
}

/// The epoch the next event opened under, when it is `wanted`; `None` when
/// the event is another one or none came within `left`.
async fn heard(sub: &mut Subscription, wanted: &str, left: Duration) -> Option<[u8; 8]> {
    let event = tokio::time::timeout(left, sub.recv()).await.ok()??;
    if let Some(reason) = event.unopened {
        panic!("an event did not open: {reason}");
    }
    match &event.payload {
        Payload::Clear(Value::Text(text)) if text == wanted => event.seal_key_id,
        _ => None,
    }
}

/// A writer publishes sealed every quarter of a rotation and a reader opens
/// each event, until the reader has opened events under three epochs: both
/// members pulled the group's key across two rotations, the writer its next
/// epoch to seal under and the reader the one each event names.
#[tokio::test(flavor = "multi_thread")]
async fn members_keep_sealing_and_opening_across_a_one_second_rotation() {
    let env = TestStations::start(Profile::PqPure);
    let (host, _served) = host(&env).await;
    let prefix = format!("{}/{}/notes", env.realm_name, env.org);
    let topic = format!("{prefix}/note_written_v1");
    let (reader, reader_group) = member(&env, &prefix, host.node_id()).await;
    let (writer, writer_group) = member(&env, &prefix, host.node_id()).await;
    let mut sub = reader
        .subscribe_group(&env.realm_id, &topic, &reader_group)
        .await
        .expect("the reader joins and subscribes");

    let mut epochs: Vec<[u8; 8]> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut n = 0;
    while epochs.len() < 3 {
        assert!(
            Instant::now() < deadline,
            "opened under {} epochs in 60 s",
            epochs.len()
        );
        let note = format!("note {n}");
        writer
            .publish_group(&env.realm_id, &topic, &writer_group, Value::text(&note))
            .await
            .expect("the writer seals under the current epoch");
        let opened = heard(&mut sub, &note, Duration::from_secs(5)).await;
        epochs.extend(opened.filter(|e| !epochs.contains(e)));
        n += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
