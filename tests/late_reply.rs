//! A reply arriving after its call gave up is counted as unmatched and the
//! link goes on: matching it once held the link's state lock while counting
//! it, which took the same lock again and hung the link's reader for good,
//! and with it every caller of that link. Against macula-go's in-process
//! stations (tests/common).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{handler, Call, Config, Link, Offer, Seal};

async fn node(env: &TestStations, station: usize) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    Link::dial(Config::new(env.target(station), identity, issuer))
        .await
        .unwrap()
}

/// How many replies `link` could not match, read off the runtime's workers
/// so a link whose state is locked for good fails the test instead of
/// hanging it.
async fn unmatched(link: &Link) -> u64 {
    let link = link.clone();
    let read = tokio::task::spawn_blocking(move || {
        link.unrouted().get("unmatched_reply").copied().unwrap_or(0)
    });
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("the link's state is readable")
        .unwrap()
}

/// Answers when the request's deadline comes, as the provider's own watch on
/// it does: either answer leaves at the deadline, and the caller's wait ends
/// within a millisecond of it, so now and then the reply arrives after.
async fn at_the_deadline(deadline_ms: u64) -> Result<Value, String> {
    let left = deadline_ms.saturating_sub(now_ms());
    tokio::time::sleep(Duration::from_millis(left)).await;
    Ok(Value::text("at the deadline"))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_after_its_call_gave_up_is_counted_and_the_link_goes_on() {
    let env = TestStations::start(Profile::PqPure);
    let provider = node(&env, 0).await;
    let procedure = record::own_procedure(&provider.node_id(), "at_the_deadline");
    let answer = handler(|r| at_the_deadline(r.deadline_ms));
    let _served = provider
        .serve(Offer::unary(env.realm_id, &procedure, answer))
        .await
        .unwrap();
    let caller = node(&env, 0).await;
    let call = || Call {
        realm: env.realm_id,
        procedure: procedure.clone(),
        target: provider.node_id(),
        timeout: Duration::from_millis(50),
        seal: Some(Seal::Clear),
        ..Call::default()
    };

    let mut calls = 0;
    while unmatched(&caller).await == 0 {
        assert!(calls < 300, "no reply came late in {calls} calls");
        let _ = caller.call(call()).await;
        calls += 1;
    }
    // The link still reads and answers.
    let answered = tokio::time::timeout(Duration::from_secs(2), caller.call(call())).await;
    assert!(
        answered.is_ok(),
        "the link answers a call after the late reply"
    );
}
