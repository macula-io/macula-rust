//! Sealed calls and streams from this SDK to a macula 13 provider, end to
//! end: scripts/interop/sealed.sh starts a station and an Erlang provider
//! that switches kem_advertise on and serves ~<node>/vault (a call) and
//! ~<node>/watch (a server stream), both confidential => required, then runs
//! this test with:
//!
//! MACULA_RUST_SEALED_SEED (host:port), MACULA_RUST_SEALED_STATION_ID,
//! MACULA_RUST_SEALED_REALM, MACULA_RUST_SEALED_PROFILE and
//! MACULA_RUST_SEALED_PROVIDER (hex).
//!
//! A required provider refuses every clear request, so an answer at all
//! proves the request was sealed to the key its advertisement names and the
//! answer opened under the keys it agreed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Call, Confidentiality, Opts, Pool, PoolError, Seed, StreamCall};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::station_link::StreamEvent;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn hex32(name: &str) -> [u8; 32] {
    hex::decode(var(name))
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{name} must be 64 hex characters"))
}

async fn pool() -> (Pool, [u8; 32], [u8; 32]) {
    let seed = var("MACULA_RUST_SEALED_SEED");
    let (host, port) = seed.rsplit_once(':').expect("host:port");
    let profile = Profile::parse(&var("MACULA_RUST_SEALED_PROFILE")).unwrap();
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.connect_timeout = Duration::from_secs(60);
    let pool = Pool::connect(
        vec![Seed {
            host: host.to_string(),
            port: port.parse().unwrap(),
            node_id: hex32("MACULA_RUST_SEALED_STATION_ID"),
        }],
        opts,
    )
    .await
    .unwrap();
    (
        pool,
        hex32("MACULA_RUST_SEALED_REALM"),
        hex32("MACULA_RUST_SEALED_PROVIDER"),
    )
}

/// The provider's advertisement reaches the DHT in its own time.
async fn until_served(pool: &Pool, c: Call) -> Result<Value, PoolError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match pool.call(c.clone()).await {
            Err(PoolError::NoProvider(tried)) if tried.is_empty() && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            outcome => return outcome,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "interop: run by scripts/interop/sealed.sh"]
async fn a_sealed_call_and_stream_reach_a_required_macula_provider() {
    let (pool, realm, provider) = pool().await;
    let vault = record::own_procedure(&provider, "vault");
    let watch = record::own_procedure(&provider, "watch");
    for confidential in [Confidentiality::Preferred, Confidentiality::Required] {
        let answered = until_served(
            &pool,
            Call {
                realm,
                procedure: vault.clone(),
                payload: Value::Map(vec![(Value::text("n"), Value::Int(1))]),
                timeout: Duration::from_secs(10),
                confidential,
                ..Call::default()
            },
        )
        .await;
        println!("sealed call ({confidential:?}): {answered:?}");
        assert_eq!(answered.unwrap(), Value::text("kept by erlang"));
    }

    let stream = pool
        .open_stream(StreamCall {
            realm,
            procedure: watch,
            mode: StreamMode::ServerStream,
            payload: Value::Map(Vec::new()),
            ..StreamCall::default()
        })
        .await
        .unwrap();
    let chunk = stream.recv().await;
    println!("sealed stream chunk: {chunk:?}");
    assert!(
        matches!(&chunk, Ok(StreamEvent::Data { body: Value::Bytes(b), .. }) if b == b"chunk from erlang"),
        "{chunk:?}"
    );
    let reply = stream.recv().await;
    println!("sealed stream reply: {reply:?}");
    assert_eq!(
        reply.unwrap(),
        StreamEvent::Reply {
            payload: Value::text("streamed by erlang")
        }
    );
    pool.close().await;
}
