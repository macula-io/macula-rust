//! Sealed calls and streams between this SDK and macula 13, end to end, both
//! ways. scripts/interop/sealed.sh starts a station, then:
//!
//! - an Erlang provider that switches kem_advertise on and serves
//!   ~<node>/vault (a call) and ~<node>/watch (a server stream), both
//!   confidential => required, and runs the caller test here against it;
//! - the provider test here, which serves the same two procedures, required,
//!   from a pool with kem_advertise on, prints "node <hex>" and "serving" and
//!   holds, while erlang_sealed.escript calls them as macula does.
//!
//! Both read MACULA_RUST_SEALED_SEED (host:port),
//! MACULA_RUST_SEALED_STATION_ID, MACULA_RUST_SEALED_REALM and
//! MACULA_RUST_SEALED_PROFILE; the caller also MACULA_RUST_SEALED_PROVIDER
//! (hex), the provider MACULA_RUST_SEALED_HOLD (seconds).
//!
//! A required provider refuses every clear request, so an answer at all
//! proves the request was sealed to the key its advertisement names and the
//! answer opened under the keys it agreed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{
    Call, Confidentiality, Offer, Opts, Pool, PoolError, Report, Seed, StreamCall,
};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::station_link::{handler, stream_handler, StreamEvent};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn hex32(name: &str) -> [u8; 32] {
    hex::decode(var(name))
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{name} must be 64 hex characters"))
}

/// A pool on the interop station, with kem_advertise as given, and the
/// realm.
async fn pool(kem_advertise: bool) -> (Pool, [u8; 32]) {
    let seed = var("MACULA_RUST_SEALED_SEED");
    let (host, port) = seed.rsplit_once(':').expect("host:port");
    let profile = Profile::parse(&var("MACULA_RUST_SEALED_PROFILE")).unwrap();
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.connect_timeout = Duration::from_secs(60);
    opts.kem_advertise = kem_advertise;
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
    (pool, hex32("MACULA_RUST_SEALED_REALM"))
}

/// The provider's advertisement reaches the DHT in its own time.
async fn until_served(pool: &Pool, c: Call) -> Result<(Value, Report), PoolError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match pool.call_report(c.clone()).await {
            Err(PoolError::NoProvider(tried)) if tried.is_empty() && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            outcome => return outcome,
        }
    }
}

/// One call to macula's vault, `confidential` as given, answered sealed by
/// `provider`; returns its report.
async fn sealed_call(
    pool: &Pool,
    realm: [u8; 32],
    vault: &str,
    provider: [u8; 32],
    confidential: Confidentiality,
) -> Report {
    let answered = until_served(
        pool,
        Call {
            realm,
            procedure: vault.to_string(),
            payload: Value::Map(vec![(Value::text("n"), Value::Int(1))]),
            timeout: Duration::from_secs(10),
            confidential,
            ..Call::default()
        },
    )
    .await;
    println!("sealed call ({confidential:?}): {answered:?}");
    let (result, report) = answered.unwrap();
    assert_eq!(result, Value::text("kept by erlang"));
    println!("call report: {report:?}");
    assert_eq!((report.sealed, report.provider), (1, provider));
    assert!(report.seal_key_id.is_some());
    report
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "interop: run by scripts/interop/sealed.sh"]
async fn a_sealed_call_and_stream_reach_a_required_macula_provider() {
    let (pool, realm) = pool(false).await;
    let provider = hex32("MACULA_RUST_SEALED_PROVIDER");
    let vault = record::own_procedure(&provider, "vault");
    let watch = record::own_procedure(&provider, "watch");
    let mut call_key = None;
    for confidential in [Confidentiality::Preferred, Confidentiality::Required] {
        call_key = sealed_call(&pool, realm, &vault, provider, confidential)
            .await
            .seal_key_id;
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
    let report = stream.report();
    println!("stream report: {report:?}");
    assert_eq!(
        report,
        Ok(Report {
            sealed: 1,
            provider,
            seal_key_id: call_key,
        })
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "interop: run by scripts/interop/sealed.sh"]
async fn a_required_rust_provider_serves_a_macula_caller_sealed() {
    let (pool, realm) = pool(true).await;
    let node = pool.node_id();
    let vault = record::own_procedure(&node, "vault");
    let watch = record::own_procedure(&node, "watch");
    let mut call = Offer::unary(
        realm,
        &vault,
        handler(|r| async move {
            match r.sealed {
                true => Ok(Value::text("kept by rust")),
                false => Err("a clear request reached a required handler".into()),
            }
        }),
    );
    call.confidential = Confidentiality::Required;
    let mut stream = Offer::stream(
        realm,
        &watch,
        StreamMode::ServerStream,
        stream_handler(|s| async move {
            s.send(b"chunk from rust")
                .await
                .map_err(|e| e.to_string())?;
            s.reply(Value::text("streamed by rust"))
                .await
                .map_err(|e| e.to_string())
        }),
    );
    stream.confidential = Confidentiality::Required;
    let _call = pool.serve(call).await.unwrap();
    let _stream = pool.serve(stream).await.unwrap();
    println!("node {}", hex::encode(node));
    println!("serving");
    let hold: u64 = var("MACULA_RUST_SEALED_HOLD").parse().unwrap();
    tokio::time::sleep(Duration::from_secs(hold)).await;
    pool.close().await;
}
