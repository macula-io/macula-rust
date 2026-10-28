//! A pool learns the key a clear call's or stream's refusal names (release
//! A0, DESIGN_E2E_SEALED_BY_DEFAULT section 3, macula-rust#42), against
//! macula-go's in-process stations (tests/common/lab.rs). The pool
//! remembers a provider from before it keyed, whose advertisement named no
//! key; the provider then serves keyed and requires sealing. The pool's next
//! call goes in the clear, is refused sealed_required naming the provider's
//! key, and is sealed to it once more; the pool remembers the key, so the
//! call after goes sealed the first time with no second refusal. A stream
//! learns the same way. The pool remembers per (realm, procedure,
//! provider), so each is shown on its own procedure.

mod common;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Call, Opts, Pool, StreamCall};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::seal::{Clock, Keyring, KEY_LIFETIME_MS, RETIRED_KEY_KEPT_MS};
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Confidentiality, Config, Link, LinkError, Offer, Served, Stream,
    StreamEvent,
};
use macula_rust::transport::Target;

const REALM: [u8; 32] = [0x5f; 32];

/// A provider of `identity` linked to `s`: with `keyring`, keyed,
/// advertising its key and naming it in a sealed_required refusal.
async fn provider(s: &LabStation, identity: Arc<NodeKey>, keyring: Option<Arc<Keyring>>) -> Link {
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: s.host.clone(),
        port: s.port,
        profile: identity.profile(),
        expected_node_id: s.node_id,
    };
    let mut cfg = Config::new(target, identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.refusal_names_key = keyring.is_some();
    cfg.keyring = keyring;
    Link::dial(cfg).await.unwrap()
}

async fn caller(profile: Profile, s: &LabStation) -> Pool {
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(vec![s.seed()], opts).await.unwrap()
}

/// Serves an echo of `procedure` and a one-chunk server stream of `watch`,
/// required to be sealed when `required`.
async fn serve_both(link: &Link, echo: &str, watch: &str, required: bool) -> [Served; 2] {
    let confidential = match required {
        true => Confidentiality::Required,
        false => Confidentiality::Preferred,
    };
    let mut unary = Offer::unary(REALM, echo, handler(|r| async move { Ok(r.payload) }));
    unary.confidential = confidential;
    let sent =
        stream_handler(
            |s: Stream| async move { s.send(b"watched").await.map_err(|e| e.to_string()) },
        );
    let mut stream = Offer::stream(REALM, watch, StreamMode::ServerStream, sent);
    stream.confidential = confidential;
    [
        link.serve(unary).await.unwrap(),
        link.serve(stream).await.unwrap(),
    ]
}

/// How many times the link counted `what`.
fn counted(link: &Link, what: &str) -> u64 {
    link.unrouted().get(what).copied().unwrap_or(0)
}

/// The stream's first event, within five seconds, and whether it was sealed.
async fn watched(pool: &Pool, open: StreamCall) -> bool {
    let stream = pool.open_stream(open).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .expect("an event within five seconds")
        .unwrap();
    assert_eq!(
        first,
        StreamEvent::Data {
            encoding: StreamEncoding::Raw,
            body: Value::Bytes(b"watched".to_vec()),
        }
    );
    stream.sealed()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pool_that_resealed_a_clear_call_or_stream_seals_the_next_first_time() {
    let profile = Profile::PqHybrid;
    let lab = Lab::start(profile);
    let station = lab.station("clear reseal");
    let identity = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let echo = record::own_procedure(&identity.node_id().unwrap(), "echo");
    let watch = record::own_procedure(&identity.node_id().unwrap(), "watch");
    let call = Call {
        realm: REALM,
        procedure: echo.clone(),
        payload: Value::text("kept"),
        ..Call::default()
    };
    let open = StreamCall {
        realm: REALM,
        procedure: watch.clone(),
        mode: StreamMode::ServerStream,
        ..StreamCall::default()
    };

    // Before it keys: the pool calls and opens in the clear and remembers
    // the keyless provider.
    let keyless = provider(&station, identity.clone(), None).await;
    let served = serve_both(&keyless, &echo, &watch, false).await;
    let pool = caller(profile, &station).await;
    let (_, report) = pool.call_report(call.clone()).await.unwrap();
    assert_eq!(report.sealed, 0);
    assert!(!watched(&pool, open.clone()).await);
    for s in served {
        s.stop().await.unwrap();
    }
    keyless.close("keying").await.unwrap();

    // Keyed and required: the remembered keyless provider is called in the
    // clear once, refused naming the key, and sealed to it.
    let keyring = Arc::new(Keyring::system(profile).unwrap());
    let keyed = provider(&station, identity, Some(keyring.clone())).await;
    let _served = serve_both(&keyed, &echo, &watch, true).await;
    let (answered, report) = pool.call_report(call.clone()).await.unwrap();
    assert_eq!(answered, Value::text("kept"));
    assert_eq!(report.sealed, 1);
    assert_eq!(report.seal_key_id, Some(keyring.current_id()));
    assert_eq!(counted(&keyed, "call_refused_sealed_required"), 1);
    assert!(watched(&pool, open.clone()).await);
    assert_eq!(counted(&keyed, "stream_refused_sealed_required"), 1);

    // The pool remembers the key: both go sealed the first time.
    let (_, report) = pool.call_report(call).await.unwrap();
    assert_eq!(report.sealed, 1);
    assert_eq!(counted(&keyed, "call_refused_sealed_required"), 1);
    assert!(watched(&pool, open).await);
    assert_eq!(counted(&keyed, "stream_refused_sealed_required"), 1);
    pool.close().await;
}

/// A clock that stands still until `armed`, then moves on by a key's
/// lifetime and its keeping at every read: a key the keyring names is
/// forgotten two reads later, so a reopen sealed to the key a refusal named
/// is refused sealed_refused.
fn forgetting_clock(armed: Arc<AtomicBool>) -> Clock {
    let now = AtomicI64::new(1_790_000_000_000);
    let step = KEY_LIFETIME_MS + RETIRED_KEY_KEPT_MS + 1;
    Arc::new(move || match armed.load(Ordering::SeqCst) {
        true => now.fetch_add(step, Ordering::SeqCst) + step,
        false => now.load(Ordering::SeqCst),
    })
}

/// Replies the bytes the caller sent, once it has ended its sending.
async fn count_bytes(stream: Stream) -> Result<(), String> {
    let mut total = 0i128;
    while let Ok(event) = stream.recv().await {
        match event {
            StreamEvent::Data {
                body: Value::Bytes(b),
                ..
            } => total += b.len() as i128,
            StreamEvent::End { .. } => break,
            _ => {}
        }
    }
    stream
        .reply(Value::Int(total))
        .await
        .map_err(|e| e.to_string())
}

/// Opens `open` on `pool`, sends five bytes and its end, and gives the
/// provider's answer.
async fn uploaded(pool: &Pool, open: StreamCall) -> Result<StreamEvent, LinkError> {
    let stream = pool.open_stream(open).await.unwrap();
    for chunk in ["ab", "cde"] {
        stream.send(chunk.as_bytes()).await?;
    }
    stream.close_send().await?;
    tokio::time::timeout(Duration::from_secs(10), stream.recv())
        .await
        .expect("an answer within ten seconds")
}

/// Serves `procedure` as a client stream counting what it is sent.
async fn serve_count(link: &Link, procedure: &str, required: bool) -> Served {
    let mut offer = Offer::stream(
        REALM,
        procedure,
        StreamMode::ClientStream,
        stream_handler(count_bytes),
    );
    if required {
        offer.confidential = Confidentiality::Required;
    }
    link.serve(offer).await.unwrap()
}

/// Fable's review of #42, finding 1: a sealed_refused that reached the
/// reopened session before its replay carried the stream onto a third
/// session without the copy, every write after it answered Ok. The copy
/// arrives, or the stream ends with an error; never a stream short of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_reopen_refused_sealed_refused_never_loses_the_copy() {
    let profile = Profile::PqHybrid;
    let lab = Lab::start(profile);
    let station = lab.station("reopen refused");
    let identity = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let count = record::own_procedure(&identity.node_id().unwrap(), "count");
    let open = StreamCall {
        realm: REALM,
        procedure: count.clone(),
        mode: StreamMode::ClientStream,
        ..StreamCall::default()
    };

    // The pool remembers the provider keyless, so it opens in the clear.
    let keyless = provider(&station, identity.clone(), None).await;
    let served = serve_count(&keyless, &count, false).await;
    let pool = caller(profile, &station).await;
    let answer = uploaded(&pool, open.clone()).await.unwrap();
    assert_eq!(
        answer,
        StreamEvent::Reply {
            payload: Value::Int(5)
        }
    );
    served.stop().await.unwrap();
    keyless.close("keying").await.unwrap();

    let armed = Arc::new(AtomicBool::new(false));
    let keyring = Arc::new(Keyring::new(profile, forgetting_clock(armed.clone())).unwrap());
    let keyed = provider(&station, identity, Some(keyring)).await;
    let _served = serve_count(&keyed, &count, true).await;
    armed.store(true, Ordering::SeqCst);
    match uploaded(&pool, open).await {
        Ok(StreamEvent::Reply { payload }) => assert_eq!(payload, Value::Int(5)),
        Ok(other) => panic!("{other:?}"),
        Err(_) => {}
    }
    assert_eq!(counted(&keyed, "stream_refused_sealed_required"), 1);
    assert!(counted(&keyed, "stream_refused_sealed_refused") >= 1);
    pool.close().await;
}
