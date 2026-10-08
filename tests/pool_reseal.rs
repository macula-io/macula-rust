//! A pool call reseals once after its provider's KEM key rotated
//! (macula-rust#20, as macula's `resealed/7`), against macula-go's
//! in-process stations (tests/common/lab.rs). The caller seals to the key
//! it remembered; the provider, rotated past keeping it, refuses
//! sealed_refused naming its current key; one fresh lookup finds an
//! advertisement naming exactly that key and the call is sealed to it again.
//! A refusal naming a key no advertisement names fails key_mismatch, naming
//! both. Never the clear.
//!
//! A pool stream reseals the same way, once, behind the handle its caller
//! holds (macula-rust#21, as macula's `stream_resealed/6`): refused before
//! it has sent anything, it reopens sealed to the key the provider names and
//! delivers the provider's frames; a refusal naming a key no advertisement
//! names ends it key_mismatch, naming both.

mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Call, Opts, Pool, PoolError, Report, StreamCall};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::seal::{Clock, Keyring, KEY_LIFETIME_MS, RETIRED_KEY_KEPT_MS};
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Confidentiality, ConfidentialityError, ConfidentialityReason, Config,
    Link, LinkError, Offer, Served, Stream, StreamEvent,
};
use macula_rust::transport::Target;

const REALM: [u8; 32] = [0x5e; 32];

/// A clock the test moves: unix milliseconds.
fn test_clock() -> (Arc<AtomicI64>, Clock) {
    let now = Arc::new(AtomicI64::new(1_790_000_000_000));
    let read = now.clone();
    (now, Arc::new(move || read.load(Ordering::SeqCst)))
}

/// A provider linked to `s` with kem_advertise on and `keyring`.
async fn provider(profile: Profile, s: &LabStation, keyring: Arc<Keyring>) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let target = Target {
        host: s.host.clone(),
        port: s.port,
        profile,
        expected_node_id: s.node_id,
    };
    let mut cfg = Config::new(target, identity, issuer);
    cfg.kem_advertise = true;
    cfg.keyring = Some(keyring);
    Link::dial(cfg).await.unwrap()
}

async fn caller(profile: Profile, s: &LabStation) -> Pool {
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(vec![s.seed()], opts).await.unwrap()
}

/// Serves an echo of `procedure` on `link`, keyed, advertising the
/// keyring's current key.
async fn serve_echo(link: &Link, procedure: &str) -> Served {
    let mut offer = Offer::unary(REALM, procedure, handler(|r| async move { Ok(r.payload) }));
    offer.confidential = Confidentiality::Preferred;
    link.serve(offer).await.unwrap()
}

fn echo(procedure: &str) -> Call {
    Call {
        realm: REALM,
        procedure: procedure.to_string(),
        payload: Value::text("kept"),
        ..Call::default()
    }
}

/// Rotates `keyring` and then moves `now` past the time a replaced key is
/// kept, so the keyring no longer opens the key it named before. A keyring
/// rotates when it is read after its key's lifetime, and keeps the replaced
/// key from then on. The new current key's id.
fn rotate_past_keeping(now: &AtomicI64, keyring: &Keyring) -> [u8; 8] {
    now.fetch_add(KEY_LIFETIME_MS + 1, Ordering::SeqCst);
    let current = keyring.current_id();
    now.fetch_add(RETIRED_KEY_KEPT_MS + 1, Ordering::SeqCst);
    assert_eq!(keyring.current_id(), current, "rotated once");
    current
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_reseals_to_the_key_the_rotated_provider_names() {
    let profile = Profile::PqHybrid;
    let lab = Lab::start(profile);
    let station = lab.station("reseal");
    let (now, clock) = test_clock();
    let keyring = Arc::new(Keyring::new(profile, clock).unwrap());
    let link = provider(profile, &station, keyring.clone()).await;
    let pool = caller(profile, &station).await;
    let procedure = record::own_procedure(&link.node_id(), "echo");
    let served = serve_echo(&link, &procedure).await;

    // Sealed to the first key, which the caller now remembers.
    let first = keyring.current_id();
    let (_, report) = pool.call_report(echo(&procedure)).await.unwrap();
    assert_eq!(report.seal_key_id, Some(first));

    // The provider rotates past keeping the first key and advertises the
    // second; the caller still remembers the first.
    let second = rotate_past_keeping(&now, &keyring);
    served.stop().await.unwrap();
    let served = serve_echo(&link, &procedure).await;
    let (result, report) = pool.call_report(echo(&procedure)).await.unwrap();
    assert_eq!(result, Value::text("kept"));
    assert_eq!(
        report,
        Report {
            sealed: 1,
            provider: link.node_id(),
            seal_key_id: Some(second),
        }
    );

    // Rotated again with no advertisement naming the third key: the refusal
    // names it, the lookup finds only older keys, and the call fails naming
    // both.
    let third = rotate_past_keeping(&now, &keyring);
    match pool.call_report(echo(&procedure)).await {
        Err(PoolError::Confidentiality(ConfidentialityError {
            reason: ConfidentialityReason::KeyMismatch,
            advertised,
            named,
        })) => {
            assert_eq!(named, Some(third));
            assert!(advertised.contains(&second), "{advertised:?}");
        }
        other => panic!("{other:?}"),
    }
    served.stop().await.unwrap();
    pool.close().await;
}

/// Serves a server stream of `procedure` on `link`, keyed: one chunk, then
/// the provider's reply.
async fn serve_watch(link: &Link, procedure: &str) -> Served {
    let mut offer = Offer::stream(
        REALM,
        procedure,
        StreamMode::ServerStream,
        stream_handler(|s: Stream| async move {
            s.send(b"watched").await.map_err(|e| e.to_string())?;
            s.reply(Value::text("done"))
                .await
                .map_err(|e| e.to_string())
        }),
    );
    offer.confidential = Confidentiality::Preferred;
    link.serve(offer).await.unwrap()
}

fn watch(procedure: &str) -> StreamCall {
    StreamCall {
        realm: REALM,
        procedure: procedure.to_string(),
        mode: StreamMode::ServerStream,
        ..StreamCall::default()
    }
}

/// The stream's first event, or why it ended, within five seconds.
async fn first(s: &Stream) -> Result<StreamEvent, LinkError> {
    tokio::time::timeout(Duration::from_secs(5), s.recv())
        .await
        .expect("an event within five seconds")
}

fn watched() -> StreamEvent {
    StreamEvent::Data {
        encoding: macula_rust::frame::StreamEncoding::Raw,
        body: Value::Bytes(b"watched".to_vec()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_reseals_to_the_key_the_rotated_provider_names() {
    let profile = Profile::PqHybrid;
    let lab = Lab::start(profile);
    let station = lab.station("stream reseal");
    let (now, clock) = test_clock();
    let keyring = Arc::new(Keyring::new(profile, clock).unwrap());
    let link = provider(profile, &station, keyring.clone()).await;
    let pool = caller(profile, &station).await;
    let procedure = record::own_procedure(&link.node_id(), "watch");
    let served = serve_watch(&link, &procedure).await;

    // Sealed to the first key, which the caller now remembers.
    let first_key = keyring.current_id();
    let stream = pool.open_stream(watch(&procedure)).await.unwrap();
    assert_eq!(first(&stream).await.unwrap(), watched());
    assert_eq!(stream.report().unwrap().seal_key_id, Some(first_key));

    // The provider rotates past keeping the first key: the stream opened to
    // it is refused, reopens sealed to the second, and delivers the
    // provider's frames behind the same handle.
    let second = rotate_past_keeping(&now, &keyring);
    served.stop().await.unwrap();
    let served = serve_watch(&link, &procedure).await;
    let stream = pool.open_stream(watch(&procedure)).await.unwrap();
    assert_eq!(first(&stream).await.unwrap(), watched());
    assert_eq!(
        stream.report().unwrap(),
        Report {
            sealed: 1,
            provider: link.node_id(),
            seal_key_id: Some(second),
        }
    );
    assert_eq!(
        first(&stream).await.unwrap(),
        StreamEvent::Reply {
            payload: Value::text("done")
        }
    );

    // Rotated again with no advertisement naming the third key: the stream
    // ends naming both, never reopened in the clear.
    let third = rotate_past_keeping(&now, &keyring);
    let stream = pool.open_stream(watch(&procedure)).await.unwrap();
    match first(&stream).await {
        Err(LinkError::Confidentiality(ConfidentialityError {
            reason: ConfidentialityReason::KeyMismatch,
            advertised,
            named,
        })) => {
            assert_eq!(named, Some(third));
            assert!(advertised.contains(&second), "{advertised:?}");
        }
        other => panic!("{other:?}"),
    }
    served.stop().await.unwrap();
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_has_sent_is_not_resealed() {
    let profile = Profile::PqHybrid;
    let lab = Lab::start(profile);
    let station = lab.station("stream sent");
    let (now, clock) = test_clock();
    let keyring = Arc::new(Keyring::new(profile, clock).unwrap());
    let link = provider(profile, &station, keyring.clone()).await;
    let pool = caller(profile, &station).await;
    let procedure = record::own_procedure(&link.node_id(), "watch");
    let served = serve_watch(&link, &procedure).await;
    let stream = pool.open_stream(watch(&procedure)).await.unwrap();
    assert_eq!(first(&stream).await.unwrap(), watched());

    // Refused after this side ended its sending: nothing is opened again,
    // so nothing it sent is lost or sent twice; the refusal ends the stream.
    rotate_past_keeping(&now, &keyring);
    served.stop().await.unwrap();
    let served = serve_watch(&link, &procedure).await;
    let stream = pool.open_stream(watch(&procedure)).await.unwrap();
    stream.close_send().await.unwrap();
    match first(&stream).await {
        Err(LinkError::Stream { code, .. }) => assert_eq!(code, "sealed_refused"),
        other => panic!("{other:?}"),
    }
    served.stop().await.unwrap();
    pool.close().await;
}
