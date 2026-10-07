//! The caller's seal report (macula's DESIGN_E2E_SEAL_REPORT §8), against
//! macula-go's in-process stations (tests/common/lab.rs): a call to a keyed
//! provider reports 1 and the key it was sealed to, one to a keyless
//! provider 0 and no key, and an error no report. A stream reports
//! not_settled until the provider's first data or reply opened under its key
//! (on a clear stream, its first data, reply or end), keeps the report once
//! settled, and stays not_settled when it ends first or with an error; a
//! served stream is not_a_caller.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{Call, Offer, Opts, Pool, PoolError, Report, ReportError, StreamCall};
use macula_rust::profile::Profile;
use macula_rust::record::{self, read_procedure_advertisement, RecordType};
use macula_rust::seal;
use macula_rust::station_link::{handler, stream_handler, LinkError, Stream, StreamEvent};
use tokio::sync::Notify;

const REALM: [u8; 32] = [0x5e; 32];

async fn connect(profile: Profile, s: &LabStation, kem_advertise: bool) -> Pool {
    let key = Arc::new(NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap());
    let mut opts = Opts::new(key);
    opts.kem_advertise = kem_advertise;
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(vec![s.seed()], opts).await.unwrap()
}

/// Echoes its payload, and refuses "fail" with a handler error.
fn echo(procedure: &str) -> Offer {
    Offer::unary(
        REALM,
        procedure,
        handler(|r| async move {
            if r.payload == Value::text("fail") {
                return Err("refused by the handler".to_string());
            }
            Ok(r.payload)
        }),
    )
}

fn server_stream(procedure: &str, h: macula_rust::station_link::StreamHandler) -> Offer {
    Offer::stream(REALM, procedure, StreamMode::ServerStream, h)
}

/// The id of the KEM key `provider`'s advertisement of `procedure` names,
/// read from the DHT as a caller reads it.
async fn advertised_key_id(caller: &Pool, procedure: &str) -> [u8; 8] {
    let (found, _) = caller
        .find_records(&record::procedure_key(&REALM, procedure))
        .await
        .unwrap();
    let key = found
        .iter()
        .filter(|v| v.record().record_type == RecordType::PROCEDURE_ADVERTISEMENT)
        .find_map(|v| read_procedure_advertisement(v.record()).unwrap().kem_key)
        .expect("the advertisement names a key")
        .0;
    seal::key_id(&key)
}

fn call(procedure: &str, payload: Value) -> Call {
    Call {
        realm: REALM,
        procedure: procedure.to_string(),
        payload,
        ..Call::default()
    }
}

async fn open(caller: &Pool, procedure: &str) -> Stream {
    caller
        .open_stream(StreamCall {
            realm: REALM,
            procedure: procedure.to_string(),
            ..StreamCall::default()
        })
        .await
        .unwrap()
}

async fn next(s: &Stream) -> Result<StreamEvent, LinkError> {
    tokio::time::timeout(Duration::from_secs(5), s.recv())
        .await
        .expect("the stream answered in time")
}

/// Reads `s` until it has ended, and returns why.
async fn drained(s: &Stream) -> LinkError {
    loop {
        if let Err(e) = next(s).await {
            return e;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_reports_the_key_it_was_sealed_to_and_a_clear_call_none() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        call_reports_under(profile).await;
    }
}

/// One profile's pass of the call report test: a sealed call, a clear call,
/// a failed call and a bare call, against a keyed and a keyless provider.
async fn call_reports_under(profile: Profile) {
    let lab = Lab::start(profile);
    let (serving, callers) = (lab.station("report serving"), lab.station("report callers"));
    lab.share(&[&serving, &callers]);
    let keyed = connect(profile, &serving, true).await;
    let keyless = connect(profile, &serving, false).await;
    let sealed_echo = record::own_procedure(&keyed.node_id(), "echo");
    let clear_echo = record::own_procedure(&keyless.node_id(), "echo");
    keyed.serve(echo(&sealed_echo)).await.unwrap();
    keyless.serve(echo(&clear_echo)).await.unwrap();
    let caller = connect(profile, &callers, false).await;

    let (result, report) = caller
        .call_report(call(&sealed_echo, Value::text("kept")))
        .await
        .unwrap();
    assert_eq!(result, Value::text("kept"));
    let key_id = advertised_key_id(&caller, &sealed_echo).await;
    assert_eq!(
        report,
        Report {
            sealed: 1,
            provider: keyed.node_id(),
            seal_key_id: Some(key_id),
        },
        "{profile:?}"
    );

    clear_failed_and_bare_calls(profile, &caller, &keyless, &sealed_echo, &clear_echo).await;
    for p in [caller, keyed, keyless] {
        p.close().await;
    }
}

/// The rest of one profile's pass: a clear call reports no key, a failed
/// call no report, and a bare call answers the bare result.
async fn clear_failed_and_bare_calls(
    profile: Profile,
    caller: &Pool,
    keyless: &Pool,
    sealed_echo: &str,
    clear_echo: &str,
) {
    let (result, report) = caller
        .call_report(call(clear_echo, Value::text("plain")))
        .await
        .unwrap();
    assert_eq!(result, Value::text("plain"));
    assert_eq!(
        report,
        Report {
            sealed: 0,
            provider: keyless.node_id(),
            seal_key_id: None,
        },
        "{profile:?}"
    );

    let failed = caller
        .call_report(call(sealed_echo, Value::text("fail")))
        .await;
    assert!(
        matches!(failed, Err(PoolError::Link(LinkError::Provider { .. }))),
        "an error carries no report: {failed:?}"
    );
    assert_eq!(
        caller
            .call(call(sealed_echo, Value::text("again")))
            .await
            .unwrap(),
        Value::text("again"),
        "call still answers the bare result"
    );
}

/// `p`'s own procedure `name`.
fn own(p: &Pool, name: &str) -> String {
    record::own_procedure(&p.node_id(), name)
}

/// Sends one chunk once told to, then closes.
async fn drip(told: Arc<Notify>, s: Stream) -> Result<(), String> {
    told.notified().await;
    s.send(b"a").await.map_err(|e| e.to_string())?;
    s.close().await.map_err(|e| e.to_string())
}

/// Ends the stream before any data or reply.
async fn quiet(s: Stream) -> Result<(), String> {
    s.close().await.map_err(|e| e.to_string())
}

/// Aborts before any data or reply.
async fn refuse(s: Stream) -> Result<(), String> {
    s.abort("nope", "").await.map_err(|e| e.to_string())
}

/// Tells the caller what its own side's report is.
async fn served(s: Stream) -> Result<(), String> {
    let said = match s.report() {
        Ok(_) => "a report".to_string(),
        Err(e) => e.name().to_string(),
    };
    s.send(said.as_bytes()).await.map_err(|e| e.to_string())?;
    s.close().await.map_err(|e| e.to_string())
}

/// Serves the stream report test's procedures, in order: drip (released by
/// `go`) on `keyed`, quiet on both, refuse and served on `keyed`.
async fn serve_report_streams(keyed: &Pool, keyless: &Pool, go: &Arc<Notify>) {
    let told = go.clone();
    keyed
        .serve(server_stream(
            &own(keyed, "drip"),
            stream_handler(move |s| drip(told.clone(), s)),
        ))
        .await
        .unwrap();
    for p in [keyed, keyless] {
        p.serve(server_stream(&own(p, "quiet"), stream_handler(quiet)))
            .await
            .unwrap();
    }
    keyed
        .serve(server_stream(&own(keyed, "refuse"), stream_handler(refuse)))
        .await
        .unwrap();
    keyed
        .serve(server_stream(&own(keyed, "served"), stream_handler(served)))
        .await
        .unwrap();
}

/// A sealed stream is not settled before any data, settles on its opened
/// data and keeps the report after its end.
async fn drip_settles_on_opened_data(
    caller: &Pool,
    keyed: &Pool,
    go: &Notify,
    sealed_report: Report,
) {
    let s = open(caller, &own(keyed, "drip")).await;
    assert!(s.sealed());
    assert_eq!(s.report(), Err(ReportError::NotSettled), "before any data");
    go.notify_one();
    assert!(matches!(next(&s).await, Ok(StreamEvent::Data { .. })));
    assert_eq!(s.report(), Ok(sealed_report), "settled on opened data");
    assert_eq!(drained(&s).await, LinkError::EndOfStream);
    assert_eq!(s.report(), Ok(sealed_report), "kept after the end");
}

/// A sealed stream's clear end settles nothing; a clear stream's end does.
async fn quiet_streams_settle_only_when_clear(caller: &Pool, keyed: &Pool, keyless: &Pool) {
    let s = open(caller, &own(keyed, "quiet")).await;
    assert!(s.sealed());
    assert_eq!(drained(&s).await, LinkError::EndOfStream);
    assert_eq!(
        s.report(),
        Err(ReportError::NotSettled),
        "a sealed stream's clear end settles nothing"
    );

    let s = open(caller, &own(keyless, "quiet")).await;
    assert!(!s.sealed());
    assert_eq!(drained(&s).await, LinkError::EndOfStream);
    assert_eq!(
        s.report(),
        Ok(Report {
            sealed: 0,
            provider: keyless.node_id(),
            seal_key_id: None,
        }),
        "a clear stream settles on its end"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_reports_once_the_provider_s_first_answer_opened() {
    let profile = Profile::PqPure;
    let lab = Lab::start(profile);
    let (serving, callers) = (
        lab.station("stream report serving"),
        lab.station("stream report callers"),
    );
    lab.share(&[&serving, &callers]);
    let keyed = connect(profile, &serving, true).await;
    let keyless = connect(profile, &serving, false).await;
    let caller = connect(profile, &callers, false).await;

    let go = Arc::new(Notify::new());
    serve_report_streams(&keyed, &keyless, &go).await;
    let key_id = advertised_key_id(&caller, &own(&keyed, "drip")).await;
    let sealed_report = Report {
        sealed: 1,
        provider: keyed.node_id(),
        seal_key_id: Some(key_id),
    };

    drip_settles_on_opened_data(&caller, &keyed, &go, sealed_report).await;
    quiet_streams_settle_only_when_clear(&caller, &keyed, &keyless).await;

    let s = open(&caller, &own(&keyed, "refuse")).await;
    assert!(matches!(drained(&s).await, LinkError::Stream { code, .. } if code == "nope"));
    assert_eq!(
        s.report(),
        Err(ReportError::NotSettled),
        "an error settles nothing"
    );

    let s = open(&caller, &own(&keyed, "served")).await;
    assert_eq!(
        next(&s).await.unwrap(),
        StreamEvent::Data {
            encoding: macula_rust::frame::StreamEncoding::Raw,
            body: Value::Bytes(b"not_a_caller".to_vec()),
        }
    );
    for p in [caller, keyed, keyless] {
        p.close().await;
    }
}
