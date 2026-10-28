//! A clear stream a keyed provider refuses sealed_required naming its KEM
//! key in the refusal's signed tbs reopens once, sealed to that key, behind
//! the same handle, and replays what it already sent, its end included, in
//! order (release A0, DESIGN_E2E_SEALED_BY_DEFAULT section 3,
//! macula-rust#42), against macula-go's in-process stations (tests/common).
//! The provider names its key only because the test sets it to; release A
//! makes it the rule. A refusal that names no key ends the stream as the
//! provider's own.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::seal::Keyring;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    stream_handler, Confidentiality, Config, Link, LinkError, Offer, Seal, Served, Stream,
    StreamCall, StreamEvent, StreamHandler,
};

/// A link as a new node; with `keyring`, it advertises its key and, when
/// `names_key`, names it in a sealed_required refusal.
async fn node(env: &TestStations, keyring: Option<Arc<Keyring>>, names_key: bool) -> Link {
    draining(env, keyring, names_key, 16).await
}

/// A node as [`node`] that drains `drains` refused streams at a time.
async fn draining(
    env: &TestStations,
    keyring: Option<Arc<Keyring>>,
    names_key: bool,
    drains: usize,
) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.refusal_names_key = names_key;
    cfg.refusal_drains = drains;
    cfg.keyring = keyring;
    Link::dial(cfg).await.unwrap()
}

/// Serves `procedure` as a required stream of `mode` run by `handler`.
async fn serve(
    env: &TestStations,
    provider: &Link,
    procedure: &str,
    mode: StreamMode,
    handler: StreamHandler,
) -> Served {
    let mut offer = Offer::stream(env.realm_id, procedure, mode, handler);
    offer.confidential = Confidentiality::Required;
    provider.serve(offer).await.unwrap()
}

fn clear_open(
    env: &TestStations,
    provider: &Link,
    procedure: &str,
    mode: StreamMode,
) -> StreamCall {
    StreamCall {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        mode,
        payload: Value::Bytes(b"one".to_vec()),
        seal: Some(Seal::Clear),
        ..StreamCall::default()
    }
}

fn raw(b: &[u8]) -> StreamEvent {
    StreamEvent::Data {
        encoding: StreamEncoding::Raw,
        body: Value::Bytes(b.to_vec()),
    }
}

/// Sends the open's payload and whether the stream came sealed.
async fn asked_and_sealed(stream: Stream) -> Result<(), String> {
    let Value::Bytes(asked) = stream.request().payload.clone() else {
        return Err("no payload".into());
    };
    let sealed = [u8::from(stream.sealed())];
    for chunk in [&asked[..], &sealed[..]] {
        stream.send(chunk).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Replies the bytes the caller sent and whether the stream came sealed,
/// once the caller has ended its sending.
async fn count_bytes(stream: Stream) -> Result<(), String> {
    let mut total = 0usize;
    while let Ok(event) = stream.recv().await {
        match event {
            StreamEvent::Data {
                body: Value::Bytes(b),
                ..
            } => total += b.len(),
            StreamEvent::End { .. } => break,
            _ => {}
        }
    }
    let answer = Value::Map(vec![
        (Value::text("total"), Value::Int(total as i128)),
        (
            Value::text("sealed"),
            Value::Int(i128::from(stream.sealed())),
        ),
    ]);
    stream.reply(answer).await.map_err(|e| e.to_string())
}

/// Sends `chunks` chunks of `size` bytes as fast as the link takes them,
/// ends its sending and gives the provider's reply.
async fn upload(stream: Stream, chunks: usize, size: usize) -> Result<Value, LinkError> {
    let chunk = vec![7u8; size];
    for _ in 0..chunks {
        stream.send(&chunk).await?;
    }
    stream.close_send().await?;
    match stream.recv().await? {
        StreamEvent::Reply { payload } => Ok(payload),
        other => Err(LinkError::Frame(macula_rust::frame::FrameError::Payload(
            format!("no reply: {other:?}"),
        ))),
    }
}

/// How many times the link counted `what`.
fn counted(link: &Link, what: &str) -> u64 {
    link.unrouted().get(what).copied().unwrap_or(0)
}

/// Waits for the caller's first chunk and sends it back.
async fn echo_first(stream: Stream) -> Result<(), String> {
    let first = stream.recv().await.map_err(|e| e.to_string())?;
    let StreamEvent::Data {
        body: Value::Bytes(b),
        ..
    } = first
    else {
        return Err("no chunk first".into());
    };
    stream.send(&b).await.map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_open_reseals_to_the_key_its_refusal_names() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let env = TestStations::start(profile);
        let keyring = Arc::new(Keyring::system(profile).unwrap());
        let provider = node(&env, Some(keyring.clone()), true).await;
        let caller = node(&env, None, false).await;
        let watch = record::own_procedure(&provider.node_id(), "watch");
        let handler = stream_handler(asked_and_sealed);
        let _served = serve(&env, &provider, &watch, StreamMode::ServerStream, handler).await;

        let open = clear_open(&env, &provider, &watch, StreamMode::ServerStream);
        let stream = caller.open_stream(open).await.unwrap();
        assert_eq!(stream.recv().await.unwrap(), raw(b"one"), "{profile:?}");
        assert_eq!(
            stream.recv().await.unwrap(),
            raw(&[1]),
            "{profile:?}: sealed"
        );
        assert!(stream.sealed());
        let report = stream.report().unwrap();
        assert_eq!(report.sealed, 1);
        assert_eq!(report.seal_key_id, Some(keyring.current_id()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_client_stream_that_wrote_and_closed_replays_it_all_sealed() {
    let env = TestStations::start(Profile::PqHybrid);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let count = record::own_procedure(&provider.node_id(), "count");
    let handler = stream_handler(count_bytes);
    let _served = serve(&env, &provider, &count, StreamMode::ClientStream, handler).await;

    let open = clear_open(&env, &provider, &count, StreamMode::ClientStream);
    let upload = caller.open_stream(open).await.unwrap();
    for chunk in ["ab", "cde", "f"] {
        upload.send(chunk.as_bytes()).await.unwrap();
    }
    upload.close_send().await.unwrap();
    let StreamEvent::Reply { payload } = upload.recv().await.unwrap() else {
        panic!("no reply");
    };
    assert_eq!(payload.get("total"), Some(&Value::Int(6)), "in order, once");
    assert_eq!(payload.get("sealed"), Some(&Value::Int(1)));
    assert!(upload.sealed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_bidi_stream_whose_provider_waits_for_its_first_chunk_completes() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let echo = record::own_procedure(&provider.node_id(), "echo");
    let _served = serve(
        &env,
        &provider,
        &echo,
        StreamMode::Bidi,
        stream_handler(echo_first),
    )
    .await;

    let open = clear_open(&env, &provider, &echo, StreamMode::Bidi);
    let stream = caller.open_stream(open).await.unwrap();
    stream.send(b"first").await.unwrap();
    assert_eq!(stream.recv().await.unwrap(), raw(b"first"));
    assert!(stream.sealed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_refusal_naming_no_key_stands_as_sealed_required() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), false).await;
    let caller = node(&env, None, false).await;
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let handler = stream_handler(asked_and_sealed);
    let _served = serve(&env, &provider, &watch, StreamMode::ServerStream, handler).await;

    let open = clear_open(&env, &provider, &watch, StreamMode::ServerStream);
    let stream = caller.open_stream(open).await.unwrap();
    match stream.recv().await {
        Err(LinkError::Stream { code, .. }) => assert_eq!(code, "sealed_required"),
        other => panic!("{other:?}"),
    }
    assert!(!stream.sealed());
}

/// A caller that wrote 4 MiB ahead before the refusal reached it still
/// reseals: the provider drains its writes, so the station does not reset the
/// stream and lose the refusal (macula-rust#42, Terra's finding from go#43).
#[tokio::test(flavor = "multi_thread")]
async fn a_clear_client_stream_that_wrote_hard_before_its_refusal_still_reseals() {
    let env = TestStations::start(Profile::PqHybrid);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let count = record::own_procedure(&provider.node_id(), "count");
    let handler = stream_handler(count_bytes);
    let _served = serve(&env, &provider, &count, StreamMode::ClientStream, handler).await;

    let open = clear_open(&env, &provider, &count, StreamMode::ClientStream);
    let stream = caller.open_stream(open).await.unwrap();
    let payload = upload(stream.clone(), 256, 16 * 1024).await.unwrap();
    assert_eq!(payload.get("total"), Some(&Value::Int(4 * 1024 * 1024)));
    assert_eq!(payload.get("sealed"), Some(&Value::Int(1)));
    assert!(stream.sealed());
    assert!(counted(&provider, "stream_refusal_drained") >= 1);
}

/// A flood of clear opens refused sealed_required past the link's drain
/// places: each is released at once and every flooder's stream ends rather
/// than waiting on a provider that reads no more, and a caller of another
/// procedure on the same provider is answered meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_refused_opens_past_the_drain_places_does_not_stall_other_callers() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = draining(&env, Some(keyring), true, 0).await;
    let count = record::own_procedure(&provider.node_id(), "count");
    let handler = stream_handler(count_bytes);
    let _served = serve(&env, &provider, &count, StreamMode::ClientStream, handler).await;
    let open = record::own_procedure(&provider.node_id(), "open");
    let handler = stream_handler(count_bytes);
    let offer = Offer::stream(env.realm_id, &open, StreamMode::ClientStream, handler);
    let _open_served = provider.serve(offer).await.unwrap();

    let mut flood = Vec::new();
    for _ in 0..4 {
        let flooder = node(&env, None, false).await;
        let call = clear_open(&env, &provider, &count, StreamMode::ClientStream);
        flood.extend((0..8).map(|_| tokio::spawn(flooded(flooder.clone(), call.clone()))));
    }
    let other = node(&env, None, false).await;
    let call = clear_open(&env, &provider, &open, StreamMode::ClientStream);
    let answered = tokio::time::timeout(Duration::from_secs(5), async {
        upload(other.open_stream(call).await?, 4, 1024).await
    })
    .await
    .expect("answered during the flood")
    .unwrap();
    assert_eq!(answered.get("total"), Some(&Value::Int(4 * 1024)));
    // A guard against a stall, not a speed bound: on two busy cores the
    // flood's sealed replays take tens of seconds.
    tokio::time::timeout(Duration::from_secs(60), ended(flood))
        .await
        .expect("every flooded stream ends");
    // Every refusal past the drain places is released at once, none drained.
    // Not every open need reach the provider: under load the station may
    // drop an open whose first frame waits behind the flood's uploads.
    let refused = counted(&provider, "stream_refused_sealed_required");
    assert!(refused > 0);
    assert_eq!(counted(&provider, "stream_refusal_drained"), 0);
    assert_eq!(counted(&provider, "stream_refusal_drains_full"), refused);
}

/// Waits for every task in `tasks` to end.
async fn ended(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for t in tasks {
        t.await.unwrap();
    }
}

/// Opens `call` and uploads 256 KiB as fast as the link takes it, whatever
/// becomes of the stream.
async fn flooded(caller: Link, call: StreamCall) {
    if let Ok(stream) = caller.open_stream(call).await {
        let _ = upload(stream, 16, 16 * 1024).await;
    }
}

/// Writes 4 MiB before reading anything, then counts what the caller sent
/// until it ends its sending, and replies the count.
async fn write_then_count(stream: Stream) -> Result<(), String> {
    let chunk = vec![9u8; 16 * 1024];
    for _ in 0..256 {
        stream.send(&chunk).await.map_err(|e| e.to_string())?;
    }
    count_bytes(stream).await
}

/// Both sides write 4 MiB before either reads: each side's reader keeps
/// taking frames while its owner's writes wait on flow control, clear and
/// sealed (Terra, from go#43's reader-takes-the-send-lock deadlock).
#[tokio::test(flavor = "multi_thread")]
async fn a_bidi_stream_whose_sides_both_write_4_mib_before_reading_completes() {
    let env = TestStations::start(Profile::PqHybrid);
    for sealed in [false, true] {
        let keyring = Arc::new(Keyring::system(env.profile).unwrap());
        let key = keyring.current().public_key().carried().to_vec();
        let provider = node(&env, sealed.then_some(keyring), false).await;
        let caller = node(&env, None, false).await;
        let both = record::own_procedure(&provider.node_id(), "both");
        let handler = stream_handler(write_then_count);
        let offer = Offer::stream(env.realm_id, &both, StreamMode::Bidi, handler);
        let _served = provider.serve(offer).await.unwrap();
        let mut open = clear_open(&env, &provider, &both, StreamMode::Bidi);
        open.seal = Some(match sealed {
            true => Seal::To(key),
            false => Seal::Clear,
        });

        let stream = caller.open_stream(open).await.unwrap();
        // A guard against a deadlock, not a speed bound: 4 MiB each way of
        // signed frames in a debug build takes ~11 s on two idle cores.
        let read = tokio::time::timeout(Duration::from_secs(120), write_then_read(&stream))
            .await
            .expect("both sides' 4 MiB went through");
        assert_eq!(read.0, 4 * 1024 * 1024, "sealed {sealed}");
        assert_eq!(read.1.get("total"), Some(&Value::Int(4 * 1024 * 1024)));
        assert_eq!(read.1.get("sealed"), Some(&Value::Int(i128::from(sealed))));
    }
}

/// Writes 4 MiB and ends its sending, then reads what the provider sent.
async fn write_then_read(stream: &Stream) -> (usize, Value) {
    let chunk = vec![7u8; 16 * 1024];
    for _ in 0..256 {
        stream.send(&chunk).await.unwrap();
    }
    stream.close_send().await.unwrap();
    received(stream).await
}

/// The bytes the provider sent and its reply.
async fn received(stream: &Stream) -> (usize, Value) {
    let mut total = 0;
    loop {
        match stream.recv().await.unwrap() {
            StreamEvent::Data {
                body: Value::Bytes(b),
                ..
            } => total += b.len(),
            StreamEvent::Reply { payload } => return (total, payload),
            other => panic!("{other:?}"),
        }
    }
}

/// A clear client stream closed both ways right after it sent, before its
/// refusal came, still reaches the provider sealed: the session reads on
/// and the reopen replays the sends and the close. Before, the stream was
/// ended at once and what it sent was lost, though close() returned Ok.
#[tokio::test(flavor = "multi_thread")]
async fn a_clear_stream_closed_before_its_refusal_came_reaches_the_provider_sealed() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), true).await;
    let caller = node(&env, None, false).await;
    let drop_box = record::own_procedure(&provider.node_id(), "drop_box");
    let (got, mut got_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = stream_handler(move |stream: Stream| received_into(stream, got.clone()));
    let _served = serve(
        &env,
        &provider,
        &drop_box,
        StreamMode::ClientStream,
        handler,
    )
    .await;

    for _ in 0..5 {
        let open = clear_open(&env, &provider, &drop_box, StreamMode::ClientStream);
        let upload = caller.open_stream(open).await.unwrap();
        upload.send(b"abcde").await.unwrap();
        upload.close().await.unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(10), got_rx.recv())
            .await
            .expect("the provider got the stream");
        assert_eq!(delivered, Some((5, true)));
    }
}

/// A clear client stream to a provider that takes clear opens and sends
/// nothing first: what it sent before close() reaches the provider, and
/// close() returns once the provider has ended its side, not at the
/// deadline. Before, the close ended the stream at once and the station's
/// reset lost the end.
#[tokio::test(flavor = "multi_thread")]
async fn a_clear_stream_that_sent_then_closed_is_delivered_and_close_returns_promptly() {
    let env = TestStations::start(Profile::PqPure);
    let provider = node(&env, None, false).await;
    let caller = node(&env, None, false).await;
    let drop_box = record::own_procedure(&provider.node_id(), "drop_box");
    let (got, mut got_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = stream_handler(move |stream: Stream| received_into(stream, got.clone()));
    let offer = Offer::stream(env.realm_id, &drop_box, StreamMode::ClientStream, handler);
    let _served = provider.serve(offer).await.unwrap();

    for _ in 0..5 {
        let open = clear_open(&env, &provider, &drop_box, StreamMode::ClientStream);
        let upload = caller.open_stream(open).await.unwrap();
        upload.send(b"abcde").await.unwrap();
        let closing = std::time::Instant::now();
        upload.close().await.unwrap();
        assert!(
            closing.elapsed() < Duration::from_secs(3),
            "{:?}",
            closing.elapsed()
        );
        let delivered = tokio::time::timeout(Duration::from_secs(10), got_rx.recv())
            .await
            .expect("the provider got the stream");
        assert_eq!(delivered, Some((5, false)));
    }
}

/// Counts the bytes the caller sent until its sending ends and hands the
/// count and whether the stream came sealed to `got`.
async fn received_into(
    stream: Stream,
    got: tokio::sync::mpsc::UnboundedSender<(usize, bool)>,
) -> Result<(), String> {
    let mut total = 0usize;
    while let Ok(StreamEvent::Data {
        body: Value::Bytes(b),
        ..
    }) = stream.recv().await
    {
        total += b.len();
    }
    let _ = got.send((total, stream.sealed()));
    Ok(())
}
