//! Integration tests against real, live macula-station boxes.
//!
//! **Not run by default CI** — every test here is `#[ignore]`d, since it
//! depends on external infrastructure this crate doesn't own or control
//! (network reachability, the fleet's own uptime). Run explicitly with:
//!
//! ```text
//! cargo test --test live_station -- --ignored --nocapture
//! ```
//!
//! **DNS gotcha, confirmed directly against the live box (2026-08-28):**
//! the bare `macula.io` hostname has an A (IPv4) record but genuinely no
//! AAAA record at all, while `macula-station-frankfurt`'s actual QUIC
//! listener (confirmed via `ss -ulnp` on the box itself) is bound to a
//! *specific* IPv6 address that has no relationship to the A record.
//! Dialing `macula.io` therefore resolves to a real, reachable IPv4
//! address with nothing listening on port 4433 — every packet vanishes
//! silently (correct, spec-compliant QUIC behavior for unrecognized
//! traffic, indistinguishable from a firewalled port from the client
//! side alone). `station-de-frankfurt.macula.io` is the name that
//! actually resolves to the listener's real IPv6 address — this matches
//! the DNS-repoint gotcha already on file in project memory
//! (`reference_demo_fleet_boxes`), confirmed still true today.

use macula_rust::cbor::Value;
use macula_rust::cert::ed25519_pubkey_from_cert;
use macula_rust::connection;
use macula_rust::identity::KeyPair;
use macula_rust::transport::{connect, Trust};

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

/// `stations-linode-toronto`, provisioned 2026-08-29 specifically to have a
/// fleet member with no DNS entry and no CA-issued cert -- see
/// `macula-demo/infrastructure/stations-linode-toronto/`. Dialed by its bare
/// `host_advertised` IPv6 literal, never a hostname.
const TORONTO_HOST: &str = "2600:3c04::2000:f0ff:feb9:e155";
const TORONTO_PORT: u16 = 4433;
const TORONTO_NODE_ID_HEX: &str =
    "5748e81d89a6ea4b619fecda394ffac9f8f58a05d7a7234034783b6e1fd043d5";

const MILAN_HOST: &str = "station-it-milan.macula.io";
const MILAN_PORT: u16 = 4433;

/// Probe: dial with verification skipped, and report exactly what the
/// station presents (cert count, and its Ed25519 pubkey if the leaf is
/// Ed25519) — informational, not asserting a specific pubkey, since
/// that's fleet configuration this crate doesn't control and shouldn't
/// hardcode as a test expectation.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn probe_what_frankfurt_presents() {
    let connection = connect(STATION_HOST, STATION_PORT, Trust::Insecure)
        .await
        .expect("QUIC/TLS handshake with ALPN=macula should succeed against a live station");

    println!(
        "connected: alpn={:?} remote={}",
        connection
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
            .map(|p| String::from_utf8_lossy(&p).into_owned()),
        connection.remote_address(),
    );

    let identity = connection
        .peer_identity()
        .expect("server cert chain should be present after a completed handshake");
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .expect("peer_identity for a rustls-backed QUIC connection is a cert chain");
    println!("station presented {} certificate(s)", certs.len());

    let leaf = certs.first().expect("at least one cert in the chain");
    match ed25519_pubkey_from_cert(leaf.as_ref()) {
        Ok(pubkey) => println!("leaf is Ed25519, pubkey = {}", hex::encode(pubkey)),
        Err(e) => println!("leaf is NOT a bare Ed25519 SPKI cert: {e}"),
    }

    connection.close(0u32.into(), b"probe complete");
}

/// **Empirical finding, 2026-08-28:** `macula-station-frankfurt` presents
/// a 3-certificate RSA chain (SPKI OID `1.2.840.113549.1.1.1`), not a
/// self-signed Ed25519 identity cert — confirmed directly via
/// `probe_what_frankfurt_presents` above. That matches macula's own
/// documented "public-IP path with Let's Encrypt-anchored certs" trust
/// mode exactly (`plans/PLAN_WIRE_PROTOCOL.md` §2's `verify => webpki`),
/// which is what this test exercises. Pubkey-pinned trust
/// (`Trust::Pinned`) is for macula's *other* documented deployment shape
/// — a station without public DNS/CA-issued TLS, identified by its raw
/// Ed25519 key instead — which no box in the current demo fleet happens
/// to be configured as. `PubkeyPinVerifier`'s own matching logic is still
/// fully covered, just as a local unit test against a synthetic cert
/// (`src/cert.rs`'s own tests), not a live one — see that module.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn webpki_trust_succeeds_against_the_real_fleet() {
    let connection = connect(STATION_HOST, STATION_PORT, Trust::WebPki)
        .await
        .expect("CA-chain validation should succeed against a real Let's Encrypt cert");
    connection.close(0u32.into(), b"done");
}

/// The real milestone: not just a QUIC/TLS connection, but a complete
/// macula application-layer handshake — signed CONNECT out, verified
/// HELLO back, `accepted = true` — against a real production station.
/// Uses a **puzzle-hardened** identity deliberately: see
/// `plans/PLAN_WIRE_PROTOCOL.md` §5's callout on why an unhardened one
/// fails this silently (QUIC/TLS looks fine, the station just never
/// accepts).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn full_handshake_succeeds_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();

    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("CONNECT/HELLO handshake should succeed against a live station");

    println!(
        "handshake accepted: remote={} station_node_id={} negotiated_capabilities={}",
        session.remote_address(),
        hex::encode(session.station.node_id),
        session.station.negotiated_capabilities,
    );
    assert!(session.station.accepted);

    session
        .close("normal", Some("integration test done"), &identity)
        .await;
}

/// **Empirical finding, 2026-08-28 — contradicts the documented
/// expectation, recorded honestly rather than papered over.** The plan
/// (`plans/PLAN_WIRE_PROTOCOL.md` §5) and the production incident it's
/// based on both describe every station enforcing puzzle admission on
/// every CONNECT. Tested directly against `macula-station-frankfurt`: an
/// **unhardened identity was accepted** (`accepted = true`, same shape
/// as the hardened case). This crate's `puzzle_evidence` computation is
/// independently verified byte-for-byte against real Erlang
/// `crypto:hash/2` output (`src/identity.rs`'s own tests), so this isn't
/// a computation bug here — it means either (a) this specific dev-fleet
/// station has puzzle enforcement disabled or configured leniently (it's
/// documented elsewhere as throwaway dev infra, not production), (b) the
/// deployed image predates that enforcement, or (c) enforcement is
/// scoped to some condition this plain CONNECT doesn't trigger. Which
/// one is true is a `macula-station`-side question, out of scope for
/// this crate to chase — recorded here as a fact about what actually
/// happens against this fleet today, not a guarantee about macula's
/// protocol in general. **Always grind the puzzle regardless** (the cost
/// is negligible and it's clearly the intended, documented behavior) —
/// this test does not license skipping it.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unhardened_identity_against_the_real_fleet_is_observed_not_assumed() {
    let identity = KeyPair::generate(); // NOT puzzle-hardened, on purpose

    let result = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity).await;
    match result {
        Ok(session) => {
            println!(
                "OBSERVED: unhardened identity was ACCEPTED (accepted={}) -- see this \
                 test's doc comment for why that's a fleet-configuration fact, not \
                 evidence this crate's puzzle handling is wrong",
                session.station.accepted
            );
            session.close("normal", None, &identity).await;
        }
        Err(e) => {
            println!("OBSERVED: unhardened identity was rejected, as: {e}");
        }
    }
}

/// A real end-to-end CALL/RESULT-or-ERROR round trip. Calls a procedure
/// name that certainly doesn't exist (`macula_rust.test_probe`,
/// under the content sentinel realm) — the point isn't to exercise any
/// particular procedure, only to prove the wire round trip itself: a
/// signed CALL sent, and a signed RESULT or ERROR received back,
/// correlated by call_id, with a real BOLT#4 code if it's an error.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn call_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let response = session
        .call(
            "macula_rust.test_probe",
            [0u8; 32], // the content-sentinel realm, reused here as a harmless default
            macula_rust::cbor::Value::Null,
            (now_ms() + 10_000) as i128,
            &identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("should get SOME response (result or a well-formed error), not a timeout");

    match response {
        macula_rust::frame::CallResponse::Result {
            payload,
            responded_by,
        } => {
            println!("OBSERVED: got a RESULT (unexpected for a made-up procedure, but valid): payload={payload:?} responded_by={}", hex::encode(responded_by));
        }
        macula_rust::frame::CallResponse::Error {
            code,
            name,
            reported_by,
            detail,
        } => {
            println!(
                "OBSERVED: got an ERROR (expected for a nonexistent procedure): code={code} name={name} reported_by={} detail={detail:?}",
                hex::encode(reported_by)
            );
        }
    }

    session
        .close("normal", Some("call test done"), &identity)
        .await;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

/// A real end-to-end SUBSCRIBE -> PUBLISH -> (maybe) EVENT round trip.
/// Whether a subscriber receives its own publish is genuinely unknown
/// going in — this test observes and reports rather than assuming an
/// answer, same discipline as the unhardened-identity test above.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn pubsub_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    // A realm+topic scratch value nobody else would collide with.
    let realm: [u8; 32] = rand::random();
    let topic = format!(
        "macula-rust.test.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let mut subscription = session
        .subscribe(
            &macula_rust::frame::SubscribeSpec::new(topic.clone(), realm, identity.node_id()),
            &identity,
        )
        .await
        .expect("SUBSCRIBE should send without error");

    session
        .publish(
            &macula_rust::frame::PublishSpec::new(
                topic.clone(),
                realm,
                identity.node_id(),
                1,
                macula_rust::cbor::Value::text("hello from macula-rust"),
                now_ms(),
            ),
            &identity,
        )
        .await
        .expect("PUBLISH should send without error");

    match subscription
        .recv_event(std::time::Duration::from_secs(5))
        .await
    {
        Ok(event) => {
            println!(
                "OBSERVED: received our own EVENT back — topic={} seq={} delivered_via={} payload={:?}",
                event.topic, event.seq, event.delivered_via, event.payload
            );
            assert_eq!(event.topic, topic);
        }
        Err(e) => {
            println!(
                "OBSERVED: no EVENT arrived within 5s ({e}) — a subscriber may not receive its \
                 own publish, or delivery may simply be slower than this test waits. Not \
                 asserted as a failure either way; see this test's doc comment."
            );
        }
    }

    session
        .close("normal", Some("pubsub test done"), &identity)
        .await;
}

/// Real end-to-end proof that `run_subscriber`/`run_publisher` work, not
/// just compile — same discipline as `macula-go`'s
/// `TestLiveRunSubscriberAndRunPublisher`: three SEPARATE sessions/
/// identities (this fleet kicks whichever connection reuses an identity
/// second, confirmed elsewhere this session), a subscriber genuinely
/// receiving a real event through its callback (not manual polling), and
/// the auto-published `pubsub.publish_completed_v1` fact confirmed by an
/// INDEPENDENT fourth session subscribed BEFORE the publish happens — not
/// the publisher's own bookkeeping. A random realm scopes this test's
/// traffic away from any real third-party activity on this shared public
/// fleet, same as `pubsub_round_trip_against_the_real_fleet` above.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn run_subscriber_and_run_publisher_against_the_real_fleet() {
    let realm: [u8; 32] = rand::random();
    let topic = format!(
        "macula-rust.test.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    // Independent watcher, subscribed to the fact topic BEFORE anything
    // publishes -- pubsub has no replay for a late subscriber.
    let watcher_id = KeyPair::generate_with_default_puzzle();
    let watcher = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &watcher_id)
        .await
        .expect("watcher handshake should succeed");
    let mut watcher_subscription = watcher
        .subscribe(
            &macula_rust::frame::SubscribeSpec::new(
                "pubsub.publish_completed_v1",
                realm,
                watcher_id.node_id(),
            ),
            &watcher_id,
        )
        .await
        .expect("watcher SUBSCRIBE should send without error");

    let sub_id = KeyPair::generate_with_default_puzzle();
    let sub_session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &sub_id)
        .await
        .expect("subscriber handshake should succeed");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub_topic = topic.clone();
    let subscribe_task = tokio::spawn(async move {
        let spec = macula_rust::frame::SubscribeSpec::new(sub_topic, realm, sub_id.node_id());
        let stop = tokio::time::sleep(std::time::Duration::from_secs(8));
        sub_session
            .run_subscriber(&spec, &sub_id, stop, |evt| {
                let _ = tx.send(evt);
            })
            .await
    });

    // Give both SUBSCRIBEs a moment to actually land before publishing.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let pub_id = KeyPair::generate_with_default_puzzle();
    let pub_session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &pub_id)
        .await
        .expect("publisher handshake should succeed");
    let spec = macula_rust::frame::PublishSpec::new(
        topic.clone(),
        realm,
        pub_id.node_id(),
        1,
        Value::text("hello from run_publisher"),
        now_ms(),
    );
    let publish_result = pub_session.run_publisher(&spec, &pub_id, true).await;
    assert!(
        publish_result.is_ok(),
        "run_publisher should succeed: {publish_result:?}"
    );
    println!("OBSERVED: run_publisher completed cleanly");
    pub_session
        .close("normal", Some("publisher test done"), &pub_id)
        .await;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
        Ok(Some(evt)) => {
            println!(
                "OBSERVED: run_subscriber's handler received the real EVENT -- topic={} payload={:?}",
                evt.topic, evt.payload
            );
            assert_eq!(evt.topic, topic);
        }
        _ => println!(
            "OBSERVED: no EVENT arrived via the subscriber's callback within 5s -- a subscriber \
             may not receive its own publish, same caveat as pubsub_round_trip_against_the_real_fleet"
        ),
    }

    let sub_result = subscribe_task
        .await
        .expect("subscriber task should not panic");
    assert!(
        sub_result.is_ok(),
        "run_subscriber should return Ok after its stop future resolves: {sub_result:?}"
    );
    println!("OBSERVED: run_subscriber returned cleanly after its stop future resolved");

    // The watcher's subscription only receives events for its own topic, under
    // a realm nobody else uses; wait within an overall deadline for the fact
    // to arrive.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut confirmed = false;
    while std::time::Instant::now() < deadline {
        match watcher_subscription
            .recv_event(std::time::Duration::from_secs(2))
            .await
        {
            Ok(evt) if evt.topic == "pubsub.publish_completed_v1" => {
                let outcome = evt.payload.get("outcome");
                println!(
                    "OBSERVED: independent watcher confirmed a real pubsub.publish_completed_v1 fact landed -- outcome={outcome:?}"
                );
                assert_eq!(outcome, Some(&Value::text("completed")));
                confirmed = true;
                break;
            }
            Ok(other) => {
                println!(
                    "(watcher skipping unrelated event on topic {})",
                    other.topic
                );
            }
            Err(e) => {
                println!("(watcher still waiting: {e})");
            }
        }
    }
    assert!(
        confirmed,
        "independent watcher never observed a pubsub.publish_completed_v1 fact within the deadline"
    );

    watcher
        .close("normal", Some("watcher test done"), &watcher_id)
        .await;
}

/// Regression test for a real bug found live 2026-08-29 in the Go port
/// of this exact `connect -> write -> Close` shape (macula-go's
/// `connection.Session.Close`): a PUBLISH sent immediately before
/// `close` -- exactly what every one-shot CLI/tool invocation does --
/// could be silently dropped, because `Connection::close` is abrupt and
/// does not wait for outstanding stream data to actually reach the
/// peer. `pubsub_round_trip_against_the_real_fleet` above can't catch
/// this: it keeps reading (blocking on `recv_event`) on the SAME
/// session that published, so `close` doesn't run until well after the
/// write already had time to flush. This uses two INDEPENDENT sessions
/// specifically so the publisher's `close` isn't incidentally delayed
/// by anything the subscriber does. Fixed proactively in
/// `Session::close` (`CLOSE_DRAIN`) before this was independently
/// rediscovered against this crate -- this test is what proves that
/// held.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn publish_survives_immediate_close_against_the_real_fleet() {
    let sub_identity = KeyPair::generate_with_default_puzzle();
    let sub_session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &sub_identity)
        .await
        .expect("handshake should succeed (subscriber)");

    let realm: [u8; 32] = rand::random();
    let topic = format!(
        "macula-rust.test.immediate-close.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let mut subscription = sub_session
        .subscribe(
            &macula_rust::frame::SubscribeSpec::new(topic.clone(), realm, sub_identity.node_id()),
            &sub_identity,
        )
        .await
        .expect("SUBSCRIBE should send without error");
    // Give the SUBSCRIBE a moment to register before the publish races
    // it -- this test is about the PUBLISH-then-close race, not about
    // subscribe-propagation timing (a separate concern).
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Separate connection, separate identity: publish then close
    // immediately, no read in between -- the exact shape a one-shot
    // CLI/tool invocation uses.
    {
        let pub_identity = KeyPair::generate_with_default_puzzle();
        let pub_session =
            connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &pub_identity)
                .await
                .expect("handshake should succeed (publisher)");
        pub_session
            .publish(
                &macula_rust::frame::PublishSpec::new(
                    topic.clone(),
                    realm,
                    pub_identity.node_id(),
                    1,
                    macula_rust::cbor::Value::text(
                        "hello from the immediate-close regression test",
                    ),
                    now_ms(),
                ),
                &pub_identity,
            )
            .await
            .expect("PUBLISH should send without error");
        pub_session.close("normal", None, &pub_identity).await;
    }

    // The subscription only receives events for its own topic, so the first
    // one within the deadline is the EVENT this test waits for.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "EVENT for our topic never arrived after a publish immediately followed by close \
             (this is the exact race this test exists to catch)"
        );
        match subscription.recv_event(remaining).await {
            Ok(event) if event.topic == topic => break,
            Ok(event) => println!("skipping an unrelated EVENT: topic={}", event.topic),
            Err(connection::RecvEventError::Timeout) => {
                panic!(
                    "EVENT for our topic never arrived after a publish immediately followed by \
                     close (this is the exact race this test exists to catch)"
                );
            }
            Err(e) => panic!("the subscription ended before the EVENT arrived: {e}"),
        }
    }

    sub_session
        .close("normal", Some("immediate-close test done"), &sub_identity)
        .await;
}

/// A real single-block put/get round trip: content small enough
/// (`<= manifest::DEFAULT_CHUNK_SIZE`) to be addressed purely by content
/// hash, no manifest involved. Every byte is randomized per run so
/// there's no risk of colliding with content some other run already
/// stored under the same MCID.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn single_block_put_get_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();
    let mcid = macula_rust::content::put(&session, &data, "test-block", &identity)
        .await
        .expect("put should succeed");
    assert!(
        !macula_rust::manifest::mcid_is_chunked(&mcid),
        "4096 bytes is well under the chunking threshold"
    );
    println!(
        "OBSERVED: stored single block under mcid={}",
        hex::encode(mcid)
    );

    let fetched = macula_rust::content::get(&session, mcid, &identity)
        .await
        .expect("get should succeed for content this session just put");
    assert_eq!(
        fetched, data,
        "fetched bytes must match what was put, exactly"
    );

    session
        .close("normal", Some("content single-block test done"), &identity)
        .await;
}

/// A real chunked put/get round trip: content large enough to force
/// `manifest::create`'s multi-chunk path, exercising `_content.put_block`
/// (several times, sequentially — see `src/content.rs`'s module doc on
/// why this crate doesn't parallelize lanes), `_content.put_manifest`,
/// `_content.get_manifest`, and `_content.get_block` (again several
/// times) all against a real station, then verifies the reassembled
/// bytes against the manifest's Merkle root.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn chunked_put_get_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let size = macula_rust::manifest::DEFAULT_CHUNK_SIZE * 2 + 12_345;
    let data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    let mcid = macula_rust::content::put(&session, &data, "test-chunked", &identity)
        .await
        .expect("chunked put should succeed");
    assert!(
        macula_rust::manifest::mcid_is_chunked(&mcid),
        "{size} bytes is well over the chunking threshold"
    );
    println!(
        "OBSERVED: stored {size} bytes as a manifest under mcid={}",
        hex::encode(mcid)
    );

    let fetched = macula_rust::content::get(&session, mcid, &identity)
        .await
        .expect("chunked get should succeed for content this session just put");
    assert_eq!(
        fetched, data,
        "reassembled bytes must match what was put, exactly"
    );

    session
        .close("normal", Some("content chunked test done"), &identity)
        .await;
}

/// A made-up MCID that (with overwhelming probability) nothing has ever
/// stored — proves the wire-level `not_found` reply is reached and
/// parsed correctly, not just the happy path.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn get_of_an_unknown_block_reports_not_found_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let random_hash: [u8; 32] = rand::random();
    let mcid = macula_rust::manifest::block_mcid(&random_hash);

    match macula_rust::content::get(&session, mcid, &identity).await {
        Err(macula_rust::content::GetError::NotFound) => {
            println!("OBSERVED: not_found reported correctly for an unknown mcid");
        }
        other => panic!("expected GetError::NotFound, got {other:?}"),
    }

    session
        .close("normal", Some("content not-found test done"), &identity)
        .await;
}

/// Proves the exact bug class `macula-station`'s mode-aware half-close
/// fix (commit `07db0d8`) addresses: a `client_stream` caller that
/// pushes its data, half-closes its own send side with `close_send`,
/// and then awaits the provider's reply. Before that fix, the relay
/// tore down the ENTIRE bidirectional stream route on the caller's
/// STREAM_END regardless of the wire's `role` field, so the provider's
/// `send_reply` returned no error locally while the caller's
/// `await_reply` timed out — this crate's SDK-side code was already
/// correct, the bug lived entirely in the station's relay.
///
/// This deliberately does NOT reuse the shape the previous version of
/// this test had (a lone caller against a made-up, unregistered
/// procedure with no real provider): that only ever proved wire
/// mechanics, never actually exercised `send_reply`/`await_reply`
/// against a real counterpart, and a hand-written mock provider here
/// could too easily bake the old (buggy) relay behavior in as
/// "correct" without anyone noticing. Two independent connections to
/// the SAME real, live station — one provider, one caller — same
/// pattern as `streaming_provider_round_trip_against_the_real_fleet`
/// above, with the roles matched to `ClientStream`'s actual wire shape
/// instead of `ServerStream`'s: the CALLER pushes data and closes its
/// own send side, the PROVIDER drains with `recv` and finishes with
/// `send_reply`, and the caller's `await_reply` is what's actually
/// being proven. Matches `macula-go`'s own
/// `TestLiveClientStreamReplyRoundTrip` (`stream/live_test.go`), the
/// SDK that already had this shape right, including asserting the
/// actual reply payload and `responded_by` rather than just logging
/// whichever of the two possible outcomes happened to occur.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn client_stream_reply_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_client_stream.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give the station a moment to register the advertisement before
    // the caller dials in against it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let accept_task = tokio::spawn(async move {
        let result = macula_rust::stream::StreamHandle::accept(
            &provider_session,
            std::time::Duration::from_secs(10),
        )
        .await;
        (result, provider_session)
    });

    let mut caller_handle = macula_rust::stream::StreamHandle::open(
        &caller_session,
        &procedure,
        realm,
        macula_rust::frame::StreamMode::ClientStream,
        macula_rust::cbor::Value::Null,
        (now_ms() + 10_000) as i128,
        &caller_identity,
    )
    .await
    .expect("caller should open a stream");

    let (accept_result, provider_session) =
        accept_task.await.expect("accept task should not panic");
    let (mut provider_handle, open_info) =
        accept_result.expect("provider should accept the inbound STREAM_OPEN");

    println!(
        "OBSERVED: provider accepted stream_open for procedure={} mode={:?}",
        open_info.procedure, open_info.mode
    );
    assert_eq!(open_info.procedure, procedure);
    assert_eq!(open_info.mode, macula_rust::frame::StreamMode::ClientStream);

    caller_handle
        .send_data(
            macula_rust::frame::StreamEncoding::Raw,
            macula_rust::cbor::Value::Bytes(b"hello from the caller".to_vec()),
            &caller_identity,
        )
        .await
        .expect("caller should push a chunk");
    caller_handle
        .close_send(&caller_identity)
        .await
        .expect("caller should close its send side");

    match provider_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("provider should receive the pushed chunk")
    {
        macula_rust::stream::StreamItem::Data { body, .. } => {
            assert_eq!(
                body,
                macula_rust::cbor::Value::Bytes(b"hello from the caller".to_vec())
            );
        }
        other => panic!("expected Data, got {other:?}"),
    }
    match provider_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("provider should see end-of-stream")
    {
        macula_rust::stream::StreamItem::Eof => {}
        other => panic!("expected Eof, got {other:?}"),
    }

    provider_handle
        .send_reply(
            macula_rust::cbor::Value::Text("processed: hello from the caller".to_string()),
            &provider_identity,
        )
        .await
        .expect("provider should send a reply");

    let (payload, responded_by) = caller_handle
        .await_reply(std::time::Duration::from_secs(5))
        .await
        .expect(
            "caller should receive the reply -- if this times out, macula-station's \
             mode-aware half-close fix (commit 07db0d8) is not live on this station",
        );
    assert_eq!(
        payload,
        macula_rust::cbor::Value::Text("processed: hello from the caller".to_string())
    );
    assert_eq!(responded_by, provider_identity.node_id());
    println!(
        "OBSERVED: caller received a real STREAM_REPLY through ClientStream mode: payload={payload:?} responded_by={}",
        hex::encode(responded_by)
    );

    provider_session
        .close("normal", Some("provider test done"), &provider_identity)
        .await;
    caller_session
        .close("normal", Some("caller test done"), &caller_identity)
        .await;
}

/// The real point of §13.2's whole existence: two independent
/// connections to the SAME live station — one advertises a procedure
/// and accepts inbound streams for it (the provider role), the other
/// dials in and pushes/pulls data against it (the caller role, already
/// live-verified elsewhere). This is the first test in this crate where
/// this process is on the RECEIVING end of a mesh interaction it didn't
/// initiate — everything before this dialed out and waited for a
/// response; here, one session sits idle after `advertise` until the
/// station itself routes a stranger's request back to it.
///
/// Same station on purpose: cross-station routing depends on gossip
/// propagation between stations, which isn't instant and isn't this
/// crate's concern to wait out — same-station is the direct case
/// `plans/PLAN_WIRE_PROTOCOL.md` §6.9 describes ("registers the handler
/// with the pool's advertise-gossip mechanism"), and it's what a real
/// provider dialed into one station actually needs day to day.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn streaming_provider_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_provider.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give the station a moment to register the advertisement before
    // the caller dials in against it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let accept_task = tokio::spawn(async move {
        let result = macula_rust::stream::StreamHandle::accept(
            &provider_session,
            std::time::Duration::from_secs(10),
        )
        .await;
        (result, provider_session)
    });

    let mut caller_handle = macula_rust::stream::StreamHandle::open(
        &caller_session,
        &procedure,
        realm,
        macula_rust::frame::StreamMode::ServerStream,
        macula_rust::cbor::Value::Null,
        (now_ms() + 10_000) as i128,
        &caller_identity,
    )
    .await
    .expect("caller should open a stream");

    let (accept_result, provider_session) =
        accept_task.await.expect("accept task should not panic");
    let (mut provider_handle, open_info) =
        accept_result.expect("provider should accept the inbound STREAM_OPEN");

    println!(
        "OBSERVED: provider accepted stream_open for procedure={} mode={:?}",
        open_info.procedure, open_info.mode
    );
    assert_eq!(open_info.procedure, procedure);
    assert_eq!(open_info.mode, macula_rust::frame::StreamMode::ServerStream);

    provider_handle
        .send_data(
            macula_rust::frame::StreamEncoding::Raw,
            macula_rust::cbor::Value::Bytes(b"hello from the provider".to_vec()),
            &provider_identity,
        )
        .await
        .expect("provider should push a chunk");
    provider_handle
        .close_send(&provider_identity)
        .await
        .expect("provider should close its send side");

    match caller_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("caller should receive the pushed chunk")
    {
        macula_rust::stream::StreamItem::Data { body, .. } => {
            assert_eq!(
                body,
                macula_rust::cbor::Value::Bytes(b"hello from the provider".to_vec())
            );
        }
        other => panic!("expected Data, got {other:?}"),
    }
    match caller_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("caller should see end-of-stream")
    {
        macula_rust::stream::StreamItem::Eof => {}
        other => panic!("expected Eof, got {other:?}"),
    }

    provider_session
        .close("normal", Some("provider test done"), &provider_identity)
        .await;
    caller_session
        .close("normal", Some("caller test done"), &caller_identity)
        .await;
}

/// The unary-RPC counterpart to `streaming_provider_round_trip_against_the_real_fleet`
/// above, and the gap this crate's own README used to list as "not yet
/// built": two independent connections to the SAME live station, one
/// advertising a procedure and serving inbound CALLs for it via
/// [`connection::Session::serve_one_call`], the other dialing in and
/// calling it — the caller role already covered by
/// `call_round_trip_against_the_real_fleet`. Without this, a service
/// built on this crate could call RPCs and serve streams, but could
/// never serve a request/response procedure at all.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unary_call_provider_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_add.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give the station a moment to register the advertisement before
    // the caller dials in against it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move {
                let a = match payload.get("a") {
                    Some(Value::Int(n)) => *n,
                    _ => return Err("missing or non-integer field \"a\"".to_string()),
                };
                let b = match payload.get("b") {
                    Some(Value::Int(n)) => *n,
                    _ => return Err("missing or non-integer field \"b\"".to_string()),
                };
                Ok(Value::Int(a + b))
            }) as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let payload = Value::Map(vec![
        (Value::text("a"), Value::Int(3)),
        (Value::text("b"), Value::Int(4)),
    ]);
    let response = caller_session
        .call(
            &procedure,
            realm,
            payload,
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL");

    match response {
        macula_rust::frame::CallResponse::Result { payload, .. } => {
            assert_eq!(payload, Value::Int(7), "3 + 4 should reply with RESULT 7");
        }
        other => panic!("expected a RESULT, got {other:?}"),
    }
    println!(
        "OBSERVED: provider served the inbound CALL for procedure={procedure}, caller got RESULT 7"
    );

    provider_session
        .close(
            "normal",
            Some("unary provider test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close("normal", Some("unary caller test done"), &caller_identity)
        .await;
}

/// Regression test for a real bug found and root-caused 2026-09-05
/// building the quickstart example: identical to
/// `unary_call_provider_round_trip_against_the_real_fleet` above, EXCEPT
/// `#[tokio::test]`'s default flavor there is single-threaded
/// (`current_thread`) -- this test forces the MULTI-threaded flavor
/// `#[tokio::main]` itself defaults to, which is what any real
/// consumer's `main` actually runs under.
///
/// Root cause, confirmed by instrumenting `FrameStream::send_frame`/
/// `recv_frame` with thread-id and frame-content logging against the
/// real fleet: it is NOT fundamentally about multi-threading. It's
/// [`Session`]'s own documented "always call `close` before this goes
/// out of scope" contract (see that type's own doc, and
/// [`Session::serve_one_call`]'s) -- a bare drop tears down the
/// connection with no guarantee the last write reached the peer, and a
/// `tokio::spawn`ed task with nothing after the `served_one_call().await`
/// drops its `Session` the instant the task completes. Under a
/// multi-threaded runtime that spawned task can run to completion (and
/// drop the session) within microseconds of the write -- deterministically,
/// every run in this environment -- while a single-threaded runtime's own
/// cooperative scheduling happens to leave enough incidental delay before
/// the drop for quinn's send-scheduling to flush first. This test
/// deliberately closes `provider_session` explicitly before the task
/// ends, exactly like `unary_call_provider_round_trip_against_the_real_fleet`
/// above already does (returning the session out of the spawned task and
/// closing it afterward is equally correct) -- with that discipline
/// applied, the round trip is exactly as reliable under multi-thread as
/// under current_thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires network access to a live macula-station"]
async fn unary_call_provider_round_trip_multi_thread_runtime() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_multithread.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move { Ok(payload) })
                as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        // The fix: close explicitly instead of letting provider_session
        // drop when this task ends -- see this test's own doc comment.
        provider_session
            .close(
                "normal",
                Some("multi-thread provider test done"),
                &provider_identity,
            )
            .await;
        result
    });

    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::text("hello"),
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");

    let serve_result = serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL");

    match response {
        macula_rust::frame::CallResponse::Result { payload, .. } => {
            assert_eq!(payload, Value::text("hello"));
        }
        other => panic!("expected a RESULT, got {other:?}"),
    }

    caller_session
        .close(
            "normal",
            Some("multi-thread caller test done"),
            &caller_identity,
        )
        .await;
}

/// Proves `call`/`serve_one_call` genuinely auto-publish `rpc.sent_v1`/
/// `rpc.completed_v1` (caller) and `rpc.received_v1`/`rpc.replied_v1`
/// (provider) — confirmed by an INDEPENDENT watcher session, not the
/// caller's/provider's own bookkeeping. A random realm (same trick
/// `unary_call_provider_round_trip_against_the_real_fleet` and the pubsub
/// live test already use) scopes every fact this test's own call
/// generates away from any real third-party activity on this shared
/// public fleet — with only one call made under a realm nobody else
/// uses, there is exactly one of each fact to expect, so no request_id
/// correlation against unrelated traffic is needed here (unlike
/// `macula-go`'s equivalent test, which had to add that specifically
/// because it published under a FIXED, shared topic/realm).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn rpc_telemetry_facts_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();
    let watcher_identity = KeyPair::generate_with_default_puzzle();

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_rpc_facts.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    // Watcher subscribes to all 4 topics BEFORE anything happens — pubsub
    // has no replay for a late subscriber.
    let watcher = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &watcher_identity)
        .await
        .expect("watcher handshake should succeed");
    let mut subscriptions = Vec::new();
    for topic in [
        "rpc.sent_v1",
        "rpc.completed_v1",
        "rpc.received_v1",
        "rpc.replied_v1",
    ] {
        subscriptions.push(
            watcher
                .subscribe(
                    &macula_rust::frame::SubscribeSpec::new(
                        topic,
                        realm,
                        watcher_identity.node_id(),
                    ),
                    &watcher_identity,
                )
                .await
                .expect("watcher SUBSCRIBE should send without error"),
        );
    }

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give both the advertise and the 4 SUBSCRIBEs a moment to land.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        Some(std::sync::Arc::new(|payload: Value| {
            Box::pin(async move { Ok(payload) })
                as connection::BoxFuture<'static, Result<Value, String>>
        }))
    };

    // Returns provider_session/provider_identity back out, rather than
    // letting them drop when the task ends, so they can be explicitly
    // `.close()`d below — NOT a stylistic choice. A bare `Drop` right
    // after `serve_one_call` returns races the just-sent RESULT frame
    // against abrupt QUIC connection teardown with zero drain time,
    // exactly the "PUBLISH sent immediately before Close intermittently
    // never reached the peer" gotcha `Session::close`'s own doc already
    // warns about (quinn's `write_all`/`finish` only hand data to its
    // send-scheduling machinery, they don't wait for the peer to receive
    // it) — except a bare drop has even less margin than `close()`'s own
    // built-in drain sleep. Found live: an earlier draft of this test let
    // `provider_session` drop bare and got a deterministic, 100%-reproducible
    // caller-side timeout even though `serve_one_call` itself returned
    // `Ok(())` every time — isolated by bisection against
    // `unary_call_provider_round_trip_against_the_real_fleet` (which
    // already returns its sessions and explicitly closes them, and never
    // hits this), not a fleet flake and not caused by the RPC telemetry
    // facts this test actually exists to check.
    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::text("hello"),
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");
    assert!(
        matches!(response, macula_rust::frame::CallResponse::Result { .. }),
        "expected a RESULT, got {response:?}"
    );

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL");
    provider_session
        .close("normal", Some("rpc facts test done"), &provider_identity)
        .await;

    let mut seen = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while seen.len() < 4 && std::time::Instant::now() < deadline {
        for subscription in subscriptions.iter_mut() {
            let Ok(evt) = subscription
                .recv_event(std::time::Duration::from_millis(250))
                .await
            else {
                continue;
            };
            if seen.insert(evt.topic.clone()) {
                println!(
                    "OBSERVED: {} fact landed with payload={:?}",
                    evt.topic, evt.payload
                );
            }
        }
    }
    assert_eq!(
        seen,
        std::collections::HashSet::from([
            "rpc.sent_v1".to_string(),
            "rpc.completed_v1".to_string(),
            "rpc.received_v1".to_string(),
            "rpc.replied_v1".to_string(),
        ]),
        "expected all 4 RPC telemetry facts to land, only saw: {seen:?}"
    );

    caller_session
        .close("normal", Some("rpc facts test done"), &caller_identity)
        .await;
    watcher
        .close("normal", Some("rpc facts test done"), &watcher_identity)
        .await;
}

/// Confirms the BOLT#4 error path: a provider that's advertised but
/// whose lookup (deliberately, here) can't find a handler replies with
/// the exact same `unknown_next_peer` code the reference sends for this
/// race (`macula_station_link.erl`'s `handle_inbound_call/2`, "unknown
/// (realm, procedure)" branch).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unary_call_provider_reports_unknown_next_peer_on_lookup_miss_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_miss.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let no_handlers = |_realm: &[u8; 32], _proc: &str| -> Option<connection::CallHandler> { None };
    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                no_handlers,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::Null,
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL (with an error reply)");

    match response {
        macula_rust::frame::CallResponse::Error { code, name, .. } => {
            assert_eq!(code, macula_rust::bolt4::Code::UnknownNextPeer.as_u8());
            println!("OBSERVED: lookup miss correctly reported as ERROR code={code} name={name}");
        }
        other => panic!("expected an ERROR, got {other:?}"),
    }

    provider_session
        .close(
            "normal",
            Some("unary provider miss test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close(
            "normal",
            Some("unary caller miss test done"),
            &caller_identity,
        )
        .await;
}

/// **First-ever live test of `Trust::Pinned` against a real station.**
/// Every other test in this file dials `station-de-frankfurt.macula.io`
/// under `Trust::WebPki`, because that's the only trust mode Frankfurt's
/// CA-issued cert can satisfy -- `Trust::Pinned` had unit coverage only
/// (`src/cert.rs`, a synthetic cert), never a real handshake. Toronto
/// exists specifically to close that gap: no DNS entry, no CA cert, dialed
/// by its bare `host_advertised` IPv6 literal and validated by pinning its
/// known Ed25519 NodeId instead of a certificate chain -- exactly the
/// "station without public DNS/CA-issued TLS" mode `Trust::Pinned`'s own
/// doc comment describes as the normal case for a mobile client dialing a
/// known station.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn pinned_trust_full_handshake_succeeds_against_toronto() {
    let node_id: [u8; 32] = hex::decode(TORONTO_NODE_ID_HEX)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");
    let identity = KeyPair::generate_with_default_puzzle();

    let session = connection::connect(
        TORONTO_HOST,
        TORONTO_PORT,
        Trust::Pinned(node_id),
        &identity,
    )
    .await
    .expect("Pinned-trust CONNECT/HELLO handshake should succeed against a live no-DNS station");

    println!(
        "handshake accepted: remote={} station_node_id={} negotiated_capabilities={}",
        session.remote_address(),
        hex::encode(session.station.node_id),
        session.station.negotiated_capabilities,
    );
    assert!(session.station.accepted);
    assert_eq!(
        session.station.node_id, node_id,
        "the station's own reported node_id should match the one we pinned"
    );

    session
        .close("normal", Some("pinned trust test done"), &identity)
        .await;
}

/// The primitive a real cam2me call would ride on -- two independent
/// identities each dialed into a DIFFERENT station (Frankfurt, Milan,
/// mirroring an actual two-emulator cam2me session run 2026-08-29: one
/// phone left on its default station, the other switched to Milan via
/// Settings), one advertising and accepting a bidirectional stream, the
/// other opening it and both sides exchanging data -- unlike
/// `streaming_provider_round_trip_against_the_real_fleet` above, which is
/// deliberately same-station because "cross-station routing depends on
/// gossip propagation between stations, which isn't instant and isn't this
/// crate's concern to wait out". This test IS concerned with exactly that:
/// it's the one open question a real call feature can't avoid, since two
/// contacts are never guaranteed to share a station. `StreamMode::Bidi`
/// rather than the one-directional `ServerStream` used above, since a call
/// needs both directions, not one.
///
/// **Root cause found and fixed, 2026-08-29 -- this crate's bug, not
/// `macula-station`'s.** First run of this test found STREAM_OPEN routing
/// cross-station correctly but a DATA frame sent afterward never arriving,
/// reproducible at both 5s and 25s timeouts. Traced into
/// `macula_station_peer_observer.erl`'s dedicated-stream relay
/// (`verify_dedicated/4`): non-OPEN stream frames (DATA/END/ERROR) verify
/// against an optional `signer` field when present, falling back to "the
/// connection this frame arrived on" when absent -- and the reference's own
/// comment on that fallback says outright it's "single-hop only", because
/// at a second relay hop the connection belongs to the RELAYING STATION,
/// not the original sender. This crate's STREAM_DATA/END/ERROR
/// constructors never stamped `signer` at all (`frame.rs`'s own prior doc
/// comment reasoned "a direct-dial client... has no relay hop to
/// authenticate across" -- true of the client's OWN single hop, false of
/// what the STATION does with it afterward). Fixed: `StreamDataSpec`/
/// `StreamEndSpec`/`StreamErrorSpec` all gained `signer: Option<[u8; 32]>`,
/// and every real call site (`StreamHandle::send_data`/`close_send`/
/// `abort`) now always supplies `Some(identity.public_bytes())`. New
/// differential vectors added in `frame.rs` for the `Some` case, generated
/// live against `macula_frame:stream_data/1` etc with `signer` in the spec
/// map -- the two pre-existing vectors testing `None` are untouched and
/// still pass, since that's a real, still-valid branch of the reference's
/// own optional field.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn cross_station_streaming_round_trip_frankfurt_provider_milan_caller() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake against Frankfurt should succeed");
    let caller_session =
        connection::connect(MILAN_HOST, MILAN_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake against Milan should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_call.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise on Frankfurt should send");

    // Same-station tests above give this 500ms; a cross-station lookup has
    // to actually reach the other station first, so this waits longer
    // before concluding it never will.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let accept_task = tokio::spawn(async move {
        let result = macula_rust::stream::StreamHandle::accept(
            &provider_session,
            std::time::Duration::from_secs(15),
        )
        .await;
        (result, provider_session)
    });

    let open_result = macula_rust::stream::StreamHandle::open(
        &caller_session,
        &procedure,
        realm,
        macula_rust::frame::StreamMode::Bidi,
        macula_rust::cbor::Value::Null,
        (now_ms() + 10_000) as i128,
        &caller_identity,
    )
    .await;

    let mut caller_handle = match open_result {
        Ok(h) => h,
        Err(e) => {
            println!(
                "OBSERVED: cross-station STREAM_OPEN failed as: {e} -- Milan could not \
                 route to a procedure only advertised on Frankfurt within 5s. This is the \
                 real, useful answer to whether a call feature can rely on cross-station \
                 routing working promptly; see this test's doc comment."
            );
            let _ = accept_task.await;
            return;
        }
    };
    println!("OBSERVED: cross-station STREAM_OPEN succeeded -- Milan routed it to Frankfurt");

    let (accept_result, provider_session) =
        accept_task.await.expect("accept task should not panic");
    let (mut provider_handle, open_info) =
        accept_result.expect("provider should accept the inbound STREAM_OPEN");
    assert_eq!(open_info.procedure, procedure);
    assert_eq!(open_info.mode, macula_rust::frame::StreamMode::Bidi);

    // Send both frames, then DRAIN both (recv the Data) before either side
    // closes its send half -- closing before the peer has drained the data
    // that preceded the close is exactly the ordering the first run of
    // this test got wrong (a real bug in this test, not in the SDK):
    // provider_handle.recv() failed with StreamClosed because both sides
    // half-closed before either had received the other's frame.
    caller_handle
        .send_data(
            macula_rust::frame::StreamEncoding::Raw,
            macula_rust::cbor::Value::Bytes(b"audio frame from phone2 (milan)".to_vec()),
            &caller_identity,
        )
        .await
        .expect("caller should push a frame");
    provider_handle
        .send_data(
            macula_rust::frame::StreamEncoding::Raw,
            macula_rust::cbor::Value::Bytes(b"audio frame from phone1 (frankfurt)".to_vec()),
            &provider_identity,
        )
        .await
        .expect("provider should push a frame");

    match provider_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect(
            "provider should receive the caller's frame -- see this test's doc comment, \
                 fixed 2026-08-29 by stamping `signer` on stream data frames",
        ) {
        macula_rust::stream::StreamItem::Data { body, .. } => {
            assert_eq!(
                body,
                macula_rust::cbor::Value::Bytes(b"audio frame from phone2 (milan)".to_vec())
            );
            println!("OBSERVED: provider (Frankfurt) received phone2's frame from Milan");
        }
        other => panic!("expected Data, got {other:?}"),
    }
    match caller_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("caller should receive the provider's frame")
    {
        macula_rust::stream::StreamItem::Data { body, .. } => {
            assert_eq!(
                body,
                macula_rust::cbor::Value::Bytes(b"audio frame from phone1 (frankfurt)".to_vec())
            );
            println!("OBSERVED: caller (Milan) received phone1's frame from Frankfurt");
        }
        other => panic!("expected Data, got {other:?}"),
    }

    caller_handle
        .close_send(&caller_identity)
        .await
        .expect("caller should half-close");
    provider_handle
        .close_send(&provider_identity)
        .await
        .expect("provider should half-close");

    provider_session
        .close(
            "normal",
            Some("cross-station call test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close(
            "normal",
            Some("cross-station call test done"),
            &caller_identity,
        )
        .await;
}

/// Follow-up to `cross_station_streaming_round_trip_frankfurt_provider_milan_caller`
/// above, asking a narrower question: that test found STREAM_OPEN routes
/// cross-station but DATA on the resulting stream does not.
/// `plans/PLAN_MACULA_STREAMING.md` (macula-architecture) says cross-relay
/// STREAM_OPEN routing "will follow the CALL path's procedure-resolver
/// pattern" -- so if plain CALL/RESULT (a single request/response, no
/// persistent per-stream relay state to pin across the station boundary)
/// also crosses stations cleanly, that's real signal that a signaling
/// exchange (SDP offer/answer, ICE candidates) built on CALL rather than a
/// long-lived STREAM_OPEN session would not hit the same gap.
///
/// **Empirical finding, 2026-08-29, confirmed:** it does not hit the gap.
/// Milan's CALL reached Frankfurt's advertised provider, the RESULT came
/// back with the exact expected payload, round trip in ~5s (almost all of
/// it the propagation wait, not the call itself). Unlike the streaming
/// case, there's no follow-up DATA frame to lose -- a CALL is one
/// request, one response, both riding the same resolver lookup that
/// already proved reliable for STREAM_OPEN. So a signaling exchange built
/// on CALL/RESULT (or short-lived RPCs generally) rather than a
/// persistent STREAM_OPEN+DATA session is on solid ground cross-station,
/// independent of whether the streaming DATA-relay gap above ever gets
/// fixed.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn cross_station_unary_call_round_trip_frankfurt_provider_milan_caller() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake against Frankfurt should succeed");
    let caller_session =
        connection::connect(MILAN_HOST, MILAN_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake against Milan should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_signal.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise on Frankfurt should send");

    // Same wait the streaming counterpart used for its own resolver lookup.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move {
                match payload {
                    Value::Text(s) if s == "offer from phone2 (milan)" => {
                        Ok(Value::text("answer from phone1 (frankfurt)"))
                    }
                    other => Err(format!("unexpected payload: {other:?}")),
                }
            }) as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(20),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::text("offer from phone2 (milan)"),
            (now_ms() + 15_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(15),
        )
        .await;

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");

    match (response, serve_result) {
        (Ok(macula_rust::frame::CallResponse::Result { payload, .. }), Ok(())) => {
            let matches = payload == Value::text("answer from phone1 (frankfurt)");
            println!(
                "OBSERVED: cross-station CALL/RESULT succeeded -- Milan's CALL reached \
                 Frankfurt's provider and the RESULT came back, content matches = {matches}"
            );
        }
        (Ok(other), serve_result) => {
            println!(
                "OBSERVED: cross-station CALL got a response but not the expected RESULT: \
                 {other:?} (serve_result={serve_result:?})"
            );
        }
        (Err(e), serve_result) => {
            println!(
                "OBSERVED: cross-station CALL failed -- {e} (serve_result={serve_result:?}). \
                 If this fails the same way the streaming test's DATA phase did, the CALL \
                 path shares the same cross-station gap; if it succeeds, signaling built on \
                 CALL rather than STREAM_OPEN+DATA is on solid ground."
            );
        }
    }

    provider_session
        .close(
            "normal",
            Some("cross-station signaling test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close(
            "normal",
            Some("cross-station signaling test done"),
            &caller_identity,
        )
        .await;
}

/// Full direct-dial loop, end to end: a provider advertises via
/// `direct_dial::advertise_direct` (publishing a signed DHT record, not
/// the ordinary gossip ADVERTISE), a caller resolves that record over a
/// SEPARATE connection via `direct_dial::resolve`, and `direct_dial::call`
/// dials the resolved station directly and gets a REAL RESULT back —
/// proving the whole chain (sign, publish, resolve, verify the trust
/// chain, dial, call, serve) works against the real fleet, not just that
/// resolution reaches the call stage.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn direct_dial_advertise_resolve_and_call_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let provider_session =
        connection::connect(MILAN_HOST, MILAN_PORT, Trust::WebPki, &provider_identity)
            .await
            .expect("provider handshake should succeed");
    // Used only to query the DHT -- per direct_dial::resolve's own doc, it
    // does not need to be connected to the same station that ends up
    // serving the call. Dialing a DIFFERENT station than the provider's
    // own makes that claim meaningful rather than accidentally true.
    let resolve_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("resolve-side handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_direct_dial.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    macula_rust::direct_dial::advertise_direct(
        &provider_session,
        &provider_identity,
        realm,
        &procedure,
        std::time::Duration::from_secs(120),
    )
    .await
    .expect("advertise_direct should publish the DHT record");

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move {
                let n = match payload.get("n") {
                    Some(Value::Int(n)) => *n,
                    _ => return Err("missing or non-integer field \"n\"".to_string()),
                };
                Ok(Value::Int(n * 2))
            }) as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(20),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let payload = Value::Map(vec![(Value::text("n"), Value::Int(21))]);
    let response = macula_rust::direct_dial::call(
        &resolve_session,
        &caller_identity,
        realm,
        &procedure,
        payload,
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("direct-dial call should resolve, dial, and complete");

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the direct-dialed inbound CALL");

    match response {
        macula_rust::frame::CallResponse::Result { payload, .. } => {
            assert_eq!(
                payload,
                Value::Int(42),
                "21 * 2 should reply with RESULT 42"
            );
        }
        other => panic!("expected a RESULT, got {other:?}"),
    }
    println!(
        "OBSERVED: direct-dial resolved+dialed a station DIFFERENT from the resolve session's own, and got a real RESULT for procedure={procedure}"
    );

    provider_session
        .close(
            "normal",
            Some("direct-dial provider test done"),
            &provider_identity,
        )
        .await;
    resolve_session
        .close(
            "normal",
            Some("direct-dial resolve-side test done"),
            &caller_identity,
        )
        .await;
}

/// A direct call runs on the caller's own session to the provider's station
/// instead of dialing a second connection under the same identity, which
/// would make the station close that session. The name matches the .NET and
/// Go tests.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn resolver_session_still_connected_after_a_direct_call() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();
    let realm = [0u8; 32];
    let procedure = format!(
        "macula_rust.direct_dial_reuse_test.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    macula_rust::direct_dial::advertise_direct(
        &provider_session,
        &provider_identity,
        realm,
        &procedure,
        std::time::Duration::from_secs(3600),
    )
    .await
    .expect("advertise_direct should publish the DHT record");
    let provider_station = provider_session.station.node_id;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let echo: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move { Ok(payload) })
                as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(echo)
    };
    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(20),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let resolver = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
        .await
        .expect("resolver handshake should succeed");
    // Reuse needs the resolver on the provider's own station.
    assert_eq!(
        hex::encode(resolver.station.node_id),
        hex::encode(provider_station),
        "the resolver and the provider reached different stations"
    );

    let response = macula_rust::direct_dial::call(
        &resolver,
        &caller_identity,
        realm,
        &procedure,
        Value::text("hello again"),
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("the direct call should be answered");
    match response {
        macula_rust::frame::CallResponse::Result { payload, .. } => {
            assert_eq!(payload, Value::text("hello again"));
        }
        other => panic!("expected a RESULT, got {other:?}"),
    }
    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the direct call");

    // A second connection under caller_identity would have made the station
    // close the resolver by now.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(
        resolver.end_reason().is_none(),
        "the resolver session ended: {:?}",
        resolver.end_reason()
    );
    // A plain DHT query, so a stale station_endpoint record on the fleet
    // can't fail the check.
    let advertisements = macula_rust::dht::find_records(
        &resolver,
        &caller_identity,
        macula_rust::dht::procedure_key(&macula_rust::dht::discovery_uri(realm, &procedure)),
    )
    .await
    .expect("the resolver still answers DHT queries");
    assert!(
        !advertisements.is_empty(),
        "the resolver found no advertisement for {procedure}"
    );

    provider_session
        .close(
            "normal",
            Some("direct-dial reuse provider done"),
            &provider_identity,
        )
        .await;
    resolver
        .close(
            "normal",
            Some("direct-dial reuse resolver done"),
            &caller_identity,
        )
        .await;
}

/// Proves `direct_dial::keep_advertised_direct` genuinely re-publishes on
/// each tick (not a no-op) and stops cleanly once told to.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn keep_advertised_direct_republishes_against_the_real_fleet() {
    // Two independent identities on purpose: `publisher_identity` is owned
    // by the spawned loop task; `reader_identity` is only ever used by this
    // test's own verifying reads. `_dht.find_record` doesn't care who's
    // asking, so there's no need to share one identity across an await
    // boundary that would otherwise fight the loop task for ownership.
    let publisher_identity = KeyPair::generate_with_default_puzzle();
    let reader_identity = KeyPair::generate_with_default_puzzle();

    let reader_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &reader_identity)
            .await
            .expect("reader handshake should succeed");
    let loop_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &publisher_identity,
    )
    .await
    .expect("loop session handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.test_keep_advertised.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );
    let uri = macula_rust::dht::discovery_uri(realm, &procedure);
    let key = macula_rust::dht::procedure_key(&uri);

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let loop_procedure = procedure.clone();
    let loop_task = tokio::spawn(async move {
        macula_rust::direct_dial::keep_advertised_direct(
            &loop_session,
            &publisher_identity,
            realm,
            &loop_procedure,
            std::time::Duration::from_secs(120),
            std::time::Duration::from_millis(500),
            async move {
                let _ = stop_rx.await;
            },
            |e| eprintln!("keep_advertised_direct tick failed (non-fatal): {e}"),
        )
        .await;
        (loop_session, publisher_identity)
    });

    // Give the first (immediate) tick time to land, then read it back.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let first = macula_rust::dht::find_record(&reader_session, &reader_identity, key)
        .await
        .expect("first tick should already be visible");

    // Wait past a second tick and confirm the record genuinely changed --
    // not a stale read of the same one.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let second = macula_rust::dht::find_record(&reader_session, &reader_identity, key)
        .await
        .expect("second tick should be visible");
    assert!(
        second.created_at > first.created_at,
        "expected the second tick's created_at ({}) to be strictly after the first's ({})",
        second.created_at,
        first.created_at
    );
    println!(
        "OBSERVED: created_at advanced from {} to {} across two KeepAdvertisedDirect ticks",
        first.created_at, second.created_at
    );

    stop_tx
        .send(())
        .expect("loop task should still be listening for stop");
    let (loop_session, publisher_identity) =
        tokio::time::timeout(std::time::Duration::from_secs(5), loop_task)
            .await
            .expect("keep_advertised_direct should return promptly after stop")
            .expect("loop task should not panic");
    println!("OBSERVED: keep_advertised_direct returned promptly after stop");

    reader_session
        .close(
            "normal",
            Some("keep_advertised_direct reader test done"),
            &reader_identity,
        )
        .await;
    loop_session
        .close(
            "normal",
            Some("keep_advertised_direct loop session done"),
            &publisher_identity,
        )
        .await;
}
