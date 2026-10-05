//! A provider that names its KEM key (macula 13, E2E design §5, amendment
//! A1), against macula-go's in-process stations (tests/common): its
//! advertisement names the keyring's current key, a call sealed to it is
//! opened and answered sealed, a call sealed to a key it does not hold is
//! refused sealed_refused naming the key it holds, and a required procedure
//! refuses every clear call sealed_required. Streams likewise: a sealed open
//! is opened, every frame after it sealed both ways, and a refusal after
//! the open goes sealed.

mod common;

use std::sync::Arc;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::{StreamEncoding, StreamMode, StreamRole};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record::{self, read_procedure_advertisement, RecordType};
use macula_rust::seal::{self, Keyring};
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Call, Confidentiality, Config, Link, LinkError, Offer, Seal, Stream,
    StreamCall, StreamEvent,
};

/// A link as a new node, with `keyring` and kem_advertise on when given.
async fn node(env: &TestStations, keyring: Option<Arc<Keyring>>) -> Result<Link, LinkError> {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.keyring = keyring;
    Link::dial(cfg).await
}

/// A procedure that answers who called, whether sealed, and what it was
/// asked, and refuses "fail" with a handler error.
fn echo(realm: [u8; 32], procedure: &str, confidential: Confidentiality) -> Offer {
    let mut offer = Offer::unary(
        realm,
        procedure,
        handler(|r| async move {
            if r.payload == Value::text("fail") {
                return Err("refused by the handler".to_string());
            }
            Ok(Value::Map(vec![
                (Value::text("asked"), r.payload),
                (Value::text("sealed"), Value::Int(i128::from(r.sealed))),
            ]))
        }),
    );
    offer.confidential = confidential;
    offer
}

/// The KEM key the provider's advertisement of `procedure` names, read back
/// from the DHT as a caller reads it.
async fn advertised_key(link: &Link, procedure: &str) -> Option<Vec<u8>> {
    let (ads, _) = link
        .find_records_by_type(RecordType::PROCEDURE_ADVERTISEMENT)
        .await
        .unwrap();
    ads.iter()
        .map(|v| read_procedure_advertisement(v.record()).unwrap())
        .find(|ad| ad.procedure == procedure)
        .expect("the advertisement is in the DHT")
        .kem_key
        .map(|(key, _)| key)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keyed_provider_opens_sealed_calls_and_answers_them_sealed() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let env = TestStations::start(profile);
        let keyring = Arc::new(Keyring::system(profile).unwrap());
        let provider = node(&env, Some(keyring.clone())).await.unwrap();
        let caller = node(&env, None).await.unwrap();
        let vault = record::own_procedure(&provider.node_id(), "vault");
        let _served = provider
            .serve(echo(env.realm_id, &vault, Confidentiality::Preferred))
            .await
            .unwrap();

        let key = advertised_key(&caller, &vault).await;
        assert_eq!(
            key.as_deref(),
            Some(keyring.current().public_key().carried()),
            "{profile:?}: the advertisement names the keyring's current key"
        );
        let call = |payload: Value, seal: Seal| Call {
            realm: env.realm_id,
            procedure: vault.clone(),
            target: provider.node_id(),
            payload,
            seal: Some(seal),
            ..Call::default()
        };
        let to = Seal::To(key.unwrap());
        let answered = caller
            .call(call(Value::text("secret"), to.clone()))
            .await
            .unwrap();
        assert_eq!(answered.get("asked"), Some(&Value::text("secret")));
        assert_eq!(answered.get("sealed"), Some(&Value::Int(1)));

        // A handler's refusal of a sealed request goes back sealed and
        // opens to its code and detail.
        match caller.call(call(Value::text("fail"), to)).await {
            Err(LinkError::Provider { code, detail, .. }) => {
                assert_eq!(code, "handler_error");
                assert_eq!(detail.as_deref(), Some("refused by the handler"));
            }
            other => panic!("{profile:?}: {other:?}"),
        }

        // A preferred procedure still takes a clear call within its keyless
        // window, and its handler sees it was clear.
        let clear = caller
            .call(call(Value::text("plain"), Seal::Clear))
            .await
            .unwrap();
        assert_eq!(clear.get("sealed"), Some(&Value::Int(0)));

        // Sealed to a key this provider never held: refused in the clear,
        // naming the key it holds now, and the handler never runs.
        let stranger = seal::PrivateKey::generate(profile).unwrap();
        let refused = caller
            .call(call(
                Value::text("secret"),
                Seal::To(stranger.public_key().carried().to_vec()),
            ))
            .await;
        assert_eq!(
            refused,
            Err(LinkError::SealedRefused {
                named: Some(keyring.current_id())
            }),
            "{profile:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_required_procedure_refuses_clear_calls_and_an_off_one_names_no_key() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring)).await.unwrap();
    let caller = node(&env, None).await.unwrap();
    let required = record::own_procedure(&provider.node_id(), "required");
    let off = record::own_procedure(&provider.node_id(), "off");
    let _required = provider
        .serve(echo(env.realm_id, &required, Confidentiality::Required))
        .await
        .unwrap();
    let _off = provider
        .serve(echo(env.realm_id, &off, Confidentiality::Off))
        .await
        .unwrap();

    let clear = |procedure: &str| Call {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        payload: Value::text("plain"),
        seal: Some(Seal::Clear),
        ..Call::default()
    };
    match caller.call(clear(&required)).await {
        Err(LinkError::Provider { code, detail, .. }) => {
            assert_eq!(code, "sealed_required");
            assert_eq!(detail, None);
        }
        other => panic!("{other:?}"),
    }
    assert!(advertised_key(&caller, &required).await.is_some());

    assert_eq!(advertised_key(&caller, &off).await, None);
    let answered = caller.call(clear(&off)).await.unwrap();
    assert_eq!(answered.get("sealed"), Some(&Value::Int(0)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_required_procedure_needs_kem_advertise_and_kem_advertise_needs_a_keyring() {
    let env = TestStations::start(Profile::PqPure);
    let plain = node(&env, None).await.unwrap();
    let required = record::own_procedure(&plain.node_id(), "required");
    assert_eq!(
        plain
            .serve(echo(env.realm_id, &required, Confidentiality::Required))
            .await
            .err(),
        Some(LinkError::KemAdvertiseDisabled)
    );

    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity.clone(), issuer);
    cfg.kem_advertise = true;
    assert!(matches!(
        Link::dial(cfg).await,
        Err(LinkError::InvalidConfig(_))
    ));
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.keyring = Some(Arc::new(Keyring::system(Profile::PqHybrid).unwrap()));
    assert!(matches!(
        Link::dial(cfg).await,
        Err(LinkError::InvalidConfig(_))
    ));
}

/// Every event a stream delivers until it ends, and how it ended.
async fn drained(stream: &Stream) -> (Vec<StreamEvent>, LinkError) {
    let mut events = Vec::new();
    loop {
        match stream.recv().await {
            Ok(event) => events.push(event),
            Err(e) => return (events, e),
        }
    }
}

fn raw(b: &[u8]) -> StreamEvent {
    StreamEvent::Data {
        encoding: StreamEncoding::Raw,
        body: Value::Bytes(b.to_vec()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keyed_provider_serves_sealed_streams_both_ways() {
    let env = TestStations::start(Profile::PqHybrid);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring.clone())).await.unwrap();
    let caller = node(&env, None).await.unwrap();
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let count = record::own_procedure(&provider.node_id(), "count");
    let vault = record::own_procedure(&provider.node_id(), "vault");
    let guarded = record::own_procedure(&provider.node_id(), "guarded");
    let _watch = provider
        .serve(Offer::stream(
            env.realm_id,
            &watch,
            StreamMode::ServerStream,
            stream_handler(|stream| async move {
                // The handler reads the open's opened payload.
                let Value::Bytes(asked) = stream.request().payload.clone() else {
                    return Err("the open's payload did not open".into());
                };
                let sealed = [u8::from(stream.sealed())];
                for chunk in [&asked[..], b"two", &sealed[..]] {
                    stream.send(chunk).await.map_err(|e| e.to_string())?;
                }
                Ok(())
            }),
        ))
        .await
        .unwrap();
    let _count = provider
        .serve(Offer::stream(
            env.realm_id,
            &count,
            StreamMode::ClientStream,
            stream_handler(|stream| async move {
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
            }),
        ))
        .await
        .unwrap();
    let _vault = provider
        .serve(echo(env.realm_id, &vault, Confidentiality::Preferred))
        .await
        .unwrap();
    let mut required = Offer::stream(
        env.realm_id,
        &guarded,
        StreamMode::ServerStream,
        stream_handler(|_| async move { Ok(()) }),
    );
    required.confidential = Confidentiality::Required;
    let _guarded = provider.serve(required).await.unwrap();

    let key = advertised_key(&caller, &watch).await.unwrap();
    let open = |procedure: &str, mode, seal: Seal| StreamCall {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        mode,
        payload: Value::Bytes(b"one".to_vec()),
        seal: Some(seal),
        ..StreamCall::default()
    };
    let to = Seal::To(key.clone());

    let stream = caller
        .open_stream(open(&watch, StreamMode::ServerStream, to.clone()))
        .await
        .unwrap();
    assert!(stream.sealed());
    let (events, ended) = drained(&stream).await;
    assert_eq!(
        events,
        vec![
            raw(b"one"),
            raw(b"two"),
            raw(&[1]),
            StreamEvent::End {
                role: StreamRole::Both
            }
        ]
    );
    assert_eq!(ended, LinkError::EndOfStream);

    let stream = caller
        .open_stream(open(&count, StreamMode::ClientStream, to.clone()))
        .await
        .unwrap();
    for chunk in [&b"abc"[..], b"de"] {
        stream.send(chunk).await.unwrap();
    }
    stream.close_send().await.unwrap();
    let (events, _) = drained(&stream).await;
    assert_eq!(
        events,
        vec![StreamEvent::Reply {
            payload: Value::Int(5)
        }]
    );

    // A refusal after the open opened goes sealed, and opens to its code.
    let stream = caller
        .open_stream(open(&vault, StreamMode::ServerStream, to))
        .await
        .unwrap();
    assert!(matches!(
        drained(&stream).await.1,
        LinkError::Stream { code, .. } if code == "not_found"
    ));

    // Sealed to a key the provider never held: refused in the clear, naming
    // the key it holds now.
    let stranger = seal::PrivateKey::generate(env.profile).unwrap();
    let stream = caller
        .open_stream(open(
            &watch,
            StreamMode::ServerStream,
            Seal::To(stranger.public_key().carried().to_vec()),
        ))
        .await
        .unwrap();
    let current: String = keyring
        .current_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        drained(&stream).await.1,
        LinkError::Stream {
            code: "sealed_refused".into(),
            message: current,
            relay: false
        }
    );

    // A clear open of a required procedure is refused sealed_required.
    let stream = caller
        .open_stream(open(&guarded, StreamMode::ServerStream, Seal::Clear))
        .await
        .unwrap();
    assert!(matches!(
        drained(&stream).await.1,
        LinkError::Stream { code, .. } if code == "sealed_required"
    ));
}
