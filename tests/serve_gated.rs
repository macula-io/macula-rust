//! A procedure gated on a UCAN policy, against macula-go's in-process
//! stations (tests/common): a call or a stream open whose token the policy
//! authorizes is served, through a delegation chain too; one with no token,
//! another caller's token or another issuer's chain is refused unauthorized;
//! a proof no link names is malformed_frame; and an open procedure ignores
//! any token.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, stream_handler, Call, Config, Link, LinkError, Offer, Seal, Stream, StreamCall,
    StreamEvent,
};
use macula_rust::ucan::{create, proof_id, Capability, Options, Policy};
use sha2::{Digest, Sha256};

const REALM: &str = "io.macula";

fn realm_id() -> [u8; 32] {
    Sha256::digest(REALM.as_bytes()).into()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A node's identity key and its link.
async fn node(env: &TestStations) -> (Arc<NodeKey>, Link) {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let cfg = Config::new(env.target(0), identity.clone(), issuer);
    (identity, Link::dial(cfg).await.unwrap())
}

/// A token from `issuer` for `audience`, granting `with`, resting on
/// `parent` when given.
fn token(issuer: &NodeKey, audience: &NodeKey, with: &str, parent: Option<&[u8]>) -> Vec<u8> {
    let caps = [Capability {
        with: with.into(),
        can: "invoke".into(),
    }];
    let o = Options {
        exp: now() + 300,
        prf: parent.map(|p| vec![proof_id(p)]),
        ..Options::default()
    };
    create(issuer, &audience.node_id().unwrap(), &caps, &o).unwrap()
}

async fn drained(stream: &Stream) -> (Vec<StreamEvent>, LinkError) {
    let mut events = Vec::new();
    loop {
        match stream.recv().await {
            Ok(event) => events.push(event),
            Err(e) => return (events, e),
        }
    }
}

fn refused(code: &str) -> impl Fn(&Result<Value, LinkError>) -> bool + '_ {
    move |r| matches!(r, Err(LinkError::Provider { code: c, .. }) if c == code)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gated_procedure_serves_only_what_its_policy_authorizes() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let env = TestStations::start(profile);
        let (provider_key, provider) = node(&env).await;
        let (alice_key, alice) = node(&env).await;
        let (bob_key, bob) = node(&env).await;
        let gated = record::own_procedure(&provider.node_id(), "count");
        let open = record::own_procedure(&provider.node_id(), "echo");
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = ran.clone();
        let mut offer = Offer::unary(
            realm_id(),
            &gated,
            handler(move |r| {
                counted.fetch_add(1, Ordering::SeqCst);
                async move { Ok(r.payload) }
            }),
        );
        offer.policy = Some(Policy::UcanRequired {
            issuer: provider_key.node_id().unwrap(),
        });
        let _gated = provider.serve(offer).await.unwrap();
        let _open = provider
            .serve(Offer::unary(
                realm_id(),
                &open,
                handler(|r| async move { Ok(r.payload) }),
            ))
            .await
            .unwrap();

        let with = format!("mri:proc:{REALM}/{gated}");
        let call = |procedure: &str, token: Option<Vec<u8>>, proofs: Vec<Vec<u8>>| Call {
            realm: realm_id(),
            procedure: procedure.to_string(),
            target: provider.node_id(),
            payload: Value::text("hello"),
            token,
            proofs,
            seal: Some(Seal::Clear),
            ..Call::default()
        };

        let to_alice = token(&provider_key, &alice_key, &with, None);
        let answered = alice
            .call(call(&gated, Some(to_alice.clone()), vec![]))
            .await;
        assert_eq!(answered, Ok(Value::text("hello")), "{profile:?}");

        // Alice hands it on to Bob, whose call carries her token as proof.
        let to_bob = token(&alice_key, &bob_key, &with, Some(&to_alice));
        let delegated = bob
            .call(call(&gated, Some(to_bob.clone()), vec![to_alice.clone()]))
            .await;
        assert_eq!(delegated, Ok(Value::text("hello")), "{profile:?}");
        assert_eq!(ran.load(Ordering::SeqCst), 2);

        let unauthorized = refused("unauthorized");
        for (who, answer) in [
            ("no token", alice.call(call(&gated, None, vec![])).await),
            (
                "another caller's token",
                bob.call(call(&gated, Some(to_alice.clone()), vec![])).await,
            ),
            (
                "a chain without its proof",
                bob.call(call(&gated, Some(to_bob.clone()), vec![])).await,
            ),
            (
                "another issuer's token",
                alice
                    .call(call(
                        &gated,
                        Some(token(&bob_key, &alice_key, &with, None)),
                        vec![],
                    ))
                    .await,
            ),
        ] {
            assert!(unauthorized(&answer), "{profile:?} {who}: {answer:?}");
        }
        let stray = alice
            .call(call(&gated, Some(to_alice.clone()), vec![to_bob.clone()]))
            .await;
        assert!(refused("malformed_frame")(&stray), "{profile:?}: {stray:?}");
        assert_eq!(
            ran.load(Ordering::SeqCst),
            2,
            "no refused call reached the handler"
        );

        // An open procedure ignores any token.
        let ignored = bob
            .call(call(&open, Some(b"not a token".to_vec()), vec![]))
            .await;
        assert_eq!(ignored, Ok(Value::text("hello")), "{profile:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gated_stream_opens_only_for_an_authorized_token() {
    let env = TestStations::start(Profile::PqPure);
    let (provider_key, provider) = node(&env).await;
    let (alice_key, alice) = node(&env).await;
    let watch = record::own_procedure(&provider.node_id(), "watch");
    let mut offer = Offer::stream(
        realm_id(),
        &watch,
        StreamMode::ServerStream,
        stream_handler(|s| async move {
            s.send(b"tick").await.map_err(|e| e.to_string())?;
            s.close().await.map_err(|e| e.to_string())
        }),
    );
    offer.policy = Some(Policy::RealmMemberRequired {
        key_id: macula_rust::node_key::key_id_of(&provider_key.public_key(), env.profile),
        can: "invoke".into(),
    });
    let _served = provider.serve(offer).await.unwrap();
    let open = |token: Option<Vec<u8>>| StreamCall {
        realm: realm_id(),
        procedure: watch.clone(),
        target: provider.node_id(),
        mode: StreamMode::ServerStream,
        token,
        seal: Some(Seal::Clear),
        ..StreamCall::default()
    };

    let member = token(
        &provider_key,
        &alice_key,
        &format!("mri:realm:{REALM}"),
        None,
    );
    let stream = alice.open_stream(open(Some(member))).await.unwrap();
    let (events, _) = tokio::time::timeout(Duration::from_secs(10), drained(&stream))
        .await
        .unwrap();
    assert!(
        matches!(events.first(), Some(StreamEvent::Data { body: Value::Bytes(b), .. }) if b == b"tick"),
        "{events:?}"
    );

    let stream = alice.open_stream(open(None)).await.unwrap();
    let (_, refusal) = tokio::time::timeout(Duration::from_secs(10), drained(&stream))
        .await
        .unwrap();
    assert!(
        matches!(&refusal, LinkError::Stream { code, .. } if code == "unauthorized"),
        "{refusal:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_realm_member_policy_without_a_can_is_not_served() {
    let env = TestStations::start(Profile::PqPure);
    let (_, provider) = node(&env).await;
    let mut offer = Offer::unary(
        realm_id(),
        &record::own_procedure(&provider.node_id(), "count"),
        handler(|r| async move { Ok(r.payload) }),
    );
    offer.policy = Some(Policy::RealmMemberRequired {
        key_id: [1; 32],
        can: String::new(),
    });
    assert!(matches!(
        provider.serve(offer).await,
        Err(LinkError::InvalidOffer)
    ));
}
