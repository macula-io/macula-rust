//! A clear call a keyed provider refuses sealed_required naming its KEM key
//! in the refusal's signed tbs is sealed to that key and sent once more
//! (release A0, DESIGN_E2E_SEALED_BY_DEFAULT section 3, macula-rust#42),
//! against macula-go's in-process stations (tests/common). The provider
//! here names its key only because the test sets it to; release A makes it
//! the rule. A refusal that names no key stands as the provider's own.

mod common;

use std::sync::Arc;

use common::TestStations;
use macula_rust::cbor::Value;
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::record;
use macula_rust::seal::Keyring;
use macula_rust::statement_issuer::StatementIssuer;
use macula_rust::station_link::{
    handler, Call, Called, Confidentiality, Config, Link, LinkError, Offer, Seal,
};

/// A link as a new node; with `keyring`, it advertises its key and, when
/// `names_key`, names it in a sealed_required refusal.
async fn node(env: &TestStations, keyring: Option<Arc<Keyring>>, names_key: bool) -> Link {
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.kem_advertise = keyring.is_some();
    cfg.refusal_names_key = names_key;
    cfg.keyring = keyring;
    Link::dial(cfg).await.unwrap()
}

/// A required procedure that answers what it was asked and whether sealed.
fn required(realm: [u8; 32], procedure: &str) -> Offer {
    let mut offer = Offer::unary(
        realm,
        procedure,
        handler(|r| async move {
            Ok(Value::Map(vec![
                (Value::text("asked"), r.payload),
                (Value::text("sealed"), Value::Int(i128::from(r.sealed))),
            ]))
        }),
    );
    offer.confidential = Confidentiality::Required;
    offer
}

fn clear(env: &TestStations, provider: &Link, procedure: &str) -> Call {
    Call {
        realm: env.realm_id,
        procedure: procedure.to_string(),
        target: provider.node_id(),
        payload: Value::text("plain"),
        seal: Some(Seal::Clear),
        ..Call::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_call_to_an_explicit_target_reseals_to_the_key_its_refusal_names() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        resealed_under(profile).await;
    }
}

/// One profile's pass: the clear call is answered sealed, under the key
/// the refusal named, by `Link::call_resealing` and by `Link::call`.
async fn resealed_under(profile: Profile) {
    let env = TestStations::start(profile);
    let keyring = Arc::new(Keyring::system(profile).unwrap());
    let provider = node(&env, Some(keyring.clone()), true).await;
    let caller = node(&env, None, false).await;
    let vault = record::own_procedure(&provider.node_id(), "vault");
    let _served = provider
        .serve(required(env.realm_id, &vault))
        .await
        .unwrap();

    let Called {
        outcome,
        resealed_to,
    } = caller.call_resealing(clear(&env, &provider, &vault)).await;
    let answered = outcome.unwrap_or_else(|e| panic!("{profile:?}: {e:?}"));
    assert_eq!(answered.get("asked"), Some(&Value::text("plain")));
    assert_eq!(
        answered.get("sealed"),
        Some(&Value::Int(1)),
        "{profile:?}: answered sealed"
    );
    assert_eq!(
        resealed_to.as_deref(),
        Some(keyring.current().public_key().carried()),
        "{profile:?}: sealed to the key the refusal named"
    );

    let answered = caller.call(clear(&env, &provider, &vault)).await.unwrap();
    assert_eq!(answered.get("sealed"), Some(&Value::Int(1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_naming_no_key_stands_as_sealed_required() {
    let env = TestStations::start(Profile::PqPure);
    let keyring = Arc::new(Keyring::system(env.profile).unwrap());
    let provider = node(&env, Some(keyring), false).await;
    let caller = node(&env, None, false).await;
    let vault = record::own_procedure(&provider.node_id(), "vault");
    let _served = provider
        .serve(required(env.realm_id, &vault))
        .await
        .unwrap();

    let called = caller.call_resealing(clear(&env, &provider, &vault)).await;
    assert_eq!(called.resealed_to, None);
    match called.outcome {
        Err(LinkError::Provider { code, detail, .. }) => {
            assert_eq!(code, "sealed_required");
            assert_eq!(detail, None);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refusal_names_key_needs_a_keyring() {
    let env = TestStations::start(Profile::PqPure);
    let identity = Arc::new(NodeKey::generate_identity(env.profile, PUZZLE_DIFFICULTY).unwrap());
    let issuer = StatementIssuer::with_wall_clock(identity.clone()).unwrap();
    let mut cfg = Config::new(env.target(0), identity, issuer);
    cfg.refusal_names_key = true;
    match Link::dial(cfg).await {
        Err(LinkError::InvalidConfig(_)) => {}
        other => panic!("{:?}", other.map(|l| l.node_id())),
    }
}
