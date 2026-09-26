//! The client's statement issuer (D22): a CONNECT key bound to the identity
//! key, a status statement for it reissued every 15 minutes and handed to its
//! subscribers, the CONNECT key rotated every 5 days, and material for a new
//! dial that is always in force.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use macula_rust::binding::{verify_connect_binding, verify_status};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;
use macula_rust::statement_issuer::{
    IssuerError, StatementIssuer, CONNECT_ROTATE_EVERY_MS, STATEMENT_EVERY_MS,
};

const P: Profile = Profile::PqPure;
const START: i64 = 1_789_000_000_000;

fn issuer() -> (Arc<AtomicI64>, StatementIssuer, Vec<u8>) {
    let clock = Arc::new(AtomicI64::new(START));
    let seen = clock.clone();
    let identity = Arc::new(NodeKey::generate(Purpose::Identity, P).unwrap());
    let carried = identity.public_key();
    let issuer =
        StatementIssuer::new(identity, Box::new(move || seen.load(Ordering::SeqCst))).unwrap();
    (clock, issuer, carried)
}

#[test]
fn connect_material_is_a_bound_connect_key_with_a_statement_in_force() {
    let (_clock, issuer, identity) = issuer();
    let material = issuer.connect_material().unwrap();
    assert_eq!(material.key.purpose(), Purpose::Connect);
    verify_connect_binding(
        &material.binding,
        &identity,
        P,
        &material.key.public_key(),
        START,
    )
    .unwrap();
    assert_eq!(
        verify_status(&material.status, &material.binding, &identity, P, START).unwrap(),
        START + 60 * 60 * 1000
    );
}

#[test]
fn each_tick_hands_subscribers_the_newest_statement() {
    let (clock, issuer, identity) = issuer();
    let material = issuer.connect_material().unwrap();
    let mut statements = issuer.subscribe(&material.binding).unwrap();
    clock.store(START + STATEMENT_EVERY_MS, Ordering::SeqCst);
    issuer.tick().unwrap();
    clock.store(START + 2 * STATEMENT_EVERY_MS, Ordering::SeqCst);
    issuer.tick().unwrap();
    // The subscription holds the newest statement only.
    let newest = statements.try_recv().expect("a statement was handed over");
    assert!(statements.try_recv().is_err());
    let expires = verify_status(
        &newest,
        &material.binding,
        &identity,
        P,
        START + 2 * STATEMENT_EVERY_MS,
    )
    .unwrap();
    assert_eq!(expires, START + 2 * STATEMENT_EVERY_MS + 60 * 60 * 1000);
}

#[test]
fn the_connect_key_rotates_and_a_late_dial_still_gets_material_in_force() {
    let (clock, issuer, identity) = issuer();
    let first = issuer.connect_material().unwrap();
    // No tick for 5 days: the next dial's material is rotated and in force.
    let later = START + CONNECT_ROTATE_EVERY_MS;
    clock.store(later, Ordering::SeqCst);
    let second = issuer.connect_material().unwrap();
    assert_ne!(second.key.public_key(), first.key.public_key());
    verify_connect_binding(
        &second.binding,
        &identity,
        P,
        &second.key.public_key(),
        later,
    )
    .unwrap();
    verify_status(&second.status, &second.binding, &identity, P, later).unwrap();
    assert_eq!(issuer.rotation_failures(), 0);
}

#[test]
fn a_binding_the_issuer_does_not_hold_cannot_be_subscribed_to() {
    let (_clock, mine, _) = issuer();
    let (_clock2, other, _) = issuer();
    let foreign = other.connect_material().unwrap();
    assert!(matches!(
        mine.subscribe(&foreign.binding),
        Err(IssuerError::UnknownBinding)
    ));
}

#[test]
fn only_an_identity_key_issues() {
    let connect = NodeKey::generate(Purpose::Connect, P).unwrap();
    assert!(StatementIssuer::new(Arc::new(connect), Box::new(|| START)).is_err());
}
