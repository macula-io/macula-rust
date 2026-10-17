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

/// The issued_at a status statement's tbs names.
fn issued_at(statement: &macula_rust::binding::SignedTbs) -> i64 {
    let fields = macula_rust::cbor::decode(&statement.tbs).unwrap();
    match fields.get("issued_at") {
        Some(macula_rust::cbor::Value::Int(n)) => *n as i64,
        other => panic!("a statement's issued_at: {other:?}"),
    }
}

/// Ticks at `ms` and returns the statement the subscription holds.
fn pushed_at(
    clock: &AtomicI64,
    issuer: &StatementIssuer,
    statements: &mut macula_rust::statement_issuer::StatementSubscription,
    ms: i64,
) -> macula_rust::binding::SignedTbs {
    clock.store(ms, Ordering::SeqCst);
    issuer.tick().unwrap();
    statements.try_recv().expect("a statement was handed over")
}

/// A peer drops a statement that is not newer than the last it accepted on a
/// connection (macula 15.5.0's status_not_newer), so each statement pushed
/// for a binding is issued after the one before it, a millisecond after it
/// when the clock has stepped back, as macula_statement_issuer does
/// (macula-architecture#22).
#[test]
fn a_statement_pushed_after_the_clock_stepped_back_is_still_newer() {
    let (clock, issuer, _identity) = issuer();
    let material = issuer.connect_material().unwrap();
    let mut statements = issuer.subscribe(&material.binding).unwrap();
    let minute = 60 * 1000;

    let before = issued_at(&pushed_at(
        &clock,
        &issuer,
        &mut statements,
        START + 30 * minute,
    ));
    // 20 minutes back: past the tolerance, but not before the binding, so the
    // CONNECT key stays.
    let stepped = issued_at(&pushed_at(
        &clock,
        &issuer,
        &mut statements,
        START + 10 * minute,
    ));
    assert_eq!(stepped, before + 1);
    // Once the clock passes the last statement, statements follow it again.
    let later = START + 50 * minute;
    assert_eq!(
        issued_at(&pushed_at(&clock, &issuer, &mut statements, later)),
        later
    );
}

/// A new dial has no earlier statement to be newer than, so after the clock
/// stepped back past the tolerance it carries a statement at the clock's
/// time, which verifies there, while statements pushed on connections stay
/// newer than every statement issued for the binding, the new dial's too.
#[test]
fn a_new_dial_after_the_clock_stepped_back_carries_a_statement_in_force() {
    let (clock, issuer, identity) = issuer();
    let material = issuer.connect_material().unwrap();
    let mut statements = issuer.subscribe(&material.binding).unwrap();
    let minute = 60 * 1000;
    let last = issued_at(&pushed_at(
        &clock,
        &issuer,
        &mut statements,
        START + 30 * minute,
    ));

    let stepped = START + 10 * minute;
    clock.store(stepped, Ordering::SeqCst);
    let dial = issuer.connect_material().unwrap();
    assert_eq!(
        verify_status(&dial.status, &dial.binding, &identity, P, stepped).unwrap(),
        stepped + 60 * minute
    );
    if let Ok(pushed) = statements.try_recv() {
        assert!(issued_at(&pushed) > last, "a push older than the last");
    }
    let next = issued_at(&pushed_at(
        &clock,
        &issuer,
        &mut statements,
        stepped + 16 * minute,
    ));
    assert!(
        next > last,
        "the next push, {next}, is not after the last, {last}"
    );
}
