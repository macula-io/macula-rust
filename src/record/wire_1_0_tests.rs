//! The wire 1.0 record vectors (macula#100): a reader ([`verify`]) runs
//! verify.json and check_order.json's reader cases; a custodian
//! ([`check_as_custodian`]) runs custodian.json, with the slot each stored
//! record of an unknown tag lands at, and check_order.json's custodian cases.
//! Each refusal is the first fault in WIRE_1_0.md section 5.2's order.

use std::collections::HashMap;

use super::*;
use crate::wire_vectors::{self, Case};

/// The refusal name section 5.2 gives `e`.
fn refusal_name(e: &RecordError) -> &'static str {
    match e {
        RecordError::TooLarge => "record_too_large",
        RecordError::Malformed(_) => "malformed",
        RecordError::AlgUnsupported => "alg_unsupported",
        RecordError::SignatureInvalid => "signature_invalid",
        RecordError::NotYetValid => "not_yet_valid",
        RecordError::Expired => "expired",
        RecordError::LifetimeReversed => "lifetime_reversed",
        RecordError::LifetimeClassUnknown => "lifetime_class_unknown",
        RecordError::LifetimeTooLong => "lifetime_too_long",
        RecordError::LifetimeClassMismatch => "lifetime_class_mismatch",
        RecordError::SubjectMissing => "subject_missing",
        RecordError::TypeUnknown => "type_unknown",
        RecordError::SchemaUnsupported => "schema_unsupported",
        RecordError::ExtensionUnsupported(_) => "extension_unsupported",
        RecordError::McidTagUnknown => "mcid_tag_unknown",
        RecordError::KeyIdMismatch => "key_id_mismatch",
        _ => "another refusal",
    }
}

fn profile(c: &Case) -> Profile {
    Profile::parse(&c.profile).unwrap()
}

fn now(c: &Case) -> i64 {
    c.int("now_ms").unwrap()
}

/// The verdict on one case, in the vectors' terms.
fn verdict<T>(read: Result<T, RecordError>, ok: &'static str) -> (&'static str, &'static str) {
    match read {
        Ok(_) => (ok, ""),
        Err(e) => ("refuse", refusal_name(&e)),
    }
}

/// The cases of `classes` a `role` runs: every case of a class that names no
/// role, and check_order.json's cases of that role.
fn cases_of(classes: &[&str], role: &str) -> Vec<Case> {
    classes
        .iter()
        .flat_map(|class| wire_vectors::load(class).cases)
        .filter(|c| matches!(c.expect_text("role"), "") || c.expect_text("role") == role)
        .collect()
}

#[test]
fn the_wire_1_0_reader_vectors() {
    let cases = cases_of(&["verify", "check_order"], "reader");
    let ignored = || {
        let counts = crate::frame::wire_counters();
        counts.ext_ignored.values().sum::<u64>()
    };
    for c in &cases {
        let before = ignored();
        let got = verdict(verify(&c.hex("object"), profile(c), now(c)), "accept");
        assert_eq!(got, (c.outcome(), c.reason()), "{}", c.id);
        let counted = ignored() > before;
        assert!(
            !c.id.contains("ext_noncritical_unknown") || counted,
            "{}",
            c.id
        );
    }
    assert_eq!(
        cases.len(),
        132 + 14,
        "verify.json's cases and check_order.json's reader ones"
    );
}

#[test]
fn the_wire_1_0_custodian_vectors() {
    let objects: HashMap<String, Vec<u8>> = wire_vectors::load("verify")
        .cases
        .iter()
        .map(|c| (c.id.clone(), c.hex("object")))
        .collect();
    let cases = cases_of(&["custodian", "check_order"], "custodian");
    for c in &cases {
        let wire = match c.has("object") {
            true => c.hex("object"),
            false => objects[c.text("object_of")].clone(),
        };
        let stored = check_as_custodian(&wire, profile(c), now(c));
        let slot = stored.as_ref().ok().map(hex::encode);
        let want = c.expect["slot"].as_str();
        assert!(
            want.is_none() || slot.as_deref() == want,
            "{}: the slot",
            c.id
        );
        assert_eq!(
            verdict(stored, "store"),
            (c.outcome(), c.reason()),
            "{}",
            c.id
        );
    }
    assert_eq!(
        cases.len(),
        132 + 26,
        "custodian.json's cases and check_order.json's custodian ones"
    );
}
