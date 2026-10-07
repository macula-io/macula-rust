//! TLS and CONNECT bindings and status statements, held to the ones macula
//! itself made (tests/vectors/identity/erlang_bindings.json, by
//! macula_key_bindings and macula_node_keys at macula v12.1.0): they verify
//! here as there, are refused where macula refuses them, and carry tbs bytes
//! this crate's encoder writes byte for byte. Then the ones this crate makes.

use macula_rust::binding::{
    connect_binding, status_statement, tls_binding, verify_connect_binding, verify_status,
    verify_tls_binding, BindingError, BindingUse, SignedTbs,
};
use macula_rust::cbor;
use macula_rust::node_key::{node_id_of, NodeKey, Purpose};
use macula_rust::profile::Profile;

/// A change to a signed structure that must leave it unverifiable.
type Alteration = Box<dyn Fn(&SignedTbs) -> SignedTbs>;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const MINUTE_MS: i64 = 60 * 1000;
const MLDSA_SIGNATURE: usize = 4627;

struct Entry {
    profile: Profile,
    now_ms: i64,
    identity_key: Vec<u8>,
    node_id: Vec<u8>,
    leaf: Vec<u8>,
    tls_binding: SignedTbs,
    tls_status: SignedTbs,
    connect_key: Vec<u8>,
    connect_binding: SignedTbs,
    connect_status: SignedTbs,
}

fn entries() -> Vec<Entry> {
    let text = std::fs::read_to_string("tests/vectors/identity/erlang_bindings.json").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let signed = |v: &serde_json::Value| SignedTbs {
        tbs: bytes(&v["tbs"]),
        signature: bytes(&v["signature"]),
    };
    let entries: Vec<Entry> = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| Entry {
            profile: Profile::parse(e["profile"].as_str().unwrap()).unwrap(),
            now_ms: e["now_ms"].as_i64().unwrap(),
            identity_key: bytes(&e["identity_key"]),
            node_id: bytes(&e["node_id"]),
            leaf: bytes(&e["leaf"]),
            tls_binding: signed(&e["tls_binding"]),
            tls_status: signed(&e["tls_status"]),
            connect_key: bytes(&e["connect_key"]),
            connect_binding: signed(&e["connect_binding"]),
            connect_status: signed(&e["connect_status"]),
        })
        .collect();
    assert_eq!(entries.len(), 2, "one entry per profile");
    entries
}

fn other(profile: Profile) -> Profile {
    match profile {
        Profile::PqPure => Profile::PqHybrid,
        Profile::PqHybrid => Profile::PqPure,
    }
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 1;
    out
}

#[test]
fn bindings_and_statements_macula_made_verify_here() {
    for e in entries() {
        macula_entry_verifies(&e);
        macula_entry_refusals(&e);
    }
}

/// One entry macula made: its node_id, its tbs bytes re-encoded here, and
/// its bindings and statements verified.
fn macula_entry_verifies(e: &Entry) {
    let p = e.profile;
    assert_eq!(
        node_id_of(&e.identity_key, p).to_vec(),
        e.node_id,
        "{p:?}: node_id"
    );
    tbs_reencode_to_macula_s_bytes(e);

    let info = verify_tls_binding(&e.tls_binding, &e.identity_key, p, &e.leaf, e.now_ms).unwrap();
    assert_eq!(info.use_, BindingUse::Tls);
    assert_eq!(info.node_id.to_vec(), e.node_id);
    assert_eq!(info.not_after, e.now_ms + 7 * DAY_MS);
    verify_status(&e.tls_status, &e.tls_binding, &e.identity_key, p, e.now_ms).unwrap();
    verify_connect_binding(
        &e.connect_binding,
        &e.identity_key,
        p,
        &e.connect_key,
        e.now_ms,
    )
    .unwrap();
    verify_status(
        &e.connect_status,
        &e.connect_binding,
        &e.identity_key,
        p,
        e.now_ms,
    )
    .unwrap();
}

/// Each of an entry's tbs decodes and re-encodes to macula's bytes.
fn tbs_reencode_to_macula_s_bytes(e: &Entry) {
    let p = e.profile;
    for (name, tbs) in [
        ("TLS binding", &e.tls_binding.tbs),
        ("TLS status", &e.tls_status.tbs),
        ("CONNECT binding", &e.connect_binding.tbs),
        ("CONNECT status", &e.connect_status.tbs),
    ] {
        let value = cbor::decode(tbs).unwrap();
        assert_eq!(
            &cbor::encode(&value).unwrap(),
            tbs,
            "{p:?}: {name} re-encodes to macula's bytes"
        );
    }
}

/// One entry macula made, refused for another leaf, the other binding, the
/// other profile and past its window.
fn macula_entry_refusals(e: &Entry) {
    let p = e.profile;
    let mut other_leaf = e.leaf.clone();
    other_leaf.push(0);
    assert_eq!(
        verify_tls_binding(&e.tls_binding, &e.identity_key, p, &other_leaf, e.now_ms).unwrap_err(),
        BindingError::KeyMismatch
    );
    assert_eq!(
        verify_tls_binding(
            &e.connect_binding,
            &e.identity_key,
            p,
            &e.connect_key,
            e.now_ms
        )
        .unwrap_err(),
        BindingError::BindingSignatureInvalid
    );
    assert_eq!(
        verify_status(
            &e.tls_status,
            &e.connect_binding,
            &e.identity_key,
            p,
            e.now_ms
        )
        .unwrap_err(),
        BindingError::StatusBindingMismatch
    );
    assert_eq!(
        verify_tls_binding(&e.tls_binding, &e.identity_key, other(p), &e.leaf, e.now_ms)
            .unwrap_err(),
        BindingError::BindingSignatureInvalid
    );
    assert_eq!(
        verify_tls_binding(
            &e.tls_binding,
            &e.identity_key,
            p,
            &e.leaf,
            e.now_ms + 7 * DAY_MS + 6 * MINUTE_MS
        )
        .unwrap_err(),
        BindingError::Expired
    );
}

#[test]
fn a_binding_or_statement_macula_made_altered_by_one_byte_is_refused() {
    for e in entries() {
        let p = e.profile;
        let mut offsets = vec![10];
        if p == Profile::PqHybrid {
            offsets.push(MLDSA_SIGNATURE + 10);
        }
        let mut alterations: Vec<Alteration> = vec![Box::new(|s: &SignedTbs| SignedTbs {
            tbs: flipped(&s.tbs, s.tbs.len() / 2),
            signature: s.signature.clone(),
        })];
        for offset in offsets {
            alterations.push(Box::new(move |s: &SignedTbs| SignedTbs {
                tbs: s.tbs.clone(),
                signature: flipped(&s.signature, offset),
            }));
        }
        for alter in &alterations {
            assert_eq!(
                verify_tls_binding(
                    &alter(&e.tls_binding),
                    &e.identity_key,
                    p,
                    &e.leaf,
                    e.now_ms
                )
                .unwrap_err(),
                BindingError::BindingSignatureInvalid
            );
            assert_eq!(
                verify_connect_binding(
                    &alter(&e.connect_binding),
                    &e.identity_key,
                    p,
                    &e.connect_key,
                    e.now_ms
                )
                .unwrap_err(),
                BindingError::BindingSignatureInvalid
            );
            assert_eq!(
                verify_status(
                    &alter(&e.tls_status),
                    &e.tls_binding,
                    &e.identity_key,
                    p,
                    e.now_ms
                )
                .unwrap_err(),
                BindingError::StatusSignatureInvalid
            );
        }
    }
}

#[test]
fn bindings_and_statements_made_here_verify_and_hold_their_windows() {
    let now = 1_789_000_000_000;
    let identity = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let carried = identity.public_key();
    let connect = NodeKey::generate(Purpose::Connect, Profile::PqPure).unwrap();

    let tls = tls_binding(&identity, b"a leaf", now, now + 7 * DAY_MS).unwrap();
    assert_eq!(
        verify_tls_binding(&tls, &carried, Profile::PqPure, b"a leaf", now)
            .unwrap()
            .node_id,
        identity.node_id().unwrap()
    );
    let bound = connect_binding(&identity, &connect.public_key(), now, now + DAY_MS).unwrap();
    verify_connect_binding(
        &bound,
        &carried,
        Profile::PqPure,
        &connect.public_key(),
        now,
    )
    .unwrap();
    let status = status_statement(&identity, &bound, now, now + 60 * MINUTE_MS).unwrap();
    assert_eq!(
        verify_status(&status, &bound, &carried, Profile::PqPure, now).unwrap(),
        now + 60 * MINUTE_MS
    );

    made_here_held_to_their_windows(&tls, &bound, &status, &carried, now);
    windows_a_verifier_refuses_are_not_issued(&identity, &bound, now);

    // A CONNECT key has no node_id to bind for.
    assert!(tls_binding(&connect, b"a leaf", now, now + DAY_MS).is_err());
}

/// A binding and a statement made here, refused before and after their
/// windows.
fn made_here_held_to_their_windows(
    tls: &SignedTbs,
    bound: &SignedTbs,
    status: &SignedTbs,
    carried: &[u8],
    now: i64,
) {
    assert_eq!(
        verify_tls_binding(
            tls,
            carried,
            Profile::PqPure,
            b"a leaf",
            now - 6 * MINUTE_MS
        )
        .unwrap_err(),
        BindingError::NotYetValid
    );
    assert_eq!(
        verify_status(
            status,
            bound,
            carried,
            Profile::PqPure,
            now + 66 * MINUTE_MS
        )
        .unwrap_err(),
        BindingError::StatusExpired
    );
    assert_eq!(
        verify_status(status, bound, carried, Profile::PqPure, now - 6 * MINUTE_MS).unwrap_err(),
        BindingError::StatusFutureDated
    );
}

/// The windows a verifier would refuse, never issued.
fn windows_a_verifier_refuses_are_not_issued(identity: &NodeKey, bound: &SignedTbs, now: i64) {
    // A window a verifier would refuse is not issued: backwards, longer than
    // 7 days for a binding or an hour for a statement, or negative.
    assert_eq!(
        tls_binding(identity, b"a leaf", now, now - 1).unwrap_err(),
        BindingError::ValidityWindow
    );
    assert_eq!(
        tls_binding(identity, b"a leaf", now, now + 7 * DAY_MS + 1).unwrap_err(),
        BindingError::ValidityWindow
    );
    assert_eq!(
        status_statement(identity, bound, now, now + 60 * MINUTE_MS + 1).unwrap_err(),
        BindingError::ValidityWindow
    );
    assert_eq!(
        tls_binding(identity, b"a leaf", -1, now).unwrap_err(),
        BindingError::ValidityWindow
    );
}

#[test]
fn a_signed_tbs_travels_as_exactly_tbs_and_signature() {
    let s = SignedTbs {
        tbs: vec![1],
        signature: vec![2],
    };
    assert_eq!(SignedTbs::from_value(&s.to_value()).unwrap(), s);
    let extra = cbor::Value::Map(vec![
        (cbor::Value::text("tbs"), cbor::Value::Bytes(vec![1])),
        (cbor::Value::text("signature"), cbor::Value::Bytes(vec![2])),
        (cbor::Value::text("more"), cbor::Value::Null),
    ]);
    assert_eq!(
        SignedTbs::from_value(&extra).unwrap_err(),
        BindingError::Malformed
    );
}
