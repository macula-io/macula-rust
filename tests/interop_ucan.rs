//! UCANs this SDK mints, for macula's macula_ucan to authorize: the reverse
//! of the vectors, which macula mints and tests/ucan.rs checks.
//! scripts/interop/ucan.sh runs the test here, which writes the cases as
//! JSON to MACULA_RUST_UCAN_CASES, each with the policy, context and verdict
//! macula must reach, then authorizes them with erlang_ucan.escript.

use std::time::SystemTime;

use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;
use macula_rust::ucan::{create, proof_id, Capability, Options, MAX_LIFETIME};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_790_000_000;

#[test]
#[ignore = "scripts/interop/ucan.sh runs it, then authorizes its tokens with macula"]
fn tokens_for_macula_to_authorize() {
    let out = std::env::var("MACULA_RUST_UCAN_CASES").expect("MACULA_RUST_UCAN_CASES is not set");
    // Minted for NOW, whatever the clock says: create checks its window
    // against the clock, so the furthest exp is taken from it.
    let clock = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(clock >= NOW, "the clock is before the cases' now");
    let realm = hex::encode(Sha256::digest(b"io.macula"));
    let mut cases = cases_for("pq_pure", Profile::PqPure, &realm);
    cases.extend(cases_for("pq_hybrid", Profile::PqHybrid, &realm));
    std::fs::write(
        &out,
        serde_json::to_string_pretty(&Value::Array(cases)).unwrap(),
    )
    .unwrap();
}

fn node(k: &NodeKey) -> [u8; 32] {
    k.node_id().unwrap()
}

/// A token from `issuer` for `audience`, invoking `with`, as text.
fn mint(issuer: &NodeKey, audience: &NodeKey, with: &str, o: Options) -> String {
    let caps = [Capability {
        with: with.into(),
        can: "invoke".into(),
    }];
    String::from_utf8(create(issuer, &node(audience), &caps, &o).unwrap()).unwrap()
}

fn until(exp: i64) -> Options {
    Options {
        exp,
        ..Options::default()
    }
}

/// The cases of one profile, each with the verdict macula must reach.
fn cases_for(name: &str, profile: Profile, realm: &str) -> Vec<Value> {
    let key = || NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap();
    let (root, alice, bob) = (key(), key(), key());
    let to_alice = mint(&root, &alice, "mri:org:io.macula/acme", until(NOW + 3600));
    let chained = Options {
        exp: NOW + 60,
        nbf: Some(NOW - 60),
        nnc: Some("n1".into()),
        prf: Some(vec![proof_id(to_alice.as_bytes())]),
        ..Options::default()
    };
    let to_bob = mint(&alice, &bob, "mri:proc:io.macula/acme/count_v1", chained);
    let expired = mint(&root, &alice, "mri:realm:io.macula", until(NOW));
    // The furthest exp this side mints, at NOW: macula refuses a second
    // more, which this side would not mint.
    let furthest = mint(
        &root,
        &alice,
        "mri:realm:io.macula",
        until(NOW + MAX_LIFETIME),
    );
    let case = |case: &str, token: &str, proofs: &[&str], caller: &NodeKey, verdict: &str| {
        json!({
            "name": case,
            "profile": name,
            "token": token,
            "proofs": proofs,
            "issuer": hex::encode(node(&root)),
            "caller": hex::encode(node(caller)),
            "now": NOW,
            "realm": realm,
            "procedure": "acme/count_v1",
            "verdict": verdict,
        })
    };
    vec![
        case("root token", &to_alice, &[], &alice, "ok"),
        case("delegated chain", &to_bob, &[&to_alice], &bob, "ok"),
        case(
            "presented by another node",
            &to_alice,
            &[],
            &bob,
            "not_the_audience",
        ),
        case(
            "chain without its proof",
            &to_bob,
            &[],
            &bob,
            "missing_proof",
        ),
        case("expired", &expired, &[], &alice, "expired"),
        case("exp at the max lifetime", &furthest, &[], &alice, "ok"),
    ]
}
