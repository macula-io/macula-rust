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
    let mut cases = Vec::new();
    for (name, profile) in [
        ("pq_pure", Profile::PqPure),
        ("pq_hybrid", Profile::PqHybrid),
    ] {
        let key = || NodeKey::generate_identity(profile, PUZZLE_DIFFICULTY).unwrap();
        let node = |k: &NodeKey| k.node_id().unwrap();
        let (root, alice, bob) = (key(), key(), key());
        let mint = |issuer: &NodeKey, audience: &NodeKey, with: &str, o: Options| {
            let caps = [Capability {
                with: with.into(),
                can: "invoke".into(),
            }];
            String::from_utf8(create(issuer, &node(audience), &caps, &o).unwrap()).unwrap()
        };
        let until = |exp| Options {
            exp,
            ..Options::default()
        };
        let to_alice = mint(&root, &alice, "mri:org:io.macula/acme", until(NOW + 3600));
        let to_bob = mint(
            &alice,
            &bob,
            "mri:proc:io.macula/acme/count_v1",
            Options {
                exp: NOW + 60,
                nbf: Some(NOW - 60),
                nnc: Some("n1".into()),
                prf: Some(vec![proof_id(to_alice.as_bytes())]),
                ..Options::default()
            },
        );
        let mut add =
            |case: &str, token: &str, proofs: &[&str], caller: &NodeKey, verdict: &str| {
                cases.push(json!({
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
                }));
            };
        add("root token", &to_alice, &[], &alice, "ok");
        add("delegated chain", &to_bob, &[&to_alice], &bob, "ok");
        add(
            "presented by another node",
            &to_alice,
            &[],
            &bob,
            "not_the_audience",
        );
        add(
            "chain without its proof",
            &to_bob,
            &[],
            &bob,
            "missing_proof",
        );
        let expired = mint(&root, &alice, "mri:realm:io.macula", until(NOW));
        add("expired", &expired, &[], &alice, "expired");
        // The furthest exp this side mints, at NOW: macula refuses a second
        // more, which this side would not mint.
        let furthest = mint(
            &root,
            &alice,
            "mri:realm:io.macula",
            until(NOW + MAX_LIFETIME),
        );
        add("exp at the max lifetime", &furthest, &[], &alice, "ok");
    }
    std::fs::write(
        &out,
        serde_json::to_string_pretty(&Value::Array(cases)).unwrap(),
    )
    .unwrap();
}
