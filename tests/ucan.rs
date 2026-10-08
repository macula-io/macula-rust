//! UCAN against macula's own vectors (tests/vectors/ucan, copied unchanged
//! from macula v13.6.0): every verdict, proof id, did:key key and narrowing
//! is macula's. Then tokens this crate mints, by round trip: authorized
//! alone and through a chain, and refused where macula refuses them.

use std::collections::HashMap;

use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;
use macula_rust::ucan::{
    self, authorize, carried_key, covers, create, proof_id, Capability, Context, CreateError,
    Options, Policy, Refusal, Request, MAX_LIFETIME,
};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/ucan/ucan_v1.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors parse")
}

fn id32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().expect("hex text"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn profile_of(name: &str) -> Profile {
    match name {
        "pq_pure" => Profile::PqPure,
        "pq_hybrid" => Profile::PqHybrid,
        other => panic!("no profile {other}"),
    }
}

fn policy_of(p: &Value) -> Policy {
    match p["kind"].as_str() {
        Some("ucan_required") => Policy::UcanRequired {
            issuer: id32(&p["issuer"]),
        },
        Some("realm_member_required") => Policy::RealmMemberRequired {
            key_id: id32(&p["key_id"]),
            can: p["can"].as_str().expect("a can").into(),
        },
        other => panic!("no policy {other:?}"),
    }
}

fn verdict_of(result: Result<serde_json::Map<String, Value>, Refusal>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(refusal) => refusal.name().into(),
    }
}

#[test]
fn every_case_reaches_macula_s_verdict() {
    let v = vectors();
    let mut seen = 0;
    for (name, profile_cases) in v["profiles"].as_object().expect("profiles") {
        let profile = profile_of(name);
        for case in profile_cases["cases"].as_array().expect("cases") {
            let c = &case["context"];
            let request = c.get("procedure").map(|procedure| Request {
                realm: id32(&c["realm"]),
                procedure: procedure.as_str().expect("a procedure").into(),
            });
            let proofs: Vec<Vec<u8>> = case["proofs"]
                .as_array()
                .expect("proofs")
                .iter()
                .map(|p| p.as_str().expect("a proof").as_bytes().to_vec())
                .collect();
            let ctx = Context {
                caller: id32(&c["caller"]),
                profile,
                now: c["now"].as_i64().expect("now"),
                request,
                proofs: Context::keyed_proofs(&proofs),
            };
            let token = case["token"].as_str().expect("a token").as_bytes();
            let got = verdict_of(authorize(token, &policy_of(&case["policy"]), &ctx));
            assert_eq!(got, case["verdict"], "{name} {}: {got}", case["name"]);
            seen += 1;
        }
    }
    assert!(seen >= 68, "every case of both profiles: {seen}");
}

#[test]
fn every_refusal_appears_in_both_profiles() {
    let v = vectors();
    let verdicts = |name: &str| {
        let mut all: Vec<String> = v["profiles"][name]["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|c| c["verdict"].as_str().expect("a verdict").to_string())
            .collect();
        all.sort();
        all.dedup();
        all
    };
    assert_eq!(verdicts("pq_pure"), verdicts("pq_hybrid"));
    assert_eq!(verdicts("pq_pure").len(), 19, "ok and the 18 refusals");
}

#[test]
fn proof_ids_are_macula_s() {
    let v = vectors();
    for (name, profile_cases) in v["profiles"].as_object().expect("profiles") {
        for entry in profile_cases["proof_ids"].as_array().expect("proof_ids") {
            let token = entry["token"].as_str().expect("a token").as_bytes();
            assert_eq!(proof_id(token), entry["proof_id"], "{name}");
        }
    }
}

/// The key's node_id, when the vector names one, is the one its carried key
/// derives.
fn assert_node_id(key: &Value, carried: &[u8], profile: Profile, label: &str) {
    let Some(node_id) = key.get("node_id") else {
        return;
    };
    let ours = macula_rust::node_key::node_id_of(carried, profile);
    assert_eq!(hex::encode(ours), *node_id, "{label}");
}

#[test]
fn every_did_key_decodes_to_macula_s_key() {
    let v = vectors();
    for (name, profile_cases) in v["profiles"].as_object().expect("profiles") {
        let profile = profile_of(name);
        for (who, key) in profile_cases["keys"].as_object().expect("keys") {
            let did = key["did_key"].as_str().expect("a did:key");
            let carried = carried_key(did, profile).expect("a well-formed key");
            assert_eq!(ucan::did_key(&carried, profile), did, "{name} {who}");
            let key_id = macula_rust::node_key::key_id_of(&carried, profile);
            assert_eq!(hex::encode(key_id), key["key_id"], "{name} {who}");
            assert_node_id(key, &carried, profile, &format!("{name} {who}"));
            let other = match profile {
                Profile::PqPure => Profile::PqHybrid,
                Profile::PqHybrid => Profile::PqPure,
            };
            assert_eq!(
                carried_key(did, other),
                Err(Refusal::Malformed),
                "{name} {who}"
            );
        }
    }
}

#[test]
fn narrowing_is_macula_s() {
    let v = vectors();
    let table = v["covers"].as_array().expect("covers");
    assert!(!table.is_empty());
    for entry in table {
        let (parent, child) = (
            entry["parent"].as_str().expect("parent"),
            entry["child"].as_str().expect("child"),
        );
        assert_eq!(
            covers(parent, child),
            entry["covers"],
            "{parent} covers {child}"
        );
    }
}

// ---- tokens this crate mints ----

const REALM: &str = "io.macula";
const PROCEDURE: &str = "acme/count_v1";

fn realm_id() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(REALM.as_bytes()).into()
}

fn identity(profile: Profile) -> NodeKey {
    NodeKey::generate(Purpose::Identity, profile).expect("a key")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn cap(with: &str, can: &str) -> Capability {
    Capability {
        with: with.into(),
        can: can.into(),
    }
}

fn until(exp: i64) -> Options {
    Options {
        exp,
        ..Options::default()
    }
}

fn context(caller: &NodeKey, proofs: &[Vec<u8>]) -> Context {
    Context {
        caller: caller.node_id().unwrap(),
        profile: caller.profile(),
        now: now(),
        request: Some(Request {
            realm: realm_id(),
            procedure: PROCEDURE.into(),
        }),
        proofs: Context::keyed_proofs(proofs),
    }
}

#[test]
fn a_minted_token_and_chain_authorize_as_macula_s_do() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let (root, alice, bob) = (identity(profile), identity(profile), identity(profile));
        let issuer = Policy::UcanRequired {
            issuer: root.node_id().unwrap(),
        };
        let org = cap(&format!("mri:org:{REALM}/acme"), "invoke");
        let direct = create(
            &root,
            &alice.node_id().unwrap(),
            std::slice::from_ref(&org),
            &until(now() + 60),
        )
        .unwrap();
        assert!(
            authorize(&direct, &issuer, &context(&alice, &[])).is_ok(),
            "{profile:?}"
        );
        assert_eq!(
            authorize(&direct, &issuer, &context(&bob, &[])).err(),
            Some(Refusal::NotTheAudience)
        );
        let narrower = cap(&format!("mri:proc:{REALM}/{PROCEDURE}"), "invoke");
        let delegated = create(
            &alice,
            &bob.node_id().unwrap(),
            &[narrower],
            &Options {
                exp: now() + 60,
                prf: Some(vec![proof_id(&direct)]),
                ..Options::default()
            },
        )
        .unwrap();
        assert!(
            authorize(
                &delegated,
                &issuer,
                &context(&bob, std::slice::from_ref(&direct))
            )
            .is_ok(),
            "{profile:?}"
        );
        assert_eq!(
            authorize(&delegated, &issuer, &context(&bob, &[])).err(),
            Some(Refusal::MissingProof)
        );
        let stray = create(&root, &bob.node_id().unwrap(), &[org], &until(now() + 60)).unwrap();
        assert_eq!(
            authorize(&delegated, &issuer, &context(&bob, &[direct, stray])).err(),
            Some(Refusal::UnreferencedProof)
        );
    }
}

#[test]
fn a_minted_realm_member_token_answers_by_its_can() {
    let profile = Profile::PqPure;
    let (realm, alice) = (identity(profile), identity(profile));
    let member = Policy::RealmMemberRequired {
        key_id: macula_rust::node_key::key_id_of(&realm.public_key(), profile),
        can: "invoke".into(),
    };
    let caps = [
        cap(&format!("mri:realm:{REALM}"), "read"),
        cap(&format!("mri:realm:{REALM}"), "invoke"),
    ];
    let token = create(&realm, &alice.node_id().unwrap(), &caps, &until(now() + 60)).unwrap();
    assert!(authorize(&token, &member, &context(&alice, &[])).is_ok());
    let reader = create(
        &realm,
        &alice.node_id().unwrap(),
        &caps[..1],
        &until(now() + 60),
    )
    .unwrap();
    assert_eq!(
        authorize(&reader, &member, &context(&alice, &[])).err(),
        Some(Refusal::MissingCapability)
    );
}

#[test]
fn a_window_no_verifier_accepts_is_not_minted() {
    let root = identity(Profile::PqPure);
    let audience = [7; 32];
    let caps = [cap(&format!("mri:realm:{REALM}"), "invoke")];
    let in_ms = (now() + 60) * 1000;
    match create(&root, &audience, &caps, &until(in_ms)) {
        Err(CreateError::ExpBeyondMaxLifetime { exp, max, .. }) => {
            assert_eq!(exp, in_ms);
            assert!(max <= now() + MAX_LIFETIME);
        }
        other => panic!("an exp in milliseconds: {other:?}"),
    }
    let shut = Options {
        exp: now() + 60,
        nbf: Some(now() + 60),
        ..Options::default()
    };
    assert!(matches!(
        create(&root, &audience, &caps, &shut),
        Err(CreateError::WindowNeverOpens { .. })
    ));
    let connect = NodeKey::generate(Purpose::Connect, Profile::PqPure).unwrap();
    assert_eq!(
        create(&connect, &audience, &caps, &until(now() + 60)),
        Err(CreateError::NotAnIdentityKey(Purpose::Connect))
    );
}

#[test]
fn a_minted_token_carries_its_optional_claims() {
    let (root, alice) = (identity(Profile::PqPure), identity(Profile::PqPure));
    let mut fct = serde_json::Map::new();
    fct.insert("note".into(), Value::String("for the count".into()));
    let o = Options {
        exp: now() + 60,
        nbf: Some(now() - 1),
        nnc: Some("n-1".into()),
        fct: Some(fct.clone()),
        prf: None,
    };
    let caps = [cap(&format!("mri:realm:{REALM}"), "invoke")];
    let token = create(&root, &alice.node_id().unwrap(), &caps, &o).unwrap();
    let issuer = Policy::UcanRequired {
        issuer: root.node_id().unwrap(),
    };
    let claims = authorize(&token, &issuer, &context(&alice, &[])).unwrap();
    assert_eq!(claims["nnc"], "n-1");
    assert_eq!(claims["fct"], Value::Object(fct));
    let alone = Context {
        request: None,
        proofs: HashMap::new(),
        ..context(&alice, &[])
    };
    assert!(authorize(&token, &issuer, &alone).is_ok());
}
