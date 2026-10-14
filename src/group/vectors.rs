//! Sealed groups against macula's vectors (tests/vectors/group/
//! e2e_seal_v1_group_keys.json, macula 13.2, the file macula-go v0.27.0-rc.3
//! carries byte for byte): the CALL payloads to `group_keys_v1` exactly, the
//! RESULT read and re-encoded to the same bytes, the org's group_keys grant
//! reaching the verdict macula's own `macula_ucan:authorize/3` reaches on it,
//! and the refusal names the closed set.

use serde_json::Value as Json;

use super::*;
use crate::profile::Profile;
use crate::ucan::{authorize, Context, Policy as UcanPolicy, Request};

fn vectors() -> Json {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/group/e2e_seal_v1_group_keys.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn b(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn id32(v: &Json) -> [u8; 32] {
    b(v).try_into().unwrap()
}

fn id8(v: &Json) -> [u8; ID_SIZE] {
    b(v).try_into().unwrap()
}

fn profile_of(name: &str) -> Profile {
    match name {
        "pq_pure" => Profile::PqPure,
        "pq_hybrid" => Profile::PqHybrid,
        other => panic!("no profile {other}"),
    }
}

/// Both CALL payloads are macula's bytes: the current-epoch pull and the
/// by-id pull, which differ only in what `epoch` carries.
#[test]
fn the_call_payloads_reach_macula_s_bytes() {
    let v = vectors();
    let p = &v["payloads"];
    let prefix = p["call_current"]["prefix"].as_str().unwrap();
    assert_eq!(
        crate::cbor::encode(&current_request(prefix)).unwrap(),
        b(&p["call_current"]["cbor"]),
        "the current-epoch pull"
    );
    assert_eq!(
        crate::cbor::encode(&by_id_request(prefix, &id8(&p["call_by_id"]["epoch_id"]))).unwrap(),
        b(&p["call_by_id"]["cbor"]),
        "the by-id pull"
    );
    // The group's org is the prefix's second segment, and the procedure the
    // pull goes to is that org's.
    assert_eq!(org_of(prefix), Ok("acme"));
    assert_eq!(procedure("acme"), "acme/group_keys_v1");
}

/// A distributor's RESULT reads as the protocol says, and re-encodes to
/// exactly the bytes it arrived as. A prefix the reply does not echo refuses
/// the whole of it.
#[test]
fn the_result_reads_and_re_encodes_byte_for_byte() {
    let v = vectors();
    let r = &v["payloads"]["result"];
    let prefix = r["prefix"].as_str().unwrap();
    let bytes = b(&r["cbor"]);
    let value = crate::cbor::decode(&bytes).unwrap();
    let reply = parse_reply(prefix, &value).unwrap();

    assert_eq!(
        reply.policy,
        Policy::parse(r["policy"].as_str().unwrap()).unwrap()
    );
    let epochs = r["epochs"].as_array().unwrap();
    assert_eq!(reply.epochs.len(), epochs.len());
    for (parsed, expected) in reply.epochs.iter().zip(epochs) {
        assert_eq!(parsed.id, id8(&expected["id"]));
        assert_eq!(parsed.key(), b(&expected["key"]).as_slice());
        assert_eq!(parsed.issued_at, expected["issued_at"].as_i64().unwrap());
        assert_eq!(
            parsed.publish_until,
            expected["publish_until"].as_i64().unwrap()
        );
        assert_eq!(
            parsed.accept_until,
            expected["accept_until"].as_i64().unwrap()
        );
    }

    assert_eq!(
        crate::cbor::encode(&reply_value(&reply)).unwrap(),
        bytes,
        "the reply re-encodes to macula's bytes"
    );
    assert!(matches!(
        parse_reply("io.macula/other/chat", &value),
        Err(GroupError::MalformedReply)
    ));
}

/// Every org-grant case gives macula's own verdict: six cases, in both
/// profiles, all judged under the distributor's realm-member policy with the
/// grant as the token.
#[test]
fn every_org_grant_case_reaches_macula_s_verdict() {
    let v = vectors();
    let mut seen = 0;
    for (name, profile_cases) in v["profiles"].as_object().unwrap() {
        let profile = profile_of(name);
        for case in profile_cases["cases"].as_array().unwrap() {
            let policy = &case["policy"];
            assert_eq!(
                policy["kind"].as_str(),
                Some("realm_member_required"),
                "{}",
                case["name"]
            );
            let policy = UcanPolicy::RealmMemberRequired {
                key_id: id32(&policy["key_id"]),
                can: policy["can"].as_str().unwrap().into(),
            };
            let c = &case["context"];
            let ctx = Context {
                caller: id32(&c["caller"]),
                profile,
                now: c["now"].as_i64().unwrap(),
                request: Some(Request {
                    realm: id32(&c["realm"]),
                    procedure: c["procedure"].as_str().unwrap().into(),
                }),
                proofs: Context::keyed_proofs(&[]),
            };
            let token = case["token"].as_str().unwrap().as_bytes();
            let verdict = match authorize(token, &policy, &ctx) {
                Ok(_) => "ok".to_string(),
                Err(refusal) => refusal.name().to_string(),
            };
            assert_eq!(
                verdict,
                case["verdict"].as_str().unwrap(),
                "{name} {}",
                case["name"]
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 12, "six cases in each of two profiles");
}

/// The refusals a distributor names are exactly the ones this crate maps, so
/// a refusal it sends is never read as a failure of another kind.
#[test]
fn the_refusals_are_the_closed_set() {
    let v = vectors();
    let refusals = v["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 5, "the distributor's own five");
    for r in refusals {
        let name = r.as_str().unwrap();
        let reason = Reason::from_refusal(name).unwrap_or_else(|| panic!("no reason {name}"));
        assert_eq!(reason.name(), name.replace("unknown_group", "no_distributor"));
    }
}
