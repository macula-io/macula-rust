//! macula's sealed_required refusals naming the provider's KEM key (release
//! A0, DESIGN_E2E_SEALED_BY_DEFAULT section 3), read as this crate reads a
//! refusal: per profile, a clear CALL and the ERROR answering it, a clear
//! STREAM_OPEN and the STREAM_ERROR answering it, both carrying the key in
//! the signed `seal.kem_key` extension. Copied unchanged from macula
//! f1aea93b's `test/vectors/e2e_seal_v1_refusals.json` (macula#136).

use macula_rust::cbor;
use macula_rust::frame::{
    open_stream, verify_provider_stream, verify_reply, verify_request, ReplyType, StreamFields,
};
use macula_rust::profile::Profile;
use macula_rust::seal::key_id;
use serde_json::Value as Json;

fn vectors() -> Json {
    let text = std::fs::read_to_string("tests/vectors/seal/e2e_seal_v1_refusals.json").unwrap();
    serde_json::from_str(&text).unwrap()
}

fn hex_of(v: &Json, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().unwrap()).unwrap()
}

/// A frame as written on a stream, `<Len:32/big, CBOR>`, decoded.
fn framed(v: &Json, name: &str) -> cbor::Value {
    let bytes = hex_of(v, name);
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 4 + length, "{name}: one whole frame");
    cbor::decode(&bytes[4..]).unwrap()
}

fn profiles() -> [(&'static str, Profile); 2] {
    [
        ("pq_pure", Profile::PqPure),
        ("pq_hybrid", Profile::PqHybrid),
    ]
}

#[test]
fn macula_s_call_refusal_names_the_provider_s_key() {
    let all = vectors();
    assert_eq!(all["profiles"]["pq_pure"]["extension"], "seal.kem_key");
    for (name, profile) in profiles() {
        let v = &all["profiles"][name];
        let key = hex_of(v, "kem_key");
        assert_eq!(
            key.len() as u64,
            v["kem_key_size"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(key_id(&key).to_vec(), hex_of(v, "kem_key_id"), "{name}");

        let request = verify_request(&framed(v, "call"), profile).unwrap();
        assert_eq!(
            request.target.to_vec(),
            hex_of(v, "provider_node_id"),
            "{name}"
        );
        let reply = verify_reply(&framed(v, "refusal"), &request, profile).unwrap();
        assert_eq!(reply.frame_type, ReplyType::Error, "{name}");
        assert_eq!(reply.code.as_deref(), Some("sealed_required"), "{name}");
        assert_eq!(reply.kem_key, Some(key), "{name}");
    }
}

#[test]
fn macula_s_stream_refusal_names_the_provider_s_key() {
    let all = vectors();
    for (name, profile) in profiles() {
        let v = &all["profiles"][name];
        let open = verify_request(&framed(v, "stream_open"), profile).unwrap();
        assert_eq!(
            open.target.to_vec(),
            hex_of(v, "provider_node_id"),
            "{name}"
        );
        let state = open_stream(&open).unwrap();
        let (verified, _) =
            verify_provider_stream(&framed(v, "stream_refusal"), &state, profile).unwrap();
        assert!(
            matches!(
                &verified.fields,
                StreamFields::Error { seq: 0, code, .. } if code == "sealed_required"
            ),
            "{name}: {:?}",
            verified.fields
        );
        assert_eq!(verified.kem_key, Some(hex_of(v, "kem_key")), "{name}");
    }
}
