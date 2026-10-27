//! A provider's sealed_required carries the KEM key it holds now in its signed
//! tbs, as the non-critical extension `seal.kem_key`
//! (DESIGN_E2E_SEALED_BY_DEFAULT section 3, release A0): an ERROR to a CALL
//! and a STREAM_ERROR to a STREAM_OPEN. The reader takes it there, knows it
//! (so it is not counted as ignored), and nowhere else. The signature covers
//! it: a refusal with the extension stripped does not verify.

use macula_rust::cbor::{self, Value};
use macula_rust::frame::{
    open_stream, sign_call, sign_provider_error, sign_provider_stream, sign_result,
    sign_sealed_required, sign_stream_open, sign_stream_sealed_required, verify_provider_stream,
    verify_reply, verify_request, wire_counters, ReplyType, RequestSpec, StreamFields, StreamMode,
    VerifiedRequest, SEAL_KEM_KEY_EXT,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;
use macula_rust::seal::Keyring;
use macula_rust::signed_object::Object;

struct Keys {
    caller: NodeKey,
    provider: NodeKey,
}

fn keys(profile: Profile) -> Keys {
    Keys {
        caller: NodeKey::generate(Purpose::Identity, profile).unwrap(),
        provider: NodeKey::generate(Purpose::Identity, profile).unwrap(),
    }
}

fn spec(k: &Keys, mode: Option<StreamMode>) -> RequestSpec {
    RequestSpec {
        request_id: [7; 16],
        realm: [3; 32],
        procedure: "acme/echo".to_string(),
        target: k.provider.key_id(),
        deadline: 1_789_000_005_000,
        payload: Value::text("hello"),
        sealed: None,
        mode,
        token: None,
        proofs: Vec::new(),
        source_route: None,
        retry_budget: None,
    }
}

/// A frame as it arrives: encoded and decoded under the decoding rule.
fn arrived(frame: &Value) -> Value {
    cbor::decode(&cbor::encode(frame).unwrap()).unwrap()
}

fn call(k: &Keys, profile: Profile) -> VerifiedRequest {
    verify_request(
        &arrived(&sign_call(&spec(k, None), &k.caller).unwrap()),
        profile,
    )
    .unwrap()
}

fn stream_open(k: &Keys, profile: Profile) -> VerifiedRequest {
    let open = sign_stream_open(&spec(k, Some(StreamMode::ClientStream)), &k.caller).unwrap();
    verify_request(&arrived(&open), profile).unwrap()
}

/// The KEM key a provider of `profile` holds now, as carried.
fn kem_key(profile: Profile) -> Vec<u8> {
    let keyring = Keyring::system(profile).unwrap();
    let key = keyring.current().public_key().carried().to_vec();
    key
}

fn ignored_seal_kem_key() -> u64 {
    wire_counters()
        .ext_ignored
        .get(SEAL_KEM_KEY_EXT)
        .copied()
        .unwrap_or(0)
}

/// `frame` with its signed object's tbs changed by `change` and the
/// signature left as it was.
fn tampered(
    frame: &Value,
    object_name: &str,
    change: impl Fn(Vec<(Value, Value)>) -> Vec<(Value, Value)>,
) -> Value {
    let mut object = Object::from_value(frame.get(object_name).unwrap()).unwrap();
    let Value::Map(fields) = cbor::decode(&object.tbs).unwrap() else {
        unreachable!()
    };
    object.tbs = cbor::encode(&Value::Map(change(fields))).unwrap();
    let Value::Map(pairs) = frame.clone() else {
        unreachable!()
    };
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| match k == Value::text(object_name) {
                true => (k, object.to_value()),
                false => (k, v),
            })
            .collect(),
    )
}

fn without_ext(fields: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
    fields
        .into_iter()
        .filter(|(k, _)| *k != Value::text("ext"))
        .collect()
}

#[test]
fn a_sealed_required_error_carries_the_provider_s_key_and_it_is_known() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let k = keys(profile);
        let request = call(&k, profile);
        let key = kem_key(profile);
        let before = ignored_seal_kem_key();
        let refusal = arrived(&sign_sealed_required(&request, &key, None, &k.provider).unwrap());
        let reply = verify_reply(&refusal, &request, profile).unwrap();
        assert_eq!(reply.frame_type, ReplyType::Error);
        assert_eq!(reply.code.as_deref(), Some("sealed_required"));
        assert_eq!(reply.kem_key, Some(key));
        assert_eq!(
            ignored_seal_kem_key(),
            before,
            "a known extension is not ignored"
        );
    }
}

#[test]
fn a_sealed_required_without_the_extension_carries_no_key() {
    let k = keys(Profile::PqPure);
    let request = call(&k, Profile::PqPure);
    let refusal =
        sign_provider_error(&request, "sealed_required", None, None, &k.provider).unwrap();
    let reply = verify_reply(&arrived(&refusal), &request, Profile::PqPure).unwrap();
    assert_eq!(reply.code.as_deref(), Some("sealed_required"));
    assert_eq!(reply.kem_key, None);
}

#[test]
fn a_stripped_extension_fails_as_a_tampered_reply_never_as_a_keyless_refusal() {
    let k = keys(Profile::PqPure);
    let request = call(&k, Profile::PqPure);
    let key = kem_key(Profile::PqPure);
    let refusal = arrived(&sign_sealed_required(&request, &key, None, &k.provider).unwrap());
    let stripped = tampered(&refusal, "reply", without_ext);
    assert!(verify_reply(&stripped, &request, Profile::PqPure).is_err());
}

#[test]
fn seal_kem_key_on_a_result_is_unknown_there_counted_and_carries_nothing() {
    let k = keys(Profile::PqPure);
    let request = call(&k, Profile::PqPure);
    let result = sign_result(&request, &Value::text("ok"), None, &k.provider).unwrap();
    let ext = Value::Map(vec![(
        Value::text(SEAL_KEM_KEY_EXT),
        Value::Map(vec![
            (Value::text("critical"), Value::Int(0)),
            (Value::text("value"), Value::Bytes(kem_key(Profile::PqPure))),
        ]),
    )]);
    // Re-signed with the extension added, so only where it sits is wrong.
    let object = Object::from_value(result.get("reply").unwrap()).unwrap();
    let Value::Map(mut fields) = cbor::decode(&object.tbs).unwrap() else {
        unreachable!()
    };
    fields.push((Value::text("ext"), ext));
    let resigned =
        macula_rust::signed_object::sign_object("MACULA-PQ-REPLY-V1", &fields, &k.provider)
            .unwrap();
    let Value::Map(pairs) = result else {
        unreachable!()
    };
    let with_ext = Value::Map(
        pairs
            .into_iter()
            .map(|(name, v)| match name == Value::text("reply") {
                true => (name, resigned.to_value()),
                false => (name, v),
            })
            .collect(),
    );
    let before = ignored_seal_kem_key();
    let reply = verify_reply(&arrived(&with_ext), &request, Profile::PqPure).unwrap();
    assert_eq!(reply.kem_key, None);
    assert!(ignored_seal_kem_key() > before);
}

#[test]
fn a_stream_open_refused_sealed_required_carries_the_provider_s_key() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let k = keys(profile);
        let open = stream_open(&k, profile);
        let state = open_stream(&open).unwrap();
        let key = kem_key(profile);
        let before = ignored_seal_kem_key();
        let refusal = arrived(
            &sign_stream_sealed_required("sealed opens only", &key, &open, &k.provider).unwrap(),
        );
        let (verified, _) = verify_provider_stream(&refusal, &state, profile).unwrap();
        assert_eq!(
            verified.fields,
            StreamFields::Error {
                seq: 0,
                code: "sealed_required".into(),
                message: "sealed opens only".into(),
            }
        );
        assert_eq!(verified.kem_key, Some(key));
        assert_eq!(ignored_seal_kem_key(), before);
    }
}

#[test]
fn a_stream_error_without_the_extension_carries_no_key_and_a_stripped_one_fails() {
    let k = keys(Profile::PqPure);
    let open = stream_open(&k, Profile::PqPure);
    let state = open_stream(&open).unwrap();
    let plain = StreamFields::Error {
        seq: 0,
        code: "sealed_required".into(),
        message: String::new(),
    };
    let keyless = arrived(&sign_provider_stream(&plain, &open, &k.provider).unwrap());
    let (verified, _) = verify_provider_stream(&keyless, &state, Profile::PqPure).unwrap();
    assert_eq!(verified.kem_key, None);

    let key = kem_key(Profile::PqPure);
    let refusal = arrived(&sign_stream_sealed_required("", &key, &open, &k.provider).unwrap());
    let stripped = tampered(&refusal, "stream", without_ext);
    assert!(verify_provider_stream(&stripped, &state, Profile::PqPure).is_err());
}
