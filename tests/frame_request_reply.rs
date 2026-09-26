//! Requests, replies and relay errors (D25): signed by their senders' identity
//! keys, verified by who they claim to be from and which request they answer,
//! and every build refused where macula refuses it.

use macula_rust::cbor::{self, Value};
use macula_rust::frame::{
    claimed_reply_ids, sign_call, sign_provider_error, sign_relay_error, sign_result,
    sign_stream_open, verify_relay_error, verify_reply, verify_request, FrameError, RelayErrorSpec,
    RelayErrorType, ReplyType, RequestSpec, RequestType, StreamMode, VerifiedRequest, MAX_PROOFS,
    MAX_PROOFS_BYTES,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

struct Keys {
    caller: NodeKey,
    provider: NodeKey,
    station: NodeKey,
}

fn keys(profile: Profile) -> Keys {
    Keys {
        caller: NodeKey::generate(Purpose::Identity, profile).unwrap(),
        provider: NodeKey::generate(Purpose::Identity, profile).unwrap(),
        station: NodeKey::generate(Purpose::Identity, profile).unwrap(),
    }
}

fn call_spec(keys: &Keys) -> RequestSpec {
    RequestSpec {
        request_id: [7; 16],
        realm: [3; 32],
        procedure: "acme/echo".to_string(),
        target: keys.provider.key_id(),
        deadline: 1_789_000_005_000,
        payload: Value::text("hello"),
        mode: None,
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

fn verified_call(keys: &Keys, spec: &RequestSpec, profile: Profile) -> VerifiedRequest {
    verify_request(&arrived(&sign_call(spec, &keys.caller).unwrap()), profile).unwrap()
}

#[test]
fn a_call_verifies_as_its_caller_signed_it() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let k = keys(profile);
        let mut spec = call_spec(&k);
        spec.token = Some(b"a token".to_vec());
        spec.source_route = Some(b"route".to_vec());
        spec.retry_budget = Some(3);
        let request = verified_call(&k, &spec, profile);
        assert_eq!(request.frame_type, RequestType::Call);
        assert_eq!(request.caller, k.caller.key_id());
        assert_eq!(request.key, k.caller.public_key());
        assert_eq!(request.request_id, spec.request_id);
        assert_eq!(request.realm, spec.realm);
        assert_eq!(request.procedure, "acme/echo");
        assert_eq!(request.target, spec.target);
        assert_eq!(request.deadline, spec.deadline);
        assert_eq!(request.payload, Value::text("hello"));
        assert_eq!(request.mode, None);
        assert_eq!(request.token.as_deref(), Some(&b"a token"[..]));
        assert_eq!(request.proofs, None);
    }
}

#[test]
fn a_stream_open_carries_its_mode() {
    let k = keys(Profile::PqPure);
    let mut spec = call_spec(&k);
    spec.mode = Some(StreamMode::Bidi);
    let request = verify_request(
        &arrived(&sign_stream_open(&spec, &k.caller).unwrap()),
        Profile::PqPure,
    )
    .unwrap();
    assert_eq!(request.frame_type, RequestType::StreamOpen);
    assert_eq!(request.mode, Some(StreamMode::Bidi));
    spec.mode = None;
    assert!(matches!(
        sign_stream_open(&spec, &k.caller),
        Err(FrameError::OutOfRange(_))
    ));
    spec.mode = Some(StreamMode::ServerStream);
    assert!(matches!(
        sign_call(&spec, &k.caller),
        Err(FrameError::OutOfRange(_))
    ));
}

#[test]
fn a_request_build_is_refused_in_macula_s_order() {
    let k = keys(Profile::PqPure);
    let connect = NodeKey::generate(Purpose::Connect, Profile::PqPure).unwrap();
    assert_eq!(
        sign_call(&call_spec(&k), &connect).unwrap_err(),
        FrameError::Unsignable
    );
    let mut long = call_spec(&k);
    long.procedure = "p".repeat(513);
    assert!(matches!(
        sign_call(&long, &k.caller),
        Err(FrameError::TextTooLong(_))
    ));
    let mut unsendable = call_spec(&k);
    unsendable.payload = Value::Float(f64::NAN);
    assert!(matches!(
        sign_call(&unsendable, &k.caller),
        Err(FrameError::Payload(_))
    ));
    let mut late = call_spec(&k);
    late.deadline = 1 << 53;
    assert!(matches!(
        sign_call(&late, &k.caller),
        Err(FrameError::OutOfRange(_))
    ));
}

#[test]
fn a_request_carries_its_proofs_within_their_bound() {
    let k = keys(Profile::PqPure);
    let mut spec = call_spec(&k);
    spec.proofs = vec![b"proof.one".to_vec(), b"proof.two".to_vec()];
    assert_eq!(
        verified_call(&k, &spec, Profile::PqPure).proofs,
        Some(spec.proofs.clone())
    );
    for (name, proofs) in [
        (
            "nine",
            (0..=MAX_PROOFS as u8).map(|i| vec![i]).collect::<Vec<_>>(),
        ),
        ("one repeated", vec![b"same".to_vec(), b"same".to_vec()]),
        ("over the bytes", vec![vec![0u8; MAX_PROOFS_BYTES + 1]]),
    ] {
        spec.proofs = proofs;
        assert_eq!(
            sign_call(&spec, &k.caller).unwrap_err(),
            FrameError::ProofsOutOfBound,
            "{name}"
        );
    }
}

/// The shared decoding rule vectors macula reads as a CALL's fields: where a
/// delegation chain's proofs are bounded.
#[test]
fn the_request_field_vectors_read_as_every_stack_reads_them() {
    let text = std::fs::read_to_string("tests/vectors/cbor/decoding_rule_v1.json").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut ran = 0;
    for e in doc["entries"].as_array().unwrap() {
        if e["via"].as_str() != Some("request_fields") {
            continue;
        }
        ran += 1;
        let fields = cbor::decode(&hex::decode(e["cbor"].as_str().unwrap()).unwrap()).unwrap();
        let accepted = macula_rust::frame::request_fields_accepted(&fields);
        assert_eq!(accepted, e["expect"] == "accept", "{}", e["name"]);
    }
    assert_eq!(ran, 5);
}

#[test]
fn a_request_altered_or_from_another_caller_is_refused() {
    let k = keys(Profile::PqPure);
    let frame = arrived(&sign_call(&call_spec(&k), &k.caller).unwrap());
    // One tbs byte changed.
    let altered = rewrite_object(&frame, "request", |object| {
        if let Some(Value::Bytes(tbs)) = object
            .iter_mut()
            .find(|(k, _)| *k == Value::text("tbs"))
            .map(|(_, v)| v)
        {
            let at = tbs.len() / 2;
            tbs[at] ^= 1;
        }
    });
    assert_eq!(
        verify_request(&altered, Profile::PqPure).unwrap_err(),
        FrameError::SignatureInvalid
    );
    // Another key carried in place of the caller's.
    let swapped = rewrite_object(&frame, "request", |object| {
        for (k2, v) in object.iter_mut() {
            if *k2 == Value::text("key") {
                *v = Value::Bytes(k.station.public_key());
            }
        }
    });
    assert_eq!(
        verify_request(&swapped, Profile::PqPure).unwrap_err(),
        FrameError::SignatureInvalid
    );
    // An extra field on the frame.
    let extra = match frame.clone() {
        Value::Map(mut pairs) => {
            pairs.push((Value::text("more"), Value::Int(1)));
            Value::Map(pairs)
        }
        _ => unreachable!(),
    };
    assert_eq!(
        verify_request(&extra, Profile::PqPure).unwrap_err(),
        FrameError::Malformed
    );
}

fn rewrite_object(frame: &Value, name: &str, mut f: impl FnMut(&mut Vec<(Value, Value)>)) -> Value {
    let Value::Map(mut pairs) = frame.clone() else {
        unreachable!()
    };
    for (k, v) in pairs.iter_mut() {
        if *k == Value::text(name) {
            if let Value::Map(object) = v {
                f(object);
            }
        }
    }
    Value::Map(pairs)
}

#[test]
fn a_reply_verifies_only_from_the_target_for_its_request() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let k = keys(profile);
        let request = verified_call(&k, &call_spec(&k), profile);

        let result =
            arrived(&sign_result(&request, &Value::text("pong"), None, &k.provider).unwrap());
        let reply = verify_reply(&result, &request, profile).unwrap();
        assert_eq!(reply.frame_type, ReplyType::Result);
        assert_eq!(reply.responded_by, k.provider.key_id());
        assert_eq!(reply.payload, Some(Value::text("pong")));

        let error = arrived(
            &sign_provider_error(
                &request,
                "handler_error",
                Some("refused"),
                Some(b"back".to_vec()),
                &k.provider,
            )
            .unwrap(),
        );
        let reply = verify_reply(&error, &request, profile).unwrap();
        assert_eq!(reply.frame_type, ReplyType::Error);
        assert_eq!(reply.code.as_deref(), Some("handler_error"));
        assert_eq!(reply.detail.as_deref(), Some("refused"));

        // Signed by anyone but the target: not signable, and not accepted.
        assert_eq!(
            sign_result(&request, &Value::Null, None, &k.station).unwrap_err(),
            FrameError::Unsignable
        );
        let mut other_target = call_spec(&k);
        other_target.target = k.station.key_id();
        let other_request = verified_call(&k, &other_target, profile);
        let from_station =
            arrived(&sign_result(&other_request, &Value::Null, None, &k.station).unwrap());
        assert_eq!(
            verify_reply(&from_station, &request, profile).unwrap_err(),
            FrameError::RequestMismatch
        );
        let mut same_ids = request.clone();
        same_ids.target = k.station.key_id();
        let as_other = arrived(&sign_result(&same_ids, &Value::Null, None, &k.station).unwrap());
        assert_eq!(
            verify_reply(&as_other, &request, profile).unwrap_err(),
            FrameError::NotTheTarget
        );

        assert_eq!(
            claimed_reply_ids(&result).unwrap(),
            (request.request_id, request.request_hash)
        );
    }
}

#[test]
fn a_provider_error_s_text_is_bounded() {
    let k = keys(Profile::PqPure);
    let request = verified_call(&k, &call_spec(&k), Profile::PqPure);
    assert!(matches!(
        sign_provider_error(&request, &"c".repeat(65), None, None, &k.provider),
        Err(FrameError::TextTooLong(_))
    ));
    assert!(matches!(
        sign_provider_error(&request, "code", Some(&"d".repeat(257)), None, &k.provider),
        Err(FrameError::TextTooLong(_))
    ));
}

#[test]
fn a_relay_error_verifies_only_from_the_connection_s_station() {
    let k = keys(Profile::PqPure);
    let request = verified_call(&k, &call_spec(&k), Profile::PqPure);
    let spec = RelayErrorSpec {
        frame_type: RelayErrorType::Error,
        request: request.clone(),
        code: "unknown_next_peer".to_string(),
        offending_hop: Some([5; 32]),
        source_route_partial: None,
    };
    let frame = arrived(&sign_relay_error(&spec, &k.station).unwrap());
    let relay = verify_relay_error(&frame, &request, Profile::PqPure, &k.station.key_id()).unwrap();
    assert_eq!(relay.reported_by, k.station.key_id());
    assert_eq!(relay.code, "unknown_next_peer");
    assert_eq!(relay.offending_hop, Some([5; 32]));
    assert_eq!(
        verify_relay_error(&frame, &request, Profile::PqPure, &[1; 32]).unwrap_err(),
        FrameError::NotTheConnection
    );
    assert_eq!(
        claimed_reply_ids(&frame).unwrap(),
        (request.request_id, request.request_hash)
    );
    let mut outside = spec.clone();
    outside.code = "handler_error".to_string();
    assert_eq!(
        sign_relay_error(&outside, &k.station).unwrap_err(),
        FrameError::RelayCodeOutsideItsSet
    );
}
