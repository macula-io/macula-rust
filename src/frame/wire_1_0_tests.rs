//! The wire 1.0 frame vectors (macula#97, frames.json): one valid frame of
//! every one of the 47 frame types. Every one reads as an envelope; each type
//! this crate reads, it reads through its own table, the signed object in it
//! in its carried or held form (its signature, clock and request context are
//! the verify, enums and tbs classes').

use super::*;

/// The shape of a frame of `frame_type` that this crate reads, through the
/// table its reader uses; `None` for a type it never reads.
fn read_by_its_table(frame_type: &str, frame: &Value) -> Option<bool> {
    let carried = |object, routes: &[(&str, Rule)], types| {
        received_frame(frame, object, Rule::CarriedObject, routes, types).is_some()
    };
    let read = match frame_type {
        "call" | "stream_open" => verify_request(frame, profile_of(frame)?).is_ok(),
        "result" | "error" if frame.get("relay_error").is_some() => carried(
            "relay_error",
            reply::RELAY_ERROR_ROUTES,
            &["error", "stream_error"],
        ),
        "result" | "error" => carried("reply", reply::REPLY_ROUTES, &["result", "error"]),
        "publish" => carried("publication", &[], &["publish"]),
        "event" => carried(
            "publication",
            &[("delivered_via", Rule::EnumText)],
            &["event"],
        ),
        "stream_data" | "stream_end" | "stream_error" | "stream_reply"
            if frame.get("caller_stream").is_some() =>
        {
            received_frame(
                frame,
                "caller_stream",
                Rule::HeldObject,
                &[],
                &["stream_data", "stream_end", "stream_error"],
            )
            .is_some()
        }
        "stream_data" | "stream_end" | "stream_error" | "stream_reply" => received_frame(
            frame,
            "stream",
            Rule::StreamObject,
            &[],
            &["stream_data", "stream_end", "stream_error", "stream_reply"],
        )
        .is_some(),
        "register_ack" => read_register_ack(frame).is_ok(),
        t if is_control_frame(t) => read_control(frame).is_ok(),
        _ => return None,
    };
    Some(read)
}

/// The profile a request was signed in, from its alg.
fn profile_of(frame: &Value) -> Option<crate::profile::Profile> {
    let object = crate::signed_object::Object::from_value(frame.get("request")?).ok()?;
    let tbs = cbor::decode(&object.tbs).ok()?;
    match tbs.get("alg") {
        Some(Value::Text(alg)) if alg == crate::profile::Profile::PqPure.sig_alg() => {
            Some(crate::profile::Profile::PqPure)
        }
        Some(Value::Text(_)) => Some(crate::profile::Profile::PqHybrid),
        _ => None,
    }
}

#[test]
fn the_wire_1_0_frame_vectors() {
    let file = crate::wire_vectors::load("frames");
    let mut read_here = 0;
    for c in &file.cases {
        let v = cbor::decode(&c.hex("frame")).unwrap();
        let read = read_envelope(&v)
            .map(|envelope| read_by_its_table(&envelope.frame_type, &envelope.frame));
        let accepted = match read {
            Ok(Some(read)) => {
                read_here += 1;
                read
            }
            Ok(None) => true,
            Err(_) => false,
        };
        let want = c.outcome() == "accept";
        assert_eq!(accepted, want, "{}", c.id);
        assert!(want || c.reason() == "malformed_frame", "{}", c.id);
    }
    // 17 types this crate reads, and 16 REGISTER_ACKs past the envelope (its
    // realm_31 case is refused by the envelope's own realm rule).
    assert_eq!(read_here, 33, "the frames of the types this crate reads");
}

/// An EVENT read, and its delivered_via as the case says it reads.
fn read_event(
    c: &crate::wire_vectors::Case,
    v: &Value,
    profile: crate::profile::Profile,
) -> Result<(), FrameError> {
    verify_publication(v, profile, c.int("now_ms").unwrap())?;
    assert_eq!(delivered_via(v), c.expect_text("value"), "{}", c.id);
    Ok(())
}

/// The enum case's frame read by its reader, with its context.
fn read_enum_frame(c: &crate::wire_vectors::Case, field: &str) -> Result<(), FrameError> {
    let profile = crate::profile::Profile::parse(&c.profile).unwrap();
    let v = cbor::decode(&c.hex("frame")).unwrap();
    match field {
        "delivered_via" => read_event(c, &v, profile),
        "mode" => verify_request(&v, profile).map(|_| ()),
        "code" => {
            let request = verify_request(&context_frame(c, 0), profile).unwrap();
            let station = crate::wire_vectors::key_id(&c.profile, "station_identity");
            verify_relay_error(&v, &request, profile, &station).map(|_| ())
        }
        "encoding" | "role" => {
            let open = verify_request(&context_frame(c, 0), profile).unwrap();
            let state = open_stream(&open).unwrap();
            verify_caller_stream(&v, &state, profile).map(|_| ())
        }
        other => panic!("{}: no reader for {other}", c.id),
    }
}

/// A REGISTER_ACK enum case: an unknown kind ignores the ack, an unknown
/// reason reads as `refused`, each counted under its field.
fn register_ack_enum(c: &crate::wire_vectors::Case, field: &str) {
    let fallbacks = |f: &str| wire_counters().enum_fallback.get(f).copied().unwrap_or(0);
    let before = fallbacks(field);
    let ack = read_register_ack(&cbor::decode(&c.hex("frame")).unwrap()).unwrap();
    match c.outcome() {
        "ignore" => assert_eq!(ack, None, "{}", c.id),
        _ => assert_eq!(
            ack.unwrap().refusal.as_deref(),
            Some(c.expect_text("value")),
            "{}",
            c.id
        ),
    }
    let counted = fallbacks(field) > before;
    assert_eq!(
        counted,
        c.expect_text("count") == "wire_enum_fallback",
        "{}",
        c.id
    );
}

/// The field an enum case tests: expect.field, or its id's name
/// (`enum.<name>.…`), relay_code being the relay error's code.
fn enum_field(c: &crate::wire_vectors::Case) -> String {
    match c.expect_text("field") {
        "" => match c.id.trim_start_matches("enum.").split('.').next() {
            Some("relay_code") => "code".to_string(),
            Some(name) => name.to_string(),
            None => String::new(),
        },
        field => field.to_string(),
    }
}

fn context_frame(c: &crate::wire_vectors::Case, i: usize) -> Value {
    let hex = c.input["context"][i].as_str().unwrap();
    cbor::decode(&hex::decode(hex).unwrap()).unwrap()
}

/// The wire 1.0 enum vectors (macula#99) for the frames a client reads: an
/// EVENT's delivered_via per hop, and STREAM_OPEN mode, a relay error's code,
/// STREAM_DATA encoding and STREAM_END role inside a signed tbs. HELLO's
/// refusal_code runs with the handshake; HyParView priority and SWIM state
/// ride frames only stations exchange.
#[test]
fn the_wire_1_0_enum_vectors() {
    let file = crate::wire_vectors::load("enums");
    let mut ran = 0;
    for c in &file.cases {
        let field = enum_field(c);
        if matches!(field.as_str(), "priority" | "state" | "refusal_code") {
            continue;
        }
        if c.id.starts_with("enum.register_ack.") {
            ran += 1;
            register_ack_enum(c, &field);
            continue;
        }
        ran += 1;
        let before = wire_counters()
            .enum_fallback
            .get(&field)
            .copied()
            .unwrap_or(0);
        let read = read_enum_frame(c, &field);
        match c.outcome() {
            "accept" | "fallback" => assert_eq!(read, Ok(()), "{}", c.id),
            "refuse" => {
                assert_eq!(c.reason(), "enum_unknown", "{}", c.id);
                assert_eq!(
                    read,
                    Err(FrameError::EnumUnknown(field.clone())),
                    "{}",
                    c.id
                );
            }
            other => panic!("{}: outcome {other}", c.id),
        }
        let counted = wire_counters()
            .enum_fallback
            .get(&field)
            .copied()
            .unwrap_or(0)
            > before;
        assert_eq!(
            counted,
            c.expect_text("count") == "wire_enum_fallback",
            "{}: wire_enum_fallback",
            c.id
        );
    }
    assert_eq!(ran, 21, "the enum cases a client reads");
}

/// A CALL signed with `ext` in its request's tbs, by a fresh identity key.
fn call_with_ext(ext: Value) -> Value {
    let key =
        crate::node_key::NodeKey::generate_identity(crate::profile::Profile::PqPure, 0).unwrap();
    let spec = RequestSpec {
        request_id: [1; 16],
        realm: [2; 32],
        procedure: "example.procedure".into(),
        target: [3; 32],
        deadline: 1,
        payload: Value::Map(Vec::new()),
        sealed: None,
        mode: None,
        token: None,
        proofs: Vec::new(),
        source_route: None,
        retry_budget: None,
    };
    let call = sign_call(&spec, &key).unwrap();
    let object = crate::signed_object::Object::from_value(call.get("request").unwrap()).unwrap();
    let Value::Map(fields) = cbor::decode(&object.tbs).unwrap().with_field("ext", ext) else {
        unreachable!()
    };
    let resigned = crate::signed_object::sign_object(REQUEST_LABEL, &fields, &key).unwrap();
    call.with_field("request", resigned.to_value())
}

fn one_ext(name: &str, critical: i128) -> Value {
    Value::Map(vec![(
        Value::text(name),
        Value::Map(vec![
            (Value::text("critical"), Value::Int(critical)),
            (Value::text("value"), Value::text("x")),
        ]),
    )])
}

/// WIRE_1_0.md section 3.2: ext inside a signed object's tbs. An unknown
/// critical extension refuses the object by name; a non-critical one is read
/// past and counted.
#[test]
fn a_signed_object_acts_on_the_ext_in_its_tbs() {
    let profile = crate::profile::Profile::PqPure;
    let refused = verify_request(&call_with_ext(one_ext("example.critical", 1)), profile);
    assert_eq!(
        refused.err(),
        Some(FrameError::ExtensionUnsupported("example.critical".into()))
    );
    let ignored = |w: &WireCounts| w.ext_ignored.get("example.ignored").copied().unwrap_or(0);
    let before = ignored(&wire_counters());
    assert!(verify_request(&call_with_ext(one_ext("example.ignored", 0)), profile).is_ok());
    assert!(ignored(&wire_counters()) > before);
    let empty = verify_request(&call_with_ext(Value::Map(Vec::new())), profile);
    assert_eq!(empty.err(), Some(FrameError::Malformed));
}
