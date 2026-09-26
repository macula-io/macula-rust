//! Replies and relay errors (D25): a provider's RESULT or ERROR, signed under
//! MACULA-PQ-REPLY-V1 by the request's target, and a station's relay ERROR or
//! STREAM_ERROR, signed under MACULA-PQ-RELAY-ERROR-V1 with a code from a
//! closed set and no free text.

use crate::cbor::{self, Value};
use crate::node_key::{node_id_of, NodeKey};
use crate::profile::Profile;
use crate::signed_object::{sign_object, verify_object, Object};

use super::{
    bounded_text, check_payload, entry, fixed, has_fields, identity_signer, names_request,
    object_refusal, read_fields, received_frame, text_of, FrameError, Rule, VerifiedRequest,
    MAX_ERROR_CODE_BYTES, MAX_ERROR_TEXT_BYTES, PROTOCOL_VERSION, RELAY_ERROR_LABEL, REPLY_LABEL,
};

const RESULT: &str = "result";
const ERROR: &str = "error";
const STREAM_ERROR: &str = "stream_error";

/// The closed set of relay error codes, disjoint from every provider code.
const RELAY_CODES: &[&str] = &["unknown_next_peer"];

/// A reply's frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyType {
    Result,
    Error,
}

/// A relay error's frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayErrorType {
    Error,
    StreamError,
}

impl RelayErrorType {
    fn name(self) -> &'static str {
        match self {
            RelayErrorType::Error => ERROR,
            RelayErrorType::StreamError => STREAM_ERROR,
        }
    }
}

/// A provider's RESULT or ERROR that verified for its request: the node that
/// responded, a RESULT's payload, and an ERROR's code and detail.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedReply {
    pub frame_type: ReplyType,
    pub responded_by: [u8; 32],
    pub payload: Option<Value>,
    pub code: Option<String>,
    pub detail: Option<String>,
}

/// A station's relay error as it gives it: for a pending verified request, a
/// code from the closed set, the hop that failed, and a routing field outside
/// the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayErrorSpec {
    pub frame_type: RelayErrorType,
    pub request: VerifiedRequest,
    pub code: String,
    pub offending_hop: Option<[u8; 32]>,
    pub source_route_partial: Option<Vec<u8>>,
}

/// A relay error that verified for its request: the station that reported
/// it, its code, and the hop that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelayError {
    pub frame_type: RelayErrorType,
    pub reported_by: [u8; 32],
    pub code: String,
    pub offending_hop: Option<[u8; 32]>,
}

/// Signs a provider's RESULT for a verified request: responded_by is the
/// key's key id, which must be the request's target, and the payload one the
/// wire carries. `source_route_reverse` rides outside the signature.
pub fn sign_result(
    request: &VerifiedRequest,
    payload: &Value,
    source_route_reverse: Option<Vec<u8>>,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    reply_signer(request, key)?;
    check_payload(payload)?;
    sign_reply(
        ReplyType::Result,
        request,
        vec![entry("payload", payload.clone())],
        source_route_reverse,
        key,
    )
}

/// Signs a provider's ERROR for a verified request, with [`sign_result`]'s
/// key check: a code of at most 64 bytes and a detail of at most 256.
pub fn sign_provider_error(
    request: &VerifiedRequest,
    code: &str,
    detail: Option<&str>,
    source_route_reverse: Option<Vec<u8>>,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    reply_signer(request, key)?;
    bounded_text("code", code.as_bytes(), MAX_ERROR_CODE_BYTES)?;
    let mut fields = vec![entry("code", Value::text(code))];
    if let Some(detail) = detail {
        bounded_text("detail", detail.as_bytes(), MAX_ERROR_TEXT_BYTES)?;
        fields.push(entry("detail", Value::text(detail)));
    }
    sign_reply(ReplyType::Error, request, fields, source_route_reverse, key)
}

fn reply_signer(request: &VerifiedRequest, key: &NodeKey) -> Result<(), FrameError> {
    identity_signer(key)?;
    if key.key_id() != request.target {
        return Err(FrameError::Unsignable);
    }
    Ok(())
}

fn sign_reply(
    frame_type: ReplyType,
    request: &VerifiedRequest,
    mut fields: Vec<(Value, Value)>,
    source_route_reverse: Option<Vec<u8>>,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    let name = match frame_type {
        ReplyType::Result => RESULT,
        ReplyType::Error => ERROR,
    };
    fields.extend([
        entry("frame_type", Value::text(name)),
        entry("request_id", Value::Bytes(request.request_id.to_vec())),
        entry("request_hash", Value::Bytes(request.request_hash.to_vec())),
        entry("responded_by", Value::Bytes(key.key_id().to_vec())),
    ]);
    let reply = sign_object(REPLY_LABEL, &fields, key).map_err(object_refusal)?;
    Ok(routed_frame(
        name,
        "reply",
        &reply,
        "source_route_reverse",
        source_route_reverse,
    ))
}

const REPLY_ROUTES: &[(&str, Rule)] = &[("source_route_reverse", Rule::AnyBytes)];
const RELAY_ERROR_ROUTES: &[(&str, Rule)] = &[("source_route_partial", Rule::AnyBytes)];

/// Verifies a received RESULT or provider ERROR for the request it answers:
/// the frame's shape, the reply's signature and fields, responded_by as the
/// key id of its key, the request's request_id and request_hash, and
/// responded_by as the request's target.
pub fn verify_reply(
    frame: &Value,
    request: &VerifiedRequest,
    profile: Profile,
) -> Result<VerifiedReply, FrameError> {
    let (frame_type, object) = received_frame(
        frame,
        "reply",
        Rule::CarriedObject,
        REPLY_ROUTES,
        &[RESULT, ERROR],
    )
    .ok_or(FrameError::Malformed)?;
    let verified = verify_object(REPLY_LABEL, &object, profile).map_err(object_refusal)?;
    let fields =
        read_fields(&verified.fields, &reply_table(&frame_type)).ok_or(FrameError::Malformed)?;
    let (has_payload, has_code, has_detail) = (
        fields.contains_key("payload"),
        fields.contains_key("code"),
        fields.contains_key("detail"),
    );
    let shaped = if frame_type == RESULT {
        has_payload && !has_code && !has_detail
    } else {
        has_code && !has_payload
    };
    if !has_fields(
        &fields,
        &["frame_type", "request_id", "request_hash", "responded_by"],
    ) || !shaped
    {
        return Err(FrameError::Malformed);
    }
    let reply = VerifiedReply {
        frame_type: if frame_type == RESULT {
            ReplyType::Result
        } else {
            ReplyType::Error
        },
        responded_by: fixed(&fields["responded_by"]),
        payload: fields.get("payload").cloned(),
        code: fields.get("code").map(text_of),
        detail: fields.get("detail").map(text_of),
    };
    if reply.responded_by != node_id_of(&verified.key, profile) {
        return Err(FrameError::KeyIdMismatch);
    }
    if !names_request(&fields, request) {
        return Err(FrameError::RequestMismatch);
    }
    if reply.responded_by != request.target {
        return Err(FrameError::NotTheTarget);
    }
    Ok(reply)
}

fn reply_table(frame_type: &str) -> Vec<(&'static str, Rule)> {
    vec![
        (
            "frame_type",
            Rule::TextIn(if frame_type == RESULT {
                &[RESULT]
            } else {
                &[ERROR]
            }),
        ),
        ("alg", Rule::Any),
        ("request_id", Rule::BytesOf(16)),
        ("request_hash", Rule::BytesOf(48)),
        ("responded_by", Rule::BytesOf(32)),
        ("payload", Rule::Any),
        ("code", Rule::TextWithin(MAX_ERROR_CODE_BYTES)),
        ("detail", Rule::TextWithin(MAX_ERROR_TEXT_BYTES)),
    ]
}

/// Signs a station's relay error with its identity key: reported_by is the
/// key's key id. Refused, in this order: a key that is not an identity key, a
/// code outside the closed set.
pub fn sign_relay_error(spec: &RelayErrorSpec, key: &NodeKey) -> Result<Value, FrameError> {
    identity_signer(key)?;
    if !RELAY_CODES.contains(&spec.code.as_str()) {
        return Err(FrameError::RelayCodeOutsideItsSet);
    }
    let name = spec.frame_type.name();
    let mut fields = vec![
        entry("frame_type", Value::text(name)),
        entry("request_id", Value::Bytes(spec.request.request_id.to_vec())),
        entry(
            "request_hash",
            Value::Bytes(spec.request.request_hash.to_vec()),
        ),
        entry("reported_by", Value::Bytes(key.key_id().to_vec())),
        entry("code", Value::text(spec.code.clone())),
    ];
    if let Some(hop) = spec.offending_hop {
        fields.push(entry("offending_hop", Value::Bytes(hop.to_vec())));
    }
    let relay_error = sign_object(RELAY_ERROR_LABEL, &fields, key).map_err(object_refusal)?;
    Ok(routed_frame(
        name,
        "relay_error",
        &relay_error,
        "source_route_partial",
        spec.source_route_partial.clone(),
    ))
}

/// Verifies a received relay error for the pending request it names, from
/// the station the connection authenticated, `expected_reporter`.
pub fn verify_relay_error(
    frame: &Value,
    request: &VerifiedRequest,
    profile: Profile,
    expected_reporter: &[u8; 32],
) -> Result<VerifiedRelayError, FrameError> {
    let (frame_type, object) = received_frame(
        frame,
        "relay_error",
        Rule::CarriedObject,
        RELAY_ERROR_ROUTES,
        &[ERROR, STREAM_ERROR],
    )
    .ok_or(FrameError::Malformed)?;
    let verified = verify_object(RELAY_ERROR_LABEL, &object, profile).map_err(object_refusal)?;
    let fields = read_fields(&verified.fields, &relay_error_table(&frame_type))
        .ok_or(FrameError::Malformed)?;
    if !has_fields(
        &fields,
        &[
            "frame_type",
            "request_id",
            "request_hash",
            "reported_by",
            "code",
        ],
    ) {
        return Err(FrameError::Malformed);
    }
    let relay_error = VerifiedRelayError {
        frame_type: if frame_type == ERROR {
            RelayErrorType::Error
        } else {
            RelayErrorType::StreamError
        },
        reported_by: fixed(&fields["reported_by"]),
        code: text_of(&fields["code"]),
        offending_hop: fields.get("offending_hop").map(fixed),
    };
    if relay_error.reported_by != node_id_of(&verified.key, profile) {
        return Err(FrameError::KeyIdMismatch);
    }
    if !names_request(&fields, request) {
        return Err(FrameError::RequestMismatch);
    }
    if &relay_error.reported_by != expected_reporter {
        return Err(FrameError::NotTheConnection);
    }
    Ok(relay_error)
}

fn relay_error_table(frame_type: &str) -> Vec<(&'static str, Rule)> {
    vec![
        (
            "frame_type",
            Rule::TextIn(if frame_type == ERROR {
                &[ERROR]
            } else {
                &[STREAM_ERROR]
            }),
        ),
        ("alg", Rule::Any),
        ("request_id", Rule::BytesOf(16)),
        ("request_hash", Rule::BytesOf(48)),
        ("reported_by", Rule::BytesOf(32)),
        ("code", Rule::TextIn(RELAY_CODES)),
        ("offending_hop", Rule::BytesOf(32)),
    ]
}

/// The request_id and request_hash a received reply or relay error names,
/// read without verifying it: a key for finding the pending request and
/// nothing more. The frame's fields and the signed object's shape are checked
/// as the verifiers check them, so ids of another length or shape never come
/// back.
pub fn claimed_reply_ids(frame: &Value) -> Result<([u8; 16], [u8; 48]), FrameError> {
    let frame_type = frame.get("frame_type").map(text_of).unwrap_or_default();
    let (object_name, routes, table) = match (frame.get("reply"), frame.get("relay_error")) {
        (Some(_), _) if frame_type == RESULT || frame_type == ERROR => {
            ("reply", REPLY_ROUTES, reply_table(&frame_type))
        }
        (_, Some(_)) if frame_type == ERROR || frame_type == STREAM_ERROR => (
            "relay_error",
            RELAY_ERROR_ROUTES,
            relay_error_table(&frame_type),
        ),
        _ => return Err(FrameError::Malformed),
    };
    let types: &'static [&'static str] = match frame_type.as_str() {
        RESULT => &[RESULT],
        ERROR => &[ERROR],
        _ => &[STREAM_ERROR],
    };
    let (_, object) = received_frame(frame, object_name, Rule::CarriedObject, routes, types)
        .ok_or(FrameError::Malformed)?;
    let parsed = Object::from_value(&object).map_err(|_| FrameError::Malformed)?;
    let tbs = cbor::decode(&parsed.tbs).map_err(|_| FrameError::Malformed)?;
    let fields = read_fields(&tbs, &table).ok_or(FrameError::Malformed)?;
    if !has_fields(&fields, &["frame_type", "request_id", "request_hash"]) {
        return Err(FrameError::Malformed);
    }
    Ok((fixed(&fields["request_id"]), fixed(&fields["request_hash"])))
}

/// A frame of `frame_type` carrying `object` under `object_name`, with the
/// routing field `route_name` when there is one.
fn routed_frame(
    frame_type: &str,
    object_name: &str,
    object: &Object,
    route_name: &str,
    route: Option<Vec<u8>>,
) -> Value {
    let mut entries = vec![
        entry("version", Value::Int(i128::from(PROTOCOL_VERSION))),
        entry("frame_type", Value::text(frame_type)),
        entry(object_name, object.to_value()),
    ];
    if let Some(route) = route {
        entries.push(entry(route_name, Value::Bytes(route)));
    }
    Value::Map(entries)
}
