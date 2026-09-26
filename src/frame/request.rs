//! Requests (D25): a CALL or STREAM_OPEN, a signed object under
//! MACULA-PQ-REQUEST-V1 by the caller's identity key, with routing fields
//! outside the signature.

use sha2::{Digest, Sha384};

use crate::cbor::Value;
use crate::node_key::{node_id_of, NodeKey};
use crate::profile::Profile;
use crate::signed_object::{sign_object, verify_object};

use super::{
    bounded_text, check_payload, entry, fixed, has_fields, identity_signer, object_refusal,
    protocol_uint, read_fields, received_frame, text_of, uint, FrameError, Rule, StreamMode,
    MAX_PROCEDURE_BYTES, MAX_PROTOCOL_INT, PROTOCOL_VERSION, REQUEST_LABEL,
};

/// The bound on a request's proofs (D7, chain transport): eight tokens, 256
/// KiB in all, none repeated.
pub const MAX_PROOFS: usize = 8;
pub const MAX_PROOFS_BYTES: usize = 256 * 1024;

const CALL: &str = "call";
const STREAM_OPEN: &str = "stream_open";

/// A request's frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Call,
    StreamOpen,
}

impl RequestType {
    fn name(self) -> &'static str {
        match self {
            RequestType::Call => CALL,
            RequestType::StreamOpen => STREAM_OPEN,
        }
    }
}

/// A request as its caller gives it: `mode` is a STREAM_OPEN's and `None` for
/// a CALL; `token` is `None` when the request carries none; `proofs` are the
/// tokens of the delegation chain the token rests on, empty for none;
/// `source_route` and `retry_budget` are routing fields outside the
/// signature.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestSpec {
    pub request_id: [u8; 16],
    pub realm: [u8; 32],
    pub procedure: String,
    pub target: [u8; 32],
    pub deadline: u64,
    pub payload: Value,
    pub mode: Option<StreamMode>,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub source_route: Option<Vec<u8>>,
    pub retry_budget: Option<u64>,
}

/// A CALL or STREAM_OPEN whose request verified: its fields, the caller's key
/// as carried, and `request_hash`, the SHA-384 of its tbs, which replies and
/// stream frames name.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRequest {
    pub frame_type: RequestType,
    pub key: Vec<u8>,
    pub request_hash: [u8; 48],
    pub caller: [u8; 32],
    pub request_id: [u8; 16],
    pub realm: [u8; 32],
    pub procedure: String,
    pub target: [u8; 32],
    pub deadline: u64,
    pub payload: Value,
    pub mode: Option<StreamMode>,
    pub token: Option<Vec<u8>>,
    pub proofs: Option<Vec<Vec<u8>>>,
}

/// Signs a CALL with the caller's identity key: caller is the key's key id.
/// Refused, in this order: a key that is not an identity key, a procedure over
/// 512 bytes, a payload the wire cannot carry, a deadline or retry budget of
/// 2^53 or more, or a stream mode, which a CALL does not carry; then proofs
/// outside their bound.
pub fn sign_call(spec: &RequestSpec, key: &NodeKey) -> Result<Value, FrameError> {
    sign_request(RequestType::Call, spec, key)
}

/// Signs a STREAM_OPEN, which carries `spec.mode`, with [`sign_call`]'s
/// checks, the last of them refusing no mode.
pub fn sign_stream_open(spec: &RequestSpec, key: &NodeKey) -> Result<Value, FrameError> {
    sign_request(RequestType::StreamOpen, spec, key)
}

fn sign_request(
    frame_type: RequestType,
    spec: &RequestSpec,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    identity_signer(key)?;
    bounded_text("procedure", spec.procedure.as_bytes(), MAX_PROCEDURE_BYTES)?;
    check_payload(&spec.payload)?;
    if spec.deadline >= MAX_PROTOCOL_INT || spec.retry_budget.is_some_and(|b| b >= MAX_PROTOCOL_INT)
    {
        return Err(FrameError::OutOfRange(
            "a deadline or retry budget of 2^53 or more".into(),
        ));
    }
    match (frame_type, spec.mode) {
        (RequestType::Call, Some(_)) => {
            return Err(FrameError::OutOfRange(
                "a CALL carries no stream mode".into(),
            ))
        }
        (RequestType::StreamOpen, None) => {
            return Err(FrameError::OutOfRange(
                "a STREAM_OPEN carries one of the three stream modes".into(),
            ))
        }
        _ => {}
    }
    let proofs = proofs_value(&spec.proofs);
    if !proofs_within_bound(&proofs) {
        return Err(FrameError::ProofsOutOfBound);
    }
    let mut fields = vec![
        entry("frame_type", Value::text(frame_type.name())),
        entry("caller", Value::Bytes(key.key_id().to_vec())),
        entry("request_id", Value::Bytes(spec.request_id.to_vec())),
        entry("realm", Value::Bytes(spec.realm.to_vec())),
        entry("procedure", Value::text(spec.procedure.clone())),
        entry("target", Value::Bytes(spec.target.to_vec())),
        entry("deadline", uint(spec.deadline)),
        entry("payload", spec.payload.clone()),
    ];
    if let Some(mode) = spec.mode {
        fields.push(entry("mode", Value::text(mode.name())));
    }
    if let Some(token) = &spec.token {
        fields.push(entry("token", Value::Bytes(token.clone())));
    }
    if !spec.proofs.is_empty() {
        fields.push(entry("proofs", proofs));
    }
    let request = sign_object(REQUEST_LABEL, &fields, key).map_err(object_refusal)?;
    let mut frame = vec![
        entry("version", Value::Int(i128::from(PROTOCOL_VERSION))),
        entry("frame_type", Value::text(frame_type.name())),
        entry("request", request.to_value()),
    ];
    if let Some(route) = &spec.source_route {
        frame.push(entry("source_route", Value::Bytes(route.clone())));
    }
    if let Some(budget) = spec.retry_budget {
        frame.push(entry("retry_budget", uint(budget)));
    }
    Ok(Value::Map(frame))
}

const REQUEST_ROUTES: &[(&str, Rule)] = &[
    ("source_route", Rule::AnyBytes),
    ("retry_budget", Rule::ProtocolUint),
];

/// Verifies a received CALL or STREAM_OPEN under the connection's `profile`:
/// the frame's shape, the request's signature and fields, and caller as the
/// key id of its key. A station checks this before it routes, and a provider
/// before its own checks, which stay with the caller: its node_id as target,
/// the deadline window, replays and tokens.
pub fn verify_request(frame: &Value, profile: Profile) -> Result<VerifiedRequest, FrameError> {
    let (frame_type, object) = received_frame(
        frame,
        "request",
        Rule::CarriedObject,
        REQUEST_ROUTES,
        &[CALL, STREAM_OPEN],
    )
    .ok_or(FrameError::Malformed)?;
    let frame_type = if frame_type == CALL {
        RequestType::Call
    } else {
        RequestType::StreamOpen
    };
    let verified = verify_object(REQUEST_LABEL, &object, profile).map_err(object_refusal)?;
    let fields =
        read_fields(&verified.fields, &request_table(frame_type)).ok_or(FrameError::Malformed)?;
    let has_mode = fields.contains_key("mode");
    if !has_fields(
        &fields,
        &[
            "frame_type",
            "caller",
            "request_id",
            "realm",
            "procedure",
            "target",
            "deadline",
            "payload",
        ],
    ) || has_mode != (frame_type == RequestType::StreamOpen)
    {
        return Err(FrameError::Malformed);
    }
    let request = VerifiedRequest {
        frame_type,
        request_hash: Sha384::digest(&verified.tbs).into(),
        caller: fixed(&fields["caller"]),
        request_id: fixed(&fields["request_id"]),
        realm: fixed(&fields["realm"]),
        procedure: text_of(&fields["procedure"]),
        target: fixed(&fields["target"]),
        deadline: protocol_uint(&fields["deadline"]).unwrap_or(0),
        payload: fields["payload"].clone(),
        mode: fields
            .get("mode")
            .and_then(|m| StreamMode::parse(&text_of(m))),
        token: fields.get("token").map(super::bytes_of),
        proofs: fields.get("proofs").map(|p| match p {
            Value::List(items) => items.iter().map(super::bytes_of).collect(),
            _ => Vec::new(),
        }),
        key: verified.key,
    };
    if request.caller != node_id_of(&request.key, profile) {
        return Err(FrameError::KeyIdMismatch);
    }
    Ok(request)
}

fn request_table(frame_type: RequestType) -> Vec<(&'static str, Rule)> {
    vec![
        (
            "frame_type",
            Rule::TextIn(match frame_type {
                RequestType::Call => &[CALL],
                RequestType::StreamOpen => &[STREAM_OPEN],
            }),
        ),
        ("alg", Rule::Any),
        ("caller", Rule::BytesOf(32)),
        ("request_id", Rule::BytesOf(16)),
        ("realm", Rule::BytesOf(32)),
        ("procedure", Rule::TextWithin(MAX_PROCEDURE_BYTES)),
        ("target", Rule::BytesOf(32)),
        ("deadline", Rule::ProtocolUint),
        ("payload", Rule::Any),
        (
            "mode",
            Rule::TextIn(&["server_stream", "client_stream", "bidi"]),
        ),
        ("token", Rule::AnyBytes),
        ("proofs", Rule::Proofs),
    ]
}

/// Whether `fields` read as a CALL's under the request table, where a
/// delegation chain's proofs are bounded: the reading the shared decoding
/// rule vectors name `request_fields`.
pub fn request_fields_accepted(fields: &Value) -> bool {
    read_fields(fields, &request_table(RequestType::Call)).is_some()
}

fn proofs_value(proofs: &[Vec<u8>]) -> Value {
    Value::List(proofs.iter().map(|p| Value::Bytes(p.clone())).collect())
}

/// macula's bytes_set rule for proofs: a list of at most [`MAX_PROOFS`] byte
/// strings, [`MAX_PROOFS_BYTES`] in all, none repeated.
pub(super) fn proofs_within_bound(v: &Value) -> bool {
    let Value::List(items) = v else {
        return false;
    };
    if items.len() > MAX_PROOFS {
        return false;
    }
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    let mut total = 0;
    for item in items {
        let Value::Bytes(b) = item else {
            return false;
        };
        if !seen.insert(b.as_slice()) {
            return false;
        }
        total += b.len();
    }
    total <= MAX_PROOFS_BYTES
}
