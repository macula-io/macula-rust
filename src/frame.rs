//! macula 12's frames, as macula_frame and macula-go build and read them: the
//! requests, replies, relay errors, publications and stream frames that carry
//! signed objects, the control frames a pq_hybrid link neighbour-signs, the
//! decoding rule's payload bounds, and the length-prefixed wire codec.
//!
//! A wire frame is `<Length:4 bytes big-endian><Cbor>`, the deterministic
//! encoding of one map with `version` and `frame_type`. No frame carries a
//! frame-level signature: what is signed is the signed object a frame holds,
//! and, in pq_hybrid, a control frame's neighbour signature.

mod check_payload;
mod control;
mod envelope;
mod publication;
mod register_ack;
mod reply;
mod request;
mod sealed;
mod session;
mod stream;
#[cfg(test)]
mod wire_1_0_tests;
mod wire_counters;

pub use check_payload::{
    check_frame, check_payload, FRAME_RESERVED_ELEMENTS, MAX_PAYLOAD_ELEMENTS, MAX_PAYLOAD_NESTING,
};
pub use control::{
    advertise_frame, goodbye_frame, is_control_frame, read_control, subscribe_frame,
    unadvertise_frame, unsubscribe_frame,
};
pub use envelope::{
    act_on_ext, check_ext, ext_value, read_envelope, unknown_frame_type, Envelope, MAX_EXTENSIONS,
    MAX_EXTENSION_NAME_BYTES, MAX_FRAME_TYPE_BYTES, QUIC_CODE_UNKNOWN_FRAME_TYPE, SEAL_KEM_KEY_EXT,
};
pub use publication::{
    accepted_until, delivered_via, sign_publish, verify_publication, Payload, PublicationSpec,
    VerifiedPublication,
};
pub use register_ack::{read_register_ack, Answered, RegisterAck, RegisterKind};
pub use reply::{
    claimed_reply_ids, sign_provider_error, sign_relay_error, sign_result,
    sign_sealed_provider_error, sign_sealed_required, sign_sealed_result, verify_relay_error,
    verify_reply, RelayErrorSpec, RelayErrorType, ReplyType, VerifiedRelayError, VerifiedReply,
};
pub use request::{
    request_fields_accepted, sign_call, sign_stream_open, verify_request, RequestSpec, RequestType,
    VerifiedRequest, MAX_PROOFS, MAX_PROOFS_BYTES,
};
pub use sealed::{Sealed, SEALED_SCHEME};
pub use session::{
    liveness_nonce, liveness_ping_frame, liveness_pong_frame, Liveness, LIVENESS_NONCE_SIZE,
};
pub use stream::{
    open_stream, sign_caller_stream, sign_provider_stream, sign_stream_sealed_required,
    verify_caller_stream, verify_provider_stream, StreamEncoding, StreamFields, StreamMode,
    StreamRole, StreamState, VerifiedStreamFrame,
};
pub(crate) use wire_counters::count_enum_fallback;
pub use wire_counters::{wire_counters, WireCounts};

use std::fmt;

use crate::cbor::{self, Value};
use crate::node_key::{KeyError, NodeKey, Purpose};
use crate::signed_object::ObjectError;

/// The version field every frame carries: wire 1.0's frame version is its
/// handshake version, 5 (WIRE_1_0.md section 2).
pub const PROTOCOL_VERSION: i64 = 5;

/// The CBOR payload size cap: 16 MiB minus one byte, as macula's.
pub const MAX_FRAME_BYTES: usize = 0x00FF_FFFF;

/// The labels of the signed objects frames carry (D25, D17).
const REQUEST_LABEL: &str = "MACULA-PQ-REQUEST-V1";
const REPLY_LABEL: &str = "MACULA-PQ-REPLY-V1";
const RELAY_ERROR_LABEL: &str = "MACULA-PQ-RELAY-ERROR-V1";
const STREAM_LABEL: &str = "MACULA-PQ-STREAM-V1";
const CALLER_STREAM_LABEL: &str = "MACULA-PQ-CALLER-STREAM-V1";
const PUBLICATION_LABEL: &str = "MACULA-PQ-PUBLICATION-V1";

/// A protocol integer stays below 2^53; a procedure name is at most 512
/// bytes, an error code at most 64, and an error's text at most 256.
const MAX_PROTOCOL_INT: u64 = 1 << 53;
const MAX_PROCEDURE_BYTES: usize = 512;
const MAX_ERROR_CODE_BYTES: usize = 64;
const MAX_ERROR_TEXT_BYTES: usize = 256;
const MAX_TOPIC_BYTES: usize = 512;
/// An enum value on the wire, known or not, is text of 1 to 64 bytes.
const MAX_ENUM_VALUE_BYTES: usize = 64;

/// The refusals of a frame, named as macula_frame names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// An encoding longer than [`MAX_FRAME_BYTES`], or a header claiming one.
    TooLarge(usize),
    /// A frame, or the signed object it carries, without exactly the shape and
    /// fields of its type.
    Malformed,
    /// A payload the decoding rule would refuse where it arrives, and where.
    Payload(String),
    /// A whole frame the decoding rule would refuse, and where.
    BreaksDecodingRule(String),
    /// A request's delegation chain proofs outside their bound.
    ProofsOutOfBound,
    /// A signed object whose signer is not the key it verified with.
    KeyIdMismatch,
    /// A reply, relay error or stream frame naming another request.
    RequestMismatch,
    /// A reply, or a provider's first stream frame, from a node other than its
    /// request's target.
    NotTheTarget,
    /// A relay error from another station than the connection's.
    NotTheConnection,
    /// A key that cannot sign this frame.
    Unsignable,
    /// A text longer than its bound, naming the field.
    TextTooLong(String),
    /// A text that is not valid UTF-8, naming the field.
    InvalidText(String),
    /// A relay error code outside its closed set.
    RelayCodeOutsideItsSet,
    /// A field outside its range, and which.
    OutOfRange(String),
    /// A sealed payload built with another shape than its frame's: a
    /// request's without a kem_ct of a profile's size or with a nonce, a
    /// reply's or a provider stream frame's without a 12-byte nonce or with a
    /// kem_ct, or a caller stream frame's with either.
    SealedShape,
    /// A stream frame its side does not send, and which.
    NotAllowed(String),
    /// A stream frame out of its side's order.
    SeqMismatch,
    /// A stream frame after its side's STREAM_END.
    StreamEnded,
    /// A publication published too far ahead, by how many milliseconds.
    NotYetValid(i64),
    /// A publication past its expiry, by how many milliseconds.
    Expired(i64),
    /// A signed object's signature that does not verify.
    SignatureInvalid,
    /// A frame or signed object carrying a critical extension this node does
    /// not know, by name (`extension_unsupported`).
    ExtensionUnsupported(String),
    /// A signed object carrying an enum value this node does not know, naming
    /// the field (`enum_unknown`).
    EnumUnknown(String),
    /// A key that could not sign.
    Key(KeyError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge(n) => write!(
                f,
                "a frame of {n} bytes, over the {MAX_FRAME_BYTES}-byte cap"
            ),
            FrameError::Malformed => f.write_str("malformed frame"),
            FrameError::Payload(why) | FrameError::BreaksDecodingRule(why) => f.write_str(why),
            FrameError::ProofsOutOfBound => {
                f.write_str("the request's proofs are outside the bound")
            }
            FrameError::KeyIdMismatch => {
                f.write_str("the signer the frame names is not the key it verified with")
            }
            FrameError::RequestMismatch => f.write_str("the frame names another request"),
            FrameError::NotTheTarget => f.write_str("the frame is not from the request's target"),
            FrameError::NotTheConnection => {
                f.write_str("the relay error is not from the connection's station")
            }
            FrameError::Unsignable => f.write_str("the key cannot sign this frame"),
            FrameError::TextTooLong(what) => write!(f, "text longer than its bound: {what}"),
            FrameError::InvalidText(what) => write!(f, "text that is not valid UTF-8: {what}"),
            FrameError::RelayCodeOutsideItsSet => {
                f.write_str("a relay error code outside its closed set")
            }
            FrameError::OutOfRange(what) => write!(f, "a field outside its range: {what}"),
            FrameError::SealedShape => {
                f.write_str("a sealed payload of another shape than its frame's")
            }
            FrameError::NotAllowed(what) => {
                write!(f, "a stream frame its side does not send: {what}")
            }
            FrameError::SeqMismatch => f.write_str("a stream frame out of its side's order"),
            FrameError::StreamEnded => f.write_str("a stream frame after its side's STREAM_END"),
            FrameError::NotYetValid(ms) => write!(f, "a publication not yet valid, by {ms} ms"),
            FrameError::Expired(ms) => write!(f, "a publication past its expiry, by {ms} ms"),
            FrameError::SignatureInvalid => {
                f.write_str("the signed object's signature does not verify")
            }
            FrameError::ExtensionUnsupported(name) => {
                write!(f, "a critical extension this node does not know: {name}")
            }
            FrameError::EnumUnknown(field) => {
                write!(f, "an enum value this node does not know, in {field}")
            }
            FrameError::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The refusal of a frame whose signed object did not verify: a signature
/// that does not verify as it is, anything else as [`FrameError::Malformed`].
fn object_refusal(e: ObjectError) -> FrameError {
    match e {
        ObjectError::SignatureInvalid => FrameError::SignatureInvalid,
        ObjectError::Key(k) => FrameError::Key(k),
        _ => FrameError::Malformed,
    }
}

/// Wraps `frame` as `<Length:4 bytes big-endian><Cbor>`, refusing one over
/// the frame cap.
pub fn encode(frame: &Value) -> Result<Vec<u8>, FrameError> {
    let payload = cbor::encode(frame).map_err(|e| FrameError::Payload(e.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// What decoding the head of a buffer found.
#[derive(Debug, Clone, PartialEq)]
pub enum Decoded {
    /// A whole frame, and how many bytes of the buffer it took.
    Complete { frame: Value, consumed: usize },
    /// At least this many more bytes are needed before trying again.
    NeedMore(usize),
}

/// Decodes one length-prefixed frame from the head of `buf`, under the
/// decoding rule.
pub fn decode(buf: &[u8]) -> Result<Decoded, FrameError> {
    let Some((header, rest)) = buf.split_first_chunk::<4>() else {
        return Ok(Decoded::NeedMore(4 - buf.len()));
    };
    let length = u32::from_be_bytes(*header) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(length));
    }
    if rest.len() < length {
        return Ok(Decoded::NeedMore(length - rest.len()));
    }
    let frame = cbor::decode(&rest[..length]).map_err(|_| FrameError::Malformed)?;
    Ok(Decoded::Complete {
        frame,
        consumed: 4 + length,
    })
}

/// A field's rule, as a frame's field table names it.
#[derive(Debug, Clone, Copy)]
enum Rule {
    Any,
    AnyBytes,
    BytesOf(usize),
    TextWithin(usize),
    TextIn(&'static [&'static str]),
    ProtocolUint,
    ProtocolVersion,
    CarriedObject,
    HeldObject,
    StreamObject,
    Proofs,
    Sealed(sealed::SealedContext),
    /// An enum value's shape, known or not: text of 1 to 64 bytes. Whether
    /// the value is known is its reader's next check (WIRE_1_0.md 3.4).
    EnumText,
    /// The unsigned 0 or 1.
    ZeroOrOne,
    /// A well-formed `ext` map (WIRE_1_0.md section 3.2), not yet acted on.
    Ext,
}

impl Rule {
    fn accepts(self, v: &Value) -> bool {
        match self {
            Rule::Any => true,
            Rule::AnyBytes => matches!(v, Value::Bytes(_)),
            Rule::BytesOf(n) => matches!(v, Value::Bytes(b) if b.len() == n),
            Rule::TextWithin(n) => matches!(v, Value::Text(t) if t.len() <= n),
            Rule::TextIn(names) => matches!(v, Value::Text(t) if names.contains(&t.as_str())),
            Rule::ProtocolUint => protocol_uint(v).is_some(),
            Rule::ProtocolVersion => {
                matches!(v, Value::Int(n) if *n == i128::from(PROTOCOL_VERSION))
            }
            Rule::CarriedObject => crate::signed_object::Object::from_value(v).is_ok(),
            Rule::HeldObject => crate::signed_object::HeldObject::from_value(v).is_ok(),
            Rule::StreamObject => Rule::CarriedObject.accepts(v) || Rule::HeldObject.accepts(v),
            Rule::Proofs => request::proofs_within_bound(v),
            Rule::Sealed(context) => sealed::read_sealed(v, context).is_some(),
            Rule::ZeroOrOne => matches!(v, Value::Int(0 | 1)),
            Rule::Ext => check_ext(v).is_ok(),
            Rule::EnumText => {
                matches!(v, Value::Text(t) if !t.is_empty() && t.len() <= MAX_ENUM_VALUE_BYTES)
            }
        }
    }
}

/// A frame's or signed object's fields by name.
type Fields = std::collections::HashMap<String, Value>;

/// A map read through its table, as macula_frame's read_fields does: every
/// key text, named in the table and there once, with a value its rule
/// accepts.
fn read_fields(v: &Value, table: &[(&str, Rule)]) -> Option<Fields> {
    let Value::Map(pairs) = v else {
        return None;
    };
    let mut fields = Fields::with_capacity(pairs.len());
    for (key, value) in pairs {
        let Value::Text(name) = key else {
            return None;
        };
        let rule = table.iter().find(|(n, _)| *n == name)?.1;
        if fields.contains_key(name) || !rule.accepts(value) {
            return None;
        }
        fields.insert(name.clone(), value.clone());
    }
    Some(fields)
}

/// Acts on the `ext` a signed object's tbs carries (WIRE_1_0.md section 3.2),
/// knowing the extensions `known` names in that object: an unknown critical
/// extension refuses that object, by name, never the link; an unknown
/// non-critical one is counted.
fn signed_ext(fields: &Fields, known: &[&str]) -> Result<(), FrameError> {
    match fields.get("ext") {
        Some(ext) => act_on_ext(ext, known),
        None => Ok(()),
    }
}

/// The signed tbs entry that carries `kem_key` as the non-critical extension
/// [`SEAL_KEM_KEY_EXT`].
fn kem_key_ext(kem_key: &[u8]) -> (Value, Value) {
    entry(
        "ext",
        Value::Map(vec![(
            Value::text(SEAL_KEM_KEY_EXT),
            Value::Map(vec![
                entry("critical", Value::Int(0)),
                entry("value", Value::Bytes(kem_key.to_vec())),
            ]),
        )]),
    )
}

/// The KEM key a provider's refusal carries in its signed tbs, as the
/// non-critical extension [`SEAL_KEM_KEY_EXT`]: its bytes, or `None` when
/// the extension is not there or its value is not a byte string. Whether the
/// key fits a profile is its caller's check.
fn carried_kem_key(fields: &Fields) -> Option<Vec<u8>> {
    match fields
        .get("ext")
        .and_then(|ext| ext_value(ext, SEAL_KEM_KEY_EXT))
    {
        Some(Value::Bytes(key)) => Some(key.clone()),
        _ => None,
    }
}

/// Refuses a signed object whose `field` holds an enum value outside `known`
/// as [`FrameError::EnumUnknown`] naming the field (WIRE_1_0.md section 3.4):
/// inside a tbs an unknown value refuses that object, never the link. An
/// absent field is not judged here.
fn tbs_enum(fields: &Fields, field: &str, known: &[&str]) -> Result<(), FrameError> {
    match fields.get(field) {
        Some(Value::Text(t)) if !known.contains(&t.as_str()) => {
            Err(FrameError::EnumUnknown(field.to_string()))
        }
        _ => Ok(()),
    }
}

fn has_fields(fields: &Fields, names: &[&str]) -> bool {
    names.iter().all(|n| fields.contains_key(*n))
}

/// A received frame that carries its fields in one signed object: exactly
/// version, frame_type, the object under `object_name` and the routing fields
/// `routes` names; the protocol's version; a frame type of `types`; the object
/// in a shape `object_rule` accepts; and each routing field of its rule.
fn received_frame(
    v: &Value,
    object_name: &str,
    object_rule: Rule,
    routes: &[(&str, Rule)],
    types: &'static [&'static str],
) -> Option<(String, Value)> {
    let mut table = vec![
        ("version", Rule::ProtocolVersion),
        ("frame_type", Rule::TextIn(types)),
        ("frame_id", Rule::BytesOf(16)),
        ("sent_at_ms", Rule::ProtocolUint),
        (object_name, object_rule),
    ];
    table.extend_from_slice(routes);
    let fields = read_fields(v, &table)?;
    if !has_fields(&fields, &["version", "frame_type", object_name]) {
        return None;
    }
    Some((text_of(&fields["frame_type"]), fields[object_name].clone()))
}

/// Refuses text longer than `max` bytes, judged first, then text that is not
/// UTF-8, naming the field.
fn bounded_text(field: &str, text: &[u8], max: usize) -> Result<(), FrameError> {
    if text.len() > max {
        return Err(FrameError::TextTooLong(format!(
            "a {field} of {} bytes, over {max}",
            text.len()
        )));
    }
    if std::str::from_utf8(text).is_err() {
        return Err(FrameError::InvalidText(format!("the {field}")));
    }
    Ok(())
}

/// Refuses a key that is not an identity key.
fn identity_signer(key: &NodeKey) -> Result<(), FrameError> {
    if key.purpose() != Purpose::Identity {
        return Err(FrameError::Unsignable);
    }
    Ok(())
}

fn protocol_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Int(n) if *n >= 0 && *n < i128::from(MAX_PROTOCOL_INT) => Some(*n as u64),
        _ => None,
    }
}

fn text_of(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        _ => String::new(),
    }
}

fn bytes_of(v: &Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b.clone(),
        _ => Vec::new(),
    }
}

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    let mut out = [0u8; N];
    if let Value::Bytes(b) = v {
        if b.len() == N {
            out.copy_from_slice(b);
        }
    }
    out
}

fn entry(name: &str, value: Value) -> (Value, Value) {
    (Value::text(name), value)
}

fn uint(n: u64) -> Value {
    Value::Int(i128::from(n))
}

/// Whether a reply's, relay error's or stream frame's request_id and
/// request_hash are `request`'s.
fn names_request(fields: &Fields, request: &VerifiedRequest) -> bool {
    fields.get("request_id") == Some(&Value::Bytes(request.request_id.to_vec()))
        && fields.get("request_hash") == Some(&Value::Bytes(request.request_hash.to_vec()))
}

/// The envelope a control frame carries (WIRE_1_0.md section 3.1): version,
/// frame_type, a fresh frame_id (UUID v7) and sent_at_ms. A key the frame has
/// no value for is left out, so one frame has one encoding.
fn base(frame_type: &str) -> Vec<(Value, Value)> {
    vec![
        entry("version", Value::Int(i128::from(PROTOCOL_VERSION))),
        entry("frame_type", Value::text(frame_type)),
        entry("frame_id", Value::Bytes(crate::uuid_v7::new().to_vec())),
        entry("sent_at_ms", uint(crate::uuid_v7::now_ms())),
    ]
}

/// Replaces `fields`' entry for `key`, or appends one: a raw push over a base
/// field would put two entries under one key.
fn with_field(mut fields: Vec<(Value, Value)>, key: &str, value: Value) -> Vec<(Value, Value)> {
    match fields.iter_mut().find(|(k, _)| *k == Value::text(key)) {
        Some(slot) => slot.1 = value,
        None => fields.push(entry(key, value)),
    }
    fields
}
