//! Stream frames (D25 item 5): STREAM_DATA, STREAM_END, STREAM_ERROR and
//! STREAM_REPLY. A provider's are signed objects under MACULA-PQ-STREAM-V1
//! that carry the provider's key on the first frame, seq 0, and leave it out
//! after; a caller's are held objects under MACULA-PQ-CALLER-STREAM-V1,
//! verified with the key its STREAM_OPEN carried. Each side's seq runs from 0
//! without a gap, and nothing follows a side's STREAM_END.

use crate::cbor::Value;
use crate::node_key::{node_id_of, NodeKey};
use crate::profile::Profile;
use crate::signed_object::{
    sign_held_object, sign_object, verify_held_object, verify_object, VerifiedObject,
};

use super::{
    bounded_text, check_payload, entry, fixed, has_fields, identity_signer, names_request,
    object_refusal, protocol_uint, read_fields, received_frame, text_of, uint, FrameError,
    RequestType, Rule, VerifiedRequest, CALLER_STREAM_LABEL, MAX_ERROR_CODE_BYTES,
    MAX_ERROR_TEXT_BYTES, MAX_PROTOCOL_INT, PROTOCOL_VERSION, STREAM_LABEL,
};

const STREAM_DATA: &str = "stream_data";
const STREAM_END: &str = "stream_end";
const STREAM_ERROR: &str = "stream_error";
const STREAM_REPLY: &str = "stream_reply";

/// Who pushes data on a stream: the provider (ServerStream), the caller
/// (ClientStream), or both (Bidi).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    ServerStream,
    ClientStream,
    Bidi,
}

impl StreamMode {
    pub fn name(self) -> &'static str {
        match self {
            StreamMode::ServerStream => "server_stream",
            StreamMode::ClientStream => "client_stream",
            StreamMode::Bidi => "bidi",
        }
    }

    pub fn parse(name: &str) -> Option<StreamMode> {
        match name {
            "server_stream" => Some(StreamMode::ServerStream),
            "client_stream" => Some(StreamMode::ClientStream),
            "bidi" => Some(StreamMode::Bidi),
            _ => None,
        }
    }
}

/// How a STREAM_DATA's body reads: raw bytes, or a structured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEncoding {
    Raw,
    Msgpack,
}

impl StreamEncoding {
    fn name(self) -> &'static str {
        match self {
            StreamEncoding::Raw => "raw",
            StreamEncoding::Msgpack => "msgpack",
        }
    }
}

/// Which directions a STREAM_END closes: this side's sending, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Send,
    Both,
}

impl StreamRole {
    fn name(self) -> &'static str {
        match self {
            StreamRole::Send => "send",
            StreamRole::Both => "both",
        }
    }
}

/// A stream frame's own fields, each with its sender's seq on the stream.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamFields {
    /// One chunk: a raw body is a byte string, a msgpack body any value the
    /// wire carries.
    Data {
        seq: u64,
        encoding: StreamEncoding,
        body: Value,
    },
    /// The last frame of its sender's side.
    End { seq: u64, role: StreamRole },
    /// An error: a code of at most 64 bytes and a message of at most 256.
    Error {
        seq: u64,
        code: String,
        message: String,
    },
    /// A provider's terminal value for a client_stream or bidi stream.
    Reply { seq: u64, payload: Value },
}

impl StreamFields {
    fn seq(&self) -> u64 {
        match self {
            StreamFields::Data { seq, .. }
            | StreamFields::End { seq, .. }
            | StreamFields::Error { seq, .. }
            | StreamFields::Reply { seq, .. } => *seq,
        }
    }

    fn frame_type(&self) -> &'static str {
        match self {
            StreamFields::Data { .. } => STREAM_DATA,
            StreamFields::End { .. } => STREAM_END,
            StreamFields::Error { .. } => STREAM_ERROR,
            StreamFields::Reply { .. } => STREAM_REPLY,
        }
    }
}

/// A stream frame that verified against its stream: its signer's key id and
/// its fields.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedStreamFrame {
    pub signer: [u8; 32],
    pub fields: StreamFields,
}

/// What a verifier holds for one stream: the verified STREAM_OPEN and, for
/// each side, the next seq and whether it has ended, and for the provider the
/// key and signer its first frame carried. Each verification returns the
/// next state, which replaces this one: a state has one owner.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamState {
    open: VerifiedRequest,
    mode: StreamMode,
    provider: Side,
    caller: Side,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct Side {
    next: u64,
    ended: bool,
    key: Option<Vec<u8>>,
    signer: [u8; 32],
}

/// The state a verifier starts a stream with: nothing seen from either side
/// yet. `open` must be a verified STREAM_OPEN.
pub fn open_stream(open: &VerifiedRequest) -> Result<StreamState, FrameError> {
    match (open.frame_type, open.mode) {
        (RequestType::StreamOpen, Some(mode)) => Ok(StreamState {
            open: open.clone(),
            mode,
            provider: Side::default(),
            caller: Side::default(),
        }),
        _ => Err(FrameError::OutOfRange(
            "a stream opens on a STREAM_OPEN".into(),
        )),
    }
}

/// Signs a provider's stream frame for a verified STREAM_OPEN with the
/// provider's identity key, whose key id must be the STREAM_OPEN's target.
/// The first frame, seq 0, carries the key; the later ones leave it out.
pub fn sign_provider_stream(
    fields: &StreamFields,
    open: &VerifiedRequest,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    let tbs = stream_build(fields, open, key, false)?;
    let object = if fields.seq() == 0 {
        sign_object(STREAM_LABEL, &tbs, key)
            .map_err(object_refusal)?
            .to_value()
    } else {
        sign_held_object(STREAM_LABEL, &tbs, key)
            .map_err(object_refusal)?
            .to_value()
    };
    Ok(stream_frame(fields.frame_type(), "stream", object))
}

/// Signs a caller's stream frame for a verified STREAM_OPEN with the caller's
/// identity key, whose key id must be the STREAM_OPEN's caller. A caller sends
/// no STREAM_REPLY, and no STREAM_DATA in a server_stream.
pub fn sign_caller_stream(
    fields: &StreamFields,
    open: &VerifiedRequest,
    key: &NodeKey,
) -> Result<Value, FrameError> {
    let tbs = stream_build(fields, open, key, true)?;
    let object = sign_held_object(CALLER_STREAM_LABEL, &tbs, key).map_err(object_refusal)?;
    Ok(stream_frame(
        fields.frame_type(),
        "caller_stream",
        object.to_value(),
    ))
}

/// A stream frame build's checks in macula's order: the key against its
/// side's sender, the frame types its side sends, the text, the body or
/// payload, then the ranges. Returns the signed fields.
fn stream_build(
    fields: &StreamFields,
    open: &VerifiedRequest,
    key: &NodeKey,
    caller: bool,
) -> Result<Vec<(Value, Value)>, FrameError> {
    identity_signer(key)?;
    let sender = if caller { open.caller } else { open.target };
    if open.frame_type != RequestType::StreamOpen || open.mode.is_none() || key.key_id() != sender {
        return Err(FrameError::Unsignable);
    }
    if caller {
        match fields {
            StreamFields::Reply { .. } => {
                return Err(FrameError::NotAllowed("a caller's STREAM_REPLY".into()))
            }
            StreamFields::Data { .. } if open.mode == Some(StreamMode::ServerStream) => {
                return Err(FrameError::NotAllowed(
                    "a caller's STREAM_DATA in a server_stream".into(),
                ))
            }
            _ => {}
        }
    }
    if let StreamFields::Error { code, message, .. } = fields {
        bounded_text("code", code.as_bytes(), MAX_ERROR_CODE_BYTES)?;
        bounded_text("message", message.as_bytes(), MAX_ERROR_TEXT_BYTES)?;
    }
    match fields {
        StreamFields::Data {
            encoding: StreamEncoding::Msgpack,
            body,
            ..
        } => check_payload(body)?,
        StreamFields::Reply { payload, .. } => check_payload(payload)?,
        _ => {}
    }
    let mut tbs = match fields {
        StreamFields::Data { encoding, body, .. } => {
            if *encoding == StreamEncoding::Raw && !matches!(body, Value::Bytes(_)) {
                return Err(FrameError::OutOfRange(
                    "a raw body that is not a byte string".into(),
                ));
            }
            vec![
                entry("encoding", Value::text(encoding.name())),
                entry("body", body.clone()),
            ]
        }
        StreamFields::End { role, .. } => vec![entry("role", Value::text(role.name()))],
        StreamFields::Error { code, message, .. } => {
            vec![
                entry("code", Value::text(code.clone())),
                entry("message", Value::text(message.clone())),
            ]
        }
        StreamFields::Reply { payload, .. } => vec![entry("payload", payload.clone())],
    };
    if fields.seq() >= MAX_PROTOCOL_INT {
        return Err(FrameError::OutOfRange("a seq of 2^53 or more".into()));
    }
    tbs.extend([
        entry("frame_type", Value::text(fields.frame_type())),
        entry("request_id", Value::Bytes(open.request_id.to_vec())),
        entry("request_hash", Value::Bytes(open.request_hash.to_vec())),
        entry("signer", Value::Bytes(key.key_id().to_vec())),
        entry("seq", uint(fields.seq())),
    ]);
    Ok(tbs)
}

fn stream_frame(frame_type: &str, object_name: &str, object: Value) -> Value {
    Value::Map(vec![
        entry("version", Value::Int(i128::from(PROTOCOL_VERSION))),
        entry("frame_type", Value::text(frame_type)),
        entry(object_name, object),
    ])
}

const PROVIDER_TYPES: &[&str] = &[STREAM_DATA, STREAM_END, STREAM_ERROR, STREAM_REPLY];
const CALLER_TYPES: &[&str] = &[STREAM_DATA, STREAM_END, STREAM_ERROR];

/// Verifies a provider's received stream frame against its stream's state,
/// and returns the frame and the stream's next state. Before the provider's
/// first frame the state holds no provider key, so a frame without one is out
/// of order. The first frame's signer is the key id of the key it carries and
/// the STREAM_OPEN's target, with seq 0; later frames verify with that key,
/// name that signer and carry no key.
pub fn verify_provider_stream(
    frame: &Value,
    state: &StreamState,
    profile: Profile,
) -> Result<(VerifiedStreamFrame, StreamState), FrameError> {
    let (frame_type, object) =
        received_frame(frame, "stream", Rule::StreamObject, &[], PROVIDER_TYPES)
            .ok_or(FrameError::Malformed)?;
    if state.provider.ended {
        return Err(FrameError::StreamEnded);
    }
    let carries_key = object.get("key").is_some();
    let Some(held_key) = &state.provider.key else {
        return provider_first(&frame_type, &object, carries_key, state, profile);
    };
    let verified = if carries_key {
        verify_object(STREAM_LABEL, &object, profile)
    } else {
        verify_held_object(STREAM_LABEL, &object, held_key, profile)
    }
    .map_err(object_refusal)?;
    if &verified.key != held_key {
        return Err(FrameError::KeyIdMismatch);
    }
    let (signer, fields, read) = stream_read(&frame_type, &verified)?;
    if signer != state.provider.signer {
        return Err(FrameError::KeyIdMismatch);
    }
    if !names_request(&read, &state.open) {
        return Err(FrameError::RequestMismatch);
    }
    if fields.seq() != state.provider.next {
        return Err(FrameError::SeqMismatch);
    }
    if carries_key {
        return Err(FrameError::Malformed);
    }
    let mut next = state.clone();
    next.provider.next = fields.seq() + 1;
    next.provider.ended = frame_type == STREAM_END;
    Ok((VerifiedStreamFrame { signer, fields }, next))
}

fn provider_first(
    frame_type: &str,
    object: &Value,
    carries_key: bool,
    state: &StreamState,
    profile: Profile,
) -> Result<(VerifiedStreamFrame, StreamState), FrameError> {
    if !carries_key {
        return Err(FrameError::SeqMismatch);
    }
    let verified = verify_object(STREAM_LABEL, object, profile).map_err(object_refusal)?;
    let (signer, fields, read) = stream_read(frame_type, &verified)?;
    if signer != node_id_of(&verified.key, profile) {
        return Err(FrameError::KeyIdMismatch);
    }
    if !names_request(&read, &state.open) {
        return Err(FrameError::RequestMismatch);
    }
    if signer != state.open.target {
        return Err(FrameError::NotTheTarget);
    }
    if fields.seq() != 0 {
        return Err(FrameError::SeqMismatch);
    }
    let mut next = state.clone();
    next.provider = Side {
        next: 1,
        ended: frame_type == STREAM_END,
        key: Some(verified.key),
        signer,
    };
    Ok((VerifiedStreamFrame { signer, fields }, next))
}

/// Verifies a caller's received stream frame against its stream's state,
/// with the STREAM_OPEN's key, and returns the frame and the next state. A
/// caller sends no STREAM_DATA in a server_stream.
pub fn verify_caller_stream(
    frame: &Value,
    state: &StreamState,
    profile: Profile,
) -> Result<(VerifiedStreamFrame, StreamState), FrameError> {
    let (frame_type, object) =
        received_frame(frame, "caller_stream", Rule::HeldObject, &[], CALLER_TYPES)
            .ok_or(FrameError::Malformed)?;
    if state.caller.ended {
        return Err(FrameError::StreamEnded);
    }
    let verified = verify_held_object(CALLER_STREAM_LABEL, &object, &state.open.key, profile)
        .map_err(object_refusal)?;
    let (signer, fields, read) = stream_read(&frame_type, &verified)?;
    if frame_type == STREAM_DATA && state.mode == StreamMode::ServerStream {
        return Err(FrameError::Malformed);
    }
    if signer != state.open.caller {
        return Err(FrameError::KeyIdMismatch);
    }
    if !names_request(&read, &state.open) {
        return Err(FrameError::RequestMismatch);
    }
    if fields.seq() != state.caller.next {
        return Err(FrameError::SeqMismatch);
    }
    let mut next = state.clone();
    next.caller.next = fields.seq() + 1;
    next.caller.ended = frame_type == STREAM_END;
    Ok((VerifiedStreamFrame { signer, fields }, next))
}

/// A stream frame's signed fields read through its type's table: frame_type,
/// request_id, request_hash, signer and seq, and exactly the fields of its
/// type, a raw body a byte string.
fn stream_read(
    frame_type: &str,
    verified: &VerifiedObject,
) -> Result<([u8; 32], StreamFields, super::Fields), FrameError> {
    let types: &'static [&'static str] = match frame_type {
        STREAM_DATA => &[STREAM_DATA],
        STREAM_END => &[STREAM_END],
        STREAM_ERROR => &[STREAM_ERROR],
        _ => &[STREAM_REPLY],
    };
    let table = [
        ("frame_type", Rule::TextIn(types)),
        ("alg", Rule::Any),
        ("request_id", Rule::BytesOf(16)),
        ("request_hash", Rule::BytesOf(48)),
        ("signer", Rule::BytesOf(32)),
        ("seq", Rule::ProtocolUint),
        ("encoding", Rule::TextIn(&["raw", "msgpack"])),
        ("body", Rule::Any),
        ("role", Rule::TextIn(&["send", "both"])),
        ("code", Rule::TextWithin(MAX_ERROR_CODE_BYTES)),
        ("message", Rule::TextWithin(MAX_ERROR_TEXT_BYTES)),
        ("payload", Rule::Any),
    ];
    let fields = read_fields(&verified.fields, &table).ok_or(FrameError::Malformed)?;
    if !has_fields(
        &fields,
        &["frame_type", "request_id", "request_hash", "signer", "seq"],
    ) {
        return Err(FrameError::Malformed);
    }
    let own: &[&str] = match frame_type {
        STREAM_DATA => &["encoding", "body"],
        STREAM_END => &["role"],
        STREAM_ERROR => &["code", "message"],
        _ => &["payload"],
    };
    let carried = 5 + own.len() + usize::from(fields.contains_key("alg"));
    if !has_fields(&fields, own) || fields.len() != carried {
        return Err(FrameError::Malformed);
    }
    let seq = protocol_uint(&fields["seq"]).unwrap_or(0);
    let parsed = match frame_type {
        STREAM_DATA => {
            let encoding = if text_of(&fields["encoding"]) == "raw" {
                StreamEncoding::Raw
            } else {
                StreamEncoding::Msgpack
            };
            if encoding == StreamEncoding::Raw && !matches!(fields["body"], Value::Bytes(_)) {
                return Err(FrameError::Malformed);
            }
            StreamFields::Data {
                seq,
                encoding,
                body: fields["body"].clone(),
            }
        }
        STREAM_END => StreamFields::End {
            seq,
            role: if text_of(&fields["role"]) == "send" {
                StreamRole::Send
            } else {
                StreamRole::Both
            },
        },
        STREAM_ERROR => StreamFields::Error {
            seq,
            code: text_of(&fields["code"]),
            message: text_of(&fields["message"]),
        },
        _ => StreamFields::Reply {
            seq,
            payload: fields["payload"].clone(),
        },
    };
    Ok((fixed(&fields["signer"]), parsed, fields))
}
