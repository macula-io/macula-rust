//! End-to-end payload confidentiality on a link, as macula 13 has it (E2E
//! design §5, §8, amendment A1; seal scheme 1), the caller's side. A call or a
//! stream to a provider states how it is kept: sealed to the key the
//! provider's verified advertisement names, or in the clear by the
//! application's own decision. A sealed request is never answered in the
//! clear except from a closed set of refusals that carry no application data,
//! and never falls back to the clear.

use std::fmt;

use crate::cbor::{self, Value};
use crate::frame::{
    self, Sealed, StreamEncoding, StreamFields, VerifiedReply, VerifiedRequest, VerifiedStreamFrame,
};
use crate::profile::Profile;
use crate::seal::{self, Direction, Parties, KEY_ID_SIZE, NONCE_SIZE};

use super::LinkError;

/// How a call or an open to a provider is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seal {
    /// In the clear, by the application's own decision: only for a provider
    /// whose advertisement names no key.
    Clear,
    /// Sealed to this KEM key as carried, the one the provider's verified
    /// advertisement names.
    To(Vec<u8>),
}

/// The refusal codes of a sealed request.
pub(super) const CODE_SEALED_REFUSED: &str = "sealed_refused";

/// A sealed_refused's detail from a node that holds no KEM key.
pub(super) const NO_KEY_DETAIL: &str = "this node opens no sealed payload";

/// The codes a provider may answer a sealed request with in the clear (E2E
/// design §5.1): the admission refusals, which carry no application data, a
/// STREAM_OPEN's session admission included. sealed_refused is read on its
/// own.
const CLEAR_REFUSALS: &[&str] = &[
    "expired",
    "not_yet_valid",
    "request_id_reused",
    "request_copy",
    "reply_not_kept",
    "caller_quota",
    "share_full",
    "admission_full",
    "too_many_sessions",
    "unavailable",
];

/// Whether `code` may answer a sealed request in the clear.
pub fn is_clear_refusal(code: &str) -> bool {
    CLEAR_REFUSALS.contains(&code)
}

/// Why a call could not be kept confidential, as macula's
/// {error, {confidentiality, Reason}} names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialityReason {
    /// The provider names a key this node cannot seal to, or none where the
    /// call requires one.
    NoKemKey,
    /// The provider's sealed_refused named one key and its advertisement
    /// another.
    KeyMismatch,
    /// A sealed answer that does not open. It is signed by the provider and
    /// bound to its request, so it is the only answer the request gets.
    ReplyNotOpened,
    /// A call or an open to a provider that states neither a key to seal to
    /// nor the clear. Nothing is sent.
    NoSignedState,
}

impl ConfidentialityReason {
    /// The reason as macula names it.
    pub fn name(self) -> &'static str {
        match self {
            ConfidentialityReason::NoKemKey => "no_kem_key",
            ConfidentialityReason::KeyMismatch => "key_mismatch",
            ConfidentialityReason::ReplyNotOpened => "reply_not_opened",
            ConfidentialityReason::NoSignedState => "no_signed_state",
        }
    }
}

/// A call or an open that could not be kept confidential, and so was not
/// made, or failed rather than be taken in the clear. `advertised` holds the
/// key ids the trusted providers' advertisements named; `named` is the key
/// a provider's refusal named, for a key mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialityError {
    pub reason: ConfidentialityReason,
    pub advertised: Vec<[u8; KEY_ID_SIZE]>,
    pub named: Option<[u8; KEY_ID_SIZE]>,
}

impl ConfidentialityError {
    /// The error for `reason`, naming no key.
    pub fn new(reason: ConfidentialityReason) -> ConfidentialityError {
        ConfidentialityError {
            reason,
            advertised: Vec::new(),
            named: None,
        }
    }
}

impl fmt::Display for ConfidentialityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "confidentiality: {}", self.reason.name())?;
        for id in &self.advertised {
            write!(f, " {}", hex(id))?;
        }
        if let Some(named) = &self.named {
            write!(f, " (the provider named {})", hex(named))?;
        }
        Ok(())
    }
}

fn hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn confidentiality(reason: ConfidentialityReason) -> LinkError {
    LinkError::Confidentiality(ConfidentialityError::new(reason))
}

/// Refuses a call or an open to a provider that does not say how it is kept.
/// A call to the connected station (the zero target, or its node_id) is
/// always clear.
pub(super) fn stated(
    target: &[u8; 32],
    station: &[u8; 32],
    seal: &Option<Seal>,
) -> Result<(), LinkError> {
    match seal {
        None if target != &[0; 32] && target != station => {
            Err(confidentiality(ConfidentialityReason::NoSignedState))
        }
        _ => Ok(()),
    }
}

/// What a sealed request agreed: the key id, the reply key, a stream's two
/// keys, and the routing fields its answers are bound to.
#[derive(Debug, Clone)]
pub(super) struct CallSeal {
    pub(super) key_id: [u8; KEY_ID_SIZE],
    k_rep: [u8; 32],
    pub(super) k_c2p: [u8; 32],
    pub(super) k_p2c: [u8; 32],
    request: seal::Request,
}

/// A request's payload sealed to the provider key carried as `to`, in place
/// of its clear payload, and the keys the caller keeps. A key that is not
/// one of this profile's is no_kem_key.
#[allow(clippy::too_many_arguments)]
pub(super) fn sealed_request(
    profile: Profile,
    to: &[u8],
    frame_type: &str,
    realm: [u8; 32],
    procedure: &str,
    caller: [u8; 32],
    target: [u8; 32],
    request_id: [u8; 16],
    deadline: u64,
    payload: &Value,
) -> Result<(Sealed, CallSeal), LinkError> {
    let key = seal::parse_public_key(profile, to)
        .map_err(|_| confidentiality(ConfidentialityReason::NoKemKey))?;
    frame::check_payload(payload)?;
    let (secret, kem_ct) =
        seal::sender_secret(&key).map_err(|_| confidentiality(ConfidentialityReason::NoKemKey))?;
    let parties = Parties {
        request_id,
        caller,
        target,
    };
    let (k_req, k_rep) = seal::call_keys(&secret, frame_type, &parties);
    let (k_c2p, k_p2c) = seal::stream_keys(&secret, &parties);
    let request = seal::Request {
        frame_type: frame_type.to_string(),
        realm,
        procedure: procedure.to_string(),
        caller,
        target,
        request_id,
        deadline,
    };
    let plain = cbor::encode(payload)
        .map_err(|e| LinkError::Frame(frame::FrameError::Payload(e.to_string())))?;
    let key_id = key.key_id();
    let sealed = Sealed {
        key_id,
        kem_ct: Some(kem_ct),
        nonce: None,
        ct: seal::seal(
            &k_req,
            &[0; NONCE_SIZE],
            &seal::request_aad(&request),
            &plain,
        ),
    };
    Ok((
        sealed,
        CallSeal {
            key_id,
            k_rep,
            k_c2p,
            k_p2c,
            request,
        },
    ))
}

/// The key id a sealed_refused's detail names, `None` for none.
pub(super) fn refused_key(detail: Option<&str>) -> Option<[u8; KEY_ID_SIZE]> {
    let detail = detail?;
    if detail.len() != 2 * KEY_ID_SIZE {
        return None;
    }
    let mut id = [0; KEY_ID_SIZE];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(detail.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

/// What a verified provider reply means to a call: for a sealed call, a
/// sealed answer under the request's key id opened; a clear sealed_refused
/// naming the provider's key; a clear refusal from the closed set; anything
/// else clear refused, never taken as the answer. For a clear call, a sealed
/// answer is one this node sealed nothing for.
pub(super) fn reply_outcome(
    reply: VerifiedReply,
    request: &VerifiedRequest,
    seal: Option<&CallSeal>,
) -> Result<Value, LinkError> {
    let provider = |code: String, detail: Option<String>| LinkError::Provider {
        responded_by: reply.responded_by,
        code,
        detail,
    };
    let Some(s) = seal else {
        return match (reply.sealed.is_some(), reply.frame_type) {
            (true, _) => Err(provider(CODE_SEALED_REFUSED.into(), None)),
            (false, frame::ReplyType::Result) => Ok(reply.payload.unwrap_or(Value::Null)),
            (false, frame::ReplyType::Error) => {
                Err(provider(reply.code.unwrap_or_default(), reply.detail))
            }
        };
    };
    let not_opened = || confidentiality(ConfidentialityReason::ReplyNotOpened);
    match (&reply.sealed, reply.frame_type, reply.code.as_deref()) {
        (Some(sealed), frame_type, _) => {
            // As macula's open_reply/4: an answer naming another key than
            // the request's is not opened.
            if sealed.key_id != s.key_id {
                return Err(not_opened());
            }
            let nonce: [u8; NONCE_SIZE] = sealed
                .nonce
                .as_deref()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(not_opened)?;
            let name = match frame_type {
                frame::ReplyType::Result => seal::FRAME_RESULT,
                frame::ReplyType::Error => seal::FRAME_ERROR,
            };
            let aad = seal::reply_aad(&s.request, name, &request.request_hash, &reply.responded_by);
            let plain = seal::open(&s.k_rep, &nonce, &aad, &sealed.ct).map_err(|_| not_opened())?;
            match frame_type {
                frame::ReplyType::Result => cbor::decode(&plain).map_err(|_| not_opened()),
                frame::ReplyType::Error => {
                    let (code, detail) =
                        seal::open_error_plain(&plain).map_err(|_| not_opened())?;
                    Err(provider(code, detail))
                }
            }
        }
        (None, frame::ReplyType::Error, Some(CODE_SEALED_REFUSED)) => {
            Err(LinkError::SealedRefused {
                named: refused_key(reply.detail.as_deref()),
            })
        }
        (None, frame::ReplyType::Error, Some(code)) if is_clear_refusal(code) => {
            Err(provider(code.to_string(), reply.detail.clone()))
        }
        _ => Err(LinkError::ClearAnswerToSealed),
    }
}

/// One side's keys for a sealed stream: a caller's frames seal under k_c2p
/// with their seq as the nonce; a provider's under k_p2c with a random nonce
/// each, carried. A STREAM_END has nothing to seal.
#[derive(Debug, Clone)]
pub(super) struct StreamSeal {
    key_id: [u8; KEY_ID_SIZE],
    request_id: [u8; 16],
    send: [u8; 32],
    recv: [u8; 32],
}

impl StreamSeal {
    /// The caller's side of the stream `s` opened.
    pub(super) fn caller(s: &CallSeal) -> StreamSeal {
        StreamSeal {
            key_id: s.key_id,
            request_id: s.request.request_id,
            send: s.k_c2p,
            recv: s.k_p2c,
        }
    }

    /// `fields` with its body, payload, or code and message sealed. The
    /// plaintext of a raw chunk is its bytes, of a structured chunk or a
    /// reply the value's CBOR, and of a STREAM_ERROR cbor([code, message]),
    /// as macula_stream's plain_of/1 has them.
    pub(super) fn sealed(&self, fields: StreamFields) -> Result<StreamFields, LinkError> {
        let seq = match &fields {
            StreamFields::Data { seq, .. }
            | StreamFields::Error { seq, .. }
            | StreamFields::Reply { seq, .. } => *seq,
            _ => return Ok(fields),
        };
        let (frame_type, plain) = match &fields {
            StreamFields::Data {
                encoding: StreamEncoding::Raw,
                body: Value::Bytes(b),
                ..
            } => ("stream_data", b.clone()),
            StreamFields::Data {
                encoding: StreamEncoding::Raw,
                ..
            } => {
                return Err(LinkError::Frame(frame::FrameError::OutOfRange(
                    "a raw body that is not a byte string".into(),
                )))
            }
            StreamFields::Data { body, .. } => {
                frame::check_payload(body)?;
                ("stream_data", encoded(body)?)
            }
            StreamFields::Reply { payload, .. } => {
                frame::check_payload(payload)?;
                ("stream_reply", encoded(payload)?)
            }
            StreamFields::Error { code, message, .. } => {
                ("stream_error", seal::error_plain(code, message))
            }
            _ => unreachable!("only the three sealable frames reach here"),
        };
        let aad = seal::stream_aad(
            frame_type,
            &self.request_id,
            seq,
            Direction::CallerToProvider,
        );
        let sealed = Sealed {
            key_id: self.key_id,
            kem_ct: None,
            nonce: None,
            ct: seal::seal(&self.send, &seal::stream_nonce(seq), &aad, &plain),
        };
        Ok(match fields {
            StreamFields::Data { encoding, .. } => StreamFields::SealedData {
                seq,
                encoding,
                sealed,
            },
            StreamFields::Reply { .. } => StreamFields::SealedReply { seq, sealed },
            _ => StreamFields::SealedError { seq, sealed },
        })
    }

    /// A verified sealed frame from the provider with its body, payload, or
    /// code and message opened; one that does not open, or opens to nothing
    /// its type holds, is reply_not_opened.
    pub(super) fn opened(&self, frame: VerifiedStreamFrame) -> Result<StreamFields, LinkError> {
        let not_opened = || confidentiality(ConfidentialityReason::ReplyNotOpened);
        let (seq, frame_type, sealed) = match &frame.fields {
            StreamFields::SealedData { seq, sealed, .. } => (*seq, "stream_data", sealed),
            StreamFields::SealedReply { seq, sealed } => (*seq, "stream_reply", sealed),
            StreamFields::SealedError { seq, sealed } => (*seq, "stream_error", sealed),
            _ => return Ok(frame.fields),
        };
        // As macula_stream's opened/5: a frame naming another key than the
        // stream's is not opened.
        if sealed.key_id != self.key_id {
            return Err(not_opened());
        }
        let nonce: [u8; NONCE_SIZE] = sealed
            .nonce
            .as_deref()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(not_opened)?;
        let aad = seal::stream_aad(
            frame_type,
            &self.request_id,
            seq,
            Direction::ProviderToCaller,
        );
        let plain = seal::open(&self.recv, &nonce, &aad, &sealed.ct).map_err(|_| not_opened())?;
        match frame.fields {
            StreamFields::SealedData {
                encoding: StreamEncoding::Raw,
                ..
            } => Ok(StreamFields::Data {
                seq,
                encoding: StreamEncoding::Raw,
                body: Value::Bytes(plain),
            }),
            StreamFields::SealedData { encoding, .. } => Ok(StreamFields::Data {
                seq,
                encoding,
                body: cbor::decode(&plain).map_err(|_| not_opened())?,
            }),
            StreamFields::SealedReply { .. } => Ok(StreamFields::Reply {
                seq,
                payload: cbor::decode(&plain).map_err(|_| not_opened())?,
            }),
            _ => {
                let (code, message) = seal::open_error_plain(&plain).map_err(|_| not_opened())?;
                Ok(StreamFields::Error {
                    seq,
                    code,
                    message: message.unwrap_or_default(),
                })
            }
        }
    }
}

fn encoded(v: &Value) -> Result<Vec<u8>, LinkError> {
    cbor::encode(v).map_err(|e| LinkError::Frame(frame::FrameError::Payload(e.to_string())))
}

/// A verified frame from the provider as a caller's stream takes it, as
/// macula_stream's peer_event/2 does. A clear stream takes no sealed frame:
/// that ends the session as sealed_refused, this node holding no key for it.
/// A sealed stream opens each sealed frame before anything of it takes
/// effect, and takes nothing clear but a STREAM_END and the provider's
/// refusal of the open at seq 0: sealed_refused, or one from the closed set.
/// Anything else clear is [`LinkError::ClearAnswerToSealed`].
pub(super) fn unsealed(
    frame: VerifiedStreamFrame,
    sealing: Option<&StreamSeal>,
) -> Result<StreamFields, LinkError> {
    let sealed = matches!(
        frame.fields,
        StreamFields::SealedData { .. }
            | StreamFields::SealedReply { .. }
            | StreamFields::SealedError { .. }
    );
    match (sealing, sealed, &frame.fields) {
        (None, true, _) => Err(LinkError::Stream {
            code: CODE_SEALED_REFUSED.into(),
            message: NO_KEY_DETAIL.into(),
            relay: false,
        }),
        (None, false, _) => Ok(frame.fields),
        (Some(s), true, _) => s.opened(frame),
        (Some(_), false, StreamFields::End { .. }) => Ok(frame.fields),
        (Some(_), false, StreamFields::Error { seq: 0, code, .. })
            if code == CODE_SEALED_REFUSED || is_clear_refusal(code) =>
        {
            Ok(frame.fields)
        }
        (Some(_), false, _) => Err(LinkError::ClearAnswerToSealed),
    }
}
