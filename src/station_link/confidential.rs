//! End-to-end payload confidentiality on a link, as macula 13 has it (E2E
//! design §5, §8, amendment A1; seal scheme 1). A provider that names its KEM
//! key in its advertisement opens the requests sealed to it and seals every
//! answer to them; what it cannot open it refuses in the clear, from a
//! closed set that carries no application data. A call or a stream to a
//! provider states how it is kept: sealed to the key the provider's verified
//! advertisement names, or in the clear by the application's own decision.
//! A sealed request is never answered in the clear except from that closed
//! set, and never falls back to the clear.

use std::fmt;
use std::str::FromStr;

use crate::cbor::{self, Value};
use crate::frame::{
    self, Sealed, StreamEncoding, StreamFields, VerifiedReply, VerifiedRequest, VerifiedStreamFrame,
};
use crate::profile::Profile;
use crate::record::CLOCK_TOLERANCE_MS;
use crate::seal::{self, Direction, Keyring, Parties, KEY_ID_SIZE, NONCE_SIZE};

use super::LinkError;

/// How a procedure takes its requests, and how a pool's call or open must
/// be kept, as macula-go's stationlink.Confidentiality.
///
/// Serving: `Preferred`, the default, names this node's KEM key in the
/// advertisement when the link's `kem_advertise` is on, and still takes a
/// clear request while the procedure's last keyless advertisement could be
/// served, then refuses it sealed_required. `Required` names the key and
/// refuses every clear request; it needs `kem_advertise` on. `Off` names no
/// key: the procedure is served in the clear.
///
/// Calling through a pool: `Preferred` seals to a provider that names a key
/// and calls one that names none in the clear; `Required` never calls one
/// that names none. `Off` is refused: a clear call is an explicit target's
/// (a [`Seal::Clear`] on a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Confidentiality {
    #[default]
    Preferred,
    Required,
    Off,
}

impl FromStr for Confidentiality {
    type Err = String;

    /// "preferred" (or "", the default), "required" or "off", as macula-go's
    /// options name them.
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "" | "preferred" => Ok(Confidentiality::Preferred),
            "required" => Ok(Confidentiality::Required),
            "off" => Ok(Confidentiality::Off),
            other => Err(format!(
                "confidential is preferred, required or off, not {other:?}"
            )),
        }
    }
}

/// How a call or an open to a provider is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seal {
    /// In the clear, by the application's own decision: only for a provider
    /// whose advertisement names no key. On a link nothing checks that: a
    /// pool refuses a clear call to a provider that names a key, but a
    /// direct [`super::Link`] caller must read the advertisement itself.
    Clear,
    /// Sealed to this KEM key as carried, the one the provider's verified
    /// advertisement names.
    To(Vec<u8>),
}

/// The refusal codes of a sealed request, and of a clear one to a procedure
/// past its keyless window.
pub(super) const CODE_SEALED_REFUSED: &str = "sealed_refused";
pub(super) const CODE_SEALED_REQUIRED: &str = "sealed_required";

/// macula's default and longest advertisement lifetime, which bounds the
/// keyless window.
pub(super) const MAX_ADVERTISEMENT_TTL_MS: i64 = 5 * 60 * 1000;

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
/// keys, and the routing fields its answers are bound to. Showing it gives
/// the key id, never a key.
#[derive(Clone)]
pub(super) struct CallSeal {
    pub(super) key_id: [u8; KEY_ID_SIZE],
    k_rep: [u8; 32],
    pub(super) k_c2p: [u8; 32],
    pub(super) k_p2c: [u8; 32],
    request: seal::Request,
}

impl fmt::Debug for CallSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CallSeal(key id {})", hex(&self.key_id))
    }
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

/// The key id a sealed_refused's detail names, `None` for none: exactly 16
/// lowercase hex digits, as macula writes a key id, and nothing else.
pub(super) fn refused_key(detail: Option<&str>) -> Option<[u8; KEY_ID_SIZE]> {
    let detail = detail?;
    let lowercase_hex = detail.len() == 2 * KEY_ID_SIZE
        && detail
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !lowercase_hex {
        return None;
    }
    let mut id = [0; KEY_ID_SIZE];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&detail[2 * i..2 * i + 2], 16).ok()?;
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

/// Whether a procedure under `confidential` takes a clear request at
/// `now_ms`, as macula's clear_allowed/2 decides it: never when required,
/// always when its advertisement names no key (`keyed_since` is `None`),
/// and once keyed only while its last keyless advertisement could still be
/// served, the longest advertisement lifetime and the clock tolerance from
/// the moment it was first keyed.
pub(super) fn clear_allowed(
    confidential: Confidentiality,
    keyed_since: Option<i64>,
    now_ms: i64,
) -> bool {
    match (confidential, keyed_since) {
        (Confidentiality::Required, _) => false,
        (_, None) => true,
        (_, Some(since)) => now_ms <= since + MAX_ADVERTISEMENT_TTL_MS + CLOCK_TOLERANCE_MS as i64,
    }
}

/// A sealed request opened with this node's keyring: its plaintext payload
/// and the keys it agreed, or the detail of the sealed_refused it is
/// answered with, naming the key this node holds now, or that it holds none.
pub(super) fn opened_request(
    keyring: Option<&Keyring>,
    request: &VerifiedRequest,
) -> Result<(Value, CallSeal), String> {
    let Some(keyring) = keyring else {
        return Err(NO_KEY_DETAIL.into());
    };
    let refused = hex(&keyring.current_id());
    let Some(sealed) = &request.sealed else {
        return Err(refused);
    };
    let key = keyring
        .find(&sealed.key_id)
        .ok_or_else(|| refused.clone())?;
    let kem_ct = sealed.kem_ct.as_deref().ok_or_else(|| refused.clone())?;
    let secret = seal::recipient_secret(&key, kem_ct).map_err(|_| refused.clone())?;
    let frame_type = match request.frame_type {
        frame::RequestType::Call => seal::FRAME_CALL,
        frame::RequestType::StreamOpen => seal::FRAME_STREAM_OPEN,
    };
    let parties = Parties {
        request_id: request.request_id,
        caller: request.caller,
        target: request.target,
    };
    let (k_req, k_rep) = seal::call_keys(&secret, frame_type, &parties);
    let (k_c2p, k_p2c) = seal::stream_keys(&secret, &parties);
    let bound = seal::Request {
        frame_type: frame_type.to_string(),
        realm: request.realm,
        procedure: request.procedure.clone(),
        caller: request.caller,
        target: request.target,
        request_id: request.request_id,
        deadline: request.deadline,
    };
    let plain = seal::open(
        &k_req,
        &[0; NONCE_SIZE],
        &seal::request_aad(&bound),
        &sealed.ct,
    )
    .map_err(|_| refused.clone())?;
    let payload = cbor::decode(&plain).map_err(|_| refused)?;
    Ok((
        payload,
        CallSeal {
            key_id: sealed.key_id,
            k_rep,
            k_c2p,
            k_p2c,
            request: bound,
        },
    ))
}

impl CallSeal {
    /// A RESULT's payload, or an ERROR's cbor([code, detail]), sealed under
    /// the request's reply key with a fresh nonce, carried, bound to the
    /// request and to `responded_by` as the node that answered.
    pub(super) fn sealed_answer(
        &self,
        frame_type: &str,
        plain: &[u8],
        request_hash: &[u8; 48],
        responded_by: &[u8; 32],
    ) -> Result<Sealed, LinkError> {
        let nonce = seal::random_nonce().map_err(|_| LinkError::Io("no randomness".into()))?;
        let aad = seal::reply_aad(&self.request, frame_type, request_hash, responded_by);
        Ok(Sealed {
            key_id: self.key_id,
            kem_ct: None,
            nonce: Some(nonce.to_vec()),
            ct: seal::seal(&self.k_rep, &nonce, &aad, plain),
        })
    }
}

/// A provider seals at most this many frames under random nonces on one
/// stream: GCM's bound, as macula's max_sealed_frames.
const MAX_SEALED_PROVIDER_FRAMES: u64 = 1 << 32;

/// One side's keys for a sealed stream (macula 13's E2E design §5.2): a
/// caller's frames seal under k_c2p with their seq as the nonce; a
/// provider's under k_p2c with a random nonce each, carried, since a
/// provider restarted by a retried open numbers from 0 again. A STREAM_END
/// has nothing to seal. Showing it gives the key id, never a key.
#[derive(Clone)]
pub(super) struct StreamSeal {
    key_id: [u8; KEY_ID_SIZE],
    request_id: [u8; 16],
    caller: bool,
    send: [u8; 32],
    recv: [u8; 32],
}

impl fmt::Debug for StreamSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamSeal(key id {})", hex(&self.key_id))
    }
}

/// What a sealable frame seals: its type's name and its plaintext.
pub(super) struct StreamPlain {
    frame_type: &'static str,
    plain: Vec<u8>,
}

impl StreamSeal {
    /// The caller's side of the stream `s` opened.
    pub(super) fn caller(s: &CallSeal) -> StreamSeal {
        StreamSeal {
            key_id: s.key_id,
            request_id: s.request.request_id,
            caller: true,
            send: s.k_c2p,
            recv: s.k_p2c,
        }
    }

    /// The provider's side of the stream `s` opened.
    pub(super) fn provider(s: &CallSeal) -> StreamSeal {
        StreamSeal {
            key_id: s.key_id,
            request_id: s.request.request_id,
            caller: false,
            send: s.k_p2c,
            recv: s.k_c2p,
        }
    }

    fn directions(&self) -> (Direction, Direction) {
        match self.caller {
            true => (Direction::CallerToProvider, Direction::ProviderToCaller),
            false => (Direction::ProviderToCaller, Direction::CallerToProvider),
        }
    }

    /// What `fields` seals, checked before any nonce is spent: the
    /// plaintext of a raw chunk is its bytes, of a structured chunk or a
    /// reply the value's CBOR, and of a STREAM_ERROR cbor([code, message]),
    /// as macula_stream's plain_of/1 has them. `None` for a STREAM_END,
    /// which goes as it is.
    pub(super) fn plain_of(&self, fields: &StreamFields) -> Result<Option<StreamPlain>, LinkError> {
        let (frame_type, plain) = match fields {
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
            _ => return Ok(None),
        };
        if !self.caller && fields.seq() >= MAX_SEALED_PROVIDER_FRAMES {
            return Err(LinkError::SealedFramesExhausted);
        }
        Ok(Some(StreamPlain { frame_type, plain }))
    }

    /// `fields` with what [`Self::plain_of`] took from it sealed in place.
    /// Each call spends a nonce: the caller's seq or a fresh random one, so
    /// a sender takes the seq before it seals and never seals under it
    /// again.
    pub(super) fn sealed(
        &self,
        fields: StreamFields,
        p: StreamPlain,
    ) -> Result<StreamFields, LinkError> {
        let seq = fields.seq();
        let (nonce, carried) = match self.caller {
            true => (seal::stream_nonce(seq), None),
            false => {
                let nonce =
                    seal::random_nonce().map_err(|_| LinkError::Io("no randomness".into()))?;
                (nonce, Some(nonce.to_vec()))
            }
        };
        let aad = seal::stream_aad(p.frame_type, &self.request_id, seq, self.directions().0);
        let sealed = Sealed {
            key_id: self.key_id,
            kem_ct: None,
            nonce: carried,
            ct: seal::seal(&self.send, &nonce, &aad, &p.plain),
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

    /// A verified sealed frame from the peer with its body, payload, or
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
        // A provider's frame carries its nonce; a caller's is its seq.
        let nonce: [u8; NONCE_SIZE] = match self.caller {
            true => sealed
                .nonce
                .as_deref()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(not_opened)?,
            false => seal::stream_nonce(seq),
        };
        let aad = seal::stream_aad(frame_type, &self.request_id, seq, self.directions().1);
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

/// A verified frame from the peer as a stream takes it, as macula_stream's
/// peer_event/2 does. A clear stream takes no sealed frame: that ends the
/// session as sealed_refused, this node holding no key for it. A sealed
/// stream opens each sealed frame before anything of it takes effect, and
/// takes nothing clear but a STREAM_END and, on a caller's side, the
/// provider's refusal of the open at seq 0: sealed_refused, or one from the
/// closed set. Anything else clear is [`LinkError::ClearAnswerToSealed`].
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
        (Some(s), false, StreamFields::Error { seq: 0, code, .. })
            if s.caller && (code == CODE_SEALED_REFUSED || is_clear_refusal(code)) =>
        {
            Ok(frame.fields)
        }
        (Some(_), false, _) => Err(LinkError::ClearAnswerToSealed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{ReplyType, RequestType};

    const CALLER: [u8; 32] = [1; 32];
    const PROVIDER: [u8; 32] = [2; 32];

    /// A request sealed by a caller to `keyring`'s current key, as the
    /// provider verified it, and the caller's keys.
    fn sealed_to(keyring: &Keyring, frame_type: RequestType) -> (VerifiedRequest, CallSeal) {
        let name = match frame_type {
            RequestType::Call => seal::FRAME_CALL,
            RequestType::StreamOpen => seal::FRAME_STREAM_OPEN,
        };
        let to = keyring.current().public_key().carried().to_vec();
        let (sealed, caller) = sealed_request(
            keyring.profile(),
            &to,
            name,
            [3; 32],
            "~ring",
            CALLER,
            PROVIDER,
            [4; 16],
            1_790_000_000_000,
            &Value::text("secret"),
        )
        .unwrap();
        let request = VerifiedRequest {
            frame_type,
            key: Vec::new(),
            request_hash: [5; 48],
            caller: CALLER,
            request_id: [4; 16],
            realm: [3; 32],
            procedure: "~ring".into(),
            target: PROVIDER,
            deadline: 1_790_000_000_000,
            payload: Value::Null,
            sealed: Some(sealed),
            mode: None,
            token: None,
            proofs: None,
        };
        (request, caller)
    }

    fn clear_reply(frame_type: ReplyType, code: Option<&str>) -> VerifiedReply {
        VerifiedReply {
            frame_type,
            responded_by: PROVIDER,
            payload: code.is_none().then(|| Value::text("in the clear")),
            code: code.map(str::to_string),
            detail: None,
            sealed: None,
        }
    }

    #[test]
    fn a_provider_opens_what_a_caller_sealed_and_its_answer_opens_to_the_caller() {
        let keyring = Keyring::system(Profile::PqHybrid).unwrap();
        let (request, caller) = sealed_to(&keyring, RequestType::Call);
        let (payload, provider) = opened_request(Some(&keyring), &request).unwrap();
        assert_eq!(payload, Value::text("secret"));

        let plain = cbor::encode(&Value::text("answer")).unwrap();
        let sealed = provider
            .sealed_answer(seal::FRAME_RESULT, &plain, &request.request_hash, &PROVIDER)
            .unwrap();
        let reply = VerifiedReply {
            frame_type: ReplyType::Result,
            responded_by: PROVIDER,
            payload: None,
            code: None,
            detail: None,
            sealed: Some(sealed),
        };
        assert_eq!(
            reply_outcome(reply, &request, Some(&caller)),
            Ok(Value::text("answer"))
        );
    }

    #[test]
    fn a_sealed_request_this_node_cannot_open_is_refused_naming_its_key() {
        let keyring = Keyring::system(Profile::PqPure).unwrap();
        let other = Keyring::system(Profile::PqPure).unwrap();
        let (request, _) = sealed_to(&other, RequestType::Call);
        assert_eq!(
            opened_request(Some(&keyring), &request).err(),
            Some(hex(&keyring.current_id()))
        );
        assert_eq!(
            opened_request(None, &request).err().as_deref(),
            Some(NO_KEY_DETAIL)
        );
    }

    /// Venus's review of package 1, observation 2: a forged clear answer to
    /// a sealed call is never taken, unless it is sealed_refused or a
    /// refusal from the closed set.
    #[test]
    fn a_forged_clear_answer_to_a_sealed_call_is_refused() {
        let keyring = Keyring::system(Profile::PqPure).unwrap();
        let (request, caller) = sealed_to(&keyring, RequestType::Call);
        for forged in [
            clear_reply(ReplyType::Result, None),
            clear_reply(ReplyType::Error, Some("handler_error")),
            clear_reply(ReplyType::Error, Some("sealed_required")),
        ] {
            assert_eq!(
                reply_outcome(forged.clone(), &request, Some(&caller)),
                Err(LinkError::ClearAnswerToSealed),
                "{forged:?}"
            );
        }
        assert!(matches!(
            reply_outcome(
                clear_reply(ReplyType::Error, Some("caller_quota")),
                &request,
                Some(&caller)
            ),
            Err(LinkError::Provider { code, .. }) if code == "caller_quota"
        ));
        assert_eq!(
            reply_outcome(
                clear_reply(ReplyType::Error, Some(CODE_SEALED_REFUSED)),
                &request,
                Some(&caller)
            ),
            Err(LinkError::SealedRefused { named: None })
        );
    }

    fn data(seq: u64, body: &[u8]) -> StreamFields {
        StreamFields::Data {
            seq,
            encoding: StreamEncoding::Raw,
            body: Value::Bytes(body.to_vec()),
        }
    }

    fn sealed(side: &StreamSeal, fields: StreamFields) -> StreamFields {
        let plain = side.plain_of(&fields).unwrap().unwrap();
        side.sealed(fields, plain).unwrap()
    }

    fn from(signer: [u8; 32], fields: StreamFields) -> VerifiedStreamFrame {
        VerifiedStreamFrame { signer, fields }
    }

    #[test]
    fn each_side_of_a_sealed_stream_opens_what_the_other_sealed() {
        let keyring = Keyring::system(Profile::PqHybrid).unwrap();
        let (open, caller_seal) = sealed_to(&keyring, RequestType::StreamOpen);
        let (_, provider_seal) = opened_request(Some(&keyring), &open).unwrap();
        let (caller, provider) = (
            StreamSeal::caller(&caller_seal),
            StreamSeal::provider(&provider_seal),
        );

        let up = sealed(&caller, data(0, b"up"));
        assert_eq!(
            unsealed(from(CALLER, up), Some(&provider)),
            Ok(data(0, b"up"))
        );
        // A provider's frames carry a fresh random nonce each.
        let (one, two) = (
            sealed(&provider, data(0, b"down")),
            sealed(&provider, data(0, b"down")),
        );
        let nonce = |f: &StreamFields| match f {
            StreamFields::SealedData { sealed, .. } => sealed.nonce.clone().unwrap(),
            other => panic!("{other:?}"),
        };
        assert_ne!(nonce(&one), nonce(&two));
        assert_eq!(
            unsealed(from(PROVIDER, one), Some(&caller)),
            Ok(data(0, b"down"))
        );
        // Sealed by the caller, a frame does not open as the provider's.
        let up = sealed(&caller, data(1, b"up"));
        assert!(matches!(
            unsealed(from(CALLER, up), Some(&caller)),
            Err(LinkError::Confidentiality(_))
        ));
    }

    /// Venus's review of package 1, observation 2: a forged clear frame on
    /// a sealed stream is refused on either side; only a caller takes the
    /// provider's clear refusal of the open at seq 0.
    #[test]
    fn a_forged_clear_frame_on_a_sealed_stream_is_refused() {
        let keyring = Keyring::system(Profile::PqPure).unwrap();
        let (open, caller_seal) = sealed_to(&keyring, RequestType::StreamOpen);
        let (_, provider_seal) = opened_request(Some(&keyring), &open).unwrap();
        let (caller, provider) = (
            StreamSeal::caller(&caller_seal),
            StreamSeal::provider(&provider_seal),
        );
        let refusal = StreamFields::Error {
            seq: 0,
            code: CODE_SEALED_REFUSED.into(),
            message: String::new(),
        };
        for side in [&caller, &provider] {
            assert_eq!(
                unsealed(from(PROVIDER, data(0, b"clear")), Some(side)),
                Err(LinkError::ClearAnswerToSealed)
            );
            let reply = StreamFields::Reply {
                seq: 1,
                payload: Value::Null,
            };
            assert_eq!(
                unsealed(from(PROVIDER, reply), Some(side)),
                Err(LinkError::ClearAnswerToSealed)
            );
        }
        assert_eq!(
            unsealed(from(PROVIDER, refusal.clone()), Some(&caller)),
            Ok(refusal.clone())
        );
        assert_eq!(
            unsealed(from(CALLER, refusal), Some(&provider)),
            Err(LinkError::ClearAnswerToSealed)
        );
    }

    #[test]
    fn a_keyed_procedure_takes_clear_calls_only_within_its_keyless_window() {
        let since = 1_790_000_000_000;
        let window = MAX_ADVERTISEMENT_TTL_MS + CLOCK_TOLERANCE_MS as i64;
        for c in [Confidentiality::Preferred, Confidentiality::Off] {
            assert!(clear_allowed(c, None, since + 10 * window), "{c:?} keyless");
        }
        assert!(clear_allowed(
            Confidentiality::Preferred,
            Some(since),
            since + window
        ));
        assert!(!clear_allowed(
            Confidentiality::Preferred,
            Some(since),
            since + window + 1
        ));
        for keyed_since in [None, Some(since)] {
            assert!(!clear_allowed(
                Confidentiality::Required,
                keyed_since,
                since
            ));
        }
    }

    #[test]
    fn a_refusal_names_a_key_only_as_sixteen_lowercase_hex_digits() {
        assert_eq!(
            refused_key(Some("0966848943d688e2")),
            Some([0x09, 0x66, 0x84, 0x89, 0x43, 0xd6, 0x88, 0xe2])
        );
        for not_one in [
            "+1+2+3+4+5+6+7+8",
            "0966848943D688E2",
            "0966848943d688e",
            "0966848943d688e2f",
            NO_KEY_DETAIL,
            "",
        ] {
            assert_eq!(refused_key(Some(not_one)), None, "{not_one:?}");
        }
        assert_eq!(refused_key(None), None);
    }
}
