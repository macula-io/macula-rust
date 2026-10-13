//! REGISTER_ACK (WIRE_1_0.md section 3.5, macula#12): the station's answer to
//! an ADVERTISE, UNADVERTISE, SUBSCRIBE or UNSUBSCRIBE, on the control stream,
//! unsigned (per-hop). Its `kind` and `reason` are per-hop enums: an unknown
//! kind ignores the ack, an unknown reason reads as `refused`, each counted.

use crate::cbor::Value;

use super::wire_counters::count_enum_fallback;
use super::{fixed, has_fields, read_fields, text_of, FrameError, Rule, MAX_TOPIC_BYTES};

/// The refusal reasons a REGISTER_ACK names; `refused` is the generic one.
const REASONS: &[&str] = &[
    "too_many_providers",
    "advertiser_quota",
    "name_too_long",
    "record_refused",
    "not_authorized",
    "too_many_realms",
    "refused",
];

/// The frame a REGISTER_ACK answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterKind {
    Advertise,
    Unadvertise,
    Subscribe,
    Unsubscribe,
}

impl RegisterKind {
    fn parse(name: &str) -> Option<RegisterKind> {
        match name {
            "advertise" => Some(RegisterKind::Advertise),
            "unadvertise" => Some(RegisterKind::Unadvertise),
            "subscribe" => Some(RegisterKind::Subscribe),
            "unsubscribe" => Some(RegisterKind::Unsubscribe),
            _ => None,
        }
    }

    /// The key that names what the ack answers: an advertisement's
    /// record_version, or a subscription's subscriber.
    fn own_key(self) -> &'static str {
        match self {
            RegisterKind::Advertise | RegisterKind::Unadvertise => "record_version",
            RegisterKind::Subscribe | RegisterKind::Unsubscribe => "subscriber",
        }
    }
}

/// What the station answered, and to which frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// An ADVERTISE or UNADVERTISE of the advertisement of this record
    /// version.
    Advertisement { record_version: [u8; 16] },
    /// A SUBSCRIBE or UNSUBSCRIBE of this subscriber.
    Subscription { subscriber: [u8; 32] },
}

/// A REGISTER_ACK that read: the frame it answers, in which realm and for
/// which procedure or topic, and the refusal's reason, `None` when accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAck {
    pub kind: RegisterKind,
    pub realm: [u8; 32],
    pub name: String,
    pub answered: Answered,
    pub refusal: Option<String>,
}

/// Reads a REGISTER_ACK, its envelope already read
/// ([`super::read_envelope`]): exactly the envelope keys and its own, each of
/// its rule; `reason` present exactly when `accepted` is 0; and the key of its
/// kind alone, an advertisement's `record_version` or a subscription's
/// `subscriber`. Any other shape is [`FrameError::Malformed`]. `None` for a
/// kind this crate does not know: the ack is ignored, counted.
pub fn read_register_ack(frame: &Value) -> Result<Option<RegisterAck>, FrameError> {
    let table = [
        ("version", Rule::ProtocolVersion),
        ("frame_type", Rule::TextIn(&["register_ack"])),
        ("frame_id", Rule::BytesOf(16)),
        ("sent_at_ms", Rule::ProtocolUint),
        ("kind", Rule::EnumText),
        ("realm", Rule::BytesOf(32)),
        ("name", Rule::TextWithin(MAX_TOPIC_BYTES)),
        ("record_version", Rule::BytesOf(16)),
        ("subscriber", Rule::BytesOf(32)),
        ("accepted", Rule::ZeroOrOne),
        ("reason", Rule::EnumText),
    ];
    let fields = read_fields(frame, &table).ok_or(FrameError::Malformed)?;
    let accepted = fields.get("accepted") == Some(&Value::Int(1));
    if !has_fields(&fields, &["kind", "realm", "name", "accepted"])
        || text_of(&fields["name"]).is_empty()
        || accepted == fields.contains_key("reason")
    {
        return Err(FrameError::Malformed);
    }
    let Some(kind) = RegisterKind::parse(&text_of(&fields["kind"])) else {
        count_enum_fallback("kind");
        return Ok(None);
    };
    let own = kind.own_key();
    let other = if own == "subscriber" {
        "record_version"
    } else {
        "subscriber"
    };
    if !fields.contains_key(own) || fields.contains_key(other) {
        return Err(FrameError::Malformed);
    }
    let answered = match kind.own_key() {
        "record_version" => Answered::Advertisement {
            record_version: fixed(&fields["record_version"]),
        },
        _ => Answered::Subscription {
            subscriber: fixed(&fields["subscriber"]),
        },
    };
    Ok(Some(RegisterAck {
        kind,
        realm: fixed(&fields["realm"]),
        name: text_of(&fields["name"]),
        answered,
        refusal: fields.get("reason").map(|r| reason(&text_of(r))),
    }))
}

/// A refusal's reason as this crate reads it: a reason it does not know reads
/// as `refused`, counted.
fn reason(name: &str) -> String {
    if REASONS.contains(&name) {
        return name.to_string();
    }
    count_enum_fallback("reason");
    "refused".to_string()
}
