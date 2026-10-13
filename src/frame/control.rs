//! The control frames a client link exchanges after HELLO (WIRE_1_0.md
//! section 3): ADVERTISE and UNADVERTISE carry a signed record, SUBSCRIBE and
//! UNSUBSCRIBE a topic, GOODBYE a reason, and the liveness probe a nonce. None
//! carries a signature of its own: the session proofs authenticated the peer
//! once, and QUIC's AEAD authenticates every frame.

use crate::cbor::Value;

use super::{
    base, bounded_text, entry, has_fields, read_fields, with_field, FrameError, Rule,
    LIVENESS_NONCE_SIZE, MAX_TOPIC_BYTES,
};

const MAX_GOODBYE_REASON_BYTES: usize = 256;
const MAX_GOODBYE_DETAIL_BYTES: usize = 256;

/// A frame type's field table, and the fields it must hold.
type Table = Vec<(&'static str, Rule)>;
type Required = &'static [&'static str];

/// The field table of a control frame a client link exchanges: the envelope
/// keys every frame may carry and the type's own fields, with the fields it
/// must hold.
fn control_table(frame_type: &str) -> Option<(Table, Required)> {
    let (own, required): (&[(&'static str, Rule)], &'static [&'static str]) = match frame_type {
        "advertise" => (&[("advertisement", Rule::AnyBytes)], &["advertisement"]),
        "unadvertise" => (&[("withdrawal", Rule::AnyBytes)], &["withdrawal"]),
        "subscribe" => (
            &[
                ("realm", Rule::BytesOf(32)),
                ("topic", Rule::AnyBytes),
                ("subscriber", Rule::BytesOf(32)),
                ("options", Rule::Any),
            ],
            &["realm", "topic", "subscriber"],
        ),
        "unsubscribe" => (
            &[
                ("realm", Rule::BytesOf(32)),
                ("topic", Rule::AnyBytes),
                ("subscriber", Rule::BytesOf(32)),
            ],
            &["realm", "topic", "subscriber"],
        ),
        "goodbye" => (
            &[
                ("reason", Rule::TextWithin(MAX_GOODBYE_REASON_BYTES)),
                ("detail", Rule::AnyBytes),
            ],
            &["reason"],
        ),
        "liveness_ping" | "liveness_pong" => {
            (&[("nonce", Rule::BytesOf(LIVENESS_NONCE_SIZE))], &["nonce"])
        }
        _ => return None,
    };
    let mut table = vec![
        ("version", Rule::ProtocolVersion),
        ("frame_type", Rule::Any),
        ("frame_id", Rule::BytesOf(16)),
        ("sent_at_ms", Rule::ProtocolUint),
        ("realm", Rule::BytesOf(32)),
        ("call_id", Rule::BytesOf(16)),
        ("source_route", Rule::AnyBytes),
    ];
    for (name, rule) in own {
        match table.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = *rule,
            None => table.push((name, *rule)),
        }
    }
    Some((table, required))
}

/// Reads a control frame, its envelope already read
/// ([`super::read_envelope`]), through its type's table: exactly the envelope
/// keys and the type's fields, each of its rule, with the fields the type
/// requires. A frame of another type or shape is [`FrameError::Malformed`]: a
/// field no table names is an extra core field.
pub fn read_control(frame: &Value) -> Result<Value, FrameError> {
    let frame_type = match frame.get("frame_type") {
        Some(Value::Text(t)) => t.as_str(),
        _ => return Err(FrameError::Malformed),
    };
    let (table, required) = control_table(frame_type).ok_or(FrameError::Malformed)?;
    let fields = read_fields(frame, &table).ok_or(FrameError::Malformed)?;
    if !has_fields(&fields, &["version", "frame_type"]) || !has_fields(&fields, required) {
        return Err(FrameError::Malformed);
    }
    Ok(frame.clone())
}

/// Whether `frame_type` is a control frame [`read_control`] reads.
pub fn is_control_frame(frame_type: &str) -> bool {
    control_table(frame_type).is_some()
}

/// macula 12's ADVERTISE: the signed procedure_advertisement record, as
/// encoded bytes.
pub fn advertise_frame(advertisement: &[u8]) -> Value {
    let mut fields = base("advertise");
    fields.push(entry("advertisement", Value::Bytes(advertisement.to_vec())));
    Value::Map(fields)
}

/// macula 12's UNADVERTISE: the signed withdrawal record, as encoded bytes.
pub fn unadvertise_frame(withdrawal: &[u8]) -> Value {
    let mut fields = base("unadvertise");
    fields.push(entry("withdrawal", Value::Bytes(withdrawal.to_vec())));
    Value::Map(fields)
}

/// macula 12's SUBSCRIBE of `subscriber` to `topic` in `realm`, with no
/// options. A topic over 512 bytes or not UTF-8 is refused.
pub fn subscribe_frame(
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Value, FrameError> {
    let mut fields = topic_frame("subscribe", topic, realm, subscriber)?;
    fields.push(entry("options", Value::Map(Vec::new())));
    Ok(Value::Map(fields))
}

/// macula 12's UNSUBSCRIBE of `subscriber` from `topic` in `realm`, with
/// [`subscribe_frame`]'s bound on the topic.
pub fn unsubscribe_frame(
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Value, FrameError> {
    topic_frame("unsubscribe", topic, realm, subscriber).map(Value::Map)
}

fn topic_frame(
    frame_type: &str,
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Vec<(Value, Value)>, FrameError> {
    bounded_text("topic", topic, MAX_TOPIC_BYTES)?;
    let mut fields = with_field(base(frame_type), "realm", Value::Bytes(realm.to_vec()));
    fields.push(entry("topic", Value::Bytes(topic.to_vec())));
    fields.push(entry("subscriber", Value::Bytes(subscriber.to_vec())));
    Ok(fields)
}

/// macula 12's GOODBYE: a reason of at most 256 bytes, and a detail of at
/// most 256 bytes of UTF-8, left out when there is none.
pub fn goodbye_frame(reason: &str, detail: Option<&[u8]>) -> Result<Value, FrameError> {
    bounded_text("reason", reason.as_bytes(), MAX_GOODBYE_REASON_BYTES)?;
    let mut fields = base("goodbye");
    fields.push(entry("reason", Value::text(reason)));
    if let Some(d) = detail {
        bounded_text("detail", d, MAX_GOODBYE_DETAIL_BYTES)?;
        fields.push(entry("detail", Value::Bytes(d.to_vec())));
    }
    Ok(Value::Map(fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::PROTOCOL_VERSION;

    #[test]
    fn every_control_frame_built_here_reads_back() {
        let built = [
            advertise_frame(b"record"),
            unadvertise_frame(b"withdrawal"),
            subscribe_frame(b"a.topic", &[1; 32], &[2; 32]).unwrap(),
            unsubscribe_frame(b"a.topic", &[1; 32], &[2; 32]).unwrap(),
            goodbye_frame("bye", None).unwrap(),
            goodbye_frame("bye", Some(b"detail")).unwrap(),
            super::super::liveness_ping_frame(&[3; 16]),
        ];
        for frame in built {
            let envelope = super::super::read_envelope(&frame).unwrap();
            assert_eq!(read_control(&envelope.frame).unwrap(), frame);
            assert_eq!(
                frame.get("version"),
                Some(&Value::Int(PROTOCOL_VERSION.into()))
            );
            assert_eq!(frame.get("capabilities"), None, "the dropped header");
        }
    }

    #[test]
    fn a_frame_with_a_field_its_type_does_not_have_is_malformed() {
        let goodbye = goodbye_frame("bye", None).unwrap();
        for extra in ["neighbour", "colour", "capabilities"] {
            let frame = goodbye.clone().with_field(extra, Value::Int(0));
            assert_eq!(read_control(&frame), Err(FrameError::Malformed), "{extra}");
        }
    }
}
