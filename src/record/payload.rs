//! Whether a record's payload holds what its type's rules require, as
//! macula_record's payload_ok/2: every field a storage key or a signer check
//! reads is present, of its kind, and the payloads the design pins hold
//! exactly their keys. A domain type's owner sets its rules.

use crate::cbor::Value;
use crate::seal;

use super::{signed_by_some_key, RecordType};

/// A tombstone's own payload fields; the rest are the withdrawn record's slot
/// fields.
const TOMBSTONE_FIELDS: &[&str] = &["withdrawn_type", "withdrawn_version", "reason", "detail"];

/// The reasons a tombstone may give.
const TOMBSTONE_REASONS: &[&str] = &["shutdown", "moved", "revoked"];

pub(super) fn payload_ok(t: RecordType, payload: &Value) -> bool {
    let Value::Map(pairs) = payload else {
        return false;
    };
    let field = |name: &str| payload.get(name);
    match t {
        RecordType::NODE_RECORD => is_id(field("node_id")),
        RecordType::REALM_DIRECTORY | RecordType::REALM_STATIONS => is_id(field("realm_id")),
        RecordType::REALM_MEMBER_ENDORSEMENT => {
            is_id(field("realm_id")) && is_id(field("member_node"))
        }
        RecordType::PROCEDURE_ADVERTISEMENT => advertisement_ok(payload, pairs.len()),
        RecordType::TOMBSTONE => tombstone_ok(payload, pairs),
        RecordType::FOUNDATION_SEED_LIST
        | RecordType::FOUNDATION_REALM_TRUST_LIST
        | RecordType::STATION_ENDPOINT => true,
        RecordType::FOUNDATION_PARAMETER => is_text(field("param_name")),
        RecordType::FOUNDATION_T3_ATTESTATION => is_id(field("station_id")),
        RecordType::CONTENT_ANNOUNCEMENT => {
            is_id(field("announcer_node"))
                && is_content_id(field("mcid"))
                && is_id(field("realm_id"))
                && is_id(field("serving_station"))
                && matches!(field("procedure"), Some(Value::Text(p)) if !p.is_empty())
        }
        RecordType::ORG_DIRECTORY => {
            is_id(field("realm_id")) && is_text(field("org_name")) && is_id(field("org_key"))
        }
        RecordType::PROCEDURE_DELEGATION => is_id(field("org_key")) && is_id(field("advertiser")),
        t => t >= RecordType::DOMAIN_MIN,
    }
}

/// Exactly realm_id, procedure, advertiser_node and serving_station, with an
/// authorization map when it carries one, and a KEM key pair when it names
/// one.
fn advertisement_ok(payload: &Value, size: usize) -> bool {
    if !is_id(payload.get("realm_id"))
        || !is_text(payload.get("procedure"))
        || !is_id(payload.get("advertiser_node"))
        || !is_id(payload.get("serving_station"))
    {
        return false;
    }
    let authorization = match payload.get("authorization") {
        None => 0,
        Some(Value::Map(_)) => 1,
        Some(_) => return false,
    };
    kem_key_pair(payload).is_some_and(|pair| size == 4 + authorization + pair)
}

/// A provider's KEM key and its id travel only as a pair (E2E design,
/// amendment A1), as macula_record's kem_key_pair/1: the key as carried, of
/// a profile's size, and its id. The two count 2, their absence 0; a lone
/// field, a key of another size or an id that is not its key's is malformed.
fn kem_key_pair(payload: &Value) -> Option<usize> {
    match (payload.get("kem_key"), payload.get("kem_key_id")) {
        (None, None) => Some(0),
        (Some(Value::Bytes(key)), Some(Value::Bytes(id)))
            if seal::is_carried_key_size(key.len()) && seal::key_id(key).as_slice() == id =>
        {
            Some(2)
        }
        _ => None,
    }
}

fn tombstone_ok(payload: &Value, pairs: &[(Value, Value)]) -> bool {
    let (Some(Value::Int(withdrawn)), Some(Value::Bytes(version)), Some(Value::Text(reason))) = (
        payload.get("withdrawn_type"),
        payload.get("withdrawn_version"),
        payload.get("reason"),
    ) else {
        return false;
    };
    if version.len() != 16 {
        return false;
    }
    let slot: Vec<&(Value, Value)> = pairs
        .iter()
        .filter(|(k, _)| !matches!(k, Value::Text(n) if TOMBSTONE_FIELDS.contains(&n.as_str())))
        .collect();
    TOMBSTONE_REASONS.contains(&reason.as_str())
        && withdrawable(*withdrawn)
        && payload
            .get("detail")
            .is_none_or(|d| matches!(d, Value::Text(_)))
        && slot_ok(*withdrawn, &slot)
}

/// Whether a record of type `t` can be withdrawn: a domain type, or a
/// built-in type other than a tombstone that some key signs.
fn withdrawable(t: i128) -> bool {
    match t {
        0x20..=0xFF => true,
        1..=0x1F => t != 0x0C && signed_by_some_key(t),
        _ => false,
    }
}

/// Whether a tombstone's slot fields are exactly the withdrawn type's, each
/// of its kind; for a domain type, none or a subject that is not empty.
fn slot_ok(t: i128, slot: &[&(Value, Value)]) -> bool {
    if t >= 0x20 {
        return match slot {
            [] => true,
            [(Value::Text(name), Value::Bytes(subject))] => {
                name == "subject" && !subject.is_empty()
            }
            _ => false,
        };
    }
    let names = slot_field_names(t);
    slot.len() == names.len()
        && slot.iter().all(|(k, v)| matches!(k, Value::Text(n) if names.contains(&n.as_str()) && slot_value_ok(n, v)))
}

/// The payload fields a type's storage key derives from, besides its
/// signer's key id.
pub(super) fn slot_field_names(t: i128) -> &'static [&'static str] {
    match t {
        0x03 | 0x04 => &["realm_id"],
        0x05 => &["realm_id", "member_node"],
        0x06 => &["realm_id", "procedure"],
        0x0E => &["param_name"],
        0x10 => &["station_id"],
        0x11 => &["mcid"],
        0x15 => &["realm_id", "org_name"],
        0x16 => &["advertiser"],
        _ => &[],
    }
}

fn slot_value_ok(name: &str, v: &Value) -> bool {
    match name {
        "procedure" | "param_name" | "org_name" => matches!(v, Value::Text(_)),
        "mcid" => is_content_id(Some(v)),
        _ => is_id(Some(v)),
    }
}

pub(super) fn is_id(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bytes(b)) if b.len() == 32)
}

fn is_text(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Text(_)))
}

/// An MCID: 50 bytes, tag 2 for SHA-384, a codec byte and the hash (D24).
pub(super) fn is_content_id(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bytes(b)) if b.len() == 50 && b[0] == 2)
}
