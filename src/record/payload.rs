//! Whether a record's payload holds what its type's rules require, as
//! macula_record's payload_ok/2: every field a storage key or a signer check
//! reads is present, of its kind, and the payloads the design pins hold
//! exactly their keys. A domain type's owner sets its rules.

use crate::cbor::Value;
use crate::seal;

use super::{procedure_org, signed_by_some_key, RecordError, RecordType};

/// A tombstone's own payload fields; the rest are the withdrawn record's slot
/// fields.
const TOMBSTONE_FIELDS: &[&str] = &["withdrawn_type", "withdrawn_version", "reason", "detail"];

/// The reasons a tombstone may give.
const TOMBSTONE_REASONS: &[&str] = &["shutdown", "moved", "revoked"];

/// The most stations one procedure advertisement names (K > 1, WIRE_1_0.md
/// section 5.3).
pub const MAX_SERVING_STATIONS: usize = 8;

/// A station authorization's bounds: its hostname, each role, and its window.
const MAX_STATION_HOSTNAME_BYTES: usize = 253;
const MAX_STATION_ROLE_BYTES: usize = 64;
const STATION_AUTHORIZATION_MAX_WINDOW_MS: i128 = 30 * 60 * 1000;

/// An app record's names and version are 1 to 64 bytes.
const MAX_APP_TEXT_BYTES: usize = 64;

/// The content id tag this crate knows: SHA-384, a 48-byte digest
/// (WIRE_1_0.md section 5.4).
const CONTENT_ID_TAG_SHA384: u8 = 2;

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
        RecordType::FOUNDATION_SEED_LIST | RecordType::STATION_ENDPOINT => true,
        RecordType::FOUNDATION_REALM_TRUST_LIST => trust_list_ok(payload, pairs.len()),
        RecordType::STATION_AUTHORIZATION => station_authorization_ok(payload),
        RecordType::APP_RECORD => app_ok(payload, pairs.len()),
        RecordType::FOUNDATION_PARAMETER => is_text(field("param_name")),
        RecordType::FOUNDATION_T3_ATTESTATION => is_id(field("station_id")),
        RecordType::CONTENT_ANNOUNCEMENT => {
            is_id(field("announcer_node"))
                && is_content_id_shaped(field("mcid"))
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

/// Exactly realm_id, procedure, advertiser_node and serving_stations, with
/// an authorization map when it carries one, and a KEM key pair when it names
/// one.
fn advertisement_ok(payload: &Value, size: usize) -> bool {
    if !is_id(payload.get("realm_id"))
        || !is_text(payload.get("procedure"))
        || !is_id(payload.get("advertiser_node"))
        || !serving_stations_ok(payload.get("serving_stations"))
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

/// An advertisement's serving_stations (K > 1): 1 to 8 node ids, strictly
/// ascending by bytes, so no two alike.
pub(super) fn serving_stations_ok(v: Option<&Value>) -> bool {
    let Some(Value::List(items)) = v else {
        return false;
    };
    let ids: Option<Vec<&Vec<u8>>> = items
        .iter()
        .map(|item| match item {
            Value::Bytes(b) if b.len() == 32 => Some(b),
            _ => None,
        })
        .collect();
    ids.is_some_and(|ids| {
        (1..=MAX_SERVING_STATIONS).contains(&ids.len()) && ids.windows(2).all(|w| w[0] < w[1])
    })
}

/// A foundation realm trust list: exactly realms_trusted, a list of maps of
/// exactly a 32-byte realm_id and realm_key_id.
fn trust_list_ok(payload: &Value, size: usize) -> bool {
    let Some(Value::List(trusted)) = payload.get("realms_trusted") else {
        return false;
    };
    size == 1
        && trusted.iter().all(|entry| {
            matches!(entry, Value::Map(fields) if fields.len() == 2)
                && is_id(entry.get("realm_id"))
                && is_id(entry.get("realm_key_id"))
        })
}

/// A station authorization: realm_id and station_node (32-byte ids), a
/// hostname of 1 to 253 bytes, roles of 1 to 64 bytes each, a window of at
/// most 30 minutes that ends at or after it starts, and the attestation pair
/// under its co-presence bound.
fn station_authorization_ok(payload: &Value) -> bool {
    let field = |name: &str| payload.get(name);
    let hostname = matches!(field("hostname"), Some(Value::Text(h)) if !h.is_empty() && h.len() <= MAX_STATION_HOSTNAME_BYTES);
    let roles = matches!(field("roles"), Some(Value::List(roles)) if roles.iter().all(|r| matches!(r, Value::Text(t) if !t.is_empty() && t.len() <= MAX_STATION_ROLE_BYTES)));
    let window = match (field("valid_from"), field("valid_until")) {
        (Some(Value::Int(from)), Some(Value::Int(until))) => {
            protocol_int(*from)
                && protocol_int(*until)
                && until >= from
                && until - from <= STATION_AUTHORIZATION_MAX_WINDOW_MS
        }
        _ => false,
    };
    let attestation = match (field("attestation_required"), field("attestation_key_id")) {
        (None, None) => true,
        (None | Some(Value::Int(1)), key_id @ Some(_)) => is_id(key_id),
        _ => false,
    };
    is_id(field("realm_id"))
        && is_id(field("station_node"))
        && hostname
        && roles
        && window
        && attestation
}

fn protocol_int(n: i128) -> bool {
    (0..1 << 53).contains(&n)
}

/// An app record (0x17, macula#75): exactly its seven fields. Its org is a
/// real org namespace, not `_` and not a node's `~<node_id>`, and every
/// procedure it lists is in that namespace; names and version are 1 to 64
/// bytes of text; service names are unique; the authorization is exactly the
/// carried org directory, as bytes.
fn app_ok(payload: &Value, size: usize) -> bool {
    let field = |name: &str| payload.get(name);
    let (Some(Value::Text(org)), Some(Value::Text(app)), Some(Value::Text(version))) =
        (field("org_name"), field("app_name"), field("version"))
    else {
        return false;
    };
    let authorization = match field("authorization") {
        Some(Value::Map(fields)) => {
            fields.len() == 1
                && matches!(
                    field("authorization").and_then(|a| a.get("org_directory")),
                    Some(Value::Bytes(_))
                )
        }
        _ => false,
    };
    let services = match field("services") {
        Some(Value::List(services)) => app_services_ok(services, org),
        _ => false,
    };
    size == 7
        && is_id(field("realm_id"))
        && is_id(field("org_key"))
        && app_org(org)
        && app_text(app)
        && !app.contains('/')
        && app_text(version)
        && services
        && authorization
}

fn app_org(org: &str) -> bool {
    org != "_" && !org.starts_with('~') && app_text(org) && !org.contains('/')
}

fn app_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_APP_TEXT_BYTES
}

/// Each service exactly a name and its procedures, the names unique and every
/// procedure in `org`'s namespace.
fn app_services_ok(services: &[Value], org: &str) -> bool {
    let mut names = std::collections::HashSet::with_capacity(services.len());
    services.iter().all(|service| {
        let (Some(Value::Text(name)), Some(Value::List(procedures))) =
            (service.get("name"), service.get("procedures"))
        else {
            return false;
        };
        matches!(service, Value::Map(fields) if fields.len() == 2)
            && app_text(name)
            && names.insert(name.clone())
            && procedures
                .iter()
                .all(|p| matches!(p, Value::Text(p) if procedure_org(p) == Ok(Some(org))))
    })
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
        0x13 => &["realm_id", "station_node"],
        0x15 => &["realm_id", "org_name"],
        0x16 => &["advertiser"],
        0x17 => &["realm_id", "org_name", "app_name"],
        _ => &[],
    }
}

fn slot_value_ok(name: &str, v: &Value) -> bool {
    match name {
        "procedure" | "param_name" | "org_name" | "app_name" => matches!(v, Value::Text(_)),
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
    matches!(v, Some(Value::Bytes(b)) if b.len() == 50 && b[0] == CONTENT_ID_TAG_SHA384)
}

/// A content id's shape, `<<Tag:8, Codec:8, Digest>>`, whatever its tag: the
/// tag this crate knows with its digest length, or any other tag, which
/// custodians store and readers refuse by name.
pub(super) fn is_content_id_shaped(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bytes(b)) if b.len() > 2 && (b[0] != CONTENT_ID_TAG_SHA384 || b.len() == 50))
}

/// Refuses a content announcement naming a content id whose tag this crate
/// does not know.
pub(super) fn content_id_tag_known(t: RecordType, payload: &Value) -> Result<(), RecordError> {
    match (t, payload.get("mcid")) {
        (RecordType::CONTENT_ANNOUNCEMENT, Some(Value::Bytes(m)))
            if m.first() != Some(&CONTENT_ID_TAG_SHA384) =>
        {
            Err(RecordError::McidTagUnknown)
        }
        _ => Ok(()),
    }
}
