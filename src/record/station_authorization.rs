//! Station authorizations (0x13, macula-station#63): a realm's statement,
//! signed by its realm key, that a station serves the realm under a hostname
//! and roles, for a window of at most 30 minutes. It is stored under the realm
//! id and the station's node_id, where the realm's tombstone of it lands once
//! it is revoked.

use crate::cbor::Value;

use super::{id_field, malformed, text_field, Record, RecordError, RecordType};

/// A station authorization's payload: the realm and station, the hostname and
/// roles, its window, and the attestation key a station must prove when
/// `attestation_required`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StationAuthorization {
    pub realm_id: [u8; 32],
    pub station_node: [u8; 32],
    pub hostname: String,
    pub roles: Vec<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub attestation_key_id: Option<[u8; 32]>,
    pub attestation_required: bool,
}

/// Reads a station authorization's payload, as macula_record's
/// read_station_authorization/1 does.
pub fn read_station_authorization(r: &Record) -> Result<StationAuthorization, RecordError> {
    if r.record_type != RecordType::STATION_AUTHORIZATION {
        return Err(malformed("not a station authorization"));
    }
    let p = &r.payload;
    let uint = |name: &str| match p.get(name) {
        Some(Value::Int(n)) => u64::try_from(*n).unwrap_or(0),
        _ => 0,
    };
    let roles = match p.get("roles") {
        Some(Value::List(roles)) => roles
            .iter()
            .filter_map(|r| match r {
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(StationAuthorization {
        realm_id: id_field(p, "realm_id"),
        station_node: id_field(p, "station_node"),
        hostname: text_field(p, "hostname"),
        roles,
        valid_from: uint("valid_from"),
        valid_until: uint("valid_until"),
        attestation_key_id: p
            .get("attestation_key_id")
            .map(|_| id_field(p, "attestation_key_id")),
        attestation_required: p.get("attestation_required") == Some(&Value::Int(1)),
    })
}
