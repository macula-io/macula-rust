//! Tombstones: a signer's withdrawal of one of its records, stored in the
//! withdrawn record's slot and signed with the key that signed it.

use crate::cbor::Value;

use super::payload::slot_field_names;
use super::{
    entry, id_field, malformed, text_field, unsigned, Record, RecordError, RecordType,
    CLOCK_TOLERANCE_MS,
};

/// Why a tombstone withdraws a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Shutdown,
    Moved,
    Revoked,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Reason::Shutdown => "shutdown",
            Reason::Moved => "moved",
            Reason::Revoked => "revoked",
        }
    }
}

/// A tombstone's optional fields: `detail`, left out when empty, and
/// `ttl_ms`, 0 for the clock tolerance, 5 minutes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TombstoneOptions {
    pub detail: String,
    pub ttl_ms: u64,
}

/// An unsigned tombstone that withdraws `withdrawn`: it names the record's
/// type, version and slot fields, takes its slot, and lives until the record
/// has expired plus the clock tolerance, or `ttl_ms` past its own creation
/// when later, so no replica serves the record again after it lapses.
pub fn new_tombstone(
    withdrawn: &Record,
    reason: Reason,
    opts: &TombstoneOptions,
) -> Result<Record, RecordError> {
    if withdrawn.record_type == RecordType::TOMBSTONE {
        return Err(RecordError::TombstoneOfATombstone);
    }
    let mut entries = vec![
        entry(
            "withdrawn_type",
            Value::Int(i128::from(withdrawn.record_type.0)),
        ),
        entry(
            "withdrawn_version",
            Value::Bytes(withdrawn.version.to_vec()),
        ),
        entry("reason", Value::text(reason.name())),
    ];
    entries.extend(slot_fields(withdrawn)?);
    if !opts.detail.is_empty() {
        entries.push(entry("detail", Value::text(opts.detail.clone())));
    }
    let ttl_ms = if opts.ttl_ms == 0 {
        CLOCK_TOLERANCE_MS
    } else {
        opts.ttl_ms
    };
    let mut r = unsigned(RecordType::TOMBSTONE, Value::Map(entries), ttl_ms);
    r.expires_at = (r.created_at + ttl_ms).max(withdrawn.expires_at + CLOCK_TOLERANCE_MS);
    Ok(r)
}

fn slot_fields(withdrawn: &Record) -> Result<Vec<(Value, Value)>, RecordError> {
    if withdrawn.record_type >= RecordType::DOMAIN_MIN {
        return Ok(withdrawn
            .subject
            .as_ref()
            .map(|s| vec![entry("subject", Value::Bytes(s.clone()))])
            .unwrap_or_default());
    }
    slot_field_names(i128::from(withdrawn.record_type.0))
        .iter()
        .map(|name| {
            withdrawn
                .payload
                .get(name)
                .map(|v| entry(name, v.clone()))
                .ok_or_else(|| malformed(format!("the withdrawn record has no {name}")))
        })
        .collect()
}

/// A tombstone's payload: what it withdraws, why, and the withdrawn record's
/// slot fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tombstone {
    pub withdrawn_type: RecordType,
    pub withdrawn_version: [u8; 16],
    pub reason: String,
    pub detail: String,
    pub realm_id: [u8; 32],
    pub member_node: [u8; 32],
    pub procedure: String,
    pub param_name: String,
    pub station_id: [u8; 32],
    pub mcid: Vec<u8>,
    pub org_name: String,
    pub advertiser: [u8; 32],
    pub subject: Vec<u8>,
}

/// Reads a tombstone's payload.
pub fn read_tombstone(r: &Record) -> Result<Tombstone, RecordError> {
    if r.record_type != RecordType::TOMBSTONE {
        return Err(malformed("not a tombstone"));
    }
    let p = &r.payload;
    let withdrawn = match p.get("withdrawn_type") {
        Some(Value::Int(n)) if (1..=255).contains(n) => RecordType(*n as u8),
        _ => {
            return Err(malformed(
                "a withdrawn_type that is not an integer from 1 to 255",
            ))
        }
    };
    let bytes = |name: &str| match p.get(name) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    Ok(Tombstone {
        withdrawn_type: withdrawn,
        withdrawn_version: bytes("withdrawn_version").try_into().unwrap_or([0; 16]),
        reason: text_field(p, "reason"),
        detail: text_field(p, "detail"),
        realm_id: id_field(p, "realm_id"),
        member_node: id_field(p, "member_node"),
        procedure: text_field(p, "procedure"),
        param_name: text_field(p, "param_name"),
        station_id: id_field(p, "station_id"),
        mcid: bytes("mcid"),
        org_name: text_field(p, "org_name"),
        advertiser: id_field(p, "advertiser"),
        subject: bytes("subject"),
    })
}
