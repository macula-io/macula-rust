//! A record's 32-byte DHT storage key, as macula_record's storage_key/1
//! derives it. A node record is stored under its node_id, and every other
//! record under SHA-256 over MACULA-PQ-STORAGE-KEY-V1, a zero byte, its type
//! and the fields of its slot, a 32-byte id as it is and any other field
//! length-prefixed. A tombstone takes the key of the record it withdraws.

use sha2::{Digest, Sha256};

use crate::cbor::Value;

use super::{malformed, payload::is_content_id, Record, RecordError, RecordType};

const STORAGE_KEY_LABEL: &[u8] = b"MACULA-PQ-STORAGE-KEY-V1";

/// The storage key of `r`. A record stored under its signer must be signed or
/// verified.
pub fn storage_key(r: &Record) -> Result<[u8; 32], RecordError> {
    if r.record_type != RecordType::TOMBSTONE {
        return slot_key(
            i128::from(r.record_type.0),
            &r.payload,
            r.subject.as_deref(),
            r,
        );
    }
    let Some(Value::Int(withdrawn)) = r.payload.get("withdrawn_type") else {
        return Err(malformed("a tombstone without an integer withdrawn_type"));
    };
    let subject = match r.payload.get("subject") {
        None => None,
        Some(Value::Bytes(s)) => Some(s.as_slice()),
        Some(_) => return Err(malformed("a tombstone's subject that is not bytes")),
    };
    slot_key(*withdrawn, &r.payload, subject, r)
}

/// The storage key of a procedure's advertisements.
pub fn procedure_key(realm_id: &[u8; 32], procedure: &str) -> [u8; 32] {
    derived(0x06, &[realm_id, &length_prefixed(procedure.as_bytes())])
}

/// The storage key every announcement of a content id shares.
pub fn content_key(mcid: &[u8]) -> Result<[u8; 32], RecordError> {
    if !is_content_id(Some(&Value::Bytes(mcid.to_vec()))) {
        return Err(RecordError::NotAContentId);
    }
    Ok(derived(0x11, &[&length_prefixed(mcid)]))
}

/// The storage key of a station's endpoint record.
pub fn station_endpoint_key(node_id: &[u8; 32]) -> [u8; 32] {
    derived(0x12, &[node_id])
}

/// The storage key of an org directory record.
pub fn org_directory_key(realm_id: &[u8; 32], org_name: &str) -> [u8; 32] {
    derived(0x15, &[realm_id, &length_prefixed(org_name.as_bytes())])
}

/// The storage key of a procedure delegation.
pub fn procedure_delegation_key(org_key_id: &[u8; 32], advertiser: &[u8; 32]) -> [u8; 32] {
    derived(0x16, &[org_key_id, advertiser])
}

fn slot_key(
    t: i128,
    payload: &Value,
    subject: Option<&[u8]>,
    r: &Record,
) -> Result<[u8; 32], RecordError> {
    let id = |name: &str| -> Result<Vec<u8>, RecordError> {
        match payload.get(name) {
            Some(Value::Bytes(b)) if b.len() == 32 => Ok(b.clone()),
            _ => Err(malformed(format!("a storage key needs a 32-byte {name}"))),
        }
    };
    let text = |name: &str| -> Result<Vec<u8>, RecordError> {
        match payload.get(name) {
            Some(Value::Text(t)) => Ok(length_prefixed(t.as_bytes())),
            _ => Err(malformed(format!("a storage key needs {name} as text"))),
        }
    };
    let signer = || -> Result<Vec<u8>, RecordError> {
        r.signed
            .as_ref()
            .map(|s| s.key_id.to_vec())
            .ok_or(RecordError::Unsigned)
    };
    let key = match t {
        0x01 => {
            let signer = signer()?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&signer);
            key
        }
        0x03 | 0x04 => derived(t as u8, &[&id("realm_id")?]),
        0x05 => derived(t as u8, &[&id("realm_id")?, &id("member_node")?]),
        0x06 => derived(t as u8, &[&id("realm_id")?, &text("procedure")?]),
        0x0D | 0x0F => derived(t as u8, &[&signer()?]),
        0x0E => derived(t as u8, &[&signer()?, &text("param_name")?]),
        0x10 => derived(t as u8, &[&id("station_id")?]),
        0x11 => match payload.get("mcid") {
            Some(Value::Bytes(m)) if is_content_id(Some(&Value::Bytes(m.clone()))) => {
                derived(0x11, &[&length_prefixed(m)])
            }
            _ => return Err(RecordError::NotAContentId),
        },
        0x12 => derived(t as u8, &[&signer()?]),
        0x15 => derived(t as u8, &[&id("realm_id")?, &text("org_name")?]),
        0x16 => derived(t as u8, &[&signer()?, &id("advertiser")?]),
        0x20..=0xFF => match subject {
            Some(s) => derived(t as u8, &[&signer()?, &length_prefixed(s)]),
            None => derived(t as u8, &[&signer()?]),
        },
        _ => return Err(malformed(format!("no storage key for type {t:#04x}"))),
    };
    Ok(key)
}

fn derived(t: u8, fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STORAGE_KEY_LABEL);
    h.update([0, t]);
    for field in fields {
        h.update(field);
    }
    h.finalize().into()
}

fn length_prefixed(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}
