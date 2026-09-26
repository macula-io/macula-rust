//! Procedure advertisements: a node's statement that it serves a procedure in
//! a realm, through a station, signed by the node. A procedure with an org
//! namespace carries its provider authorization inside the payload: the
//! realm's org directory and the org's procedure delegation, as their wire
//! forms (see `authorization`).

use crate::cbor::Value;

use super::{entry, id_field, malformed, text_field, unsigned, Record, RecordError, RecordType};

/// A procedure advertisement's provider authorization, as macula_record's
/// read_authorization/1 reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Authorization {
    /// The advertisement carries none.
    #[default]
    None,
    /// The realm's org directory and the org's procedure delegation, the one
    /// form macula 12 has, as the records' wire forms.
    Delegation {
        org_directory: Vec<u8>,
        procedure_delegation: Vec<u8>,
    },
    /// A map of any other fields, a certificate chain among them.
    Unsupported,
    /// Not a map, or an org directory and a delegation that are not both
    /// byte strings.
    Malformed,
}

/// A procedure advertisement's optional fields: its authorization, and
/// `ttl_ms`, 0 for the default and maximum, 5 minutes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcedureAdvertisementOptions {
    pub authorization: Authorization,
    pub ttl_ms: u64,
}

/// An unsigned advertisement, by `advertiser_node`, which signs it, of
/// `procedure` in `realm_id`, served through `serving_station`. It builds no
/// authorization but an org directory and a procedure delegation.
pub fn new_procedure_advertisement(
    advertiser_node: &[u8; 32],
    realm_id: &[u8; 32],
    procedure: &str,
    serving_station: &[u8; 32],
    opts: &ProcedureAdvertisementOptions,
) -> Result<Record, RecordError> {
    let mut entries = vec![
        entry("realm_id", Value::Bytes(realm_id.to_vec())),
        entry("procedure", Value::text(procedure)),
        entry("advertiser_node", Value::Bytes(advertiser_node.to_vec())),
        entry("serving_station", Value::Bytes(serving_station.to_vec())),
    ];
    match &opts.authorization {
        Authorization::None => {}
        Authorization::Delegation {
            org_directory,
            procedure_delegation,
        } => entries.push(entry(
            "authorization",
            Value::Map(vec![
                entry("org_directory", Value::Bytes(org_directory.clone())),
                entry(
                    "procedure_delegation",
                    Value::Bytes(procedure_delegation.clone()),
                ),
            ]),
        )),
        Authorization::Unsupported => return Err(RecordError::AuthorizationFormUnsupported),
        Authorization::Malformed => return Err(malformed("an authorization in no form")),
    }
    Ok(unsigned(
        RecordType::PROCEDURE_ADVERTISEMENT,
        Value::Map(entries),
        opts.ttl_ms,
    ))
}

/// A procedure advertisement's payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcedureAdvertisement {
    pub realm_id: [u8; 32],
    pub procedure: String,
    pub advertiser_node: [u8; 32],
    pub serving_station: [u8; 32],
    pub authorization: Authorization,
}

/// Reads a procedure advertisement's payload.
pub fn read_procedure_advertisement(r: &Record) -> Result<ProcedureAdvertisement, RecordError> {
    if r.record_type != RecordType::PROCEDURE_ADVERTISEMENT {
        return Err(malformed("not a procedure advertisement"));
    }
    let p = &r.payload;
    Ok(ProcedureAdvertisement {
        realm_id: id_field(p, "realm_id"),
        procedure: text_field(p, "procedure"),
        advertiser_node: id_field(p, "advertiser_node"),
        serving_station: id_field(p, "serving_station"),
        authorization: read_authorization(p),
    })
}

fn read_authorization(payload: &Value) -> Authorization {
    let Some(value) = payload.get("authorization") else {
        return Authorization::None;
    };
    let Value::Map(pairs) = value else {
        return Authorization::Malformed;
    };
    let (Some(directory), Some(delegation)) = (
        value.get("org_directory"),
        value.get("procedure_delegation"),
    ) else {
        return Authorization::Unsupported;
    };
    if pairs.len() != 2 {
        return Authorization::Unsupported;
    }
    match (directory, delegation) {
        (Value::Bytes(d), Value::Bytes(g)) => Authorization::Delegation {
            org_directory: d.clone(),
            procedure_delegation: g.clone(),
        },
        _ => Authorization::Malformed,
    }
}
