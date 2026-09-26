//! A procedure advertisement's provider authorization (D25), as
//! macula_record's verify_authorization/3 and own_namespace/1 decide it. A
//! procedure `org/name` is authorized by the realm's org directory, which
//! names the org's key, and the org's procedure delegation to the
//! advertiser, both carried in the advertisement. A procedure in a node's own
//! namespace, `~<node_id>/name`, is authorized by the advertisement's
//! signature alone, and needs no realm key. A procedure without a namespace
//! carries no authorization.

use crate::profile::Profile;

use super::{
    id_field, malformed, read_procedure_advertisement, text_field, verify, Authorization,
    ProcedureAdvertisement, Record, RecordError, RecordType, Verified,
};

/// Starts the namespace of a node's own procedures, `~<node_id>/<name>`.
pub const OWN_NAMESPACE_PREFIX: &str = "~";

/// What a caller trusts for its realm: the verifier's profile and the realm
/// key as carried, `None` when none is pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub profile: Profile,
    pub realm_key: Option<Vec<u8>>,
}

/// A procedure's org namespace: the text before the first `/` of its name.
/// A name without a slash, or with `_` before it, has none; a name starting
/// with a slash is malformed.
pub fn procedure_org(procedure: &str) -> Result<Option<&str>, RecordError> {
    match procedure.split_once('/') {
        None => Ok(None),
        Some(("_", _)) => Ok(None),
        Some(("", _)) => Err(malformed("a procedure name starting with a slash")),
        Some((org, _)) => Ok(Some(org)),
    }
}

/// Whether `procedure` names a node's own namespace, `~` before its first
/// slash, spelled well or not.
pub fn in_own_namespace(procedure: &str) -> bool {
    matches!(procedure_org(procedure), Ok(Some(org)) if org.starts_with(OWN_NAMESPACE_PREFIX))
}

/// `name` in the own namespace of `node`: `~<node_id hex>/name`.
pub fn own_procedure(node: &[u8; 32], name: &str) -> String {
    let hex: String = node.iter().map(|b| format!("{b:02x}")).collect();
    format!("{OWN_NAMESPACE_PREFIX}{hex}/{name}")
}

/// The node_id a `~` namespace names: exactly 64 lowercase hex characters,
/// the one spelling of a node_id in a namespace.
pub fn namespace_node(hex_node: &str) -> Result<[u8; 32], RecordError> {
    let bad = || malformed("a ~ namespace is 64 lowercase hex characters");
    if hex_node.len() != 64
        || !hex_node
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad());
    }
    let mut node = [0u8; 32];
    for (i, byte) in node.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex_node[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(node)
}

/// Whether a verified procedure advertisement is in its advertiser's own
/// namespace and admissible there: `~<node_id>/<name>` where node_id is the
/// advertiser_node verifying bound to its signer, with no authorization.
pub fn own_namespace(advertisement: &Verified) -> Result<(), RecordError> {
    let r = advertisement.record();
    if r.record_type != RecordType::PROCEDURE_ADVERTISEMENT {
        return Err(RecordError::NotOwnNamespace);
    }
    let read = read_procedure_advertisement(r)?;
    match procedure_org(&read.procedure) {
        Ok(Some(org)) if org.starts_with(OWN_NAMESPACE_PREFIX) => {
            own_node(&org[OWN_NAMESPACE_PREFIX.len()..], &read)
        }
        _ => Err(RecordError::NotOwnNamespace),
    }
}

fn own_node(hex_node: &str, read: &ProcedureAdvertisement) -> Result<(), RecordError> {
    let node = namespace_node(hex_node)?;
    if node != read.advertiser_node {
        return Err(RecordError::NotOwnNamespace);
    }
    if read.authorization != Authorization::None {
        return Err(RecordError::AuthorizationNotAllowed);
    }
    Ok(())
}

/// A caller's check of a verified procedure advertisement's provider
/// authorization against the realm it trusts, at `now_ms`. An org procedure
/// needs an org directory and a procedure delegation, and the realm key: the
/// directory must verify, carry the realm key and name the advertisement's
/// realm and the procedure's org; the delegation must verify, signed by the
/// org key the directory names, for the advertiser; and the advertisement
/// expires no later than either.
pub fn verify_authorization(
    advertisement: &Verified,
    trust: &Trust,
    now_ms: i64,
) -> Result<(), RecordError> {
    let r = advertisement.record();
    if r.record_type != RecordType::PROCEDURE_ADVERTISEMENT {
        return Err(malformed("not a procedure advertisement"));
    }
    let read = read_procedure_advertisement(r)?;
    let org = procedure_org(&read.procedure)?;
    if let Some(org) = org.filter(|o| o.starts_with(OWN_NAMESPACE_PREFIX)) {
        return own_node(&org[OWN_NAMESPACE_PREFIX.len()..], &read);
    }
    match (org, &read.authorization) {
        (None, Authorization::None) => Ok(()),
        (None, _) => Err(RecordError::AuthorizationNotAllowed),
        (Some(_), Authorization::None) => Err(RecordError::NoAuthorization),
        (
            Some(org),
            Authorization::Delegation {
                org_directory,
                procedure_delegation,
            },
        ) => delegation_path(
            r,
            &read,
            org,
            org_directory,
            procedure_delegation,
            trust,
            now_ms,
        ),
        (Some(_), Authorization::Unsupported) => Err(RecordError::AuthorizationFormUnsupported),
        (Some(_), Authorization::Malformed) => Err(malformed(
            "an org directory and a procedure delegation that are not both byte strings",
        )),
    }
}

fn delegation_path(
    advertisement: &Record,
    read: &ProcedureAdvertisement,
    org: &str,
    directory_wire: &[u8],
    delegation_wire: &[u8],
    trust: &Trust,
    now_ms: i64,
) -> Result<(), RecordError> {
    let realm_key = trust.realm_key.as_ref().ok_or(RecordError::NoRealmKey)?;
    let directory = verify(directory_wire, trust.profile, now_ms)
        .map_err(|e| RecordError::OrgDirectoryInvalid(e.to_string()))?
        .into_record();
    let named = read_org_directory(&directory)
        .map_err(|e| RecordError::OrgDirectoryInvalid(e.to_string()))?;
    let directory_key = directory.signed.as_ref().map(|s| &s.key);
    if directory_key != Some(realm_key) || named.realm_id != read.realm_id {
        return Err(RecordError::OrgDirectoryWrongRealm);
    }
    if named.org_name != org {
        return Err(RecordError::OrgDirectoryWrongOrg);
    }
    let delegation = verify(delegation_wire, trust.profile, now_ms)
        .map_err(|e| RecordError::DelegationInvalid(e.to_string()))?
        .into_record();
    let granted = read_procedure_delegation(&delegation)
        .map_err(|e| RecordError::DelegationInvalid(e.to_string()))?;
    let delegation_key_id = delegation.signed.as_ref().map(|s| s.key_id);
    if delegation_key_id != Some(named.org_key) || granted.advertiser != read.advertiser_node {
        return Err(RecordError::DelegationMismatch);
    }
    if advertisement.expires_at > directory.expires_at.min(delegation.expires_at) {
        return Err(RecordError::AuthorizationOutlived);
    }
    Ok(())
}

/// An org directory's payload: a realm's statement that the org `org_name`
/// is held by the key with key id `org_key`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgDirectory {
    pub realm_id: [u8; 32],
    pub org_name: String,
    pub org_key: [u8; 32],
}

/// Reads an org directory's payload.
pub fn read_org_directory(r: &Record) -> Result<OrgDirectory, RecordError> {
    if r.record_type != RecordType::ORG_DIRECTORY {
        return Err(malformed("not an org directory"));
    }
    Ok(OrgDirectory {
        realm_id: id_field(&r.payload, "realm_id"),
        org_name: text_field(&r.payload, "org_name"),
        org_key: id_field(&r.payload, "org_key"),
    })
}

/// A procedure delegation's payload: an org's grant, signed by its org key,
/// that the node `advertiser` may serve procedures under the org.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcedureDelegation {
    pub org_key: [u8; 32],
    pub advertiser: [u8; 32],
}

/// Reads a procedure delegation's payload.
pub fn read_procedure_delegation(r: &Record) -> Result<ProcedureDelegation, RecordError> {
    if r.record_type != RecordType::PROCEDURE_DELEGATION {
        return Err(malformed("not a procedure delegation"));
    }
    Ok(ProcedureDelegation {
        org_key: id_field(&r.payload, "org_key"),
        advertiser: id_field(&r.payload, "advertiser"),
    })
}
