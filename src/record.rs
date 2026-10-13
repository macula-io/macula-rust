//! Wire 1.0's DHT records (WIRE_1_0.md section 5, macula#100). A record is
//! the signed object `{key, tbs, signature}` under MACULA-PQ-RECORD-V1; its
//! tbs holds type, alg, version, created_at, expires_at, schema,
//! lifetime_class and payload, and subject and ext where present. [`sign`]
//! refuses a key whose purpose does not fit the type. [`check_as_custodian`]
//! runs the checks a station stores any record by, known type or not, and
//! never reads a payload; [`verify`] runs them and then a reader's own, and
//! keeps the tbs bytes, so [`encode`] sends them unchanged.
//!
//! A record is named by the key id of its key: the node_id for node records,
//! procedure advertisements, content announcements and station endpoints, and
//! the key id for every other type. A tombstone is named as the type it
//! withdraws.

mod authorization;
mod content_announcement;
mod node_record;
mod payload;
mod procedure_advertisement;
mod station_authorization;
mod station_endpoint;
mod storage_key;
mod tombstone;
#[cfg(test)]
mod wire_1_0_tests;

pub use authorization::{
    in_own_namespace, namespace_node, own_namespace, own_procedure, procedure_org,
    read_org_directory, read_procedure_delegation, verify_authorization, OrgDirectory,
    ProcedureDelegation, Trust, OWN_NAMESPACE_PREFIX,
};
pub use content_announcement::{
    new_content_announcement, read_content_announcement, ContentAnnouncement,
    ContentAnnouncementOptions,
};
pub use node_record::{new_node_record, read_node_record, NodeRecord, NodeRecordOptions};
pub use procedure_advertisement::{
    new_procedure_advertisement, read_procedure_advertisement, Authorization,
    ProcedureAdvertisement, ProcedureAdvertisementOptions,
};
pub use station_authorization::{read_station_authorization, StationAuthorization};
pub use station_endpoint::{
    new_station_endpoint, read_station_endpoint, StationEndpoint, StationEndpointOptions,
};
pub use storage_key::{
    app_record_key, content_key, org_directory_key, procedure_delegation_key, procedure_key,
    station_authorization_key, station_endpoint_key, storage_key,
};
pub use tombstone::{new_tombstone, read_tombstone, Reason, Tombstone, TombstoneOptions};

use std::fmt;

use crate::cbor::{self, Value};
use crate::node_key::{key_id_of, node_id_of, signature_size, KeyError, NodeKey, Purpose};
use crate::profile::Profile;
use crate::signed_object::{sign_object, verify_object_by_alg, Object, ObjectError};

const LABEL: &str = "MACULA-PQ-RECORD-V1";

/// The longest wire form a record may have, 256 KiB.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

/// How far a verifier's clock may be from a record's created_at and
/// expires_at, 5 minutes.
pub const CLOCK_TOLERANCE_MS: u64 = 5 * MINUTE_MS;

/// The longest a realm member endorsement admits its member, 30 days.
pub const MAX_ENDORSEMENT_WINDOW_MS: u64 = 30 * DAY_MS;

/// The schema version every built-in type has in wire 1.0; readers check it,
/// custodians do not (WIRE_1_0.md section 5.1).
pub const SCHEMA: u16 = 1;

/// The frozen lifetime table (WIRE_1_0.md section 5.1): a record's
/// lifetime_class is a row, and it lives at most that row's maximum. Rows are
/// only added, and a row's maximum never grows.
pub const LIFETIME_CLASS_MAX_MS: [u64; 6] = [
    5 * MINUTE_MS,
    30 * MINUTE_MS,
    6 * HOUR_MS,
    48 * HOUR_MS,
    7 * DAY_MS,
    30 * DAY_MS,
];

const MAX_PROTOCOL_INT: u64 = 1 << 53;
const MAX_PAYLOAD_NESTING: usize = 63;
const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;
const DEFAULT_TTL_MS: u64 = 48 * HOUR_MS;

/// The rows the types this crate knows name.
const ROW_5_MINUTES: u8 = 0;
const ROW_30_MINUTES: u8 = 1;
const ROW_6_HOURS: u8 = 2;
const ROW_48_HOURS: u8 = 3;
const ROW_7_DAYS: u8 = 4;
const ROW_30_DAYS: u8 = 5;

/// A record's type tag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(pub u8);

impl RecordType {
    pub const NODE_RECORD: RecordType = RecordType(0x01);
    pub const REALM_DIRECTORY: RecordType = RecordType(0x03);
    pub const REALM_STATIONS: RecordType = RecordType(0x04);
    pub const REALM_MEMBER_ENDORSEMENT: RecordType = RecordType(0x05);
    pub const PROCEDURE_ADVERTISEMENT: RecordType = RecordType(0x06);
    pub const TOMBSTONE: RecordType = RecordType(0x0C);
    pub const FOUNDATION_SEED_LIST: RecordType = RecordType(0x0D);
    pub const FOUNDATION_PARAMETER: RecordType = RecordType(0x0E);
    pub const FOUNDATION_REALM_TRUST_LIST: RecordType = RecordType(0x0F);
    pub const FOUNDATION_T3_ATTESTATION: RecordType = RecordType(0x10);
    pub const CONTENT_ANNOUNCEMENT: RecordType = RecordType(0x11);
    pub const STATION_ENDPOINT: RecordType = RecordType(0x12);
    pub const STATION_AUTHORIZATION: RecordType = RecordType(0x13);
    pub const ORG_DIRECTORY: RecordType = RecordType(0x15);
    pub const PROCEDURE_DELEGATION: RecordType = RecordType(0x16);
    pub const APP_RECORD: RecordType = RecordType(0x17);
    /// Tags from here to 0xFF are domain types, whose owners set their
    /// payload rules.
    pub const DOMAIN_MIN: RecordType = RecordType(0x20);

    fn is_domain(self) -> bool {
        self >= RecordType::DOMAIN_MIN
    }
}

/// The refusals of a record, named as macula_record names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// A wire form over 256 KiB.
    TooLarge,
    /// A record without exactly the shape, fields and payload of its type,
    /// and what.
    Malformed(String),
    /// Created more than 5 minutes ahead of the verifier's clock.
    NotYetValid,
    /// Expired more than 5 minutes before the verifier's clock.
    Expired,
    /// A payload that names a signer other than the key id of its key.
    KeyIdMismatch,
    /// A lifetime over its type's maximum.
    LifetimeTooLong,
    /// Expires no later than it is created.
    LifetimeReversed,
    /// A key whose purpose does not fit the type it would sign.
    KeyPurposeMismatch,
    /// A record with no key, tbs or signature to encode.
    Unsigned,
    /// A domain envelope for a built-in type.
    NotADomainType,
    /// A domain record's subject that is empty.
    InvalidSubject,
    /// A signature that does not verify.
    SignatureInvalid,
    /// An alg the verifier's allowlist does not hold, refused before any
    /// signature work (`alg_unsupported`).
    AlgUnsupported,
    /// A lifetime_class that names no row of the frozen table.
    LifetimeClassUnknown,
    /// A known type's lifetime_class that is not its own row.
    LifetimeClassMismatch,
    /// A type with no slot rule of its own that carries no subject to place
    /// it by.
    SubjectMissing,
    /// A type the reader does not know; a custodian stores it.
    TypeUnknown,
    /// A schema the reader does not read; a custodian stores it.
    SchemaUnsupported,
    /// A content id whose tag the reader does not know; a custodian stores
    /// it.
    McidTagUnknown,
    /// A critical extension the reader does not know, by name.
    ExtensionUnsupported(String),
    /// A node record coordinate that is not a number within its range.
    InvalidCoordinate(String),
    /// A station endpoint's QUIC port of 0.
    InvalidPort,
    /// Not a tag 2 content id of 50 bytes.
    NotAContentId,
    /// A tombstone built to withdraw a tombstone.
    TombstoneOfATombstone,
    /// An org procedure's advertisement that carries no authorization.
    NoAuthorization,
    /// An authorization on a procedure whose namespace takes none.
    AuthorizationNotAllowed,
    /// An authorization in a form macula 12 does not have, a certificate
    /// chain among them.
    AuthorizationFormUnsupported,
    /// An advertisement that is not in its advertiser's own namespace.
    NotOwnNamespace,
    /// An authorization checked without a trusted realm key.
    NoRealmKey,
    /// An org directory that does not verify as one, and why.
    OrgDirectoryInvalid(String),
    /// An org directory the trusted realm key did not sign, or for another
    /// realm.
    OrgDirectoryWrongRealm,
    /// An org directory for another org.
    OrgDirectoryWrongOrg,
    /// A procedure delegation that does not verify as one, and why.
    DelegationInvalid(String),
    /// A delegation the org key did not sign, or for another advertiser.
    DelegationMismatch,
    /// An advertisement that expires after its org directory or delegation.
    AuthorizationOutlived,
    /// The key could not sign.
    Key(KeyError),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Malformed(why) => write!(f, "malformed record: {why}"),
            RecordError::InvalidCoordinate(what) => {
                write!(f, "a coordinate outside its range: {what}")
            }
            RecordError::OrgDirectoryInvalid(why) => {
                write!(f, "the org directory does not verify: {why}")
            }
            RecordError::DelegationInvalid(why) => {
                write!(f, "the procedure delegation does not verify: {why}")
            }
            RecordError::Key(e) => write!(f, "{e}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for RecordError {}

fn malformed(why: impl Into<String>) -> RecordError {
    RecordError::Malformed(why.into())
}

/// What signing or verifying gave a record: the key as carried, its key id,
/// the alg, the tbs bytes, and the signature.
#[derive(Debug, Clone, PartialEq)]
pub struct Signed {
    pub key: Vec<u8>,
    pub key_id: [u8; 32],
    pub alg: String,
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A record: unsigned as a builder returns it, or signed or verified, when
/// `signed` holds what signing or verifying gave. The payload is a map.
/// `subject` names a domain record's subject, `None` for none and on every
/// other type. `schema` and `lifetime_class` are the tbs's schema version and
/// lifetime row, which a builder sets to [`SCHEMA`] and the type's own row;
/// `ext` is the tbs's ext map, `None` for none.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub record_type: RecordType,
    pub version: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
    pub payload: Value,
    pub subject: Option<Vec<u8>>,
    pub schema: u16,
    pub lifetime_class: u8,
    pub ext: Option<Value>,
    pub signed: Option<Signed>,
}

/// A record of `record_type`, created now with a UUID v7 version, living
/// `ttl_ms`, or its type's default when `ttl_ms` is 0.
fn unsigned(record_type: RecordType, payload: Value, ttl_ms: u64) -> Record {
    let ttl_ms = if ttl_ms == 0 {
        default_ttl(record_type)
    } else {
        ttl_ms
    };
    let now = crate::uuid_v7::now_ms();
    let (lifetime_class, _) = type_row(i128::from(record_type.0), &payload);
    Record {
        record_type,
        version: crate::uuid_v7::new(),
        created_at: now,
        expires_at: now + ttl_ms,
        payload,
        subject: None,
        schema: SCHEMA,
        lifetime_class,
        ext: None,
        signed: None,
    }
}

/// An unsigned record of a domain type, 0x20 to 0xFF, with `subject`, living
/// `ttl_ms`, or 48 hours when 0. An empty subject would name a slot apart
/// from no subject, so it is refused.
pub fn envelope(
    record_type: u8,
    payload: Value,
    subject: Option<Vec<u8>>,
    ttl_ms: u64,
) -> Result<Record, RecordError> {
    let t = RecordType(record_type);
    if !t.is_domain() {
        return Err(RecordError::NotADomainType);
    }
    if subject.as_ref().is_some_and(|s| s.is_empty()) {
        return Err(RecordError::InvalidSubject);
    }
    let mut r = unsigned(t, payload, ttl_ms);
    r.subject = subject;
    Ok(r)
}

/// Signs `r` with `key`, as macula_record's sign/2 does. Refused, in
/// macula's order: a key whose purpose does not fit the type; a lifetime that
/// runs backwards or past its type's maximum; a payload that names a signer
/// other than the key; a tbs or payload a verifier would refuse; and a record
/// over 256 KiB.
pub fn sign(r: &Record, key: &NodeKey) -> Result<Record, RecordError> {
    let profile = key.profile();
    if !signer_may_sign(r.record_type.0, &r.payload, key.purpose()) {
        return Err(RecordError::KeyPurposeMismatch);
    }
    lifetime(r)?;
    let carried = key.public_key();
    let key_id = key_id_by_kind(r.record_type.0, &r.payload, &carried, profile);
    if !named_signer(r.record_type, &r.payload, &key_id) {
        return Err(RecordError::KeyIdMismatch);
    }
    let fields = tbs_fields(r);
    let mut with_alg = fields.clone();
    with_alg.push((Value::text("alg"), Value::text(profile.sig_alg())));
    let encoded = cbor::encode(&Value::Map(with_alg)).map_err(|e| malformed(e.to_string()))?;
    let tbs = cbor::decode(&encoded)
        .map_err(|e| malformed(format!("a tbs the decoding rule refuses: {e}")))?;
    let read = read_envelope_tbs(&tbs).ok_or_else(|| malformed("a tbs of another shape"))?;
    if reader_knows(&read)
        .and_then(|()| payload_checks(&read))
        .is_err()
    {
        return Err(malformed("a record a verifier would refuse"));
    }
    let unsigned_size = cbor::encode(&Value::Map(fields.clone()))
        .map_err(|e| malformed(e.to_string()))?
        .len()
        + carried.len()
        + signature_size(profile);
    if unsigned_size > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let object = sign_object(LABEL, &fields, key).map_err(|e| match e {
        ObjectError::Key(k) => RecordError::Key(k),
        other => malformed(other.to_string()),
    })?;
    let wire = cbor::encode(&object.to_value()).map_err(|e| malformed(e.to_string()))?;
    if wire.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let mut out = r.clone();
    out.signed = Some(Signed {
        key: object.key,
        key_id,
        alg: profile.sig_alg().to_string(),
        tbs: object.tbs,
        signature: object.signature,
    });
    Ok(out)
}

/// `r` with a new version, created now, with the same lifetime, signed again
/// with `key`.
pub fn refresh(r: &Record, key: &NodeKey) -> Result<Record, RecordError> {
    let now = crate::uuid_v7::now_ms();
    let fresh = Record {
        version: crate::uuid_v7::new(),
        created_at: now,
        expires_at: now + r.expires_at.saturating_sub(r.created_at),
        signed: None,
        ..r.clone()
    };
    sign(&fresh, key)
}

/// The wire form of a signed or verified record: its `{key, tbs, signature}`
/// map, tbs unchanged.
pub fn encode(r: &Record) -> Result<Vec<u8>, RecordError> {
    let signed = r.signed.as_ref().ok_or(RecordError::Unsigned)?;
    let object = Object {
        key: signed.key.clone(),
        tbs: signed.tbs.clone(),
        signature: signed.signature.clone(),
    };
    cbor::encode(&object.to_value()).map_err(|e| malformed(e.to_string()))
}

/// A record [`verify`] returned. Only `verify` makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified(Record);

impl Verified {
    /// The verified record.
    pub fn record(&self) -> &Record {
        &self.0
    }

    /// The verified record, taken.
    pub fn into_record(self) -> Record {
        self.0
    }
}

/// Reads a record's wire form as a reader does (WIRE_1_0.md section 5.2),
/// under the verifier's `profile` and clock `now_ms`: a custodian's checks
/// first ([`check_as_custodian`]'s), then a reader's own, in this order: a
/// type it knows, a schema it reads; an unknown critical extension, an
/// unknown non-critical one counted; the type's payload rules, a content id
/// tag it knows, and a payload that names its signer by the key's id.
pub fn verify(wire: &[u8], profile: Profile, now_ms: i64) -> Result<Verified, RecordError> {
    let r = custodian_checks(wire, profile, now_ms)?;
    reader_knows(&r)?;
    if let Some(ext) = &r.ext {
        crate::frame::act_on_ext(ext).map_err(|e| match e {
            crate::frame::FrameError::ExtensionUnsupported(name) => {
                RecordError::ExtensionUnsupported(name)
            }
            other => malformed(other.to_string()),
        })?;
    }
    payload_checks(&r)?;
    let key_id = r.signed.as_ref().map(|s| s.key_id).unwrap_or_default();
    if !named_signer(r.record_type, &r.payload, &key_id) {
        return Err(RecordError::KeyIdMismatch);
    }
    Ok(Verified(r))
}

/// Runs the checks a station stores a record by (WIRE_1_0.md section 5.2,
/// steps 1 to 9), under `profile`'s alg allowlist and the clock `now_ms`, in
/// this order: a wire form over 256 KiB; a signed object of key, tbs and
/// signature; a tbs under the decoding rule holding alg as text; alg on the
/// allowlist, and key in its carried form; the signature; a tbs of exactly
/// the envelope keys, each of its type; the clock, with 5 minutes of
/// tolerance; the lifetime against the row it names, then a known type's own
/// row; the slot. It never reads a payload beyond its type's slot rule, never
/// checks schema, and stores any type, known or not. It returns the record's
/// storage key: its type's own slot, or for a type with none,
/// H(type | signer key id | subject).
pub fn check_as_custodian(
    wire: &[u8],
    profile: Profile,
    now_ms: i64,
) -> Result<[u8; 32], RecordError> {
    custodian_slot(&custodian_checks(wire, profile, now_ms)?)
}

/// Section 5.2's steps 1 to 9: the record read, signed with what verifying
/// gave.
fn custodian_checks(wire: &[u8], profile: Profile, now_ms: i64) -> Result<Record, RecordError> {
    if wire.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let value = cbor::decode(wire).map_err(|e| malformed(e.to_string()))?;
    let object = Object::from_value(&value).map_err(|e| malformed(e.to_string()))?;
    let verified = verify_object_by_alg(LABEL, &value, profile).map_err(|e| match e {
        ObjectError::SignatureInvalid => RecordError::SignatureInvalid,
        ObjectError::AlgUnsupported(_) => RecordError::AlgUnsupported,
        other => malformed(other.to_string()),
    })?;
    let mut r =
        read_envelope_tbs(&verified.fields).ok_or_else(|| malformed("a tbs of another shape"))?;
    clock(&r, now_ms)?;
    lifetime(&r)?;
    let (row, known) = type_row(i128::from(r.record_type.0), &r.payload);
    if known && r.lifetime_class != row {
        return Err(RecordError::LifetimeClassMismatch);
    }
    let key_id = key_id_by_kind(r.record_type.0, &r.payload, &verified.key, profile);
    r.signed = Some(Signed {
        key: verified.key,
        key_id,
        alg: profile.sig_alg().to_string(),
        tbs: verified.tbs,
        signature: object.signature,
    });
    custodian_slot(&r)?;
    Ok(r)
}

/// A record's slot as a custodian places it: a known type by its own rule,
/// any other by H(type | signer key id | subject), refusing one without a
/// subject.
fn custodian_slot(r: &Record) -> Result<[u8; 32], RecordError> {
    if type_row(i128::from(r.record_type.0), &r.payload).1 {
        return storage_key(r).map_err(|e| match e {
            RecordError::Malformed(why) => RecordError::Malformed(why),
            other => malformed(other.to_string()),
        });
    }
    let subject = r.subject.as_deref().ok_or(RecordError::SubjectMissing)?;
    let key_id = r.signed.as_ref().ok_or(RecordError::Unsigned)?.key_id;
    Ok(storage_key::unknown_type_key(
        r.record_type.0,
        &key_id,
        subject,
    ))
}

/// A reader's step 10: a type this crate knows and a schema it reads.
fn reader_knows(r: &Record) -> Result<(), RecordError> {
    if !type_row(i128::from(r.record_type.0), &r.payload).1 {
        return Err(RecordError::TypeUnknown);
    }
    if r.schema != SCHEMA {
        return Err(RecordError::SchemaUnsupported);
    }
    Ok(())
}

/// A reader's step 12 before the signer: the type's payload rules, with no
/// subject on a built-in type, and a content id tag this crate knows.
fn payload_checks(r: &Record) -> Result<(), RecordError> {
    let lifetime_class_is_own =
        type_row(i128::from(r.record_type.0), &r.payload).0 == r.lifetime_class;
    if (r.subject.is_some() && !r.record_type.is_domain())
        || !payload::payload_ok(r.record_type, &r.payload)
        || !lifetime_class_is_own
    {
        return Err(malformed("a payload its type's rules refuse"));
    }
    payload::content_id_tag_known(r.record_type, &r.payload)
}

/// Refuses a record created more than the clock tolerance ahead of `now_ms`,
/// or expired more than the tolerance before it.
fn clock(r: &Record, now_ms: i64) -> Result<(), RecordError> {
    let tolerance = CLOCK_TOLERANCE_MS as i64;
    if r.created_at as i64 > now_ms + tolerance {
        return Err(RecordError::NotYetValid);
    }
    if (r.expires_at as i64) + tolerance < now_ms {
        return Err(RecordError::Expired);
    }
    Ok(())
}

/// Checks a payload before anything is signed: its encoding is at most 256
/// KiB, and it nests at most 63 levels, which a record's tbs leaves it under
/// the decoding rule's 64.
pub fn payload_bounded(payload: &Value) -> Result<(), RecordError> {
    let size = cbor::encode(payload)
        .map_err(|e| malformed(e.to_string()))?
        .len();
    if size > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    if nesting(payload, 0) > MAX_PAYLOAD_NESTING {
        return Err(malformed("a payload nested past 63 levels"));
    }
    Ok(())
}

fn nesting(v: &Value, depth: usize) -> usize {
    let children: Vec<&Value> = match v {
        Value::List(items) => items.iter().collect(),
        Value::Map(pairs) => pairs.iter().flat_map(|(k, v)| [k, v]).collect(),
        _ => return depth,
    };
    let mut deepest = depth + 1;
    for child in children {
        if deepest > MAX_PAYLOAD_NESTING {
            break;
        }
        deepest = deepest.max(nesting(child, depth + 1));
    }
    deepest
}

fn tbs_fields(r: &Record) -> Vec<(Value, Value)> {
    let mut fields = vec![
        (Value::text("type"), Value::Int(i128::from(r.record_type.0))),
        (Value::text("version"), Value::Bytes(r.version.to_vec())),
        (
            Value::text("created_at"),
            Value::Int(i128::from(r.created_at)),
        ),
        (
            Value::text("expires_at"),
            Value::Int(i128::from(r.expires_at)),
        ),
        (Value::text("payload"), r.payload.clone()),
        (Value::text("schema"), Value::Int(i128::from(r.schema))),
        (
            Value::text("lifetime_class"),
            Value::Int(i128::from(r.lifetime_class)),
        ),
    ];
    if let Some(subject) = &r.subject {
        fields.push((Value::text("subject"), Value::Bytes(subject.clone())));
    }
    if let Some(ext) = &r.ext {
        fields.push((Value::text("ext"), ext.clone()));
    }
    fields
}

/// A verified record's tbs as section 5.2's step 6 reads it: exactly type
/// (1 to 255), alg (text), version (16 bytes), created_at and expires_at
/// (below 2^53), schema (1 to 65535), lifetime_class (below 2^53), payload (a
/// map, not otherwise read), and, where present, subject (bytes, not empty)
/// and ext (a well-formed ext map, not acted on).
fn read_envelope_tbs(tbs: &Value) -> Option<Record> {
    let Value::Map(pairs) = tbs else {
        return None;
    };
    let field = |name: &str| tbs.get(name);
    let record_type = match field("type")? {
        Value::Int(n) if (1..=255).contains(n) => RecordType(*n as u8),
        _ => return None,
    };
    let Value::Text(_) = field("alg")? else {
        return None;
    };
    let version: [u8; 16] = match field("version")? {
        Value::Bytes(b) => b.as_slice().try_into().ok()?,
        _ => return None,
    };
    let schema = match field("schema")? {
        Value::Int(n) if (1..=65535).contains(n) => *n as u16,
        _ => return None,
    };
    let lifetime_class = protocol_uint(field("lifetime_class")?)?;
    let payload = field("payload")?;
    if !matches!(payload, Value::Map(_)) {
        return None;
    }
    let subject = match field("subject") {
        None => None,
        Some(Value::Bytes(s)) if !s.is_empty() => Some(s.clone()),
        Some(_) => return None,
    };
    let ext = match field("ext") {
        None => None,
        Some(ext) => {
            crate::frame::check_ext(ext).ok()?;
            Some(ext.clone())
        }
    };
    let size = 8 + usize::from(subject.is_some()) + usize::from(ext.is_some());
    if pairs.len() != size {
        return None;
    }
    Some(Record {
        record_type,
        version,
        created_at: protocol_uint(field("created_at")?)?,
        expires_at: protocol_uint(field("expires_at")?)?,
        payload: payload.clone(),
        subject,
        schema,
        lifetime_class: u8::try_from(lifetime_class).unwrap_or(u8::MAX),
        ext,
        signed: None,
    })
}

fn protocol_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Int(n) if *n >= 0 && *n < i128::from(MAX_PROTOCOL_INT) => Some(*n as u64),
        _ => None,
    }
}

/// Refuses a record whose lifetime does not run forward, whose
/// lifetime_class names no row of the frozen table, or that lives longer
/// than its row's maximum (section 5.1). A tombstone may live twice the clock
/// tolerance past its row: it outlives a record that may have been created
/// up to the tolerance ahead, by the tolerance.
fn lifetime(r: &Record) -> Result<(), RecordError> {
    let lived = r.expires_at as i128 - r.created_at as i128;
    if lived <= 0 {
        return Err(RecordError::LifetimeReversed);
    }
    let Some(max) = LIFETIME_CLASS_MAX_MS.get(usize::from(r.lifetime_class)) else {
        return Err(RecordError::LifetimeClassUnknown);
    };
    let margin = match r.record_type {
        RecordType::TOMBSTONE => 2 * CLOCK_TOLERANCE_MS,
        _ => 0,
    };
    if lived > i128::from(max + margin) {
        return Err(RecordError::LifetimeTooLong);
    }
    Ok(())
}

/// The withdrawn_type a tombstone's payload names, when it is an integer.
fn withdrawn_type(payload: &Value) -> Option<Option<i128>> {
    match payload.get("withdrawn_type") {
        None => None,
        Some(Value::Int(n)) => Some(Some(*n)),
        Some(_) => Some(None),
    }
}

/// The row a record of type `t` names (section 5.1), and whether this crate
/// knows the type: node record and content announcement 48 hours; procedure
/// advertisement and station endpoint 5 minutes; realm stations and org
/// directory 6 hours; procedure delegation, app record and station
/// authorization 30 minutes; a domain type 7 days; the other built-in types it
/// knows 30 days; and a tombstone the row of the type it withdraws.
fn type_row(t: i128, payload: &Value) -> (u8, bool) {
    match t {
        0x01 | 0x11 => (ROW_48_HOURS, true),
        0x06 | 0x12 => (ROW_5_MINUTES, true),
        0x04 | 0x15 => (ROW_6_HOURS, true),
        0x13 | 0x16 | 0x17 => (ROW_30_MINUTES, true),
        0x03 | 0x05 | 0x0D..=0x10 => (ROW_30_DAYS, true),
        0x0C => match withdrawn_type(payload) {
            Some(Some(w)) if w != 0x0C => (type_row(w, &Value::Map(Vec::new())).0, true),
            _ => (ROW_30_DAYS, true),
        },
        0x20..=0xFF => (ROW_7_DAYS, true),
        _ => (ROW_30_DAYS, false),
    }
}

/// The lifetime a builder given no ttl takes: 48 hours, or the type's row's
/// maximum when that is shorter.
fn default_ttl(t: RecordType) -> u64 {
    let (row, _) = type_row(i128::from(t.0), &Value::Map(Vec::new()));
    DEFAULT_TTL_MS.min(LIFETIME_CLASS_MAX_MS[usize::from(row)])
}

/// Whether a key of `purpose` may sign a record of type `t`, as
/// macula_record's signer_purposes/2 has it: an identity key signs node
/// records, procedure advertisements, content announcements, station
/// endpoints and domain records; the realm, org and foundation types are
/// their keys'; a tombstone is signed like the type it withdraws.
fn signer_may_sign(t: u8, payload: &Value, purpose: Purpose) -> bool {
    match t {
        0x0C => match withdrawn_type(payload) {
            Some(Some(w)) if (0..=255).contains(&w) && w != 0x0C => {
                signer_may_sign(w as u8, &Value::Map(Vec::new()), purpose)
            }
            _ => false,
        },
        0x01 | 0x06 | 0x11 | 0x12 => purpose == Purpose::Identity,
        t if t >= 0x20 => purpose == Purpose::Identity,
        _ => false,
    }
}

/// Whether a type is signed by some key at all, which a withdrawable type
/// must be.
fn signed_by_some_key(t: i128) -> bool {
    matches!(t, 0x01 | 0x03..=0x06 | 0x0D..=0x13 | 0x15..=0x17) || t >= 0x20
}

/// Whether a record of type `t` names its signer by node_id rather than key
/// id. A tombstone is named as the type it withdraws.
fn named_by_node_id(t: u8, payload: &Value) -> bool {
    let t = if t == 0x0C {
        match withdrawn_type(payload) {
            Some(Some(w)) => w,
            _ => return false,
        }
    } else {
        i128::from(t)
    };
    matches!(t, 0x01 | 0x06 | 0x11 | 0x12)
}

fn key_id_by_kind(t: u8, payload: &Value, carried: &[u8], profile: Profile) -> [u8; 32] {
    if named_by_node_id(t, payload) {
        node_id_of(carried, profile)
    } else {
        key_id_of(carried, profile)
    }
}

/// Whether the payload field that names a type's signer, where the type has
/// one, holds `key_id`.
fn named_signer(t: RecordType, payload: &Value, key_id: &[u8; 32]) -> bool {
    let name = match t {
        RecordType::NODE_RECORD => "node_id",
        RecordType::PROCEDURE_ADVERTISEMENT => "advertiser_node",
        RecordType::CONTENT_ANNOUNCEMENT => "announcer_node",
        RecordType::PROCEDURE_DELEGATION => "org_key",
        _ => return true,
    };
    matches!(payload.get(name), Some(Value::Bytes(b)) if b.as_slice() == key_id)
}

/// A 32-byte id field of `payload`, or zeros.
fn id_field(payload: &Value, name: &str) -> [u8; 32] {
    match payload.get(name) {
        Some(Value::Bytes(b)) if b.len() == 32 => b.as_slice().try_into().unwrap_or([0; 32]),
        _ => [0; 32],
    }
}

fn text_field(payload: &Value, name: &str) -> String {
    match payload.get(name) {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    }
}

fn entry(name: &str, value: Value) -> (Value, Value) {
    (Value::text(name), value)
}
