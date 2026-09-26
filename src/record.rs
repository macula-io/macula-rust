//! macula 12's DHT records, as macula_record and macula-go sign and verify
//! them. A record is the signed object `{key, tbs, signature}` under
//! MACULA-PQ-RECORD-V1; its tbs holds type, alg, version, created_at,
//! expires_at and payload, and subject only on a domain type (tags 0x20 to
//! 0xFF). [`sign`] refuses a key whose purpose does not fit the type; [`verify`]
//! reads a record's wire form in the design's order and keeps its tbs bytes,
//! so [`encode`] sends them unchanged.
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
mod station_endpoint;
mod storage_key;
mod tombstone;

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
pub use station_endpoint::{
    new_station_endpoint, read_station_endpoint, StationEndpoint, StationEndpointOptions,
};
pub use storage_key::{
    content_key, org_directory_key, procedure_delegation_key, procedure_key, station_endpoint_key,
    storage_key,
};
pub use tombstone::{new_tombstone, read_tombstone, Reason, Tombstone, TombstoneOptions};

use std::fmt;

use crate::cbor::{self, Value};
use crate::node_key::{key_id_of, node_id_of, signature_size, KeyError, NodeKey, Purpose};
use crate::profile::Profile;
use crate::signed_object::{sign_object, verify_object, Object, ObjectError};

const LABEL: &str = "MACULA-PQ-RECORD-V1";

/// The longest wire form a record may have, 256 KiB.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

/// How far a verifier's clock may be from a record's created_at and
/// expires_at, 5 minutes.
pub const CLOCK_TOLERANCE_MS: u64 = 5 * MINUTE_MS;

/// The longest a realm member endorsement admits its member, 30 days.
pub const MAX_ENDORSEMENT_WINDOW_MS: u64 = 30 * DAY_MS;

const MAX_PROTOCOL_INT: u64 = 1 << 53;
const MAX_PAYLOAD_NESTING: usize = 63;
const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

/// The longest a record of a type lives (D28).
const NODE_RECORD_MAX_LIFETIME_MS: u64 = 48 * HOUR_MS;
const CONTENT_ANNOUNCEMENT_MAX_LIFETIME_MS: u64 = 48 * HOUR_MS;
const PROCEDURE_ADVERTISEMENT_MAX_LIFETIME_MS: u64 = 5 * MINUTE_MS;
const STATION_ENDPOINT_TTL_MS: u64 = 5 * MINUTE_MS;
const REALM_AND_ORG_MAX_LIFETIME_MS: u64 = 6 * HOUR_MS;
const DOMAIN_RECORD_MAX_LIFETIME_MS: u64 = 7 * DAY_MS;
const DEFAULT_MAX_LIFETIME_MS: u64 = 30 * DAY_MS;
const DEFAULT_TTL_MS: u64 = 48 * HOUR_MS;

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
    pub const ORG_DIRECTORY: RecordType = RecordType(0x15);
    pub const PROCEDURE_DELEGATION: RecordType = RecordType(0x16);
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
    /// A signed object whose alg names another profile's algorithm.
    AlgMismatch,
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
/// other type.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub record_type: RecordType,
    pub version: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
    pub payload: Value,
    pub subject: Option<Vec<u8>>,
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
    Record {
        record_type,
        version: crate::uuid_v7::new(),
        created_at: now,
        expires_at: now + ttl_ms,
        payload,
        subject: None,
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
    match read_tbs(&tbs) {
        Some(read) if payload::payload_ok(read.record_type, &read.payload) => {}
        _ => return Err(malformed("a record a verifier would refuse")),
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

/// Reads a record's wire form under the verifier's `profile` and clock
/// `now_ms`, as macula_record's verify/3 does, in this order: a wire form
/// over 256 KiB, before anything is decoded; a signed object that carries its
/// key; its signature and alg; a tbs of exactly its fields; created_at no more
/// than 5 minutes ahead and expires_at no more than 5 minutes behind; a
/// lifetime within its type's maximum; its type's payload rules; and a payload
/// that names its signer by the key's id.
pub fn verify(wire: &[u8], profile: Profile, now_ms: i64) -> Result<Verified, RecordError> {
    if wire.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let value = cbor::decode(wire).map_err(|e| malformed(e.to_string()))?;
    let object = Object::from_value(&value).map_err(|e| malformed(e.to_string()))?;
    let verified = verify_object(LABEL, &value, profile).map_err(|e| match e {
        ObjectError::SignatureInvalid => RecordError::SignatureInvalid,
        ObjectError::AlgMismatch => RecordError::AlgMismatch,
        other => malformed(other.to_string()),
    })?;
    let mut r = read_tbs(&verified.fields).ok_or_else(|| malformed("a tbs of another shape"))?;
    let created = r.created_at as i64;
    let expires = r.expires_at as i64;
    let tolerance = CLOCK_TOLERANCE_MS as i64;
    if created > now_ms + tolerance {
        return Err(RecordError::NotYetValid);
    }
    if expires + tolerance < now_ms {
        return Err(RecordError::Expired);
    }
    lifetime(&r)?;
    if !payload::payload_ok(r.record_type, &r.payload) {
        return Err(malformed("a payload its type's rules refuse"));
    }
    let key_id = key_id_by_kind(r.record_type.0, &r.payload, &verified.key, profile);
    if !named_signer(r.record_type, &r.payload, &key_id) {
        return Err(RecordError::KeyIdMismatch);
    }
    r.signed = Some(Signed {
        key: verified.key,
        key_id,
        alg: profile.sig_alg().to_string(),
        tbs: verified.tbs,
        signature: object.signature,
    });
    Ok(Verified(r))
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
    ];
    if let Some(subject) = &r.subject {
        fields.push((Value::text("subject"), Value::Bytes(subject.clone())));
    }
    fields
}

/// A verified record's tbs, as macula_record's read_tbs does: exactly type
/// (1 to 255), alg, version (16 bytes), created_at and expires_at (below
/// 2^53), payload (a map), and subject (bytes, not empty) only on a domain
/// type.
fn read_tbs(tbs: &Value) -> Option<Record> {
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
    let created_at = protocol_uint(field("created_at")?)?;
    let expires_at = protocol_uint(field("expires_at")?)?;
    let payload = field("payload")?;
    if !matches!(payload, Value::Map(_)) {
        return None;
    }
    let mut r = Record {
        record_type,
        version,
        created_at,
        expires_at,
        payload: payload.clone(),
        subject: None,
        signed: None,
    };
    match (pairs.len(), field("subject")) {
        (6, None) => Some(r),
        (7, Some(Value::Bytes(subject))) if !subject.is_empty() && record_type.is_domain() => {
            r.subject = Some(subject.clone());
            Some(r)
        }
        _ => None,
    }
}

fn protocol_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Int(n) if *n >= 0 && *n < i128::from(MAX_PROTOCOL_INT) => Some(*n as u64),
        _ => None,
    }
}

/// Refuses a record whose lifetime does not run forward, or is longer than
/// its type's maximum.
fn lifetime(r: &Record) -> Result<(), RecordError> {
    let lived = r.expires_at as i128 - r.created_at as i128;
    if lived <= 0 {
        return Err(RecordError::LifetimeReversed);
    }
    if lived > i128::from(max_lifetime(i128::from(r.record_type.0), &r.payload)) {
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

/// The longest a record of type `t` lives, as macula_record's max_lifetime/2
/// has it. A tombstone's follows the type it withdraws, plus twice the clock
/// tolerance.
fn max_lifetime(t: i128, payload: &Value) -> u64 {
    match t {
        0x01 => NODE_RECORD_MAX_LIFETIME_MS,
        0x11 => CONTENT_ANNOUNCEMENT_MAX_LIFETIME_MS,
        0x06 => PROCEDURE_ADVERTISEMENT_MAX_LIFETIME_MS,
        0x12 => STATION_ENDPOINT_TTL_MS,
        0x04 | 0x15 | 0x16 => REALM_AND_ORG_MAX_LIFETIME_MS,
        0x05 => MAX_ENDORSEMENT_WINDOW_MS,
        0x0C => match withdrawn_type(payload) {
            None | Some(Some(0x0C)) => DEFAULT_MAX_LIFETIME_MS,
            Some(None) => DEFAULT_MAX_LIFETIME_MS + 2 * CLOCK_TOLERANCE_MS,
            Some(Some(w)) => max_lifetime(w, &Value::Map(Vec::new())) + 2 * CLOCK_TOLERANCE_MS,
        },
        t if t >= 0x20 => DOMAIN_RECORD_MAX_LIFETIME_MS,
        _ => DEFAULT_MAX_LIFETIME_MS,
    }
}

/// The lifetime a builder given no ttl takes: 48 hours, or the type's
/// maximum when shorter.
fn default_ttl(t: RecordType) -> u64 {
    DEFAULT_TTL_MS.min(max_lifetime(i128::from(t.0), &Value::Map(Vec::new())))
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
    matches!(t, 0x01 | 0x03..=0x06 | 0x0D..=0x12 | 0x15 | 0x16) || t >= 0x20
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
