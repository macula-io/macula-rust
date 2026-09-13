//! The subset of Macula's signed DHT records that direct-dial resolution
//! needs: `procedure_advertisement` and `station_endpoint` construction,
//! signing, verification, and storage-key derivation, plus thin wrappers
//! around the mesh's `_dht.*` RPC procedures.
//!
//! Ported from `macula-io/macula`'s `src/record/macula_record.erl` and
//! `src/macula.erl` (the `put_record`/`find_record`/`find_records` facade),
//! cross-checked against `macula-go`'s own port of the same reference
//! (`dht/record.go`, `dht/client.go`) — see those files' doc comments for
//! the fuller reasoning behind each field. Only the two record types
//! direct-dial needs are ported; add more constructors here as other
//! direct-dial consumers (streaming, content) are built.
//!
//! **This is a thin RPC client, not a DHT participant.** Every function
//! here just issues an ordinary signed CALL (`_dht.put_record` etc.) to
//! whichever station the given [`Session`] is
//! already connected to — real Kademlia routing, replication, and k-bucket
//! maintenance stay entirely on the relay side (`macula-station`). Nothing
//! in this module talks DHT protocol directly.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cbor::Value;
use crate::connection::{CallError, Session};
use crate::frame::CallResponse;
use crate::identity::KeyPair;

/// Record type tags — `macula_record.erl`'s `?TYPE_*` constants.
pub const TYPE_PROCEDURE_ADVERTISEMENT: u8 = 0x06;
pub const TYPE_STATION_ENDPOINT: u8 = 0x12;
pub const TYPE_CONTENT_ANNOUNCEMENT: u8 = 0x11;

/// Matches `macula_record`'s `?DEFAULT_TTL_MS` (48h) — the TTL a
/// `procedure_advertisement` gets when the caller doesn't specify one.
pub const DEFAULT_TTL: Duration = Duration::from_secs(48 * 60 * 60);

/// The Ed25519 signature domain separator — `macula_record`'s
/// `?SIG_DOMAIN`. 17 bytes: "macula-v2-record" (16 ASCII) plus a trailing
/// NUL.
const SIG_DOMAIN: &[u8] = b"macula-v2-record\0";

/// Mirrors `macula_record.erl`'s envelope map (type/key/version/
/// created_at/expires_at/payload/signature). `subject_id` is not carried —
/// neither record type this module builds uses it.
#[derive(Debug, Clone)]
pub struct Record {
    pub record_type: u8,
    /// 32B: envelope signer's Ed25519 pubkey.
    pub key: [u8; 32],
    /// 16B: UUIDv7.
    pub version: [u8; 16],
    /// ms since epoch.
    pub created_at: i128,
    /// ms since epoch.
    pub expires_at: i128,
    pub payload: Value,
    /// 64B once [`sign`] has been called; empty beforehand.
    pub signature: Vec<u8>,
}

fn now_ms() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i128
}

fn new_envelope(record_type: u8, key: [u8; 32], payload: Value, ttl: Duration) -> Record {
    let created_at = now_ms();
    Record {
        record_type,
        key,
        version: *uuid::Uuid::now_v7().as_bytes(),
        created_at,
        expires_at: created_at + ttl.as_millis() as i128,
        payload,
        signature: Vec::new(),
    }
}

/// Builds an UNSIGNED `procedure_advertisement` record naming
/// `serving_station` as `procedure_uri`'s current handler. `procedure_uri`
/// should be the realm-qualified discovery URI (see [`discovery_uri`]),
/// matching `macula_direct_dial`'s own convention — the advertiser and the
/// resolver must derive the identical URI or the DHT storage key
/// ([`procedure_key`]) will not agree. Sign before [`put_record`].
///
/// Mirrors `macula_record:procedure_advertisement/3,4`. See
/// [`new_procedure_advertisement_with_cert_chain`] for the `cert_chain`
/// variant.
pub fn new_procedure_advertisement(
    advertiser_node: [u8; 32],
    procedure_uri: impl Into<String>,
    serving_station: [u8; 32],
    ttl: Duration,
) -> Record {
    let ttl = if ttl.is_zero() { DEFAULT_TTL } else { ttl };
    let payload = Value::Map(vec![
        (Value::text("procedure_uri"), Value::text(procedure_uri)),
        (
            Value::text("advertiser_node"),
            Value::Bytes(advertiser_node.to_vec()),
        ),
        (
            Value::text("serving_station"),
            Value::Bytes(serving_station.to_vec()),
        ),
    ]);
    new_envelope(TYPE_PROCEDURE_ADVERTISEMENT, advertiser_node, payload, ttl)
}

/// [`new_procedure_advertisement`] plus an embedded X.509 service-cert
/// chain (leaf-first PEM: leaf ++ org CA), for Slice 7c Direction B
/// managed-realm authorization — see
/// [`cert_chain::verify_advertisement_cert_chain`](crate::cert_chain::verify_advertisement_cert_chain)
/// for the corresponding check. Opt-in: plain [`new_procedure_advertisement`]
/// is unaffected and remains the right choice for unmanaged realms.
pub fn new_procedure_advertisement_with_cert_chain(
    advertiser_node: [u8; 32],
    procedure_uri: impl Into<String>,
    serving_station: [u8; 32],
    ttl: Duration,
    cert_chain_pem: Vec<u8>,
) -> Record {
    let mut rec = new_procedure_advertisement(advertiser_node, procedure_uri, serving_station, ttl);
    let Value::Map(mut entries) = rec.payload else {
        unreachable!("new_procedure_advertisement always returns a Map payload");
    };
    entries.push((Value::text("cert_chain"), Value::Bytes(cert_chain_pem)));
    rec.payload = Value::Map(entries);
    rec
}

/// Builds an UNSIGNED `content_announcement` record naming
/// `announcer_node` as reachable at `endpoint` for `mcid`. Sign before
/// [`put_record`]. Mirrors `macula_record:content_announcement/3,4` — see
/// [`ContentAnnouncement`] for which optional metadata fields are not
/// ported.
pub fn new_content_announcement(
    announcer_node: [u8; 32],
    mcid: crate::manifest::Mcid,
    endpoint: impl Into<String>,
    ttl: Duration,
) -> Record {
    let payload = Value::Map(vec![
        (
            Value::text("announcer_node"),
            Value::Bytes(announcer_node.to_vec()),
        ),
        (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
        (Value::text("endpoint"), Value::text(endpoint)),
    ]);
    new_envelope(TYPE_CONTENT_ANNOUNCEMENT, announcer_node, payload, ttl)
}

/// Extracts a `content_announcement` record's typed fields, or an error if
/// `r` isn't one or is malformed. Mirrors
/// `macula_record:read_content_announcement/1`.
pub fn read_content_announcement(r: &Record) -> Result<ContentAnnouncement, ReadRecordError> {
    if r.record_type != TYPE_CONTENT_ANNOUNCEMENT {
        return Err(ReadRecordError::WrongRecordType);
    }
    let announcer_node = bytes32_field(&r.payload, "announcer_node")?;
    let mcid: crate::manifest::Mcid = match r.payload.get("mcid") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ReadRecordError::WrongFieldType("mcid"))?,
        Some(_) => return Err(ReadRecordError::WrongFieldType("mcid")),
        None => return Err(ReadRecordError::MissingField("mcid")),
    };
    let endpoint = match r.payload.get("endpoint") {
        Some(Value::Text(t)) => t.clone(),
        Some(_) => return Err(ReadRecordError::WrongFieldType("endpoint")),
        None => return Err(ReadRecordError::MissingField("endpoint")),
    };
    Ok(ContentAnnouncement {
        announcer_node,
        mcid,
        endpoint,
    })
}

/// The exact bytes `macula_record:canonical_unsigned/1` signs and
/// verifies: deterministic CBOR of the envelope map using the COMPACT
/// single-letter keys (t/k/v/c/x/p), signature excluded. This is a
/// DIFFERENT representation from the full-field-name map [`to_rpc_value`]
/// sends as RPC args — the compact form exists only to be signed/verified,
/// never sent on the wire as such.
fn canonical_unsigned(r: &Record) -> Vec<u8> {
    let entries = Value::Map(vec![
        (Value::text("t"), Value::Int(r.record_type as i128)),
        (Value::text("k"), Value::Bytes(r.key.to_vec())),
        (Value::text("v"), Value::Bytes(r.version.to_vec())),
        (Value::text("c"), Value::Int(r.created_at)),
        (Value::text("x"), Value::Int(r.expires_at)),
        (Value::text("p"), r.payload.clone()),
    ]);
    // Signing bytes are protocol-internal and always within the
    // deterministic encoder's supported range — an encode failure here
    // would mean a payload this module itself built is malformed, which
    // is a bug in this module, not a runtime condition to recover from.
    crate::cbor::encode(&entries).expect("dht record payload must be encodable")
}

/// Sets `r.signature` to the Ed25519 signature over
/// `SIG_DOMAIN || canonical_unsigned(r)`, matching `macula_record:sign/2`.
pub fn sign(mut r: Record, id: &KeyPair) -> Record {
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&canonical_unsigned(&r));
    r.signature = id.sign(&msg).to_vec();
    r
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSignature,
    Expired,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::InvalidSignature => write!(f, "dht: signature invalid"),
            VerifyError::Expired => write!(f, "dht: record expired"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Checks `r`'s Ed25519 signature against its own `key`, then its expiry.
/// Matches `macula_record:verify/1`. Distinguishes [`VerifyError::Expired`]
/// from [`VerifyError::InvalidSignature`] because a caller resolving a
/// record (e.g. `direct_dial`'s retry loop) should retry past a
/// stale-but-once-valid replica, never past a forged one — see
/// `macula_direct_dial.erl`'s `on_endpoint_verified/3` doing exactly this
/// branch.
pub fn verify(r: &Record) -> Result<(), VerifyError> {
    let sig: [u8; 64] = r
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::InvalidSignature)?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&canonical_unsigned(r));
    if !crate::identity::verify(&msg, &sig, &r.key) {
        return Err(VerifyError::InvalidSignature);
    }
    if r.expires_at > 0 && now_ms() >= r.expires_at {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

/// Namespaces `station_endpoint` storage keys so they don't collide with
/// `node_record`, which keys on the same pubkey — `macula_record`'s
/// `?STORAGE_DOMAIN_STATION_ENDPOINT`.
const STORAGE_DOMAIN_STATION_ENDPOINT: &[u8] = b"station_endpoint";

/// The DHT storage key for a `procedure_advertisement` by its (already
/// realm-qualified — see [`discovery_uri`]) URI: `SHA-256(uri)`. Matches
/// `macula_record:procedure_key/1`.
pub fn procedure_key(procedure_uri: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(procedure_uri.as_bytes()).into()
}

/// The DHT storage key for a station's own `station_endpoint` record:
/// `SHA-256("station_endpoint" || pubkey)`. Matches
/// `macula_record:station_endpoint_key/1`.
pub fn station_endpoint_key(station_pubkey: [u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(STORAGE_DOMAIN_STATION_ENDPOINT);
    hasher.update(station_pubkey);
    hasher.finalize().into()
}

/// The DHT storage key for every `content_announcement` naming `mcid`:
/// `SHA-256(mcid)`. Matches `macula_record:content_key/1`. Consumers use
/// this with [`find_records`] (there may be more than one announcer)
/// before holding any record.
pub fn content_key(mcid: crate::manifest::Mcid) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(mcid).into()
}

/// Matches `macula_direct_dial`'s `discovery_uri/2`: the DHT
/// lookup/advertisement key input is `hex(realm) + "/" + procedure`, so the
/// same procedure name under different realms doesn't collide in the DHT.
/// The advertiser and every resolver must derive this identically.
pub fn discovery_uri(realm: [u8; 32], procedure: &str) -> String {
    let mut hex_realm = String::with_capacity(64);
    for b in realm {
        hex_realm.push_str(&format!("{b:02X}"));
    }
    format!("{hex_realm}/{procedure}")
}

/// A `procedure_advertisement` record's fields, read out of its payload —
/// mirrors `macula_record:read_procedure_advertisement/1`. `cert_chain` is
/// `None` when the advertisement carries no `cert_chain` field (the common,
/// unmanaged-realm case); see
/// [`cert_chain::verify_advertisement_cert_chain`](crate::cert_chain::verify_advertisement_cert_chain).
#[derive(Debug, Clone)]
pub struct ProcedureAdvertisement {
    pub procedure_uri: String,
    pub advertiser_node: [u8; 32],
    pub serving_station: [u8; 32],
    /// Optional: leaf-first PEM bundle, leaf ++ org CA.
    pub cert_chain: Option<Vec<u8>>,
}

/// A `station_endpoint` record's fields, read out of its payload — mirrors
/// `macula_record:read_station_endpoint/1`.
#[derive(Debug, Clone)]
pub struct StationEndpoint {
    pub quic_port: u16,
    pub host_advertised: Vec<String>,
}

/// A `content_announcement` record's fields, read out of its payload —
/// mirrors `macula_record:read_content_announcement/1`. The optional
/// `name`/`size`/`chunk_count` metadata fields
/// (`content_announcement_opts()`) are not ported — direct-dial content
/// fetch doesn't need them to resolve and dial; add them if a future
/// caller needs to prioritize candidates without fetching the manifest.
#[derive(Debug, Clone)]
pub struct ContentAnnouncement {
    pub announcer_node: [u8; 32],
    pub mcid: crate::manifest::Mcid,
    /// A dialable seed URL, e.g. `"https://host:4433"` — matches
    /// `macula_client:seed()`'s own format, NOT a `station_endpoint`'s
    /// split host/port.
    pub endpoint: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadRecordError {
    WrongRecordType,
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for ReadRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadRecordError::WrongRecordType => write!(f, "dht: unexpected record type"),
            ReadRecordError::MissingField(name) => write!(f, "dht: missing field {name:?}"),
            ReadRecordError::WrongFieldType(name) => {
                write!(f, "dht: field {name:?} has the wrong type")
            }
        }
    }
}

impl std::error::Error for ReadRecordError {}

/// Extracts a `procedure_advertisement` record's typed fields, or an error
/// if `r` isn't one or is malformed.
pub fn read_procedure_advertisement(r: &Record) -> Result<ProcedureAdvertisement, ReadRecordError> {
    if r.record_type != TYPE_PROCEDURE_ADVERTISEMENT {
        return Err(ReadRecordError::WrongRecordType);
    }
    let procedure_uri = match r.payload.get("procedure_uri") {
        Some(Value::Text(t)) => t.clone(),
        Some(_) => return Err(ReadRecordError::WrongFieldType("procedure_uri")),
        None => return Err(ReadRecordError::MissingField("procedure_uri")),
    };
    let advertiser_node = bytes32_field(&r.payload, "advertiser_node")?;
    let serving_station = bytes32_field(&r.payload, "serving_station")?;
    // Absent is valid, not an error — the common, unmanaged-realm case.
    let cert_chain = match r.payload.get("cert_chain") {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    Ok(ProcedureAdvertisement {
        procedure_uri,
        advertiser_node,
        serving_station,
        cert_chain,
    })
}

/// Extracts a `station_endpoint` record's typed fields, or an error if `r`
/// isn't one or is malformed.
pub fn read_station_endpoint(r: &Record) -> Result<StationEndpoint, ReadRecordError> {
    if r.record_type != TYPE_STATION_ENDPOINT {
        return Err(ReadRecordError::WrongRecordType);
    }
    let quic_port = match r.payload.get("quic_port") {
        Some(Value::Int(n)) if (1..=65535).contains(n) => *n as u16,
        Some(_) => return Err(ReadRecordError::WrongFieldType("quic_port")),
        None => return Err(ReadRecordError::MissingField("quic_port")),
    };
    // `macula_record.erl`'s `with_host_list/2` puts each host in as a bare
    // Erlang binary, unlike every other string field in this record (which
    // wraps with `{text, Bin}`) — so on the wire these are CBOR BYTE
    // strings (major type 2), not text strings, confirmed against a real
    // station's own published record while building `macula-go`'s
    // equivalent. Try bytes first, text as a fallback in case a future
    // publisher wraps these properly.
    let host_advertised = match r.payload.get("host_advertised") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Bytes(b) => String::from_utf8(b.clone()).ok(),
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(StationEndpoint {
        quic_port,
        host_advertised,
    })
}

fn bytes32_field(v: &Value, name: &'static str) -> Result<[u8; 32], ReadRecordError> {
    match v.get(name) {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ReadRecordError::WrongFieldType(name)),
        Some(_) => Err(ReadRecordError::WrongFieldType(name)),
        None => Err(ReadRecordError::MissingField(name)),
    }
}

// ---------------------------------------------------------------------
// Thin RPC wrappers over the mesh's `_dht.*` procedures.
// ---------------------------------------------------------------------

/// The all-zero 32-byte realm DHT traffic travels under, protocol-internal
/// infrastructure — matches `macula.erl`'s `?DHT_REALM`.
const DHT_REALM: [u8; 32] = [0u8; 32];

/// Matches `macula.erl`'s `?DHT_RECORD_TIMEOUT_MS`.
const DHT_TIMEOUT: Duration = Duration::from_secs(5);

const PUT_RECORD_PROC: &str = "_dht.put_record";
const FIND_RECORD_PROC: &str = "_dht.find_record";
const FIND_RECORDS_PROC: &str = "_dht.find_records";
const FIND_RECORDS_BY_TYPE_PROC: &str = "_dht.find_records_by_type";

/// The FULL-field-name map `macula.erl`'s `put_record/2` sends as a CALL's
/// args (and `find_record`/`find_records` return as a RESULT) — distinct
/// from [`canonical_unsigned`]'s compact single-letter envelope, which
/// exists only to be signed/verified, never sent as such.
fn to_rpc_value(r: &Record) -> Value {
    let mut entries = vec![
        (Value::text("type"), Value::Int(r.record_type as i128)),
        (Value::text("key"), Value::Bytes(r.key.to_vec())),
        (Value::text("version"), Value::Bytes(r.version.to_vec())),
        (Value::text("created_at"), Value::Int(r.created_at)),
        (Value::text("expires_at"), Value::Int(r.expires_at)),
        (Value::text("payload"), r.payload.clone()),
    ];
    if r.signature.len() == 64 {
        entries.push((Value::text("signature"), Value::Bytes(r.signature.clone())));
    }
    Value::Map(entries)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordFromRpcError {
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for RecordFromRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordFromRpcError::MissingField(name) => write!(f, "dht: missing field {name:?}"),
            RecordFromRpcError::WrongFieldType(name) => {
                write!(f, "dht: field {name:?} has the wrong type")
            }
        }
    }
}

impl std::error::Error for RecordFromRpcError {}

fn record_from_rpc_value(v: &Value) -> Result<Record, RecordFromRpcError> {
    let record_type = match v.get("type") {
        Some(Value::Int(n)) if (0..=255).contains(n) => *n as u8,
        Some(_) => return Err(RecordFromRpcError::WrongFieldType("type")),
        None => return Err(RecordFromRpcError::MissingField("type")),
    };
    let key = match v.get("key") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| RecordFromRpcError::WrongFieldType("key"))?,
        Some(_) => return Err(RecordFromRpcError::WrongFieldType("key")),
        None => return Err(RecordFromRpcError::MissingField("key")),
    };
    let version = match v.get("version") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| RecordFromRpcError::WrongFieldType("version"))?,
        Some(_) => return Err(RecordFromRpcError::WrongFieldType("version")),
        None => return Err(RecordFromRpcError::MissingField("version")),
    };
    let created_at = match v.get("created_at") {
        Some(Value::Int(n)) => *n,
        Some(_) => return Err(RecordFromRpcError::WrongFieldType("created_at")),
        None => return Err(RecordFromRpcError::MissingField("created_at")),
    };
    let expires_at = match v.get("expires_at") {
        Some(Value::Int(n)) => *n,
        Some(_) => return Err(RecordFromRpcError::WrongFieldType("expires_at")),
        None => return Err(RecordFromRpcError::MissingField("expires_at")),
    };
    let payload = v
        .get("payload")
        .cloned()
        .ok_or(RecordFromRpcError::MissingField("payload"))?;
    let signature = match v.get("signature") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    Ok(Record {
        record_type,
        key,
        version,
        created_at,
        expires_at,
        payload,
        signature,
    })
}

#[derive(Debug)]
pub enum DhtError {
    Call(CallError),
    /// The station answered with an ERROR frame — carries its `name`.
    Remote(String),
    NotFound,
    Malformed(RecordFromRpcError),
    /// The RESULT payload wasn't the list shape `find_records`/
    /// `find_records_by_type` are expected to return.
    ExpectedList,
}

impl std::fmt::Display for DhtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhtError::Call(e) => write!(f, "dht: {e}"),
            DhtError::Remote(name) => write!(f, "dht: station reported {name}"),
            DhtError::NotFound => write!(f, "dht: record not found"),
            DhtError::Malformed(e) => write!(f, "dht: {e}"),
            DhtError::ExpectedList => write!(f, "dht: expected a list reply"),
        }
    }
}

impl std::error::Error for DhtError {}

fn deadline_ms(timeout: Duration) -> i128 {
    now_ms() + timeout.as_millis() as i128
}

/// Stores a signed record in the mesh DHT. Mirrors `macula:put_record/2` —
/// the relay validates the signature on receipt.
pub async fn put_record(session: &Session, id: &KeyPair, rec: &Record) -> Result<(), DhtError> {
    let resp = session
        .call(
            PUT_RECORD_PROC,
            DHT_REALM,
            to_rpc_value(rec),
            deadline_ms(DHT_TIMEOUT),
            id,
            DHT_TIMEOUT,
        )
        .await
        .map_err(DhtError::Call)?;
    match resp {
        CallResponse::Result { .. } => Ok(()),
        CallResponse::Error { name, .. } => Err(DhtError::Remote(name)),
    }
}

/// Fetches one record by its storage key (see [`procedure_key`] /
/// [`station_endpoint_key`]). Returns [`DhtError::NotFound`] if none
/// exists — the caller's signature should still be checked via [`verify`]
/// before the payload is trusted; this function does not verify on the
/// caller's behalf.
pub async fn find_record(
    session: &Session,
    id: &KeyPair,
    key: [u8; 32],
) -> Result<Record, DhtError> {
    let args = Value::Map(vec![(Value::text("key"), Value::Bytes(key.to_vec()))]);
    let resp = session
        .call(
            FIND_RECORD_PROC,
            DHT_REALM,
            args,
            deadline_ms(DHT_TIMEOUT),
            id,
            DHT_TIMEOUT,
        )
        .await
        .map_err(DhtError::Call)?;
    match resp {
        CallResponse::Result { payload, .. } => {
            if matches!(&payload, Value::Text(t) if t == "not_found") {
                return Err(DhtError::NotFound);
            }
            record_from_rpc_value(&payload).map_err(DhtError::Malformed)
        }
        CallResponse::Error { name, .. } => Err(DhtError::Remote(name)),
    }
}

/// Fetches every record stored at `key` — the full signer-deduped multiset
/// (e.g. every `procedure_advertisement` for one procedure). Each record's
/// signature should be verified via [`verify`] before its payload is
/// trusted; this function does not verify on the caller's behalf.
pub async fn find_records(
    session: &Session,
    id: &KeyPair,
    key: [u8; 32],
) -> Result<Vec<Record>, DhtError> {
    let args = Value::Map(vec![(Value::text("key"), Value::Bytes(key.to_vec()))]);
    let resp = session
        .call(
            FIND_RECORDS_PROC,
            DHT_REALM,
            args,
            deadline_ms(DHT_TIMEOUT),
            id,
            DHT_TIMEOUT,
        )
        .await
        .map_err(DhtError::Call)?;
    records_list_from_response(resp)
}

/// Returns every record of `typ` currently visible from the station this
/// session is connected to. Coverage depends on that station's own view of
/// the DHT. Mirrors `macula:find_records_by_type/2`.
pub async fn find_records_by_type(
    session: &Session,
    id: &KeyPair,
    typ: u8,
) -> Result<Vec<Record>, DhtError> {
    let args = Value::Map(vec![(Value::text("type"), Value::Int(typ as i128))]);
    let resp = session
        .call(
            FIND_RECORDS_BY_TYPE_PROC,
            DHT_REALM,
            args,
            deadline_ms(DHT_TIMEOUT),
            id,
            DHT_TIMEOUT,
        )
        .await
        .map_err(DhtError::Call)?;
    records_list_from_response(resp)
}

fn records_list_from_response(resp: CallResponse) -> Result<Vec<Record>, DhtError> {
    match resp {
        CallResponse::Result { payload, .. } => match payload {
            Value::List(items) => Ok(items
                .iter()
                .filter_map(|item| record_from_rpc_value(item).ok())
                .collect()),
            _ => Err(DhtError::ExpectedList),
        },
        CallResponse::Error { name, .. } => Err(DhtError::Remote(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_advertisement(id: &KeyPair) -> Record {
        let station: [u8; 32] = [7u8; 32];
        let uri = discovery_uri([0u8; 32], "test.procedure");
        let rec = new_procedure_advertisement(id.node_id(), uri, station, DEFAULT_TTL);
        sign(rec, id)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let id = KeyPair::generate();
        let rec = sample_advertisement(&id);
        assert_eq!(rec.signature.len(), 64);
        assert!(verify(&rec).is_ok());
    }

    #[test]
    fn verify_rejects_a_tampered_payload() {
        let id = KeyPair::generate();
        let mut rec = sample_advertisement(&id);
        // Flip the record's advertised type after signing -- the signature
        // covers record_type, so this must invalidate it.
        rec.record_type = TYPE_STATION_ENDPOINT;
        assert_eq!(verify(&rec), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_a_signature_from_the_wrong_signer() {
        let signer = KeyPair::generate();
        let mut rec = sample_advertisement(&signer);
        // The envelope's own `key` field claims a DIFFERENT signer than
        // the one that actually produced `signature` -- verify checks the
        // signature against `key`, so this must fail.
        rec.key = KeyPair::generate().public_bytes();
        assert_eq!(verify(&rec), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_an_expired_record() {
        let id = KeyPair::generate();
        let station: [u8; 32] = [7u8; 32];
        let uri = discovery_uri([0u8; 32], "test.procedure");
        // A TTL that has already elapsed by the time verify() runs.
        let rec = new_procedure_advertisement(id.node_id(), uri, station, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        let rec = sign(rec, &id);
        assert_eq!(verify(&rec), Err(VerifyError::Expired));
    }

    #[test]
    fn canonical_unsigned_is_deterministic() {
        let id = KeyPair::generate();
        let rec = sample_advertisement(&id);
        // Re-deriving the same bytes from the same (already-built) record
        // must always agree -- this is exactly what a verifier on the
        // other end of the wire independently recomputes.
        assert_eq!(canonical_unsigned(&rec), canonical_unsigned(&rec));
    }

    #[test]
    fn procedure_key_differs_by_realm() {
        let a = procedure_key(&discovery_uri([0u8; 32], "same.name"));
        let b = procedure_key(&discovery_uri([1u8; 32], "same.name"));
        assert_ne!(
            a, b,
            "the same bare procedure name under different realms must not collide"
        );
    }

    #[test]
    fn discovery_uri_matches_expected_hex_format() {
        let uri = discovery_uri([0u8; 32], "hecate_mail.initiate_mailbox");
        assert_eq!(
            uri,
            format!("{}/hecate_mail.initiate_mailbox", "00".repeat(32))
        );
    }

    #[test]
    fn read_procedure_advertisement_round_trips_the_payload() {
        let id = KeyPair::generate();
        let station: [u8; 32] = [9u8; 32];
        let uri = "0".repeat(64) + "/some.procedure";
        let rec = new_procedure_advertisement(id.node_id(), uri.clone(), station, DEFAULT_TTL);
        let read = read_procedure_advertisement(&rec).expect("should read back cleanly");
        assert_eq!(read.procedure_uri, uri);
        assert_eq!(read.advertiser_node, id.node_id());
        assert_eq!(read.serving_station, station);
    }

    #[test]
    fn read_procedure_advertisement_rejects_the_wrong_record_type() {
        let id = KeyPair::generate();
        let station: [u8; 32] = [9u8; 32];
        let mut rec = new_procedure_advertisement(id.node_id(), "x/y", station, DEFAULT_TTL);
        rec.record_type = TYPE_STATION_ENDPOINT;
        assert!(matches!(
            read_procedure_advertisement(&rec),
            Err(ReadRecordError::WrongRecordType)
        ));
    }

    #[test]
    fn station_endpoint_host_advertised_reads_byte_string_entries() {
        // macula_record.erl's with_host_list/2 puts each host in as a bare
        // Erlang binary -- on the wire these decode as CBOR byte strings
        // (major type 2), not text, confirmed against a real station's own
        // published record while building macula-go's equivalent. This
        // guards that this crate reads that shape too, not just a
        // hypothetical text-wrapped one.
        let rec = Record {
            record_type: TYPE_STATION_ENDPOINT,
            key: [1u8; 32],
            version: [0u8; 16],
            created_at: 0,
            expires_at: 0,
            payload: Value::Map(vec![
                (Value::text("quic_port"), Value::Int(4433)),
                (
                    Value::text("host_advertised"),
                    Value::List(vec![Value::Bytes(b"203.0.113.5".to_vec())]),
                ),
            ]),
            signature: Vec::new(),
        };
        let ep = read_station_endpoint(&rec).expect("should read the byte-string host");
        assert_eq!(ep.quic_port, 4433);
        assert_eq!(ep.host_advertised, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn to_rpc_value_and_record_from_rpc_value_round_trip() {
        let id = KeyPair::generate();
        let rec = sample_advertisement(&id);
        let rpc_value = to_rpc_value(&rec);
        let back = record_from_rpc_value(&rpc_value).expect("should decode cleanly");
        assert_eq!(back.record_type, rec.record_type);
        assert_eq!(back.key, rec.key);
        assert_eq!(back.version, rec.version);
        assert_eq!(back.created_at, rec.created_at);
        assert_eq!(back.expires_at, rec.expires_at);
        assert_eq!(back.signature, rec.signature);
        // The payload survives the RPC round trip byte-for-byte-equivalent
        // even though it isn't compared via canonical_unsigned here.
        assert!(verify(&back).is_ok());
    }
}
