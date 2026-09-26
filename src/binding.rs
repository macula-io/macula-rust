//! TLS and CONNECT bindings and status statements, as macula_key_bindings and
//! macula-go make and check them. A binding ties a station's TLS leaf, or a
//! node's CONNECT key, to an identity key for up to 7 days; a status
//! statement keeps a binding in force for up to an hour. Each travels as
//! `{tbs, signature}`, the signature over its label, a zero byte and the tbs
//! bytes; a verifier checks the signature over the bytes it received first,
//! and only then decodes them.

use std::fmt;

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::node_key::{node_id_of, verify, KeyError, NodeKey};
use crate::profile::Profile;

const LABEL_BINDING_TLS: &str = "MACULA-PQ-BINDING-TLS-V1";
const LABEL_BINDING_CONNECT: &str = "MACULA-PQ-BINDING-CONNECT-V1";
const LABEL_STATUS: &str = "MACULA-PQ-STATUS-V1";
const MAX_BINDING_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_STATUS_MS: i64 = 60 * 60 * 1000;
const TOLERANCE_MS: i64 = 5 * 60 * 1000;
const MAX_PROTOCOL_INT: i64 = 1 << 53;

const BINDING_FIELDS: [&str; 9] = [
    "label",
    "node_id",
    "use",
    "subject_hash",
    "binding_id",
    "not_before",
    "not_after",
    "hash_alg",
    "sig_alg",
];
const STATUS_FIELDS: [&str; 6] = [
    "label",
    "node_id",
    "binding_hash",
    "issued_at",
    "expires_at",
    "sig_alg",
];

/// What a binding binds to the identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingUse {
    /// A station's TLS key, by the leaf certificate it presents.
    Tls,
    /// A CONNECT key.
    Connect,
}

impl BindingUse {
    fn name(self) -> &'static str {
        match self {
            BindingUse::Tls => "tls",
            BindingUse::Connect => "connect",
        }
    }

    fn label(self) -> &'static str {
        match self {
            BindingUse::Tls => LABEL_BINDING_TLS,
            BindingUse::Connect => LABEL_BINDING_CONNECT,
        }
    }
}

/// The refusals of the binding and status checks, named as macula names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// A signed structure of the wrong shape: not exactly `{tbs, signature}`,
    /// or a tbs that the decoding rule refuses, with a key its structure does
    /// not define, or a field of the wrong type, length or range.
    Malformed,
    /// A binding whose signature does not verify under its use's label.
    BindingSignatureInvalid,
    /// A binding whose label or use is another use's.
    WrongUse,
    /// A binding whose subject is not the leaf or CONNECT key it came with.
    KeyMismatch,
    /// A binding more than 5 minutes past its not_after.
    Expired,
    /// A binding more than 5 minutes before its not_before.
    NotYetValid,
    /// A binding or statement naming a node_id other than the identity key's.
    NodeIdMismatch,
    /// A status statement whose signature does not verify.
    StatusSignatureInvalid,
    /// A status statement for another binding.
    StatusBindingMismatch,
    /// A status statement more than 5 minutes past its expiry.
    StatusExpired,
    /// A status statement issued more than 5 minutes ahead.
    StatusFutureDated,
    /// A window a verifier would refuse: negative, backwards, at 2^53 or later,
    /// or longer than 7 days for a binding and an hour for a statement.
    ValidityWindow,
    /// The signing key could not sign, or is not an identity key.
    Key(KeyError),
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::Malformed => f.write_str("malformed signed structure"),
            BindingError::BindingSignatureInvalid => {
                f.write_str("the binding's signature does not verify")
            }
            BindingError::WrongUse => f.write_str("the binding is for another use"),
            BindingError::KeyMismatch => f.write_str("the binding binds another key"),
            BindingError::Expired => f.write_str("the binding has expired"),
            BindingError::NotYetValid => f.write_str("the binding is not valid yet"),
            BindingError::NodeIdMismatch => f.write_str("the structure names another node_id"),
            BindingError::StatusSignatureInvalid => {
                f.write_str("the status statement's signature does not verify")
            }
            BindingError::StatusBindingMismatch => {
                f.write_str("the status statement is for another binding")
            }
            BindingError::StatusExpired => f.write_str("the status statement has expired"),
            BindingError::StatusFutureDated => {
                f.write_str("the status statement is dated in the future")
            }
            BindingError::ValidityWindow => {
                f.write_str("a validity period outside what a verifier accepts")
            }
            BindingError::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BindingError {}

impl From<KeyError> for BindingError {
    fn from(e: KeyError) -> Self {
        BindingError::Key(e)
    }
}

/// A signed structure as it travels: tbs, the deterministic CBOR of its
/// fields, and a signature over its label, a zero byte and tbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTbs {
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedTbs {
    /// The structure as the map `{tbs, signature}`.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("tbs"), Value::Bytes(self.tbs.clone())),
            (
                Value::text("signature"),
                Value::Bytes(self.signature.clone()),
            ),
        ])
    }

    /// The structure in `value`, which must be a map of exactly `tbs` and
    /// `signature`, both byte strings.
    pub fn from_value(value: &Value) -> Result<SignedTbs, BindingError> {
        match value {
            Value::Map(pairs) if pairs.len() == 2 => {
                match (value.get("tbs"), value.get("signature")) {
                    (Some(Value::Bytes(tbs)), Some(Value::Bytes(signature))) => Ok(SignedTbs {
                        tbs: tbs.clone(),
                        signature: signature.clone(),
                    }),
                    _ => Err(BindingError::Malformed),
                }
            }
            _ => Err(BindingError::Malformed),
        }
    }
}

/// What a verified binding says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingInfo {
    pub use_: BindingUse,
    pub node_id: [u8; 32],
    pub not_after: i64,
}

/// Binds the TLS key of the leaf certificate a listener presents to
/// `identity_key`, by the SHA-384 of the leaf's DER, from `not_before` to
/// `not_after` in milliseconds.
pub fn tls_binding(
    identity_key: &NodeKey,
    leaf_der: &[u8],
    not_before: i64,
    not_after: i64,
) -> Result<SignedTbs, BindingError> {
    issue_binding(
        identity_key,
        BindingUse::Tls,
        &sha384(leaf_der),
        not_before,
        not_after,
    )
}

/// Binds a CONNECT key, by the SHA-384 of the key as carried, to
/// `identity_key`, from `not_before` to `not_after` in milliseconds.
pub fn connect_binding(
    identity_key: &NodeKey,
    connect_key: &[u8],
    not_before: i64,
    not_after: i64,
) -> Result<SignedTbs, BindingError> {
    issue_binding(
        identity_key,
        BindingUse::Connect,
        &sha384(connect_key),
        not_before,
        not_after,
    )
}

fn issue_binding(
    identity_key: &NodeKey,
    use_: BindingUse,
    subject_hash: &[u8; 48],
    not_before: i64,
    not_after: i64,
) -> Result<SignedTbs, BindingError> {
    let node_id = identity_key.node_id()?;
    if !within_window(not_before, not_after, MAX_BINDING_MS) {
        return Err(BindingError::ValidityWindow);
    }
    let mut binding_id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut binding_id)
        .map_err(|_| BindingError::Key(KeyError::RandomnessUnavailable))?;
    let tbs = encode(Value::Map(vec![
        text("label", use_.label()),
        bytes("node_id", &node_id),
        text("use", use_.name()),
        bytes("subject_hash", subject_hash),
        bytes("binding_id", &binding_id),
        int("not_before", not_before),
        int("not_after", not_after),
        text("hash_alg", "SHA-384"),
        text("sig_alg", identity_key.profile().sig_alg()),
    ]));
    sign_tbs(identity_key, use_.label(), tbs)
}

/// Keeps `binding` in force from `issued_at` to `expires_at` in milliseconds,
/// at most an hour, signed by `identity_key`.
pub fn status_statement(
    identity_key: &NodeKey,
    binding: &SignedTbs,
    issued_at: i64,
    expires_at: i64,
) -> Result<SignedTbs, BindingError> {
    let node_id = identity_key.node_id()?;
    if !within_window(issued_at, expires_at, MAX_STATUS_MS) {
        return Err(BindingError::ValidityWindow);
    }
    let tbs = encode(Value::Map(vec![
        text("label", LABEL_STATUS),
        bytes("node_id", &node_id),
        bytes("binding_hash", &sha384(&binding.tbs)),
        int("issued_at", issued_at),
        int("expires_at", expires_at),
        text("sig_alg", identity_key.profile().sig_alg()),
    ]));
    sign_tbs(identity_key, LABEL_STATUS, tbs)
}

/// Checks `binding` against the identity key as carried, under `profile`, and
/// the leaf certificate this connection presented, at `now_ms` with 5 minutes
/// of tolerance.
pub fn verify_tls_binding(
    binding: &SignedTbs,
    identity_key: &[u8],
    profile: Profile,
    leaf_der: &[u8],
    now_ms: i64,
) -> Result<BindingInfo, BindingError> {
    verify_binding(
        binding,
        identity_key,
        profile,
        BindingUse::Tls,
        &sha384(leaf_der),
        now_ms,
    )
}

/// Checks `binding` against the identity key as carried, under `profile`, and
/// the CONNECT key as carried, at `now_ms` with 5 minutes of tolerance.
pub fn verify_connect_binding(
    binding: &SignedTbs,
    identity_key: &[u8],
    profile: Profile,
    connect_key: &[u8],
    now_ms: i64,
) -> Result<BindingInfo, BindingError> {
    verify_binding(
        binding,
        identity_key,
        profile,
        BindingUse::Connect,
        &sha384(connect_key),
        now_ms,
    )
}

/// The signature over the tbs bytes as received first, then the tbs decoded,
/// then its fields in macula's order: shape, use, node_id, subject,
/// not_before, not_after.
fn verify_binding(
    binding: &SignedTbs,
    identity_key: &[u8],
    profile: Profile,
    use_: BindingUse,
    subject_hash: &[u8; 48],
    now_ms: i64,
) -> Result<BindingInfo, BindingError> {
    if !verify(
        &labelled(use_.label(), &binding.tbs),
        &binding.signature,
        identity_key,
        profile,
    ) {
        return Err(BindingError::BindingSignatureInvalid);
    }
    let fields = decode_tbs(&binding.tbs, &BINDING_FIELDS).ok_or(BindingError::Malformed)?;
    let parsed = well_formed_binding(&fields, profile).ok_or(BindingError::Malformed)?;
    if parsed.label != use_.label() || parsed.use_ != use_.name() {
        return Err(BindingError::WrongUse);
    }
    if parsed.node_id != node_id_of(identity_key, profile) {
        return Err(BindingError::NodeIdMismatch);
    }
    if &parsed.subject_hash != subject_hash {
        return Err(BindingError::KeyMismatch);
    }
    if now_ms + TOLERANCE_MS < parsed.not_before {
        return Err(BindingError::NotYetValid);
    }
    if now_ms - TOLERANCE_MS > parsed.not_after {
        return Err(BindingError::Expired);
    }
    Ok(BindingInfo {
        use_,
        node_id: parsed.node_id,
        not_after: parsed.not_after,
    })
}

struct BindingTbs<'a> {
    label: &'a str,
    use_: &'a str,
    node_id: [u8; 32],
    subject_hash: [u8; 48],
    not_before: i64,
    not_after: i64,
}

fn well_formed_binding<'a>(f: &'a Fields, profile: Profile) -> Option<BindingTbs<'a>> {
    let binding_id = field_bytes(f, "binding_id")?;
    let not_before = protocol_int(f, "not_before")?;
    let not_after = protocol_int(f, "not_after")?;
    let well_formed = binding_id.len() == 16
        && within_window(not_before, not_after, MAX_BINDING_MS)
        && field_text(f, "hash_alg")? == "SHA-384"
        && field_text(f, "sig_alg")? == profile.sig_alg();
    well_formed.then_some(BindingTbs {
        label: field_text(f, "label")?,
        use_: field_text(f, "use")?,
        node_id: field_array(f, "node_id")?,
        subject_hash: field_array(f, "subject_hash")?,
        not_before,
        not_after,
    })
}

/// Checks a status statement for the binding it came with, against the
/// identity key as carried, under `profile`, at `now_ms` with 5 minutes of
/// tolerance, and returns when the statement expires. It checks that the
/// statement names that binding, not the binding itself: a caller verifies
/// the binding too.
pub fn verify_status(
    statement: &SignedTbs,
    binding: &SignedTbs,
    identity_key: &[u8],
    profile: Profile,
    now_ms: i64,
) -> Result<i64, BindingError> {
    if !verify(
        &labelled(LABEL_STATUS, &statement.tbs),
        &statement.signature,
        identity_key,
        profile,
    ) {
        return Err(BindingError::StatusSignatureInvalid);
    }
    let fields = decode_tbs(&statement.tbs, &STATUS_FIELDS).ok_or(BindingError::Malformed)?;
    let issued_at = protocol_int(&fields, "issued_at").ok_or(BindingError::Malformed)?;
    let expires_at = protocol_int(&fields, "expires_at").ok_or(BindingError::Malformed)?;
    let node_id: [u8; 32] = field_array(&fields, "node_id").ok_or(BindingError::Malformed)?;
    let binding_hash: [u8; 48] =
        field_array(&fields, "binding_hash").ok_or(BindingError::Malformed)?;
    let well_formed = field_text(&fields, "label") == Some(LABEL_STATUS)
        && within_window(issued_at, expires_at, MAX_STATUS_MS)
        && field_text(&fields, "sig_alg") == Some(profile.sig_alg());
    if !well_formed {
        return Err(BindingError::Malformed);
    }
    if node_id != node_id_of(identity_key, profile) {
        return Err(BindingError::NodeIdMismatch);
    }
    if binding_hash != sha384(&binding.tbs) {
        return Err(BindingError::StatusBindingMismatch);
    }
    if issued_at > now_ms + TOLERANCE_MS {
        return Err(BindingError::StatusFutureDated);
    }
    if now_ms - TOLERANCE_MS > expires_at {
        return Err(BindingError::StatusExpired);
    }
    Ok(expires_at)
}

/// A tbs's fields by name.
type Fields = std::collections::HashMap<String, Value>;

/// `tbs` decoded under the decoding rule, when it is a map whose keys are
/// exactly `names`, all text.
fn decode_tbs(tbs: &[u8], names: &[&str]) -> Option<Fields> {
    let Value::Map(pairs) = cbor::decode(tbs).ok()? else {
        return None;
    };
    if pairs.len() != names.len() {
        return None;
    }
    let mut fields = Fields::with_capacity(pairs.len());
    for (key, value) in pairs {
        let Value::Text(name) = key else {
            return None;
        };
        fields.insert(name, value);
    }
    names
        .iter()
        .all(|n| fields.contains_key(*n))
        .then_some(fields)
}

/// Whether `from` and `to` are a validity period a verifier accepts: `from`
/// at least 0, `to` no earlier than `from` and below 2^53, and at most `max`
/// apart.
fn within_window(from: i64, to: i64, max: i64) -> bool {
    from >= 0 && from <= to && to < MAX_PROTOCOL_INT && to - from <= max
}

fn protocol_int(f: &Fields, name: &str) -> Option<i64> {
    match f.get(name)? {
        Value::Int(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

fn field_text<'a>(f: &'a Fields, name: &str) -> Option<&'a str> {
    match f.get(name)? {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

fn field_bytes<'a>(f: &'a Fields, name: &str) -> Option<&'a [u8]> {
    match f.get(name)? {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn field_array<const N: usize>(f: &Fields, name: &str) -> Option<[u8; N]> {
    field_bytes(f, name)?.try_into().ok()
}

fn sign_tbs(key: &NodeKey, label: &str, tbs: Vec<u8>) -> Result<SignedTbs, BindingError> {
    let signature = key.sign(&labelled(label, &tbs))?;
    Ok(SignedTbs { tbs, signature })
}

/// `label`, a zero byte and `tbs`: what a binding or status statement signs.
fn labelled(label: &str, tbs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 1 + tbs.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend_from_slice(tbs);
    out
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    Sha384::digest(bytes).into()
}

/// A map of text keys and protocol values always encodes: every integer here
/// is an i64.
fn encode(value: Value) -> Vec<u8> {
    cbor::encode(&value).expect("text-keyed fields of i64 integers always encode")
}

fn text(name: &str, value: &str) -> (Value, Value) {
    (Value::text(name), Value::text(value))
}

fn bytes(name: &str, value: &[u8]) -> (Value, Value) {
    (Value::text(name), Value::Bytes(value.to_vec()))
}

fn int(name: &str, value: i64) -> (Value, Value) {
    (Value::text(name), Value::Int(i128::from(value)))
}
