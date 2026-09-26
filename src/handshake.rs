//! macula 12's post-quantum connection handshake, as macula_handshake and
//! macula-go build and check it: the opener, challenge, CONNECT, HELLO and
//! status frames (D16, D22), as CBOR bytes without the length prefix.
//!
//! The client opens with an opener. The station answers with a challenge: its
//! carried identity key, its TLS binding and status statement, and a fresh
//! nonce. The client checks the challenge against the node_id it dialed and
//! the leaf it received, before it signs anything, and answers with CONNECT:
//! its identity and CONNECT keys, the CONNECT binding and status statement,
//! and a proof by the CONNECT key. The station checks CONNECT, the puzzle
//! before any signature, and answers with HELLO. Status frames renew a peer's
//! statement on the open connection.
//!
//! Every frame decodes under the decoding rule and must hold exactly the keys
//! of its type, each of its type and length. Close reasons are local: a
//! refusing station sends only a HELLO with one coarse refusal code.

use std::fmt;

use sha2::{Digest, Sha384};

use crate::binding::{
    verify_connect_binding, verify_status, verify_tls_binding, BindingError, SignedTbs,
};
use crate::cbor::{self, Value};
use crate::node_key::{
    carried_key_well_formed, node_id_of, puzzle_solved, signature_size, verify, KeyError, NodeKey,
};
use crate::profile::Profile;

/// The handshake's frame version: 4, as macula 12's. A peer on another version
/// hears `unsupported_version`.
pub const VERSION: i64 = 4;

const NONCE_SIZE: usize = 32;
const MAX_PROTOCOL_INT: i64 = 1 << 53;
const MLDSA_KEY_SIZE: usize = 2592;
const CONNECT_PROOF_LABEL: &[u8] = b"MACULA-PQ-CONNECT-PROOF-V1";

const OPENER_KEYS: &[&str] = &["frame_type", "version"];
const CHALLENGE_KEYS: &[&str] = &[
    "frame_type",
    "identity_key",
    "nonce",
    "profile",
    "tls_binding",
    "tls_status",
    "version",
];
/// CONNECT always holds member_endorsement, empty when the node has none, as
/// macula 12's: one layout, so the wire does not tell whether a node holds an
/// endorsement or a station asks for one.
const CONNECT_KEYS: &[&str] = &[
    "capabilities",
    "connect_binding",
    "connect_key",
    "connect_status",
    "frame_type",
    "identity_key",
    "member_endorsement",
    "proof",
    "version",
];
const HELLO_ACCEPTED_KEYS: &[&str] = &["accepted", "capabilities", "frame_type", "version"];
const HELLO_REFUSED_KEYS: &[&str] = &[
    "accepted",
    "capabilities",
    "frame_type",
    "refusal_code",
    "version",
];
const STATUS_KEYS: &[&str] = &["frame_type", "statement", "version"];

/// The one coarse reason a refusing HELLO carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// Frames that are not version 4.
    UnsupportedVersion,
    /// A node_id that misses the puzzle, which the client can check itself.
    PuzzleInvalid,
    /// A CONNECT that failed any other check.
    NotAccepted,
}

impl RefusalCode {
    fn name(self) -> &'static str {
        match self {
            RefusalCode::UnsupportedVersion => "unsupported_version",
            RefusalCode::PuzzleInvalid => "puzzle_invalid",
            RefusalCode::NotAccepted => "not_accepted",
        }
    }

    fn parse(name: &str) -> Option<RefusalCode> {
        match name {
            "unsupported_version" => Some(RefusalCode::UnsupportedVersion),
            "puzzle_invalid" => Some(RefusalCode::PuzzleInvalid),
            "not_accepted" => Some(RefusalCode::NotAccepted),
            _ => None,
        }
    }
}

/// The handshake's close reasons, named as macula names them. A binding or
/// status statement that fails its check closes with its [`BindingError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A frame of another type than the one expected next.
    UnexpectedFrame,
    /// A frame of another version than 4.
    UnsupportedVersion,
    /// A frame that does not decode exactly, or a carried key or proof of the
    /// wrong form.
    Malformed,
    /// A challenge that names another profile.
    ProfileMismatch,
    /// A key that would serve two purposes: a CONNECT key that shares a half
    /// with its identity key, or a key found in the leaf.
    KeyPurposeReuse,
    /// A station whose node_id is not the one dialed.
    PeerIdentityMismatch {
        expected: [u8; 32],
        derived: [u8; 32],
    },
    /// A client whose node_id does not meet the puzzle.
    PuzzleInvalid,
    /// A CONNECT proof that does not verify.
    ProofInvalid,
    /// A HELLO that refuses the connection, with its code.
    Refused(RefusalCode),
    /// A station session with a puzzle difficulty the design does not have.
    InvalidStationSession,
    /// A binding or status statement that did not verify.
    Binding(BindingError),
    /// A key that could not sign, or randomness that could not be drawn.
    Key(KeyError),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::UnexpectedFrame => f.write_str("unexpected frame"),
            HandshakeError::UnsupportedVersion => f.write_str("unsupported frame version"),
            HandshakeError::Malformed => f.write_str("malformed frame"),
            HandshakeError::ProfileMismatch => f.write_str("the peer names another profile"),
            HandshakeError::KeyPurposeReuse => f.write_str("a key would serve two purposes"),
            HandshakeError::PeerIdentityMismatch { expected, derived } => write!(
                f,
                "dialed node_id {}, but the station's key derives {}",
                hex_of(expected),
                hex_of(derived)
            ),
            HandshakeError::PuzzleInvalid => f.write_str("the node_id does not meet the puzzle"),
            HandshakeError::ProofInvalid => f.write_str("the CONNECT proof does not verify"),
            HandshakeError::Refused(code) => {
                write!(f, "the station refused the connection: {}", code.name())
            }
            HandshakeError::InvalidStationSession => {
                f.write_str("the station session has an unknown puzzle difficulty")
            }
            HandshakeError::Binding(e) => write!(f, "{e}"),
            HandshakeError::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<BindingError> for HandshakeError {
    fn from(e: BindingError) -> Self {
        HandshakeError::Binding(e)
    }
}

/// How a station treats a client's node_id puzzle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuzzleMode {
    /// The puzzle is not checked.
    Off,
    /// An unsolved puzzle is accepted and reported.
    LogOnly,
    /// An unsolved puzzle is refused.
    Enforce,
}

/// What a station found of a client's puzzle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuzzleResult {
    Solved,
    Unsolved,
    NotChecked,
}

/// The client's first frame on the control stream. It carries nothing that
/// relates to identity.
pub fn opener() -> Vec<u8> {
    encode_frame("opener", Vec::new())
}

/// The station's check of the first frame.
pub fn read_opener(frame: &[u8]) -> Result<(), HandshakeError> {
    decode(frame, "opener", &[OPENER_KEYS]).map(|_| ())
}

/// What a station precomputes for its challenges: its carried identity key,
/// and the TLS binding and status statement for the leaf it presents.
#[derive(Debug, Clone)]
pub struct StationMaterial {
    pub profile: Profile,
    pub identity_key: Vec<u8>,
    pub tls_binding: SignedTbs,
    pub tls_status: SignedTbs,
}

/// A station's challenge, with a fresh nonce. The station keeps the bytes it
/// sends, for the proof check.
pub fn challenge(m: &StationMaterial) -> Result<Vec<u8>, HandshakeError> {
    let mut nonce = [0u8; NONCE_SIZE];
    aws_lc_rs::rand::fill(&mut nonce)
        .map_err(|_| HandshakeError::Key(KeyError::RandomnessUnavailable))?;
    Ok(encode_frame(
        "challenge",
        vec![
            entry("nonce", Value::Bytes(nonce.to_vec())),
            entry("profile", Value::text(m.profile.name())),
            entry("identity_key", Value::Bytes(m.identity_key.clone())),
            entry("tls_binding", m.tls_binding.to_value()),
            entry("tls_status", m.tls_status.to_value()),
        ],
    ))
}

/// What a client brings to a handshake: its profile, the node_id it dialed,
/// the leaf DER it received in this TLS handshake, its carried identity key,
/// its CONNECT key with binding and status statement, its capability bits,
/// the time in milliseconds, and the realm membership endorsement CONNECT
/// carries, empty for a node that holds none.
pub struct ClientSession<'a> {
    pub profile: Profile,
    pub expected_node_id: [u8; 32],
    pub leaf: &'a [u8],
    pub identity_key: Vec<u8>,
    pub connect_key: &'a NodeKey,
    pub connect_binding: &'a SignedTbs,
    pub connect_status: &'a SignedTbs,
    pub capabilities: u64,
    pub now_ms: i64,
    pub member_endorsement: Vec<u8>,
}

/// What a client knows of the station once it has checked the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub node_id: [u8; 32],
    pub identity_key: Vec<u8>,
    pub tls_binding: SignedTbs,
    pub status_expires_at: i64,
    pub binding_not_after: i64,
}

/// Checks a challenge and, when every check passes, returns the CONNECT to
/// send. It checks, in macula's order: the frame, the profile, the station's
/// carried key, that each key in view serves one purpose, the station's
/// node_id against the one dialed, the TLS binding against the leaf received,
/// and the status statement. It signs nothing before all of them pass.
pub fn answer_challenge(
    challenge: &[u8],
    s: &ClientSession<'_>,
) -> Result<(Vec<u8>, Station), HandshakeError> {
    let f = decode(challenge, "challenge", &[CHALLENGE_KEYS])?;
    let station_key = f.bytes("identity_key");
    let connect_key = s.connect_key.public_key();
    if f.text("profile") != s.profile.name() {
        return Err(HandshakeError::ProfileMismatch);
    }
    if !carried_key_well_formed(station_key, s.profile) {
        return Err(HandshakeError::Malformed);
    }
    if shares_a_half(&s.identity_key, &connect_key)
        || in_leaf(station_key, s.leaf)
        || in_leaf(&connect_key, s.leaf)
    {
        return Err(HandshakeError::KeyPurposeReuse);
    }
    let station_node_id = node_id_of(station_key, s.profile);
    if station_node_id != s.expected_node_id {
        return Err(HandshakeError::PeerIdentityMismatch {
            expected: s.expected_node_id,
            derived: station_node_id,
        });
    }
    let tls_binding = f.signed("tls_binding");
    let binding = verify_tls_binding(&tls_binding, station_key, s.profile, s.leaf, s.now_ms)?;
    let expires_at = verify_status(
        &f.signed("tls_status"),
        &tls_binding,
        station_key,
        s.profile,
        s.now_ms,
    )?;
    let client_node_id = node_id_of(&s.identity_key, s.profile);
    let proof = s
        .connect_key
        .sign(&proof_message(
            f.bytes("nonce"),
            &station_node_id,
            &client_node_id,
            s.leaf,
            challenge,
        ))
        .map_err(HandshakeError::Key)?;
    let connect = encode_frame(
        "connect",
        vec![
            entry("identity_key", Value::Bytes(s.identity_key.clone())),
            entry("connect_key", Value::Bytes(connect_key)),
            entry("connect_binding", s.connect_binding.to_value()),
            entry("connect_status", s.connect_status.to_value()),
            entry("proof", Value::Bytes(proof)),
            entry("capabilities", Value::Int(i128::from(s.capabilities))),
            entry(
                "member_endorsement",
                Value::Bytes(s.member_endorsement.clone()),
            ),
        ],
    );
    Ok((
        connect,
        Station {
            node_id: station_node_id,
            identity_key: station_key.to_vec(),
            tls_binding,
            status_expires_at: expires_at,
            binding_not_after: binding.not_after,
        },
    ))
}

/// What a station brings to a CONNECT check: its profile, the challenge bytes
/// it sent, the leaf DER this connection presented, its puzzle difficulty and
/// mode, its capability bits, and the time in milliseconds.
#[derive(Debug, Clone)]
pub struct StationSession {
    pub profile: Profile,
    pub challenge: Vec<u8>,
    pub leaf: Vec<u8>,
    pub puzzle_difficulty: u32,
    pub puzzle_mode: PuzzleMode,
    pub capabilities: u64,
    pub now_ms: i64,
}

/// What a station knows of an accepted client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub node_id: [u8; 32],
    pub identity_key: Vec<u8>,
    pub connect_key: Vec<u8>,
    pub connect_binding: SignedTbs,
    pub capabilities: u64,
    pub status_expires_at: i64,
    pub binding_not_after: i64,
    pub puzzle: PuzzleResult,
    /// The endorsement the CONNECT carried, empty when the client holds none.
    /// Nothing here checks it: that is the station's policy.
    pub member_endorsement: Vec<u8>,
}

/// Checks a CONNECT, and returns the verdict with the HELLO to send. It
/// checks, in macula's order: the frame, the carried keys and the proof's
/// length, that each key serves one purpose, the puzzle on the derived node_id
/// before any signature, the CONNECT binding and status statement, and the
/// proof against the challenge this station sent and the leaf it presented. A
/// refusal is the local close reason, and the HELLO refuses with one coarse
/// code.
pub fn accept_connect(
    connect: &[u8],
    s: &StationSession,
) -> (Result<Client, HandshakeError>, Vec<u8>) {
    match check_connect(connect, s) {
        Ok(client) => (Ok(client), hello(None, s.capabilities)),
        Err(e) => {
            let code = match e {
                HandshakeError::UnsupportedVersion => RefusalCode::UnsupportedVersion,
                HandshakeError::PuzzleInvalid => RefusalCode::PuzzleInvalid,
                _ => RefusalCode::NotAccepted,
            };
            (Err(e), hello(Some(code), s.capabilities))
        }
    }
}

fn check_connect(connect: &[u8], s: &StationSession) -> Result<Client, HandshakeError> {
    if s.puzzle_difficulty > 256 {
        return Err(HandshakeError::InvalidStationSession);
    }
    let f = decode(connect, "connect", &[CONNECT_KEYS])?;
    let (identity_key, connect_key, proof) = (
        f.bytes("identity_key"),
        f.bytes("connect_key"),
        f.bytes("proof"),
    );
    if !carried_key_well_formed(identity_key, s.profile)
        || !carried_key_well_formed(connect_key, s.profile)
        || proof.len() != signature_size(s.profile)
    {
        return Err(HandshakeError::Malformed);
    }
    if shares_a_half(identity_key, connect_key) || in_leaf(connect_key, &s.leaf) {
        return Err(HandshakeError::KeyPurposeReuse);
    }
    let node_id = node_id_of(identity_key, s.profile);
    let puzzle = match s.puzzle_mode {
        PuzzleMode::Off => PuzzleResult::NotChecked,
        _ if puzzle_solved(&node_id, s.puzzle_difficulty) => PuzzleResult::Solved,
        _ => PuzzleResult::Unsolved,
    };
    if puzzle == PuzzleResult::Unsolved && s.puzzle_mode == PuzzleMode::Enforce {
        return Err(HandshakeError::PuzzleInvalid);
    }
    let connect_binding = f.signed("connect_binding");
    let binding = verify_connect_binding(
        &connect_binding,
        identity_key,
        s.profile,
        connect_key,
        s.now_ms,
    )?;
    let expires_at = verify_status(
        &f.signed("connect_status"),
        &connect_binding,
        identity_key,
        s.profile,
        s.now_ms,
    )?;
    if !proof_verifies(s, &node_id, connect_key, proof) {
        return Err(HandshakeError::ProofInvalid);
    }
    Ok(Client {
        node_id,
        identity_key: identity_key.to_vec(),
        connect_key: connect_key.to_vec(),
        connect_binding,
        capabilities: f.uint("capabilities"),
        status_expires_at: expires_at,
        binding_not_after: binding.not_after,
        puzzle,
        member_endorsement: f.bytes("member_endorsement").to_vec(),
    })
}

/// A CONNECT proof checked against the challenge the station sent and the
/// leaf it presented. The station's own challenge decodes: it built it.
fn proof_verifies(
    s: &StationSession,
    client_node_id: &[u8; 32],
    connect_key: &[u8],
    proof: &[u8],
) -> bool {
    let Ok(challenge) = decode(&s.challenge, "challenge", &[CHALLENGE_KEYS]) else {
        return false;
    };
    let station_node_id = node_id_of(challenge.bytes("identity_key"), s.profile);
    let message = proof_message(
        challenge.bytes("nonce"),
        &station_node_id,
        client_node_id,
        &s.leaf,
        &s.challenge,
    );
    verify(&message, proof, connect_key, s.profile)
}

/// What the CONNECT proof signs: the label, a zero byte, the nonce, the
/// station's and the client's node_ids, the SHA-384 of the leaf DER and the
/// SHA-384 of the challenge bytes as received.
fn proof_message(
    nonce: &[u8],
    station_node_id: &[u8; 32],
    client_node_id: &[u8; 32],
    leaf: &[u8],
    challenge: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONNECT_PROOF_LABEL.len() + 1 + nonce.len() + 64 + 96);
    out.extend_from_slice(CONNECT_PROOF_LABEL);
    out.push(0);
    out.extend_from_slice(nonce);
    out.extend_from_slice(station_node_id);
    out.extend_from_slice(client_node_id);
    out.extend_from_slice(&Sha384::digest(leaf));
    out.extend_from_slice(&Sha384::digest(challenge));
    out
}

fn hello(refusal: Option<RefusalCode>, capabilities: u64) -> Vec<u8> {
    let mut entries = vec![
        entry("accepted", Value::Int(i128::from(refusal.is_none()))),
        entry("capabilities", Value::Int(i128::from(capabilities))),
    ];
    if let Some(code) = refusal {
        entries.push(entry("refusal_code", Value::text(code.name())));
    }
    encode_frame("hello", entries)
}

/// The client's reading of HELLO: the station's capability bits, or
/// [`HandshakeError::Refused`] with its refusal code.
pub fn read_hello(frame: &[u8]) -> Result<u64, HandshakeError> {
    let f = decode(frame, "hello", &[HELLO_ACCEPTED_KEYS, HELLO_REFUSED_KEYS])?;
    let accepted = f.int("accepted");
    match (accepted, f.0.get("refusal_code")) {
        (1, None) => Ok(f.uint("capabilities")),
        (0, Some(Value::Text(code))) => Err(HandshakeError::Refused(
            RefusalCode::parse(code).ok_or(HandshakeError::Malformed)?,
        )),
        _ => Err(HandshakeError::Malformed),
    }
}

/// A status frame carrying a fresh status statement, sent at every reissue.
pub fn status_frame(statement: &SignedTbs) -> Vec<u8> {
    encode_frame("status", vec![entry("statement", statement.to_value())])
}

/// What a connection checks a peer's status frames against: the profile, the
/// identity key and binding the handshake verified, and the time in
/// milliseconds.
#[derive(Debug, Clone)]
pub struct Peer {
    pub profile: Profile,
    pub identity_key: Vec<u8>,
    pub binding: SignedTbs,
    pub now_ms: i64,
}

/// Checks a peer's status frame, and returns when its statement expires.
pub fn read_status(frame: &[u8], p: &Peer) -> Result<i64, HandshakeError> {
    let f = decode(frame, "status", &[STATUS_KEYS])?;
    Ok(verify_status(
        &f.signed("statement"),
        &p.binding,
        &p.identity_key,
        p.profile,
        p.now_ms,
    )?)
}

/// A decoded handshake frame's values by their keys.
struct Fields(std::collections::HashMap<String, Value>);

impl Fields {
    fn bytes(&self, key: &str) -> &[u8] {
        match self.0.get(key) {
            Some(Value::Bytes(b)) => b,
            _ => &[],
        }
    }

    fn text(&self, key: &str) -> &str {
        match self.0.get(key) {
            Some(Value::Text(t)) => t,
            _ => "",
        }
    }

    fn int(&self, key: &str) -> i128 {
        match self.0.get(key) {
            Some(Value::Int(n)) => *n,
            _ => -1,
        }
    }

    fn uint(&self, key: &str) -> u64 {
        u64::try_from(self.int(key)).unwrap_or(0)
    }

    fn signed(&self, key: &str) -> SignedTbs {
        self.0
            .get(key)
            .and_then(|v| SignedTbs::from_value(v).ok())
            .unwrap_or(SignedTbs {
                tbs: Vec::new(),
                signature: Vec::new(),
            })
    }
}

/// A handshake frame read strictly, in macula's order: the decoding rule, the
/// version, the frame type, exactly the keys of one of the layouts, then the
/// type and length of every field.
fn decode(frame: &[u8], frame_type: &str, layouts: &[&[&str]]) -> Result<Fields, HandshakeError> {
    let Ok(Value::Map(pairs)) = cbor::decode(frame) else {
        return Err(HandshakeError::Malformed);
    };
    let mut fields = std::collections::HashMap::with_capacity(pairs.len());
    let mut non_text = 0;
    for (key, value) in pairs {
        match key {
            Value::Text(name) => {
                fields.insert(name, value);
            }
            _ => non_text += 1,
        }
    }
    match fields.get("version") {
        Some(Value::Int(v)) if *v == i128::from(VERSION) => {}
        Some(Value::Int(_)) => return Err(HandshakeError::UnsupportedVersion),
        _ => return Err(HandshakeError::Malformed),
    }
    match fields.get("frame_type") {
        Some(Value::Text(t)) if t == frame_type => {}
        Some(Value::Text(_)) => return Err(HandshakeError::UnexpectedFrame),
        _ => return Err(HandshakeError::Malformed),
    }
    let mut keys: Vec<&str> = fields.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let has_layout = layouts.contains(&keys.as_slice());
    if non_text > 0 || !has_layout || !fields.iter().all(|(k, v)| field_typed(k, v)) {
        return Err(HandshakeError::Malformed);
    }
    Ok(Fields(fields))
}

fn field_typed(key: &str, v: &Value) -> bool {
    match key {
        "version" | "frame_type" => true,
        "profile" => matches!(v, Value::Text(_)),
        "nonce" => matches!(v, Value::Bytes(b) if b.len() == NONCE_SIZE),
        "identity_key" | "connect_key" | "proof" | "member_endorsement" => {
            matches!(v, Value::Bytes(_))
        }
        "tls_binding" | "tls_status" | "connect_binding" | "connect_status" | "statement" => {
            SignedTbs::from_value(v).is_ok()
        }
        "capabilities" => {
            matches!(v, Value::Int(n) if *n >= 0 && *n < i128::from(MAX_PROTOCOL_INT))
        }
        "accepted" => matches!(v, Value::Int(0 | 1)),
        "refusal_code" => matches!(v, Value::Text(t) if RefusalCode::parse(t).is_some()),
        _ => false,
    }
}

/// Whether `leaf` holds `key`'s ML-DSA-87 half.
fn in_leaf(key: &[u8], leaf: &[u8]) -> bool {
    key.len() >= MLDSA_KEY_SIZE
        && leaf
            .windows(MLDSA_KEY_SIZE)
            .any(|w| w == &key[..MLDSA_KEY_SIZE])
}

/// Whether two carried keys share their ML-DSA-87 half, or a classical half.
fn shares_a_half(a: &[u8], b: &[u8]) -> bool {
    if a.len() < MLDSA_KEY_SIZE || b.len() < MLDSA_KEY_SIZE {
        return a == b;
    }
    let (classical_a, classical_b) = (&a[MLDSA_KEY_SIZE..], &b[MLDSA_KEY_SIZE..]);
    a[..MLDSA_KEY_SIZE] == b[..MLDSA_KEY_SIZE]
        || (!classical_a.is_empty() && classical_a == classical_b)
}

fn encode_frame(frame_type: &str, entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut all = vec![
        entry("version", Value::Int(i128::from(VERSION))),
        entry("frame_type", Value::text(frame_type)),
    ];
    all.extend(entries);
    cbor::encode(&Value::Map(all)).expect("a handshake frame's integers are all below 2^53")
}

fn entry(key: &str, value: Value) -> (Value, Value) {
    (Value::text(key), value)
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
