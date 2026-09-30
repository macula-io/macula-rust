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
//!
//! Version 5 (macula 13.2, DESIGN_NEIGHBOUR_CHANNEL_BINDING) binds both ends
//! to the TLS session. The opener and the challenge stay version 4; the client
//! picks 4 or 5 in CONNECT, and the station answers HELLO in the same version.
//! In version 5 the CONNECT proof (V2) also covers E, the session's TLS
//! exporter value, and the client's capabilities, and HELLO carries the
//! station's session proof, signed by its identity key over E, both frames and
//! both node_ids, only after every check on CONNECT has passed. A station with
//! no exporter answers a v5 CONNECT as an old station does, with
//! `unsupported_version`.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha384};

use crate::binding::{
    verify_connect_binding, verify_status, verify_tls_binding, BindingError, SignedTbs,
};
use crate::cbor::{self, Value};
use crate::node_key::{
    carried_key_well_formed, node_id_of, puzzle_solved, signature_size, verify, KeyError, NodeKey,
};
use crate::profile::Profile;

#[cfg(test)]
mod v5_tests;

/// The handshake's frame version: 4, as macula 12's. A peer on another version
/// hears `unsupported_version`.
pub const VERSION: i64 = 4;

/// The channel-bound handshake: both proofs over the TLS session's exporter
/// value.
pub const VERSION_5: i64 = 5;

/// The TLS 1.3 exporter label (RFC 8446 section 7.5) handshake v5 binds to,
/// over the context client node_id || station node_id, 32 bytes.
pub const EXPORTER_LABEL: &str = "EXPORTER-macula-session-v1";

const NONCE_SIZE: usize = 32;
const EXPORTER_SIZE: usize = 32;
const MAX_PROTOCOL_INT: i64 = 1 << 53;
const MLDSA_KEY_SIZE: usize = 2592;
const CONNECT_PROOF_LABEL: &[u8] = b"MACULA-PQ-CONNECT-PROOF-V1";
const CONNECT_PROOF_LABEL_V2: &[u8] = b"MACULA-PQ-CONNECT-PROOF-V2";
const SESSION_PROOF_LABEL: &[u8] = b"MACULA-PQ-SESSION-PROOF-V1";

/// A TLS 1.3 session's exporter: label, context and length to bytes, or
/// `None` when the session gives none. Both ends of one session export the
/// same bytes.
pub type Exporter = dyn Fn(&str, &[u8], usize) -> Option<Vec<u8>> + Send + Sync;

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
const HELLO_PROVED_KEYS: &[&str] = &[
    "accepted",
    "capabilities",
    "frame_type",
    "session_proof",
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
    /// A v5 CONNECT past the station's session proof budget. Only a v5 HELLO
    /// carries it.
    SessionProofRate,
    /// A CONNECT that failed any other check.
    NotAccepted,
}

impl RefusalCode {
    fn name(self) -> &'static str {
        match self {
            RefusalCode::UnsupportedVersion => "unsupported_version",
            RefusalCode::PuzzleInvalid => "puzzle_invalid",
            RefusalCode::SessionProofRate => "session_proof_rate",
            RefusalCode::NotAccepted => "not_accepted",
        }
    }

    fn parse(name: &str) -> Option<RefusalCode> {
        match name {
            "unsupported_version" => Some(RefusalCode::UnsupportedVersion),
            "puzzle_invalid" => Some(RefusalCode::PuzzleInvalid),
            "session_proof_rate" => Some(RefusalCode::SessionProofRate),
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
    /// A v5 HELLO whose session proof does not verify under the station's
    /// identity key over this session.
    SessionProofInvalid,
    /// A v5 HELLO that accepts without a session proof.
    SessionProofMissing,
    /// A station past its session proof budget.
    SessionProofRate,
    /// A v4 HELLO that accepts a v5 CONNECT: never taken as a v4 connection.
    V4HelloToV5Connect,
    /// A v5 session whose TLS exporter gave no value.
    ExporterUnavailable,
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
            HandshakeError::SessionProofInvalid => f.write_str("the session proof does not verify"),
            HandshakeError::SessionProofMissing => {
                f.write_str("the HELLO carries no session proof")
            }
            HandshakeError::SessionProofRate => {
                f.write_str("the station's session proof budget is spent")
            }
            HandshakeError::V4HelloToV5Connect => f.write_str("a v4 HELLO accepted a v5 CONNECT"),
            HandshakeError::ExporterUnavailable => f.write_str("the TLS exporter is unavailable"),
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
/// the time in milliseconds, the realm membership endorsement CONNECT
/// carries, empty for a node that holds none, the version CONNECT carries
/// ([`VERSION`] or [`VERSION_5`]), and this connection's TLS exporter, which
/// version 5 needs.
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
    pub version: i64,
    pub export: Option<&'a Exporter>,
}

/// What a client knows of the station once it has checked the challenge, and
/// what its HELLO must answer: the version the CONNECT carried and, in
/// version 5, what the session proof covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub node_id: [u8; 32],
    pub identity_key: Vec<u8>,
    pub tls_binding: SignedTbs,
    pub status_expires_at: i64,
    pub binding_not_after: i64,
    pub version: i64,
    profile: Profile,
    exporter_value: Vec<u8>,
    challenge: Vec<u8>,
    connect: Vec<u8>,
    client_node_id: [u8; 32],
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
    let e = session_exported(s.version, s.export, &client_node_id, &station_node_id)?;
    let proof = s
        .connect_key
        .sign(&proof_message(
            s.version,
            f.bytes("nonce"),
            &station_node_id,
            &client_node_id,
            s.leaf,
            challenge,
            &e,
            s.capabilities,
        ))
        .map_err(HandshakeError::Key)?;
    let connect = encode_frame_version(
        s.version,
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
        connect.clone(),
        Station {
            node_id: station_node_id,
            identity_key: station_key.to_vec(),
            tls_binding,
            status_expires_at: expires_at,
            binding_not_after: binding.not_after,
            version: s.version,
            profile: s.profile,
            exporter_value: e,
            challenge: challenge.to_vec(),
            connect,
            client_node_id,
        },
    ))
}

/// E for a v5 session, with the client's node_id first in the context (the
/// initiator's), and nothing for version 4.
fn session_exported(
    version: i64,
    export: Option<&Exporter>,
    client_node_id: &[u8; 32],
    station_node_id: &[u8; 32],
) -> Result<Vec<u8>, HandshakeError> {
    match (version, export) {
        (VERSION, _) => Ok(Vec::new()),
        (VERSION_5, Some(export)) => {
            let context = [client_node_id.as_slice(), station_node_id].concat();
            match export(EXPORTER_LABEL, &context, EXPORTER_SIZE) {
                Some(e) if e.len() == EXPORTER_SIZE => Ok(e),
                _ => Err(HandshakeError::ExporterUnavailable),
            }
        }
        (VERSION_5, None) => Err(HandshakeError::ExporterUnavailable),
        _ => Err(HandshakeError::UnsupportedVersion),
    }
}

/// What a station brings to a CONNECT check: its profile, the challenge bytes
/// it sent, the leaf DER this connection presented, its puzzle difficulty and
/// mode, its capability bits, the time in milliseconds, and what it binds a v5
/// session with. Without `v5` it answers only version 4.
#[derive(Debug, Clone)]
pub struct StationSession {
    pub profile: Profile,
    pub challenge: Vec<u8>,
    pub leaf: Vec<u8>,
    pub puzzle_difficulty: u32,
    pub puzzle_mode: PuzzleMode,
    pub capabilities: u64,
    pub now_ms: i64,
    pub v5: Option<StationV5>,
}

/// Signs a v5 session proof with the station's identity key for the client
/// named, within the station's budget ([`HandshakeError::SessionProofRate`]
/// past it).
pub type SessionProofSigner =
    dyn Fn(&[u8; 32], &[u8]) -> Result<Vec<u8>, HandshakeError> + Send + Sync;

/// A station's means to bind a v5 session: this connection's TLS exporter,
/// and its session proof signer.
#[derive(Clone)]
pub struct StationV5 {
    pub export: Arc<Exporter>,
    pub sign_session_proof: Arc<SessionProofSigner>,
}

impl fmt::Debug for StationV5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StationV5")
    }
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
    /// The version the CONNECT carried, 4 or 5.
    pub version: i64,
}

/// Checks a CONNECT, and returns the verdict with the HELLO to send. It
/// checks, in macula's order: the frame, the carried keys and the proof's
/// length, that each key serves one purpose, the puzzle on the derived node_id
/// before any signature, the CONNECT binding and status statement, and the
/// proof against the challenge this station sent and the leaf it presented. A
/// refusal is the local close reason, and the HELLO refuses with one coarse
/// code.
///
/// A station with `v5` answers version 4 and 5, HELLO in the CONNECT's
/// version; in version 5 it signs the session proof only once every check has
/// passed. Without it, a v5 CONNECT is refused `unsupported_version` in
/// version 4, as an old station refuses it.
pub fn accept_connect(
    connect: &[u8],
    s: &StationSession,
) -> (Result<Client, HandshakeError>, Vec<u8>) {
    let mut version = VERSION;
    match check_connect(connect, s, &mut version) {
        Ok((client, session_proof)) => {
            let hello = hello(client.version, None, s.capabilities, session_proof);
            (Ok(client), hello)
        }
        Err(e) => {
            let code = match e {
                HandshakeError::UnsupportedVersion => RefusalCode::UnsupportedVersion,
                HandshakeError::PuzzleInvalid => RefusalCode::PuzzleInvalid,
                HandshakeError::SessionProofRate => RefusalCode::SessionProofRate,
                _ => RefusalCode::NotAccepted,
            };
            (Err(e), hello(version, Some(code), s.capabilities, None))
        }
    }
}

/// The client and, in version 5, the session proof. `version` is set to the
/// CONNECT's once it decodes, so a refusal answers in it.
fn check_connect(
    connect: &[u8],
    s: &StationSession,
    version: &mut i64,
) -> Result<(Client, Option<Vec<u8>>), HandshakeError> {
    if s.puzzle_difficulty > 256 {
        return Err(HandshakeError::InvalidStationSession);
    }
    let versions: &[i64] = match s.v5 {
        Some(_) => &[VERSION, VERSION_5],
        None => &[VERSION],
    };
    let f = decode_versioned(connect, "connect", versions, &[CONNECT_KEYS])?;
    *version = f.version();
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
    // The station's own challenge decodes: it built it.
    let challenge = decode(&s.challenge, "challenge", &[CHALLENGE_KEYS])
        .map_err(|_| HandshakeError::ProofInvalid)?;
    let station_node_id = node_id_of(challenge.bytes("identity_key"), s.profile);
    let export = s.v5.as_ref().map(|v5| v5.export.as_ref());
    let e = session_exported(*version, export, &node_id, &station_node_id)?;
    let capabilities = f.uint("capabilities");
    let message = proof_message(
        *version,
        challenge.bytes("nonce"),
        &station_node_id,
        &node_id,
        &s.leaf,
        &s.challenge,
        &e,
        capabilities,
    );
    if !verify(&message, proof, connect_key, s.profile) {
        return Err(HandshakeError::ProofInvalid);
    }
    let session_proof = match (&s.v5, *version) {
        (Some(v5), VERSION_5) => Some((v5.sign_session_proof)(
            &node_id,
            &session_proof_message(
                &e,
                &s.challenge,
                connect,
                &station_node_id,
                &node_id,
                s.capabilities,
            ),
        )?),
        _ => None,
    };
    Ok((
        Client {
            node_id,
            identity_key: identity_key.to_vec(),
            connect_key: connect_key.to_vec(),
            connect_binding,
            capabilities,
            status_expires_at: expires_at,
            binding_not_after: binding.not_after,
            puzzle,
            member_endorsement: f.bytes("member_endorsement").to_vec(),
            version: *version,
        },
        session_proof,
    ))
}

/// What the CONNECT proof signs: the label, a zero byte, the nonce, the
/// station's and the client's node_ids, the SHA-384 of the leaf DER and the
/// SHA-384 of the challenge bytes as received. Version 5 (V2) appends E and
/// the client's capabilities, 8 bytes big-endian: every field has a fixed
/// width, so no two field sequences encode to the same bytes.
#[allow(clippy::too_many_arguments)]
fn proof_message(
    version: i64,
    nonce: &[u8],
    station_node_id: &[u8; 32],
    client_node_id: &[u8; 32],
    leaf: &[u8],
    challenge: &[u8],
    e: &[u8],
    capabilities: u64,
) -> Vec<u8> {
    let label = match version {
        VERSION_5 => CONNECT_PROOF_LABEL_V2,
        _ => CONNECT_PROOF_LABEL,
    };
    let mut out = Vec::with_capacity(label.len() + 1 + nonce.len() + 64 + 96 + EXPORTER_SIZE + 8);
    out.extend_from_slice(label);
    out.push(0);
    out.extend_from_slice(nonce);
    out.extend_from_slice(station_node_id);
    out.extend_from_slice(client_node_id);
    out.extend_from_slice(&Sha384::digest(leaf));
    out.extend_from_slice(&Sha384::digest(challenge));
    if version == VERSION_5 {
        out.extend_from_slice(e);
        out.extend_from_slice(&capabilities.to_be_bytes());
    }
    out
}

/// What the station's session proof signs: the label, a zero byte, E, the
/// SHA-384 of the challenge and of CONNECT, the station's and the client's
/// node_ids, and the station's capabilities, 8 bytes big-endian. The SHA-384
/// of CONNECT covers the client's capabilities.
fn session_proof_message(
    e: &[u8],
    challenge: &[u8],
    connect: &[u8],
    station_node_id: &[u8; 32],
    client_node_id: &[u8; 32],
    capabilities: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SESSION_PROOF_LABEL.len() + 1 + EXPORTER_SIZE + 96 + 64 + 8);
    out.extend_from_slice(SESSION_PROOF_LABEL);
    out.push(0);
    out.extend_from_slice(e);
    out.extend_from_slice(&Sha384::digest(challenge));
    out.extend_from_slice(&Sha384::digest(connect));
    out.extend_from_slice(station_node_id);
    out.extend_from_slice(client_node_id);
    out.extend_from_slice(&capabilities.to_be_bytes());
    out
}

fn hello(
    version: i64,
    refusal: Option<RefusalCode>,
    capabilities: u64,
    session_proof: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut entries = vec![
        entry("accepted", Value::Int(i128::from(refusal.is_none()))),
        entry("capabilities", Value::Int(i128::from(capabilities))),
    ];
    if let Some(code) = refusal {
        entries.push(entry("refusal_code", Value::text(code.name())));
    }
    if let Some(proof) = session_proof {
        entries.push(entry("session_proof", Value::Bytes(proof)));
    }
    encode_frame_version(version, "hello", entries)
}

/// The client's reading of HELLO against the version its CONNECT carried
/// (`station`, as [`answer_challenge`] returned it): the station's capability
/// bits, or why not. After a v5 CONNECT an accepting HELLO must be version 5
/// with a session proof that verifies under the station's identity key over
/// this session. A v4 refusal is how an old station answers
/// ([`HandshakeError::Refused`]); a v4 acceptance is never taken as a v4
/// connection.
pub fn read_hello(frame: &[u8], station: &Station) -> Result<u64, HandshakeError> {
    let (versions, layouts): (&[i64], &[&[&str]]) = match station.version {
        VERSION_5 => (
            &[VERSION, VERSION_5],
            &[HELLO_PROVED_KEYS, HELLO_ACCEPTED_KEYS, HELLO_REFUSED_KEYS],
        ),
        _ => (&[VERSION], &[HELLO_ACCEPTED_KEYS, HELLO_REFUSED_KEYS]),
    };
    let f = decode_versioned(frame, "hello", versions, layouts)?;
    let refusal = f.0.get("refusal_code");
    let proof = f.0.get("session_proof");
    match (f.int("accepted"), refusal) {
        (0, Some(Value::Text(code))) => {
            return Err(HandshakeError::Refused(
                RefusalCode::parse(code).ok_or(HandshakeError::Malformed)?,
            ))
        }
        (1, None) => {}
        _ => return Err(HandshakeError::Malformed),
    }
    let capabilities = f.uint("capabilities");
    match (f.version(), station.version, proof) {
        (VERSION, VERSION_5, _) => Err(HandshakeError::V4HelloToV5Connect),
        (VERSION, _, None) => Ok(capabilities),
        (VERSION_5, VERSION_5, None) => Err(HandshakeError::SessionProofMissing),
        (VERSION_5, VERSION_5, Some(Value::Bytes(proof))) => {
            if proof.len() != signature_size(station.profile) {
                return Err(HandshakeError::Malformed);
            }
            let message = session_proof_message(
                &station.exporter_value,
                &station.challenge,
                &station.connect,
                &station.node_id,
                &station.client_node_id,
                capabilities,
            );
            if !verify(&message, proof, &station.identity_key, station.profile) {
                return Err(HandshakeError::SessionProofInvalid);
            }
            Ok(capabilities)
        }
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

    fn version(&self) -> i64 {
        i64::try_from(self.int("version")).unwrap_or(-1)
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
    decode_versioned(frame, frame_type, &[VERSION], layouts)
}

/// `decode` in any of `versions`: another version is
/// [`HandshakeError::UnsupportedVersion`].
fn decode_versioned(
    frame: &[u8],
    frame_type: &str,
    versions: &[i64],
    layouts: &[&[&str]],
) -> Result<Fields, HandshakeError> {
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
        Some(Value::Int(v)) if versions.iter().any(|known| *v == i128::from(*known)) => {}
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
        "identity_key" | "connect_key" | "proof" | "member_endorsement" | "session_proof" => {
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
    encode_frame_version(VERSION, frame_type, entries)
}

/// `encode_frame` in a given version: CONNECT and HELLO carry the version the
/// client chose; opener, challenge and status are always 4.
fn encode_frame_version(version: i64, frame_type: &str, entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut all = vec![
        entry("version", Value::Int(i128::from(version))),
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
