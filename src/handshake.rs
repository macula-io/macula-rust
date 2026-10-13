//! The post-quantum connection handshake as wire 1.0 freezes it (WIRE_1_0.md
//! section 4, macula#98): the opener, challenge, CONNECT, HELLO and status
//! frames of DESIGN_PQ_HANDSHAKE_FRAMES and DESIGN_NEIGHBOUR_CHANNEL_BINDING, as
//! CBOR bytes without the length prefix.
//!
//! The client opens with an opener naming the versions and profiles it speaks.
//! The station picks the highest common version and the first profile in the
//! client's list it supports, or refuses at once with a HELLO naming its own
//! ranges. It answers with a challenge: the chosen version and profile, its own
//! ranges, its carried identity key, its TLS binding and status statement, and
//! a fresh nonce. The client checks the choice against both ranges (a downgrade
//! is detected here), and the challenge against the node_id it dialed and the
//! leaf it received, before it signs anything, and answers with CONNECT: its
//! ranges again, the chosen profile, its identity and CONNECT keys, the CONNECT
//! binding and status statement, and a proof (V3) by the CONNECT key over the
//! session, the challenge and the CONNECT itself. The station checks CONNECT,
//! the puzzle before any signature, and answers with HELLO, carrying its
//! session proof (V2) over the HELLO tbs. Status frames renew a peer's
//! statement on the open connection.
//!
//! Version 5 is the only version: every frame, before and after HELLO, carries
//! it, and both ends bind to the TLS session through its exporter value E. Each
//! end records the highest version it completed with each node_id and never
//! completes below it.
//!
//! Every frame decodes under the decoding rule and must hold exactly the keys
//! of its type, each of its type and length. Close reasons are local: a
//! refusing station sends only a HELLO with one coarse refusal code.

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
mod tests;
#[cfg(test)]
mod wire_1_0_tests;

/// The handshake and frame version of wire 1.0. A handshake version bump is a
/// wire major: there is no version 6 inside wire 1.x.
pub const VERSION: i64 = 5;

/// The TLS 1.3 exporter label (RFC 8446 section 7.5) the handshake binds to,
/// over the context client node_id || station node_id, 32 bytes.
pub const EXPORTER_LABEL: &str = "EXPORTER-macula-session-v1";

/// The capability bits CONNECT and HELLO carry (WIRE_1_0.md section 4.7): an
/// unsigned integer below 2^53, bits 0 to [`MAX_CAPABILITY_BIT`] reserved. Bits
/// never retire and are never reassigned; an unknown bit is ignored. Each one
/// states its behaviour towards a peer that lacks it and towards one that
/// claims it falsely: waste, never loss, both ways.
pub const CAP_STATION: u64 = 1 << 0;
/// A station that answers SWIM indirect probes.
pub const CAP_SWIM_INDIRECT: u64 = 1 << 1;
/// A peer that reads the relay code `overloaded` (macula#54), which a station
/// sends only to a peer that declares it.
pub const CAP_RELAY_OVERLOADED: u64 = 1 << 2;
/// The highest bit of the reserved range.
pub const MAX_CAPABILITY_BIT: u32 = 52;

const NONCE_SIZE: usize = 32;
const EXPORTER_SIZE: usize = 32;
const MAX_PROTOCOL_INT: i128 = 1 << 53;
const MLDSA_KEY_SIZE: usize = 2592;
const MAX_PROFILES: usize = 8;
const MAX_REFUSAL_CODE_BYTES: usize = 64;
const CONNECT_PROOF_LABEL: &[u8] = b"MACULA-PQ-CONNECT-PROOF-V3";
const SESSION_PROOF_LABEL: &[u8] = b"MACULA-PQ-SESSION-PROOF-V2";

/// A TLS 1.3 session's exporter: label, context and length to bytes, or
/// `None` when the session gives none. Both ends of one session export the
/// same bytes.
pub type Exporter = dyn Fn(&str, &[u8], usize) -> Option<Vec<u8>> + Send + Sync;

/// The highest handshake version an end last completed with a node_id, 0 for
/// none (WIRE_1_0.md section 4.6). It survives restarts where the host can
/// write, and lasts the run where it cannot.
pub type Floor = dyn Fn(&[u8; 32]) -> i64 + Send + Sync;

const OPENER_KEYS: &[&str] = &["frame_type", "profiles", "version", "versions"];
const CHALLENGE_KEYS: &[&str] = &[
    "frame_type",
    "identity_key",
    "nonce",
    "profile",
    "profiles",
    "tls_binding",
    "tls_status",
    "version",
    "versions",
];
/// CONNECT always holds member_endorsement, empty when the node has none: one
/// layout, so the wire does not tell whether a node holds an endorsement or a
/// station asks for one.
const CONNECT_KEYS: &[&str] = &[
    "capabilities",
    "connect_binding",
    "connect_key",
    "connect_status",
    "frame_type",
    "identity_key",
    "member_endorsement",
    "profile",
    "profiles",
    "proof",
    "version",
    "versions",
];
const HELLO_PROVED_KEYS: &[&str] = &[
    "accepted",
    "capabilities",
    "frame_type",
    "session_proof",
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
const HELLO_EARLY_KEYS: &[&str] = &[
    "accepted",
    "frame_type",
    "profiles",
    "refusal_code",
    "version",
    "versions",
];

/// The one coarse reason a refusing HELLO carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// Ranges that share no version, or a frame of another version.
    UnsupportedVersion,
    /// Profile lists that share no profile (WIRE_1_0.md section 4.4).
    ProfileUnsupported,
    /// A node_id that misses the puzzle, which the client can check itself.
    PuzzleInvalid,
    /// A CONNECT past the station's session proof budget.
    SessionProofRate,
    /// A CONNECT that failed any other check. A refusal code this crate does
    /// not know reads as this one.
    NotAccepted,
}

impl RefusalCode {
    const ALL: [RefusalCode; 5] = [
        RefusalCode::UnsupportedVersion,
        RefusalCode::ProfileUnsupported,
        RefusalCode::PuzzleInvalid,
        RefusalCode::SessionProofRate,
        RefusalCode::NotAccepted,
    ];

    pub fn name(self) -> &'static str {
        match self {
            RefusalCode::UnsupportedVersion => "unsupported_version",
            RefusalCode::ProfileUnsupported => "profile_unsupported",
            RefusalCode::PuzzleInvalid => "puzzle_invalid",
            RefusalCode::SessionProofRate => "session_proof_rate",
            RefusalCode::NotAccepted => "not_accepted",
        }
    }

    /// A HELLO's refusal_code, a per-hop enum (WIRE_1_0.md section 3.4): one
    /// this crate does not know reads as `not_accepted`, counted.
    fn read(name: &str) -> RefusalCode {
        RefusalCode::ALL
            .into_iter()
            .find(|code| code.name() == name)
            .unwrap_or_else(|| {
                crate::frame::count_enum_fallback("refusal_code");
                RefusalCode::NotAccepted
            })
    }
}

/// What one end speaks: the versions `[min, max]` and its profiles by name,
/// in its order of preference, 1 to 8 of them. A peer may name profiles this
/// crate does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranges {
    pub min_version: i64,
    pub max_version: i64,
    pub profiles: Vec<String>,
}

impl Ranges {
    /// This crate's ranges for `profile`: version 5 alone, the policy of N
    /// and N-1 holding 5 alone in wire 1.0.
    pub fn supported(profile: Profile) -> Ranges {
        Ranges {
            min_version: VERSION,
            max_version: VERSION,
            profiles: vec![profile.name().to_string()],
        }
    }

    fn entries(&self) -> Vec<(Value, Value)> {
        vec![
            entry(
                "versions",
                Value::List(vec![
                    Value::Int(i128::from(self.min_version)),
                    Value::Int(i128::from(self.max_version)),
                ]),
            ),
            entry(
                "profiles",
                Value::List(self.profiles.iter().map(Value::text).collect()),
            ),
        ]
    }
}

/// The handshake's close reasons, named as macula names them. A binding or
/// status statement that fails its check closes with its [`BindingError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A frame of another type than the one expected next.
    UnexpectedFrame,
    /// A frame of another version than 5, or ranges that share no version
    /// (`unsupported_version`).
    UnsupportedVersion,
    /// Profile lists that share no profile, or a CONNECT naming a profile the
    /// station did not choose (`profile_unsupported`).
    ProfileUnsupported,
    /// A challenge whose chosen version or profile is not the highest common
    /// one of the client's ranges and the station's repeated ranges
    /// (`downgrade_detected`).
    DowngradeDetected,
    /// A CONNECT whose versions or profiles differ from the opener's
    /// (`negotiation_mismatch`).
    NegotiationMismatch,
    /// A chosen version below the one this end last completed with that
    /// node_id (`version_below_floor`).
    VersionBelowFloor,
    /// A frame that does not decode exactly, or a carried key or proof of the
    /// wrong form (`malformed_frame`).
    Malformed,
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
    /// A HELLO that refuses the connection, with its code, and the station's
    /// ranges when it refused before the challenge.
    Refused {
        code: RefusalCode,
        station_ranges: Option<Ranges>,
    },
    /// A station session with a puzzle difficulty the design does not have.
    InvalidStationSession,
    /// A HELLO whose session proof does not verify under the station's
    /// identity key over this session.
    SessionProofInvalid,
    /// A HELLO that accepts without a session proof.
    SessionProofMissing,
    /// A station past its session proof budget.
    SessionProofRate,
    /// A session whose TLS exporter gave no value.
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
            HandshakeError::UnsupportedVersion => f.write_str("unsupported_version"),
            HandshakeError::ProfileUnsupported => f.write_str("profile_unsupported"),
            HandshakeError::DowngradeDetected => f.write_str("downgrade_detected"),
            HandshakeError::NegotiationMismatch => f.write_str("negotiation_mismatch"),
            HandshakeError::VersionBelowFloor => f.write_str("version_below_floor"),
            HandshakeError::Malformed => f.write_str("malformed frame"),
            HandshakeError::KeyPurposeReuse => f.write_str("a key would serve two purposes"),
            HandshakeError::PeerIdentityMismatch { expected, derived } => write!(
                f,
                "dialed node_id {}, but the station's key derives {}",
                hex_of(expected),
                hex_of(derived)
            ),
            HandshakeError::PuzzleInvalid => f.write_str("the node_id does not meet the puzzle"),
            HandshakeError::ProofInvalid => f.write_str("the CONNECT proof does not verify"),
            HandshakeError::Refused { code, .. } => {
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

impl HandshakeError {
    /// The coarse code a refusing HELLO carries for this close reason.
    fn wire_refusal(&self) -> RefusalCode {
        match self {
            HandshakeError::UnsupportedVersion => RefusalCode::UnsupportedVersion,
            HandshakeError::PuzzleInvalid => RefusalCode::PuzzleInvalid,
            HandshakeError::SessionProofRate => RefusalCode::SessionProofRate,
            _ => RefusalCode::NotAccepted,
        }
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

/// The version and profile a station chooses for a client: the highest
/// version in both ranges and this crate's, and the first profile in the
/// client's list the station supports.
fn negotiate(client: &Ranges, station: &Ranges) -> Result<(i64, String), HandshakeError> {
    let version = client.max_version.min(station.max_version).min(VERSION);
    if version < client.min_version.max(station.min_version) {
        return Err(HandshakeError::UnsupportedVersion);
    }
    client
        .profiles
        .iter()
        .find(|p| station.profiles.contains(p))
        .map(|p| (version, p.clone()))
        .ok_or(HandshakeError::ProfileUnsupported)
}

/// The client's first frame on the control stream: its ranges, and nothing
/// that relates to identity.
pub fn opener(ranges: &Ranges) -> Vec<u8> {
    encode_frame("opener", ranges.entries())
}

/// What a station chose for a client from its opener: the version and
/// profile, and the client's ranges, which its CONNECT must repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub version: i64,
    pub profile: String,
    pub client: Ranges,
}

/// The station's reading of the first frame against its own ranges, and the
/// refusing HELLO to send before closing when there is one. A frame that is
/// not an opener of exactly its keys is [`HandshakeError::Malformed`], with no
/// HELLO. Ranges that share no version, or an opener of another version, are
/// `unsupported_version`, and lists that share no profile
/// `profile_unsupported`; each comes with a HELLO naming the station's
/// ranges.
pub fn read_opener(
    opener: &[u8],
    station: &Ranges,
) -> (Result<Negotiated, HandshakeError>, Option<Vec<u8>>) {
    let read = decode(opener, "opener", &[OPENER_KEYS]).and_then(|f| {
        let client = f.ranges();
        let (version, profile) = negotiate(&client, station)?;
        Ok(Negotiated {
            version,
            profile,
            client,
        })
    });
    match &read {
        Err(e @ (HandshakeError::UnsupportedVersion | HandshakeError::ProfileUnsupported)) => {
            let hello = hello_early_refusal(e, station);
            (read, Some(hello))
        }
        _ => (read, None),
    }
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

/// A station's challenge, with a fresh nonce: the version and profile it
/// chose, and its own ranges. The station keeps the bytes it sends, for the
/// proof check.
pub fn challenge(
    m: &StationMaterial,
    n: &Negotiated,
    station: &Ranges,
) -> Result<Vec<u8>, HandshakeError> {
    let mut nonce = [0u8; NONCE_SIZE];
    aws_lc_rs::rand::fill(&mut nonce)
        .map_err(|_| HandshakeError::Key(KeyError::RandomnessUnavailable))?;
    let mut entries = station.entries();
    entries.extend([
        entry("nonce", Value::Bytes(nonce.to_vec())),
        entry("profile", Value::text(n.profile.as_str())),
        entry("identity_key", Value::Bytes(m.identity_key.clone())),
        entry("tls_binding", m.tls_binding.to_value()),
        entry("tls_status", m.tls_status.to_value()),
    ]);
    Ok(encode_frame("challenge", entries))
}

/// What a client brings to a handshake: its profile, the node_id it dialed,
/// the leaf DER it received in this TLS handshake, its carried identity key,
/// its CONNECT key with binding and status statement, its capability bits,
/// the time in milliseconds, the realm membership endorsement CONNECT carries
/// (empty for a node that holds none), the ranges its opener carried, its
/// floor per station, and this connection's TLS exporter.
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
    pub ranges: Ranges,
    pub floor: &'a Floor,
    pub export: &'a Exporter,
}

/// What a client checks a challenge against: [`ClientSession`]'s parts that
/// the checks read, with the CONNECT key as carried, so a transcript can be
/// replayed without private keys.
struct ChallengeCheck<'a> {
    profile: Profile,
    expected_node_id: [u8; 32],
    leaf: &'a [u8],
    identity_key: &'a [u8],
    connect_public: &'a [u8],
    now_ms: i64,
    ranges: &'a Ranges,
    floor: &'a Floor,
    export: &'a Exporter,
}

/// What a client knows of the station once it has checked the challenge, and
/// what its HELLO must answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub node_id: [u8; 32],
    pub identity_key: Vec<u8>,
    pub tls_binding: SignedTbs,
    pub status_expires_at: i64,
    pub binding_not_after: i64,
    /// The version the station chose.
    pub version: i64,
    profile: Profile,
    nonce: Vec<u8>,
    leaf: Vec<u8>,
    exporter_value: Vec<u8>,
    challenge: Vec<u8>,
    connect: Vec<u8>,
    client_node_id: [u8; 32],
}

impl Station {
    /// The client proof V3 over this session and the CONNECT tbs.
    fn proof_message(&self, connect_tbs: &[u8]) -> Vec<u8> {
        proof_message(
            &self.nonce,
            &self.node_id,
            &self.client_node_id,
            &self.leaf,
            &self.challenge,
            &self.exporter_value,
            connect_tbs,
        )
    }
}

/// Checks a challenge, in macula's order, and signs nothing: the frame; the
/// chosen version and profile against the client's ranges and the station's
/// repeated ranges (`downgrade_detected`), and against the floor for the
/// node_id dialed (`version_below_floor`); the station's carried key in the
/// chosen profile; that each key in view serves one purpose; the station's
/// node_id against the one dialed; the TLS binding against the leaf received;
/// the status statement; and the session's exporter value.
fn read_challenge(challenge: &[u8], s: &ChallengeCheck<'_>) -> Result<Station, HandshakeError> {
    let f = decode(challenge, "challenge", &[CHALLENGE_KEYS])
        .map_err(|e| refusal_before_challenge(challenge).unwrap_or(e))?;
    let negotiated = negotiate(s.ranges, &f.ranges()).ok();
    let chosen = negotiated.filter(|(version, profile)| {
        i128::from(*version) == f.int("version")
            && profile == f.text("profile")
            && profile == s.profile.name()
    });
    let Some((version, _)) = chosen else {
        return Err(HandshakeError::DowngradeDetected);
    };
    if version < (s.floor)(&s.expected_node_id) {
        return Err(HandshakeError::VersionBelowFloor);
    }
    let station_key = f.bytes("identity_key");
    if !carried_key_well_formed(station_key, s.profile) {
        return Err(HandshakeError::Malformed);
    }
    if shares_a_half(s.identity_key, s.connect_public)
        || in_leaf(station_key, s.leaf)
        || in_leaf(s.connect_public, s.leaf)
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
    let status = f.signed("tls_status");
    let expires_at = verify_status(&status, &tls_binding, station_key, s.profile, s.now_ms)?;
    let client_node_id = node_id_of(s.identity_key, s.profile);
    let e = session_exported(s.export, &client_node_id, &station_node_id)?;
    Ok(Station {
        node_id: station_node_id,
        identity_key: station_key.to_vec(),
        tls_binding,
        status_expires_at: expires_at,
        binding_not_after: binding.not_after,
        version,
        profile: s.profile,
        nonce: f.bytes("nonce").to_vec(),
        leaf: s.leaf.to_vec(),
        exporter_value: e,
        challenge: challenge.to_vec(),
        connect: Vec::new(),
        client_node_id,
    })
}

/// Checks a challenge and, when every check passes, returns the CONNECT to
/// send, with its proof V3 by the CONNECT key. A refused challenge produces no
/// CONNECT, and nothing is signed before every check has passed.
pub fn answer_challenge(
    challenge: &[u8],
    s: &ClientSession<'_>,
) -> Result<(Vec<u8>, Station), HandshakeError> {
    let connect_public = s.connect_key.public_key();
    let mut station = read_challenge(
        challenge,
        &ChallengeCheck {
            profile: s.profile,
            expected_node_id: s.expected_node_id,
            leaf: s.leaf,
            identity_key: &s.identity_key,
            connect_public: &connect_public,
            now_ms: s.now_ms,
            ranges: &s.ranges,
            floor: s.floor,
            export: s.export,
        },
    )?;
    let mut entries = s.ranges.entries();
    entries.extend([
        entry("profile", Value::text(s.profile.name())),
        entry("identity_key", Value::Bytes(s.identity_key.clone())),
        entry("connect_key", Value::Bytes(connect_public)),
        entry("connect_binding", s.connect_binding.to_value()),
        entry("connect_status", s.connect_status.to_value()),
        entry("capabilities", Value::Int(i128::from(s.capabilities))),
        entry(
            "member_endorsement",
            Value::Bytes(s.member_endorsement.clone()),
        ),
    ]);
    let with_proof = |proof: Vec<u8>| {
        let mut all = entries.clone();
        all.push(entry("proof", Value::Bytes(proof)));
        encode_frame("connect", all)
    };
    let tbs = with_proof(Vec::new());
    let proof = s
        .connect_key
        .sign(&station.proof_message(&tbs))
        .map_err(HandshakeError::Key)?;
    station.connect = with_proof(proof);
    Ok((station.connect.clone(), station))
}

/// E for the session, with the client's node_id first in the context (the
/// initiator's).
fn session_exported(
    export: &Exporter,
    client_node_id: &[u8; 32],
    station_node_id: &[u8; 32],
) -> Result<Vec<u8>, HandshakeError> {
    let context = [client_node_id.as_slice(), station_node_id].concat();
    match export(EXPORTER_LABEL, &context, EXPORTER_SIZE) {
        Some(e) if e.len() == EXPORTER_SIZE => Ok(e),
        _ => Err(HandshakeError::ExporterUnavailable),
    }
}

/// Signs a session proof with the station's identity key for the client
/// named, within the station's budget ([`HandshakeError::SessionProofRate`]
/// past it).
pub type SessionProofSigner =
    dyn Fn(&[u8; 32], &[u8]) -> Result<Vec<u8>, HandshakeError> + Send + Sync;

/// What a station brings to a CONNECT check: its profile, the negotiation its
/// challenge carried and the challenge bytes it sent, the leaf DER this
/// connection presented, its puzzle difficulty and mode, its capability bits,
/// the time in milliseconds, its floor per client, its TLS exporter, and its
/// session proof signer.
#[derive(Clone)]
pub struct StationSession {
    pub profile: Profile,
    pub negotiated: Negotiated,
    pub challenge: Vec<u8>,
    pub leaf: Vec<u8>,
    pub puzzle_difficulty: u32,
    pub puzzle_mode: PuzzleMode,
    pub capabilities: u64,
    pub now_ms: i64,
    pub floor: Arc<Floor>,
    pub export: Arc<Exporter>,
    pub sign_session_proof: Arc<SessionProofSigner>,
}

impl fmt::Debug for StationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StationSession")
            .field("profile", &self.profile)
            .field("negotiated", &self.negotiated)
            .finish_non_exhaustive()
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
    /// The version the connection completed in.
    pub version: i64,
}

/// Checks a CONNECT and returns the verdict with the HELLO to send. It
/// checks, in macula's order: the frame; the client's ranges against its
/// opener's (`negotiation_mismatch`) and the profile against the one chosen
/// (`profile_unsupported`); the carried keys and the proof's length; that each
/// key serves one purpose; the puzzle on the derived node_id before any
/// signature; the floor for that node_id; the CONNECT binding and status
/// statement; and the proof V3 against the challenge this station sent, the
/// leaf it presented, the session and the CONNECT tbs. It signs the session
/// proof only once every check has passed. On a refusal the error is the
/// local close reason, and the HELLO refuses with one coarse code.
pub fn accept_connect(
    connect: &[u8],
    s: &StationSession,
) -> (Result<Client, HandshakeError>, Vec<u8>) {
    match check_connect(connect, s) {
        Ok((client, session_proof)) => {
            let hello = hello_accepted(s.capabilities, &session_proof);
            (Ok(client), hello)
        }
        Err(e) => {
            let hello = hello_refused(e.wire_refusal());
            (Err(e), hello)
        }
    }
}

/// The client and its session proof.
fn check_connect(connect: &[u8], s: &StationSession) -> Result<(Client, Vec<u8>), HandshakeError> {
    if s.puzzle_difficulty > 256 {
        return Err(HandshakeError::InvalidStationSession);
    }
    let f = decode(connect, "connect", &[CONNECT_KEYS])?;
    if f.ranges() != s.negotiated.client {
        return Err(HandshakeError::NegotiationMismatch);
    }
    if f.text("profile") != s.negotiated.profile || s.negotiated.profile != s.profile.name() {
        return Err(HandshakeError::ProfileUnsupported);
    }
    let (identity_key, connect_key, proof) = (
        f.bytes("identity_key"),
        f.bytes("connect_key"),
        f.bytes("proof"),
    );
    check_carried_keys(identity_key, connect_key, proof, s)?;
    let node_id = node_id_of(identity_key, s.profile);
    let puzzle = puzzle_verdict(&node_id, s)?;
    if s.negotiated.version < (s.floor)(&node_id) {
        return Err(HandshakeError::VersionBelowFloor);
    }
    let (connect_binding, binding_not_after, expires_at) =
        verified_connect_statements(&f, identity_key, connect_key, s)?;
    let session_proof = proved_session(connect, proof, connect_key, &node_id, s)?;
    Ok((
        Client {
            node_id,
            identity_key: identity_key.to_vec(),
            connect_key: connect_key.to_vec(),
            connect_binding,
            capabilities: f.uint("capabilities"),
            status_expires_at: expires_at,
            binding_not_after,
            puzzle,
            member_endorsement: f.bytes("member_endorsement").to_vec(),
            version: s.negotiated.version,
        },
        session_proof,
    ))
}

/// The CONNECT proof V3 checked against the challenge this station sent, the
/// leaf it presented, the session with the client `node_id` and the CONNECT
/// tbs; then, and only then, the session proof V2 over the HELLO tbs, signed.
fn proved_session(
    connect: &[u8],
    proof: &[u8],
    connect_key: &[u8],
    node_id: &[u8; 32],
    s: &StationSession,
) -> Result<Vec<u8>, HandshakeError> {
    let challenge = decode(&s.challenge, "challenge", &[CHALLENGE_KEYS])
        .map_err(|_| HandshakeError::ProofInvalid)?;
    let station_node_id = node_id_of(challenge.bytes("identity_key"), s.profile);
    let e = session_exported(s.export.as_ref(), node_id, &station_node_id)?;
    let tbs = frame_tbs(connect, "proof")?;
    let message = proof_message(
        challenge.bytes("nonce"),
        &station_node_id,
        node_id,
        &s.leaf,
        &s.challenge,
        &e,
        &tbs,
    );
    if !verify(&message, proof, connect_key, s.profile) {
        return Err(HandshakeError::ProofInvalid);
    }
    let hello_tbs = hello_accepted(s.capabilities, &[]);
    (s.sign_session_proof)(
        node_id,
        &session_proof_message(
            &e,
            &s.challenge,
            connect,
            &station_node_id,
            node_id,
            &hello_tbs,
        ),
    )
}

/// The CONNECT's carried keys and proof length: each key well formed and the
/// proof a signature's length, then each key serving one purpose.
fn check_carried_keys(
    identity_key: &[u8],
    connect_key: &[u8],
    proof: &[u8],
    s: &StationSession,
) -> Result<(), HandshakeError> {
    if !carried_key_well_formed(identity_key, s.profile)
        || !carried_key_well_formed(connect_key, s.profile)
        || proof.len() != signature_size(s.profile)
    {
        return Err(HandshakeError::Malformed);
    }
    if shares_a_half(identity_key, connect_key) || in_leaf(connect_key, &s.leaf) {
        return Err(HandshakeError::KeyPurposeReuse);
    }
    Ok(())
}

/// The puzzle on the derived `node_id` in the station's mode, refused when
/// unsolved and the station enforces it.
fn puzzle_verdict(node_id: &[u8; 32], s: &StationSession) -> Result<PuzzleResult, HandshakeError> {
    let puzzle = match s.puzzle_mode {
        PuzzleMode::Off => PuzzleResult::NotChecked,
        _ if puzzle_solved(node_id, s.puzzle_difficulty) => PuzzleResult::Solved,
        _ => PuzzleResult::Unsolved,
    };
    if puzzle == PuzzleResult::Unsolved && s.puzzle_mode == PuzzleMode::Enforce {
        return Err(HandshakeError::PuzzleInvalid);
    }
    Ok(puzzle)
}

/// The CONNECT binding and its status statement, verified at the station's
/// time: the binding, its not_after, and the statement's expiry.
fn verified_connect_statements(
    f: &Fields,
    identity_key: &[u8],
    connect_key: &[u8],
    s: &StationSession,
) -> Result<(SignedTbs, i64, i64), HandshakeError> {
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
    Ok((connect_binding, binding.not_after, expires_at))
}

/// A received frame with its signature field as the zero-length byte string,
/// re-encoded deterministically: the CONNECT tbs a proof covers (WIRE_1_0.md
/// section 4.2) or the HELLO tbs a session proof covers (4.3). A frame whose
/// received bytes are not its own deterministic encoding is malformed, so the
/// rebuild is exact.
fn frame_tbs(raw: &[u8], signature_key: &str) -> Result<Vec<u8>, HandshakeError> {
    let v = cbor::decode(raw).map_err(|_| HandshakeError::Malformed)?;
    if cbor::encode(&v).ok().as_deref() != Some(raw) {
        return Err(HandshakeError::Malformed);
    }
    let rebuilt = v.with_field(signature_key, Value::Bytes(Vec::new()));
    cbor::encode(&rebuilt).map_err(|_| HandshakeError::Malformed)
}

/// What the client proof V3 signs (WIRE_1_0.md section 4.2): the label, a
/// zero byte, the nonce, the station's and the client's node_ids, the SHA-384
/// of the leaf DER and of the challenge bytes as received, E, and the SHA-384
/// of the CONNECT tbs. Every field has a fixed width, so no two field
/// sequences encode to the same bytes.
fn proof_message(
    nonce: &[u8],
    station_node_id: &[u8; 32],
    client_node_id: &[u8; 32],
    leaf: &[u8],
    challenge: &[u8],
    e: &[u8],
    connect_tbs: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONNECT_PROOF_LABEL.len() + 1 + NONCE_SIZE + 64 + 144 + 32);
    out.extend_from_slice(CONNECT_PROOF_LABEL);
    out.push(0);
    out.extend_from_slice(nonce);
    out.extend_from_slice(station_node_id);
    out.extend_from_slice(client_node_id);
    out.extend_from_slice(&Sha384::digest(leaf));
    out.extend_from_slice(&Sha384::digest(challenge));
    out.extend_from_slice(e);
    out.extend_from_slice(&Sha384::digest(connect_tbs));
    out
}

/// What the station's session proof V2 signs (WIRE_1_0.md section 4.3): the
/// label, a zero byte, E, the SHA-384 of the challenge and of CONNECT, the
/// station's and the client's node_ids, and the SHA-384 of the HELLO tbs,
/// which covers the station's capabilities at any width and accepted. The
/// SHA-384 of the challenge covers the chosen version and profile and the
/// station's ranges, and that of CONNECT the client's.
fn session_proof_message(
    e: &[u8],
    challenge: &[u8],
    connect: &[u8],
    station_node_id: &[u8; 32],
    client_node_id: &[u8; 32],
    hello_tbs: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SESSION_PROOF_LABEL.len() + 1 + EXPORTER_SIZE + 144 + 64);
    out.extend_from_slice(SESSION_PROOF_LABEL);
    out.push(0);
    out.extend_from_slice(e);
    out.extend_from_slice(&Sha384::digest(challenge));
    out.extend_from_slice(&Sha384::digest(connect));
    out.extend_from_slice(station_node_id);
    out.extend_from_slice(client_node_id);
    out.extend_from_slice(&Sha384::digest(hello_tbs));
    out
}

fn hello_accepted(capabilities: u64, session_proof: &[u8]) -> Vec<u8> {
    encode_frame(
        "hello",
        vec![
            entry("accepted", Value::Int(1)),
            entry("capabilities", Value::Int(i128::from(capabilities))),
            entry("session_proof", Value::Bytes(session_proof.to_vec())),
        ],
    )
}

fn hello_refused(code: RefusalCode) -> Vec<u8> {
    encode_frame(
        "hello",
        vec![
            entry("accepted", Value::Int(0)),
            entry("refusal_code", Value::text(code.name())),
            entry("capabilities", Value::Int(0)),
        ],
    )
}

/// The HELLO a station answers an opener with when the ranges share no
/// version or the lists no profile, naming its own ranges.
fn hello_early_refusal(e: &HandshakeError, station: &Ranges) -> Vec<u8> {
    let code = match e {
        HandshakeError::UnsupportedVersion => RefusalCode::UnsupportedVersion,
        _ => RefusalCode::ProfileUnsupported,
    };
    let mut entries = station.entries();
    entries.extend([
        entry("accepted", Value::Int(0)),
        entry("refusal_code", Value::text(code.name())),
    ]);
    encode_frame("hello", entries)
}

/// The client's reading of HELLO (`station`, as [`answer_challenge`] returned
/// it): the station's capability bits, or why not. An accepting HELLO must
/// carry a session proof that verifies under the station's identity key over
/// this session and the HELLO tbs. A refusal is [`HandshakeError::Refused`],
/// which names the station's ranges when it came before the challenge.
pub fn read_hello(hello: &[u8], station: &Station) -> Result<u64, HandshakeError> {
    let f = decode(
        hello,
        "hello",
        &[
            HELLO_PROVED_KEYS,
            HELLO_ACCEPTED_KEYS,
            HELLO_REFUSED_KEYS,
            HELLO_EARLY_KEYS,
        ],
    )?;
    let accepted = f.int("accepted");
    let code =
        f.0.get("refusal_code")
            .map(|_| RefusalCode::read(f.text("refusal_code")));
    let early = f.0.contains_key("versions");
    match (accepted, code, early) {
        (0, Some(code), true) => {
            return Err(HandshakeError::Refused {
                code,
                station_ranges: Some(f.ranges()),
            })
        }
        (0, Some(code), false) => {
            return Err(HandshakeError::Refused {
                code,
                station_ranges: None,
            })
        }
        (1, None, false) => {}
        _ => return Err(HandshakeError::Malformed),
    }
    let Some(Value::Bytes(proof)) = f.0.get("session_proof") else {
        return Err(HandshakeError::SessionProofMissing);
    };
    if proof.len() != signature_size(station.profile) {
        return Err(HandshakeError::Malformed);
    }
    let tbs = frame_tbs(hello, "session_proof")?;
    let message = session_proof_message(
        &station.exporter_value,
        &station.challenge,
        &station.connect,
        &station.node_id,
        &station.client_node_id,
        &tbs,
    );
    if !verify(&message, proof, &station.identity_key, station.profile) {
        return Err(HandshakeError::SessionProofInvalid);
    }
    Ok(f.uint("capabilities"))
}

/// A station that shares no version or profile with the opener answers it
/// with a refusing HELLO in place of the challenge (WIRE_1_0.md section 4.4):
/// that HELLO as [`HandshakeError::Refused`] with the station's ranges, or
/// `None` for any other frame.
fn refusal_before_challenge(frame: &[u8]) -> Option<HandshakeError> {
    let f = decode(frame, "hello", &[HELLO_EARLY_KEYS]).ok()?;
    (f.int("accepted") == 0).then(|| HandshakeError::Refused {
        code: RefusalCode::read(f.text("refusal_code")),
        station_ranges: Some(f.ranges()),
    })
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

/// Checks a peer's status frame, and returns when its statement expires. A
/// STATUS is a control frame, not a handshake frame: it is read as every
/// frame after HELLO is (WIRE_1_0.md section 3), so it may carry the optional
/// envelope keys and a non-critical `ext`, and any other extra key is
/// [`HandshakeError::Malformed`].
pub fn read_status(frame: &[u8], p: &Peer) -> Result<i64, HandshakeError> {
    let envelope = cbor::decode(frame)
        .ok()
        .and_then(|v| crate::frame::read_envelope(&v).ok())
        .filter(|e| e.frame_type == "status")
        .ok_or(HandshakeError::Malformed)?;
    read_status_frame(&envelope.frame, p)
}

/// [`read_status`] of a frame whose envelope is already read, `ext` gone.
pub fn read_status_frame(frame: &Value, p: &Peer) -> Result<i64, HandshakeError> {
    let statement = crate::frame::read_control(frame)
        .ok()
        .and_then(|f| f.get("statement").map(SignedTbs::from_value))
        .ok_or(HandshakeError::Malformed)?
        .map_err(|_| HandshakeError::Malformed)?;
    Ok(verify_status(
        &statement,
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

    /// The frame's versions and profiles, already typed.
    fn ranges(&self) -> Ranges {
        let (min_version, max_version) = self
            .0
            .get("versions")
            .and_then(versions_of)
            .unwrap_or((0, 0));
        Ranges {
            min_version,
            max_version,
            profiles: self
                .0
                .get("profiles")
                .and_then(profiles_of)
                .unwrap_or_default(),
        }
    }
}

/// A handshake frame read strictly, in macula's order: the decoding rule, the
/// version (another is `unsupported_version`), the frame type, exactly the
/// keys of one of the layouts, then the type and length of every field.
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
        "versions" => versions_of(v).is_some(),
        "profiles" => profiles_of(v).is_some(),
        "nonce" => matches!(v, Value::Bytes(b) if b.len() == NONCE_SIZE),
        "identity_key" | "connect_key" | "proof" | "member_endorsement" | "session_proof" => {
            matches!(v, Value::Bytes(_))
        }
        "tls_binding" | "tls_status" | "connect_binding" | "connect_status" | "statement" => {
            SignedTbs::from_value(v).is_ok()
        }
        "capabilities" => matches!(v, Value::Int(n) if *n >= 0 && *n < MAX_PROTOCOL_INT),
        "accepted" => matches!(v, Value::Int(0 | 1)),
        "refusal_code" => {
            matches!(v, Value::Text(t) if !t.is_empty() && t.len() <= MAX_REFUSAL_CODE_BYTES)
        }
        _ => false,
    }
}

/// versions: `[min, max]`, unsigned integers below 2^53 with min <= max.
fn versions_of(v: &Value) -> Option<(i64, i64)> {
    match v {
        Value::List(items) => match items.as_slice() {
            [Value::Int(lo), Value::Int(hi)] if *lo >= 0 && *hi < MAX_PROTOCOL_INT && lo <= hi => {
                Some((*lo as i64, *hi as i64))
            }
            _ => None,
        },
        _ => None,
    }
}

/// profiles: 1 to 8 distinct profile names, as text.
fn profiles_of(v: &Value) -> Option<Vec<String>> {
    let Value::List(items) = v else {
        return None;
    };
    if items.is_empty() || items.len() > MAX_PROFILES {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Text(name) if !name.is_empty() && !out.contains(name) => out.push(name.clone()),
            _ => return None,
        }
    }
    Some(out)
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

/// A handshake frame: version 5, its type, and its own fields.
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
