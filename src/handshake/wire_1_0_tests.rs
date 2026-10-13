//! The wire 1.0 handshake vectors (macula#98, handshake.json): opener-to-HELLO
//! transcripts, replayed step by step. Each frame the client sent gets the
//! verdict this crate's station side reaches on it, and each frame the station
//! sent the verdict its client side reaches, under the fixed public keys, so
//! nothing is signed: a station's session proof is stood in for, and the proof
//! and session proof messages are compared byte for byte with the
//! transcript's. HELLO's refusal_code as a per-hop enum runs here too.

use std::sync::Mutex;

use serde_json::Value as Json;

use super::*;
use crate::wire_vectors::{self, hex_of, Case};

/// One end's input: its ranges, capabilities and floor, and the station's
/// puzzle or the client's expected station.
struct Side {
    ranges: Ranges,
    capabilities: u64,
    floor: Vec<([u8; 32], i64)>,
    expected: [u8; 32],
    puzzle: (u32, PuzzleMode),
}

fn ranges_of(v: &Json) -> Ranges {
    let versions: Vec<i64> = v["versions"]
        .as_array()
        .map(|a| a.iter().filter_map(Json::as_i64).collect())
        .unwrap_or_default();
    Ranges {
        min_version: versions.first().copied().unwrap_or(0),
        max_version: versions.get(1).copied().unwrap_or(0),
        profiles: v["profiles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn side_of(v: &Json) -> Side {
    let floor = v["floor"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|e| (fixed(&e["node_id"]), e["version"].as_i64().unwrap()))
                .collect()
        })
        .unwrap_or_default();
    let mode = match v["puzzle"]["mode"].as_str() {
        Some("enforce") => PuzzleMode::Enforce,
        Some("log_only") => PuzzleMode::LogOnly,
        _ => PuzzleMode::Off,
    };
    Side {
        ranges: ranges_of(v),
        capabilities: v["capabilities"].as_u64().unwrap_or(0),
        floor,
        expected: v["expected_station_node_id"]
            .as_str()
            .map(|_| fixed(&v["expected_station_node_id"]))
            .unwrap_or_default(),
        puzzle: (v["puzzle"]["difficulty"].as_u64().unwrap_or(0) as u32, mode),
    }
}

fn fixed(v: &Json) -> [u8; 32] {
    hex_of(v).try_into().unwrap()
}

/// A side's floor as a lookup.
fn floor_of(side: &Side) -> Arc<Floor> {
    let floor = side.floor.clone();
    Arc::new(move |node: &[u8; 32]| floor.iter().find(|(n, _)| n == node).map_or(0, |(_, v)| *v))
}

/// A step's verdict in the vectors' terms.
fn verdict<T>(read: &Result<T, HandshakeError>) -> (&'static str, String) {
    let refusal = match read {
        Ok(_) => return ("accept", String::new()),
        Err(HandshakeError::Refused { code, .. }) => format!("refused:{}", code.name()),
        Err(e) => close_reason(e).to_string(),
    };
    ("refuse", refusal)
}

fn close_reason(e: &HandshakeError) -> &'static str {
    match e {
        HandshakeError::Malformed => "malformed_frame",
        HandshakeError::UnsupportedVersion => "unsupported_version",
        HandshakeError::ProfileUnsupported => "profile_unsupported",
        HandshakeError::NegotiationMismatch => "negotiation_mismatch",
        HandshakeError::DowngradeDetected => "downgrade_detected",
        HandshakeError::VersionBelowFloor => "version_below_floor",
        HandshakeError::ProofInvalid => "proof_invalid",
        HandshakeError::PuzzleInvalid => "puzzle_invalid",
        HandshakeError::SessionProofInvalid => "session_proof_invalid",
        HandshakeError::SessionProofMissing => "session_proof_missing",
        _ => "another close reason",
    }
}

fn want(step: &Json, id: &str, i: usize, got: (&str, String)) {
    let expect = &step["expect"];
    let wanted = (
        expect["outcome"].as_str().unwrap(),
        expect["reason"].as_str().unwrap_or("").to_string(),
    );
    assert_eq!((got.0, got.1), (wanted.0, wanted.1), "{id} step {i}");
}

/// A station's refusing HELLO: its wire refusal code, and for an early
/// refusal the ranges it names.
fn want_hello(step: &Json, id: &str, i: usize, hello: Option<&[u8]>) {
    let Some(code) = step["expect"]["wire_refusal"].as_str() else {
        return;
    };
    let read = read_hello(hello.unwrap(), &any_station());
    let Err(HandshakeError::Refused {
        code: got,
        station_ranges,
    }) = read
    else {
        panic!("{id} step {i}: the HELLO sent reads {read:?}");
    };
    assert_eq!(got.name(), code, "{id} step {i}");
    if !step["expect"]["hello"].is_null() {
        assert_eq!(
            station_ranges,
            Some(ranges_of(&step["expect"]["hello"])),
            "{id} step {i}"
        );
    }
}

/// A station a client holds before any challenge: enough to read a refusal.
fn any_station() -> Station {
    Station {
        node_id: [0; 32],
        identity_key: Vec::new(),
        tls_binding: SignedTbs {
            tbs: Vec::new(),
            signature: Vec::new(),
        },
        status_expires_at: 0,
        binding_not_after: 0,
        version: VERSION,
        profile: Profile::PqPure,
        nonce: Vec::new(),
        leaf: Vec::new(),
        exporter_value: Vec::new(),
        challenge: Vec::new(),
        connect: Vec::new(),
        client_node_id: [0; 32],
    }
}

/// The CONNECT key the transcript's client carries, from its CONNECT, or the
/// vectors' fixed CONNECT key when it sends none.
fn connect_key_of(c: &Case) -> Vec<u8> {
    let steps = c.input["steps"].as_array().unwrap();
    steps
        .iter()
        .filter_map(|step| decode(&hex_of(&step["frame"]), "connect", &[CONNECT_KEYS]).ok())
        .map(|f| f.bytes("connect_key").to_vec())
        .next()
        .unwrap_or_else(|| wire_vectors::key(&c.profile, "client_connect"))
}

/// One transcript, replayed.
struct Replay<'c> {
    case: &'c Case,
    profile: Profile,
    client: Side,
    station: Side,
    leaf: Vec<u8>,
    exporter: Arc<Exporter>,
    negotiated: Option<Negotiated>,
    challenge: Option<Vec<u8>>,
    read: Option<Station>,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl<'c> Replay<'c> {
    fn new(case: &'c Case) -> Replay<'c> {
        let e = hex_of(&case.input["tls"]["exporter"]);
        Replay {
            case,
            profile: Profile::parse(&case.profile).unwrap(),
            client: side_of(&case.input["client"]),
            station: side_of(&case.input["station"]),
            leaf: hex_of(&case.input["tls"]["leaf_der"]),
            exporter: Arc::new(move |_: &str, _: &[u8], _: usize| Some(e.clone())),
            negotiated: None,
            challenge: None,
            read: None,
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn now(&self) -> i64 {
        self.case.int("now_ms").unwrap()
    }

    fn step(&mut self, i: usize, step: &Json) {
        let frame = hex_of(&step["frame"]);
        let id = &self.case.id;
        let is_hello = decode(&frame, "hello", &[HELLO_EARLY_KEYS]).is_ok()
            || matches!(cbor::decode(&frame), Ok(v) if v.get("frame_type") == Some(&Value::text("hello")));
        match step["from"].as_str().unwrap() {
            "client" if i == 0 => {
                let (read, hello) = read_opener(&frame, &self.station.ranges);
                want(step, id, i, verdict(&read));
                want_hello(step, id, i, hello.as_deref());
                self.negotiated = read.ok();
            }
            "client" => self.connect(i, step, &frame),
            "station" if self.challenge.is_none() && !is_hello => self.challenge(i, step, frame),
            _ => {
                let mut station = self.read.clone().unwrap_or_else(any_station);
                station.connect = self.connect_sent().unwrap_or_default();
                let read = read_hello(&frame, &station);
                want(step, id, i, verdict(&read));
                self.want_station_ranges(step, &read, i);
                self.want_session_proof_message(step, i);
            }
        }
    }

    fn challenge(&mut self, i: usize, step: &Json, frame: Vec<u8>) {
        let identity_key = wire_vectors::key(&self.case.profile, "client_identity");
        let connect_public = connect_key_of(self.case);
        let floor = floor_of(&self.client);
        let read = read_challenge(
            &frame,
            &ChallengeCheck {
                profile: self.profile,
                expected_node_id: self.client.expected,
                leaf: &self.leaf,
                identity_key: &identity_key,
                connect_public: &connect_public,
                now_ms: self.now(),
                ranges: &self.client.ranges,
                floor: floor.as_ref(),
                export: self.exporter.as_ref(),
            },
        );
        want(step, &self.case.id, i, verdict(&read));
        self.read = read.ok();
        self.challenge = Some(frame);
    }

    fn connect(&mut self, i: usize, step: &Json, frame: &[u8]) {
        let captured = self.captured.clone();
        let size = signature_size(self.profile);
        let session = StationSession {
            profile: self.profile,
            negotiated: self.negotiated.clone().unwrap(),
            challenge: self.challenge.clone().unwrap(),
            leaf: self.leaf.clone(),
            puzzle_difficulty: self.station.puzzle.0,
            puzzle_mode: self.station.puzzle.1,
            capabilities: self.station.capabilities,
            now_ms: self.now(),
            floor: floor_of(&self.station),
            export: self.exporter.clone(),
            sign_session_proof: Arc::new(move |_: &[u8; 32], message: &[u8]| {
                *captured.lock().unwrap() = message.to_vec();
                Ok(vec![0; size])
            }),
        };
        let (read, hello) = accept_connect(frame, &session);
        want(step, &self.case.id, i, verdict(&read));
        want_hello(step, &self.case.id, i, Some(&hello));
        let (Some(message), Some(station)) = (step["proof_message"].as_str(), &self.read) else {
            return;
        };
        let tbs = frame_tbs(frame, "proof").unwrap();
        assert_eq!(
            hex::encode(station.proof_message(&tbs)),
            message,
            "{} step {i}",
            self.case.id
        );
    }

    /// The CONNECT the client sent in this transcript, when it sent one.
    fn connect_sent(&self) -> Option<Vec<u8>> {
        let steps = self.case.input["steps"].as_array().unwrap();
        steps
            .iter()
            .map(|step| hex_of(&step["frame"]))
            .find(|frame| decode(frame, "connect", &[CONNECT_KEYS]).is_ok())
    }

    /// The session proof message the station side signed, as the transcript
    /// has it.
    fn want_session_proof_message(&self, step: &Json, i: usize) {
        let Some(message) = step["session_proof_message"].as_str() else {
            return;
        };
        let captured = self.captured.lock().unwrap().clone();
        assert_eq!(
            hex::encode(captured),
            message,
            "{} step {i}: session proof",
            self.case.id
        );
    }

    fn want_station_ranges(&self, step: &Json, read: &Result<u64, HandshakeError>, i: usize) {
        let named = &step["expect"]["station_ranges"];
        if named.is_null() {
            return;
        }
        let Err(HandshakeError::Refused { station_ranges, .. }) = read else {
            panic!("{} step {i}: {read:?}", self.case.id);
        };
        assert_eq!(
            station_ranges.as_ref(),
            Some(&ranges_of(named)),
            "{} step {i}",
            self.case.id
        );
    }
}

#[test]
fn the_wire_1_0_handshake_vectors() {
    let file = wire_vectors::load("handshake");
    for c in &file.cases {
        let mut replay = Replay::new(c);
        for (i, step) in c.input["steps"].as_array().unwrap().iter().enumerate() {
            replay.step(i, step);
        }
    }
    assert_eq!(file.cases.len(), 50);
}

/// HELLO's refusal_code from the enum vectors: a per-hop enum, so a code this
/// crate does not know reads as not_accepted, counted.
#[test]
fn the_wire_1_0_refusal_code_vectors() {
    let file = wire_vectors::load("enums");
    let cases: Vec<&Case> = file
        .cases
        .iter()
        .filter(|c| c.expect_text("field") == "refusal_code")
        .collect();
    let fallbacks = || {
        let counts = crate::frame::wire_counters();
        counts
            .enum_fallback
            .get("refusal_code")
            .copied()
            .unwrap_or(0)
    };
    for c in &cases {
        let before = fallbacks();
        let read = read_hello(&c.hex("frame"), &any_station());
        let Err(HandshakeError::Refused { code, .. }) = read else {
            panic!("{}: {read:?}", c.id);
        };
        assert_eq!(code.name(), c.expect_text("value"), "{}", c.id);
        let counted = fallbacks() > before;
        assert_eq!(
            counted,
            c.expect_text("count") == "wire_enum_fallback",
            "{}",
            c.id
        );
    }
    assert_eq!(cases.len(), 2);
}
