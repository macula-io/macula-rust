//! The wire 1.0 handshake through the crate's public API, between its client
//! and station halves: a whole handshake and a status renewal, and the
//! refusals each side reaches before it signs anything, with the one coarse
//! code a refusing HELLO carries. The transcripts every stack shares are
//! the handshake class of the wire 1.0 vectors (src/handshake/
//! wire_1_0_tests.rs).

use std::sync::Arc;

use macula_rust::binding::{
    connect_binding, status_statement, tls_binding, BindingError, SignedTbs,
};
use macula_rust::cbor::{self, Value};
use macula_rust::handshake::{
    accept_connect, answer_challenge, challenge, opener, read_hello, read_opener, read_status,
    status_frame, ClientSession, Exporter, Floor, HandshakeError, Negotiated, Peer, PuzzleMode,
    PuzzleResult, Ranges, RefusalCode, StationMaterial, StationSession,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

const NOW: i64 = 1_789_000_000_000;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const LEAF: &[u8] = b"the leaf this connection presents";

/// A client's identity key, CONNECT key, binding and status statement.
struct ClientKeys {
    identity: NodeKey,
    connect: NodeKey,
    binding: SignedTbs,
    status: SignedTbs,
}

fn client_keys(profile: Profile) -> ClientKeys {
    let identity = NodeKey::generate_identity(profile, 0).unwrap();
    let connect = NodeKey::generate(Purpose::Connect, profile).unwrap();
    let binding = connect_binding(&identity, &connect.public_key(), NOW, NOW + DAY_MS).unwrap();
    let status = status_statement(&identity, &binding, NOW, NOW + HOUR_MS).unwrap();
    ClientKeys {
        identity,
        connect,
        binding,
        status,
    }
}

/// Both ends of one TLS session export the same 32 bytes.
fn export() -> Arc<Exporter> {
    Arc::new(|_: &str, _: &[u8], length: usize| Some(vec![0x5E; length]))
}

fn no_floor() -> Arc<Floor> {
    Arc::new(|_: &[u8; 32]| 0)
}

/// A station: its identity key, and the material it challenges with for
/// `leaf`.
fn station(profile: Profile, leaf: &[u8]) -> (Arc<NodeKey>, StationMaterial) {
    let identity = Arc::new(NodeKey::generate_identity(profile, 0).unwrap());
    let binding = tls_binding(&identity, leaf, NOW, NOW + DAY_MS).unwrap();
    let status = status_statement(&identity, &binding, NOW, NOW + HOUR_MS).unwrap();
    let material = StationMaterial {
        profile,
        identity_key: identity.public_key(),
        tls_binding: binding,
        tls_status: status,
    };
    (identity, material)
}

/// One run: a station, a client, what the station chose and the challenge it
/// sent.
struct Run {
    profile: Profile,
    station_key: Arc<NodeKey>,
    material: StationMaterial,
    keys: ClientKeys,
    negotiated: Negotiated,
    challenge: Vec<u8>,
    export: Arc<Exporter>,
    floor: Arc<Floor>,
}

fn run(profile: Profile) -> Run {
    let (station_key, material) = station(profile, LEAF);
    let ranges = Ranges::supported(profile);
    let (negotiated, hello) = read_opener(&opener(&ranges), &ranges);
    assert_eq!(hello, None);
    let negotiated = negotiated.unwrap();
    let challenge = challenge(&material, &negotiated, &ranges).unwrap();
    Run {
        profile,
        station_key,
        material,
        keys: client_keys(profile),
        negotiated,
        challenge,
        export: export(),
        floor: no_floor(),
    }
}

impl Run {
    fn session<'a>(&'a self, expected: [u8; 32], leaf: &'a [u8]) -> ClientSession<'a> {
        ClientSession {
            profile: self.profile,
            expected_node_id: expected,
            leaf,
            identity_key: self.keys.identity.public_key(),
            connect_key: &self.keys.connect,
            connect_binding: &self.keys.binding,
            connect_status: &self.keys.status,
            capabilities: 3,
            now_ms: NOW,
            member_endorsement: Vec::new(),
            ranges: Ranges::supported(self.profile),
            floor: self.floor.as_ref(),
            export: self.export.as_ref(),
        }
    }

    fn dialed(&self) -> [u8; 32] {
        self.station_key.node_id().unwrap()
    }

    fn station_session(&self, leaf: &[u8]) -> StationSession {
        let key = self.station_key.clone();
        StationSession {
            profile: self.profile,
            negotiated: self.negotiated.clone(),
            challenge: self.challenge.clone(),
            leaf: leaf.to_vec(),
            puzzle_difficulty: 0,
            puzzle_mode: PuzzleMode::Enforce,
            capabilities: 5,
            now_ms: NOW,
            floor: no_floor(),
            export: self.export.clone(),
            sign_session_proof: Arc::new(move |_: &[u8; 32], message: &[u8]| {
                key.sign(message).map_err(HandshakeError::Key)
            }),
        }
    }
}

#[test]
fn a_client_and_a_station_complete_the_handshake_and_renew_status() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let r = run(profile);
        let (connect, seen) = answer_challenge(&r.challenge, &r.session(r.dialed(), LEAF)).unwrap();
        assert_eq!(seen.status_expires_at, NOW + HOUR_MS);
        let (accepted, hello) = accept_connect(&connect, &r.station_session(LEAF));
        let client = accepted.unwrap();
        assert_eq!(client.node_id, r.keys.identity.node_id().unwrap());
        assert_eq!(client.capabilities, 3);
        assert_eq!(client.puzzle, PuzzleResult::Solved);
        assert_eq!(read_hello(&hello, &seen).unwrap(), 5);

        // A renewed statement on the open connection.
        let later = NOW + 900_000;
        let renewed = status_statement(
            &r.station_key,
            &r.material.tls_binding,
            later,
            later + HOUR_MS,
        )
        .unwrap();
        let peer = Peer {
            profile,
            identity_key: r.material.identity_key.clone(),
            binding: r.material.tls_binding.clone(),
            now_ms: later,
        };
        assert_eq!(
            read_status(&status_frame(&renewed), &peer).unwrap(),
            later + HOUR_MS
        );
    }
}

#[test]
fn a_station_that_is_not_the_node_dialed_is_refused_before_anything_is_signed() {
    let r = run(Profile::PqPure);
    let dialed = [9u8; 32];
    match answer_challenge(&r.challenge, &r.session(dialed, LEAF)) {
        Err(HandshakeError::PeerIdentityMismatch { expected, derived }) => {
            assert_eq!(expected, dialed);
            assert_eq!(derived, r.dialed());
        }
        other => panic!("{:?}", other.map(|(c, _)| c.len())),
    }
}

#[test]
fn a_challenge_for_another_leaf_or_profile_is_refused() {
    let r = run(Profile::PqPure);
    assert_eq!(
        answer_challenge(&r.challenge, &r.session(r.dialed(), b"another leaf")).unwrap_err(),
        HandshakeError::Binding(BindingError::KeyMismatch)
    );
    let mut hybrid = r.session(r.dialed(), LEAF);
    hybrid.profile = Profile::PqHybrid;
    hybrid.ranges = Ranges::supported(Profile::PqHybrid);
    assert_eq!(
        answer_challenge(&r.challenge, &hybrid).unwrap_err(),
        HandshakeError::DowngradeDetected
    );
}

#[test]
fn a_connect_key_that_is_the_identity_key_is_refused() {
    let mut r = run(Profile::PqPure);
    // The identity key's own halves, as a CONNECT key: its key file with the
    // purpose byte after the magic changed to connect.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    r.keys.identity.save(&path).unwrap();
    let mut file = std::fs::read(&path).unwrap();
    file[b"macula-node-key-seed-v1\0".len()] = 2;
    std::fs::write(&path, &file).unwrap();
    let same = NodeKey::load(&path, Purpose::Connect, Profile::PqPure).unwrap();
    r.keys.binding =
        connect_binding(&r.keys.identity, &same.public_key(), NOW, NOW + DAY_MS).unwrap();
    r.keys.status =
        status_statement(&r.keys.identity, &r.keys.binding, NOW, NOW + HOUR_MS).unwrap();
    r.keys.connect = same;
    assert_eq!(
        answer_challenge(&r.challenge, &r.session(r.dialed(), LEAF)).unwrap_err(),
        HandshakeError::KeyPurposeReuse
    );
}

#[test]
fn a_station_refuses_with_one_coarse_code() {
    let r = run(Profile::PqPure);
    let (connect, seen) = answer_challenge(&r.challenge, &r.session(r.dialed(), LEAF)).unwrap();
    let refused = |code| HandshakeError::Refused {
        code,
        station_ranges: None,
    };

    // The proof covers the leaf: presented another one, the station refuses.
    let (verdict, hello) = accept_connect(&connect, &r.station_session(b"other"));
    assert_eq!(verdict.unwrap_err(), HandshakeError::ProofInvalid);
    assert_eq!(
        read_hello(&hello, &seen).unwrap_err(),
        refused(RefusalCode::NotAccepted)
    );

    // A node_id that misses an enforced puzzle.
    let mut hard = r.station_session(LEAF);
    hard.puzzle_difficulty = 256;
    let (verdict, hello) = accept_connect(&connect, &hard);
    assert_eq!(verdict.unwrap_err(), HandshakeError::PuzzleInvalid);
    assert_eq!(
        read_hello(&hello, &seen).unwrap_err(),
        refused(RefusalCode::PuzzleInvalid)
    );

    // Logged, not enforced: accepted, and reported unsolved.
    hard.puzzle_mode = PuzzleMode::LogOnly;
    let (accepted, _) = accept_connect(&connect, &hard);
    assert_eq!(accepted.unwrap().puzzle, PuzzleResult::Unsolved);
}

/// A frame rewritten: `f` edits its decoded map, and the result is
/// re-encoded.
fn rewritten(frame: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let Value::Map(mut pairs) = cbor::decode(frame).unwrap() else {
        panic!("a frame is a map")
    };
    f(&mut pairs);
    cbor::encode(&Value::Map(pairs)).unwrap()
}

#[test]
fn a_frame_is_read_strictly_in_macula_s_order() {
    let ranges = Ranges::supported(Profile::PqPure);
    let first = opener(&ranges);
    let v4 = rewritten(&first, |p| {
        p.retain(|(k, _)| *k != Value::text("version"));
        p.push((Value::text("version"), Value::Int(4)));
    });
    assert_eq!(
        read_opener(&v4, &ranges).0.unwrap_err(),
        HandshakeError::UnsupportedVersion
    );
    let extra = rewritten(&first, |p| p.push((Value::text("more"), Value::Int(1))));
    assert_eq!(
        read_opener(&extra, &ranges).0.unwrap_err(),
        HandshakeError::Malformed
    );
    let r = run(Profile::PqPure);
    let (_, seen) = answer_challenge(&r.challenge, &r.session(r.dialed(), LEAF)).unwrap();
    assert_eq!(
        read_hello(&first, &seen).unwrap_err(),
        HandshakeError::UnexpectedFrame
    );
    assert_eq!(
        read_opener(b"\xff", &ranges).0.unwrap_err(),
        HandshakeError::Malformed
    );
}
