//! macula 12's version-4 handshake: opener, challenge, CONNECT, HELLO and
//! status frames. Held to the frames macula itself made
//! (tests/vectors/handshake/erlang_handshake.json, macula_handshake at macula
//! v12.1.0) both ways, then driven end to end between this crate's client and
//! station halves, and refused where macula refuses.

use macula_rust::binding::{
    connect_binding, status_statement, tls_binding, BindingError, SignedTbs,
};
use macula_rust::cbor::{self, Value};
use macula_rust::handshake::{
    accept_connect, answer_challenge, challenge, opener, read_hello, read_opener, read_status,
    status_frame, ClientSession, HandshakeError, Peer, PuzzleMode, PuzzleResult, RefusalCode,
    StationMaterial, StationSession,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// A client's identity key, CONNECT key, binding and status statement.
struct ClientKeys {
    identity: NodeKey,
    connect: NodeKey,
    binding: SignedTbs,
    status: SignedTbs,
}

fn client_keys(profile: Profile, now: i64) -> ClientKeys {
    let identity = NodeKey::generate_identity(profile, 0).unwrap();
    let connect = NodeKey::generate(Purpose::Connect, profile).unwrap();
    let binding = connect_binding(&identity, &connect.public_key(), now, now + DAY_MS).unwrap();
    let status = status_statement(&identity, &binding, now, now + HOUR_MS).unwrap();
    ClientKeys {
        identity,
        connect,
        binding,
        status,
    }
}

fn session<'a>(
    keys: &'a ClientKeys,
    profile: Profile,
    expected: [u8; 32],
    leaf: &'a [u8],
    now: i64,
) -> ClientSession<'a> {
    ClientSession {
        profile,
        expected_node_id: expected,
        leaf,
        identity_key: keys.identity.public_key(),
        connect_key: &keys.connect,
        connect_binding: &keys.binding,
        connect_status: &keys.status,
        capabilities: 3,
        now_ms: now,
        member_endorsement: Vec::new(),
    }
}

/// A station: its identity key, and the material it challenges with for
/// `leaf`.
fn station(profile: Profile, leaf: &[u8], now: i64) -> (NodeKey, StationMaterial) {
    let identity = NodeKey::generate_identity(profile, 0).unwrap();
    let binding = tls_binding(&identity, leaf, now, now + DAY_MS).unwrap();
    let status = status_statement(&identity, &binding, now, now + HOUR_MS).unwrap();
    let material = StationMaterial {
        profile,
        identity_key: identity.public_key(),
        tls_binding: binding,
        tls_status: status,
    };
    (identity, material)
}

fn station_session(profile: Profile, challenge: &[u8], leaf: &[u8], now: i64) -> StationSession {
    StationSession {
        profile,
        challenge: challenge.to_vec(),
        leaf: leaf.to_vec(),
        puzzle_difficulty: 0,
        puzzle_mode: PuzzleMode::Enforce,
        capabilities: 5,
        now_ms: now,
    }
}

/// One profile's frames: a challenge macula made as a station, its node_id,
/// and a CONNECT macula made answering a challenge macula-go made.
struct ErlangEntry {
    profile: Profile,
    erlang_challenge: Vec<u8>,
    station_node_id: [u8; 32],
    go_challenge: Vec<u8>,
    erlang_connect: Vec<u8>,
}

struct Erlang {
    now: i64,
    leaf: Vec<u8>,
    entries: Vec<ErlangEntry>,
}

fn erlang() -> Erlang {
    let text = std::fs::read_to_string("tests/vectors/handshake/erlang_handshake.json").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_owned();
    let entries: Vec<_> = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| ErlangEntry {
            profile: Profile::parse(&s(&e["profile"])).unwrap(),
            erlang_challenge: unhex(&s(&e["erlang_challenge"])),
            station_node_id: unhex(&s(&e["erlang_station_node_id"])).try_into().unwrap(),
            go_challenge: unhex(&s(&e["go_challenge"])),
            erlang_connect: unhex(&s(&e["erlang_connect"])),
        })
        .collect();
    assert_eq!(entries.len(), 2);
    Erlang {
        now: doc["now"].as_i64().unwrap(),
        leaf: unhex(&s(&doc["leaf"])),
        entries,
    }
}

#[test]
fn a_challenge_macula_made_is_answered() {
    let h = erlang();
    for e in &h.entries {
        let keys = client_keys(e.profile, h.now);
        let (connect, station) = answer_challenge(
            &e.erlang_challenge,
            &session(&keys, e.profile, e.station_node_id, &h.leaf, h.now + 60_000),
        )
        .unwrap();
        assert_eq!(station.node_id, e.station_node_id, "{:?}", e.profile);
        assert!(!connect.is_empty());
    }
}

#[test]
fn a_connect_macula_made_is_accepted() {
    let h = erlang();
    for e in &h.entries {
        let (accepted, hello) = accept_connect(
            &e.erlang_connect,
            &station_session(e.profile, &e.go_challenge, &h.leaf, h.now + 60_000),
        );
        let client = accepted.unwrap();
        assert_eq!(read_hello(&hello).unwrap(), 5, "{:?}", e.profile);
        assert!(client.member_endorsement.is_empty());
    }
}

#[test]
fn a_client_and_a_station_complete_the_handshake_and_renew_status() {
    let now = 1_789_000_000_000;
    let leaf = b"the leaf this connection presents".to_vec();
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let first = opener();
        read_opener(&first).unwrap();
        let (station_key, material) = station(profile, &leaf, now);
        let challenge_frame = challenge(&material).unwrap();
        let keys = client_keys(profile, now);
        let (connect, seen) = answer_challenge(
            &challenge_frame,
            &session(&keys, profile, station_key.node_id().unwrap(), &leaf, now),
        )
        .unwrap();
        assert_eq!(seen.status_expires_at, now + HOUR_MS);
        let (accepted, hello) = accept_connect(
            &connect,
            &station_session(profile, &challenge_frame, &leaf, now),
        );
        let client = accepted.unwrap();
        assert_eq!(client.node_id, keys.identity.node_id().unwrap());
        assert_eq!(client.capabilities, 3);
        assert_eq!(client.puzzle, PuzzleResult::Solved);
        assert_eq!(read_hello(&hello).unwrap(), 5);

        // A renewed statement on the open connection.
        let renewed = status_statement(
            &station_key,
            &material.tls_binding,
            now + 900_000,
            now + 900_000 + HOUR_MS,
        )
        .unwrap();
        let peer = Peer {
            profile,
            identity_key: material.identity_key.clone(),
            binding: material.tls_binding.clone(),
            now_ms: now + 900_000,
        };
        assert_eq!(
            read_status(&status_frame(&renewed), &peer).unwrap(),
            now + 900_000 + HOUR_MS
        );
    }
}

#[test]
fn a_station_that_is_not_the_node_dialed_is_refused_before_anything_is_signed() {
    let now = 1_789_000_000_000;
    let leaf = b"leaf".to_vec();
    let (station_key, material) = station(Profile::PqPure, &leaf, now);
    let keys = client_keys(Profile::PqPure, now);
    let dialed = [9u8; 32];
    match answer_challenge(
        &challenge(&material).unwrap(),
        &session(&keys, Profile::PqPure, dialed, &leaf, now),
    ) {
        Err(HandshakeError::PeerIdentityMismatch { expected, derived }) => {
            assert_eq!(expected, dialed);
            assert_eq!(derived, station_key.node_id().unwrap());
        }
        other => panic!("{:?}", other.map(|(c, _)| c.len())),
    }
}

#[test]
fn a_challenge_for_another_leaf_or_profile_is_refused() {
    let now = 1_789_000_000_000;
    let (station_key, material) = station(Profile::PqPure, b"the real leaf", now);
    let frame = challenge(&material).unwrap();
    let keys = client_keys(Profile::PqPure, now);
    let expected = station_key.node_id().unwrap();
    assert_eq!(
        answer_challenge(
            &frame,
            &session(&keys, Profile::PqPure, expected, b"another leaf", now)
        )
        .unwrap_err(),
        HandshakeError::Binding(BindingError::KeyMismatch)
    );
    let hybrid = client_keys(Profile::PqHybrid, now);
    assert_eq!(
        answer_challenge(
            &frame,
            &session(&hybrid, Profile::PqHybrid, expected, b"the real leaf", now)
        )
        .unwrap_err(),
        HandshakeError::ProfileMismatch
    );
}

#[test]
fn a_connect_key_that_is_the_identity_key_is_refused() {
    let now = 1_789_000_000_000;
    let leaf = b"leaf".to_vec();
    let (station_key, material) = station(Profile::PqPure, &leaf, now);
    let identity = NodeKey::generate_identity(Profile::PqPure, 0).unwrap();
    // The identity key's own halves, as a CONNECT key: its key file with the
    // purpose byte after the magic changed to connect.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    identity.save(&path).unwrap();
    let mut file = std::fs::read(&path).unwrap();
    file[b"macula-node-key-seed-v1\0".len()] = 2;
    std::fs::write(&path, &file).unwrap();
    let same = NodeKey::load(&path, Purpose::Connect, Profile::PqPure).unwrap();
    let binding = connect_binding(&identity, &same.public_key(), now, now + DAY_MS).unwrap();
    let status = status_statement(&identity, &binding, now, now + HOUR_MS).unwrap();
    let keys = ClientKeys {
        identity,
        connect: same,
        binding,
        status,
    };
    assert_eq!(
        answer_challenge(
            &challenge(&material).unwrap(),
            &session(
                &keys,
                Profile::PqPure,
                station_key.node_id().unwrap(),
                &leaf,
                now
            )
        )
        .unwrap_err(),
        HandshakeError::KeyPurposeReuse
    );
}

#[test]
fn a_station_refuses_with_one_coarse_code() {
    let now = 1_789_000_000_000;
    let leaf = b"leaf".to_vec();
    let (station_key, material) = station(Profile::PqPure, &leaf, now);
    let frame = challenge(&material).unwrap();
    let keys = client_keys(Profile::PqPure, now);
    let (connect, _) = answer_challenge(
        &frame,
        &session(
            &keys,
            Profile::PqPure,
            station_key.node_id().unwrap(),
            &leaf,
            now,
        ),
    )
    .unwrap();

    // The proof covers the leaf: presented another one, the station refuses.
    let (refused, hello) = accept_connect(
        &connect,
        &station_session(Profile::PqPure, &frame, b"other", now),
    );
    assert_eq!(refused.unwrap_err(), HandshakeError::ProofInvalid);
    assert_eq!(
        read_hello(&hello).unwrap_err(),
        HandshakeError::Refused(RefusalCode::NotAccepted)
    );

    // A node_id that misses an enforced puzzle.
    let mut hard = station_session(Profile::PqPure, &frame, &leaf, now);
    hard.puzzle_difficulty = 256;
    let (refused, hello) = accept_connect(&connect, &hard);
    assert_eq!(refused.unwrap_err(), HandshakeError::PuzzleInvalid);
    assert_eq!(
        read_hello(&hello).unwrap_err(),
        HandshakeError::Refused(RefusalCode::PuzzleInvalid)
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
    let first = opener();
    let v3 = rewritten(&first, |p| {
        for (k, v) in p.iter_mut() {
            if *k == Value::text("version") {
                *v = Value::Int(3);
            }
        }
    });
    assert_eq!(
        read_opener(&v3).unwrap_err(),
        HandshakeError::UnsupportedVersion
    );
    let extra = rewritten(&first, |p| p.push((Value::text("more"), Value::Int(1))));
    assert_eq!(read_opener(&extra).unwrap_err(), HandshakeError::Malformed);
    assert_eq!(
        read_hello(&first).unwrap_err(),
        HandshakeError::UnexpectedFrame
    );
    assert_eq!(read_opener(b"\xff").unwrap_err(), HandshakeError::Malformed);
}
