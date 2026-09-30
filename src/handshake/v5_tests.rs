//! Handshake v5 (macula 13.2, DESIGN_NEIGHBOUR_CHANNEL_BINDING), as macula-go's
//! handshake/v5_test.go holds it, and against the v5 frames macula itself made
//! (tests/vectors/handshake/erlang_handshake.json, macula 8b8bb80a). A TLS
//! exporter cannot travel in a file, so every stack uses one stand-in:
//! HMAC-SHA256 keyed by the session's name, over the label and the context.

use std::sync::Arc;

use aws_lc_rs::hmac;
use sha2::{Digest, Sha384};

use super::*;
use crate::binding::{connect_binding, status_statement, tls_binding};
use crate::node_key::Purpose;

const NOW: i64 = 1_789_000_000_000;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const CLIENT_CAPABILITIES: u64 = 3;
const STATION_CAPABILITIES: u64 = 5;
const LEAF: &[u8] = b"the leaf this connection presents";
const MLDSA_SIGNATURE_BYTES: usize = 4627;

/// The exporter stand-in both stacks share: the same session, label and
/// context give the same bytes.
fn exported(session: &str, context: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, session.as_bytes());
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(EXPORTER_LABEL.as_bytes());
    ctx.update(context);
    ctx.sign().as_ref().to_vec()
}

fn exporter_of(session: &'static str) -> Arc<Exporter> {
    Arc::new(move |label: &str, context: &[u8], length: usize| {
        (label == EXPORTER_LABEL).then(|| exported(session, context)[..length].to_vec())
    })
}

/// One profile's station and client keys, and what they hand the handshake.
struct World {
    profile: Profile,
    station: Arc<NodeKey>,
    material: StationMaterial,
    client: NodeKey,
    connect: NodeKey,
    binding: SignedTbs,
    status: SignedTbs,
    export: Arc<Exporter>,
}

fn world(profile: Profile) -> World {
    let station = Arc::new(NodeKey::generate_identity(profile, 0).unwrap());
    let tls = tls_binding(&station, LEAF, NOW, NOW + DAY_MS).unwrap();
    let tls_status = status_statement(&station, &tls, NOW, NOW + HOUR_MS).unwrap();
    let material = StationMaterial {
        profile,
        identity_key: station.public_key(),
        tls_binding: tls,
        tls_status,
    };
    let client = NodeKey::generate_identity(profile, 0).unwrap();
    let connect = NodeKey::generate(Purpose::Connect, profile).unwrap();
    let binding = connect_binding(&client, &connect.public_key(), NOW, NOW + DAY_MS).unwrap();
    let status = status_statement(&client, &binding, NOW, NOW + HOUR_MS).unwrap();
    World {
        profile,
        station,
        material,
        client,
        connect,
        binding,
        status,
        export: exporter_of("session_a"),
    }
}

impl World {
    fn client_session(&self, version: i64) -> ClientSession<'_> {
        ClientSession {
            profile: self.profile,
            expected_node_id: self.station.node_id().unwrap(),
            leaf: LEAF,
            identity_key: self.client.public_key(),
            connect_key: &self.connect,
            connect_binding: &self.binding,
            connect_status: &self.status,
            capabilities: CLIENT_CAPABILITIES,
            now_ms: NOW,
            member_endorsement: Vec::new(),
            version,
            export: Some(self.export.as_ref()),
        }
    }

    fn station_session(&self, challenge: &[u8]) -> StationSession {
        StationSession {
            profile: self.profile,
            challenge: challenge.to_vec(),
            leaf: LEAF.to_vec(),
            puzzle_difficulty: 0,
            puzzle_mode: PuzzleMode::Enforce,
            capabilities: STATION_CAPABILITIES,
            now_ms: NOW,
            v5: None,
        }
    }

    fn station_session_v5(&self, challenge: &[u8]) -> StationSession {
        let key = self.station.clone();
        StationSession {
            v5: Some(StationV5 {
                export: exporter_of("session_a"),
                sign_session_proof: Arc::new(move |_client: &[u8; 32], message: &[u8]| {
                    key.sign(message).map_err(HandshakeError::Key)
                }),
            }),
            ..self.station_session(challenge)
        }
    }

    fn ids(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.station.node_id().unwrap(),
            self.client.node_id().unwrap(),
        )
    }

    /// The session proof's message for this challenge and CONNECT under
    /// `session`'s exporter, as the station signs it.
    fn session_message(&self, challenge: &[u8], connect: &[u8], session: &str) -> Vec<u8> {
        let (station_id, client_id) = self.ids();
        [
            b"MACULA-PQ-SESSION-PROOF-V1".as_slice(),
            &[0],
            &exported(session, &[client_id, station_id].concat()),
            &Sha384::digest(challenge),
            &Sha384::digest(connect),
            &station_id,
            &client_id,
            &STATION_CAPABILITIES.to_be_bytes(),
        ]
        .concat()
    }

    /// A whole v5 handshake: challenge, CONNECT, what the client knows of
    /// the station, the accepted client, and HELLO.
    fn v5_pair(&self) -> (Vec<u8>, Vec<u8>, Station, Client, Vec<u8>) {
        let challenge = challenge(&self.material).unwrap();
        let (connect, station) =
            answer_challenge(&challenge, &self.client_session(VERSION_5)).unwrap();
        let (client, hello) = accept_connect(&connect, &self.station_session_v5(&challenge));
        (challenge, connect, station, client.unwrap(), hello)
    }
}

fn worlds() -> Vec<World> {
    vec![world(Profile::PqPure), world(Profile::PqHybrid)]
}

fn field(frame: &[u8], key: &str) -> Option<Value> {
    cbor::decode(frame).unwrap().get(key).cloned()
}

fn frame_version(frame: &[u8]) -> Option<Value> {
    field(frame, "version")
}

fn frame_keys(frame: &[u8]) -> Vec<String> {
    let Value::Map(pairs) = cbor::decode(frame).unwrap() else {
        panic!("a frame is a map");
    };
    let mut keys: Vec<String> = pairs
        .into_iter()
        .map(|(k, _)| match k {
            Value::Text(t) => t,
            other => panic!("a key that is not text: {other:?}"),
        })
        .collect();
    keys.sort();
    keys
}

/// `frame` with `key` set to `value`, or without it for `None`.
fn rebuilt(frame: &[u8], key: &str, value: Option<Value>) -> Vec<u8> {
    let Value::Map(mut pairs) = cbor::decode(frame).unwrap() else {
        panic!("a frame is a map");
    };
    pairs.retain(|(k, _)| *k != Value::text(key));
    if let Some(v) = value {
        pairs.push((Value::text(key), v));
    }
    cbor::encode(&Value::Map(pairs)).unwrap()
}

/// What a client that sent a v5 CONNECT to no station in particular knows:
/// only the version, which is all a refusal or a v4 HELLO is read against.
fn any_station(version: i64, profile: Profile) -> Station {
    Station {
        node_id: [0; 32],
        identity_key: Vec::new(),
        tls_binding: SignedTbs {
            tbs: Vec::new(),
            signature: Vec::new(),
        },
        status_expires_at: 0,
        binding_not_after: 0,
        version,
        profile,
        exporter_value: Vec::new(),
        challenge: Vec::new(),
        connect: Vec::new(),
        client_node_id: [0; 32],
    }
}

#[test]
fn a_whole_v5_handshake_connects_both_sides() {
    for w in worlds() {
        let (challenge, connect, station, client, hello) = w.v5_pair();
        let four = Some(Value::Int(4));
        let five = Some(Value::Int(5));
        assert_eq!(
            frame_version(&opener()),
            four,
            "the client picks the version in CONNECT"
        );
        assert_eq!(frame_version(&challenge), four);
        assert_eq!(frame_version(&connect), five);
        assert_eq!(frame_version(&hello), five);
        assert_eq!(
            frame_keys(&connect),
            CONNECT_KEYS
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>(),
            "a v5 CONNECT holds v4's keys"
        );
        assert_eq!(
            frame_keys(&hello),
            [
                "accepted",
                "capabilities",
                "frame_type",
                "session_proof",
                "version"
            ]
        );
        assert_eq!((station.version, client.version), (VERSION_5, VERSION_5));
        assert_eq!(read_hello(&hello, &station), Ok(STATION_CAPABILITIES));
    }
}

/// The V2 CONNECT proof: label || 0x00 || nonce || station node_id || client
/// node_id || SHA-384(leaf) || SHA-384(challenge) || E || client
/// capabilities, 8 bytes big-endian. The session proof: label || 0x00 || E ||
/// SHA-384(challenge) || SHA-384(CONNECT) || station node_id || client
/// node_id || station capabilities.
#[test]
fn the_v5_proofs_sign_what_the_design_says() {
    for w in worlds() {
        let (challenge, connect, _, _, hello) = w.v5_pair();
        let (station_id, client_id) = w.ids();
        let Some(Value::Bytes(nonce)) = field(&challenge, "nonce") else {
            panic!("a challenge carries its nonce");
        };
        let connect_message = [
            b"MACULA-PQ-CONNECT-PROOF-V2".as_slice(),
            &[0],
            &nonce,
            &station_id,
            &client_id,
            &Sha384::digest(LEAF),
            &Sha384::digest(&challenge),
            &exported("session_a", &[client_id, station_id].concat()),
            &CLIENT_CAPABILITIES.to_be_bytes(),
        ]
        .concat();
        let Some(Value::Bytes(proof)) = field(&connect, "proof") else {
            panic!("a CONNECT carries its proof");
        };
        assert!(verify(
            &connect_message,
            &proof,
            &w.connect.public_key(),
            w.profile
        ));
        let Some(Value::Bytes(session_proof)) = field(&hello, "session_proof") else {
            panic!("a v5 HELLO carries its session proof");
        };
        assert!(verify(
            &w.session_message(&challenge, &connect, "session_a"),
            &session_proof,
            &w.station.public_key(),
            w.profile
        ));
    }
}

#[test]
fn a_station_refuses_a_v5_connect_it_cannot_trust() {
    for w in worlds() {
        let challenge = challenge(&w.material).unwrap();
        let (connect, _) = answer_challenge(&challenge, &w.client_session(VERSION_5)).unwrap();
        let (connect_v4, _) = answer_challenge(&challenge, &w.client_session(VERSION)).unwrap();

        let mut other_session = w.station_session_v5(&challenge);
        if let Some(v5) = &mut other_session.v5 {
            v5.export = exporter_of("session_b");
        }
        let (refused, hello) = accept_connect(&connect, &other_session);
        assert_eq!(refused, Err(HandshakeError::ProofInvalid));
        assert_eq!(frame_version(&hello), Some(Value::Int(5)));

        let relabelled = rebuilt(&connect_v4, "version", Some(Value::Int(5)));
        let (refused, _) = accept_connect(&relabelled, &w.station_session_v5(&challenge));
        assert_eq!(refused, Err(HandshakeError::ProofInvalid));

        let (client, hello) = accept_connect(&connect_v4, &w.station_session_v5(&challenge));
        assert_eq!(client.unwrap().version, VERSION);
        assert_eq!(frame_version(&hello), Some(Value::Int(4)));

        // A station with no exporter answers v5 as an old station does.
        let (refused, hello) = accept_connect(&connect, &w.station_session(&challenge));
        assert_eq!(refused, Err(HandshakeError::UnsupportedVersion));
        assert_eq!(frame_version(&hello), Some(Value::Int(4)));
        assert_eq!(
            read_hello(&hello, &any_station(VERSION_5, w.profile)),
            Err(HandshakeError::Refused(RefusalCode::UnsupportedVersion))
        );

        let v6 = rebuilt(&connect, "version", Some(Value::Int(6)));
        let (refused, _) = accept_connect(&v6, &w.station_session_v5(&challenge));
        assert_eq!(refused, Err(HandshakeError::UnsupportedVersion));
    }
}

/// Sign after verify: a CONNECT that fails any check never reaches the
/// signer. Past the budget the station refuses with session_proof_rate, on
/// the wire too.
#[test]
fn a_station_signs_the_session_proof_only_after_every_check_and_within_its_budget() {
    for w in worlds() {
        let challenge = challenge(&w.material).unwrap();
        let (connect, station) =
            answer_challenge(&challenge, &w.client_session(VERSION_5)).unwrap();
        let signed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = signed.clone();
        let watched = StationSession {
            v5: Some(StationV5 {
                export: exporter_of("session_a"),
                sign_session_proof: Arc::new(move |_: &[u8; 32], _: &[u8]| {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(HandshakeError::SessionProofRate)
                }),
            }),
            ..w.station_session(&challenge)
        };
        let mut other_e = watched.clone();
        if let Some(v5) = &mut other_e.v5 {
            v5.export = exporter_of("session_b");
        }
        assert_eq!(
            accept_connect(&connect, &other_e).0,
            Err(HandshakeError::ProofInvalid)
        );
        let lapsed = StationSession {
            now_ms: NOW + 2 * HOUR_MS,
            ..watched.clone()
        };
        assert!(accept_connect(&connect, &lapsed).0.is_err());
        assert_eq!(
            signed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the signer ran for CONNECTs that failed their checks"
        );
        let (refused, hello) = accept_connect(&connect, &watched);
        assert_eq!(refused, Err(HandshakeError::SessionProofRate));
        assert_eq!(signed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            read_hello(&hello, &station),
            Err(HandshakeError::Refused(RefusalCode::SessionProofRate))
        );
    }
}

#[test]
fn a_client_refuses_a_v5_hello_that_does_not_prove_the_session() {
    for w in worlds() {
        let (challenge, connect, station, _, hello) = w.v5_pair();
        let other_key = NodeKey::generate_identity(w.profile, 0).unwrap();
        let over_other_e = w
            .station
            .sign(&w.session_message(&challenge, &connect, "session_b"))
            .unwrap();
        let by_other_key = other_key
            .sign(&w.session_message(&challenge, &connect, "session_a"))
            .unwrap();
        let (_, _, _, _, other_connection) = w.v5_pair();
        let (connect_v4, _) = answer_challenge(&challenge, &w.client_session(VERSION)).unwrap();
        let (accepted_v4, hello_v4) = accept_connect(&connect_v4, &w.station_session(&challenge));
        accepted_v4.unwrap();
        let proof = |p: Vec<u8>| rebuilt(&hello, "session_proof", Some(Value::Bytes(p)));
        for (what, frame, want) in [
            (
                "a session proof over another session's E",
                proof(over_other_e),
                HandshakeError::SessionProofInvalid,
            ),
            (
                "another connection's HELLO",
                other_connection,
                HandshakeError::SessionProofInvalid,
            ),
            (
                "a session proof by another key",
                proof(by_other_key),
                HandshakeError::SessionProofInvalid,
            ),
            (
                "no session proof",
                rebuilt(&hello, "session_proof", None),
                HandshakeError::SessionProofMissing,
            ),
            (
                "a session proof of the wrong length",
                proof(vec![0, 1]),
                HandshakeError::Malformed,
            ),
            (
                "a v4 acceptance of a v5 CONNECT",
                hello_v4,
                HandshakeError::V4HelloToV5Connect,
            ),
        ] {
            assert_eq!(read_hello(&frame, &station), Err(want), "{what}");
        }
        assert_eq!(
            read_hello(&hello, &any_station(VERSION, w.profile)),
            Err(HandshakeError::UnsupportedVersion),
            "a v5 HELLO after a v4 CONNECT"
        );
    }
}

/// The case D17 existed for: an attacker who can forge ML-DSA-87 but not
/// RSA-PSS-4096. A session proof whose ML-DSA half is the station's own,
/// valid, and whose RSA half is another key's, is refused.
#[test]
fn a_hybrid_session_proof_with_a_foreign_rsa_half_is_refused() {
    let w = world(Profile::PqHybrid);
    let (challenge, connect, station, _, hello) = w.v5_pair();
    let Some(Value::Bytes(proof)) = field(&hello, "session_proof") else {
        panic!("a v5 HELLO carries its session proof");
    };
    let other_key = NodeKey::generate_identity(Profile::PqHybrid, 0).unwrap();
    let foreign = other_key
        .sign(&w.session_message(&challenge, &connect, "session_a"))
        .unwrap();
    let spliced = [
        &proof[..MLDSA_SIGNATURE_BYTES],
        &foreign[MLDSA_SIGNATURE_BYTES..],
    ]
    .concat();
    assert_ne!(spliced, proof, "the splice changed nothing");
    let frame = rebuilt(&hello, "session_proof", Some(Value::Bytes(spliced)));
    assert_eq!(
        read_hello(&frame, &station),
        Err(HandshakeError::SessionProofInvalid)
    );
}

/// One profile's frames from the fixture macula 8b8bb80a made.
struct Fixture {
    profile: Profile,
    erlang_challenge: Vec<u8>,
    go_challenge: Vec<u8>,
    erlang_connect_v5: Vec<u8>,
    go_connect_v5: Vec<u8>,
    erlang_hello_v5: Vec<u8>,
}

fn fixture() -> (Vec<u8>, i64, Vec<Fixture>) {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/handshake/erlang_handshake.json"
    ))
    .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let entries = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| Fixture {
            profile: Profile::parse(e["profile"].as_str().unwrap()).unwrap(),
            erlang_challenge: bytes(&e["erlang_challenge"]),
            go_challenge: bytes(&e["go_challenge"]),
            erlang_connect_v5: bytes(&e["erlang_connect_v5"]),
            go_connect_v5: bytes(&e["go_connect_v5"]),
            erlang_hello_v5: bytes(&e["erlang_hello_v5"]),
        })
        .collect();
    (bytes(&doc["leaf"]), doc["now"].as_i64().unwrap(), entries)
}

/// A v5 CONNECT macula made, answering a CHALLENGE macula-go made, is
/// accepted by this station check in version 5: macula's V2 proof message,
/// exporter context and capability encoding are this crate's, byte for byte,
/// or the proof would not verify.
#[test]
fn a_v5_connect_macula_made_is_accepted() {
    let (leaf, now, entries) = fixture();
    for e in entries {
        let session = StationSession {
            profile: e.profile,
            challenge: e.go_challenge.clone(),
            leaf: leaf.clone(),
            puzzle_difficulty: 0,
            puzzle_mode: PuzzleMode::Enforce,
            capabilities: STATION_CAPABILITIES,
            now_ms: now + 60_000,
            v5: Some(StationV5 {
                export: exporter_of("session_a"),
                sign_session_proof: Arc::new(|_: &[u8; 32], _: &[u8]| Ok(b"unread".to_vec())),
            }),
        };
        let (client, hello) = accept_connect(&e.erlang_connect_v5, &session);
        assert_eq!(client.unwrap().version, VERSION_5, "{:?}", e.profile);
        assert!(!hello.is_empty());
    }
}

/// The v5 HELLO macula made for macula-go's v5 CONNECT proves the session to
/// this client check: macula's session proof message is this crate's, byte
/// for byte.
#[test]
fn a_v5_hello_macula_made_proves_the_session() {
    let (_, _, entries) = fixture();
    for e in entries {
        let challenge = decode(&e.erlang_challenge, "challenge", &[CHALLENGE_KEYS]).unwrap();
        let connect =
            decode_versioned(&e.go_connect_v5, "connect", &[VERSION_5], &[CONNECT_KEYS]).unwrap();
        let station_key = challenge.bytes("identity_key").to_vec();
        let station_id = node_id_of(&station_key, e.profile);
        let client_id = node_id_of(connect.bytes("identity_key"), e.profile);
        let station = Station {
            node_id: station_id,
            identity_key: station_key,
            exporter_value: exported("session_a", &[client_id, station_id].concat()),
            challenge: e.erlang_challenge.clone(),
            connect: e.go_connect_v5.clone(),
            client_node_id: client_id,
            ..any_station(VERSION_5, e.profile)
        };
        assert_eq!(
            read_hello(&e.erlang_hello_v5, &station),
            Ok(STATION_CAPABILITIES),
            "{:?}",
            e.profile
        );
    }
}
