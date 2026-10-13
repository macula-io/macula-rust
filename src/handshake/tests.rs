//! A client and a station of this crate run the wire 1.0 handshake against
//! each other in both profiles: negotiation, proof V3, session proof V2 and
//! the version floor, each refusal on the side and with the HELLO the design
//! names. A TLS exporter cannot travel in a test, so both ends use one
//! stand-in: HMAC-SHA256 keyed by the session's name, over the label and the
//! context.

use aws_lc_rs::hmac;

use super::*;
use crate::binding::{connect_binding, status_statement, tls_binding};
use crate::node_key::Purpose;

const NOW: i64 = 1_789_000_000_000;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const CLIENT_CAPABILITIES: u64 = CAP_RELAY_OVERLOADED;
const STATION_CAPABILITIES: u64 = CAP_STATION | (1 << MAX_CAPABILITY_BIT);
const LEAF: &[u8] = b"the leaf this connection presents";

fn exporter_of(session: &'static str) -> Arc<Exporter> {
    Arc::new(move |label: &str, context: &[u8], length: usize| {
        let key = hmac::Key::new(hmac::HMAC_SHA256, session.as_bytes());
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(label.as_bytes());
        ctx.update(context);
        (label == EXPORTER_LABEL).then(|| ctx.sign().as_ref()[..length].to_vec())
    })
}

fn no_floor() -> Arc<Floor> {
    Arc::new(|_: &[u8; 32]| 0)
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
    floor: Arc<Floor>,
}

fn world(profile: Profile) -> World {
    let station = Arc::new(NodeKey::generate_identity(profile, 0).unwrap());
    let tls = tls_binding(&station, LEAF, NOW, NOW + DAY_MS).unwrap();
    let tls_status = status_statement(&station, &tls, NOW, NOW + HOUR_MS).unwrap();
    let client = NodeKey::generate_identity(profile, 0).unwrap();
    let connect = NodeKey::generate(Purpose::Connect, profile).unwrap();
    let binding = connect_binding(&client, &connect.public_key(), NOW, NOW + DAY_MS).unwrap();
    let status = status_statement(&client, &binding, NOW, NOW + HOUR_MS).unwrap();
    World {
        profile,
        material: StationMaterial {
            profile,
            identity_key: station.public_key(),
            tls_binding: tls,
            tls_status,
        },
        station,
        client,
        connect,
        binding,
        status,
        export: exporter_of("session_a"),
        floor: no_floor(),
    }
}

fn worlds() -> Vec<World> {
    vec![world(Profile::PqPure), world(Profile::PqHybrid)]
}

impl World {
    fn ranges(&self) -> Ranges {
        Ranges::supported(self.profile)
    }

    fn client_session(&self) -> ClientSession<'_> {
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
            ranges: self.ranges(),
            floor: self.floor.as_ref(),
            export: self.export.as_ref(),
        }
    }

    fn station_session(&self, negotiated: &Negotiated, challenge: &[u8]) -> StationSession {
        let key = self.station.clone();
        StationSession {
            profile: self.profile,
            negotiated: negotiated.clone(),
            challenge: challenge.to_vec(),
            leaf: LEAF.to_vec(),
            puzzle_difficulty: 0,
            puzzle_mode: PuzzleMode::Enforce,
            capabilities: STATION_CAPABILITIES,
            now_ms: NOW,
            floor: no_floor(),
            export: exporter_of("session_a"),
            sign_session_proof: Arc::new(move |_client: &[u8; 32], message: &[u8]| {
                key.sign(message).map_err(HandshakeError::Key)
            }),
        }
    }

    /// The opener read by the station, and its challenge.
    fn opened(&self) -> (Negotiated, Vec<u8>) {
        let (negotiated, hello) = read_opener(&opener(&self.ranges()), &self.ranges());
        assert_eq!(hello, None);
        let negotiated = negotiated.unwrap();
        let challenge = challenge(&self.material, &negotiated, &self.ranges()).unwrap();
        (negotiated, challenge)
    }
}

#[test]
fn a_whole_handshake_connects_both_sides_in_version_5() {
    for w in worlds() {
        let (negotiated, challenge) = w.opened();
        assert_eq!(negotiated.version, VERSION);
        assert_eq!(negotiated.profile, w.profile.name());
        let (connect, station) = answer_challenge(&challenge, &w.client_session()).unwrap();
        let (client, hello) = accept_connect(&connect, &w.station_session(&negotiated, &challenge));
        let client = client.unwrap();
        assert_eq!(client.node_id, w.client.node_id().unwrap());
        assert_eq!(client.capabilities, CLIENT_CAPABILITIES);
        assert_eq!(client.version, VERSION);
        assert_eq!(
            read_hello(&hello, &station),
            Ok(STATION_CAPABILITIES),
            "{:?}",
            w.profile
        );
        assert_eq!(station.version, VERSION);
    }
}

#[test]
fn a_station_refuses_an_opener_it_shares_nothing_with_and_names_its_ranges() {
    let w = world(Profile::PqPure);
    let hybrid_only = Ranges::supported(Profile::PqHybrid);
    let (read, hello) = read_opener(&opener(&hybrid_only), &w.ranges());
    assert_eq!(read, Err(HandshakeError::ProfileUnsupported));
    let refused = read_hello(&hello.unwrap(), &world(Profile::PqPure).answered().1);
    assert_eq!(
        refused,
        Err(HandshakeError::Refused {
            code: RefusalCode::ProfileUnsupported,
            station_ranges: Some(w.ranges()),
        })
    );
    let six = Ranges {
        min_version: 6,
        max_version: 6,
        ..w.ranges()
    };
    let (read, hello) = read_opener(&opener(&six), &w.ranges());
    assert_eq!(read, Err(HandshakeError::UnsupportedVersion));
    assert!(hello.is_some());
}

impl World {
    /// A whole handshake up to CONNECT: the negotiation, challenge, CONNECT
    /// and what the client knows of the station.
    fn answered(&self) -> (Negotiated, Station, Vec<u8>, Vec<u8>) {
        let (negotiated, challenge) = self.opened();
        let (connect, station) = answer_challenge(&challenge, &self.client_session()).unwrap();
        (negotiated, station, challenge, connect)
    }
}

#[test]
fn a_client_detects_a_downgraded_choice_and_a_version_below_its_floor() {
    let w = world(Profile::PqPure);
    let (_, challenge) = w.opened();
    let mut wider = w.client_session();
    wider.ranges = Ranges {
        profiles: vec!["pq_pure".into(), "pq_hybrid".into()],
        ..w.ranges()
    };
    wider.profile = Profile::PqHybrid;
    assert!(matches!(
        answer_challenge(&challenge, &wider),
        Err(HandshakeError::DowngradeDetected)
    ));
    let above: Arc<Floor> = Arc::new(|_: &[u8; 32]| VERSION + 1);
    let mut floored = w.client_session();
    floored.floor = above.as_ref();
    assert!(matches!(
        answer_challenge(&challenge, &floored),
        Err(HandshakeError::VersionBelowFloor)
    ));
}

#[test]
fn a_station_refuses_a_connect_whose_ranges_changed_or_whose_proof_does_not_hold() {
    let w = world(Profile::PqPure);
    let (negotiated, _, challenge, connect) = w.answered();
    let session = w.station_session(&negotiated, &challenge);
    let other_ranges = Negotiated {
        client: Ranges {
            profiles: vec!["pq_pure".into(), "pq_hybrid".into()],
            ..negotiated.client.clone()
        },
        ..negotiated.clone()
    };
    let (read, hello) = accept_connect(&connect, &w.station_session(&other_ranges, &challenge));
    assert_eq!(read, Err(HandshakeError::NegotiationMismatch));
    assert!(matches!(
        read_hello(&hello, &w.answered().1),
        Err(HandshakeError::Refused {
            code: RefusalCode::NotAccepted,
            station_ranges: None
        })
    ));
    let changed = changed_field(&connect, "capabilities", Value::Int(7));
    assert_eq!(
        accept_connect(&changed, &session).0,
        Err(HandshakeError::ProofInvalid)
    );
    let mut other_session = session.clone();
    other_session.export = exporter_of("session_b");
    assert_eq!(
        accept_connect(&connect, &other_session).0,
        Err(HandshakeError::ProofInvalid)
    );
}

#[test]
fn a_client_refuses_a_hello_that_does_not_prove_this_session() {
    for w in worlds() {
        let (negotiated, station, challenge, connect) = w.answered();
        let (_, hello) = accept_connect(&connect, &w.station_session(&negotiated, &challenge));
        let other_caps = changed_field(&hello, "capabilities", Value::Int(0));
        assert_eq!(
            read_hello(&other_caps, &station),
            Err(HandshakeError::SessionProofInvalid)
        );
        let without = encode_frame(
            "hello",
            vec![
                entry("accepted", Value::Int(1)),
                entry("capabilities", Value::Int(0)),
            ],
        );
        assert_eq!(
            read_hello(&without, &station),
            Err(HandshakeError::SessionProofMissing)
        );
    }
}

#[test]
fn a_station_signs_the_session_proof_only_after_every_check() {
    let w = world(Profile::PqPure);
    let (negotiated, _, challenge, connect) = w.answered();
    let signed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut session = w.station_session(&negotiated, &challenge);
    let count = signed.clone();
    session.sign_session_proof = Arc::new(move |_: &[u8; 32], _: &[u8]| {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(HandshakeError::SessionProofRate)
    });
    let bad = changed_field(&connect, "capabilities", Value::Int(7));
    assert_eq!(
        accept_connect(&bad, &session).0,
        Err(HandshakeError::ProofInvalid)
    );
    assert_eq!(signed.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (read, hello) = accept_connect(&connect, &session);
    assert_eq!(read, Err(HandshakeError::SessionProofRate));
    assert!(matches!(
        read_hello(&hello, &w.answered().1),
        Err(HandshakeError::Refused {
            code: RefusalCode::SessionProofRate,
            ..
        })
    ));
}

/// `frame` with `key` set to `value`, re-encoded deterministically.
fn changed_field(frame: &[u8], key: &str, value: Value) -> Vec<u8> {
    cbor::encode(&cbor::decode(frame).unwrap().with_field(key, value)).unwrap()
}
