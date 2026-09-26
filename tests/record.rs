//! macula 12's DHT records: signed under MACULA-PQ-RECORD-V1, verified in the
//! design's order, stored under their storage keys, and a procedure's provider
//! authorization (D25): an org directory and a procedure delegation, or a
//! node's own namespace, held to the verdicts macula reaches on the shared
//! fixtures (tests/vectors/record/own_namespace).

use macula_rust::cbor::{self, Value};
use macula_rust::node_key::{key_id_of, NodeKey, Purpose};
use macula_rust::profile::Profile;
use macula_rust::record::{
    encode, envelope, new_content_announcement, new_node_record, new_procedure_advertisement,
    new_station_endpoint, new_tombstone, own_namespace, own_procedure, procedure_key,
    read_node_record, read_procedure_advertisement, read_station_endpoint, read_tombstone, sign,
    station_endpoint_key, storage_key, verify, verify_authorization, Authorization,
    ContentAnnouncementOptions, NodeRecordOptions, ProcedureAdvertisementOptions, Reason,
    RecordError, RecordType, StationEndpointOptions, TombstoneOptions, Trust, Verified,
};
use macula_rust::signed_object::sign_object;

const P: Profile = Profile::PqPure;
const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn identity() -> NodeKey {
    NodeKey::generate(Purpose::Identity, P).unwrap()
}

fn verified(wire: &[u8]) -> Verified {
    verify(wire, P, now() as i64).unwrap()
}

#[test]
fn a_node_record_is_signed_by_its_node_and_stored_under_its_node_id() {
    let key = identity();
    let node_id = key.node_id().unwrap();
    let opts = NodeRecordOptions {
        display_name: "a node".into(),
        lat: Some(50.8),
        lng: Some(4.95),
        peers: vec![[2; 32], [1; 32], [2; 32]],
        ..NodeRecordOptions::default()
    };
    let record = new_node_record(&node_id, &[[3; 32]], 5, &opts).unwrap();
    let signed = sign(&record, &key).unwrap();
    let v = verified(&encode(&signed).unwrap());
    let node = read_node_record(v.record()).unwrap();
    assert_eq!(node.node_id, node_id);
    assert_eq!(node.station_id, node_id);
    assert_eq!(node.realms, vec![[3; 32]]);
    assert_eq!(node.capabilities, 5);
    assert_eq!(node.display_name, "a node");
    assert_eq!(node.lat, Some(50.8));
    assert_eq!(node.peers, vec![[1; 32], [2; 32]]);
    assert_eq!(storage_key(v.record()).unwrap(), node_id);

    // A connect key does not sign a node record; another node's is refused.
    let connect = NodeKey::generate(Purpose::Connect, P).unwrap();
    assert!(matches!(
        sign(&record, &connect),
        Err(RecordError::KeyPurposeMismatch)
    ));
    let other = new_node_record(&[9; 32], &[], 0, &NodeRecordOptions::default()).unwrap();
    assert!(matches!(
        sign(&other, &key),
        Err(RecordError::KeyIdMismatch)
    ));
    let bad_geo = NodeRecordOptions {
        lat: Some(91.0),
        ..NodeRecordOptions::default()
    };
    assert!(matches!(
        new_node_record(&node_id, &[], 0, &bad_geo),
        Err(RecordError::InvalidCoordinate(_))
    ));
}

#[test]
fn a_procedure_advertisement_lives_five_minutes_under_its_procedure_key() {
    let key = identity();
    let node_id = key.node_id().unwrap();
    let ad = new_procedure_advertisement(
        &node_id,
        &[3; 32],
        "acme/echo",
        &[4; 32],
        &ProcedureAdvertisementOptions::default(),
    )
    .unwrap();
    assert_eq!(ad.expires_at - ad.created_at, 5 * MINUTE);
    let v = verified(&encode(&sign(&ad, &key).unwrap()).unwrap());
    let read = read_procedure_advertisement(v.record()).unwrap();
    assert_eq!(read.procedure, "acme/echo");
    assert_eq!(read.serving_station, [4; 32]);
    assert_eq!(read.authorization, Authorization::None);
    assert_eq!(
        storage_key(v.record()).unwrap(),
        procedure_key(&[3; 32], "acme/echo")
    );
    let long = new_procedure_advertisement(
        &node_id,
        &[3; 32],
        "acme/echo",
        &[4; 32],
        &ProcedureAdvertisementOptions {
            ttl_ms: 5 * MINUTE + 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        sign(&long, &key),
        Err(RecordError::LifetimeTooLong)
    ));
}

#[test]
fn a_station_endpoint_is_stored_under_its_station() {
    let key = identity();
    let endpoint = new_station_endpoint(
        4433,
        &StationEndpointOptions {
            host_advertised: vec!["2001:db8::1".into()],
            alpn: "macula".into(),
            ttl_ms: 0,
        },
    )
    .unwrap();
    let v = verified(&encode(&sign(&endpoint, &key).unwrap()).unwrap());
    let read = read_station_endpoint(v.record()).unwrap();
    assert_eq!(read.quic_port, 4433);
    assert_eq!(read.host_advertised, vec!["2001:db8::1".to_string()]);
    assert_eq!(
        storage_key(v.record()).unwrap(),
        station_endpoint_key(&key.node_id().unwrap())
    );
    assert!(matches!(
        new_station_endpoint(0, &StationEndpointOptions::default()),
        Err(RecordError::InvalidPort)
    ));
}

#[test]
fn a_record_is_refused_for_its_time_its_size_and_any_change() {
    let key = identity();
    let node_id = key.node_id().unwrap();
    let signed = sign(
        &new_node_record(&node_id, &[], 0, &NodeRecordOptions::default()).unwrap(),
        &key,
    )
    .unwrap();
    let wire = encode(&signed).unwrap();
    let created = signed.created_at as i64;
    let expires = signed.expires_at as i64;
    let tolerance = 5 * MINUTE as i64;
    assert!(verify(&wire, P, created - tolerance).is_ok());
    assert!(matches!(
        verify(&wire, P, created - tolerance - 1),
        Err(RecordError::NotYetValid)
    ));
    assert!(verify(&wire, P, expires + tolerance).is_ok());
    assert!(matches!(
        verify(&wire, P, expires + tolerance + 1),
        Err(RecordError::Expired)
    ));
    assert!(matches!(
        verify(&vec![0u8; 256 * 1024 + 1], P, created),
        Err(RecordError::TooLarge)
    ));
    let mut altered = wire.clone();
    let last = altered.len() - 20;
    altered[last] ^= 1;
    assert!(matches!(
        verify(&altered, P, created),
        Err(RecordError::SignatureInvalid)
    ));
    assert!(matches!(
        verify(&wire, Profile::PqHybrid, created),
        Err(RecordError::Malformed(_))
    ));
}

#[test]
fn a_tombstone_withdraws_a_record_from_its_slot() {
    let key = identity();
    let node_id = key.node_id().unwrap();
    let ad = sign(
        &new_procedure_advertisement(
            &node_id,
            &[3; 32],
            "acme/echo",
            &[4; 32],
            &Default::default(),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    let tombstone = sign(
        &new_tombstone(&ad, Reason::Shutdown, &TombstoneOptions::default()).unwrap(),
        &key,
    )
    .unwrap();
    let v = verified(&encode(&tombstone).unwrap());
    let read = read_tombstone(v.record()).unwrap();
    assert_eq!(read.withdrawn_type, RecordType::PROCEDURE_ADVERTISEMENT);
    assert_eq!(read.withdrawn_version, ad.version);
    assert_eq!(read.procedure, "acme/echo");
    assert_eq!(storage_key(v.record()).unwrap(), storage_key(&ad).unwrap());
    assert!(matches!(
        new_tombstone(&tombstone, Reason::Shutdown, &TombstoneOptions::default()),
        Err(RecordError::TombstoneOfATombstone)
    ));
}

#[test]
fn a_content_announcement_needs_a_content_id_and_a_procedure() {
    let key = identity();
    let node_id = key.node_id().unwrap();
    let mut mcid = vec![2u8, 0x55];
    mcid.extend([7u8; 48]);
    let opts = ContentAnnouncementOptions {
        realm_id: [3; 32],
        serving_station: [4; 32],
        procedure: own_procedure(&node_id, "content_v1"),
        ..Default::default()
    };
    let announcement = new_content_announcement(&node_id, &mcid, &opts).unwrap();
    verified(&encode(&sign(&announcement, &key).unwrap()).unwrap());
    assert!(matches!(
        new_content_announcement(&node_id, &mcid[..49], &opts),
        Err(RecordError::NotAContentId)
    ));
    let no_procedure = ContentAnnouncementOptions {
        procedure: String::new(),
        ..opts
    };
    assert!(matches!(
        new_content_announcement(&node_id, &mcid, &no_procedure),
        Err(RecordError::Malformed(_))
    ));
}

#[test]
fn a_domain_envelope_is_for_a_domain_type_with_a_subject_that_is_not_empty() {
    let key = identity();
    let record = envelope(0x40, Value::Map(vec![]), Some(b"a subject".to_vec()), 0).unwrap();
    let v = verified(&encode(&sign(&record, &key).unwrap()).unwrap());
    assert_eq!(v.record().subject.as_deref(), Some(&b"a subject"[..]));
    assert!(matches!(
        envelope(0x06, Value::Map(vec![]), None, 0),
        Err(RecordError::NotADomainType)
    ));
    assert!(matches!(
        envelope(0x40, Value::Map(vec![]), Some(Vec::new()), 0),
        Err(RecordError::InvalidSubject)
    ));
}

/// The shared fixtures: advertisements in a node's own namespace, and the
/// verdicts macula reaches on each.
#[test]
fn own_namespace_fixtures_reach_macula_s_verdicts() {
    let text = std::fs::read_to_string("tests/vectors/record/own_namespace/verdicts.json").unwrap();
    let verdicts: serde_json::Value = serde_json::from_str(&text).unwrap();
    let verdicts = verdicts.as_array().unwrap();
    assert_eq!(verdicts.len(), 14);
    let reason = |r: Result<(), RecordError>| match r {
        Ok(()) => "ok".to_string(),
        Err(RecordError::NotOwnNamespace) => "not_own_namespace".into(),
        Err(RecordError::AuthorizationNotAllowed) => "authorization_not_allowed".into(),
        Err(RecordError::Malformed(_)) => "malformed".into(),
        Err(RecordError::NoAuthorization) => "no_authorization".into(),
        Err(other) => format!("{other:?}"),
    };
    for v in verdicts {
        let profile = Profile::parse(v["profile"].as_str().unwrap()).unwrap();
        let wire = std::fs::read(format!(
            "tests/vectors/record/own_namespace/{}",
            v["file"].as_str().unwrap()
        ))
        .unwrap();
        let now_ms = v["now_ms"].as_i64().unwrap();
        let record = verify(&wire, profile, now_ms).unwrap();
        assert_eq!(
            read_procedure_advertisement(record.record())
                .unwrap()
                .procedure,
            v["procedure"].as_str().unwrap()
        );
        let file = v["file"].as_str().unwrap();
        assert_eq!(
            reason(own_namespace(&record)),
            v["own_namespace"].as_str().unwrap(),
            "{file} own_namespace"
        );
        let trust = Trust {
            profile,
            realm_key: None,
        };
        assert_eq!(
            reason(verify_authorization(&record, &trust, now_ms)),
            v["verify_authorization"].as_str().unwrap(),
            "{file} verify_authorization"
        );
    }
}

/// A record signed by hand, as the realm and org sign theirs: a signed object
/// under the record label with the record's fields.
fn hand_signed(
    key: &NodeKey,
    record_type: u8,
    payload: Value,
    created: u64,
    lifetime: u64,
) -> Vec<u8> {
    let mut version = [0u8; 16];
    version[0] = record_type;
    version[15] = (created % 251) as u8;
    let fields = vec![
        (Value::text("type"), Value::Int(i128::from(record_type))),
        (Value::text("version"), Value::Bytes(version.to_vec())),
        (Value::text("created_at"), Value::Int(i128::from(created))),
        (
            Value::text("expires_at"),
            Value::Int(i128::from(created + lifetime)),
        ),
        (Value::text("payload"), payload),
    ];
    cbor::encode(
        &sign_object("MACULA-PQ-RECORD-V1", &fields, key)
            .unwrap()
            .to_value(),
    )
    .unwrap()
}

struct Chain {
    realm: NodeKey,
    node: NodeKey,
    advertisement: Verified,
}

/// A realm that names the org acme, held by an org key that delegates to a
/// node, which advertises acme/echo with that authorization: `org_name` is the
/// org the directory names, `delegate_to_other` delegates to another node,
/// and the directory lives `directory_ms`.
fn chain(org_name: &str, delegate_to_other: bool, directory_ms: u64) -> Chain {
    let (realm, org, node) = (identity(), identity(), identity());
    let t = now();
    let node_id = node.node_id().unwrap();
    let realm_id = [3u8; 32];
    let org_key_id = key_id_of(&org.public_key(), P);
    let directory = hand_signed(
        &realm,
        RecordType::ORG_DIRECTORY.0,
        Value::Map(vec![
            (Value::text("realm_id"), Value::Bytes(realm_id.to_vec())),
            (Value::text("org_name"), Value::text(org_name)),
            (Value::text("org_key"), Value::Bytes(org_key_id.to_vec())),
        ]),
        t,
        directory_ms,
    );
    let advertiser = if delegate_to_other {
        [8u8; 32]
    } else {
        node_id
    };
    let delegation = hand_signed(
        &org,
        RecordType::PROCEDURE_DELEGATION.0,
        Value::Map(vec![
            (Value::text("org_key"), Value::Bytes(org_key_id.to_vec())),
            (Value::text("advertiser"), Value::Bytes(advertiser.to_vec())),
        ]),
        t,
        6 * HOUR,
    );
    let ad = new_procedure_advertisement(
        &node_id,
        &realm_id,
        "acme/echo",
        &[4; 32],
        &ProcedureAdvertisementOptions {
            authorization: Authorization::Delegation {
                org_directory: directory,
                procedure_delegation: delegation,
            },
            ttl_ms: 0,
        },
    )
    .unwrap();
    let advertisement = verified(&encode(&sign(&ad, &node).unwrap()).unwrap());
    Chain {
        realm,
        node,
        advertisement,
    }
}

#[test]
fn an_org_procedure_is_authorized_by_the_realm_s_org_directory_and_the_org_s_delegation() {
    let c = chain("acme", false, 6 * HOUR);
    let trust = |key: Option<Vec<u8>>| Trust {
        profile: P,
        realm_key: key,
    };
    let t = now() as i64;
    assert!(verify_authorization(&c.advertisement, &trust(Some(c.realm.public_key())), t).is_ok());
    assert!(matches!(
        verify_authorization(&c.advertisement, &trust(None), t),
        Err(RecordError::NoRealmKey)
    ));
    assert!(matches!(
        verify_authorization(&c.advertisement, &trust(Some(c.node.public_key())), t),
        Err(RecordError::OrgDirectoryWrongRealm)
    ));

    let other_org = chain("globex", false, 6 * HOUR);
    assert!(matches!(
        verify_authorization(
            &other_org.advertisement,
            &trust(Some(other_org.realm.public_key())),
            t
        ),
        Err(RecordError::OrgDirectoryWrongOrg)
    ));
    let other_node = chain("acme", true, 6 * HOUR);
    assert!(matches!(
        verify_authorization(
            &other_node.advertisement,
            &trust(Some(other_node.realm.public_key())),
            t
        ),
        Err(RecordError::DelegationMismatch)
    ));
    // A directory that lapses a minute from now, before the advertisement.
    let short = chain("acme", false, MINUTE);
    assert!(matches!(
        verify_authorization(
            &short.advertisement,
            &trust(Some(short.realm.public_key())),
            t
        ),
        Err(RecordError::AuthorizationOutlived)
    ));
}

#[test]
fn an_org_procedure_without_an_authorization_is_refused() {
    let key = identity();
    let ad = new_procedure_advertisement(
        &key.node_id().unwrap(),
        &[3; 32],
        "acme/echo",
        &[4; 32],
        &Default::default(),
    )
    .unwrap();
    let v = verified(&encode(&sign(&ad, &key).unwrap()).unwrap());
    let trust = Trust {
        profile: P,
        realm_key: Some(identity().public_key()),
    };
    assert!(matches!(
        verify_authorization(&v, &trust, now() as i64),
        Err(RecordError::NoAuthorization)
    ));
}
