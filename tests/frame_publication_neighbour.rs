//! Publications (D17), signed by their publishers and held to their time, and
//! the control frames a pq_hybrid link neighbour-signs, held to the ones macula
//! itself signed (tests/vectors/frame/erlang_neighbour.json, macula_frame at
//! macula v12.1.0).

use macula_rust::cbor::{self, Value};
use macula_rust::frame::{
    advertise_frame, decode, goodbye_frame, neighbour_signed, sign_neighbour, sign_publish,
    subscribe_frame, unadvertise_frame, unsubscribe_frame, verify_neighbour, verify_publication,
    Decoded, FrameError, NeighbourLink, NeighbourPeer, PublicationSpec,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

const NOW: u64 = 1_789_000_000_000;
const MINUTE: u64 = 60_000;

fn spec() -> PublicationSpec {
    PublicationSpec {
        realm: [3; 32],
        topic: "acme/demo/greeting_sent_v1".to_string(),
        seq: 1,
        published_at: NOW,
        payload: Value::text("hi"),
        ttl_ms: None,
    }
}

fn arrived(frame: &Value) -> Value {
    cbor::decode(&cbor::encode(frame).unwrap()).unwrap()
}

#[test]
fn a_publication_verifies_for_its_publisher_within_its_time() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let key = NodeKey::generate(Purpose::Identity, profile).unwrap();
        let frame = arrived(&sign_publish(&spec(), &key).unwrap());
        let publication = verify_publication(&frame, profile, NOW as i64).unwrap();
        assert_eq!(publication.publisher, key.key_id());
        assert_eq!(publication.topic, "acme/demo/greeting_sent_v1");
        assert_eq!(publication.seq, 1);
        assert_eq!(publication.payload, Value::text("hi"));
        assert_eq!(publication.expires_at, NOW + 15 * MINUTE);

        assert_eq!(
            verify_publication(&frame, profile, (NOW - 6 * MINUTE) as i64).unwrap_err(),
            FrameError::NotYetValid(MINUTE as i64)
        );
        assert_eq!(
            verify_publication(&frame, profile, (NOW + 16 * MINUTE) as i64).unwrap_err(),
            FrameError::Expired(MINUTE as i64)
        );
    }
}

#[test]
fn a_publication_s_ttl_bounds_its_life_to_an_hour() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let mut long = spec();
    long.ttl_ms = Some(60 * MINUTE);
    let frame = arrived(&sign_publish(&long, &key).unwrap());
    assert_eq!(
        verify_publication(&frame, Profile::PqPure, NOW as i64)
            .unwrap()
            .expires_at,
        NOW + 65 * MINUTE
    );
    long.ttl_ms = Some(60 * MINUTE + 1);
    assert!(matches!(
        sign_publish(&long, &key),
        Err(FrameError::OutOfRange(_))
    ));
    let mut wide = spec();
    wide.topic = "t".repeat(513);
    assert!(matches!(
        sign_publish(&wide, &key),
        Err(FrameError::TextTooLong(_))
    ));
}

#[test]
fn an_event_carries_the_publication_with_how_it_was_delivered() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let Value::Map(pairs) = sign_publish(&spec(), &key).unwrap() else {
        unreachable!()
    };
    let direct = as_event(
        &pairs,
        Some((Value::text("delivered_via"), Value::text("direct"))),
    );
    assert!(verify_publication(&direct, Profile::PqPure, NOW as i64).is_ok());
    assert_eq!(
        verify_publication(&as_event(&pairs, None), Profile::PqPure, NOW as i64).unwrap_err(),
        FrameError::Malformed
    );
}

/// The publication's `pairs` as an EVENT, with `extra` added when given.
fn as_event(pairs: &[(Value, Value)], extra: Option<(Value, Value)>) -> Value {
    let mut event: Vec<(Value, Value)> = pairs.iter().map(event_entry).collect();
    event.extend(extra);
    Value::Map(event)
}

/// One field of a publication as an EVENT carries it: its frame_type event.
fn event_entry((k, v): &(Value, Value)) -> (Value, Value) {
    if *k == Value::text("frame_type") {
        (k.clone(), Value::text("event"))
    } else {
        (k.clone(), v.clone())
    }
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn whole(bytes: &[u8]) -> Value {
    match decode(bytes).unwrap() {
        Decoded::Complete { frame, consumed } if consumed == bytes.len() => frame,
        other => panic!("{other:?}"),
    }
}

fn frame_type(v: &Value) -> Option<&str> {
    match v.get("frame_type") {
        Some(Value::Text(t)) => Some(t),
        _ => None,
    }
}

#[test]
fn control_frames_macula_signed_open_here() {
    let text = std::fs::read_to_string("tests/vectors/frame/erlang_neighbour.json").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let entries = doc["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let mut opened_count = 0;
    for e in entries {
        opened_count += open_vector_entry(e);
    }
    assert!(opened_count >= 10);
}

/// Opens every frame of one vector entry, returning how many opened.
fn open_vector_entry(e: &serde_json::Value) -> usize {
    let profile = Profile::parse(e["profile"].as_str().unwrap()).unwrap();
    let connection: [u8; 48] = unhex(e["connection"].as_str().unwrap()).try_into().unwrap();
    let peer_key = unhex(e["peer_key"].as_str().unwrap());
    let mut opened_count = 0;
    for f in e["frames"].as_array().unwrap() {
        open_vector_frame(f, profile, connection, &peer_key);
        opened_count += 1;
    }
    opened_count
}

/// Opens one frame macula signed, and on pq_hybrid refuses it at the next
/// seq and on another connection.
fn open_vector_frame(
    f: &serde_json::Value,
    profile: Profile,
    connection: [u8; 48],
    peer_key: &[u8],
) {
    let wire = whole(&unhex(f["bytes"].as_str().unwrap()));
    let peer = NeighbourPeer {
        profile,
        peer_key: peer_key.to_vec(),
        connection,
        seq: f["seq"].as_u64().unwrap(),
    };
    let opened = verify_neighbour(&wire, &peer).unwrap();
    assert_eq!(frame_type(&opened), f["frame_type"].as_str(), "{profile:?}");
    if profile != Profile::PqHybrid {
        return;
    }
    let next = NeighbourPeer {
        seq: peer.seq + 1,
        ..peer.clone()
    };
    assert_eq!(
        verify_neighbour(&wire, &next).unwrap_err(),
        FrameError::Malformed
    );
    let mut other = peer.clone();
    other.connection[0] ^= 1;
    assert_eq!(
        verify_neighbour(&wire, &other).unwrap_err(),
        FrameError::Malformed
    );
}

#[test]
fn control_frames_built_here_open_again_and_only_pq_hybrid_signs_them() {
    for profile in [Profile::PqHybrid, Profile::PqPure] {
        built_frames_open_again(profile);
    }
}

/// Builds each control frame under `profile`, signs it on a link and opens it
/// again.
fn built_frames_open_again(profile: Profile) {
    let realm = [3u8; 32];
    let subscriber = [1u8; 32];
    let topic = b"io.macula/mcl-news/news/wire/news_item_reported_v1";
    let key = NodeKey::generate(Purpose::Identity, profile).unwrap();
    let connection = [9u8; 48];
    let frames = [
        ("advertise", advertise_frame(b"a signed record")),
        ("unadvertise", unadvertise_frame(b"a signed withdrawal")),
        (
            "subscribe",
            subscribe_frame(topic, &realm, &subscriber).unwrap(),
        ),
        (
            "unsubscribe",
            unsubscribe_frame(topic, &realm, &subscriber).unwrap(),
        ),
        (
            "goodbye",
            goodbye_frame("normal", Some(b"closing")).unwrap(),
        ),
    ];
    for (seq, (name, frame)) in frames.into_iter().enumerate() {
        built_frame_opens_again(profile, &key, connection, seq as u64, name, &frame);
    }
}

/// Signs one built frame at `seq`, neighbour-signed only on pq_hybrid, opens
/// it again, and on pq_hybrid refuses to sign it twice.
fn built_frame_opens_again(
    profile: Profile,
    key: &NodeKey,
    connection: [u8; 48],
    seq: u64,
    name: &str,
    frame: &Value,
) {
    assert_eq!(
        neighbour_signed(profile, name),
        profile == Profile::PqHybrid
    );
    let link = NeighbourLink { connection, seq };
    let signed = sign_neighbour(frame, key, &link).unwrap();
    assert_eq!(
        signed.get("neighbour").is_some(),
        profile == Profile::PqHybrid,
        "{name}"
    );
    let peer = NeighbourPeer {
        profile,
        peer_key: key.public_key(),
        connection,
        seq,
    };
    let opened = verify_neighbour(&arrived(&signed), &peer).unwrap();
    assert_eq!(frame_type(&opened), Some(name));
    if profile == Profile::PqHybrid {
        assert_eq!(
            sign_neighbour(&signed, key, &link).unwrap_err(),
            FrameError::NeighbourSigned
        );
    }
}

#[test]
fn a_subscribe_topic_is_utf8_of_at_most_512_bytes() {
    let (realm, subscriber) = ([1u8; 32], [2u8; 32]);
    assert!(subscribe_frame(&[b't'; 512], &realm, &subscriber).is_ok());
    assert!(matches!(
        subscribe_frame(&[b't'; 513], &realm, &subscriber),
        Err(FrameError::TextTooLong(_))
    ));
    assert!(matches!(
        unsubscribe_frame(b"\xff", &realm, &subscriber),
        Err(FrameError::InvalidText(_))
    ));
}
