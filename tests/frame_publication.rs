//! Publications (D17), signed by their publishers and held to their time, and
//! the topic bound of SUBSCRIBE and UNSUBSCRIBE.

use macula_rust::cbor::{self, Value};
use macula_rust::frame::{
    sign_publish, subscribe_frame, unsubscribe_frame, verify_publication, FrameError, Payload,
    PublicationSpec,
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
        payload: Payload::Clear(Value::text("hi")),
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
        assert_eq!(publication.payload, Payload::Clear(Value::text("hi")));
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
