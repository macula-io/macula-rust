//! The length-prefixed wire codec, and the payload and frame checks a sender
//! runs so nothing the decoding rule refuses on arrival leaves this node.

use macula_rust::cbor::Value;
use macula_rust::frame::{
    check_frame, check_payload, decode, encode, Decoded, FrameError, MAX_FRAME_BYTES,
    MAX_PAYLOAD_ELEMENTS, MAX_PAYLOAD_NESTING,
};

fn nested(depth: usize) -> Value {
    (0..depth).fold(Value::Int(0), |inner, _| Value::List(vec![inner]))
}

#[test]
fn a_frame_travels_length_prefixed_and_decodes_whole() {
    let frame = Value::Map(vec![(Value::text("version"), Value::Int(2))]);
    let wire = encode(&frame).unwrap();
    assert_eq!(&wire[..4], &((wire.len() - 4) as u32).to_be_bytes());
    let mut two = wire.clone();
    two.extend_from_slice(&wire);
    match decode(&two).unwrap() {
        Decoded::Complete {
            frame: decoded,
            consumed,
        } => {
            assert_eq!(decoded, frame);
            assert_eq!(consumed, wire.len());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(decode(&wire[..2]).unwrap(), Decoded::NeedMore(2));
    assert_eq!(
        decode(&wire[..wire.len() - 1]).unwrap(),
        Decoded::NeedMore(1)
    );
}

#[test]
fn a_frame_over_the_cap_is_refused_both_ways() {
    let big = Value::Bytes(vec![0u8; MAX_FRAME_BYTES]);
    assert!(matches!(encode(&big), Err(FrameError::TooLarge(_))));
    let mut header = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
    header.push(0);
    assert!(matches!(decode(&header), Err(FrameError::TooLarge(_))));
    assert!(matches!(
        decode(&[0, 0, 0, 1, 0xff]),
        Err(FrameError::Malformed)
    ));
}

#[test]
fn a_payload_the_decoding_rule_would_refuse_is_refused_before_it_is_sent() {
    let refused = [
        (
            "a float key",
            Value::Map(vec![(Value::Float(1.0), Value::Int(1))]),
        ),
        (
            "a bytes key",
            Value::Map(vec![(Value::Bytes(vec![1]), Value::Int(1))]),
        ),
        (
            "two keys that encode alike",
            Value::Map(vec![
                (Value::text("a"), Value::Int(1)),
                (Value::text("a"), Value::Int(2)),
            ]),
        ),
        (
            "an integer above 2^63-1",
            Value::Int(i128::from(i64::MAX) + 1),
        ),
        ("a NaN", Value::Float(f64::NAN)),
        ("an infinity", Value::Float(f64::INFINITY)),
        ("too deep", nested(MAX_PAYLOAD_NESTING + 1)),
        (
            "too many items",
            Value::List(vec![Value::Int(0); MAX_PAYLOAD_ELEMENTS]),
        ),
    ];
    for (name, payload) in refused {
        assert!(
            matches!(check_payload(&payload), Err(FrameError::Payload(_))),
            "{name}"
        );
    }
    assert!(check_payload(&nested(MAX_PAYLOAD_NESTING)).is_ok());
    assert!(check_payload(&Value::List(vec![Value::Int(0); MAX_PAYLOAD_ELEMENTS - 1])).is_ok());
    assert!(check_payload(&Value::Map(vec![(Value::Int(-1), Value::text("x"))])).is_ok());
}

#[test]
fn a_whole_frame_is_held_to_the_rule_s_own_limits() {
    let frame = Value::Map(vec![(Value::text("payload"), nested(MAX_PAYLOAD_NESTING))]);
    assert!(check_frame(&frame).is_ok());
    let deeper = Value::Map(vec![(
        Value::text("payload"),
        nested(MAX_PAYLOAD_NESTING + 1),
    )]);
    assert!(matches!(
        check_frame(&deeper),
        Err(FrameError::BreaksDecodingRule(_))
    ));
}
