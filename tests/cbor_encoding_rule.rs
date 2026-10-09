//! What `cbor::encode` writes, `cbor::decode` reads back: the encoder refuses
//! every value macula 12's decoding rule refuses, so no stack is handed bytes
//! it must reject, and nothing this crate stores becomes unreadable. Held to
//! the shared vectors (tests/vectors/cbor/decoding_rule_v1.json) from the
//! encoding side.

use macula_rust::cbor::{decode, encode, EncodeError, Value, MAX_ELEMENTS, MAX_NESTING_DEPTH};

fn vectors() -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string("tests/vectors/cbor/decoding_rule_v1.json").unwrap();
    let vectors: serde_json::Value = serde_json::from_str(&text).unwrap();
    vectors["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry.get("via").is_none())
        .cloned()
        .collect()
}

fn nested(count: usize, innermost: Value) -> Value {
    (0..count).fold(innermost, |inner, _| Value::List(vec![inner]))
}

fn map(pairs: Vec<(Value, Value)>) -> Value {
    Value::Map(pairs)
}

type Refused = (&'static str, Value, EncodeError);

/// The refused vectors a `Value` can hold, each as that value and the reason
/// the encoder gives for it.
fn refused_values() -> Vec<Refused> {
    [
        bad_keys(),
        duplicate_keys(),
        integers_and_nesting(),
        non_finite_floats(),
    ]
    .concat()
}

fn bad_keys() -> Vec<Refused> {
    let keyed = |key: Value| map(vec![(key, Value::Int(1))]);
    vec![
        (
            "a byte string key",
            keyed(Value::Bytes(b"a".to_vec())),
            EncodeError::BadKey,
        ),
        (
            "integer key 1 beside float key 1.0",
            map(vec![
                (Value::Int(1), Value::Int(1)),
                (Value::Float(1.0), Value::Int(2)),
            ]),
            EncodeError::BadKey,
        ),
        (
            "an array key",
            keyed(Value::List(vec![])),
            EncodeError::BadKey,
        ),
        ("a map key", keyed(map(vec![])), EncodeError::BadKey),
        ("a null key", keyed(Value::Null), EncodeError::BadKey),
    ]
}

fn duplicate_keys() -> Vec<Refused> {
    let twice = |key: Value| map(vec![(key.clone(), Value::Int(1)), (key, Value::Int(2))]);
    let a = || Value::text("a");
    vec![
        (
            "a duplicate text key",
            twice(a()),
            EncodeError::DuplicateKey,
        ),
        // A Value has no widths: the same key twice is the nearest it holds.
        (
            "a text key in two widths",
            twice(a()),
            EncodeError::DuplicateKey,
        ),
        (
            "a duplicate integer key",
            twice(Value::Int(1)),
            EncodeError::DuplicateKey,
        ),
        (
            "a duplicate key in a nested map",
            map(vec![(Value::text("b"), twice(a()))]),
            EncodeError::DuplicateKey,
        ),
        (
            "a duplicate key in a map inside an array",
            Value::List(vec![twice(a())]),
            EncodeError::DuplicateKey,
        ),
    ]
}

fn integers_and_nesting() -> Vec<Refused> {
    let int = |name, n| (name, Value::Int(n), EncodeError::IntegerOutOfRange);
    vec![
        (
            "65 nested containers",
            nested(MAX_NESTING_DEPTH + 1, Value::Int(1)),
            EncodeError::NestingTooDeep,
        ),
        int("an integer below -2^63", -(1i128 << 63) - 1),
        int("the smallest CBOR integer, -2^64", -(1i128 << 64)),
        int("an integer above 2^63-1", 1i128 << 63),
        int("the largest CBOR integer, 2^64-1", (1i128 << 64) - 1),
    ]
}

/// A Value's float is always written in double width, so each width's
/// vector is the same value.
fn non_finite_floats() -> Vec<Refused> {
    let float = |name, f| (name, Value::Float(f), EncodeError::NonFiniteFloat);
    vec![
        float("positive infinity, half width", f64::INFINITY),
        float("negative infinity, half width", f64::NEG_INFINITY),
        float("NaN, half width", f64::NAN),
        float("positive infinity, single width", f64::INFINITY),
        float("negative infinity, single width", f64::NEG_INFINITY),
        float("NaN, single width", f64::NAN),
        float("positive infinity, double width", f64::INFINITY),
        float("negative infinity, double width", f64::NEG_INFINITY),
        float("NaN, double width", f64::NAN),
    ]
}

/// The refused vectors no `Value` can hold: they break the rule in their
/// bytes (framing, widths, tags, simple values, UTF-8), which the encoder
/// never writes.
const REFUSED_IN_BYTES_ONLY: [&str; 15] = [
    "bytes after the top-level item",
    "truncated input",
    "empty input",
    "an indefinite byte string",
    "an indefinite text string",
    "an indefinite array",
    "an indefinite map",
    "tag 1",
    "tag 2, a bignum",
    "the simple value false",
    "the simple value true",
    "the simple value undefined",
    "simple value 32",
    "invalid UTF-8 in a text value",
    "invalid UTF-8 in a text key",
];

#[test]
fn every_accepted_vector_encodes_and_reads_back_alike() {
    let mut checked = 0;
    for entry in vectors() {
        if entry["expect"] != "accept" {
            continue;
        }
        let name = entry["name"].as_str().unwrap();
        let value = decode(&hex::decode(entry["cbor"].as_str().unwrap()).unwrap()).unwrap();
        let bytes = encode(&value).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // Encoding sorts map keys, so it is the bytes that read back alike.
        assert_eq!(encode(&decode(&bytes).unwrap()), Ok(bytes), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 15);
}

#[test]
fn every_refused_vector_is_one_the_encoder_refuses_or_cannot_write() {
    let values = refused_values();
    for entry in vectors() {
        if entry["expect"] != "refuse" {
            continue;
        }
        let name = entry["name"].as_str().unwrap();
        let held = values.iter().any(|(n, _, _)| *n == name);
        let bytes_only = REFUSED_IN_BYTES_ONLY.contains(&name);
        assert!(
            held != bytes_only,
            "{name}: give it a value here, or name it as refused in bytes only"
        );
    }
    for (name, value, reason) in values {
        assert_eq!(encode(&value), Err(reason), "{name}");
    }
}

#[test]
fn the_limits_are_the_decoder_s() {
    let deepest = nested(MAX_NESTING_DEPTH, Value::Int(1));
    assert_eq!(decode(&encode(&deepest).unwrap()).unwrap(), deepest);

    // The list counts as one item, its elements as the rest.
    let widest = Value::List(vec![Value::Null; MAX_ELEMENTS - 1]);
    assert!(decode(&encode(&widest).unwrap()).unwrap() == widest);
    let too_wide = Value::List(vec![Value::Null; MAX_ELEMENTS]);
    assert!(encode(&too_wide) == Err(EncodeError::TooManyElements));

    let extremes = Value::List(vec![
        Value::Int(i128::from(i64::MIN)),
        Value::Int(i128::from(i64::MAX)),
    ]);
    assert_eq!(decode(&encode(&extremes).unwrap()).unwrap(), extremes);
}
