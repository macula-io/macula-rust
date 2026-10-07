//! macula 12's decoding rule, which every stack applies to what a peer sends:
//! the shared vectors (tests/vectors/cbor/decoding_rule_v1.json), and the
//! verdict macula's reference decoder, macula_record_cbor:decode_strict/1,
//! gives each input with its reason, as macula-go pins them, so an input is
//! refused here for the same reason as in every other stack.

use macula_rust::cbor::{decode, DecodeError, MAX_ELEMENTS, MAX_NESTING_DEPTH};

fn nested(count: usize, innermost: &str) -> String {
    "81".repeat(count) + innermost
}

fn refusal(name: &str) -> DecodeError {
    match name {
        "trailing_bytes" => DecodeError::TrailingBytes,
        "bad_key" => DecodeError::BadKey,
        "duplicate_key" => DecodeError::DuplicateKey,
        "invalid_text" => DecodeError::InvalidText,
        "too_deep" => DecodeError::NestingTooDeep,
        "integer_out_of_range" => DecodeError::IntegerOutOfRange,
        "too_many_elements" => DecodeError::TooManyElements,
        "malformed" => DecodeError::Malformed,
        other => panic!("no refusal for the reference's reason {other}"),
    }
}

#[test]
fn the_limits_are_macula_s() {
    assert_eq!(MAX_NESTING_DEPTH, 64);
    assert_eq!(MAX_ELEMENTS, 131_072);
}

#[test]
fn the_shared_vectors_decode_as_every_stack_decodes_them() {
    let text = std::fs::read_to_string("tests/vectors/cbor/decoding_rule_v1.json").unwrap();
    let vectors: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut checked = 0;
    for entry in vectors["entries"].as_array().unwrap() {
        // The CALL-field entries are the request's own field rules, checked
        // where a request is read.
        if entry.get("via").is_some() {
            continue;
        }
        let name = entry["name"].as_str().unwrap();
        let bytes = hex::decode(entry["cbor"].as_str().unwrap()).unwrap();
        let result = decode(&bytes);
        match entry["expect"].as_str().unwrap() {
            "accept" => assert!(
                result.is_ok(),
                "{name}: {result:?}, but every stack accepts it"
            ),
            "refuse" => assert!(
                result.is_err(),
                "{name}: accepted, but every stack refuses it"
            ),
            other => panic!("{name}: unknown expectation {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 54);
}

#[test]
fn every_input_is_refused_for_the_reference_decoder_s_reason() {
    let cases = [
        duplicate_trailing_and_text_cases(),
        text_and_key_type_cases(),
        key_encoding_cases(),
        float_and_nesting_cases(),
        integer_range_cases(),
        non_finite_float_cases(),
        length_tag_and_simple_value_cases(),
    ]
    .concat();
    for (name, hex_input, reason) in cases {
        held_to_the_reference(name, &hex_input, reason);
    }
}

/// One input decoded here, accepted where the reference accepts it (an empty
/// `reason`) and refused for the reference's reason otherwise.
fn held_to_the_reference(name: &str, hex_input: &str, reason: &str) {
    let result = decode(&hex::decode(hex_input).unwrap());
    if reason.is_empty() {
        assert!(
            result.is_ok(),
            "{name}: {result:?}, but the reference accepts it"
        );
    } else {
        assert_eq!(
            result,
            Err(refusal(reason)),
            "{name}: the reference refuses it as {reason}"
        );
    }
}

/// Duplicate keys, bytes after an item, short input and invalid UTF-8 text.
fn duplicate_trailing_and_text_cases() -> Vec<Case> {
    vec![
        (
            "a duplicate key at the top level",
            "a2616101616102".into(),
            "duplicate_key",
        ),
        (
            "a duplicate key in a nested map",
            "a16162a2616101616102".into(),
            "duplicate_key",
        ),
        (
            "a duplicate key in a map inside an array",
            "81a2616101616102".into(),
            "duplicate_key",
        ),
        (
            "bytes after the top-level item",
            "a161610100".into(),
            "trailing_bytes",
        ),
        (
            "bytes after a nested item",
            "810000".into(),
            "trailing_bytes",
        ),
        ("truncated input", "a26161".into(), "malformed"),
        ("empty input", "".into(), "malformed"),
        (
            "invalid UTF-8 in a text value",
            "a1616161ff".into(),
            "invalid_text",
        ),
        (
            "invalid UTF-8 in a text key",
            "a161ff01".into(),
            "invalid_text",
        ),
    ]
}

/// Text the reference accepts or refuses, and keys of a type it refuses.
fn text_and_key_type_cases() -> Vec<Case> {
    vec![
        ("valid multibyte text", "a1616b65636166c3a9".into(), ""),
        (
            "a UTF-16 surrogate in text",
            "63eda080".into(),
            "invalid_text",
        ),
        ("an overlong NUL in text", "62c080".into(), "invalid_text"),
        (
            "a code point above U+10FFFF",
            "64f4908080".into(),
            "invalid_text",
        ),
        ("the noncharacter U+FFFE", "63efbfbe".into(), ""),
        ("a byte string key", "a1416101".into(), "bad_key"),
        ("a float key", "a1f93ff001".into(), "bad_key"),
        ("a half float key", "a1f93c0001".into(), "bad_key"),
        ("an array key", "a18001".into(), "bad_key"),
        ("a map key", "a1a001".into(), "bad_key"),
        ("a null key", "a1f601".into(), "bad_key"),
        ("integer keys 1 and -1", "a201022003".into(), ""),
        ("integer keys -1 and 0", "a220010002".into(), ""),
    ]
}

/// One key twice in any of its encodings, and a refusal behind a bad key.
fn key_encoding_cases() -> Vec<Case> {
    vec![
        (
            "a duplicate integer key",
            "a201020103".into(),
            "duplicate_key",
        ),
        (
            "the empty text key twice",
            "a260016002".into(),
            "duplicate_key",
        ),
        (
            "a text key in two widths",
            "a261610178016102".into(),
            "duplicate_key",
        ),
        (
            "a text key in one-byte and two-byte widths",
            "a278016101790001616102".into(),
            "duplicate_key",
        ),
        (
            "an unsigned key in two widths",
            "a20101180102".into(),
            "duplicate_key",
        ),
        (
            "a negative key in two widths",
            "a22001380002".into(),
            "duplicate_key",
        ),
        (
            "a duplicate key whose second value is invalid text",
            "a2616101616161ff".into(),
            "invalid_text",
        ),
        (
            "a byte string key whose value nests 65 containers",
            format!("a14161{}", nested(65, "00")),
            "too_deep",
        ),
    ]
}

/// Small floats, and containers nested up to and past the limit.
fn float_and_nesting_cases() -> Vec<Case> {
    vec![
        ("a half float value", "81f93e00".into(), ""),
        ("negative zero, half width", "f98000".into(), ""),
        ("the smallest half subnormal", "f90001".into(), ""),
        ("64 nested arrays", nested(64, "00"), ""),
        ("65 nested arrays", nested(65, "00"), "too_deep"),
        (
            "64 containers, the innermost an empty array",
            nested(63, "80"),
            "",
        ),
        (
            "65 containers, the innermost an empty array",
            nested(64, "80"),
            "too_deep",
        ),
        (
            "64 containers, the innermost an empty map",
            nested(63, "a0"),
            "",
        ),
        (
            "65 containers, the innermost an empty map",
            nested(64, "a0"),
            "too_deep",
        ),
        (
            "a map whose value is 63 arrays deep",
            format!("a16161{}", nested(63, "00")),
            "",
        ),
        (
            "a map whose value is 64 arrays deep",
            format!("a16161{}", nested(64, "00")),
            "too_deep",
        ),
    ]
}

/// Integers at and past the ends of -2^63 to 2^63-1.
fn integer_range_cases() -> Vec<Case> {
    vec![
        (
            "the smallest integer, -2^63",
            "3b7fffffffffffffff".into(),
            "",
        ),
        (
            "an integer below -2^63",
            "3b8000000000000000".into(),
            "integer_out_of_range",
        ),
        (
            "the smallest CBOR integer, -2^64",
            "3bffffffffffffffff".into(),
            "integer_out_of_range",
        ),
        (
            "the largest integer, 2^63-1",
            "1b7fffffffffffffff".into(),
            "",
        ),
        (
            "an integer above 2^63-1",
            "1b8000000000000000".into(),
            "integer_out_of_range",
        ),
        (
            "the largest CBOR integer, 2^64-1",
            "1bffffffffffffffff".into(),
            "integer_out_of_range",
        ),
    ]
}

/// Infinities and NaN in every float width.
fn non_finite_float_cases() -> Vec<Case> {
    vec![
        (
            "positive infinity, half width",
            "f97c00".into(),
            "malformed",
        ),
        (
            "negative infinity, half width",
            "f9fc00".into(),
            "malformed",
        ),
        ("NaN, half width", "f97e00".into(), "malformed"),
        (
            "positive infinity, single width",
            "fa7f800000".into(),
            "malformed",
        ),
        (
            "negative infinity, single width",
            "faff800000".into(),
            "malformed",
        ),
        ("NaN, single width", "fa7fc00000".into(), "malformed"),
        (
            "positive infinity, double width",
            "fb7ff0000000000000".into(),
            "malformed",
        ),
        (
            "negative infinity, double width",
            "fbfff0000000000000".into(),
            "malformed",
        ),
        (
            "NaN, double width",
            "fb7ff8000000000000".into(),
            "malformed",
        ),
    ]
}

/// Indefinite lengths, reserved additional info, lengths past the input, tags and simple values.
fn length_tag_and_simple_value_cases() -> Vec<Case> {
    vec![
        ("an indefinite byte string", "5f4161ff".into(), "malformed"),
        ("an indefinite array", "9f01ff".into(), "malformed"),
        ("an indefinite map", "bf616101ff".into(), "malformed"),
        ("a lone break byte", "ff".into(), "malformed"),
        ("additional info 28", "1c".into(), "malformed"),
        ("additional info 29", "1d".into(), "malformed"),
        ("additional info 30", "1e".into(), "malformed"),
        (
            "a byte string longer than the input",
            "4200".into(),
            "malformed",
        ),
        (
            "a text length of 2^64-1",
            "7bffffffffffffffff".into(),
            "malformed",
        ),
        (
            "a map claiming 2^64-1 entries",
            "bbffffffffffffffff".into(),
            "malformed",
        ),
        (
            "an array claiming 2^32-1 items",
            "9affffffff".into(),
            "malformed",
        ),
        (
            "a byte string length in eight bytes",
            "5b000000000000000100".into(),
            "",
        ),
        ("tag 0 on text", "c060".into(), "malformed"),
        ("tag 1", "c11a00000001".into(), "malformed"),
        ("tag 2, a bignum", "c24101".into(), "malformed"),
        ("simple value 0", "e0".into(), "malformed"),
        ("simple value 19", "f3".into(), "malformed"),
        ("the simple value false", "f4".into(), "malformed"),
        ("the simple value true", "f5".into(), "malformed"),
        ("the simple value undefined", "f7".into(), "malformed"),
        ("simple value 24 in two bytes", "f818".into(), "malformed"),
        ("simple value 32", "f820".into(), "malformed"),
        ("null", "f6".into(), ""),
    ]
}

/// An input's name, its hex, and the reference's reason for refusing it,
/// empty when it accepts it.
type Case = (&'static str, String, &'static str);

/// An array header for `count` items followed by `present` zeros.
fn zeros_array(count: u32, present: usize) -> Vec<u8> {
    let mut out = vec![0x9a];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, present));
    out
}

/// A map header for `count` entries of distinct unsigned keys, each with a
/// zero value.
fn map_of_entries(count: u32) -> Vec<u8> {
    let mut out = vec![0xba];
    out.extend_from_slice(&count.to_be_bytes());
    for i in 0..count {
        out.push(0x1a);
        out.extend_from_slice(&i.to_be_bytes());
        out.push(0x00);
    }
    out
}

#[test]
fn items_count_against_macula_s_element_budget() {
    // The array itself is one item, so 131,071 zeros fill the budget.
    assert!(decode(&zeros_array(131_071, 131_071)).is_ok());
    assert_eq!(
        decode(&zeros_array(131_072, 131_072)),
        Err(DecodeError::TooManyElements)
    );
    // One array item and 65,536 map entries of two items each: the item past
    // the budget is a key.
    let mut past = vec![0x81];
    past.extend(map_of_entries(65_536));
    assert_eq!(decode(&past), Err(DecodeError::TooManyElements));
}
