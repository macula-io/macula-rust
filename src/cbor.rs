//! Deterministic CBOR encode/decode, byte-for-byte compatible with
//! macula's own wire codec.
//!
//! This is NOT generic CBOR (no ciborium involved on either side) — it is
//! a direct Rust transcription of the hand-rolled canonical encoder macula
//! actually ships in `native/macula_cbor_nif/src/deterministic.rs`
//! (`macula-io/macula`), which `macula_frame.erl`'s wire codec calls as
//! `pack_deterministic/1` / `unpack_deterministic/1`. Every signed frame,
//! record and binding is signed over these exact bytes, so a divergence
//! here silently breaks signature verification against real stations —
//! this module's tests include fixtures captured directly from the real
//! NIF, not just hand-derived expectations.
//!
//! Encoding rules (all verified against the reference, see `tests` below):
//! - Integers: minimal-length encoding (inline for 0..=23, else the
//!   smallest of 1/2/4/8 extra bytes that fits). Non-negative → major 0.
//!   Negative → major 1, encoded value is `-1 - n`. Range:
//!   `-(2^64)..=u64::MAX` — anything outside that is a hard encode error,
//!   not silent truncation.
//! - Byte strings → major 2, raw bytes.
//! - Text → major 3. Used both for real text payloads and for macula's
//!   fixed field-name/enum-value vocabulary (what the Erlang side encodes
//!   as atoms) — there is no separate "atom" wire type.
//! - Lists → major 4.
//! - Maps → major 5, with keys sorted by the **bytewise order of their
//!   own already-encoded bytes** — encode each key independently, then
//!   sort the resulting `(key_bytes, value_bytes)` pairs by `key_bytes`
//!   using plain `Ord`. This is the single rule most likely to be gotten
//!   wrong: sorting by the *original* value instead of its *encoded*
//!   bytes silently diverges from station output for keys of different
//!   CBOR major types or different lengths.
//! - `Value::Null` → major 7, additional info 22 (`0xF6`).
//! - Floats → **always** binary64 (major 7, AI 27, `0xFB` prefix),
//!   regardless of whether the value would round-trip in fewer bits. This
//!   is a deliberate divergence from RFC 8949's own canonical-form
//!   recommendation (which prefers the shortest float width that
//!   round-trips) — macula's own comment says it's done so the byte
//!   derivation is independent of platform float encoding. A generic
//!   "canonical CBOR" crate that follows the RFC's shortest-float rule
//!   would silently produce non-matching, non-verifying bytes here.
//!
//! Decode applies macula 12's decoding rule, the rule every stack applies to
//! what a peer sends (`tests/cbor_decoding_rule.rs` holds it to the shared
//! vectors and to the reason macula's reference decoder gives for each
//! refusal): lengths in any width, map keys in any order but only text or
//! integers and never twice, integers within -2^63..=2^63-1, `null` and
//! finite half, single and double floats, at most [`MAX_NESTING_DEPTH`]
//! levels and [`MAX_ELEMENTS`] items. Tags, booleans and every other simple
//! value are refused. Every read is bounds-checked; nothing in this module
//! panics on malformed or truncated input, since decode exists specifically
//! to parse untrusted, network-received bytes.

use std::fmt;

/// A deterministic-CBOR value, restricted to exactly the shapes macula's
/// wire format supports. There is no generic "any CBOR" here on purpose.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Signed, but the encodable range is asymmetric: `-(2^64)..=u64::MAX`,
    /// matching the reference codec's own u64/i128 split.
    Int(i128),
    Bytes(Vec<u8>),
    /// Also what an Erlang atom (frame-type names, field names, enum
    /// values) becomes on the wire — see the module doc.
    Text(String),
    List(Vec<Value>),
    /// Insertion order on construction; canonical key sort happens at
    /// encode time, not here. Decode refuses a duplicate key.
    Map(Vec<(Value, Value)>),
    Null,
    /// Always round-trips through binary64 — see the module doc's note
    /// on why this diverges from RFC 8949's canonical-form guidance.
    Float(f64),
}

impl Value {
    /// Convenience: build a `Text` value from anything `Into<String>`.
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// Look up a field by text key. `None` if this isn't a `Map` or the
    /// key isn't present — mirrors macula's own field vocabulary, which
    /// is always text keys (see the module doc's atom/text note).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// A new `Map` with the given text keys removed. Non-maps pass
    /// through unchanged. Used to compute a frame's signable bytes (the
    /// frame minus `signature`/`publisher_sig`) — see `crate::frame`.
    pub fn without(&self, keys: &[&str]) -> Value {
        match self {
            Value::Map(pairs) => Value::Map(
                pairs
                    .iter()
                    .filter(|(k, _)| !matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
                    .cloned()
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Insert or replace a field in a `Map` by text key, consuming and
    /// returning `self` for chaining. A no-op on a non-map value.
    pub fn with_field(mut self, key: &str, value: Value) -> Value {
        if let Value::Map(pairs) = &mut self {
            match pairs
                .iter_mut()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
            {
                Some(entry) => entry.1 = value,
                None => pairs.push((Value::text(key), value)),
            }
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntOutOfRange(pub i128);

impl fmt::Display for IntOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "integer {} is outside the encodable range -(2^64)..=u64::MAX",
            self.0
        )
    }
}

impl std::error::Error for IntOutOfRange {}

/// Why [`decode`] refused an input: one variant for each reason macula's
/// reference decoder (`macula_record_cbor:decode_strict/1`) gives, so an input
/// is refused for the same reason in every stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Bytes after the top-level value.
    TrailingBytes,
    /// A map key that is neither text nor an integer.
    BadKey,
    /// A map key equal to an earlier key of its map: text with the same
    /// bytes, or an integer of the same value, in any width.
    DuplicateKey,
    /// Text that is not valid UTF-8.
    InvalidText,
    /// Arrays and maps nested more than [`MAX_NESTING_DEPTH`] levels.
    NestingTooDeep,
    /// An integer below -2^63 or above 2^63-1.
    IntegerOutOfRange,
    /// Input that holds more than [`MAX_ELEMENTS`] items.
    TooManyElements,
    /// Input that is not one complete item of what the rule allows: truncated
    /// input, an indefinite length, a tag, a simple value other than null, or
    /// a float that is NaN or infinite.
    Malformed,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecodeError::TrailingBytes => "bytes after the top-level value",
            DecodeError::BadKey => "a map key that is neither text nor an integer",
            DecodeError::DuplicateKey => "a duplicate map key",
            DecodeError::InvalidText => "text that is not valid UTF-8",
            DecodeError::NestingTooDeep => "arrays and maps nested more than 64 levels",
            DecodeError::IntegerOutOfRange => "an integer below -2^63 or above 2^63-1",
            DecodeError::TooManyElements => "more than 131072 items",
            DecodeError::Malformed => "malformed",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Encode `value` as deterministic CBOR. See the module doc for the exact
/// rules; every one of them is verified against the real reference in
/// this module's tests.
pub fn encode(value: &Value) -> Result<Vec<u8>, IntOutOfRange> {
    let mut out = Vec::with_capacity(64);
    encode_value(value, &mut out)?;
    Ok(out)
}

fn encode_value(value: &Value, out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    match value {
        Value::Int(n) => encode_int(*n, out),
        Value::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
            Ok(())
        }
        Value::Text(s) => {
            let bytes = s.as_bytes();
            encode_head(3, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        Value::List(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_value(item, out)?;
            }
            Ok(())
        }
        Value::Map(pairs) => encode_map(pairs, out),
        Value::Null => {
            out.push(0xF6); // major 7, additional info 22
            Ok(())
        }
        Value::Float(v) => {
            out.push(0xFB); // major 7, additional info 27 (binary64)
            out.extend_from_slice(&v.to_be_bytes());
            Ok(())
        }
    }
}

fn encode_int(n: i128, out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    if n >= 0 {
        if n <= u64::MAX as i128 {
            encode_head(0, n as u64, out);
            Ok(())
        } else {
            Err(IntOutOfRange(n))
        }
    } else {
        // n in -(2^64)..=-1 => count in 0..=2^64-1
        let count = -1i128 - n;
        if (0..=u64::MAX as i128).contains(&count) {
            encode_head(1, count as u64, out);
            Ok(())
        } else {
            Err(IntOutOfRange(n))
        }
    }
}

/// Encode each key/value independently, then sort the resulting pairs by
/// the key's OWN ENCODED BYTES (plain lexicographic `Ord` on `Vec<u8>`,
/// which already implements "shorter is smaller when a prefix" — no
/// special-casing needed). This is the one rule a naive implementation is
/// most likely to get wrong; see the module doc.
fn encode_map(pairs: &[(Value, Value)], out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let mut kbuf = Vec::with_capacity(16);
        encode_value(k, &mut kbuf)?;
        let mut vbuf = Vec::with_capacity(16);
        encode_value(v, &mut vbuf)?;
        encoded.push((kbuf, vbuf));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    encode_head(5, encoded.len() as u64, out);
    for (k, v) in &encoded {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    Ok(())
}

fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    if n <= 23 {
        out.push((major << 5) | (n as u8));
    } else if n <= 0xFF {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// How many arrays and maps may nest inside each other, the outermost
/// counted: 64 levels decode, and a 65th is refused, as in macula's decoding
/// rule.
pub const MAX_NESTING_DEPTH: usize = 64;

/// How many CBOR items one [`decode`] may read: every item counts once, the
/// top-level value, array elements, map keys and map values included. It is
/// macula's element budget, so an input macula refuses for the items it holds
/// is refused here too.
pub const MAX_ELEMENTS: usize = 131_072;

/// Decode `bytes` as exactly one value under macula's post-quantum decoding
/// rule, the rule every stack applies to what a peer sends. Lengths are
/// accepted in any width, map keys in any order, and half, single and double
/// floats; everything else the rule refuses is refused with the reason
/// macula's reference decoder gives. Every path returns an error rather than
/// panicking, since the input is untrusted.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut decoder = Decoder {
        data: bytes,
        pos: 0,
        budget: MAX_ELEMENTS,
    };
    let value = decoder.item(0)?;
    if decoder.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

/// Reads one value from `data`: `pos` is how far it has read, and `budget`
/// how many more items it may read.
struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    budget: usize,
}

/// A map key's identity under the rule: its text, or an integer's value.
#[derive(PartialEq, Eq, Hash)]
enum KeyId {
    Text(String),
    Int(i128),
}

/// The room a list or map is given before its elements decode: a declared
/// count is not checked against the input, so it is never trusted as an
/// allocation size.
const MAX_SIZE_HINT: usize = 4;

impl Decoder<'_> {
    /// The item at `pos`, which sits inside `depth` arrays and maps. As in
    /// macula's decoder, an item is counted against the budget once its head
    /// and argument have been read, and before its own checks.
    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let head = self.take(1)?[0];
        let (major, ai) = (head >> 5, head & 0x1F);
        if major == 7 {
            return self.simple_or_float(ai);
        }
        let arg = self.argument(ai)?;
        self.count()?;
        match major {
            0 => integer(i128::from(arg), arg),
            1 => integer(-1 - i128::from(arg), arg),
            2 => Ok(Value::Bytes(self.take(arg)?.to_vec())),
            3 => {
                let bytes = self.take(arg)?;
                std::str::from_utf8(bytes)
                    .map(|text| Value::Text(text.to_owned()))
                    .map_err(|_| DecodeError::InvalidText)
            }
            4 => self.list(arg, depth),
            5 => self.map(arg, depth),
            _ => Err(DecodeError::Malformed),
        }
    }

    /// Takes one item from the budget.
    fn count(&mut self) -> Result<(), DecodeError> {
        if self.budget == 0 {
            return Err(DecodeError::TooManyElements);
        }
        self.budget -= 1;
        Ok(())
    }

    /// The next `n` bytes of the input, moving past them.
    fn take(&mut self, n: u64) -> Result<&[u8], DecodeError> {
        let remaining = (self.data.len() - self.pos) as u64;
        if n > remaining {
            return Err(DecodeError::Malformed);
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.data[start..self.pos])
    }

    /// A head's argument, a value or a length: its additional information
    /// itself up to 23, or the 1, 2, 4 or 8 bytes after the head, in whichever
    /// width the sender chose. 28 to 31, every indefinite length among them,
    /// is malformed.
    fn argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
        let width = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(DecodeError::Malformed),
        };
        Ok(self
            .take(width)?
            .iter()
            .fold(0u64, |arg, &b| (arg << 8) | u64::from(b)))
    }

    /// Major type 7, counted once its bytes have been read: null, or a finite
    /// half, single or double float. Every other simple value, a boolean
    /// among them, is malformed.
    fn simple_or_float(&mut self, ai: u8) -> Result<Value, DecodeError> {
        match ai {
            22 => {
                self.count()?;
                Ok(Value::Null)
            }
            25..=27 => {
                let width = match ai {
                    25 => 2,
                    26 => 4,
                    _ => 8,
                };
                let bytes = self.take(width)?;
                let value = match bytes.len() {
                    2 => half_to_f64(u16::from_be_bytes([bytes[0], bytes[1]])),
                    4 => f64::from(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                    _ => f64::from_be_bytes(bytes.try_into().map_err(|_| DecodeError::Malformed)?),
                };
                self.count()?;
                if value.is_finite() {
                    Ok(Value::Float(value))
                } else {
                    Err(DecodeError::Malformed)
                }
            }
            0..=24 => {
                self.argument(ai)?;
                self.count()?;
                Err(DecodeError::Malformed)
            }
            _ => Err(DecodeError::Malformed),
        }
    }

    /// The room to give a list or map that declares `count` elements of at
    /// least `items_per_element` items and bytes each: at most the count,
    /// what the bytes and budget left could hold, and [`MAX_SIZE_HINT`], so
    /// what decoding allocates follows the bytes present.
    fn size_hint(&self, count: u64, items_per_element: usize) -> usize {
        let bytes_left = (self.data.len() - self.pos) / items_per_element;
        let budget_left = self.budget / items_per_element;
        count
            .min(bytes_left as u64)
            .min(budget_left as u64)
            .min(MAX_SIZE_HINT as u64) as usize
    }

    fn list(&mut self, count: u64, depth: usize) -> Result<Value, DecodeError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(DecodeError::NestingTooDeep);
        }
        let mut items = Vec::with_capacity(self.size_hint(count, 1));
        for _ in 0..count {
            items.push(self.item(depth + 1)?);
        }
        Ok(Value::List(items))
    }

    /// A map of `count` entries. Each entry's value decodes before its key is
    /// judged, as in the reference decoder, so an input that breaks two
    /// checks is refused for the same one in every stack. Duplicates are found
    /// through a hash set, so the work grows with the number of keys, not its
    /// square.
    fn map(&mut self, count: u64, depth: usize) -> Result<Value, DecodeError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(DecodeError::NestingTooDeep);
        }
        let hint = self.size_hint(count, 2);
        let mut pairs = Vec::with_capacity(hint);
        let mut seen = std::collections::HashSet::with_capacity(hint);
        for _ in 0..count {
            let key = self.item(depth + 1)?;
            let value = self.item(depth + 1)?;
            let id = match &key {
                Value::Text(text) => KeyId::Text(text.clone()),
                Value::Int(n) => KeyId::Int(*n),
                _ => return Err(DecodeError::BadKey),
            };
            if !seen.insert(id) {
                return Err(DecodeError::DuplicateKey);
            }
            pairs.push((key, value));
        }
        Ok(Value::Map(pairs))
    }
}

/// An integer head's value, refused when its argument puts it outside -2^63
/// to 2^63-1: an unsigned argument of 2^63 or more is above 2^63-1, and a
/// negative one of 2^63 or more is below -2^63.
fn integer(value: i128, arg: u64) -> Result<Value, DecodeError> {
    if arg >= 1 << 63 {
        return Err(DecodeError::IntegerOutOfRange);
    }
    Ok(Value::Int(value))
}

/// IEEE 754 binary16 to f64, infinities and NaN included; the caller refuses
/// what is not finite.
fn half_to_f64(half: u16) -> f64 {
    let sign = if half >> 15 == 1 { -1.0 } else { 1.0 };
    let exp = (half >> 10) & 0x1F;
    let frac = f64::from(half & 0x3FF);
    match exp {
        0 => sign * 2f64.powi(-24) * frac,
        31 if frac == 0.0 => sign * f64::INFINITY,
        31 => f64::NAN,
        _ => sign * 2f64.powi(i32::from(exp) - 15) * (1.0 + frac / 1024.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into bytes — test-only helper, not exposed
    /// from the crate.
    fn hex(s: &str) -> Vec<u8> {
        ::hex::decode(s).expect("valid hex fixture")
    }

    /// Every fixture below was captured directly from the real
    /// `macula_cbor_nif:pack_deterministic/1` in `macula-io/macula`
    /// (v10.10.0) via `rebar3 shell`, not hand-derived — see this
    /// module's doc comment. If one of these ever fails, the Rust port
    /// has diverged from what a real station actually accepts, not the
    /// test itself.
    fn assert_matches_reference(value: Value, expected_hex: &str) {
        let bytes = encode(&value).expect("encodable fixture");
        assert_eq!(
            bytes,
            hex(expected_hex),
            "encoding of {value:?} did not match the real macula_cbor_nif output"
        );
        // Round-trip: decoding what we just encoded must reproduce an
        // equivalent value (structural equality, not necessarily the
        // exact same Map key order — decode doesn't re-sort).
        let decoded = decode(&bytes).expect("our own output must decode");
        let re_encoded = encode(&decoded).expect("decoded value must re-encode");
        assert_eq!(re_encoded, bytes, "encode(decode(bytes)) != bytes");
    }

    #[test]
    fn empty_map() {
        assert_matches_reference(Value::Map(vec![]), "A0");
    }

    #[test]
    fn integers_non_negative_minimal_length() {
        assert_matches_reference(Value::Int(0), "00");
        assert_matches_reference(Value::Int(23), "17");
        assert_matches_reference(Value::Int(24), "1818");
        assert_matches_reference(Value::Int(255), "18FF");
        assert_matches_reference(Value::Int(256), "190100");
        assert_matches_reference(Value::Int(65535), "19FFFF");
        assert_matches_reference(Value::Int(65536), "1A00010000");
    }

    #[test]
    fn integers_negative_minimal_length() {
        assert_matches_reference(Value::Int(-1), "20");
        assert_matches_reference(Value::Int(-24), "37");
        assert_matches_reference(Value::Int(-25), "3818");
        assert_matches_reference(Value::Int(-256), "38FF");
    }

    #[test]
    fn integer_out_of_range_is_rejected() {
        // One past the documented positive bound.
        assert_eq!(
            encode(&Value::Int(u64::MAX as i128 + 1)),
            Err(IntOutOfRange(u64::MAX as i128 + 1))
        );
        // One past the documented negative bound (-(2^64)).
        let floor = -(1i128 << 64);
        assert!(encode(&Value::Int(floor)).is_ok());
        assert!(encode(&Value::Int(floor - 1)).is_err());
    }

    #[test]
    fn byte_strings() {
        assert_matches_reference(Value::Bytes(vec![]), "40");
        assert_matches_reference(Value::Bytes(b"hello".to_vec()), "4568656C6C6F");
    }

    #[test]
    fn text_and_atom_equivalent_encoding() {
        // "hello" as text, and the Erlang atom `true` (which the
        // reference encodes identically to a text value of the same
        // name) — both are just major-3 text on this wire format.
        assert_matches_reference(Value::text("hello"), "6568656C6C6F");
        assert_matches_reference(Value::text("true"), "6474727565");
    }

    #[test]
    fn lists() {
        assert_matches_reference(Value::List(vec![]), "80");
        assert_matches_reference(
            Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
            "83010203",
        );
    }

    #[test]
    fn floats_always_binary64() {
        // Even exactly-representable, "shortenable" values still emit
        // the full 8-byte form — the deliberate divergence from RFC
        // 8949's canonical-form recommendation. This is the fixture most
        // likely to catch a generic "canonical CBOR" crate substituted
        // in by mistake.
        assert_matches_reference(Value::Float(0.0), "FB0000000000000000");
        assert_matches_reference(Value::Float(12345.6789), "FB40C81CD6E631F8A1");
    }

    #[test]
    fn map_keys_sorted_by_encoded_bytes_not_input_order() {
        // Input order is b, a — output must be a, b (bytewise key sort).
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("b"), Value::Int(2)),
                (Value::text("a"), Value::Int(1)),
            ]),
            "A2616101616202",
        );
    }

    #[test]
    fn map_keys_sorted_lexicographically_same_length() {
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("zebra"), Value::Int(1)),
                (Value::text("apple"), Value::Int(2)),
            ]),
            "A2656170706C6502657A6562726101",
        );
    }

    #[test]
    fn map_keys_shorter_sorts_first_when_prefix() {
        // "a" < "aa" < "aaa" — the rule most likely to be implemented
        // wrong if a naive implementation sorts by raw value instead of
        // encoded bytes.
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("aa"), Value::Int(1)),
                (Value::text("a"), Value::Int(2)),
                (Value::text("aaa"), Value::Int(3)),
            ]),
            "A3616102626161016361616103",
        );
    }

    #[test]
    fn null_alone() {
        // The Erlang side special-cases exactly the atom named `null`
        // (0xF6) — a DIFFERENT atom like `undefined` is not recognized at
        // this layer and encodes as ordinary text instead (see
        // `text_and_atom_equivalent_encoding` and this module's doc: the
        // `undefined` -> `null` conversion happens one layer up, in
        // `macula_frame.erl`'s `to_wire/1`, not inside the codec itself).
        assert_matches_reference(Value::Null, "F6");
    }

    #[test]
    fn nested_structure_with_null() {
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("name"), Value::text("macula")),
                (
                    Value::text("nums"),
                    Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
                ),
                (Value::text("nil"), Value::Null),
            ]),
            "A3636E696CF6646E616D65666D6163756C61646E756D7383010203",
        );
    }

    #[test]
    fn frame_shaped_map() {
        let node_id: Vec<u8> = (1u8..=32).collect();
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("node_id"), Value::Bytes(node_id)),
                (Value::text("version"), Value::Int(2)),
                (Value::text("frame_type"), Value::text("connect")),
                (Value::text("capabilities"), Value::Int(0)),
            ]),
            "A4676E6F64655F696458200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F206776657273696F6E026A6672616D655F7479706567636F6E6E6563746C6361706162696C697469657300",
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // A valid `0` (0x00) followed by a stray byte.
        assert_eq!(decode(&[0x00, 0xFF]), Err(DecodeError::TrailingBytes));
    }

    /// Regression guard for a real bug: `decode_map`'s duplicate-key
    /// check used to be a `Value`-equality linear scan over every entry
    /// decoded so far, making decode O(n^2) in entry count. A single
    /// ~350 KB crafted map (well under `frame::MAX_FRAME_BYTES`) took
    /// 50+ seconds to decode as a result -- confirmed empirically against
    /// the pre-fix code, not just reasoned about. This decodes twice as
    /// many entries in a fraction of a second; if the map's dedup
    /// regresses to linear-scan behavior, this test will time out long
    /// before it fails its assertions.
    #[test]
    fn decode_map_with_many_distinct_keys_is_not_quadratic() {
        let n: i128 = 20_000;
        let pairs: Vec<(Value, Value)> = (0..n).map(|i| (Value::Int(i), Value::Int(0))).collect();
        let bytes = encode(&Value::Map(pairs)).expect("encodable");

        let start = std::time::Instant::now();
        let decoded = decode(&bytes).expect("valid map");
        let elapsed = start.elapsed();

        match decoded {
            Value::Map(decoded_pairs) => assert_eq!(decoded_pairs.len(), n as usize),
            other => panic!("expected a map, got {other:?}"),
        }
        // The fixed decoder does this in low single-digit milliseconds;
        // the old O(n^2) scan took whole seconds at this size. A wide
        // margin avoids CI flakiness while still failing fast on a
        // real complexity regression.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "decoding {n} distinct-keyed entries took {elapsed:?} -- \
             looks like decode_map regressed to O(n^2)"
        );
    }

    #[test]
    fn get_finds_a_field_by_text_key() {
        let map = Value::Map(vec![(Value::text("a"), Value::Int(1))]);
        assert_eq!(map.get("a"), Some(&Value::Int(1)));
        assert_eq!(map.get("missing"), None);
    }

    #[test]
    fn get_on_a_non_map_is_none() {
        assert_eq!(Value::Int(1).get("a"), None);
    }

    #[test]
    fn without_removes_only_the_named_keys() {
        let map = Value::Map(vec![
            (Value::text("a"), Value::Int(1)),
            (Value::text("b"), Value::Int(2)),
            (Value::text("c"), Value::Int(3)),
        ]);
        let stripped = map.without(&["b"]);
        assert_eq!(stripped.get("a"), Some(&Value::Int(1)));
        assert_eq!(stripped.get("b"), None);
        assert_eq!(stripped.get("c"), Some(&Value::Int(3)));
    }

    #[test]
    fn with_field_replaces_an_existing_key_in_place() {
        let map =
            Value::Map(vec![(Value::text("a"), Value::Int(1))]).with_field("a", Value::Int(2));
        assert_eq!(map.get("a"), Some(&Value::Int(2)));
        // Replacing, not appending — still exactly one pair.
        match map {
            Value::Map(pairs) => assert_eq!(pairs.len(), 1),
            _ => panic!("expected a map"),
        }
    }

    #[test]
    fn with_field_appends_a_new_key() {
        let map = Value::Map(vec![]).with_field("a", Value::Int(1));
        assert_eq!(map.get("a"), Some(&Value::Int(1)));
    }
}
