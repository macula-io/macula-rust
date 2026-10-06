//! A token part's JSON object as Erlang's json decodes one: a key written
//! twice keeps its FIRST value, at every depth (OTP's object_finish is
//! maps:from_list over the reversed pairs). serde_json keeps the last, so a
//! signed `{"exp":1,"exp":<later>}` would be expired in macula and valid
//! here; every part is read through these instead.

use std::collections::HashMap;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Number, Value};

/// `json` as one JSON object, its keys first-wins at every depth; `None`
/// for anything else, trailing data included.
pub(super) fn object(json: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice::<FirstWins>(json).ok()?.0 {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// `json`'s top-level values as written, first-wins, so a number is judged
/// by its text; `None` when it is not one JSON object.
pub(super) fn written(json: &[u8]) -> Option<HashMap<String, Box<RawValue>>> {
    serde_json::from_slice::<Written>(json).ok().map(|w| w.0)
}

struct FirstWins(Value);

impl<'de> Deserialize<'de> for FirstWins {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(FirstWinsVisitor)
    }
}

struct FirstWinsVisitor;

impl<'de> Visitor<'de> for FirstWinsVisitor {
    type Value = FirstWins;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::Number(v.into())))
    }

    fn visit_u64<E>(self, v: u64) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::Number(v.into())))
    }

    fn visit_f64<E>(self, v: f64) -> Result<FirstWins, E> {
        Ok(FirstWins(
            Number::from_f64(v).map_or(Value::Null, Value::Number),
        ))
    }

    fn visit_str<E>(self, v: &str) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::String(v.to_owned())))
    }

    fn visit_string<E>(self, v: String) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::Null))
    }

    fn visit_none<E>(self) -> Result<FirstWins, E> {
        Ok(FirstWins(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<FirstWins, A::Error> {
        let mut items = Vec::new();
        while let Some(FirstWins(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(FirstWins(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FirstWins, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let FirstWins(value) = map.next_value()?;
            object.entry(key).or_insert(value);
        }
        Ok(FirstWins(Value::Object(object)))
    }
}

struct Written(HashMap<String, Box<RawValue>>);

impl<'de> Deserialize<'de> for Written {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(WrittenVisitor)
    }
}

struct WrittenVisitor;

impl<'de> Visitor<'de> for WrittenVisitor {
    type Value = Written;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Written, A::Error> {
        let mut written = HashMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value: Box<RawValue> = map.next_value()?;
            written.entry(key).or_insert(value);
        }
        Ok(Written(written))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_written_twice_keeps_its_first_value_at_every_depth() {
        let parsed = object(br#"{"exp":1,"exp":2,"cap":[{"can":"a","can":"b"}]}"#).unwrap();
        assert_eq!(parsed["exp"], 1);
        assert_eq!(parsed["cap"][0]["can"], "a");
        let raw = written(br#"{"exp":1,"exp":2}"#).unwrap();
        assert_eq!(raw["exp"].get(), "1");
    }

    #[test]
    fn only_one_object_is_a_part() {
        for bad in [&b"[]"[..], b"null", b"1", b"{} {}", b"{", b"\"x\""] {
            assert_eq!(object(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(written(b"[]"), None);
        assert!(object(b" {} ").is_some());
    }
}
