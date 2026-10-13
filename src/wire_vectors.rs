//! The wire 1.0 conformance vectors (tests/vectors/wire_1_0/, macula#97,
//! copied unchanged from macula ef1cfe68's priv/vectors/wire_1_0/), as each
//! module's runner reads them: one file per class, its cases by id, and
//! typed JSON read back as CBOR values (FORMAT.md). Test-only.

#![allow(dead_code)]

use serde_json::Value as Json;

use crate::cbor::Value;

/// One class's file.
pub(crate) struct VectorFile {
    pub cases: Vec<Case>,
}

/// One case: its id, profile, input and expectation as written.
pub(crate) struct Case {
    pub id: String,
    pub profile: String,
    pub input: Json,
    pub expect: Json,
}

/// The file of `class`, `tests/vectors/wire_1_0/<class>.json`.
pub(crate) fn load(class: &str) -> VectorFile {
    let path = format!(
        "{}/tests/vectors/wire_1_0/{class}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let file: Json = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(file["wire"], "1.0", "{path}");
    assert_eq!(file["class"], class, "{path}");
    let cases = file["cases"]
        .as_array()
        .map(|cases| cases.iter().map(case).collect())
        .unwrap_or_default();
    VectorFile { cases }
}

/// The whole JSON of `class`, for the files that are not lists of cases
/// (keys.json).
pub(crate) fn load_json(class: &str) -> Json {
    let path = format!(
        "{}/tests/vectors/wire_1_0/{class}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The key of `role` in `profile` (keys.json), as carried.
pub(crate) fn key(profile: &str, role: &str) -> Vec<u8> {
    hex_of(&load_json("keys")["profiles"][profile][role]["key"])
}

/// The key id of `role` in `profile` (keys.json): the node_id for an
/// identity key, else its MACULA-KEY-ID-V1.
pub(crate) fn key_id(profile: &str, role: &str) -> [u8; 32] {
    hex_of(&load_json("keys")["profiles"][profile][role]["key_id"])
        .try_into()
        .unwrap()
}

fn case(c: &Json) -> Case {
    Case {
        id: c["id"].as_str().unwrap().to_owned(),
        profile: c["profile"].as_str().unwrap_or("both").to_owned(),
        input: c["input"].clone(),
        expect: c["expect"].clone(),
    }
}

impl Case {
    pub fn outcome(&self) -> &str {
        self.expect["outcome"].as_str().unwrap()
    }

    /// The refusal name, or "" when the case is not a refusal.
    pub fn reason(&self) -> &str {
        self.expect["reason"].as_str().unwrap_or("")
    }

    pub fn expect_text(&self, field: &str) -> &str {
        self.expect[field].as_str().unwrap_or("")
    }

    pub fn expect_int(&self, field: &str) -> Option<i64> {
        self.expect[field].as_i64()
    }

    pub fn text(&self, field: &str) -> &str {
        self.input[field].as_str().unwrap_or("")
    }

    pub fn int(&self, field: &str) -> Option<i64> {
        self.input[field].as_i64()
    }

    /// An input field of raw bytes, written as a lowercase hex string.
    pub fn hex(&self, field: &str) -> Vec<u8> {
        hex_of(&self.input[field])
    }

    pub fn has(&self, field: &str) -> bool {
        !self.input[field].is_null()
    }
}

/// Raw bytes written as a hex string.
pub(crate) fn hex_of(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// A typed JSON value read back as the CBOR value it stands for: a number
/// an integer, a string text, `{"$hex": ..}` bytes, an object a map with
/// text keys, an array a list, null null.
pub(crate) fn typed(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Number(n) => Value::Int(i128::from(n.as_i64().unwrap())),
        Json::String(s) => Value::text(s.as_str()),
        Json::Array(items) => Value::List(items.iter().map(typed).collect()),
        Json::Object(map) => match map.get("$hex") {
            Some(Json::String(h)) if map.len() == 1 => Value::Bytes(hex::decode(h).unwrap()),
            _ => Value::Map(
                map.iter()
                    .map(|(k, v)| (Value::text(k.as_str()), typed(v)))
                    .collect(),
            ),
        },
        Json::Bool(_) => panic!("the vectors carry no booleans"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_loads_with_unique_ids() {
        let mut seen = std::collections::HashSet::new();
        let classes = [
            "check_order",
            "custodian",
            "dht_procedures",
            "enums",
            "envelope",
            "frames",
            "handshake",
            "tbs",
            "verify",
        ];
        let files: Vec<VectorFile> = classes.iter().map(|class| load(class)).collect();
        assert!(files.iter().all(|f| !f.cases.is_empty()));
        for c in files.iter().flat_map(|f| &f.cases) {
            assert!(seen.insert(c.id.clone()), "{} twice", c.id);
        }
    }
}
