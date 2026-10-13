//! The DHT, as macula 12's facade reaches it: station procedures on the zero
//! realm, targeting the connected station, carrying record wire bytes. Every
//! record found is verified here before it is handed on, and one that does
//! not verify is dropped and counted.

use crate::cbor::Value;
use crate::record::{self, RecordType, Verified};

use crate::profile::Profile;

use super::{now_ms, Call, Link, LinkError};

/// The version of every `_dht.*` argument and reply form (WIRE_1_0.md
/// section 6).
const DHT_V: i128 = 1;

/// The longest refusal reason a refused put names.
const MAX_REASON_BYTES: usize = 64;

/// A `_dht.*` reply as a caller reads it.
#[derive(Debug, Clone, PartialEq)]
enum DhtReply {
    /// `_dht.put_record` stored the record.
    Stored,
    /// `_dht.put_record` refused it, by the custodian's refusal name.
    Refused(String),
    /// `_dht.find_record` found a record, as its wire bytes.
    Record(Vec<u8>),
    /// `_dht.find_record` found none.
    NotFound,
    /// `_dht.find_records` or `_dht.find_records_by_type`: the records, as
    /// their wire bytes, perhaps none.
    Records(Vec<Vec<u8>>),
}

/// Why a caller refused a `_dht.*` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyRefusal {
    /// A `v` other than 1 (`reply_version_unsupported`).
    VersionUnsupported,
    /// A missing or extra key, a field of the wrong type or length, or a
    /// result `procedure` never answers with (`malformed_reply`).
    Malformed,
}

impl From<ReplyRefusal> for LinkError {
    fn from(refusal: ReplyRefusal) -> LinkError {
        match refusal {
            ReplyRefusal::VersionUnsupported => LinkError::ReplyVersionUnsupported,
            ReplyRefusal::Malformed => LinkError::UnexpectedReply("malformed_reply".into()),
        }
    }
}

/// Reads `procedure`'s reply: a map with text keys, `v` 1, and exactly the
/// keys of one of the procedure's results, each of its type.
fn read_reply(procedure: &str, reply: &Value) -> Result<DhtReply, ReplyRefusal> {
    let Value::Map(pairs) = reply else {
        return Err(ReplyRefusal::Malformed);
    };
    match reply.get("v") {
        Some(Value::Int(DHT_V)) => {}
        Some(Value::Int(_)) => return Err(ReplyRefusal::VersionUnsupported),
        _ => return Err(ReplyRefusal::Malformed),
    }
    let result = match reply.get("result") {
        Some(Value::Text(r)) => r.as_str(),
        _ => return Err(ReplyRefusal::Malformed),
    };
    let read = match (procedure, result) {
        ("_dht.put_record", "ok") => Some((2, DhtReply::Stored)),
        ("_dht.put_record", "refused") => match reply.get("reason") {
            Some(Value::Text(r)) if r.len() <= MAX_REASON_BYTES => {
                Some((3, DhtReply::Refused(r.clone())))
            }
            _ => None,
        },
        ("_dht.find_record", "record") => match reply.get("record") {
            Some(Value::Bytes(wire)) => Some((3, DhtReply::Record(wire.clone()))),
            _ => None,
        },
        ("_dht.find_record", "not_found") => Some((2, DhtReply::NotFound)),
        ("_dht.find_records" | "_dht.find_records_by_type", "records") => {
            record_list(reply.get("records")).map(|records| (3, DhtReply::Records(records)))
        }
        _ => None,
    };
    match read {
        Some((size, reply)) if pairs.len() == size => Ok(reply),
        _ => Err(ReplyRefusal::Malformed),
    }
}

/// A `records` field: a list of byte strings, perhaps empty.
fn record_list(v: Option<&Value>) -> Option<Vec<Vec<u8>>> {
    let Some(Value::List(items)) = v else {
        return None;
    };
    items
        .iter()
        .map(|item| match item {
            Value::Bytes(wire) => Some(wire.clone()),
            _ => None,
        })
        .collect()
}

/// A `_dht.*` argument form: `v` 1 and one field.
fn dht_args(name: &str, value: Value) -> Value {
    Value::Map(vec![
        (Value::text("v"), Value::Int(DHT_V)),
        (Value::text(name), value),
    ])
}

impl Link {
    /// Stores a signed record, as its wire bytes, in the station's DHT. A
    /// station that refuses it names the custodian's refusal
    /// ([`LinkError::RecordRefused`]).
    pub async fn put_record(&self, wire: &[u8]) -> Result<(), LinkError> {
        let args = dht_args("record", Value::Bytes(wire.to_vec()));
        match self.dht_call("_dht.put_record", args).await? {
            DhtReply::Stored => Ok(()),
            DhtReply::Refused(reason) => Err(LinkError::RecordRefused(reason)),
            _ => Err(ReplyRefusal::Malformed.into()),
        }
    }

    /// The record stored under `key`, verified as a reader verifies it.
    pub async fn find_record(&self, key: &[u8; 32]) -> Result<Verified, LinkError> {
        let args = dht_args("key", Value::Bytes(key.to_vec()));
        match self.dht_call("_dht.find_record", args).await? {
            DhtReply::NotFound => Err(LinkError::RecordNotFound),
            DhtReply::Record(wire) => Ok(record::verify(&wire, self.profile(), now_ms())?),
            _ => Err(ReplyRefusal::Malformed.into()),
        }
    }

    /// Every record stored under `key` that verifies, and how many the
    /// station returned that did not.
    pub async fn find_records(&self, key: &[u8; 32]) -> Result<(Vec<Verified>, usize), LinkError> {
        let args = dht_args("key", Value::Bytes(key.to_vec()));
        self.verified_list("_dht.find_records", args).await
    }

    /// Every record of type `t` the station holds that verifies, and how many
    /// it returned that did not.
    pub async fn find_records_by_type(
        &self,
        t: RecordType,
    ) -> Result<(Vec<Verified>, usize), LinkError> {
        let args = dht_args("type", Value::Int(i128::from(t.0)));
        self.verified_list("_dht.find_records_by_type", args).await
    }

    async fn verified_list(
        &self,
        procedure: &str,
        args: Value,
    ) -> Result<(Vec<Verified>, usize), LinkError> {
        let DhtReply::Records(records) = self.dht_call(procedure, args).await? else {
            return Err(ReplyRefusal::Malformed.into());
        };
        Ok(verified_records(&records, self.profile(), now_ms()))
    }

    async fn dht_call(&self, procedure: &str, args: Value) -> Result<DhtReply, LinkError> {
        let reply = self
            .call(Call {
                procedure: procedure.to_string(),
                payload: args,
                ..Call::default()
            })
            .await?;
        Ok(read_reply(procedure, &reply)?)
    }
}

/// The records that verify as a reader verifies them, and how many did not.
fn verified_records(records: &[Vec<u8>], profile: Profile, now: i64) -> (Vec<Verified>, usize) {
    let verified: Vec<Verified> = records
        .iter()
        .filter_map(|wire| record::verify(wire, profile, now).ok())
        .collect();
    let dropped = records.len() - verified.len();
    (verified, dropped)
}

#[cfg(test)]
mod tests {
    //! The wire 1.0 `_dht.*` vectors (macula#102): the argument forms this
    //! crate sends are the accepted ones, byte for byte, and each reply reads
    //! as a caller reads it.

    use super::*;
    use crate::cbor;
    use crate::wire_vectors::{self, Case};

    /// The argument form this crate sends for an accepted case's call.
    fn sent_args(c: &Case, args: &Value) -> Value {
        match c.text("procedure") {
            "_dht.put_record" => dht_args("record", args.get("record").unwrap().clone()),
            "_dht.find_records_by_type" => dht_args("type", args.get("type").unwrap().clone()),
            _ => dht_args("key", args.get("key").unwrap().clone()),
        }
    }

    fn reply_verdict(c: &Case) -> (String, String, Option<usize>) {
        let reply = cbor::decode(&c.hex("reply")).unwrap();
        let profile = Profile::parse("pq_pure").unwrap();
        match read_reply(c.text("procedure"), &reply) {
            Err(ReplyRefusal::VersionUnsupported) => {
                ("refuse".into(), "reply_version_unsupported".into(), None)
            }
            Err(ReplyRefusal::Malformed) => ("refuse".into(), "malformed_reply".into(), None),
            Ok(DhtReply::Stored) => ("accept".into(), "ok".into(), None),
            Ok(DhtReply::Refused(_)) => ("accept".into(), "refused".into(), None),
            Ok(DhtReply::Record(_)) => ("accept".into(), "record".into(), None),
            Ok(DhtReply::NotFound) => ("accept".into(), "not_found".into(), None),
            Ok(DhtReply::Records(records)) => {
                let kept = verified_records(&records, profile, c.int("now_ms").unwrap())
                    .0
                    .len();
                ("accept".into(), "records".into(), Some(kept))
            }
        }
    }

    #[test]
    fn the_wire_1_0_dht_vectors() {
        let file = wire_vectors::load("dht_procedures");
        let accepted_args = file
            .cases
            .iter()
            .filter(|c| c.has("args") && c.outcome() == "accept");
        for c in accepted_args {
            let args = cbor::decode(&c.hex("args")).unwrap();
            assert_eq!(
                cbor::encode(&sent_args(c, &args)).unwrap(),
                c.hex("args"),
                "{}",
                c.id
            );
        }
        for c in file.cases.iter().filter(|c| c.has("reply")) {
            let (outcome, said, kept) = reply_verdict(c);
            let want = match c.outcome() {
                "accept" => c.expect_text("result"),
                _ => c.reason(),
            };
            assert_eq!(
                (outcome.as_str(), said.as_str()),
                (c.outcome(), want),
                "{}",
                c.id
            );
            let want_kept = c.expect_int("records_kept").map(|n| n as usize);
            assert!(
                want_kept.is_none() || kept == want_kept,
                "{}: records kept",
                c.id
            );
        }
    }
}
