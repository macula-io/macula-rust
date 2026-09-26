//! The DHT, as macula 12's facade reaches it: station procedures on the zero
//! realm, targeting the connected station, carrying record wire bytes. Every
//! record found is verified here before it is handed on, and one that does
//! not verify is dropped and counted.

use crate::cbor::Value;
use crate::record::{self, RecordType, Verified};

use super::{now_ms, Call, Link, LinkError};

impl Link {
    /// Stores a signed record, as its wire bytes, in the station's DHT.
    pub async fn put_record(&self, wire: &[u8]) -> Result<(), LinkError> {
        let result = self
            .dht_call("_dht.put_record", Value::Bytes(wire.to_vec()))
            .await?;
        match result {
            Value::Text(t) if t == "ok" => Ok(()),
            other => Err(LinkError::UnexpectedReply(format!(
                "put_record answered {other:?}"
            ))),
        }
    }

    /// The record stored under `key`, verified.
    pub async fn find_record(&self, key: &[u8; 32]) -> Result<Verified, LinkError> {
        match self.dht_call("_dht.find_record", key_payload(key)).await? {
            Value::Text(t) if t == "not_found" => Err(LinkError::RecordNotFound),
            Value::Bytes(wire) => Ok(record::verify(&wire, self.profile(), now_ms())?),
            other => Err(LinkError::UnexpectedReply(format!(
                "find_record answered {other:?}"
            ))),
        }
    }

    /// Every record stored under `key` that verifies, and how many the
    /// station returned that did not.
    pub async fn find_records(&self, key: &[u8; 32]) -> Result<(Vec<Verified>, usize), LinkError> {
        self.verified_list("_dht.find_records", key_payload(key))
            .await
    }

    /// Every record of type `t` the station holds that verifies, and how many
    /// it returned that did not.
    pub async fn find_records_by_type(
        &self,
        t: RecordType,
    ) -> Result<(Vec<Verified>, usize), LinkError> {
        let payload = Value::Map(vec![(Value::text("type"), Value::Int(i128::from(t.0)))]);
        self.verified_list("_dht.find_records_by_type", payload)
            .await
    }

    async fn verified_list(
        &self,
        procedure: &str,
        payload: Value,
    ) -> Result<(Vec<Verified>, usize), LinkError> {
        let Value::List(items) = self.dht_call(procedure, payload).await? else {
            return Err(LinkError::UnexpectedReply(format!(
                "{procedure} answered no list"
            )));
        };
        let now = now_ms();
        let mut verified = Vec::with_capacity(items.len());
        let mut dropped = 0;
        for item in items {
            match item {
                Value::Bytes(wire) => match record::verify(&wire, self.profile(), now) {
                    Ok(r) => verified.push(r),
                    Err(_) => dropped += 1,
                },
                _ => dropped += 1,
            }
        }
        Ok((verified, dropped))
    }

    async fn dht_call(&self, procedure: &str, payload: Value) -> Result<Value, LinkError> {
        self.call(Call {
            procedure: procedure.to_string(),
            payload,
            ..Call::default()
        })
        .await
    }
}

fn key_payload(key: &[u8; 32]) -> Value {
    Value::Map(vec![(Value::text("key"), Value::Bytes(key.to_vec()))])
}
