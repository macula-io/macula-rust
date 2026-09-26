//! Station endpoints: where a station is dialled, signed by the station and
//! stored under its node_id's station endpoint key.

use crate::cbor::Value;

use super::{entry, malformed, unsigned, Record, RecordError, RecordType};

/// A station endpoint's optional fields: the hosts it is dialled at, left
/// out when none; its ALPN, left out when empty; `ttl_ms`, 0 for the default
/// and maximum, 5 minutes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StationEndpointOptions {
    pub host_advertised: Vec<String>,
    pub alpn: String,
    pub ttl_ms: u64,
}

/// An unsigned record of a station's dialable endpoint. A QUIC port of 0 is
/// refused.
pub fn new_station_endpoint(
    quic_port: u16,
    opts: &StationEndpointOptions,
) -> Result<Record, RecordError> {
    if quic_port == 0 {
        return Err(RecordError::InvalidPort);
    }
    let mut entries = vec![entry("quic_port", Value::Int(i128::from(quic_port)))];
    if !opts.host_advertised.is_empty() {
        entries.push(entry(
            "host_advertised",
            Value::List(
                opts.host_advertised
                    .iter()
                    .map(|h| Value::Bytes(h.as_bytes().to_vec()))
                    .collect(),
            ),
        ));
    }
    if !opts.alpn.is_empty() {
        entries.push(entry("alpn", Value::text(opts.alpn.clone())));
    }
    Ok(unsigned(
        RecordType::STATION_ENDPOINT,
        Value::Map(entries),
        opts.ttl_ms,
    ))
}

/// A station endpoint's payload: its QUIC port, 0 when it carries none from
/// 1 to 65535, and the hosts it is dialled at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StationEndpoint {
    pub quic_port: u16,
    pub host_advertised: Vec<String>,
}

/// Reads a station endpoint's payload.
pub fn read_station_endpoint(r: &Record) -> Result<StationEndpoint, RecordError> {
    if r.record_type != RecordType::STATION_ENDPOINT {
        return Err(malformed("not a station endpoint"));
    }
    let quic_port = match r.payload.get("quic_port") {
        Some(Value::Int(n)) if (1..=65535).contains(n) => *n as u16,
        _ => 0,
    };
    Ok(StationEndpoint {
        quic_port,
        host_advertised: host_list(r.payload.get("host_advertised")),
    })
}

/// host_advertised as macula_record's host_list/1 reads it: a list of hosts
/// or a single host, each as bytes or text.
fn host_list(v: Option<&Value>) -> Vec<String> {
    let items: Vec<&Value> = match v {
        None => return Vec::new(),
        Some(Value::List(items)) => items.iter().collect(),
        Some(single) => vec![single],
    };
    items
        .into_iter()
        .filter_map(|item| match item {
            Value::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Value::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}
