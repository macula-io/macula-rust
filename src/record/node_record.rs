//! Node records: a node's statement of the realms it serves, its
//! capabilities and where it is, signed by the node and stored under its
//! node_id. Coordinates travel as text with at most 6 decimals and no
//! trailing zeros, stable across stacks where float encodings are not.

use crate::cbor::Value;

use super::{entry, id_field, malformed, text_field, unsigned, Record, RecordError, RecordType};

const MAX_GEO_TEXT_BYTES: usize = 32;
const LAT_BOUND: f64 = 90.0;
const LNG_BOUND: f64 = 180.0;

/// A node record's optional fields: `station_id` is `None` for the node
/// itself; empty text and `None` coordinates are left out; `kind` is
/// "station" or "daemon"; `peers` are kept sorted and once each; `ttl_ms` is
/// 0 for the default, 48 hours.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeRecordOptions {
    pub station_id: Option<[u8; 32]>,
    pub caps_hint: String,
    pub display_name: String,
    pub hostname: String,
    pub endpoint: String,
    pub city: String,
    pub country: String,
    pub lat: Option<f64>,
    pub lng: Option<f64>,
    pub kind: String,
    pub peers: Vec<[u8; 32]>,
    pub ttl_ms: u64,
}

/// An unsigned node record about `node_id`, which signs it. A coordinate out
/// of its range, or NaN, is refused.
pub fn new_node_record(
    node_id: &[u8; 32],
    realms: &[[u8; 32]],
    capabilities: u64,
    opts: &NodeRecordOptions,
) -> Result<Record, RecordError> {
    let mut entries = vec![
        entry("node_id", Value::Bytes(node_id.to_vec())),
        entry(
            "station_id",
            Value::Bytes(opts.station_id.unwrap_or(*node_id).to_vec()),
        ),
        entry("realms", id_list(realms)),
        entry("capabilities", Value::Int(i128::from(capabilities))),
    ];
    for (name, value) in [
        ("caps_hint", &opts.caps_hint),
        ("display_name", &opts.display_name),
        ("hostname", &opts.hostname),
        ("endpoint", &opts.endpoint),
        ("city", &opts.city),
        ("country", &opts.country),
        ("kind", &opts.kind),
    ] {
        if !value.is_empty() {
            entries.push(entry(name, Value::text(value.clone())));
        }
    }
    for (name, value, bound) in [("lat", opts.lat, LAT_BOUND), ("lng", opts.lng, LNG_BOUND)] {
        let Some(v) = value else { continue };
        if v.is_nan() || v.abs() > bound {
            return Err(RecordError::InvalidCoordinate(format!("{name} {v}")));
        }
        entries.push(entry(name, Value::text(geo_text(v))));
    }
    let mut peers = opts.peers.clone();
    peers.sort_unstable();
    peers.dedup();
    if !peers.is_empty() {
        entries.push(entry("peers", id_list(&peers)));
    }
    Ok(unsigned(
        RecordType::NODE_RECORD,
        Value::Map(entries),
        opts.ttl_ms,
    ))
}

/// A node record's payload, as macula_record reads it. A field left out, or
/// of another kind, is zero, empty or `None`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeRecord {
    pub node_id: [u8; 32],
    pub station_id: [u8; 32],
    pub realms: Vec<[u8; 32]>,
    pub capabilities: u64,
    pub kind: String,
    pub hostname: String,
    pub endpoint: String,
    pub city: String,
    pub country: String,
    pub lat: Option<f64>,
    pub lng: Option<f64>,
    pub display_name: String,
    pub caps_hint: String,
    pub peers: Vec<[u8; 32]>,
    pub version: String,
}

/// Reads a node record's payload.
pub fn read_node_record(r: &Record) -> Result<NodeRecord, RecordError> {
    if r.record_type != RecordType::NODE_RECORD {
        return Err(malformed("not a node record"));
    }
    let p = &r.payload;
    Ok(NodeRecord {
        node_id: id_field(p, "node_id"),
        station_id: id_field(p, "station_id"),
        realms: read_ids(p.get("realms")),
        capabilities: match p.get("capabilities") {
            Some(Value::Int(n)) if *n >= 0 => u64::try_from(*n).unwrap_or(0),
            _ => 0,
        },
        kind: text_field(p, "kind"),
        hostname: text_field(p, "hostname"),
        endpoint: text_field(p, "endpoint"),
        city: text_field(p, "city"),
        country: text_field(p, "country"),
        lat: parse_geo(&text_field(p, "lat"), LAT_BOUND),
        lng: parse_geo(&text_field(p, "lng"), LNG_BOUND),
        display_name: text_field(p, "display_name"),
        caps_hint: text_field(p, "caps_hint"),
        peers: read_ids(p.get("peers")),
        version: text_field(p, "version"),
    })
}

/// A coordinate as macula renders one: 6 decimals, trailing zeros cut,
/// keeping one digit after the point.
fn geo_text(v: f64) -> String {
    let s = format!("{v:.6}");
    let s = s.trim_end_matches('0');
    if s.ends_with('.') {
        format!("{s}0")
    } else {
        s.to_string()
    }
}

/// A coordinate's text as macula_record's parse_geo/2 reads it: at most 32
/// bytes, an optional leading minus, digits, then optionally a dot and
/// digits, within `bound` of zero.
fn parse_geo(s: &str, bound: f64) -> Option<f64> {
    if s.len() > MAX_GEO_TEXT_BYTES {
        return None;
    }
    let unsigned = s.strip_prefix('-').unwrap_or(s);
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (unsigned, None),
    };
    let digits = |d: &str| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || fraction.is_some_and(|f| !digits(f)) {
        return None;
    }
    let v: f64 = s.parse().ok()?;
    if v.abs() > bound {
        return None;
    }
    Some(if v == 0.0 && fraction.is_none() {
        0.0
    } else {
        v
    })
}

fn id_list(ids: &[[u8; 32]]) -> Value {
    Value::List(ids.iter().map(|id| Value::Bytes(id.to_vec())).collect())
}

fn read_ids(v: Option<&Value>) -> Vec<[u8; 32]> {
    match v {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Bytes(b) => b.as_slice().try_into().ok(),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
