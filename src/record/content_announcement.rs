//! Content announcements (macula 12.6.0, D27): a node's statement that it
//! shares the content with a tag 2 content id, served on its content
//! procedure in a realm and reachable through a station.

use crate::cbor::Value;

use super::{
    entry, id_field, malformed, payload::is_content_id, text_field, unsigned, Record, RecordError,
    RecordType,
};

/// Where the content is served, then its name, size and chunk count, each
/// left out when empty or `None`; `ttl_ms`, 0 for the default, 48 hours.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentAnnouncementOptions {
    pub realm_id: [u8; 32],
    pub serving_station: [u8; 32],
    pub procedure: String,
    pub name: String,
    pub size: Option<u64>,
    pub chunk_count: Option<u64>,
    pub ttl_ms: u64,
}

/// An unsigned announcement by `announcer_node`, which signs it. A content id
/// of another size or tag, or an empty procedure, is refused.
pub fn new_content_announcement(
    announcer_node: &[u8; 32],
    mcid: &[u8],
    opts: &ContentAnnouncementOptions,
) -> Result<Record, RecordError> {
    if !is_content_id(Some(&Value::Bytes(mcid.to_vec()))) {
        return Err(RecordError::NotAContentId);
    }
    if opts.procedure.is_empty() {
        return Err(malformed(
            "a content announcement names its content procedure",
        ));
    }
    let mut entries = vec![
        entry("announcer_node", Value::Bytes(announcer_node.to_vec())),
        entry("mcid", Value::Bytes(mcid.to_vec())),
        entry("realm_id", Value::Bytes(opts.realm_id.to_vec())),
        entry(
            "serving_station",
            Value::Bytes(opts.serving_station.to_vec()),
        ),
        entry("procedure", Value::text(opts.procedure.clone())),
    ];
    if !opts.name.is_empty() {
        entries.push(entry("name", Value::text(opts.name.clone())));
    }
    if let Some(size) = opts.size {
        entries.push(entry("size", Value::Int(i128::from(size))));
    }
    if let Some(chunks) = opts.chunk_count {
        entries.push(entry("chunk_count", Value::Int(i128::from(chunks))));
    }
    Ok(unsigned(
        RecordType::CONTENT_ANNOUNCEMENT,
        Value::Map(entries),
        opts.ttl_ms,
    ))
}

/// A content announcement's payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentAnnouncement {
    pub announcer_node: [u8; 32],
    pub mcid: Vec<u8>,
    pub realm_id: [u8; 32],
    pub serving_station: [u8; 32],
    pub procedure: String,
    pub name: String,
    pub size: Option<u64>,
    pub chunk_count: Option<u64>,
}

/// Reads a content announcement's payload.
pub fn read_content_announcement(r: &Record) -> Result<ContentAnnouncement, RecordError> {
    if r.record_type != RecordType::CONTENT_ANNOUNCEMENT {
        return Err(malformed("not a content announcement"));
    }
    let p = &r.payload;
    let optional = |name: &str| match p.get(name) {
        Some(Value::Int(n)) if *n >= 0 => u64::try_from(*n).ok(),
        _ => None,
    };
    Ok(ContentAnnouncement {
        announcer_node: id_field(p, "announcer_node"),
        mcid: match p.get("mcid") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => Vec::new(),
        },
        realm_id: id_field(p, "realm_id"),
        serving_station: id_field(p, "serving_station"),
        procedure: text_field(p, "procedure"),
        name: text_field(p, "name"),
        size: optional("size"),
        chunk_count: optional("chunk_count"),
    })
}
