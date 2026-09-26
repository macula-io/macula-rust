//! Neighbour signatures (D17). In pq_hybrid a control frame travels as
//! `{version, frame_type, neighbour}`: `neighbour` is a held signed object
//! under MACULA-PQ-NEIGHBOUR-V1 by the sender's identity key, which the
//! receiver holds from the handshake. Its tbs holds the frame's fields
//! (without version), alg, the connection hash (the SHA-384 of the CHALLENGE
//! frame's bytes) and seq: 0 on the first neighbour-signed frame in each
//! direction, one more on each after. In pq_pure no frame carries one.
//!
//! The builders here are the control frames a client link sends: ADVERTISE
//! and UNADVERTISE carry a signed record, SUBSCRIBE and UNSUBSCRIBE a topic,
//! and GOODBYE a reason.

use crate::cbor::Value;
use crate::node_key::NodeKey;
use crate::profile::Profile;
use crate::signed_object::{sign_held_object, verify_held_object};

use super::{
    base, bounded_text, entry, has_fields, object_refusal, protocol_uint, read_fields, uint,
    with_field, FrameError, Rule, MAX_TOPIC_BYTES, PROTOCOL_VERSION,
};

const NEIGHBOUR_LABEL: &str = "MACULA-PQ-NEIGHBOUR-V1";
const MAX_GOODBYE_REASON_BYTES: usize = 256;
const MAX_GOODBYE_DETAIL_BYTES: usize = 256;

/// The control frames pq_hybrid neighbour-signs, as macula_frame lists them.
/// Data frames carry their own end-to-end signatures.
const NEIGHBOUR_SIGNED_TYPES: &[&str] = &[
    "swim_ping",
    "swim_ack",
    "swim_suspect",
    "swim_confirm",
    "ping",
    "pong",
    "find_node",
    "nodes",
    "find_value",
    "value",
    "store",
    "store_ack",
    "advertise",
    "unadvertise",
    "subscribe",
    "unsubscribe",
    "overlay_relay",
    "hyparview_join",
    "hyparview_forward_join",
    "hyparview_neighbor",
    "hyparview_disconnect",
    "hyparview_shuffle",
    "hyparview_shuffle_reply",
    "plumtree_ihave",
    "plumtree_graft",
    "plumtree_prune",
    "goodbye",
];

/// Whether `profile` neighbour-signs frames of `frame_type`: every control
/// frame in pq_hybrid, none in pq_pure.
pub fn neighbour_signed(profile: Profile, frame_type: &str) -> bool {
    profile == Profile::PqHybrid && NEIGHBOUR_SIGNED_TYPES.contains(&frame_type)
}

/// Where a sender neighbour-signs a frame: the connection hash and the seq of
/// this frame in the sender's direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighbourLink {
    pub connection: [u8; 48],
    pub seq: u64,
}

/// What a receiver checks a frame against: the connection's profile, the
/// peer's identity key as carried, the connection hash, and the seq it
/// expects next from that peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourPeer {
    pub profile: Profile,
    pub peer_key: Vec<u8>,
    pub connection: [u8; 48],
    pub seq: u64,
}

/// Neighbour-signs `frame` with the sender's identity key, for one connection
/// and one seq, when the key's profile signs its type; otherwise `frame` goes
/// as it is. A frame that already carries a neighbour signature is refused.
pub fn sign_neighbour(
    frame: &Value,
    key: &NodeKey,
    link: &NeighbourLink,
) -> Result<Value, FrameError> {
    let Value::Map(pairs) = frame else {
        return Err(FrameError::Malformed);
    };
    let (frame_type, version, has_neighbour) = control_header(pairs);
    if has_neighbour {
        return Err(FrameError::NeighbourSigned);
    }
    if !neighbour_signed(key.profile(), &frame_type) {
        return Ok(frame.clone());
    }
    let mut fields: Vec<(Value, Value)> = pairs
        .iter()
        .filter(|(k, _)| *k != Value::text("version"))
        .cloned()
        .collect();
    fields.push(entry("connection", Value::Bytes(link.connection.to_vec())));
    fields.push(entry("seq", uint(link.seq)));
    let held = sign_held_object(NEIGHBOUR_LABEL, &fields, key).map_err(object_refusal)?;
    Ok(Value::Map(vec![
        entry("version", version),
        entry("frame_type", Value::text(frame_type)),
        entry("neighbour", held.to_value()),
    ]))
}

/// Reads a received frame under the connection's profile. A frame type the
/// profile signs must be exactly `{version, frame_type, neighbour}`, signed by
/// the peer's identity key for this connection and this seq, and comes back as
/// the frame its tbs holds. Any other frame must not carry `neighbour` and
/// comes back as it is.
pub fn verify_neighbour(frame: &Value, peer: &NeighbourPeer) -> Result<Value, FrameError> {
    let Value::Map(pairs) = frame else {
        return Err(FrameError::Malformed);
    };
    let (frame_type, version, has_neighbour) = control_header(pairs);
    if !neighbour_signed(peer.profile, &frame_type) {
        return if has_neighbour {
            Err(FrameError::Malformed)
        } else {
            Ok(frame.clone())
        };
    }
    if pairs.len() != 3 || !has_neighbour {
        return Err(FrameError::Malformed);
    }
    let neighbour = frame.get("neighbour").ok_or(FrameError::Malformed)?;
    let verified = verify_held_object(NEIGHBOUR_LABEL, neighbour, &peer.peer_key, peer.profile)
        .map_err(object_refusal)?;
    opened_control_frame(&verified.fields, &frame_type, version, peer)
}

/// The frame a neighbour tbs holds: read under its type's table with alg,
/// connection and seq, which must name this connection and this seq, and
/// returned without them and with version back.
fn opened_control_frame(
    tbs: &Value,
    frame_type: &str,
    version: Value,
    peer: &NeighbourPeer,
) -> Result<Value, FrameError> {
    let mut table = control_table(frame_type).ok_or(FrameError::Malformed)?;
    table.extend([
        ("alg", Rule::Any),
        ("connection", Rule::BytesOf(48)),
        ("seq", Rule::ProtocolUint),
    ]);
    let fields = read_fields(tbs, &table).ok_or(FrameError::Malformed)?;
    if !has_fields(&fields, &["frame_type", "alg", "connection", "seq"])
        || fields["frame_type"] != Value::text(frame_type)
        || fields["connection"] != Value::Bytes(peer.connection.to_vec())
        || protocol_uint(&fields["seq"]) != Some(peer.seq)
    {
        return Err(FrameError::Malformed);
    }
    let Value::Map(pairs) = tbs else {
        return Err(FrameError::Malformed);
    };
    let mut opened = vec![entry("version", version)];
    opened.extend(
        pairs
            .iter()
            .filter(|(k, _)| !matches!(k, Value::Text(t) if t == "alg" || t == "connection" || t == "seq"))
            .cloned(),
    );
    Ok(Value::Map(opened))
}

/// The field table of a control frame a client link exchanges, without
/// version and neighbour: the base every frame carries and the type's own.
fn control_table(frame_type: &str) -> Option<Vec<(&'static str, Rule)>> {
    let own: &[(&'static str, Rule)] = match frame_type {
        "advertise" => &[("advertisement", Rule::AnyBytes)],
        "unadvertise" => &[("withdrawal", Rule::AnyBytes)],
        "subscribe" => &[
            ("topic", Rule::Any),
            ("subscriber", Rule::BytesOf(32)),
            ("options", Rule::Any),
        ],
        "unsubscribe" => &[("topic", Rule::Any), ("subscriber", Rule::BytesOf(32))],
        "goodbye" => &[
            ("reason", Rule::TextWithin(MAX_GOODBYE_REASON_BYTES)),
            ("detail", Rule::Any),
        ],
        _ => return None,
    };
    let types: &'static [&'static str] = match frame_type {
        "advertise" => &["advertise"],
        "unadvertise" => &["unadvertise"],
        "subscribe" => &["subscribe"],
        "unsubscribe" => &["unsubscribe"],
        _ => &["goodbye"],
    };
    let mut table = vec![
        ("frame_type", Rule::TextIn(types)),
        ("frame_id", Rule::Any),
        ("sent_at_ms", Rule::ProtocolUint),
        ("capabilities", Rule::ProtocolUint),
        ("realm", Rule::Any),
        ("call_id", Rule::Any),
        ("source_route", Rule::Any),
    ];
    table.extend_from_slice(own);
    Some(table)
}

/// A frame map's frame_type, version, and whether it carries neighbour.
fn control_header(pairs: &[(Value, Value)]) -> (String, Value, bool) {
    let mut frame_type = String::new();
    let mut version = Value::Int(i128::from(PROTOCOL_VERSION));
    let mut has_neighbour = false;
    for (k, v) in pairs {
        match (k, v) {
            (Value::Text(n), Value::Text(t)) if n == "frame_type" => frame_type = t.clone(),
            (Value::Text(n), _) if n == "version" => version = v.clone(),
            (Value::Text(n), _) if n == "neighbour" => has_neighbour = true,
            _ => {}
        }
    }
    (frame_type, version, has_neighbour)
}

/// macula 12's ADVERTISE: the signed procedure_advertisement record, as
/// encoded bytes.
pub fn advertise_frame(advertisement: &[u8]) -> Value {
    let mut fields = base("advertise");
    fields.push(entry("advertisement", Value::Bytes(advertisement.to_vec())));
    Value::Map(fields)
}

/// macula 12's UNADVERTISE: the signed withdrawal record, as encoded bytes.
pub fn unadvertise_frame(withdrawal: &[u8]) -> Value {
    let mut fields = base("unadvertise");
    fields.push(entry("withdrawal", Value::Bytes(withdrawal.to_vec())));
    Value::Map(fields)
}

/// macula 12's SUBSCRIBE of `subscriber` to `topic` in `realm`, with no
/// options. A topic over 512 bytes or not UTF-8 is refused.
pub fn subscribe_frame(
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Value, FrameError> {
    let mut fields = topic_frame("subscribe", topic, realm, subscriber)?;
    fields.push(entry("options", Value::Map(Vec::new())));
    Ok(Value::Map(fields))
}

/// macula 12's UNSUBSCRIBE of `subscriber` from `topic` in `realm`, with
/// [`subscribe_frame`]'s bound on the topic.
pub fn unsubscribe_frame(
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Value, FrameError> {
    topic_frame("unsubscribe", topic, realm, subscriber).map(Value::Map)
}

fn topic_frame(
    frame_type: &str,
    topic: &[u8],
    realm: &[u8; 32],
    subscriber: &[u8; 32],
) -> Result<Vec<(Value, Value)>, FrameError> {
    bounded_text("topic", topic, MAX_TOPIC_BYTES)?;
    let mut fields = with_field(base(frame_type), "realm", Value::Bytes(realm.to_vec()));
    fields.push(entry("topic", Value::Bytes(topic.to_vec())));
    fields.push(entry("subscriber", Value::Bytes(subscriber.to_vec())));
    Ok(fields)
}

/// macula 12's GOODBYE: a reason of at most 256 bytes, and a detail of at
/// most 256 bytes of UTF-8, or none.
pub fn goodbye_frame(reason: &str, detail: Option<&[u8]>) -> Result<Value, FrameError> {
    bounded_text("reason", reason.as_bytes(), MAX_GOODBYE_REASON_BYTES)?;
    let detail = match detail {
        Some(d) => {
            bounded_text("detail", d, MAX_GOODBYE_DETAIL_BYTES)?;
            Value::Bytes(d.to_vec())
        }
        None => Value::Null,
    };
    let mut fields = base("goodbye");
    fields.push(entry("reason", Value::text(reason)));
    fields.push(entry("detail", detail));
    Ok(Value::Map(fields))
}
