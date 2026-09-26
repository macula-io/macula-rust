//! Publications (D17): signed under MACULA-PQ-PUBLICATION-V1 by the
//! publisher's identity key, with no frame_type in the tbs, since the same
//! bytes ride in every EVENT and GOSSIP made from a PUBLISH. A verifier
//! accepts one published up to 5 minutes ahead of its clock, until its
//! ttl_ms, or 10 minutes without one, and 5 minutes more; a ttl_ms is at most
//! one hour.

use sha2::{Digest, Sha384};

use crate::cbor::Value;
use crate::node_key::{node_id_of, NodeKey};
use crate::profile::Profile;
use crate::signed_object::{sign_object, verify_object};

use super::{
    bounded_text, check_payload, entry, fixed, has_fields, identity_signer, object_refusal,
    protocol_uint, read_fields, received_frame, text_of, uint, FrameError, Rule, MAX_PROTOCOL_INT,
    MAX_TOPIC_BYTES, PROTOCOL_VERSION, PUBLICATION_LABEL,
};

const PUBLISH: &str = "publish";
const EVENT: &str = "event";
const PLUMTREE_GOSSIP: &str = "plumtree_gossip";
const TOLERANCE_MS: u64 = 5 * 60_000;
const DEFAULT_TTL_MS: u64 = 10 * 60_000;
const MAX_TTL_MS: u64 = 60 * 60_000;

/// A publication as its publisher gives it: a realm, a topic, the publisher's
/// own seq, when it was published in Unix milliseconds, a payload, and a
/// ttl_ms, `None` for the 10 minutes a publication lives without one.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationSpec {
    pub realm: [u8; 32],
    pub topic: String,
    pub seq: u64,
    pub published_at: u64,
    pub payload: Value,
    pub ttl_ms: Option<u64>,
}

/// A publication that verified: its fields, the publisher's key as carried,
/// `publication_hash`, the SHA-384 of its tbs, which deduplication keys on,
/// and `expires_at`, the last moment a verifier accepts it.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPublication {
    pub publisher: [u8; 32],
    pub realm: [u8; 32],
    pub topic: String,
    pub seq: u64,
    pub published_at: u64,
    pub ttl_ms: Option<u64>,
    pub payload: Value,
    pub key: Vec<u8>,
    pub publication_hash: [u8; 48],
    pub expires_at: u64,
}

/// Signs a publication as a PUBLISH with the publisher's identity key.
/// Refused, in macula's order: a key that is not an identity key; a seq or
/// published_at of 2^53 or more; a topic over 512 bytes; a payload the wire
/// cannot carry; a ttl_ms over one hour.
pub fn sign_publish(spec: &PublicationSpec, key: &NodeKey) -> Result<Value, FrameError> {
    identity_signer(key)?;
    if spec.seq >= MAX_PROTOCOL_INT || spec.published_at >= MAX_PROTOCOL_INT {
        return Err(FrameError::OutOfRange(
            "a seq or published_at of 2^53 or more".into(),
        ));
    }
    bounded_text("topic", spec.topic.as_bytes(), MAX_TOPIC_BYTES)?;
    check_payload(&spec.payload)?;
    if spec.ttl_ms.is_some_and(|t| t > MAX_TTL_MS) {
        return Err(FrameError::OutOfRange("a ttl_ms over one hour".into()));
    }
    let mut fields = vec![
        entry("publisher", Value::Bytes(key.key_id().to_vec())),
        entry("realm", Value::Bytes(spec.realm.to_vec())),
        entry("topic", Value::text(spec.topic.clone())),
        entry("seq", uint(spec.seq)),
        entry("published_at", uint(spec.published_at)),
        entry("payload", spec.payload.clone()),
    ];
    if let Some(ttl) = spec.ttl_ms {
        fields.push(entry("ttl_ms", uint(ttl)));
    }
    let publication = sign_object(PUBLICATION_LABEL, &fields, key).map_err(object_refusal)?;
    Ok(Value::Map(vec![
        entry("version", Value::Int(i128::from(PROTOCOL_VERSION))),
        entry("frame_type", Value::text(PUBLISH)),
        entry("publication", publication.to_value()),
    ]))
}

const PUBLICATION_TABLE: &[(&str, Rule)] = &[
    ("alg", Rule::Any),
    ("publisher", Rule::BytesOf(32)),
    ("realm", Rule::BytesOf(32)),
    ("topic", Rule::TextWithin(MAX_TOPIC_BYTES)),
    ("seq", Rule::ProtocolUint),
    ("published_at", Rule::ProtocolUint),
    ("ttl_ms", Rule::ProtocolUint),
    ("payload", Rule::Any),
];

/// Verifies the publication a received PUBLISH, EVENT or GOSSIP carries,
/// under the connection's `profile` and the verifier's clock `now_ms`: the
/// frame is exactly version, frame_type and publication, with an EVENT's
/// delivered_via or a GOSSIP's round; then the publication's signature and
/// fields, a ttl_ms of at most an hour, publisher as the key id of its key,
/// and its time.
pub fn verify_publication(
    frame: &Value,
    profile: Profile,
    now_ms: i64,
) -> Result<VerifiedPublication, FrameError> {
    let frame_type = frame.get("frame_type").map(text_of).unwrap_or_default();
    let (extra, types): (&[(&str, Rule)], &'static [&'static str]) = match frame_type.as_str() {
        PUBLISH => (&[], &[PUBLISH]),
        EVENT => (
            &[("delivered_via", Rule::TextIn(&["plumtree", "direct"]))],
            &[EVENT],
        ),
        PLUMTREE_GOSSIP => (&[("round", Rule::ProtocolUint)], &[PLUMTREE_GOSSIP]),
        _ => return Err(FrameError::Malformed),
    };
    let (_, object) = received_frame(frame, "publication", Rule::CarriedObject, extra, types)
        .ok_or(FrameError::Malformed)?;
    if extra.iter().any(|(name, _)| frame.get(name).is_none()) {
        return Err(FrameError::Malformed);
    }
    let verified = verify_object(PUBLICATION_LABEL, &object, profile).map_err(object_refusal)?;
    let fields = read_fields(&verified.fields, PUBLICATION_TABLE).ok_or(FrameError::Malformed)?;
    if !has_fields(
        &fields,
        &[
            "publisher",
            "realm",
            "topic",
            "seq",
            "published_at",
            "payload",
        ],
    ) {
        return Err(FrameError::Malformed);
    }
    let ttl_ms = fields.get("ttl_ms").and_then(protocol_uint);
    let published_at = protocol_uint(&fields["published_at"]).unwrap_or(0);
    let publication = VerifiedPublication {
        publisher: fixed(&fields["publisher"]),
        realm: fixed(&fields["realm"]),
        topic: text_of(&fields["topic"]),
        seq: protocol_uint(&fields["seq"]).unwrap_or(0),
        published_at,
        ttl_ms,
        payload: fields["payload"].clone(),
        publication_hash: Sha384::digest(&verified.tbs).into(),
        expires_at: published_at + ttl_ms.unwrap_or(DEFAULT_TTL_MS) + TOLERANCE_MS,
        key: verified.key,
    };
    let valid_from = published_at as i64 - TOLERANCE_MS as i64;
    if ttl_ms.is_some_and(|t| t > MAX_TTL_MS) {
        return Err(FrameError::Malformed);
    }
    if publication.publisher != node_id_of(&publication.key, profile) {
        return Err(FrameError::KeyIdMismatch);
    }
    if valid_from > now_ms {
        return Err(FrameError::NotYetValid(valid_from - now_ms));
    }
    if now_ms > publication.expires_at as i64 {
        return Err(FrameError::Expired(now_ms - publication.expires_at as i64));
    }
    Ok(publication)
}
