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
    protocol_uint, read_fields, received_frame, sealed, text_of, uint, Fields, FrameError, Rule,
    MAX_PROTOCOL_INT, MAX_TOPIC_BYTES, PROTOCOL_VERSION, PUBLICATION_LABEL,
};

use sealed::{Sealed, SealedContext};

const PUBLISH: &str = "publish";
const EVENT: &str = "event";
const PLUMTREE_GOSSIP: &str = "plumtree_gossip";
const TOLERANCE_MS: u64 = 5 * 60_000;
const DEFAULT_TTL_MS: u64 = 10 * 60_000;
const MAX_TTL_MS: u64 = 60 * 60_000;

/// What a publication carries: a payload in the clear, or a sealed group
/// event's, exactly one of the two, as the wire's payload_or_sealed holds it
/// (DESIGN_E2E_SEALED_PUBSUB.md). A station relaying a sealed event carries
/// the ciphertext and cannot read it.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// A payload in the clear.
    Clear(Value),
    /// A sealed group event: the ciphertext, its nonce, and the id of the
    /// epoch key it was sealed under.
    Sealed(Sealed),
}

impl Payload {
    /// The sealed map, `None` for a clear payload.
    pub fn sealed(&self) -> Option<&Sealed> {
        match self {
            Payload::Clear(_) => None,
            Payload::Sealed(sealed) => Some(sealed),
        }
    }
}

/// A publication as its publisher gives it: a realm, a topic, the publisher's
/// own seq, when it was published in Unix milliseconds, a payload, and a
/// ttl_ms, `None` for the 10 minutes a publication lives without one.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationSpec {
    pub realm: [u8; 32],
    pub topic: String,
    pub seq: u64,
    pub published_at: u64,
    pub payload: Payload,
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
    pub payload: Payload,
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
    match &spec.payload {
        // A sealed map of another scheme, or of a shape no event carries, is
        // refused before anything is signed, where a clear payload the wire
        // cannot carry is.
        Payload::Sealed(sealed)
            if !sealed.known_scheme() || !sealed.shaped(SealedContext::GroupEvent) =>
        {
            return Err(FrameError::SealedShape);
        }
        Payload::Clear(payload) => check_payload(payload)?,
        Payload::Sealed(_) => {}
    }
    if spec.ttl_ms.is_some_and(|t| t > MAX_TTL_MS) {
        return Err(FrameError::OutOfRange("a ttl_ms over one hour".into()));
    }
    let mut fields = vec![
        entry("publisher", Value::Bytes(key.key_id().to_vec())),
        entry("realm", Value::Bytes(spec.realm.to_vec())),
        entry("topic", Value::text(spec.topic.clone())),
        entry("seq", uint(spec.seq)),
        entry("published_at", uint(spec.published_at)),
    ];
    fields.push(match &spec.payload {
        Payload::Clear(payload) => entry("payload", payload.clone()),
        Payload::Sealed(sealed) => entry("sealed", sealed.value()),
    });
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
    ("sealed", Rule::Sealed(SealedContext::GroupEvent)),
    ("ext", Rule::Ext),
];

/// The payload `fields` carry: the clear one or the sealed one, exactly one
/// of the two, `None` when they carry neither or both.
fn payload_of(fields: &Fields) -> Option<Payload> {
    match (
        fields.get("payload"),
        sealed::sealed_field(fields, SealedContext::GroupEvent),
    ) {
        (Some(payload), None) => Some(Payload::Clear(payload.clone())),
        (None, Some(sealed)) => Some(Payload::Sealed(sealed)),
        _ => None,
    }
}

/// How a received EVENT says its publication reached this node, a per-hop
/// enum (WIRE_1_0.md section 3.4): `plumtree` or `direct`, and any value this
/// crate does not know reads as `direct`, counted as `wire_enum_fallback`.
pub fn delivered_via(event: &Value) -> &'static str {
    match event.get("delivered_via") {
        Some(Value::Text(t)) if t == "plumtree" => "plumtree",
        Some(Value::Text(t)) if t == "direct" => "direct",
        _ => {
            super::wire_counters::count_enum_fallback("delivered_via");
            "direct"
        }
    }
}

/// The last moment, in Unix milliseconds, a subscriber accepts a publication
/// made at `published_at` with `ttl_ms`: its time to live, then the clock
/// tolerance.
pub fn accepted_until(published_at: u64, ttl_ms: Option<u64>) -> u64 {
    published_at + ttl_ms.unwrap_or(DEFAULT_TTL_MS) + TOLERANCE_MS
}

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
        EVENT => (&[("delivered_via", Rule::EnumText)], &[EVENT]),
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
        &["publisher", "realm", "topic", "seq", "published_at"],
    ) {
        return Err(FrameError::Malformed);
    }
    let payload = payload_of(&fields).ok_or(FrameError::Malformed)?;
    super::signed_ext(&fields, &[])?;
    let ttl_ms = fields.get("ttl_ms").and_then(protocol_uint);
    let published_at = protocol_uint(&fields["published_at"]).unwrap_or(0);
    let publication = VerifiedPublication {
        publisher: fixed(&fields["publisher"]),
        realm: fixed(&fields["realm"]),
        topic: text_of(&fields["topic"]),
        seq: protocol_uint(&fields["seq"]).unwrap_or(0),
        published_at,
        ttl_ms,
        payload,
        publication_hash: Sha384::digest(&verified.tbs).into(),
        expires_at: accepted_until(published_at, ttl_ms),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::node_key::NodeKey;
    use crate::profile::Profile;

    const NOW: i64 = 1_790_000_000_000;

    fn key() -> NodeKey {
        NodeKey::generate_identity(Profile::PqPure, 0).unwrap()
    }

    /// A sealed group event: a nonce and no kem_ct, as a group event carries.
    fn sealed() -> Sealed {
        Sealed {
            scheme: sealed::SEALED_SCHEME,
            key_id: [4; 8],
            kem_ct: None,
            nonce: Some(vec![7; 12]),
            ct: vec![9; 40],
        }
    }

    fn spec(payload: Payload) -> PublicationSpec {
        PublicationSpec {
            realm: [3; 32],
            topic: "acme/demo/said_v1".to_string(),
            seq: 1,
            published_at: NOW as u64,
            payload,
            ttl_ms: None,
        }
    }

    /// A sealed group event signs and verifies, and is still the sealed map it
    /// was: every station relaying it carries the ciphertext, not a payload.
    #[test]
    fn a_sealed_publication_signs_and_verifies_as_one() {
        let frame = sign_publish(&spec(Payload::Sealed(sealed())), &key()).unwrap();
        let arrived = crate::cbor::decode(&crate::cbor::encode(&frame).unwrap()).unwrap();
        let publication = verify_publication(&arrived, Profile::PqPure, NOW).unwrap();
        let Payload::Sealed(carried) = &publication.payload else {
            panic!("a sealed publication verifies as a sealed one");
        };
        assert_eq!(carried.key_id, [4; 8], "the epoch it was sealed under");
        assert_eq!(carried.nonce.as_deref(), Some(&[7u8; 12][..]));
        assert_eq!(carried.ct, vec![9; 40]);
        assert_eq!(publication.topic, "acme/demo/said_v1");
    }

    /// A publication carries a clear payload or a sealed one, exactly one of
    /// the two: both, or neither, is not a publication.
    #[test]
    fn a_publication_carries_exactly_one_of_the_two() {
        let mut clear: Fields = HashMap::new();
        clear.insert("payload".into(), Value::text("clear"));
        assert_eq!(
            payload_of(&clear),
            Some(Payload::Clear(Value::text("clear")))
        );

        let mut both = clear.clone();
        both.insert("sealed".into(), sealed().value());
        assert_eq!(payload_of(&both), None, "both at once");

        let mut neither: Fields = HashMap::new();
        neither.insert("topic".into(), Value::text("acme/demo/said_v1"));
        assert_eq!(payload_of(&neither), None, "neither");
    }

    /// A sealed map of another scheme, or of a shape no event carries, is
    /// refused before anything is signed.
    #[test]
    fn a_sealed_publication_of_the_wrong_shape_is_refused() {
        let other_scheme = Sealed {
            scheme: 2,
            ..sealed()
        };
        assert_eq!(
            sign_publish(&spec(Payload::Sealed(other_scheme)), &key()).unwrap_err(),
            FrameError::SealedShape
        );
        let with_kem_ct = Sealed {
            kem_ct: Some(vec![0; 1568]),
            ..sealed()
        };
        assert_eq!(
            sign_publish(&spec(Payload::Sealed(with_kem_ct)), &key()).unwrap_err(),
            FrameError::SealedShape,
            "a request-shaped map is not an event"
        );
    }
}
