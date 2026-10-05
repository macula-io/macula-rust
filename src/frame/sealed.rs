//! A payload sealed end to end (macula 13, E2E seal scheme 1, E2E_SEAL_V1.md
//! "The sealed map"): the recipient key's id, the ciphertext with its tag,
//! and, by the frame it rides in, a request's kem_ct (it agrees the keys; its
//! nonce is fixed) or a reply's or a provider stream frame's carried nonce. A
//! caller stream frame's nonce is its seq, so it carries neither. A frame
//! carries `sealed` in place of its clear field, never beside it. Nothing
//! here opens a payload: [`crate::seal`] does.

use crate::cbor::Value;

use super::{entry, fixed, has_fields, protocol_uint, read_fields, uint, Fields, Rule};

/// The only scheme a sealed map may name.
pub const SEALED_SCHEME: u64 = 1;

const KEM_CT_PURE_SIZE: usize = 1568;
const KEM_CT_HYBRID_SIZE: usize = 1665;
const SEALED_NONCE_SIZE: usize = 12;

/// A payload sealed end to end, as a frame carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: [u8; 8],
    pub kem_ct: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub ct: Vec<u8>,
}

/// The frame a sealed map rides in, which sets its shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedContext {
    Request,
    Reply,
    ProviderStream,
    CallerStream,
}

impl Sealed {
    /// The sealed map as it travels.
    pub(super) fn value(&self) -> Value {
        let mut entries = vec![
            entry("scheme", uint(SEALED_SCHEME)),
            entry("key_id", Value::Bytes(self.key_id.to_vec())),
            entry("ct", Value::Bytes(self.ct.clone())),
        ];
        if let Some(kem_ct) = &self.kem_ct {
            entries.push(entry("kem_ct", Value::Bytes(kem_ct.clone())));
        }
        if let Some(nonce) = &self.nonce {
            entries.push(entry("nonce", Value::Bytes(nonce.clone())));
        }
        Value::Map(entries)
    }

    /// Whether the map has the shape its frame's context requires, as
    /// macula_frame's sealed_shape/3 holds it.
    pub(super) fn shaped(&self, context: SealedContext) -> bool {
        if self
            .nonce
            .as_ref()
            .is_some_and(|n| n.len() != SEALED_NONCE_SIZE)
        {
            return false;
        }
        match (context, &self.kem_ct, &self.nonce) {
            (SealedContext::Request, Some(kem_ct), None) => {
                kem_ct.len() == KEM_CT_PURE_SIZE || kem_ct.len() == KEM_CT_HYBRID_SIZE
            }
            (SealedContext::Reply | SealedContext::ProviderStream, None, Some(_)) => true,
            (SealedContext::CallerStream, None, None) => true,
            _ => false,
        }
    }
}

const SEALED_TABLE: &[(&str, Rule)] = &[
    ("scheme", Rule::ProtocolUint),
    ("key_id", Rule::BytesOf(8)),
    ("kem_ct", Rule::AnyBytes),
    ("nonce", Rule::BytesOf(SEALED_NONCE_SIZE)),
    ("ct", Rule::AnyBytes),
];

/// A sealed map as a verifier reads it, opening nothing: scheme 1, a key id
/// and a ciphertext, and the shape its frame's context requires. Any other
/// map, or a key the table cannot name, is not one.
pub(super) fn read_sealed(v: &Value, context: SealedContext) -> Option<Sealed> {
    let fields = read_fields(v, SEALED_TABLE)?;
    if !has_fields(&fields, &["scheme", "key_id", "ct"])
        || protocol_uint(&fields["scheme"]) != Some(SEALED_SCHEME)
    {
        return None;
    }
    let bytes = |name: &str| match fields.get(name) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let sealed = Sealed {
        key_id: fixed(&fields["key_id"]),
        kem_ct: bytes("kem_ct"),
        nonce: bytes("nonce"),
        ct: bytes("ct")?,
    };
    sealed.shaped(context).then_some(sealed)
}

/// Whether `fields` carry `clear` in the clear or `sealed`, exactly one of
/// the two (macula_frame's payload_or_sealed/1).
pub(super) fn clear_or_sealed(fields: &Fields, clear: &str) -> bool {
    fields.contains_key(clear) != fields.contains_key("sealed")
}

/// The sealed map `fields` carry, `None` for none: the fields were read
/// against a table holding [`Rule::Sealed`], so it reads.
pub(super) fn sealed_field(fields: &Fields, context: SealedContext) -> Option<Sealed> {
    fields.get("sealed").and_then(|v| read_sealed(v, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(kem_ct: Option<usize>, nonce: Option<usize>) -> Sealed {
        Sealed {
            key_id: [7; 8],
            kem_ct: kem_ct.map(|n| vec![1; n]),
            nonce: nonce.map(|n| vec![2; n]),
            ct: vec![3; 20],
        }
    }

    #[test]
    fn each_frame_takes_only_its_own_sealed_shape() {
        use SealedContext::*;
        for (s, request, reply, provider_stream, caller_stream) in [
            (sealed(Some(1568), None), true, false, false, false),
            (sealed(Some(1665), None), true, false, false, false),
            (sealed(Some(1567), None), false, false, false, false),
            (sealed(None, Some(12)), false, true, true, false),
            (sealed(None, Some(11)), false, false, false, false),
            (sealed(None, None), false, false, false, true),
            (sealed(Some(1568), Some(12)), false, false, false, false),
        ] {
            assert_eq!(s.shaped(Request), request, "{s:?}");
            assert_eq!(s.shaped(Reply), reply, "{s:?}");
            assert_eq!(s.shaped(ProviderStream), provider_stream, "{s:?}");
            assert_eq!(s.shaped(CallerStream), caller_stream, "{s:?}");
            assert_eq!(
                read_sealed(&s.value(), Request).is_some(),
                request,
                "{s:?} read back"
            );
        }
    }

    #[test]
    fn a_sealed_map_of_another_scheme_or_with_a_key_the_table_cannot_name_is_not_one() {
        let Value::Map(mut other_scheme) = sealed(None, Some(12)).value() else {
            unreachable!()
        };
        other_scheme[0] = entry("scheme", uint(2));
        assert_eq!(
            read_sealed(&Value::Map(other_scheme), SealedContext::Reply),
            None
        );
        let Value::Map(mut extra) = sealed(None, Some(12)).value() else {
            unreachable!()
        };
        extra.push(entry("payload", Value::Null));
        assert_eq!(read_sealed(&Value::Map(extra), SealedContext::Reply), None);
    }
}
