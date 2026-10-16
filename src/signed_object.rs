//! Signed objects, as macula_signed_object and macula-go sign and verify them:
//! a record, a request, a reply, a relay error, a publication, or a stream
//! frame. The fields gain `alg`, the signer's profile algorithm, and are
//! encoded as tbs in the deterministic form; the signature covers the label, a
//! zero byte, the SHA-384 of the signer's key as carried, and tbs. An
//! [`Object`] carries its key; a [`HeldObject`] leaves it out for a verifier
//! that already holds it, and still signs its hash.

use std::fmt;

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::node_key::{carried_key_well_formed, verify, KeyError, NodeKey};
use crate::profile::Profile;

/// The refusals of a signed object, named as macula_signed_object names them,
/// and the ones signing gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// Not exactly the keys of its shape, each a byte string; a carried key
    /// not in the verifier's profile's carried form; or a tbs the decoding
    /// rule refuses, or that is not a map naming alg as text.
    Malformed,
    /// A signature that does not verify over the label, the key's hash and
    /// the tbs as received.
    SignatureInvalid,
    /// An alg that names another profile's algorithm than the verifier's.
    AlgMismatch,
    /// An alg the verifier's allowlist does not hold (`alg_unsupported`,
    /// WIRE_1_0.md section 7), refused before any signature work.
    AlgUnsupported(String),
    /// A field to sign whose key is not text.
    FieldKeyNotText,
    /// Two fields to sign with one key, named here.
    DuplicateField(String),
    /// The key could not sign.
    Key(KeyError),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::Malformed => f.write_str("malformed signed object"),
            ObjectError::SignatureInvalid => {
                f.write_str("the signed object's signature does not verify")
            }
            ObjectError::AlgMismatch => {
                f.write_str("the signed object names another profile's algorithm")
            }
            ObjectError::AlgUnsupported(alg) => {
                write!(f, "an alg the verifier does not take: {alg:?}")
            }
            ObjectError::FieldKeyNotText => f.write_str("a field key that is not text"),
            ObjectError::DuplicateField(name) => write!(f, "two fields named {name:?}"),
            ObjectError::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ObjectError {}

/// A signed object that carries its signer's key as carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub key: Vec<u8>,
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A signed object whose verifier already holds the signer's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldObject {
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A signed object that verified: the key it verified with, its tbs bytes as
/// received, and the map they decode to.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedObject {
    pub key: Vec<u8>,
    pub tbs: Vec<u8>,
    pub fields: Value,
}

impl Object {
    /// The object as the map `{key, tbs, signature}`.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("key"), Value::Bytes(self.key.clone())),
            (Value::text("tbs"), Value::Bytes(self.tbs.clone())),
            (
                Value::text("signature"),
                Value::Bytes(self.signature.clone()),
            ),
        ])
    }

    /// The object in `value`, a map of exactly `key`, `tbs` and `signature`,
    /// each a byte string.
    pub fn from_value(value: &Value) -> Result<Object, ObjectError> {
        let [key, tbs, signature] = exact_byte_fields(value, ["key", "tbs", "signature"])?;
        Ok(Object {
            key,
            tbs,
            signature,
        })
    }
}

impl HeldObject {
    /// The object as the map `{tbs, signature}`.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("tbs"), Value::Bytes(self.tbs.clone())),
            (
                Value::text("signature"),
                Value::Bytes(self.signature.clone()),
            ),
        ])
    }

    /// The object in `value`, a map of exactly `tbs` and `signature`, each a
    /// byte string.
    pub fn from_value(value: &Value) -> Result<HeldObject, ObjectError> {
        let [tbs, signature] = exact_byte_fields(value, ["tbs", "signature"])?;
        Ok(HeldObject { tbs, signature })
    }
}

/// Signs `fields` under `label` with `key`. The fields gain alg, replacing any
/// alg they held; every field needs a text key of its own.
pub fn sign_object(
    label: &str,
    fields: &[(Value, Value)],
    key: &NodeKey,
) -> Result<Object, ObjectError> {
    let carried = key.public_key();
    let tbs = object_tbs(fields, key.profile())?;
    let signature = key
        .sign(&object_signed_bytes(label, &carried, &tbs))
        .map_err(ObjectError::Key)?;
    Ok(Object {
        key: carried,
        tbs,
        signature,
    })
}

/// [`sign_object`] for a verifier that already holds `key`.
pub fn sign_held_object(
    label: &str,
    fields: &[(Value, Value)],
    key: &NodeKey,
) -> Result<HeldObject, ObjectError> {
    let object = sign_object(label, fields, key)?;
    Ok(HeldObject {
        tbs: object.tbs,
        signature: object.signature,
    })
}

/// Verifies an object that carries its key, under `label` and the verifier's
/// `profile`, in macula's order: exactly key, tbs and signature, each a byte
/// string; key in the profile's carried form; tbs under the decoding rule, a
/// map whose alg names the profile's algorithm; only then the signature over
/// tbs as received. Reading alg first is the cheap refusal: an object naming
/// another algorithm costs a decode, never a signature verification
/// (macula#104). alg is checked and never selects an algorithm.
pub fn verify_object(
    label: &str,
    value: &Value,
    profile: Profile,
) -> Result<VerifiedObject, ObjectError> {
    let object = Object::from_value(value)?;
    if !carried_key_well_formed(&object.key, profile) {
        return Err(ObjectError::Malformed);
    }
    verified(label, object.key, object.tbs, &object.signature, profile)
}

/// Verifies an object that carries its key, under `label`, with the verifier
/// its alg selects from `profile`'s allowlist (WIRE_1_0.md sections 5.2 and
/// 7), in this order: exactly key, tbs and signature, each a byte string; tbs
/// under the decoding rule, a map holding alg as text, nothing else in it
/// acted on before the signature; alg on the allowlist, which is the
/// profile's own algorithm alone, so the other profile's is refused before
/// any crypto ([`ObjectError::AlgUnsupported`]); key in that algorithm's
/// carried form; the signature over tbs as received.
pub fn verify_object_by_alg(
    label: &str,
    value: &Value,
    profile: Profile,
) -> Result<VerifiedObject, ObjectError> {
    let object = Object::from_value(value)?;
    let fields = cbor::decode(&object.tbs).map_err(|_| ObjectError::Malformed)?;
    let alg = match (&fields, fields.get("alg")) {
        (Value::Map(_), Some(Value::Text(alg))) => alg.clone(),
        _ => return Err(ObjectError::Malformed),
    };
    if alg != profile.sig_alg() {
        return Err(ObjectError::AlgUnsupported(alg));
    }
    if !carried_key_well_formed(&object.key, profile) {
        return Err(ObjectError::Malformed);
    }
    let signed = object_signed_bytes(label, &object.key, &object.tbs);
    if !verify(&signed, &object.signature, &object.key, profile) {
        return Err(ObjectError::SignatureInvalid);
    }
    Ok(VerifiedObject {
        key: object.key,
        tbs: object.tbs,
        fields,
    })
}

/// Verifies an object whose key the verifier holds, as carried, under `label`
/// and the verifier's `profile`.
pub fn verify_held_object(
    label: &str,
    value: &Value,
    key: &[u8],
    profile: Profile,
) -> Result<VerifiedObject, ObjectError> {
    let held = HeldObject::from_value(value)?;
    verified(label, key.to_vec(), held.tbs, &held.signature, profile)
}

fn verified(
    label: &str,
    key: Vec<u8>,
    tbs: Vec<u8>,
    signature: &[u8],
    profile: Profile,
) -> Result<VerifiedObject, ObjectError> {
    let fields = cbor::decode(&tbs).map_err(|_| ObjectError::Malformed)?;
    let alg = match (&fields, fields.get("alg")) {
        (Value::Map(_), Some(Value::Text(alg))) => alg.clone(),
        _ => return Err(ObjectError::Malformed),
    };
    if alg != profile.sig_alg() {
        return Err(ObjectError::AlgMismatch);
    }
    if !verify(
        &object_signed_bytes(label, &key, &tbs),
        signature,
        &key,
        profile,
    ) {
        return Err(ObjectError::SignatureInvalid);
    }
    Ok(VerifiedObject { key, tbs, fields })
}

/// The fields with alg for `profile`, deterministically encoded.
fn object_tbs(fields: &[(Value, Value)], profile: Profile) -> Result<Vec<u8>, ObjectError> {
    let mut seen = std::collections::HashSet::with_capacity(fields.len());
    let mut with_alg = Vec::with_capacity(fields.len() + 1);
    for (key, value) in fields {
        let Value::Text(name) = key else {
            return Err(ObjectError::FieldKeyNotText);
        };
        if seen.contains(name.as_str()) {
            return Err(ObjectError::DuplicateField(name.clone()));
        }
        if name == "alg" {
            continue;
        }
        seen.insert(name.as_str());
        with_alg.push((key.clone(), value.clone()));
    }
    with_alg.push((Value::text("alg"), Value::text(profile.sig_alg())));
    cbor::encode(&Value::Map(with_alg)).map_err(|_| ObjectError::Malformed)
}

/// What a signed object's signature covers: label, a zero byte, the SHA-384
/// of the key as carried, and tbs.
fn object_signed_bytes(label: &str, key: &[u8], tbs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 1 + 48 + tbs.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend_from_slice(&Sha384::digest(key));
    out.extend_from_slice(tbs);
    out
}

/// The byte strings under `names` in `value`, when it is a map of exactly
/// those text keys, each holding a byte string.
fn exact_byte_fields<const N: usize>(
    value: &Value,
    names: [&str; N],
) -> Result<[Vec<u8>; N], ObjectError> {
    let Value::Map(pairs) = value else {
        return Err(ObjectError::Malformed);
    };
    if pairs.len() != N {
        return Err(ObjectError::Malformed);
    }
    let mut out: [Vec<u8>; N] = std::array::from_fn(|_| Vec::new());
    for (slot, name) in out.iter_mut().zip(names) {
        match value.get(name) {
            Some(Value::Bytes(b)) => *slot = b.clone(),
            _ => return Err(ObjectError::Malformed),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod wire_1_0_tests {
    //! The wire 1.0 tbs vectors (macula#97, tbs.json): every signed structure's
    //! fields encode to exactly its canonical tbs, its signing input is the
    //! label, a zero byte, the SHA-384 of the signer's key as carried when the
    //! form is keyed, and the tbs, and its signature verifies under the
    //! signer's key.

    use super::*;
    use crate::wire_vectors::{self, hex_of, typed};

    #[test]
    fn the_wire_1_0_tbs_vectors() {
        let file = wire_vectors::load("tbs");
        for c in &file.cases {
            let profile = Profile::parse(&c.profile).unwrap();
            let key = wire_vectors::key(&c.profile, c.text("signer"));
            let tbs = cbor::encode(&typed(&c.input["fields"])).unwrap();
            assert_eq!(hex::encode(&tbs), c.expect_text("tbs"), "{}: the tbs", c.id);
            let input = match c.text("form") {
                "keyed" => object_signed_bytes(c.text("label"), &key, &tbs),
                _ => crate::binding::labelled(c.text("label"), &tbs),
            };
            assert_eq!(
                hex::encode(&input),
                c.expect_text("signing_input"),
                "{}",
                c.id
            );
            let signature = hex_of(&c.expect["signature"]);
            assert!(
                verify(&input, &signature, &key, profile),
                "{}: the signature",
                c.id
            );
        }
        assert_eq!(file.cases.len(), 30);
    }
}
