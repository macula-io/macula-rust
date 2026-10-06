//! One token, checked a step at a time in `macula_ucan`'s order: its three
//! parts, the header, the claims' shapes and the signature, the audience,
//! and the validity window.

use std::collections::HashMap;

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde_json::value::RawValue;
use serde_json::{Map, Value};

use super::{algorithm, carried_key, first_wins, hex, Refusal, MAX_LIFETIME, TYP, UCV};
use crate::node_key::verify;
use crate::profile::Profile;

/// A received part's base64url: no padding, and trailing bits ignored, as
/// macula-go decodes one. macula also takes a padded part or one with
/// whitespace in it, which it never mints; those are refused here.
const RECEIVED: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// A token parsed, and as far as it has been checked.
pub(super) struct Checked {
    header: Map<String, Value>,
    pub(super) claims: Map<String, Value>,
    /// The claims' values as written, so a number is judged by its text.
    written: HashMap<String, Box<RawValue>>,
    signature: Vec<u8>,
    input: Vec<u8>,
    /// The issuer's key as carried, once the signature has verified under it.
    pub(super) issuer_key: Vec<u8>,
}

impl Checked {
    /// A token's three parts: its header and claims decoded as JSON objects,
    /// and its signature, with the header and payload as received.
    pub(super) fn parsed(token: &[u8]) -> Result<Checked, Refusal> {
        let parts: Vec<&[u8]> = token.split(|&b| b == b'.').collect();
        let [header, payload, signature] = parts[..] else {
            return Err(Refusal::Malformed);
        };
        let header_json = RECEIVED.decode(header).map_err(|_| Refusal::Malformed)?;
        let payload_json = RECEIVED.decode(payload).map_err(|_| Refusal::Malformed)?;
        let header_object = first_wins::object(&header_json).ok_or(Refusal::Malformed)?;
        let claims = first_wins::object(&payload_json).ok_or(Refusal::Malformed)?;
        let written = first_wins::written(&payload_json).ok_or(Refusal::Malformed)?;
        let signature = RECEIVED.decode(signature).map_err(|_| Refusal::Malformed)?;
        let mut input = Vec::with_capacity(header.len() + 1 + payload.len());
        input.extend_from_slice(header);
        input.push(b'.');
        input.extend_from_slice(payload);
        Ok(Checked {
            header: header_object,
            claims,
            written,
            signature,
            input,
            issuer_key: Vec::new(),
        })
    }

    /// The header names `profile`'s algorithm, typ JWT and ucv 0.10.0:
    /// wrong_algorithm when it names another, malformed when `alg` is no text.
    pub(super) fn algorithm_is(&self, profile: Profile) -> Result<(), Refusal> {
        let Some(Value::String(alg)) = self.header.get("alg") else {
            return Err(Refusal::Malformed);
        };
        let text_is = |name: &str, want: &str| matches!(self.header.get(name), Some(Value::String(v)) if v == want);
        match alg == algorithm(profile) && text_is("typ", TYP) && text_is("ucv", UCV) {
            true => Ok(()),
            false => Err(Refusal::WrongAlgorithm),
        }
    }

    /// Every claim has its shape before anything is verified, and the
    /// signature is checked before any claim is acted on.
    pub(super) fn signed_by_iss(&mut self, profile: Profile) -> Result<(), Refusal> {
        let shaped = matches!(self.claims.get("aud"), Some(Value::String(_)))
            && matches!(self.claims.get("cap"), Some(Value::Array(_)))
            && self.integer("exp").is_some();
        let Some(Value::String(iss)) = self.claims.get("iss").filter(|_| shaped) else {
            return Err(Refusal::Malformed);
        };
        let carried = carried_key(iss, profile)?;
        if !verify(&self.input, &self.signature, &carried, profile) {
            return Err(Refusal::SignatureInvalid);
        }
        self.issuer_key = carried;
        Ok(())
    }

    /// `aud` is the request's verified caller.
    pub(super) fn audience_is(&self, caller: &[u8; 32]) -> Result<(), Refusal> {
        match self.aud() == Some(hex(caller).as_str()) {
            true => Ok(()),
            false => Err(Refusal::NotTheAudience),
        }
    }

    /// `now` lies before `exp`, `exp` at most [`MAX_LIFETIME`] past now,
    /// and `now` at or past `nbf`, an integer, where there is one.
    pub(super) fn valid_at(&self, now: i64) -> Result<(), Refusal> {
        let exp = self.integer("exp").ok_or(Refusal::Malformed)?;
        if now >= exp {
            return Err(Refusal::Expired);
        }
        if exp > now.saturating_add(MAX_LIFETIME) {
            return Err(Refusal::ExpBeyondMaxLifetime);
        }
        if !self.written.contains_key("nbf") {
            return Ok(());
        }
        match self.integer("nbf") {
            None => Err(Refusal::Malformed),
            Some(nbf) if now < nbf => Err(Refusal::NotYetValid),
            Some(_) => Ok(()),
        }
    }

    pub(super) fn aud(&self) -> Option<&str> {
        self.claims.get("aud").and_then(Value::as_str)
    }

    /// A claim written as a JSON integer, as Erlang's json decodes one: a
    /// number with a fraction or an exponent is a float, never an integer.
    /// One beyond i64 is held at its bound, which compares the same against
    /// any time.
    fn integer(&self, name: &str) -> Option<i64> {
        let text = self.written.get(name)?.get();
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(text.parse().unwrap_or(match text.starts_with('-') {
            true => i64::MIN,
            false => i64::MAX,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(header: &str, claims: &str) -> Vec<u8> {
        let e = |s: &str| RECEIVED.encode(s);
        format!("{}.{}.{}", e(header), e(claims), e("sig")).into_bytes()
    }

    const HEADER: &str = r#"{"alg":"ML-DSA-87","typ":"JWT","ucv":"0.10.0"}"#;

    #[test]
    fn a_token_is_three_parts_of_json_objects() {
        assert!(Checked::parsed(&token(HEADER, "{}")).is_ok());
        for bad in [
            b"a.b".to_vec(),
            b"a.b.c.d".to_vec(),
            token(HEADER, "[]"),
            token(HEADER, "null"),
            token(HEADER, "{} {}"),
            token("x", "{}"),
        ] {
            assert_eq!(Checked::parsed(&bad).err(), Some(Refusal::Malformed));
        }
        let padded = format!("{}=.e30.c2ln", RECEIVED.encode(HEADER));
        assert_eq!(
            Checked::parsed(padded.as_bytes()).err(),
            Some(Refusal::Malformed)
        );
    }

    #[test]
    fn a_header_of_another_algorithm_or_none_is_refused_by_name() {
        let header = |h: &str| Checked::parsed(&token(h, "{}")).unwrap();
        assert_eq!(header(HEADER).algorithm_is(Profile::PqPure), Ok(()));
        assert_eq!(
            header(HEADER).algorithm_is(Profile::PqHybrid),
            Err(Refusal::WrongAlgorithm)
        );
        assert_eq!(
            header(r#"{"alg":"ML-DSA-87","typ":"JWT","ucv":"0.9.0"}"#)
                .algorithm_is(Profile::PqPure),
            Err(Refusal::WrongAlgorithm)
        );
        assert_eq!(
            header(r#"{"alg":1,"typ":"JWT","ucv":"0.10.0"}"#).algorithm_is(Profile::PqPure),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn an_exp_or_nbf_is_an_integer_as_written() {
        let window = |claims: &str, now| {
            Checked::parsed(&token(HEADER, claims))
                .unwrap()
                .valid_at(now)
        };
        assert_eq!(window(r#"{"exp":100}"#, 99), Ok(()));
        assert_eq!(window(r#"{"exp":100}"#, 100), Err(Refusal::Expired));
        // macula reads the first of a key written twice.
        assert_eq!(
            window(r#"{"exp":100,"exp":200}"#, 150),
            Err(Refusal::Expired)
        );
        assert_eq!(window(r#"{"exp":100.0}"#, 99), Err(Refusal::Malformed));
        assert_eq!(window(r#"{"exp":1e2}"#, 99), Err(Refusal::Malformed));
        assert_eq!(
            window(r#"{"exp":99999999999999999999999}"#, 99),
            Err(Refusal::ExpBeyondMaxLifetime)
        );
        assert_eq!(
            window(r#"{"exp":100,"nbf":50}"#, 49),
            Err(Refusal::NotYetValid)
        );
        assert_eq!(
            window(r#"{"exp":100,"nbf":"50"}"#, 60),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            window(r#"{"exp":100,"nbf":null}"#, 60),
            Err(Refusal::Malformed)
        );
    }
}
