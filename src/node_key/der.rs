//! The little DER a node key reads: an `RSAPublicKey`'s modulus and exponent,
//! and the PKCS #1 key inside a PKCS #8 `PrivateKeyInfo`. Definite lengths in
//! their shortest form only, as DER has them; anything else is refused.

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;

/// The element at the start of `input` with `tag`: its content, and what
/// follows it.
fn element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first != tag {
        return None;
    }
    let (&len0, rest) = rest.split_first()?;
    let (len, rest) = if len0 < 0x80 {
        (len0 as usize, rest)
    } else {
        let count = (len0 & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count || rest[0] == 0 {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |n, &b| (n << 8) | b as usize);
        if len < 0x80 {
            return None;
        }
        (len, &rest[count..])
    };
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Whether `der` is exactly an `RSAPublicKey` with a 4,096-bit modulus and the
/// exponent 65537, each a minimal positive INTEGER.
pub(super) fn rsa_public_key_is_4096_f4(der: &[u8]) -> bool {
    let Some((body, [])) = element(der, SEQUENCE) else {
        return false;
    };
    let Some((modulus, rest)) = element(body, INTEGER) else {
        return false;
    };
    let Some((exponent, [])) = element(rest, INTEGER) else {
        return false;
    };
    modulus.len() == 513
        && modulus[0] == 0
        && modulus[1] & 0x80 != 0
        && exponent == [0x01, 0x00, 0x01]
}

/// The PKCS #1 `RSAPrivateKey` a PKCS #8 `PrivateKeyInfo` holds.
pub(super) fn pkcs1_of_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let (body, rest) = element(pkcs8, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (_version, rest) = element(body, INTEGER)?;
    let (_algorithm, rest) = element(rest, SEQUENCE)?;
    let (key, _attributes) = element(rest, OCTET_STRING)?;
    Some(key.to_vec())
}
