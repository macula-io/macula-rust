//! did:key for a node key as carried: `did:key:z` and the base58btc of the
//! key type's unsigned LEB128 varint, then the key. The key type is
//! mldsa-87-pub (0x1212) in pq_pure, and Macula's own, private-use
//! (0x300087), for pq_hybrid's composite, which has no multicodec yet.

use super::Refusal;
use crate::node_key::carried_key_well_formed;
use crate::profile::Profile;

const CODEC_MLDSA87: u64 = 0x1212;
const CODEC_MLDSA87_RSA4096: u64 = 0x30_0087;

const PREFIX: &str = "did:key:z";

/// The longest base58btc text a did:key for a node key can have: a pq_hybrid
/// key, the longest, is a 3-byte codec varint, the 2,592-byte ML-DSA-87 key
/// and a DER RSA-4096 public key of about 526 bytes, some 4,270 characters.
/// Anything longer is malformed, refused before it is decoded: base58 decodes
/// in time quadratic in its length, ahead of the signature check. macula pins
/// it in ucan_v1.json (`did_key_length`, macula#87).
pub const MAX_DID_KEY_ENCODED: usize = 4_400;
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The did:key for a key as carried in `profile`.
pub fn did_key(carried: &[u8], profile: Profile) -> String {
    let mut bytes = varint(codec(profile));
    bytes.extend_from_slice(carried);
    format!("{PREFIX}{}", base58btc_encode(&bytes))
}

/// The key a did:key carries, when it is a key in its one carried form for
/// `profile` (D13); [`Refusal::Malformed`] otherwise.
pub fn carried_key(did: &str, profile: Profile) -> Result<Vec<u8>, Refusal> {
    let encoded = did.strip_prefix(PREFIX).ok_or(Refusal::Malformed)?;
    if encoded.len() > MAX_DID_KEY_ENCODED {
        return Err(Refusal::Malformed);
    }
    let prefix = varint(codec(profile));
    let decoded = base58btc_decode(encoded).ok_or(Refusal::Malformed)?;
    match decoded.strip_prefix(prefix.as_slice()) {
        Some(carried) if !carried.is_empty() && carried_key_well_formed(carried, profile) => {
            Ok(carried.to_vec())
        }
        _ => Err(Refusal::Malformed),
    }
}

fn codec(profile: Profile) -> u64 {
    match profile {
        Profile::PqPure => CODEC_MLDSA87,
        Profile::PqHybrid => CODEC_MLDSA87_RSA4096,
    }
}

/// An unsigned LEB128 varint, as multicodec prefixes are written.
fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n >= 0x80 {
        out.push((n & 0x7f) as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
    out
}

/// base58 with the Bitcoin alphabet, as multibase's base58btc: each leading
/// zero byte is a leading `1`.
fn base58btc_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &bytes[zeros..] {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// The bytes a base58btc text encodes, or `None` for a text with a
/// character outside the alphabet.
fn base58btc_decode(text: &str) -> Option<Vec<u8>> {
    let ones = text.bytes().take_while(|&b| b == b'1').count();
    let mut value: Vec<u8> = Vec::new();
    for c in text[ones..].bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for byte in value.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            value.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; ones];
    out.extend(value.iter().rev());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58btc_round_trips_and_keeps_leading_zeros() {
        for bytes in [
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![0xff; 40],
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            let text = base58btc_encode(&bytes);
            assert_eq!(base58btc_decode(&text), Some(bytes.clone()), "{text}");
        }
        assert_eq!(base58btc_encode(&[0, 0, 0x3a]), "1121");
        assert_eq!(base58btc_decode("0OIl"), None);
    }

    #[test]
    fn the_key_types_are_leb128_varints() {
        assert_eq!(varint(CODEC_MLDSA87), vec![0x92, 0x24]);
        assert_eq!(varint(CODEC_MLDSA87_RSA4096), vec![0x87, 0x81, 0xc0, 0x01]);
    }

    #[test]
    fn a_did_key_of_another_shape_carries_no_key() {
        assert_eq!(
            carried_key("did:key:x", Profile::PqPure),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            carried_key("did:key:z", Profile::PqPure),
            Err(Refusal::Malformed)
        );
        let short = did_key(&[1, 2, 3], Profile::PqPure);
        assert_eq!(
            carried_key(&short, Profile::PqPure),
            Err(Refusal::Malformed)
        );
    }
}
