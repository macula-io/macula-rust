//! End-to-end seal scheme 1 (macula 13, E2E design, amendment A1): what a
//! provider's advertisement names its KEM key by. A key travels as carried,
//! ML-KEM-1024's encapsulation key under pq_pure, followed by a P-384 point
//! under pq_hybrid, and is named by its id, the first 8 bytes of its SHA-384,
//! as macula_seal's key_id/1. Pinned by tests/vectors/seal/e2e_seal_v1.json.

use sha2::{Digest, Sha384};

use crate::profile::Profile;

/// The bytes of a key id.
pub const KEY_ID_SIZE: usize = 8;

const MLKEM_EK_BYTES: usize = 1568;
const P384_POINT_BYTES: usize = 97;

/// The size of a KEM key as carried under `profile`.
pub fn carried_key_size(profile: Profile) -> usize {
    match profile {
        Profile::PqPure => MLKEM_EK_BYTES,
        Profile::PqHybrid => MLKEM_EK_BYTES + P384_POINT_BYTES,
    }
}

/// Whether `len` is a carried KEM key's size under some profile, as
/// macula_record's kem_key_sizes/0: an advertisement's key is checked by size
/// alone, whatever the reader's profile.
pub fn is_carried_key_size(len: usize) -> bool {
    [Profile::PqPure, Profile::PqHybrid]
        .into_iter()
        .any(|p| carried_key_size(p) == len)
}

/// A carried key's id: the first 8 bytes of its SHA-384.
pub fn key_id(carried: &[u8]) -> [u8; KEY_ID_SIZE] {
    let hash = Sha384::digest(carried);
    let mut id = [0; KEY_ID_SIZE];
    id.copy_from_slice(&hash[..KEY_ID_SIZE]);
    id
}
