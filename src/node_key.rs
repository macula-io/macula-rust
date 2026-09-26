//! A macula 12 node's keys, as macula and macula-go hold them: ML-DSA-87 in
//! pq_pure, and in pq_hybrid the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512
//! (draft-ietf-lamps-pq-composite-sigs), which signs with both halves and is
//! valid only when both verify. An identity key's node_id (D5) solves the
//! admission puzzle; a CONNECT key is bound to it (see `crate::binding`).
//! Keys are stored in macula's seed form, readable by their owner only (see
//! [`NodeKey::save`] and [`NodeKey::load`]).
//!
//! The ML-DSA-87 half is macula-mldsa, the implementation macula-pqc signs
//! TLS with, kept as its 32-byte seed. The RSA-PSS-4096 half is aws-lc-rs,
//! already linked through rustls: constant-time, with a FIPS path.

mod der;
mod key_file;

pub use key_file::KeyFileError;

use std::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    KeyPair as _, UnparsedPublicKey, RSA_PSS_2048_8192_SHA384, RSA_PSS_SHA384,
};
use macula_mldsa::{PrivateKey, Zeroizing, ML_DSA_87};
use sha2::{Digest, Sha256, Sha512};

use crate::profile::Profile;

/// How many leading zero bits an identity key's node_id has: a node generates
/// its identity key for it ([`NodeKey::generate_identity`]), and stations
/// check it.
pub const PUZZLE_DIFFICULTY: u32 = 8;

const MLDSA_PUBLIC_KEY_SIZE: usize = 2592;
const MLDSA_SIGNATURE_SIZE: usize = 4627;
const RSA_MODULUS_BYTES: usize = 512;
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const COMPOSITE_LABEL: &[u8] = b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512";
const NODE_ID_LABEL: &[u8] = b"MACULA-NODE-ID-V1";
const KEY_ID_LABEL: &[u8] = b"MACULA-KEY-ID-V1";

/// What a node key is for. Each key serves exactly one purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// A node's identity key, the key its node_id derives from and that signs
    /// its bindings, status statements and signed objects.
    Identity,
    /// A node's CONNECT key, bound to its identity key, which signs the proof
    /// of each connection it makes.
    Connect,
}

impl Purpose {
    /// The purpose's name.
    pub fn name(self) -> &'static str {
        match self {
            Purpose::Identity => "identity",
            Purpose::Connect => "connect",
        }
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a key operation refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// A node_id asked of a key that is not an identity key.
    NotAnIdentityKey,
    /// A puzzle difficulty outside 0 to 256.
    DifficultyOutOfRange(u32),
    /// The operating system gave no randomness.
    RandomnessUnavailable,
    /// Generating a half failed.
    Generate(&'static str),
    /// Signing with a half failed.
    Sign(&'static str),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NotAnIdentityKey => f.write_str("not an identity key"),
            KeyError::DifficultyOutOfRange(d) => {
                write!(f, "puzzle difficulty {d} is outside 0 to 256")
            }
            KeyError::RandomnessUnavailable => {
                f.write_str("the operating system gave no randomness")
            }
            KeyError::Generate(half) => write!(f, "could not generate the {half} half"),
            KeyError::Sign(half) => write!(f, "could not sign with the {half} half"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The RSA-PSS-4096 half of a pq_hybrid key.
struct RsaHalf {
    pair: RsaKeyPair,
    /// The DER `RSAPublicKey`, as carried after the ML-DSA-87 key.
    public_der: Vec<u8>,
}

/// One of a node's keys in its profile: the ML-DSA-87 half, and in pq_hybrid
/// the RSA-PSS-4096 half. It signs as a whole, never with one half on its own.
/// Showing it gives its purpose, profile and key id, never a private half.
pub struct NodeKey {
    purpose: Purpose,
    profile: Profile,
    mldsa_seed: Zeroizing<[u8; 32]>,
    mldsa_public: Vec<u8>,
    rsa: Option<RsaHalf>,
}

impl NodeKey {
    /// A new key for `purpose` in `profile`.
    pub fn generate(purpose: Purpose, profile: Profile) -> Result<NodeKey, KeyError> {
        let (mldsa_public, mldsa_seed) =
            macula_mldsa::key_gen_seed(ML_DSA_87).map_err(|_| KeyError::RandomnessUnavailable)?;
        let rsa = if profile.hybrid() {
            let pair = RsaKeyPair::generate(KeySize::Rsa4096)
                .map_err(|_| KeyError::Generate("RSA-4096"))?;
            let public_der = pair.public_key().as_ref().to_vec();
            Some(RsaHalf { pair, public_der })
        } else {
            None
        };
        Ok(NodeKey {
            purpose,
            profile,
            mldsa_seed,
            mldsa_public,
            rsa,
        })
    }

    /// A new identity key in `profile` whose node_id starts with `difficulty`
    /// zero bits, found in about 2^difficulty tries. Each try makes a new
    /// ML-DSA-87 half; a pq_hybrid key keeps its RSA-PSS half, since the
    /// node_id covers both.
    pub fn generate_identity(profile: Profile, difficulty: u32) -> Result<NodeKey, KeyError> {
        if difficulty > 256 {
            return Err(KeyError::DifficultyOutOfRange(difficulty));
        }
        let mut key = NodeKey::generate(Purpose::Identity, profile)?;
        while !puzzle_solved(&node_id_of(&key.public_key(), profile), difficulty) {
            let (public, seed) = macula_mldsa::key_gen_seed(ML_DSA_87)
                .map_err(|_| KeyError::RandomnessUnavailable)?;
            key.mldsa_public = public;
            key.mldsa_seed = seed;
        }
        Ok(key)
    }

    /// What the key is for.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The profile the key belongs to.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The key as carried (D13): the 2,592-byte ML-DSA-87 key, followed in
    /// pq_hybrid by the DER `RSAPublicKey`.
    pub fn public_key(&self) -> Vec<u8> {
        let mut carried = self.mldsa_public.clone();
        if let Some(rsa) = &self.rsa {
            carried.extend_from_slice(&rsa.public_der);
        }
        carried
    }

    /// The node_id of an identity key (D5).
    pub fn node_id(&self) -> Result<[u8; 32], KeyError> {
        match self.purpose {
            Purpose::Identity => Ok(node_id_of(&self.public_key(), self.profile)),
            Purpose::Connect => Err(KeyError::NotAnIdentityKey),
        }
    }

    /// The id that names the key in signed objects: an identity key's
    /// node_id, and the key id of any other key.
    pub fn key_id(&self) -> [u8; 32] {
        match self.purpose {
            Purpose::Identity => node_id_of(&self.public_key(), self.profile),
            Purpose::Connect => key_id_of(&self.public_key(), self.profile),
        }
    }

    /// Signs `message`: with ML-DSA-87 alone in pq_pure, and in pq_hybrid with
    /// the composite, where both halves sign the message representative, the
    /// ML-DSA-87 half with the composite label as its context, and the
    /// signature is the ML-DSA-87 signature followed by the RSA-PSS one.
    /// ML-DSA-87 signs hedged and RSA-PSS salted, so each signature is new.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let seed = PrivateKey::Seed(&self.mldsa_seed);
        let Some(rsa) = &self.rsa else {
            return macula_mldsa::sign(ML_DSA_87, seed, message, &[])
                .map_err(|_| KeyError::Sign("ML-DSA-87"));
        };
        let representative = composite_representative(message);
        let mut signature = macula_mldsa::sign(ML_DSA_87, seed, &representative, COMPOSITE_LABEL)
            .map_err(|_| KeyError::Sign("ML-DSA-87"))?;
        let mut rsa_signature = vec![0u8; rsa.pair.public_modulus_len()];
        rsa.pair
            .sign(
                &RSA_PSS_SHA384,
                &SystemRandom::new(),
                &representative,
                &mut rsa_signature,
            )
            .map_err(|_| KeyError::Sign("RSA-PSS"))?;
        signature.extend_from_slice(&rsa_signature);
        Ok(signature)
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} key {}",
            self.purpose,
            self.profile,
            hex_of(&self.key_id())
        )
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Whether `signature` is valid over `message` for a key as carried, under
/// `profile`: an ML-DSA-87 signature in pq_pure, and in pq_hybrid a composite
/// whose two halves both verify, with the key in its one carried form.
/// Malformed input is refused, never panicked on.
pub fn verify(message: &[u8], signature: &[u8], carried_key: &[u8], profile: Profile) -> bool {
    if !profile.hybrid() {
        return signature.len() == MLDSA_SIGNATURE_SIZE
            && carried_key.len() == MLDSA_PUBLIC_KEY_SIZE
            && macula_mldsa::verify(ML_DSA_87, carried_key, message, signature, &[]) == Ok(true);
    }
    if signature.len() != signature_size(profile) || !carried_key_well_formed(carried_key, profile)
    {
        return false;
    }
    let representative = composite_representative(message);
    let (mldsa_public, rsa_public) = carried_key.split_at(MLDSA_PUBLIC_KEY_SIZE);
    let (mldsa_signature, rsa_signature) = signature.split_at(MLDSA_SIGNATURE_SIZE);
    let mldsa_valid = macula_mldsa::verify(
        ML_DSA_87,
        mldsa_public,
        &representative,
        mldsa_signature,
        COMPOSITE_LABEL,
    ) == Ok(true);
    let rsa_valid = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, rsa_public)
        .verify(&representative, rsa_signature)
        .is_ok();
    mldsa_valid && rsa_valid
}

/// Whether `key` is a key in its one carried form for `profile` (D13): exactly
/// 2,592 bytes in pq_pure, and in pq_hybrid the ML-DSA-87 key followed by a DER
/// `RSAPublicKey` that encodes back to the same bytes, with a 4,096-bit modulus
/// and exponent 65537. It says nothing about who holds the key.
pub fn carried_key_well_formed(key: &[u8], profile: Profile) -> bool {
    if !profile.hybrid() {
        return key.len() == MLDSA_PUBLIC_KEY_SIZE;
    }
    if key.len() <= MLDSA_PUBLIC_KEY_SIZE {
        return false;
    }
    let der = &key[MLDSA_PUBLIC_KEY_SIZE..];
    der::rsa_public_key_is_4096_f4(der)
        && aws_lc_rs::rsa::PublicKey::from_der(der).is_ok_and(|parsed| parsed.as_ref() == der)
}

/// The size of a signature by a node key in `profile`: the ML-DSA-87
/// signature, followed in pq_hybrid by an RSA-PSS signature as long as the
/// modulus.
pub fn signature_size(profile: Profile) -> usize {
    if profile.hybrid() {
        MLDSA_SIGNATURE_SIZE + RSA_MODULUS_BYTES
    } else {
        MLDSA_SIGNATURE_SIZE
    }
}

/// The node_id of an identity key as carried, under `profile` (D5). A node_id
/// earns no trust on its own: rely on it only after a signature by the same
/// carried key has verified.
pub fn node_id_of(carried_key: &[u8], profile: Profile) -> [u8; 32] {
    labelled_id(NODE_ID_LABEL, carried_key, profile)
}

/// The key id of a key as carried that is not an identity key. Like a
/// node_id, it earns no trust on its own.
pub fn key_id_of(carried_key: &[u8], profile: Profile) -> [u8; 32] {
    labelled_id(KEY_ID_LABEL, carried_key, profile)
}

/// SHA-256 over `label`, a zero byte, the length and ASCII name of
/// `profile`, and a key as carried.
fn labelled_id(label: &[u8], carried_key: &[u8], profile: Profile) -> [u8; 32] {
    let name = profile.name();
    let mut h = Sha256::new();
    h.update(label);
    h.update([0, name.len() as u8]);
    h.update(name.as_bytes());
    h.update(carried_key);
    h.finalize().into()
}

/// Whether `node_id` starts with `difficulty` zero bits. A difficulty above
/// 256 is never solved.
pub fn puzzle_solved(node_id: &[u8; 32], difficulty: u32) -> bool {
    if difficulty > 256 {
        return false;
    }
    let (whole, rest) = ((difficulty / 8) as usize, difficulty % 8);
    node_id[..whole].iter().all(|&b| b == 0) && (rest == 0 || node_id[whole] >> (8 - rest) == 0)
}

/// The message both halves of a composite sign: the prefix, the label, a zero
/// byte for the empty application context, and the SHA-512 of the message.
fn composite_representative(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMPOSITE_PREFIX.len() + COMPOSITE_LABEL.len() + 1 + 64);
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(COMPOSITE_LABEL);
    out.push(0);
    out.extend_from_slice(&Sha512::digest(message));
    out
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
