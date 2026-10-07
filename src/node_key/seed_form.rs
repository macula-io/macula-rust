//! macula's seed form, as macula-go writes it: the magic, the purpose,
//! profile and half count, then each half as its algorithm tag and its public
//! and private keys, each length-prefixed in four big-endian bytes. An
//! ML-DSA-87 half keeps its 32-byte seed, and an RSA-PSS half its PKCS #1 key.
//! A key file holds these bytes (`key_file`, unix only), and so does a key
//! store ([`crate::keystore`]), which is where a Windows node keeps its key.

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::KeyPair as _;
use macula_mldsa::{PrivateKey, Zeroizing, ML_DSA_87};

use super::{der, verify, KeyError, NodeKey, Purpose, RsaHalf};
use crate::keystore::{KeyStore, KeyStoreError};
use crate::profile::Profile;

/// Opens every key file this crate writes. macula's own key files hold the
/// expanded ML-DSA-87 key and open with "macula-node-key-v1", so one is never
/// taken for the other.
const MAGIC: &[u8] = b"macula-node-key-seed-v1\0";

/// Opens what a key store keeps: the key-file layout with every public key
/// left empty, derived again on load (macula-rust#19). Windows Credential
/// Manager keeps at most 2,560 bytes, which a key file with its 2,592-byte
/// ML-DSA-87 public key alone exceeds.
const STORE_MAGIC: &[u8] = b"macula-node-key-private-v1\0";

/// Which layout a key is read or written in: a key file's, with its public
/// keys, or a key store's, with none.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    File,
    Store,
}

const TAG_MLDSA_SEED: u8 = 1;
const TAG_RSA_PSS: u8 = 2;
/// Why a key file was not saved or loaded.
#[derive(Debug)]
pub enum KeyFileError {
    /// Reading or writing the file failed.
    Io(std::io::Error),
    /// The path names something other than a regular file, directly or
    /// through a symlink.
    NotRegular,
    /// Another user than the effective user owns the file.
    Owner,
    /// The file's group or others can read it.
    Permissions,
    /// The file is longer than 64 KiB, which no key file is.
    TooLarge,
    /// The file is not a key file in the seed form.
    BadKeyFile,
    /// The file holds a key for another purpose, named here.
    WrongPurpose(Purpose),
    /// The file holds a key for another profile, named here.
    WrongProfile(Profile),
    /// The key's halves do not fit its profile.
    WrongAlgorithms,
    /// The RSA-PSS half is not a 4,096-bit key with exponent 65537.
    WrongKeySize,
    /// A private key does not decode.
    PrivateKeyInvalid,
    /// A stored public key is not the one its private key derives.
    PublicKeyMismatch,
    /// The key does not sign and verify as a whole.
    RoundTripFailed,
    /// The key store could not save or load the key.
    KeyStore(KeyStoreError),
    /// A new key could not be made.
    Generate(KeyError),
    /// Key files are not kept on this platform: on Windows a node key lives
    /// in Credential Manager only, through
    /// [`KeyringStore`](crate::keystore::KeyringStore) and
    /// [`NodeKey::save_to_keystore`]/[`NodeKey::load_from_keystore`]
    /// (macula-rust#19).
    NoKeyFile,
    /// A key store holds a key in the key-file form, as macula-rust 0.7.0
    /// kept it: refused (macula-rust#19).
    KeptInTheKeyFileForm,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::Io(e) => write!(f, "key file: {e}"),
            KeyFileError::NotRegular => f.write_str("the key file is not a regular file"),
            KeyFileError::Owner => f.write_str("the key file is owned by another user"),
            KeyFileError::Permissions => {
                f.write_str("the key file can be read by its group or others")
            }
            KeyFileError::TooLarge => f.write_str("the key file is longer than 64 KiB"),
            KeyFileError::BadKeyFile => f.write_str("not a key file in the seed form"),
            KeyFileError::WrongPurpose(p) => write!(f, "the key file holds a key for {p}"),
            KeyFileError::WrongProfile(p) => write!(f, "the key file holds a key for {p}"),
            KeyFileError::WrongAlgorithms => f.write_str("the key's halves do not fit its profile"),
            KeyFileError::WrongKeySize => {
                f.write_str("the RSA-PSS half is not a 4096-bit key with exponent 65537")
            }
            KeyFileError::PrivateKeyInvalid => {
                f.write_str("the key file's private key is not valid")
            }
            KeyFileError::PublicKeyMismatch => {
                f.write_str("the stored public key is not the one its private key derives")
            }
            KeyFileError::RoundTripFailed => f.write_str("the key does not sign and verify"),
            KeyFileError::KeyStore(e) => write!(f, "key store: {e}"),
            KeyFileError::Generate(e) => write!(f, "a new key: {e}"),
            KeyFileError::KeptInTheKeyFileForm => f.write_str(
                "the key store holds a key in the key-file form macula-rust 0.7.0 kept; \
                 it no longer loads: create the identity again \
                 (NodeKey::generate_identity, then save_to_keystore)",
            ),
            KeyFileError::NoKeyFile => f.write_str(
                "no key file on this platform: keep the key in Credential Manager \
                 through keystore::KeyringStore (NodeKey::save_to_keystore)",
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

impl From<std::io::Error> for KeyFileError {
    fn from(e: std::io::Error) -> Self {
        KeyFileError::Io(e)
    }
}

impl NodeKey {
    /// Keeps the key in `store` in one write, as its private part only: the
    /// ML-DSA-87 seed, and in pq_hybrid the RSA-PSS key as PKCS #1, at most
    /// 2,429 bytes, within Windows Credential Manager's 2,560 (see
    /// `crate::keystore`). The public keys are derived again on load.
    pub fn save_to_keystore(&self, store: &dyn KeyStore) -> Result<(), KeyFileError> {
        store
            .save_key(&self.laid_out(Form::Store)?)
            .map_err(KeyFileError::KeyStore)
    }

    /// The key kept in `store` for `purpose` in `profile`, its public keys
    /// derived from its private part, then checked as a key file's is, but
    /// for the file's owner and permissions, which the store keeps. A key
    /// kept in the key-file form, as macula-rust 0.7.0 kept it, is refused
    /// [`KeyFileError::KeptInTheKeyFileForm`].
    pub fn load_from_keystore(
        store: &dyn KeyStore,
        purpose: Purpose,
        profile: Profile,
    ) -> Result<NodeKey, KeyFileError> {
        let contents = store.load_key().map_err(KeyFileError::KeyStore)?;
        if contents.starts_with(MAGIC) {
            return Err(KeyFileError::KeptInTheKeyFileForm);
        }
        let key = parse_form(&contents, Form::Store, purpose, profile)?;
        round_trip(&key)?;
        Ok(key)
    }

    /// The key laid out as a key file.
    pub(super) fn file_bytes(&self) -> Result<Vec<u8>, KeyFileError> {
        self.laid_out(Form::File)
    }

    /// The key laid out in `form`: a key store's leaves every public key
    /// empty.
    fn laid_out(&self, form: Form) -> Result<Vec<u8>, KeyFileError> {
        let (magic, with_public) = match form {
            Form::File => (MAGIC, true),
            Form::Store => (STORE_MAGIC, false),
        };
        let public = |key: &[u8]| -> Vec<u8> {
            match with_public {
                true => key.to_vec(),
                false => Vec::new(),
            }
        };
        let mut out = magic.to_vec();
        out.extend([
            purpose_tag(self.purpose),
            profile_tag(self.profile),
            if self.rsa.is_some() { 2 } else { 1 },
        ]);
        append_half(
            &mut out,
            TAG_MLDSA_SEED,
            &public(&self.mldsa_public),
            &self.mldsa_seed[..],
        );
        if let Some(rsa) = &self.rsa {
            let private = rsa_private_pkcs1(&rsa.pair)?;
            append_half(&mut out, TAG_RSA_PSS, &public(&rsa.public_der), &private);
        }
        Ok(out)
    }
}

fn purpose_tag(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Identity => 1,
        Purpose::Connect => 2,
    }
}

fn profile_tag(profile: Profile) -> u8 {
    match profile {
        Profile::PqPure => 1,
        Profile::PqHybrid => 2,
    }
}

fn append_half(out: &mut Vec<u8>, tag: u8, public: &[u8], private: &[u8]) {
    out.push(tag);
    out.extend((public.len() as u32).to_be_bytes());
    out.extend_from_slice(public);
    out.extend((private.len() as u32).to_be_bytes());
    out.extend_from_slice(private);
}

/// The RSA half's private key as PKCS #1, which aws-lc-rs hands out inside a
/// PKCS #8 `PrivateKeyInfo`.
fn rsa_private_pkcs1(pair: &RsaKeyPair) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let pkcs8 = pair.as_der().map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    der::pkcs1_of_pkcs8(pkcs8.as_ref())
        .map(Zeroizing::new)
        .ok_or(KeyFileError::PrivateKeyInvalid)
}

/// One half as a key file holds it.
struct StoredHalf<'a> {
    tag: u8,
    public: &'a [u8],
    private: &'a [u8],
}

/// A key file's key, checked for `purpose` and `profile`.
pub(super) fn parse(
    bytes: &[u8],
    purpose: Purpose,
    profile: Profile,
) -> Result<NodeKey, KeyFileError> {
    parse_form(bytes, Form::File, purpose, profile)
}

/// A key laid out in `form`, checked for `purpose` and `profile`: a key
/// file's stored public keys must be the ones its private keys derive, a key
/// store's must be empty.
fn parse_form(
    bytes: &[u8],
    form: Form,
    purpose: Purpose,
    profile: Profile,
) -> Result<NodeKey, KeyFileError> {
    let magic = match form {
        Form::File => MAGIC,
        Form::Store => STORE_MAGIC,
    };
    let rest = bytes.strip_prefix(magic).ok_or(KeyFileError::BadKeyFile)?;
    let [purpose_byte, profile_byte, count, halves_bytes @ ..] = rest else {
        return Err(KeyFileError::BadKeyFile);
    };
    let stored_purpose = match purpose_byte {
        1 => Purpose::Identity,
        2 => Purpose::Connect,
        _ => return Err(KeyFileError::BadKeyFile),
    };
    let stored_profile = match profile_byte {
        1 => Profile::PqPure,
        2 => Profile::PqHybrid,
        _ => return Err(KeyFileError::BadKeyFile),
    };
    let halves = parse_halves(halves_bytes)?;
    if halves.len() != *count as usize {
        return Err(KeyFileError::BadKeyFile);
    }
    if stored_purpose != purpose {
        return Err(KeyFileError::WrongPurpose(stored_purpose));
    }
    if stored_profile != profile {
        return Err(KeyFileError::WrongProfile(stored_profile));
    }
    let fits = match profile {
        Profile::PqPure => halves.len() == 1 && halves[0].tag == TAG_MLDSA_SEED,
        Profile::PqHybrid => {
            halves.len() == 2 && halves[0].tag == TAG_MLDSA_SEED && halves[1].tag == TAG_RSA_PSS
        }
    };
    if !fits {
        return Err(KeyFileError::WrongAlgorithms);
    }
    let (mldsa_seed, mldsa_public) = mldsa_from_half(&halves[0], form)?;
    let rsa = if profile.hybrid() {
        Some(rsa_from_half(&halves[1], form)?)
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

fn parse_halves(mut bytes: &[u8]) -> Result<Vec<StoredHalf<'_>>, KeyFileError> {
    let mut halves = Vec::new();
    while let Some((&tag, rest)) = bytes.split_first() {
        if tag != TAG_MLDSA_SEED && tag != TAG_RSA_PSS {
            return Err(KeyFileError::BadKeyFile);
        }
        let (public, rest) = length_prefixed(rest)?;
        let (private, rest) = length_prefixed(rest)?;
        halves.push(StoredHalf {
            tag,
            public,
            private,
        });
        bytes = rest;
    }
    Ok(halves)
}

fn length_prefixed(bytes: &[u8]) -> Result<(&[u8], &[u8]), KeyFileError> {
    let (len, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or(KeyFileError::BadKeyFile)?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > rest.len() {
        return Err(KeyFileError::BadKeyFile);
    }
    Ok(rest.split_at(len))
}

/// The stored public key checked against the one derived: equal in a key
/// file, absent in a key store.
fn stored_public_fits(stored: &[u8], derived: &[u8], form: Form) -> Result<(), KeyFileError> {
    let fits = match form {
        Form::File => stored == derived,
        Form::Store => stored.is_empty(),
    };
    match fits {
        true => Ok(()),
        false => Err(KeyFileError::PublicKeyMismatch),
    }
}

fn mldsa_from_half(
    half: &StoredHalf<'_>,
    form: Form,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KeyFileError> {
    let seed: [u8; 32] = half
        .private
        .try_into()
        .map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    let seed = Zeroizing::new(seed);
    let derived = macula_mldsa::public_key(ML_DSA_87, PrivateKey::Seed(&seed))
        .map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    stored_public_fits(half.public, &derived, form)?;
    Ok((seed, derived))
}

fn rsa_from_half(half: &StoredHalf<'_>, form: Form) -> Result<RsaHalf, KeyFileError> {
    let pair = RsaKeyPair::from_der(half.private).map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    let derived = pair.public_key().as_ref().to_vec();
    stored_public_fits(half.public, &derived, form)?;
    if !der::rsa_public_key_is_4096_f4(&derived) {
        return Err(KeyFileError::WrongKeySize);
    }
    Ok(RsaHalf {
        pair,
        public_der: derived,
    })
}

/// Signs a random message with the whole key and verifies it. A hybrid key
/// signs its composite, never one half on its own.
pub(super) fn round_trip(key: &NodeKey) -> Result<(), KeyFileError> {
    let mut message = [0u8; 32];
    aws_lc_rs::rand::fill(&mut message).map_err(|_| KeyFileError::RoundTripFailed)?;
    let signature = key
        .sign(&message)
        .map_err(|_| KeyFileError::RoundTripFailed)?;
    if verify(&message, &signature, &key.public_key(), key.profile) {
        Ok(())
    } else {
        Err(KeyFileError::RoundTripFailed)
    }
}

#[cfg(test)]
mod tests {
    //! What a key store keeps (macula-rust#19): the private part only, small
    //! enough for Windows Credential Manager's 2,560-byte secret in either
    //! profile, and a key kept by 0.7.0 in the key-file form refused with its
    //! cause and fix.

    use std::sync::Mutex;

    use super::*;

    /// Credential Manager's limit on one secret (CRED_MAX_CREDENTIAL_BLOB_SIZE).
    const CREDENTIAL_MANAGER_MAX: usize = 2560;

    /// The longest PKCS #1 RSAPrivateKey of a 4,096-bit key with exponent
    /// 65537, in DER: the SEQUENCE header (4) around version (3), modulus
    /// (4 + 513), publicExponent (2 + 3), privateExponent (4 + 513), and
    /// prime1, prime2, exponent1, exponent2 and coefficient, each at most
    /// 2,048 bits (4 + 257 with a sign byte).
    const MAX_RSA4096_PKCS1: usize = 4 + 3 + (4 + 513) + (2 + 3) + (4 + 513) + 5 * (4 + 257);

    /// A key store in memory.
    #[derive(Default)]
    struct Memory(Mutex<Option<Vec<u8>>>);

    impl KeyStore for Memory {
        fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
            *self.0.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }

        fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
            let held = self.0.lock().unwrap().clone();
            held.map(Zeroizing::new).ok_or(KeyStoreError::NotFound)
        }

        fn delete_key(&self) -> Result<(), KeyStoreError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn kept(store: &Memory) -> usize {
        store.0.lock().unwrap().as_ref().map_or(0, Vec::len)
    }

    /// The bytes a store keeps of a new `profile` key, its PKCS #1 RSA key
    /// counted at its longest, and the key loaded back from the store.
    fn kept_at_worst(profile: Profile) -> usize {
        let key = NodeKey::generate_identity(profile, 0).unwrap();
        let store = Memory::default();
        key.save_to_keystore(&store).unwrap();
        let loaded = NodeKey::load_from_keystore(&store, Purpose::Identity, profile).unwrap();
        assert_eq!(loaded.public_key(), key.public_key(), "{profile:?}");
        let Some(rsa) = &key.rsa else {
            return kept(&store);
        };
        let pkcs1 = rsa_private_pkcs1(&rsa.pair).unwrap().len();
        assert!(pkcs1 <= MAX_RSA4096_PKCS1, "{pkcs1}");
        kept(&store) - pkcs1 + MAX_RSA4096_PKCS1
    }

    #[test]
    fn a_kept_key_fits_credential_manager_at_the_worst_rsa_size() {
        for profile in [Profile::PqPure, Profile::PqHybrid] {
            let worst = kept_at_worst(profile);
            assert!(
                worst <= CREDENTIAL_MANAGER_MAX,
                "{profile:?}: {worst} bytes"
            );
        }
    }

    #[test]
    fn a_key_kept_in_the_0_7_0_form_is_refused_naming_the_fix() {
        let key = NodeKey::generate_identity(Profile::PqPure, 0).unwrap();
        let store = Memory::default();
        store.save_key(&key.file_bytes().unwrap()).unwrap();
        let Err(e) = NodeKey::load_from_keystore(&store, Purpose::Identity, Profile::PqPure) else {
            panic!("the 0.7.0 form is refused");
        };
        assert!(matches!(e, KeyFileError::KeptInTheKeyFileForm), "{e:?}");
        assert!(e.to_string().contains("create the identity again"), "{e}");
    }
}
