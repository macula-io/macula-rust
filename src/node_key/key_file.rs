//! Key files in macula's seed form, as macula-go writes them: the magic, the
//! purpose, profile and half count, then each half as its algorithm tag and its
//! public and private keys, each length-prefixed in four big-endian bytes. An
//! ML-DSA-87 half keeps its 32-byte seed, and an RSA-PSS half its PKCS #1 key.
//! A key file is readable by its owner only.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::KeyPair as _;
use macula_mldsa::{PrivateKey, Zeroizing, ML_DSA_87};

use super::{der, verify, NodeKey, Purpose, RsaHalf};
use crate::profile::Profile;

/// Opens every key file this crate writes. macula's own key files hold the
/// expanded ML-DSA-87 key and open with "macula-node-key-v1", so one is never
/// taken for the other.
const MAGIC: &[u8] = b"macula-node-key-seed-v1\0";

/// The most a load reads: a key file is a few KiB.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

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
    /// Writes the key to `path` in the seed form, readable by its owner only.
    /// The file is created in a new owner-only directory beside `path`,
    /// written, synced and renamed over any file at `path`; then `path`'s
    /// directory is synced and the new one removed. Nothing else in the
    /// directory is read, written or removed.
    pub fn save(&self, path: &Path) -> Result<(), KeyFileError> {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        create_dir_owner_only(dir, true)?;
        let base = path
            .file_name()
            .ok_or(KeyFileError::NotRegular)?
            .to_string_lossy();
        let staging = dir.join(format!(".{base}.saving-{}", random_suffix()?));
        create_dir_owner_only(&staging, false)?;
        let result = write_staged(&staging, path, &self.file_bytes()?).and_then(|()| sync_dir(dir));
        let removed = std::fs::remove_dir_all(&staging);
        result?;
        removed.map_err(KeyFileError::from)
    }

    /// The key saved at `path` for `purpose` in `profile`, checked before it
    /// is returned. A path that names anything but a regular file, directly
    /// or through a symlink, is refused before it is opened, and the opened
    /// file is checked again: a regular file, owned by the effective user,
    /// that its group and others cannot read, of at most 64 KiB. Then a key
    /// for another purpose or profile, halves that do not fit the profile, a
    /// stored public key its private key does not derive, and a key that
    /// fails a sign-and-verify round trip are refused.
    pub fn load(path: &Path, purpose: Purpose, profile: Profile) -> Result<NodeKey, KeyFileError> {
        let contents = read_key_file(path)?;
        let key = parse(&contents, purpose, profile)?;
        round_trip(&key)?;
        Ok(key)
    }

    /// The key laid out as a key file.
    fn file_bytes(&self) -> Result<Vec<u8>, KeyFileError> {
        let mut out = MAGIC.to_vec();
        out.extend([
            purpose_tag(self.purpose),
            profile_tag(self.profile),
            if self.rsa.is_some() { 2 } else { 1 },
        ]);
        append_half(
            &mut out,
            TAG_MLDSA_SEED,
            &self.mldsa_public,
            &self.mldsa_seed[..],
        );
        if let Some(rsa) = &self.rsa {
            let private = rsa_private_pkcs1(&rsa.pair)?;
            append_half(&mut out, TAG_RSA_PSS, &rsa.public_der, &private);
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
fn parse(bytes: &[u8], purpose: Purpose, profile: Profile) -> Result<NodeKey, KeyFileError> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(KeyFileError::BadKeyFile)?;
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
    let (mldsa_seed, mldsa_public) = mldsa_from_half(&halves[0])?;
    let rsa = if profile.hybrid() {
        Some(rsa_from_half(&halves[1])?)
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

fn mldsa_from_half(half: &StoredHalf<'_>) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KeyFileError> {
    let seed: [u8; 32] = half
        .private
        .try_into()
        .map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    let seed = Zeroizing::new(seed);
    let derived = macula_mldsa::public_key(ML_DSA_87, PrivateKey::Seed(&seed))
        .map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    if derived != half.public {
        return Err(KeyFileError::PublicKeyMismatch);
    }
    Ok((seed, derived))
}

fn rsa_from_half(half: &StoredHalf<'_>) -> Result<RsaHalf, KeyFileError> {
    let pair = RsaKeyPair::from_der(half.private).map_err(|_| KeyFileError::PrivateKeyInvalid)?;
    if pair.public_key().as_ref() != half.public {
        return Err(KeyFileError::PublicKeyMismatch);
    }
    if !der::rsa_public_key_is_4096_f4(half.public) {
        return Err(KeyFileError::WrongKeySize);
    }
    Ok(RsaHalf {
        pair,
        public_der: half.public.to_vec(),
    })
}

/// Signs a random message with the whole key and verifies it. A hybrid key
/// signs its composite, never one half on its own.
fn round_trip(key: &NodeKey) -> Result<(), KeyFileError> {
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

fn random_suffix() -> Result<String, KeyFileError> {
    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::fill(&mut bytes)
        .map_err(|_| KeyFileError::Io(std::io::Error::other("no randomness")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn write_staged(staging: &Path, path: &Path, contents: &[u8]) -> Result<(), KeyFileError> {
    let staged = staging.join("key");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&staged)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&staged, path)?;
    Ok(())
}

fn create_dir_owner_only(dir: &Path, recursive: bool) -> Result<(), KeyFileError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), KeyFileError> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// The contents of the key file at `path`, read only once the path names a
/// regular file and the opened file passes [`owner_only`].
fn read_key_file(path: &Path) -> Result<Vec<u8>, KeyFileError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(KeyFileError::NotRegular);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // Without waiting, should the path have become a FIFO since it was
    // checked.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        rustix::fs::OFlags::NONBLOCK.bits() as i32,
    );
    let file = options.open(path)?;
    owner_only(&file.metadata()?)?;
    let mut contents = Vec::new();
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(KeyFileError::TooLarge);
    }
    Ok(contents)
}

/// Refuses an opened key file that is not a regular file, not the effective
/// user's, or readable by its group or others.
fn owner_only(metadata: &std::fs::Metadata) -> Result<(), KeyFileError> {
    if !metadata.is_file() {
        return Err(KeyFileError::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(KeyFileError::Owner);
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(KeyFileError::Permissions);
        }
    }
    Ok(())
}
