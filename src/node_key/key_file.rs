//! Key files in the seed form (`seed_form`), readable by their owner only:
//! written owner-only (0o600 in a 0o700 directory) and refused on load unless
//! the effective user owns the file and its group and others cannot read it.
//! Unix only. On Windows a node key is kept in Credential Manager instead, and
//! these calls refuse with [`KeyFileError::NoKeyFile`] (`no_key_file`,
//! macula-rust#19).

use std::io::{Read, Write};
use std::path::Path;

use super::seed_form::{parse, round_trip};
use super::{KeyFileError, NodeKey, Purpose};
use crate::profile::Profile;

/// The most a load reads: a key file is a few KiB.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
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

    /// The identity key at `path` in `profile`, or, when nothing is there, a
    /// new one with the admission puzzle solved, saved there first. Anything
    /// at `path` that does not load as such a key is refused and left as it
    /// is, never replaced.
    pub fn load_or_create(path: &Path, profile: Profile) -> Result<NodeKey, KeyFileError> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = NodeKey::generate_identity(profile, super::PUZZLE_DIFFICULTY)
                    .map_err(KeyFileError::Generate)?;
                key.save(path)?;
                Ok(key)
            }
            _ => NodeKey::load(path, Purpose::Identity, profile),
        }
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
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), KeyFileError> {
    std::fs::File::open(dir)?.sync_all()?;
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
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(KeyFileError::Owner);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(KeyFileError::Permissions);
    }
    Ok(())
}
