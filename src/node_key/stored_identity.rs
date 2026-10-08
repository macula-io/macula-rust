//! Stored identity keys, by name and profile: identity layout v1
//! (macula#76), the key a program under one user account uses when it is
//! given none. Keys sit one file per name and profile,
//! `<identity_dir>/<name>.<profile>.key`, and the single `identity.key` of
//! earlier macula releases, beside the identity directory, is moved into the
//! layout before anything is loaded. Unix only, as key files are.
//!
//! The shared vectors are macula's `test/vectors/identity_layout_v1.json`,
//! copied to `tests/vectors/identity/` and run by `tests/identity_layout.rs`.

use std::path::{Path, PathBuf};

use super::key_file::create_dir_owner_only;
use super::{KeyFileError, NodeKey, Purpose};
use crate::profile::Profile;

/// The name an identity is stored under unless the program names itself.
pub const DEFAULT_IDENTITY_NAME: &str = "default";

/// The single key file of earlier macula releases, beside the identity
/// directory.
const OLD_KEY_FILE: &str = "identity.key";

/// The longest identity name.
const MAX_NAME_BYTES: usize = 64;

/// Where identities are stored when a program names no directory: `identity`
/// in the platform's per-user data directory, where macula's
/// `filename:basedir(user_data, "macula")` puts it:
/// `$XDG_DATA_HOME/macula/identity`, or `~/.local/share/macula/identity`, and
/// on macOS `~/Library/Application Support/macula/identity`. None when HOME
/// is needed and unset.
pub fn default_identity_dir() -> Option<PathBuf> {
    let set = |var: &str| std::env::var_os(var).filter(|v| !v.is_empty());
    let home = || set("HOME").map(PathBuf::from);
    let data = if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support")
    } else {
        set("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".local/share")))?
    };
    Some(data.join("macula").join("identity"))
}

/// The file of the identity `name` in `profile` under `dir`:
/// `<name>.<profile>.key`. A name is 1 to 64 lowercase ASCII letters,
/// digits, `-` and `_`, starting with a letter or digit, so it names no other
/// directory and no other profile's key; any other is refused
/// [`KeyFileError::IdentityName`].
pub fn identity_path(dir: &Path, name: &str, profile: Profile) -> Result<PathBuf, KeyFileError> {
    if !valid_name(name) {
        return Err(KeyFileError::IdentityName(name.to_string()));
    }
    Ok(dir.join(format!("{name}.{}.key", profile.name())))
}

fn valid_name(name: &str) -> bool {
    let named = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let bytes = name.as_bytes();
    bytes.first().is_some_and(named)
        && bytes.len() <= MAX_NAME_BYTES
        && bytes.iter().all(|c| named(c) || *c == b'-' || *c == b'_')
}

impl NodeKey {
    /// The identity a program stores for `name` in `profile` under `dir`
    /// ([`default_identity_dir`] unless it names its own), with the path it
    /// is stored at: loaded, or generated with the admission puzzle solved
    /// and stored there if there is none. Two first starts at once end with
    /// one key. A key works in one profile only, so a program in both
    /// profiles is two nodes. Log the path and the node_id: a program that
    /// switches name or profile becomes another node, with no error.
    ///
    /// The old `identity.key` beside `dir` is moved first to
    /// `default.<its profile>.key`, its profile being the one it loads in,
    /// and is never read in place. The move only ever creates: another key
    /// in that place is refused [`KeyFileError::OldKeyPlaceTaken`], and an
    /// old key that will not load [`KeyFileError::OldKey`], each leaving
    /// both files as they are. A stored key that will not load is refused
    /// [`KeyFileError::StoredKey`] and never replaced.
    pub fn stored_identity(
        dir: &Path,
        name: &str,
        profile: Profile,
    ) -> Result<(NodeKey, PathBuf), KeyFileError> {
        let path = identity_path(dir, name, profile)?;
        move_old_key(dir)?;
        match NodeKey::load_or_create(&path, profile) {
            Ok(key) => Ok((key, path)),
            Err(reason) => Err(KeyFileError::StoredKey {
                path,
                reason: Box::new(reason),
            }),
        }
    }
}

/// Moves the old single key file beside `dir`, when there is one, to
/// `default.<its profile>.key` in `dir`: linked, then the old name removed.
/// The same file already in place is a move cut short, and is finished.
fn move_old_key(dir: &Path) -> Result<(), KeyFileError> {
    let old = dir.parent().unwrap_or(Path::new("")).join(OLD_KEY_FILE);
    match std::fs::symlink_metadata(&old) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(old_key(&old, e.into())),
        Ok(_) => {}
    }
    let profile = old_key_profile(&old).map_err(|e| old_key(&old, e))?;
    let to = identity_path(dir, DEFAULT_IDENTITY_NAME, profile)?;
    create_dir_owner_only(dir, true).map_err(|e| old_key(&old, e))?;
    match std::fs::hard_link(&old, &to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => same_key(&old, &to)?,
        Err(e) => return Err(old_key(&old, e.into())),
    }
    std::fs::remove_file(&old).map_err(|e| old_key(&old, e.into()))
}

/// The profile the old key loads in, as an identity key.
fn old_key_profile(old: &Path) -> Result<Profile, KeyFileError> {
    match NodeKey::load(old, Purpose::Identity, Profile::PqPure) {
        Ok(_) => Ok(Profile::PqPure),
        Err(KeyFileError::WrongProfile(found)) => {
            NodeKey::load(old, Purpose::Identity, found).map(|_| found)
        }
        Err(e) => Err(e),
    }
}

/// Ok when `to` holds the old key's bytes; otherwise the place is taken.
fn same_key(old: &Path, to: &Path) -> Result<(), KeyFileError> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| old_key(old, e.into()));
    if read(old)? == read(to)? {
        return Ok(());
    }
    Err(KeyFileError::OldKeyPlaceTaken {
        from: old.to_path_buf(),
        to: to.to_path_buf(),
    })
}

fn old_key(from: &Path, reason: KeyFileError) -> KeyFileError {
    KeyFileError::OldKey {
        from: from.to_path_buf(),
        reason: Box::new(reason),
    }
}
