//! Key files are not kept on Windows (macula-rust#19): a node key there lives
//! in Credential Manager only, through [`crate::keystore::KeyringStore`].
//! [`NodeKey::save`], [`NodeKey::load`] and [`NodeKey::load_or_create`] refuse
//! with [`KeyFileError::NoKeyFile`], which names the store to use, so a caller
//! never gets a key file without owner-only protection.

use std::path::Path;

use super::{KeyFileError, NodeKey, Purpose};
use crate::profile::Profile;

impl NodeKey {
    /// Refused on this platform: keep the key with
    /// [`NodeKey::save_to_keystore`] and a
    /// [`KeyringStore`](crate::keystore::KeyringStore).
    pub fn save(&self, _path: &Path) -> Result<(), KeyFileError> {
        Err(KeyFileError::NoKeyFile)
    }

    /// Refused on this platform: load the key with
    /// [`NodeKey::load_from_keystore`] and a
    /// [`KeyringStore`](crate::keystore::KeyringStore).
    pub fn load(
        _path: &Path,
        _purpose: Purpose,
        _profile: Profile,
    ) -> Result<NodeKey, KeyFileError> {
        Err(KeyFileError::NoKeyFile)
    }

    /// Refused on this platform, as [`NodeKey::load`] is.
    pub fn load_or_create(_path: &Path, _profile: Profile) -> Result<NodeKey, KeyFileError> {
        Err(KeyFileError::NoKeyFile)
    }
}
