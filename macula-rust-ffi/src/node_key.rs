//! A node's identity key: made in either profile with the admission puzzle
//! solved, and kept in an owner-only key file (unix only) or the platform's
//! secure store (Keychain on iOS, the Android Keystore, Credential Manager on
//! Windows, where a key file is refused; see [`macula_rust::keystore`] for the
//! one-time Android setup).

use std::path::Path;
use std::sync::Arc;

use macula_rust::keystore::{KeyStoreError, KeyringStore};
use macula_rust::node_key::{KeyFileError, NodeKey, Purpose, PUZZLE_DIFFICULTY};
use macula_rust::profile::Profile;

use crate::FfiError;

/// macula 12's two profiles: ML-DSA-87 alone, or ML-DSA-87 with RSA-PSS-4096
/// as a LAMPS composite.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiProfile {
    PqPure,
    PqHybrid,
}

impl From<FfiProfile> for Profile {
    fn from(p: FfiProfile) -> Self {
        match p {
            FfiProfile::PqPure => Profile::PqPure,
            FfiProfile::PqHybrid => Profile::PqHybrid,
        }
    }
}

impl From<Profile> for FfiProfile {
    fn from(p: Profile) -> Self {
        match p {
            Profile::PqPure => FfiProfile::PqPure,
            Profile::PqHybrid => FfiProfile::PqHybrid,
        }
    }
}

/// A node's identity key.
#[derive(uniffi::Object)]
pub struct FfiNodeKey(pub(crate) Arc<NodeKey>);

impl From<KeyFileError> for FfiError {
    fn from(e: KeyFileError) -> Self {
        match e {
            KeyFileError::KeyStore(KeyStoreError::NotFound) => FfiError::KeystoreNotFound,
            KeyFileError::KeyStore(other) => FfiError::Keystore {
                message: other.to_string(),
            },
            other => FfiError::Key {
                message: other.to_string(),
            },
        }
    }
}

impl From<KeyStoreError> for FfiError {
    fn from(e: KeyStoreError) -> Self {
        KeyFileError::KeyStore(e).into()
    }
}

#[uniffi::export]
impl FfiNodeKey {
    /// A new identity key in `profile` whose node_id solves the admission
    /// puzzle stations require. A pq_hybrid key takes a few seconds.
    #[uniffi::constructor]
    pub fn generate(profile: FfiProfile) -> Result<Arc<Self>, FfiError> {
        let key = NodeKey::generate_identity(profile.into(), PUZZLE_DIFFICULTY).map_err(|e| {
            FfiError::Key {
                message: e.to_string(),
            }
        })?;
        Ok(Arc::new(FfiNodeKey(Arc::new(key))))
    }

    /// The identity key in the key file at `path`, which must be owner-only
    /// and hold a key of `profile`.
    #[uniffi::constructor]
    pub fn load(path: String, profile: FfiProfile) -> Result<Arc<Self>, FfiError> {
        let key = NodeKey::load(Path::new(&path), Purpose::Identity, profile.into())?;
        Ok(Arc::new(FfiNodeKey(Arc::new(key))))
    }

    /// The identity key in the key file at `path`, or, when nothing is
    /// there, a new one saved there first. A file that does not load as a
    /// key of `profile` is refused and left as it is.
    #[uniffi::constructor]
    pub fn load_or_create(path: String, profile: FfiProfile) -> Result<Arc<Self>, FfiError> {
        let key = NodeKey::load_or_create(Path::new(&path), profile.into())?;
        Ok(Arc::new(FfiNodeKey(Arc::new(key))))
    }

    /// The identity key the platform's secure store holds under `service`
    /// and `account`, as [`save_to_keystore`](Self::save_to_keystore) put it.
    #[uniffi::constructor]
    pub fn load_from_keystore(
        service: String,
        account: String,
        profile: FfiProfile,
    ) -> Result<Arc<Self>, FfiError> {
        let store = KeyringStore::new(&service, &account)?;
        let key = NodeKey::load_from_keystore(&store, Purpose::Identity, profile.into())?;
        Ok(Arc::new(FfiNodeKey(Arc::new(key))))
    }

    /// Writes the key to an owner-only key file at `path`. Unix only: on
    /// Windows it is refused, and the key goes to Credential Manager with
    /// [`save_to_keystore`](Self::save_to_keystore).
    pub fn save(&self, path: String) -> Result<(), FfiError> {
        Ok(self.0.save(Path::new(&path))?)
    }

    /// Keeps the key in the platform's secure store under `service` and
    /// `account`, e.g. ("com.example.app", "macula-identity"): the store is
    /// shared by the whole device, so scope them to the app.
    pub fn save_to_keystore(&self, service: String, account: String) -> Result<(), FfiError> {
        let store = KeyringStore::new(&service, &account)?;
        Ok(self.0.save_to_keystore(&store)?)
    }

    /// The node_id the key proves, 32 bytes.
    pub fn node_id(&self) -> Vec<u8> {
        self.0
            .node_id()
            .expect("an identity key always has a node_id")
            .to_vec()
    }

    /// The key's profile.
    pub fn profile(&self) -> FfiProfile {
        self.0.profile().into()
    }

    /// The public key as carried on the wire.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }
}
