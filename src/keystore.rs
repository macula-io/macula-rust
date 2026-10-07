//! Overridable, per-platform secure storage for a node key.
//!
//! Where a node key is kept at rest:
//!
//! - **unix**: an owner-only key file
//!   ([`NodeKey::save`](crate::node_key::NodeKey::save)/[`load`](crate::node_key::NodeKey::load),
//!   0o600 in a 0o700 directory, refused on load unless the effective user
//!   owns it and nobody else can read it), or a key store from this module:
//!   Linux keyutils ([`LinuxKeyutilsStore`]) or the platform's secure store
//!   ([`KeyringStore`]).
//! - **Windows**: Credential Manager only, through [`KeyringStore`]. A key
//!   file is refused there with
//!   [`KeyFileError::NoKeyFile`](crate::node_key::KeyFileError::NoKeyFile)
//!   (macula-rust#19).
//! - **mobile**: the platform's secure store, through [`KeyringStore`].
//!
//! Every store keeps the key's private part only, in one write: the
//! ML-DSA-87 seed, and in pq_hybrid the RSA-PSS key as PKCS #1, at most 2,429
//! bytes, within Credential Manager's 2,560-byte limit on one secret. The
//! public keys are derived again on load. A key kept by macula-rust 0.7.0, in
//! the key-file form, no longer loads; create the identity again.
//!
//! This module is
//! a small [`KeyStore`] trait plus [`KeyringStore`], a
//! default implementation backed by the `keyring` crate, which selects the
//! actual native secure store per target automatically —
//! Keychain (`Security.framework`) on macOS and iOS, Secret Service (D-Bus)
//! on Linux, Credential Manager on Windows, and the Android Keystore (via
//! JNI) on Android. Nothing in this crate branches on target platform
//! itself; `keyring`'s own `Cargo.toml` does that selection via per-target
//! optional dependencies (see `keyring = 4.2.0`'s manifest), and the
//! backend that ends up linked is what actually runs.
//!
//! [`KeyStore`] itself is deliberately not tied to `keyring` at all — a
//! caller with a different secure-storage requirement (a hardware security
//! module, a different vault) can implement the trait directly and hand it
//! to [`NodeKey::save_to_keystore`](crate::node_key::NodeKey::save_to_keystore)/
//! [`load_from_keystore`](crate::node_key::NodeKey::load_from_keystore) —
//! "overridable per target platform" is a property of the trait boundary,
//! not something wired into this crate's own logic.
//!
//! ## Android setup, required once per app, not something this crate can do for you
//!
//! `android-native-keyring-store` (the backend `keyring` links in for
//! Android, confirmed via its own `Cargo.toml`: `jni` + `ndk-context`)
//! needs the embedding app to hand it a JNI `Context` once at startup,
//! because Android's Keystore is a Java API with no NDK surface — there is
//! no way for Rust code alone to reach it. That crate ships its own JNI
//! export for exactly this (confirmed in its README, not assumed): once
//! this crate is linked into an Android `.so`, that export is present
//! automatically, and the Kotlin side calls it once, e.g. from
//! `MainActivity.onCreate`:
//!
//! ```kotlin
//! package io.crates.keyring
//! class Keyring {
//!     companion object {
//!         init { System.loadLibrary("your_actual_library_name") }
//!         external fun initializeNdkContext(context: Context)
//!     }
//! }
//! // in onCreate:
//! Keyring.initializeNdkContext(this.applicationContext)
//! ```
//!
//! No custom UniFFI foreign-trait bridge is needed for Android or iOS —
//! both have first-party `keyring` backends, confirmed by reading
//! `keyring` 4.2.0's own `Cargo.toml` target-cfg dependency blocks
//! directly, not assumed from the crate's name.
//!
//! ## A second Linux backend, [`LinuxKeyutilsStore`]
//!
//! `KeyringStore`'s Linux path (`keyring`'s `v1` API) unconditionally uses
//! the D-Bus Secret Service, which requires a running provider
//! (`gnome-keyring`, KWallet) — absent on headless boxes, containers, and
//! this crate's own dev sandbox (confirmed directly: a D-Bus session
//! socket exists here, but no `org.freedesktop.secrets` provider is
//! listening on it, so `KeyringStore::new` returns
//! [`KeyStoreError::Backend`] with `NoDefaultStore`). [`LinuxKeyutilsStore`]
//! uses the kernel's own `keyutils` facility instead, always available on
//! Linux — this is exactly what lets this module's own tests verify a
//! real save/load/delete round trip in this environment.

use keyring::Entry;
use macula_mldsa::Zeroizing;

/// Secure storage for one node key, as the bytes of its key file (the seed
/// form: the ML-DSA-87 seed, and in pq_hybrid the RSA-PSS key too, a few KiB).
/// Implement this directly for a backend other than [`KeyringStore`] (a
/// hardware security module, a different vault) — this is the override point
/// "per target platform" hangs off, not a platform enum this crate switches on
/// internally.
pub trait KeyStore {
    /// Persist `key`, overwriting any value already stored under this
    /// store's identity.
    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError>;

    /// Retrieve a previously-[`save_key`](Self::save_key)d key.
    /// [`KeyStoreError::NotFound`] if nothing has been stored yet.
    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyStoreError>;

    /// Remove a previously-stored key, if any. Not required before a
    /// [`save_key`](Self::save_key) (which overwrites), only for
    /// deliberately forgetting an identity.
    fn delete_key(&self) -> Result<(), KeyStoreError>;
}

/// The default [`KeyStore`]: the platform-native secure store `keyring`
/// selects for the current target (see this module's own doc). `service`
/// and `account` are the same two strings every `keyring` consumer already
/// uses to address one credential — pick values scoped to this
/// application, e.g. `("com.example.myapp", "macula-identity")`, since the
/// underlying stores are shared OS-wide facilities, not sandboxed to this
/// crate.
pub struct KeyringStore {
    entry: Entry,
}

impl KeyringStore {
    pub fn new(service: &str, account: &str) -> Result<Self, KeyStoreError> {
        Ok(Self {
            entry: Entry::new(service, account)?,
        })
    }
}

impl KeyStore for KeyringStore {
    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        self.entry.set_secret(key)?;
        Ok(())
    }

    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        match self.entry.get_secret() {
            Ok(secret) => Ok(Zeroizing::new(secret)),
            Err(keyring::Error::NoEntry) => Err(KeyStoreError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    fn delete_key(&self) -> Result<(), KeyStoreError> {
        match self.entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// A second, independently-selectable [`KeyStore`] backend — proof that
/// the trait boundary is genuinely overridable, not merely declared to be:
/// the kernel's own `keyutils` facility, no D-Bus/secret-service daemon
/// required. This is what [`KeyringStore`]'s underlying `keyring`
/// dependency itself recommends for headless Linux (containers, CI, a
/// sandboxed dev box with no `gnome-keyring`/`kwalletd` running) — see
/// `linux-keyutils-keyring-store`'s own module doc, which states this
/// outright.
///
/// Deliberately does NOT go through `keyring`'s own `v1::Entry`/
/// `keyring_core::set_default_store` (a process-global) — doing so would
/// silently fight [`KeyringStore`]'s own default-store selection if both
/// were ever constructed in the same process, with whichever initializes
/// first winning. Instead this holds its own `Store` instance and asks it
/// directly for a credential via `CredentialStoreApi::build`, which never
/// touches the global default at all.
#[cfg(target_os = "linux")]
pub struct LinuxKeyutilsStore {
    entry: keyring_core::Entry,
}

#[cfg(target_os = "linux")]
impl LinuxKeyutilsStore {
    pub fn new(service: &str, account: &str) -> Result<Self, KeyStoreError> {
        use keyring_core::api::CredentialStoreApi;

        let store = linux_keyutils_keyring_store::Store::new()?;
        let entry = store.build(service, account, None)?;
        Ok(Self { entry })
    }
}

#[cfg(target_os = "linux")]
impl KeyStore for LinuxKeyutilsStore {
    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        self.entry.set_secret(key)?;
        Ok(())
    }

    fn load_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        match self.entry.get_secret() {
            Ok(secret) => Ok(Zeroizing::new(secret)),
            Err(keyring_core::Error::NoEntry) => Err(KeyStoreError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    fn delete_key(&self) -> Result<(), KeyStoreError> {
        match self.entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Debug)]
pub enum KeyStoreError {
    /// No key has been stored yet under this store's identity.
    NotFound,
    /// The underlying platform secure store rejected the operation.
    Backend(keyring::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreError::NotFound => write!(f, "no key stored under this identity"),
            KeyStoreError::Backend(e) => write!(f, "platform secure store error: {e}"),
        }
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyStoreError::Backend(e) => Some(e),
            _ => None,
        }
    }
}

impl From<keyring::Error> for KeyStoreError {
    fn from(e: keyring::Error) -> Self {
        match e {
            keyring::Error::NoEntry => KeyStoreError::NotFound,
            other => KeyStoreError::Backend(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real round trip against a real backend -- not mocked. Uses
    // LinuxKeyutilsStore rather than KeyringStore: this crate's own dev
    // sandbox has a D-Bus session socket but no org.freedesktop.secrets
    // provider registered on it (no gnome-keyring/kwalletd running), so
    // KeyringStore::new genuinely fails here with NoDefaultStore -- a real
    // environment fact, confirmed directly, not a bug in either backend.
    // LinuxKeyutilsStore's kernel-keyutils backend has no such external
    // dependency, which is exactly why it exists (see this module's own
    // doc). Uses a service/account pair distinguishable from any real
    // application's own entries, and always deletes what it wrote, pass or
    // fail, so a test run never leaves a credential behind.
    //
    // KEYRING_TEST_MUTEX below is load-bearing, not defensive boilerplate:
    // confirmed directly that these tests fail under Rust's default
    // parallel test-thread scheduling (NotFound errors reading a secret
    // just written by the same test) but pass 100% reliably under
    // `--test-threads=1`. This sandbox's kernel resolves
    // KeyRingIdentifier::Session per-thread rather than per-process under
    // concurrent first access -- a real environment characteristic, not a
    // bug in this module's own save/load/delete logic (which is exactly
    // what running these serially, but still by default under `cargo
    // test`, proves).
    #[cfg(target_os = "linux")]
    static KEYRING_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "linux")]
    fn test_store() -> LinuxKeyutilsStore {
        LinuxKeyutilsStore::new("macula-rust-test", "keystore-round-trip-test-entry")
            .expect("Store::new/build should succeed -- keyutils is always available on Linux")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn save_then_load_returns_the_same_key() {
        let _guard = KEYRING_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let store = test_store();
        let key = vec![0x42u8; 2400];

        let result = (|| -> Result<(), KeyStoreError> {
            store.save_key(&key)?;
            let loaded = store.load_key()?;
            assert_eq!(*loaded, key);
            Ok(())
        })();

        store.delete_key().expect("cleanup delete should succeed");
        result.expect("save/load round trip should succeed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_before_any_save_reports_not_found() {
        let _guard = KEYRING_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let store = test_store();
        // Guard against a leftover entry from a prior failed run on this
        // machine before asserting NotFound.
        let _ = store.delete_key();

        assert!(matches!(store.load_key(), Err(KeyStoreError::NotFound)));
    }

    // On Windows the node key lives in Credential Manager only: a real round
    // trip of both profiles through KeyringStore, and a key file refused.
    #[cfg(windows)]
    #[test]
    fn a_node_key_round_trips_through_credential_manager_and_a_key_file_is_refused() {
        use crate::node_key::{KeyFileError, NodeKey, Purpose};
        use crate::profile::Profile;

        for profile in [Profile::PqPure, Profile::PqHybrid] {
            let account = format!("keystore-round-trip-{}", profile.name());
            let store =
                KeyringStore::new("macula-rust-test", &account).expect("Credential Manager");
            let key = NodeKey::generate_identity(profile, 0).expect("a key");
            let result = key
                .save_to_keystore(&store)
                .and_then(|()| NodeKey::load_from_keystore(&store, Purpose::Identity, profile));
            store.delete_key().expect("cleanup delete should succeed");
            let loaded = result.expect("save/load round trip through Credential Manager");
            assert_eq!(loaded.public_key(), key.public_key(), "{profile:?}");
        }
        let path = std::env::temp_dir().join("macula-rust-test-key");
        let refused = NodeKey::load_or_create(&path, Profile::PqPure);
        assert!(matches!(refused, Err(KeyFileError::NoKeyFile)));
        assert!(!path.exists(), "no key file written");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn delete_is_idempotent() {
        let _guard = KEYRING_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let store = test_store();
        store.save_key(&[0x7Fu8; 32]).expect("save");
        store.delete_key().expect("first delete");
        // A second delete of an already-absent entry must not error --
        // KeyStore::delete_key's own doc promises this.
        store
            .delete_key()
            .expect("second delete on an absent entry");
    }
}
