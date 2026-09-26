//! Key files in macula's seed form, readable by their owner only: saved and
//! loaded back as the same key, the layout byte for byte, and every refusal a
//! loader owes, among them the LAMPS draft's own private key loading as a
//! pq_hybrid node key.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use macula_rust::node_key::{verify, KeyFileError, NodeKey, Purpose};
use macula_rust::profile::Profile;

const MAGIC: &[u8] = b"macula-node-key-seed-v1\0";

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "tests/vectors/identity/lamps_mldsa87_rsa4096_pss_sha512/{name}"
    ))
    .unwrap()
}

/// A key file written by hand, as its layout says: the magic, the purpose,
/// profile and half count, then each half's tag and its public and private
/// keys, four-byte big-endian length-prefixed.
fn key_file(purpose: u8, profile: u8, halves: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend([purpose, profile, halves.len() as u8]);
    for (tag, public, private) in halves {
        out.push(*tag);
        out.extend((public.len() as u32).to_be_bytes());
        out.extend(*public);
        out.extend((private.len() as u32).to_be_bytes());
        out.extend(*private);
    }
    out
}

fn write_owner_only(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_saved_key_loads_back_as_the_same_key_readable_by_its_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let key = NodeKey::generate(Purpose::Identity, profile).unwrap();
        let path = dir.path().join(format!("{}.key", profile.name()));
        key.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{profile:?}");
        let loaded = NodeKey::load(&path, Purpose::Identity, profile).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        assert_eq!(loaded.node_id().unwrap(), key.node_id().unwrap());
        let signature = loaded.sign(b"loaded").unwrap();
        assert!(verify(b"loaded", &signature, &key.public_key(), profile));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            if profile == Profile::PqPure { 1 } else { 2 }
        );
    }
}

#[test]
fn the_draft_s_private_key_is_a_pq_hybrid_node_key() {
    let dir = tempfile::tempdir().unwrap();
    let (sk, pk) = (vector("sk.bin"), vector("pk.bin"));
    let path = dir.path().join("draft.key");
    write_owner_only(
        &path,
        &key_file(
            1,
            2,
            &[(1, &pk[..2592], &sk[..32]), (2, &pk[2592..], &sk[32..])],
        ),
    );
    let key = NodeKey::load(&path, Purpose::Identity, Profile::PqHybrid).unwrap();
    assert_eq!(key.public_key(), pk);
    let m = vector("m.bin");
    let signature = key.sign(&m).unwrap();
    assert_eq!(signature.len(), vector("s.bin").len());
    assert!(verify(&m, &signature, &pk, Profile::PqHybrid));

    // Saved again, the key file is the same bytes: the seed form round-trips.
    let again = dir.path().join("again.key");
    key.save(&again).unwrap();
    assert_eq!(
        std::fs::read(&again).unwrap(),
        std::fs::read(&path).unwrap()
    );
}

#[test]
fn a_key_file_its_group_or_others_can_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    NodeKey::generate(Purpose::Identity, Profile::PqPure)
        .unwrap()
        .save(&path)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        NodeKey::load(&path, Purpose::Identity, Profile::PqPure),
        Err(KeyFileError::Permissions)
    ));
}

#[test]
fn a_key_of_another_purpose_or_profile_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    NodeKey::generate(Purpose::Identity, Profile::PqPure)
        .unwrap()
        .save(&path)
        .unwrap();
    assert!(matches!(
        NodeKey::load(&path, Purpose::Connect, Profile::PqPure),
        Err(KeyFileError::WrongPurpose(Purpose::Identity))
    ));
    assert!(matches!(
        NodeKey::load(&path, Purpose::Identity, Profile::PqHybrid),
        Err(KeyFileError::WrongProfile(Profile::PqPure))
    ));
}

#[test]
fn a_key_file_that_is_not_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (sk, pk) = (vector("sk.bin"), vector("pk.bin"));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("no magic", b"not a key file".to_vec()),
        (
            "halves missing",
            key_file(1, 2, &[(1, &pk[..2592], &sk[..32])]),
        ),
        ("a trailing byte", {
            let mut b = key_file(1, 1, &[(1, &pk[..2592], &sk[..32])]);
            b.push(0);
            b
        }),
        (
            "an unknown tag",
            key_file(1, 1, &[(9, &pk[..2592], &sk[..32])]),
        ),
        (
            "an unknown profile",
            key_file(1, 7, &[(1, &pk[..2592], &sk[..32])]),
        ),
    ];
    for (name, bytes) in cases {
        let path = dir.path().join("bad.key");
        write_owner_only(&path, &bytes);
        let result = NodeKey::load(&path, Purpose::Identity, Profile::PqHybrid);
        assert!(
            matches!(
                result,
                Err(KeyFileError::BadKeyFile) | Err(KeyFileError::WrongAlgorithms)
            ),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn a_stored_public_key_that_is_not_the_private_key_s_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (sk, pk) = (vector("sk.bin"), vector("pk.bin"));
    let path = dir.path().join("mismatch.key");
    let wrong = {
        let mut p = pk[..2592].to_vec();
        p[100] ^= 1;
        p
    };
    write_owner_only(&path, &key_file(1, 1, &[(1, &wrong, &sk[..32])]));
    assert!(matches!(
        NodeKey::load(&path, Purpose::Identity, Profile::PqPure),
        Err(KeyFileError::PublicKeyMismatch)
    ));
}

#[test]
fn a_directory_or_an_oversized_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        NodeKey::load(dir.path(), Purpose::Identity, Profile::PqPure),
        Err(KeyFileError::NotRegular)
    ));
    let big = dir.path().join("big.key");
    write_owner_only(&big, &vec![0u8; 64 * 1024 + 1]);
    assert!(matches!(
        NodeKey::load(&big, Purpose::Identity, Profile::PqPure),
        Err(KeyFileError::TooLarge)
    ));
}

/// A key store of the caller's own, which the trait lets any backend be.
struct InMemory(std::sync::Mutex<Option<Vec<u8>>>);

impl macula_rust::keystore::KeyStore for InMemory {
    fn save_key(&self, key: &[u8]) -> Result<(), macula_rust::keystore::KeyStoreError> {
        *self.0.lock().unwrap() = Some(key.to_vec());
        Ok(())
    }
    fn load_key(
        &self,
    ) -> Result<macula_mldsa::Zeroizing<Vec<u8>>, macula_rust::keystore::KeyStoreError> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .map(macula_mldsa::Zeroizing::new)
            .ok_or(macula_rust::keystore::KeyStoreError::NotFound)
    }
    fn delete_key(&self) -> Result<(), macula_rust::keystore::KeyStoreError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn a_key_kept_in_a_key_store_loads_back_as_the_same_key_and_is_checked_as_a_file_is() {
    let store = InMemory(std::sync::Mutex::new(None));
    assert!(matches!(
        NodeKey::load_from_keystore(&store, Purpose::Identity, Profile::PqHybrid),
        Err(KeyFileError::KeyStore(
            macula_rust::keystore::KeyStoreError::NotFound
        ))
    ));
    let key = NodeKey::generate(Purpose::Identity, Profile::PqHybrid).unwrap();
    key.save_to_keystore(&store).unwrap();
    let loaded = NodeKey::load_from_keystore(&store, Purpose::Identity, Profile::PqHybrid).unwrap();
    assert_eq!(loaded.public_key(), key.public_key());
    assert!(matches!(
        NodeKey::load_from_keystore(&store, Purpose::Identity, Profile::PqPure),
        Err(KeyFileError::WrongProfile(Profile::PqHybrid))
    ));
}

#[test]
fn load_or_create_makes_a_puzzle_solved_key_once_then_loads_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/node.key");
    let made = NodeKey::load_or_create(&path, Profile::PqPure).unwrap();
    assert_eq!(made.purpose(), Purpose::Identity);
    assert!(macula_rust::node_key::puzzle_solved(
        &made.node_id().unwrap(),
        macula_rust::node_key::PUZZLE_DIFFICULTY
    ));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "owner-only");
    let again = NodeKey::load_or_create(&path, Profile::PqPure).unwrap();
    assert_eq!(again.node_id().unwrap(), made.node_id().unwrap());
}

#[test]
fn load_or_create_never_replaces_a_file_that_does_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    write_owner_only(&path, b"not a key file");
    assert!(matches!(
        NodeKey::load_or_create(&path, Profile::PqPure),
        Err(KeyFileError::BadKeyFile)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"not a key file");
    // A key of the other profile is refused, not replaced, too.
    let hybrid = dir.path().join("hybrid.key");
    NodeKey::load_or_create(&hybrid, Profile::PqHybrid).unwrap();
    let before = std::fs::read(&hybrid).unwrap();
    assert!(matches!(
        NodeKey::load_or_create(&hybrid, Profile::PqPure),
        Err(KeyFileError::WrongProfile(Profile::PqHybrid))
    ));
    assert_eq!(std::fs::read(&hybrid).unwrap(), before);
}
