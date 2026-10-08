//! Identity layout v1 (macula#76): stored identity keys by name and profile,
//! against macula's shared vectors (tests/vectors/identity/
//! identity_layout_v1.json): each name's file, each refused name, and each
//! move of the old single key file. Two first starts at once end with one
//! key.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use macula_rust::node_key::{identity_path, KeyFileError, NodeKey, Purpose, DEFAULT_IDENTITY_NAME};
use macula_rust::profile::Profile;
use serde_json::Value;

/// The profile every stored-identity lookup here runs in, the node's.
const NODE_PROFILE: Profile = Profile::PqPure;

fn vectors() -> Value {
    let text = std::fs::read_to_string("tests/vectors/identity/identity_layout_v1.json").unwrap();
    serde_json::from_str(&text).unwrap()
}

fn text<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field].as_str().unwrap()
}

#[test]
fn each_name_and_profile_is_its_own_file() {
    let v = vectors();
    let base = Path::new("/base");
    let dir = base.join(text(&v, "identity_dir"));
    for case in v["paths"].as_array().unwrap() {
        let profile = Profile::parse(text(case, "profile")).unwrap();
        let path = identity_path(&dir, text(case, "name"), profile).unwrap();
        assert_eq!(path, base.join(text(case, "file")), "{case}");
    }
    assert_eq!(DEFAULT_IDENTITY_NAME, text(&v, "default_name"));
}

#[test]
fn a_refused_name_touches_no_file() {
    let v = vectors();
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join(text(&v, "identity_dir"));
    for name in v["refused_names"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        for profile in [Profile::PqPure, Profile::PqHybrid] {
            let refused = identity_path(&dir, name, profile);
            assert!(
                matches!(refused, Err(KeyFileError::IdentityName(_))),
                "{name:?}: {refused:?}"
            );
            let stored = NodeKey::stored_identity(&dir, name, profile);
            assert!(
                matches!(stored, Err(KeyFileError::IdentityName(_))),
                "{name:?}"
            );
        }
    }
    assert_eq!(
        std::fs::read_dir(base.path()).unwrap().count(),
        0,
        "nothing created"
    );
}

/// The bytes of a key file in `profile`, saved at `path`.
fn saved(path: &Path, profile: Profile) -> Vec<u8> {
    NodeKey::generate(Purpose::Identity, profile)
        .unwrap()
        .save(path)
        .unwrap();
    std::fs::read(path).unwrap()
}

/// Sets up an old key as `old_key` names it, and what is in place as
/// `in_place` names it; answers the old key's bytes and where it moves to.
fn set_up(case: &Value, base: &Path, dir: &Path, old: &Path) -> (Vec<u8>, std::path::PathBuf) {
    let profile = match text(case, "old_key") {
        "other_profile" => Profile::PqHybrid,
        _ => NODE_PROFILE,
    };
    let bytes = match text(case, "old_key") {
        "not_a_key" => {
            std::fs::write(old, b"not a key").unwrap();
            std::fs::set_permissions(old, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            b"not a key".to_vec()
        }
        _ => saved(old, profile),
    };
    let to = identity_path(dir, DEFAULT_IDENTITY_NAME, profile).unwrap();
    match text(case, "in_place") {
        "same_file" => {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::hard_link(old, &to).unwrap();
        }
        "another_key" => {
            saved(&to, profile);
        }
        _ => {}
    }
    assert!(base.join(old.file_name().unwrap()).exists());
    (bytes, to)
}

#[test]
fn the_old_key_moves_only_where_nothing_else_is() {
    let v = vectors();
    for case in v["old_key_cases"].as_array().unwrap() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join(text(&v, "identity_dir"));
        let old = base.path().join(text(&v, "old_key_file"));
        let (bytes, to) = set_up(case, base.path(), &dir, &old);
        let in_place = std::fs::read(&to).ok();
        let stored = NodeKey::stored_identity(&dir, DEFAULT_IDENTITY_NAME, NODE_PROFILE);
        outcome(case, stored, &old, &to, &bytes, in_place);
    }
}

/// Asserts the outcome `case` names: what `stored` answered, and the old key
/// and what is in place afterwards.
fn outcome(
    case: &Value,
    stored: Result<(NodeKey, PathBuf), KeyFileError>,
    old: &Path,
    to: &Path,
    bytes: &[u8],
    in_place: Option<Vec<u8>>,
) {
    let name = text(case, "name");
    match text(case, "outcome") {
        "moved" => {
            assert!(stored.is_ok(), "{name}: {stored:?}");
            assert!(!old.exists(), "{name}: the old name is gone");
            assert_eq!(std::fs::read(to).unwrap(), bytes, "{name}");
        }
        "place_taken" => {
            assert!(
                matches!(&stored, Err(KeyFileError::OldKeyPlaceTaken { from, to: t }) if *from == *old && *t == *to),
                "{name}: {stored:?}"
            );
            assert_eq!(
                std::fs::read(old).unwrap(),
                bytes,
                "{name}: the old key stays"
            );
            assert_eq!(
                std::fs::read(to).ok(),
                in_place,
                "{name}: the key in place stays"
            );
        }
        "bad_key_file" => {
            assert!(
                matches!(&stored, Err(KeyFileError::OldKey { from, reason }) if *from == *old && matches!(**reason, KeyFileError::BadKeyFile)),
                "{name}: {stored:?}"
            );
            assert_eq!(
                std::fs::read(old).unwrap(),
                bytes,
                "{name}: the old key stays"
            );
        }
        other => panic!("{name}: unknown outcome {other}"),
    }
}

#[test]
fn a_first_start_stores_once_and_a_second_loads_it() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("identity");
    let (first, path) = NodeKey::stored_identity(&dir, "agent-venus", NODE_PROFILE).unwrap();
    assert_eq!(path, dir.join("agent-venus.pq_pure.key"));
    let (again, _) = NodeKey::stored_identity(&dir, "agent-venus", NODE_PROFILE).unwrap();
    assert_eq!(first.node_id().unwrap(), again.node_id().unwrap());
    let (other, _) = NodeKey::stored_identity(&dir, "agent-venus", Profile::PqHybrid).unwrap();
    assert_ne!(
        first.node_id().unwrap(),
        other.node_id().unwrap(),
        "one node per profile"
    );
}

#[test]
fn eight_first_starts_at_once_end_with_one_key() {
    let base = Arc::new(tempfile::tempdir().unwrap());
    let starts: Vec<_> = (0..8)
        .map(|_| {
            let base = base.clone();
            std::thread::spawn(move || {
                let dir = base.path().join("identity");
                let (key, _) = NodeKey::stored_identity(&dir, "default", NODE_PROFILE).unwrap();
                key.node_id().unwrap()
            })
        })
        .collect();
    let mut ids: Vec<_> = starts.into_iter().map(|s| s.join().unwrap()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 1, "one node_id: {ids:?}");
}

#[test]
fn a_stored_key_that_does_not_load_is_never_replaced() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("identity");
    let path = identity_path(&dir, "default", NODE_PROFILE).unwrap();
    let hybrid = saved(&path, Profile::PqHybrid);
    let stored = NodeKey::stored_identity(&dir, "default", NODE_PROFILE);
    assert!(
        matches!(&stored, Err(KeyFileError::StoredKey { path: p, reason }) if *p == path && matches!(**reason, KeyFileError::WrongProfile(Profile::PqHybrid))),
        "{stored:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), hybrid);
}
