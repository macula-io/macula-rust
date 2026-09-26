//! A macula 12 node key, as macula-go and macula hold one: ML-DSA-87 in
//! pq_pure, the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512 in pq_hybrid,
//! node_ids and key ids, the admission puzzle, and signatures held to the LAMPS
//! draft's own vector and to one macula's OTP stack made.

use macula_rust::node_key::{
    carried_key_well_formed, key_id_of, node_id_of, puzzle_solved, signature_size, verify,
    KeyError, NodeKey, Purpose, PUZZLE_DIFFICULTY,
};
use macula_rust::profile::Profile;
use sha2::{Digest, Sha256};

const MLDSA_PUBLIC: usize = 2592;
const MLDSA_SIGNATURE: usize = 4627;

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "tests/vectors/identity/lamps_mldsa87_rsa4096_pss_sha512/{name}"
    ))
    .unwrap()
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 1;
    out
}

#[test]
fn profiles_are_parsed_by_their_exact_names() {
    assert_eq!(Profile::parse("pq_pure"), Ok(Profile::PqPure));
    assert_eq!(Profile::parse("pq_hybrid"), Ok(Profile::PqHybrid));
    assert!(Profile::parse("").is_err());
    assert!(Profile::parse("PQ_HYBRID").is_err());
    assert!(Profile::parse("classical").is_err());
    assert_eq!(Profile::PqPure.sig_alg(), "ML-DSA-87");
    assert_eq!(Profile::PqHybrid.sig_alg(), "ML-DSA-87-PS384");
    assert_eq!(signature_size(Profile::PqPure), MLDSA_SIGNATURE);
    assert_eq!(signature_size(Profile::PqHybrid), MLDSA_SIGNATURE + 512);
}

#[test]
fn a_pq_pure_key_is_ml_dsa_87_alone() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    assert_eq!(key.public_key().len(), MLDSA_PUBLIC);
    assert!(carried_key_well_formed(&key.public_key(), Profile::PqPure));
    let signature = key.sign(b"a fact").unwrap();
    assert_eq!(signature.len(), MLDSA_SIGNATURE);
    assert!(verify(
        b"a fact",
        &signature,
        &key.public_key(),
        Profile::PqPure
    ));
    assert!(!verify(
        b"a fact!",
        &signature,
        &key.public_key(),
        Profile::PqPure
    ));
    assert!(!verify(
        b"a fact",
        &flipped(&signature, 10),
        &key.public_key(),
        Profile::PqPure
    ));
    assert!(!verify(
        b"a fact",
        &signature,
        &key.public_key(),
        Profile::PqHybrid
    ));
}

#[test]
fn a_pq_hybrid_key_signs_the_composite_and_both_halves_must_verify() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqHybrid).unwrap();
    let public = key.public_key();
    assert!(public.len() > MLDSA_PUBLIC);
    assert!(carried_key_well_formed(&public, Profile::PqHybrid));
    assert!(!carried_key_well_formed(&public, Profile::PqPure));
    let signature = key.sign(b"a fact").unwrap();
    assert_eq!(signature.len(), MLDSA_SIGNATURE + 512);
    assert!(verify(b"a fact", &signature, &public, Profile::PqHybrid));
    assert!(!verify(
        b"a fact",
        &flipped(&signature, 10),
        &public,
        Profile::PqHybrid
    ));
    assert!(!verify(
        b"a fact",
        &flipped(&signature, MLDSA_SIGNATURE + 10),
        &public,
        Profile::PqHybrid
    ));
    assert!(!verify(b"a fact", &signature, &public, Profile::PqPure));
    assert!(!verify(
        b"a fact",
        &signature[..MLDSA_SIGNATURE],
        &public,
        Profile::PqHybrid
    ));
}

#[test]
fn the_lamps_draft_vector_verifies_and_every_alteration_is_refused() {
    let (m, pk, s) = (vector("m.bin"), vector("pk.bin"), vector("s.bin"));
    assert!(verify(&m, &s, &pk, Profile::PqHybrid));
    let mut longer = m.clone();
    longer.push(0);
    assert!(!verify(&longer, &s, &pk, Profile::PqHybrid));
    assert!(!verify(&m, &flipped(&s, 10), &pk, Profile::PqHybrid));
    assert!(!verify(
        &m,
        &flipped(&s, MLDSA_SIGNATURE + 10),
        &pk,
        Profile::PqHybrid
    ));
    assert!(!verify(&m, &s, &pk, Profile::PqPure));
}

#[test]
fn a_composite_whose_rsa_half_lost_its_zero_byte_is_refused_by_its_length() {
    let zero_dropped = vector("zero_dropped_sig.bin");
    assert_eq!(zero_dropped.len(), MLDSA_SIGNATURE + 511);
    assert!(!verify(
        &vector("m.bin"),
        &zero_dropped,
        &vector("pk.bin"),
        Profile::PqHybrid
    ));
}

#[test]
fn a_composite_macula_s_otp_stack_made_verifies() {
    let (m, pk, s) = (
        vector("otp_message.bin"),
        vector("otp_pk.bin"),
        vector("otp_sig.bin"),
    );
    assert!(verify(&m, &s, &pk, Profile::PqHybrid));
    assert!(!verify(
        &m,
        &flipped(&s, MLDSA_SIGNATURE + 10),
        &pk,
        Profile::PqHybrid
    ));
}

#[test]
fn a_carried_hybrid_key_must_be_its_one_canonical_form() {
    let pk = vector("pk.bin");
    assert!(carried_key_well_formed(&pk, Profile::PqHybrid));
    assert!(!carried_key_well_formed(
        &pk[..MLDSA_PUBLIC],
        Profile::PqHybrid
    ));
    assert!(!carried_key_well_formed(
        &pk[..pk.len() - 1],
        Profile::PqHybrid
    ));
    let mut trailing = pk.clone();
    trailing.push(0);
    assert!(!carried_key_well_formed(&trailing, Profile::PqHybrid));
    assert!(!carried_key_well_formed(&pk, Profile::PqPure));
    assert!(carried_key_well_formed(
        &pk[..MLDSA_PUBLIC],
        Profile::PqPure
    ));
}

/// node_id and key id: SHA-256 over their label, a zero byte, the profile's
/// name with its length, and the key as carried (D5).
#[test]
fn node_ids_and_key_ids_are_labelled_hashes_of_the_carried_key() {
    let pk = vector("pk.bin");
    for (profile, name) in [
        (Profile::PqPure, "pq_pure"),
        (Profile::PqHybrid, "pq_hybrid"),
    ] {
        for (label, id) in [
            ("MACULA-NODE-ID-V1", node_id_of(&pk, profile)),
            ("MACULA-KEY-ID-V1", key_id_of(&pk, profile)),
        ] {
            let mut h = Sha256::new();
            h.update(label.as_bytes());
            h.update([0, name.len() as u8]);
            h.update(name.as_bytes());
            h.update(&pk);
            assert_eq!(id.to_vec(), h.finalize().to_vec(), "{label} {name}");
        }
    }
}

#[test]
fn the_admission_puzzle_counts_leading_zero_bits() {
    let mut id = [0xffu8; 32];
    assert!(puzzle_solved(&id, 0));
    assert!(!puzzle_solved(&id, 1));
    id[0] = 0;
    assert!(puzzle_solved(&id, 8));
    assert!(!puzzle_solved(&id, 9));
    id[1] = 0x1f;
    assert!(puzzle_solved(&id, 11));
    assert!(!puzzle_solved(&id, 12));
    assert!(puzzle_solved(&[0u8; 32], 256));
    assert!(!puzzle_solved(&[0u8; 32], 257));
    assert_eq!(PUZZLE_DIFFICULTY, 8);
}

#[test]
fn an_identity_key_is_generated_for_the_puzzle_and_only_it_has_a_node_id() {
    let identity = NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).unwrap();
    let node_id = identity.node_id().unwrap();
    assert!(puzzle_solved(&node_id, PUZZLE_DIFFICULTY));
    assert_eq!(node_id, node_id_of(&identity.public_key(), Profile::PqPure));
    assert_eq!(identity.key_id(), node_id);

    let connect = NodeKey::generate(Purpose::Connect, Profile::PqPure).unwrap();
    assert!(matches!(connect.node_id(), Err(KeyError::NotAnIdentityKey)));
    assert_eq!(
        connect.key_id(),
        key_id_of(&connect.public_key(), Profile::PqPure)
    );
    assert!(NodeKey::generate_identity(Profile::PqPure, 257).is_err());
}

#[test]
fn a_key_shows_its_purpose_profile_and_key_id_and_never_a_private_half() {
    let key = NodeKey::generate(Purpose::Connect, Profile::PqPure).unwrap();
    let shown = format!("{key:?}");
    assert_eq!(
        shown,
        format!("connect pq_pure key {}", hex::encode(key.key_id()))
    );
    assert_eq!(format!("{key}"), shown);
}

/// The draft's bytes as macula v12.7.0 carries them, pinned by sha256 so a
/// drifted copy fails here rather than passing on bytes nobody else signed:
/// the same sums macula-go, macula-php and macula-ts pin.
#[test]
fn the_lamps_vector_is_the_bytes_macula_pins() {
    let pinned = [
        (
            "m.bin",
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        ),
        (
            "pk.bin",
            "88560e139b35d0738857f9c8e29bbcfb108e3539bd2bf6f4994bb4b34beb019d",
        ),
        (
            "sk.bin",
            "0d4c65edb8735b5b677ea88050662406c7affd8e29ae27184726822a5ca889ce",
        ),
        (
            "s.bin",
            "95e17c93e9c1d6b5c3c4bae9d8687cd1606e232dca0af38e437e7e2e16894303",
        ),
        (
            "s_with_context.bin",
            "7261d9aeaaee3eb2612bb868d00d8eb6e174717bc427e8e6fa24cb7a73dcdeec",
        ),
        (
            "zero_dropped_sig.bin",
            "4e43a85def2b0acec014724d7d4b23ac86685ef35f28a9be85d9aff4a7cd30cd",
        ),
    ];
    for (name, sum) in pinned {
        assert_eq!(hex::encode(Sha256::digest(vector(name))), sum, "{name}");
    }
}

/// Every Macula object signs with the empty context, so the draft's
/// signature made with one is refused.
#[test]
fn the_draft_s_signature_made_with_a_context_is_refused() {
    assert!(!verify(
        &vector("m.bin"),
        &vector("s_with_context.bin"),
        &vector("pk.bin"),
        Profile::PqHybrid
    ));
}
