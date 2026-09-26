//! pq_hybrid composites that crossed both ways with macula 12.x
//! (tests/vectors/identity/macula_12_cross, written by
//! scripts/cross-verify-macula.sh): one macula signed with a key of its own,
//! which verifies here, and one this crate signed, which macula verified.

use macula_rust::node_key::verify;
use macula_rust::profile::Profile;

const MLDSA_SIGNATURE: usize = 4627;

fn crossed(signer: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let read = |name: &str| {
        std::fs::read(format!(
            "tests/vectors/identity/macula_12_cross/{signer}/{name}"
        ))
        .unwrap()
    };
    (read("m.bin"), read("pk.bin"), read("s.bin"))
}

#[test]
fn a_composite_macula_signed_verifies() {
    let (m, pk, mut s) = crossed("macula_signed");
    assert!(verify(&m, &s, &pk, Profile::PqHybrid));
    s[MLDSA_SIGNATURE + 10] ^= 1;
    assert!(!verify(&m, &s, &pk, Profile::PqHybrid));
}

#[test]
fn the_composite_macula_verified_verifies_here() {
    let (m, pk, s) = crossed("rust_signed");
    assert!(verify(&m, &s, &pk, Profile::PqHybrid));
}
