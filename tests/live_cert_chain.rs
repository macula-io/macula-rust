//! Live proof that a `cert_chain`-bearing `procedure_advertisement` survives
//! a REAL DHT publish/resolve round trip and still verifies correctly
//! afterward — the offline unit tests in `src/cert_chain.rs` never touch
//! the network, so they can't catch a wire-encoding bug (e.g. the
//! `cert_chain` bytes getting mangled in transit) the way this can.
//!
//! No fleet provisioning needed: the realm CA/leaf chain is entirely
//! self-issued by this test, since cert-chain authorization is a
//! client-side check on an opaque DHT payload the station itself never
//! inspects (mirrors `macula-go`'s `TestLiveResolveWithCertChain`,
//! which makes the same observation).
//!
//! Not run by default CI — `#[ignore]`d, matching this crate's other live
//! tests (`tests/live_station.rs`). Run explicitly with
//! `cargo test --test live_cert_chain -- --ignored`.

use std::time::Duration;

use macula_rust::cert_chain::{verify_advertisement_cert_chain, CertChainError};
use macula_rust::connection;
use macula_rust::direct_dial;
use macula_rust::identity::KeyPair;
use macula_rust::transport::Trust;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair as RcgenKeyPair};

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

fn self_issued_realm_ca() -> (Vec<u8>, rcgen::Issuer<'static, RcgenKeyPair>) {
    let key_pair = RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ca keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Live Test Realm CA");
    dn.push(DnType::OrganizationName, "Live Test Realm CA");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let cert = params.self_signed(&key_pair).expect("ca self-sign");
    let pem = cert.pem().into_bytes();
    (pem, rcgen::Issuer::new(params, key_pair))
}

/// RFC 8410 SubjectPublicKeyInfo DER for a raw 32-byte Ed25519 pubkey —
/// duplicated from `src/cert_chain.rs`'s own `#[cfg(test)]` helper since an
/// integration test in `tests/` can't reach items private to the lib's
/// test module.
fn ed25519_spki_der(pubkey: [u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&pubkey);
    der
}

fn issue_leaf(
    ca_issuer: &rcgen::Issuer<'static, RcgenKeyPair>,
    advertiser_pub: [u8; 32],
    org: &str,
) -> Vec<u8> {
    let subject_spki =
        rcgen::SubjectPublicKeyInfo::from_der(&ed25519_spki_der(advertiser_pub)).expect("spki");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "live-cert-chain-test-service");
    dn.push(DnType::OrganizationName, org);
    params.distinguished_name = dn;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let cert = params
        .signed_by(&subject_spki, ca_issuer)
        .expect("leaf signed_by");
    cert.der().to_vec()
}

fn pem_bundle(ders: &[Vec<u8>]) -> Vec<u8> {
    use base64::Engine;
    let mut out = Vec::new();
    for der in ders {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        out.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.extend_from_slice(chunk);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    out
}

/// Publishes a `cert_chain`-bearing advertisement for real, resolves it
/// back over a SEPARATE session/identity, and confirms the resolved
/// record's embedded chain still verifies -- proving the wire round trip
/// (CBOR-encode the PEM bytes into a DHT record, publish via `_dht.put_record`,
/// read it back via `_dht.find_records`) doesn't corrupt the chain. Also
/// checks the negative control: the SAME resolved record correctly fails
/// authorization for the WRONG org.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn cert_chain_survives_a_real_dht_round_trip() {
    let (ca_pem, ca_issuer) = self_issued_realm_ca();

    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();
    let leaf_der = issue_leaf(&ca_issuer, provider_identity.node_id(), "acme-corp");

    let provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let resolver_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("resolver handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust.live_cert_chain_test.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    direct_dial::advertise_direct_with_cert_chain(
        &provider_session,
        &provider_identity,
        realm,
        &procedure,
        Duration::from_secs(120),
        pem_bundle(&[leaf_der]),
    )
    .await
    .expect("advertise_direct_with_cert_chain should publish the DHT record");

    let resolved = direct_dial::resolve_with_cert_chain(
        &resolver_session,
        &caller_identity,
        realm,
        &procedure,
        &ca_pem,
        "acme-corp",
    )
    .await
    .expect("resolve_with_cert_chain should find and authorize what was just published");
    assert_eq!(
        resolved.station, provider_session.station.node_id,
        "resolved station should be the provider's own"
    );

    // Negative control on the SAME real, network-round-tripped record.
    let err = direct_dial::resolve_with_cert_chain(
        &resolver_session,
        &caller_identity,
        realm,
        &procedure,
        &ca_pem,
        "wrong-org",
    )
    .await
    .expect_err("a real cert chain issued for acme-corp must not authorize wrong-org");
    match err {
        direct_dial::ResolveError::NoAuthorizedAdvertisement(CertChainError::OrgMismatch) => {}
        other => panic!("expected NoAuthorizedAdvertisement(OrgMismatch), got {other:?}"),
    }

    // Also confirm the record's chain still verifies directly, byte for
    // byte, via the resolved path -- redundant with resolve_with_cert_chain
    // succeeding above, but pins down that verify_advertisement_cert_chain
    // itself (not just the resolve wrapper) is what's being exercised.
    let recs = macula_rust::dht::find_records(
        &resolver_session,
        &caller_identity,
        macula_rust::dht::procedure_key(&macula_rust::dht::discovery_uri(realm, &procedure)),
    )
    .await
    .expect("find_records should return the published record");
    assert!(
        recs.iter()
            .any(|r| verify_advertisement_cert_chain(&ca_pem, r, "acme-corp").is_ok()),
        "at least one resolved record must verify byte-for-byte after the real DHT round trip"
    );

    provider_session
        .close("normal", None, &provider_identity)
        .await;
    resolver_session
        .close("normal", None, &caller_identity)
        .await;
}
