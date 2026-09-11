//! Direct-dial dual-trust (Slice 7c Direction B) — X.509 cert chain.
//!
//! Managed realms root trust in the realm CA, not in the (keyless) realm
//! tag. A provider embeds its own service-cert chain (leaf ++ org CA, PEM)
//! in its `procedure_advertisement`; a verifying consumer chains it to the
//! realm CA it received at its own issuance. No publisher records, no live
//! authority — the trust material already travels with the advertisement.
//!
//! Ported from `macula_record.erl`'s `verify_advertisement_cert_chain/3`
//! (and its `cert_chain_step_*`/`pem_cert_ders`/`cert_subject_pubkey`/
//! `validate_path`/`cert_org` helpers, in `src/record/macula_record.erl`)
//! — same algorithm, using `rustls-webpki`'s native path validation instead
//! of hand-rolling `pkix_path_validation`, and `x509-parser` (already used
//! by [`crate::cert`] for the unrelated TLS pubkey-pinning tier) for field
//! extraction. Cross-checked against `macula-go`'s own port
//! (`dht/cert_chain.go`), which uses `crypto/x509`'s native path validation
//! the same way. Opt-in: this has no effect on plain (non-cert-chain)
//! direct-dial, which remains exactly as it was.
//!
//! **Not the same trust tier as [`crate::cert`].** That module verifies a
//! TLS pubkey pin for dialing a KNOWN station — no CA chain, no org
//! semantics, the pubkey IS the identity. This module verifies a resolved
//! advertisement's embedded X.509 chain proves its signer belongs to a
//! specific org, authorized by a realm CA the caller already trusts — a
//! higher, separate, opt-in tier that only matters once direct-dial itself
//! exists.

use rustls::pki_types::{CertificateDer, UnixTime};

use crate::dht::{self, Record};

/// Mirrors `macula_record.erl`'s six `cert_chain_step_*` failure atoms
/// (`advertisement_bad_signature`, `no_cert_chain`, `cert_chain_undecodable`,
/// `cert_key_mismatch`, `cert_chain_untrusted`/`{bad_cert, _}`,
/// `cert_org_mismatch`) as distinguishable variants (test with
/// `matches!`/`==`) — never silently treat an unauthorized advertisement as
/// trusted.
#[derive(Debug, PartialEq, Eq)]
pub enum CertChainError {
    /// The advertisement's own Ed25519 envelope signature does not verify —
    /// checked BEFORE the cert chain is even examined, since nothing in an
    /// unverified record can be trusted. Also covers the (practically
    /// unreachable once the envelope verifies) case of a structurally
    /// malformed `procedure_advertisement` payload — `macula_record.erl`
    /// itself has no distinct atom for that case either, since it can't
    /// occur without the signer having signed garbage in the first place.
    BadSignature,
    /// `cert_chain` is absent — the common, unmanaged-realm case. Not
    /// itself a sign of tampering; callers that require managed-realm
    /// authorization should treat this as "not authorized," not as
    /// evidence of an attack.
    Absent,
    /// `cert_chain` is present but not a decodable PEM bundle containing at
    /// least one certificate.
    Undecodable,
    /// The leaf certificate's Ed25519 subject public key does not match the
    /// advertisement's own signing key — the chain does not actually belong
    /// to whoever signed this record.
    KeyMismatch,
    /// The chain does not validate to the given realm CA (expired, wrong
    /// issuer, broken path, etc.).
    Untrusted,
    /// The chain validates, but the leaf certificate's Organization (O)
    /// does not match the procedure's expected org segment — a
    /// validly-signed cert for the WRONG org, i.e. a squat.
    OrgMismatch,
}

impl std::fmt::Display for CertChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            CertChainError::BadSignature => "advertisement signature does not verify",
            CertChainError::Absent => "advertisement carries no cert_chain",
            CertChainError::Undecodable => "cert_chain is not a decodable PEM certificate bundle",
            CertChainError::KeyMismatch => {
                "leaf cert public key does not match the advertisement's signer"
            }
            CertChainError::Untrusted => "cert chain does not validate to the trusted realm CA",
            CertChainError::OrgMismatch => "leaf cert organization does not match the expected org",
        };
        write!(f, "cert_chain: {msg}")
    }
}

impl std::error::Error for CertChainError {}

/// Verifies a resolved `procedure_advertisement` record's embedded X.509
/// service-cert chain against a trusted realm CA, for Slice 7c Direction B
/// managed-realm authorization.
///
/// `realm_ca_pem` is the realm CA the caller already trusts (obtained at
/// its own issuance, out of band — never resolved from the mesh itself).
/// `rec` is a resolved `procedure_advertisement`. `expected_org` is the
/// `<org>` segment of the procedure URI the caller intended to reach.
///
/// Passes (returns `Ok(())`) only when: `rec`'s own envelope signature
/// verifies; `rec` carries a `cert_chain`; the chain decodes to at least
/// one certificate; the leaf certificate's Ed25519 subject public key
/// equals `rec`'s signing key (`rec.key`); the leaf chains to
/// `realm_ca_pem`; and the leaf's Organization RDN equals `expected_org`.
pub fn verify_advertisement_cert_chain(
    realm_ca_pem: &[u8],
    rec: &Record,
    expected_org: &str,
) -> Result<(), CertChainError> {
    dht::verify(rec).map_err(|_| CertChainError::BadSignature)?;
    let adv = dht::read_procedure_advertisement(rec).map_err(|_| CertChainError::BadSignature)?;
    let Some(chain_pem) = adv.cert_chain else {
        return Err(CertChainError::Absent);
    };

    let chain_der = decode_cert_chain(&chain_pem)?;
    let leaf_der = &chain_der[0];

    let leaf_key =
        crate::cert::ed25519_pubkey_from_cert(leaf_der).map_err(|_| CertChainError::KeyMismatch)?;
    if leaf_key != rec.key {
        return Err(CertChainError::KeyMismatch);
    }

    validate_cert_path(realm_ca_pem, &chain_der)?;

    let leaf_org = leaf_organization(leaf_der).ok_or(CertChainError::OrgMismatch)?;
    if leaf_org != expected_org {
        return Err(CertChainError::OrgMismatch);
    }
    Ok(())
}

/// Decodes a leaf-first PEM bundle (as embedded: leaf ++ org CA ++ ...)
/// into DER certificates, leaf-first, matching `macula_record`'s
/// `pem_cert_ders/1`.
fn decode_cert_chain(cert_chain_pem: &[u8]) -> Result<Vec<Vec<u8>>, CertChainError> {
    let ders: Vec<Vec<u8>> = x509_parser::pem::Pem::iter_from_buffer(cert_chain_pem)
        .filter_map(Result::ok)
        .filter(|pem| pem.label == "CERTIFICATE")
        .map(|pem| pem.contents)
        .collect();
    if ders.is_empty() {
        return Err(CertChainError::Undecodable);
    }
    Ok(ders)
}

/// The Organization (O) RDN of a leaf cert's Subject, or `None` if absent
/// or unreadable as a string.
fn leaf_organization(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let org = cert
        .subject()
        .iter_organization()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_owned);
    org
}

/// Validates `chain` (leaf-first: `[leaf, org_ca, ...]`) to `realm_ca_pem`
/// as trust anchor, with no hostname/SAN check (unlike `crate::cert`'s
/// `ServerCertVerifier` machinery) — matches `macula_record`'s
/// `validate_path/2`, which hands Erlang's `pkix_path_validation` the same
/// leaf..anchor chain and no name constraint of its own either.
fn validate_cert_path(realm_ca_pem: &[u8], chain: &[Vec<u8>]) -> Result<(), CertChainError> {
    let anchor_ders = decode_cert_chain(realm_ca_pem).map_err(|_| CertChainError::Untrusted)?;
    let anchor_der = CertificateDer::from(anchor_ders[0].clone());
    let anchor =
        webpki::anchor_from_trusted_cert(&anchor_der).map_err(|_| CertChainError::Untrusted)?;

    let leaf_der = CertificateDer::from(chain[0].clone());
    let end_entity =
        webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| CertChainError::Untrusted)?;
    let intermediates: Vec<CertificateDer> = chain[1..]
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    // KeyUsage::server_auth() is `required_if_present` — it does not
    // require the leaf to carry an EKU extension at all (macula's
    // self-issued service certs typically don't), it only rejects a leaf
    // that declares an EKU set excluding server_auth.
    end_entity
        .verify_for_usage(
            &[webpki::ring::ED25519],
            std::slice::from_ref(&anchor),
            &intermediates,
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| CertChainError::Untrusted)?;
    Ok(())
}

/// Test certificates for cert-chain authorization: a realm CA, a leaf it
/// issues for an advertiser key and org, and a leaf-first PEM bundle.
/// Shared by this module's tests and `direct_dial`'s.
#[cfg(test)]
pub(crate) mod fixtures {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair as RcgenKeyPair};

    pub(crate) fn test_ca() -> (Vec<u8>, rcgen::Issuer<'static, RcgenKeyPair>) {
        let key_pair = RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ca keygen");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test Realm CA");
        dn.push(DnType::OrganizationName, "Test Realm CA");
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(24);
        let cert = params.self_signed(&key_pair).expect("ca self-sign");
        let pem = cert.pem().into_bytes();
        (pem, rcgen::Issuer::new(params, key_pair))
    }

    pub(crate) fn test_leaf(
        ca_issuer: &rcgen::Issuer<'static, RcgenKeyPair>,
        advertiser_pub: [u8; 32],
        org: &str,
        not_after: time::OffsetDateTime,
    ) -> Vec<u8> {
        let subject_spki = rcgen::SubjectPublicKeyInfo::from_der(&ed25519_spki_der(advertiser_pub))
            .expect("advertiser SPKI");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-service");
        dn.push(DnType::OrganizationName, org);
        params.distinguished_name = dn;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = not_after;
        let cert = params
            .signed_by(&subject_spki, ca_issuer)
            .expect("leaf signed_by");
        cert.der().to_vec()
    }

    /// DER-encodes a raw 32-byte Ed25519 public key as a SubjectPublicKeyInfo
    /// structure (RFC 8410): `SEQUENCE { SEQUENCE { OID 1.3.101.112 },
    /// BIT STRING key }`. rcgen needs this to build a leaf cert whose
    /// subject key is a SPECIFIC pre-existing key (the advertiser's own
    /// node identity), not a freshly rcgen-generated one.
    fn ed25519_spki_der(pubkey: [u8; 32]) -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // SEQUENCE, 5 bytes (AlgorithmIdentifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
        ];
        der.extend_from_slice(&pubkey);
        der
    }

    pub(crate) fn pem_bundle(ders: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for der in ders {
            let b64 = base64_std_encode(der);
            out.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                out.extend_from_slice(chunk);
                out.push(b'\n');
            }
            out.extend_from_slice(b"-----END CERTIFICATE-----\n");
        }
        out
    }

    fn base64_std_encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::fixtures::{pem_bundle, test_ca, test_leaf};
    use super::*;
    use crate::dht;
    use crate::identity::KeyPair;

    fn advertiser_and_station() -> (KeyPair, KeyPair) {
        (KeyPair::generate(), KeyPair::generate())
    }

    #[test]
    fn valid_chain_verifies_and_authorizes() {
        let (ca_pem, ca_issuer) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let leaf_der = test_leaf(
            &ca_issuer,
            advertiser.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );

        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Ok(())
        );
    }

    #[test]
    fn absent_chain_is_reported_distinctly() {
        let (advertiser, station) = advertiser_and_station();
        let rec = dht::new_procedure_advertisement(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
        );
        let rec = dht::sign(rec, &advertiser);
        let (ca_pem, _) = test_ca();

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Err(CertChainError::Absent)
        );
    }

    #[test]
    fn bad_envelope_signature_is_checked_before_the_chain() {
        let (ca_pem, ca_issuer) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let leaf_der = test_leaf(
            &ca_issuer,
            advertiser.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let mut rec = dht::sign(rec, &advertiser);
        rec.signature[0] ^= 0xFF;

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Err(CertChainError::BadSignature)
        );
    }

    #[test]
    fn leaf_key_not_matching_the_signer_is_rejected() {
        let (ca_pem, ca_issuer) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let other = KeyPair::generate();
        // Leaf binds `other`'s key, but the advertisement is signed by
        // `advertiser` -- the chain does not belong to this record's signer.
        let leaf_der = test_leaf(
            &ca_issuer,
            other.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Err(CertChainError::KeyMismatch)
        );
    }

    #[test]
    fn wrong_org_is_rejected_after_a_valid_chain() {
        let (ca_pem, ca_issuer) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let leaf_der = test_leaf(
            &ca_issuer,
            advertiser.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/other-org/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "other-org"),
            Err(CertChainError::OrgMismatch)
        );
    }

    #[test]
    fn expired_leaf_is_untrusted() {
        let (ca_pem, ca_issuer) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let leaf_der = test_leaf(
            &ca_issuer,
            advertiser.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Err(CertChainError::Untrusted)
        );
    }

    #[test]
    fn chain_signed_by_a_different_ca_is_untrusted() {
        let (_, ca_issuer) = test_ca();
        let (other_ca_pem, _) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let leaf_der = test_leaf(
            &ca_issuer,
            advertiser.node_id(),
            "acme-corp",
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            pem_bundle(&[leaf_der]),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&other_ca_pem, &rec, "acme-corp"),
            Err(CertChainError::Untrusted)
        );
    }

    #[test]
    fn undecodable_chain_is_reported_distinctly() {
        let (ca_pem, _) = test_ca();
        let (advertiser, station) = advertiser_and_station();
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            advertiser.node_id(),
            "0000/acme-corp/widget.build_v1",
            station.node_id(),
            Duration::from_secs(3600),
            b"not a pem cert bundle".to_vec(),
        );
        let rec = dht::sign(rec, &advertiser);

        assert_eq!(
            verify_advertisement_cert_chain(&ca_pem, &rec, "acme-corp"),
            Err(CertChainError::Undecodable)
        );
    }
}
