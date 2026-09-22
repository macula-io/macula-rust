//! TLS trust for dialing a macula-station: pubkey-pin verification,
//! ported from `native/macula_quic/src/cert.rs` (`macula-io/macula`).
//!
//! A station presents a self-signed X.509 cert wrapping its macula
//! identity's Ed25519 public key. A client that already knows which
//! station it's dialing (from DHT records, pre-shared relay identities,
//! or — for a mobile client — configuration) verifies by comparing the
//! cert's SubjectPublicKeyInfo to that known pubkey directly. No CA
//! chain, no DNS-anchored trust: the pubkey **is** the identity.
//!
//! Unlike the Erlang SDK's own `native/macula_quic`, this crate never
//! needs to *generate* a cert — macula uses `with_no_client_auth()`
//! throughout, so a dialing client presents no TLS certificate of its
//! own at all. Identity/authentication happens entirely at the
//! application layer (the CONNECT/HELLO frame's Ed25519 signature — see
//! `plans/PLAN_WIRE_PROTOCOL.md` §2, §5), not via mutual TLS. This
//! module is verification-only.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;

/// Extract the 32-byte Ed25519 public key from a DER-encoded X.509
/// certificate's SubjectPublicKeyInfo. Errors if the SPKI algorithm
/// isn't Ed25519 (OID `1.3.101.112`) or the key isn't 32 bytes.
pub fn ed25519_pubkey_from_cert(der: &[u8]) -> Result<[u8; 32], String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("parse cert: {e}"))?;
    let spki = cert.public_key();
    let alg_oid = &spki.algorithm.algorithm;
    if alg_oid.to_id_string() != "1.3.101.112" {
        return Err(format!(
            "expected Ed25519 SPKI, got OID {}",
            alg_oid.to_id_string()
        ));
    }
    let pk = spki.subject_public_key.data.as_ref();
    pk.try_into()
        .map_err(|_| format!("Ed25519 pubkey must be 32 bytes, got {}", pk.len()))
}

/// Custom rustls `ServerCertVerifier` that pins on the leaf cert's
/// SubjectPublicKeyInfo Ed25519 pubkey rather than walking a CA chain —
/// the pragmatic equivalent of TLS raw-public-key (RFC 7250) without
/// changing the wire protocol. No expiry check, no SAN check, no CA
/// chain: matches the reference verifier exactly, including its
/// intentional narrowness.
#[derive(Debug)]
pub struct PubkeyPinVerifier {
    pinned: [u8; 32],
    crypto: Arc<rustls::crypto::CryptoProvider>,
}

impl PubkeyPinVerifier {
    /// Verifies handshake signatures with `macula-pqc`'s provider, the one
    /// every connection this crate dials runs on.
    pub fn new(pinned_pubkey: [u8; 32]) -> Self {
        Self {
            pinned: pinned_pubkey,
            crypto: macula_pqc::client_builder().crypto_provider().clone(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PubkeyPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let presented = ed25519_pubkey_from_cert(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("pubkey extract: {e}")))?;

        if presented == self.pinned {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "pubkey mismatch: pinned={} presented={}",
                hex(&self.pinned),
                hex(&presented)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Ed25519 leaves are TLS 1.3 only; if a 1.2 path somehow
        // triggers this, accept — the cert match above is what anchors
        // trust, matching the reference verifier's own reasoning.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Defer to the crypto provider: this verifies `dss` was really
        // produced by the leaf cert's own private key, i.e. that the
        // peer we pinned by pubkey is the one actually completing this
        // handshake, not just quoting someone else's cert.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Skips all server certificate verification. **Development/diagnostic
/// use only** — establishes transport connectivity with no identity
/// guarantee whatsoever. Never use this to dial a station you intend to
/// trust; use [`PubkeyPinVerifier`] once the station's identity is
/// known, matching the reference's own `verify => none` mode.
#[derive(Debug)]
pub struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    /// States the signature schemes of `macula-pqc`'s provider, the one every
    /// connection this crate dials runs on.
    pub fn new() -> Self {
        Self(macula_pqc::client_builder().crypto_provider().clone())
    }
}

impl Default for SkipServerVerification {
    fn default() -> Self {
        Self::new()
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn ed25519_pubkey_extraction_rejects_garbage_der() {
        assert!(ed25519_pubkey_from_cert(b"not a certificate").is_err());
    }

    #[test]
    fn pinned_verifier_stores_the_exact_bytes_given() {
        let pin = [0x42u8; 32];
        let verifier = PubkeyPinVerifier::new(pin);
        assert_eq!(verifier.pinned, pin);
    }

    /// A synthetic self-signed Ed25519 cert, shaped like what a station
    /// running pubkey-pinned trust actually presents — generated with
    /// `rcgen` purely for this test (not a runtime dependency, see the
    /// module doc). No live station reachable from this crate's test
    /// suite happens to be configured this way (the reachable demo
    /// fleet all uses `Trust::WebPki` — see `tests/live_station.rs`), so
    /// this is the only way to exercise `PubkeyPinVerifier`'s actual
    /// matching logic end-to-end without one.
    fn synthetic_ed25519_cert() -> (rustls::pki_types::CertificateDer<'static>, [u8; 32]) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let pubkey =
            ed25519_pubkey_from_cert(der.as_ref()).expect("our own synthetic cert must parse");
        (der, pubkey)
    }

    fn fake_server_name() -> rustls::pki_types::ServerName<'static> {
        rustls::pki_types::ServerName::try_from("station.example").expect("valid server name")
    }

    #[test]
    fn extracts_the_real_pubkey_from_a_synthetic_cert() {
        // Not asserting a specific value — proves the extraction path
        // works end-to-end against a real (if synthetic) cert, distinct
        // from `ed25519_pubkey_extraction_rejects_garbage_der`'s
        // negative case.
        let (_der, pubkey) = synthetic_ed25519_cert();
        assert_ne!(
            pubkey, [0u8; 32],
            "a real generated key should not be all-zero"
        );
    }

    #[test]
    fn verify_server_cert_accepts_the_pinned_key() {
        let (der, pubkey) = synthetic_ed25519_cert();
        let verifier = PubkeyPinVerifier::new(pubkey);
        let result = verifier.verify_server_cert(
            &der,
            &[],
            &fake_server_name(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(
            result.is_ok(),
            "pinning the cert's real key must succeed: {result:?}"
        );
    }

    #[test]
    fn verify_server_cert_rejects_a_mismatched_key() {
        let (der, pubkey) = synthetic_ed25519_cert();
        let mut wrong = pubkey;
        wrong[0] ^= 0xFF;
        let verifier = PubkeyPinVerifier::new(wrong);
        let result = verifier.verify_server_cert(
            &der,
            &[],
            &fake_server_name(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_err(), "pinning the WRONG key must fail closed");
    }

    #[test]
    fn skip_verification_accepts_anything() {
        let (der, _pubkey) = synthetic_ed25519_cert();
        let verifier = SkipServerVerification::new();
        let result = verifier.verify_server_cert(
            &der,
            &[],
            &fake_server_name(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(
            result.is_ok(),
            "insecure mode must accept any cert, by design"
        );
    }
}
