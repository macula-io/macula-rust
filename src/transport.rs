//! Dialing a macula 12 station over QUIC, as macula-go's `transport` does.
//!
//! Raw QUIC (RFC 9000) with the ALPN `"macula"`, TLS 1.3 only, and the key
//! exchange macula-pqc fixes: SecP384r1MLKEM1024, then SecP256r1MLKEM768, and
//! nothing classical. A station's certificate is self-signed, so it is not
//! checked against a CA: macula-pqc's [`KeyPossessionVerifier`] accepts
//! exactly one certificate whose key is ML-DSA-87, then the station's
//! handshake signature under that key. That proves the station holds the key,
//! not who it is: the handshake then checks the station's TLS binding, which
//! ties this leaf to the identity key whose node_id the target pins (see
//! `crate::handshake`). A target without an expected node_id is refused before
//! anything is dialed.
//!
//! quinn protects QUIC Initial packets with the suite it finds in the rustls
//! provider, and RFC 9001 fixes that suite at AES-128-GCM, which macula-pqc's
//! provider does not offer for the handshake itself; the configuration is
//! therefore built with `with_initial` and macula-pqc's `quic_initial_suite`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use macula_pqc::KeyPossessionVerifier;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, IdleTimeout, TransportConfig};

use crate::profile::Profile;

/// The ALPN macula stations listen for.
pub const ALPN: &[u8] = b"macula";

/// macula's QUIC idle timeout and keep-alive: long enough to tolerate a real
/// gap between frames, with pings often enough that a healthy connection is
/// never mistaken for a dead one.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// A station to dial: where it listens, the profile the node runs, and the
/// node_id the station must prove in the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub profile: Profile,
    pub expected_node_id: [u8; 32],
}

/// A dialed station: the QUIC connection, the endpoint it runs on, the leaf
/// certificate the station presented (DER), and the target it was dialed as.
/// The endpoint must live as long as the connection.
pub struct Dialed {
    pub connection: quinn::Connection,
    pub endpoint: Endpoint,
    pub leaf: Vec<u8>,
    pub target: Target,
}

/// Why a dial failed.
#[derive(Debug)]
pub enum DialError {
    /// The target names no expected node_id.
    NoExpectedNodeId,
    /// The host resolved to no address, or not at all.
    Resolve(std::io::Error),
    /// The local endpoint could not be made.
    Endpoint(std::io::Error),
    /// The TLS or QUIC configuration could not be built.
    Config(String),
    /// The connection could not be started.
    Connect(quinn::ConnectError),
    /// The QUIC or TLS handshake failed, the station's certificate among the
    /// reasons: not exactly one, or not an ML-DSA-87 key.
    Connection(quinn::ConnectionError),
    /// The station presented no certificate the connection could hand back.
    NoLeaf,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::NoExpectedNodeId => f.write_str("the dial target names no expected node_id"),
            DialError::Resolve(e) => write!(f, "resolving the station's address: {e}"),
            DialError::Endpoint(e) => write!(f, "creating the QUIC endpoint: {e}"),
            DialError::Config(e) => write!(f, "building the TLS configuration: {e}"),
            DialError::Connect(e) => write!(f, "starting the QUIC connection: {e}"),
            DialError::Connection(e) => write!(f, "the QUIC connection failed: {e}"),
            DialError::NoLeaf => f.write_str("the station presented no certificate"),
        }
    }
}

impl std::error::Error for DialError {}

/// Dials `target`: QUIC and TLS 1.3 with the post-quantum key exchange,
/// the station's certificate checked for an ML-DSA-87 key it holds.
pub async fn dial_target(target: &Target) -> Result<Dialed, DialError> {
    if target.expected_node_id == [0u8; 32] {
        return Err(DialError::NoExpectedNodeId);
    }
    let addr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(DialError::Resolve)?
        .next()
        .ok_or_else(|| DialError::Resolve(std::io::Error::other("no address")))?;
    let bind: SocketAddr = if addr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(bind).map_err(DialError::Endpoint)?;
    endpoint.set_default_client_config(client_config()?);
    let connection = endpoint
        .connect(addr, &target.host)
        .map_err(DialError::Connect)?
        .await
        .map_err(DialError::Connection)?;
    let leaf = connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|chain| chain.first().map(|leaf| leaf.to_vec()))
        .ok_or(DialError::NoLeaf)?;
    Ok(Dialed {
        connection,
        endpoint,
        leaf,
        target: target.clone(),
    })
}

/// The QUIC client configuration every dial uses.
fn client_config() -> Result<ClientConfig, DialError> {
    let quic = QuicClientConfig::with_initial(
        Arc::new(tls_client_config()?),
        macula_pqc::quic_initial_suite(),
    )
    .map_err(|e| DialError::Config(e.to_string()))?;
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT).map_err(|e| DialError::Config(e.to_string()))?,
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.stream_receive_window((16u32 * 1024 * 1024).into());
    transport.receive_window((64u32 * 1024 * 1024).into());
    transport.send_window(64 * 1024 * 1024);
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// The rustls half of a dial: macula-pqc's client builder, its key possession
/// verifier, the ALPN, and no session resumption.
pub(crate) fn tls_client_config() -> Result<rustls::ClientConfig, DialError> {
    let verifier = KeyPossessionVerifier::new();
    let mut config = macula_pqc::client_builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

#[cfg(test)]
mod tests {
    //! The dial, on real QUIC against local stations: one as a macula 12
    //! station is (macula-pqc, an ML-DSA-87 certificate), and the ones a dial
    //! must refuse.

    use std::sync::Arc;

    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::crypto::aws_lc_rs::kx_group as aws;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{NamedGroup, ServerConfig};

    use super::{dial_target, tls_client_config, DialError, Target, ALPN};
    use crate::profile::Profile;

    /// SecP384r1MLKEM1024, code point 0x11ED.
    const SECP384R1MLKEM1024: NamedGroup = NamedGroup::Unknown(0x11ED);

    fn mldsa_certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let (certificate, key) =
            macula_pqc::self_signed_certificate(&[7u8; 32], vec!["localhost".to_string()])
                .expect("a certificate");
        (certificate, key.into())
    }

    fn classical_certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params")
            .self_signed(&key_pair)
            .expect("a certificate");
        (
            certificate.der().clone(),
            PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        )
    }

    /// A station on 127.0.0.1, serving `config` over QUIC; its endpoint and
    /// port.
    fn station(mut config: ServerConfig, alpn: &[u8]) -> (quinn::Endpoint, u16) {
        config.alpn_protocols = vec![alpn.to_vec()];
        let quic =
            QuicServerConfig::with_initial(Arc::new(config), macula_pqc::quic_initial_suite())
                .expect("a QUIC server config");
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic)),
            ([127, 0, 0, 1], 0).into(),
        )
        .expect("an endpoint");
        let port = endpoint.local_addr().expect("an address").port();
        let accepting = endpoint.clone();
        tokio::spawn(hold_connections(accepting));
        (endpoint, port)
    }

    /// Accepts every connection the station's endpoint receives, holding each
    /// until it closes.
    async fn hold_connections(accepting: quinn::Endpoint) {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(hold_until_closed(incoming));
        }
    }

    /// Holds one incoming connection, once established, until it closes.
    async fn hold_until_closed(incoming: quinn::Incoming) {
        if let Ok(connection) = incoming.await {
            connection.closed().await;
        }
    }

    fn macula_station() -> (quinn::Endpoint, u16, CertificateDer<'static>) {
        let (certificate, key) = mldsa_certificate();
        let config = macula_pqc::server_builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("a station configuration");
        let (endpoint, port) = station(config, ALPN);
        (endpoint, port, certificate)
    }

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".to_string(),
            port,
            profile: Profile::PqHybrid,
            expected_node_id: [1u8; 32],
        }
    }

    #[test]
    fn a_dial_offers_exactly_macula_pqcs_groups() {
        let config = tls_client_config().expect("a configuration");
        let offered: Vec<NamedGroup> = config
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(
            offered,
            vec![SECP384R1MLKEM1024, NamedGroup::secp256r1MLKEM768]
        );
    }

    #[tokio::test]
    async fn a_macula_12_station_is_reached_and_its_leaf_handed_back() {
        let (_station, port, certificate) = macula_station();
        let dialed = dial_target(&target(port))
            .await
            .expect("the station is reached");
        assert_eq!(dialed.leaf, certificate.to_vec());
        dialed.connection.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn a_target_without_an_expected_node_id_is_refused_before_dialing() {
        let mut unpinned = target(9);
        unpinned.expected_node_id = [0u8; 32];
        assert!(matches!(
            dial_target(&unpinned).await,
            Err(DialError::NoExpectedNodeId)
        ));
    }

    #[tokio::test]
    async fn a_station_with_a_classical_certificate_is_refused() {
        let (certificate, key) = classical_certificate();
        let provider = CryptoProvider {
            kx_groups: vec![aws::SECP256R1MLKEM768],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .expect("a station configuration");
        let (_station, port) = station(config, ALPN);
        assert!(matches!(
            dial_target(&target(port)).await,
            Err(DialError::Connection(_))
        ));
    }

    #[tokio::test]
    async fn a_classical_only_station_is_refused() {
        let (certificate, key) = classical_certificate();
        let provider = CryptoProvider {
            kx_groups: vec![aws::X25519, aws::SECP256R1, aws::SECP384R1],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .expect("a station configuration");
        let (_station, port) = station(config, ALPN);
        assert!(matches!(
            dial_target(&target(port)).await,
            Err(DialError::Connection(_))
        ));
    }

    #[tokio::test]
    async fn a_station_that_does_not_speak_macula_is_refused() {
        let (certificate, key) = mldsa_certificate();
        let config = macula_pqc::server_builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .expect("a station configuration");
        let (_station, port) = station(config, b"h3");
        assert!(matches!(
            dial_target(&target(port)).await,
            Err(DialError::Connection(_))
        ));
    }
}
