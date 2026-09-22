//! QUIC transport: dialing a macula-station, ported from
//! `native/macula_quic/src/config.rs` (`macula-io/macula`).
//!
//! Raw QUIC (RFC 9000), not real HTTP/3 despite the "HTTP/3 mesh"
//! branding elsewhere — ALPN is the plain string `"macula"`, and macula's
//! own application framing rides directly on QUIC streams. `quinn` is
//! the exact QUIC engine macula-station's own `native/macula_quic` NIF
//! already runs, so this is wire-compatible by construction, not by
//! coincidence.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, IdleTimeout, TransportConfig};

use crate::cert::{PubkeyPinVerifier, SkipServerVerification};

/// The ALPN macula-station listens for. Not `"h3"` — see the module doc.
pub const ALPN: &[u8] = b"macula";

/// Matches macula's own defaults (`macula_quic.erl`'s `idle_timeout_ms` /
/// `keep_alive_interval_ms`): long enough to tolerate a real gap between
/// frames without closing the connection, with keepalive pings sent
/// often enough (~10x within the idle window) that a healthy connection
/// is never mistaken for a dead one.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How to trust whatever certificate the station presents. Mirrors the
/// three modes `macula_quic`'s own `build_client_config` supports — see
/// `plans/PLAN_WIRE_PROTOCOL.md` §2.
///
/// `Clone, Copy`: every variant is plain data (a bare `[u8; 32]` or
/// nothing at all), and `pool.rs` needs to redial a link — possibly
/// under a DIFFERENT per-link trust than the pool's own configured
/// default, see `pool::PooledLink`'s own doc — more than once over a
/// link's lifetime (initial dial, every respawn).
#[derive(Clone, Copy)]
pub enum Trust {
    /// Pin the station's known Ed25519 pubkey (its macula NodeId). The
    /// right mode once a station's identity is known — DHT-resolved, or
    /// configured directly, which is the normal case for a mobile client
    /// dialing a known station.
    Pinned([u8; 32]),
    /// Standard CA-bundle + hostname validation, for a station whose TLS
    /// is terminated by real PKI (e.g. Let's Encrypt) rather than a
    /// self-signed macula identity cert.
    WebPki,
    /// Skip verification entirely. **Development/diagnostic only** — see
    /// [`crate::cert::SkipServerVerification`]'s own warning.
    Insecure,
}

#[derive(Debug)]
pub enum ConnectError {
    Resolve(std::io::Error),
    NoAddress,
    Endpoint(std::io::Error),
    Config(rustls::Error),
    Connect(quinn::ConnectError),
    Connection(quinn::ConnectionError),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Resolve(e) => write!(f, "resolving station address: {e}"),
            ConnectError::NoAddress => write!(f, "hostname resolved to no addresses"),
            ConnectError::Endpoint(e) => write!(f, "creating QUIC endpoint: {e}"),
            ConnectError::Config(e) => write!(f, "building TLS config: {e}"),
            ConnectError::Connect(e) => write!(f, "starting QUIC connect: {e}"),
            ConnectError::Connection(e) => write!(f, "QUIC connection failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

fn client_config(trust: Trust) -> Result<ClientConfig, rustls::Error> {
    let crypto = tls_client_config(trust);

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(DEFAULT_IDLE_TIMEOUT).expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_INTERVAL));
    apply_flow_control_defaults(&mut transport);

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// The rustls half of a dial's configuration, before quinn wraps it: a
/// seam, so the tests drive the configuration this crate actually dials
/// with rather than a copy built the same way.
///
/// The key exchange is `macula-pq`'s: its builder arrives with the groups
/// and TLS 1.3 fixed, and keeps its provider where nothing here can edit
/// it. A station offering only classical groups, as macula 11.5.0 and
/// earlier do, cannot be reached.
pub(crate) fn tls_client_config(trust: Trust) -> rustls::ClientConfig {
    let builder = macula_pq::client_builder;
    let mut crypto = match trust {
        Trust::Pinned(pubkey) => builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PubkeyPinVerifier::new(pubkey)))
            .with_no_client_auth(),
        Trust::WebPki => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        Trust::Insecure => builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto
}

/// Matches macula's own `apply_flow_control_defaults` in
/// `native/macula_quic/src/config.rs`: default Quinn flow-control
/// windows are conservative enough to bottleneck a connection carrying
/// many small signed frames, well before either side's application-level
/// backpressure kicks in.
fn apply_flow_control_defaults(transport: &mut TransportConfig) {
    transport.stream_receive_window((16u32 * 1024 * 1024).into());
    transport.receive_window((64u32 * 1024 * 1024).into());
    transport.send_window(64u64 * 1024 * 1024);
}

/// Dial a macula-station at `host:port` over QUIC with the given trust
/// mode, completing the QUIC/TLS handshake (ALPN negotiation included).
/// This is transport-only — it does **not** send or expect any macula
/// application frame (CONNECT/HELLO); see `plans/PLAN_WIRE_PROTOCOL.md`
/// §3 for what happens on top of this connection.
pub async fn connect(
    host: &str,
    port: u16,
    trust: Trust,
) -> Result<quinn::Connection, ConnectError> {
    let addr = resolve(host, port)?;
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("valid unspecified v6 addr")
    } else {
        "0.0.0.0:0".parse().expect("valid unspecified v4 addr")
    };

    let mut endpoint = Endpoint::client(bind_addr).map_err(ConnectError::Endpoint)?;
    let config = client_config(trust).map_err(ConnectError::Config)?;
    endpoint.set_default_client_config(config);

    let connecting = endpoint
        .connect(addr, host)
        .map_err(ConnectError::Connect)?;
    connecting.await.map_err(ConnectError::Connection)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, ConnectError> {
    (host, port)
        .to_socket_addrs()
        .map_err(ConnectError::Resolve)?
        .next()
        .ok_or(ConnectError::NoAddress)
}

#[cfg(test)]
mod tests {
    //! The key exchange this crate dials with, asserted on real TLS 1.3
    //! handshakes against the configuration `connect` actually uses.

    use std::sync::Arc;

    use rustls::crypto::aws_lc_rs::kx_group as aws;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{
        ClientConnection, ConfigBuilder, Connection, NamedGroup, ServerConfig, ServerConnection,
        WantsVerifier,
    };

    use super::{tls_client_config, Trust, ALPN};

    /// `SecP384r1MLKEM1024`, code point `0x11ED`. rustls has no variant for
    /// it and no rustls provider ships it: only `macula-pq` does.
    const SECP384R1MLKEM1024: NamedGroup = NamedGroup::Unknown(0x11ED);

    fn offered(provider: &CryptoProvider) -> Vec<NamedGroup> {
        provider.kx_groups.iter().map(|g| g.name()).collect()
    }

    /// Every trust mode dials with `macula-pq`'s two groups and nothing
    /// else. A mode that built its own provider would be the one path a
    /// classical group could come back through.
    #[test]
    fn every_trust_mode_offers_exactly_macula_pqs_groups() {
        for (mode, trust) in [
            ("pinned", Trust::Pinned([7; 32])),
            ("webpki", Trust::WebPki),
            ("insecure", Trust::Insecure),
        ] {
            assert_eq!(
                offered(tls_client_config(trust).crypto_provider()),
                vec![SECP384R1MLKEM1024, NamedGroup::secp256r1MLKEM768],
                "{mode}"
            );
        }
    }

    /// A station on `macula-pq`, as macula's own QUIC NIF now is.
    #[test]
    fn a_station_on_macula_pq_negotiates_secp384r1mlkem1024() {
        let station = station(macula_pq::server_builder());
        let agreed = handshake(tls_client_config(Trust::Insecure), station);
        assert_eq!(agreed, Ok(SECP384R1MLKEM1024));
    }

    /// A station on `aws-lc-rs`'s post-quantum groups: `macula-pq`'s ML-KEM
    /// against `aws-lc-rs`'s, on the group both offer.
    #[test]
    fn a_station_on_aws_lc_rs_post_quantum_groups_negotiates_secp256r1mlkem768() {
        let list = CryptoProvider {
            kx_groups: vec![
                aws::SECP256R1MLKEM768,
                aws::X25519MLKEM768,
                aws::MLKEM1024,
                aws::MLKEM768,
            ],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let agreed = handshake(tls_client_config(Trust::Insecure), station_on(list));
        assert_eq!(agreed, Ok(NamedGroup::secp256r1MLKEM768));
    }

    /// ⛔ THE NEGATIVE CONTROL. A station offering only classical groups, as
    /// macula 11.5.0 and earlier do, must NOT agree with this dialler. It
    /// can only fail to agree if the dialler's group list is in force.
    #[test]
    fn a_classical_only_station_cannot_agree_with_us() {
        let classical = CryptoProvider {
            kx_groups: vec![aws::X25519, aws::SECP256R1, aws::SECP384R1],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let outcome = handshake(tls_client_config(Trust::Insecure), station_on(classical));
        assert!(
            outcome.is_err(),
            "a classical-only station agreed with us: {outcome:?}"
        );
    }

    fn identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params")
            .self_signed(&key_pair)
            .expect("a self-signed certificate");
        let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        (vec![certificate.der().clone()], key)
    }

    fn station(builder: ConfigBuilder<ServerConfig, WantsVerifier>) -> ServerConfig {
        let (chain, key) = identity();
        let mut config = builder
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("a server certificate");
        config.alpn_protocols = vec![ALPN.to_vec()];
        config
    }

    fn station_on(provider: CryptoProvider) -> ServerConfig {
        station(
            ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("versions"),
        )
    }

    /// One in-memory handshake; the group both sides agreed on, or why
    /// they did not. A failure to agree is what the negative control asserts.
    fn handshake(client: rustls::ClientConfig, server: ServerConfig) -> Result<NamedGroup, String> {
        let name = ServerName::try_from("localhost").expect("a server name");
        let mut client = Connection::Client(
            ClientConnection::new(Arc::new(client), name).map_err(|e| e.to_string())?,
        );
        let mut server =
            Connection::Server(ServerConnection::new(Arc::new(server)).map_err(|e| e.to_string())?);
        for _ in 0..20 {
            let moved = pump(&mut client, &mut server)? + pump(&mut server, &mut client)?;
            if moved == 0 && !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        if client.is_handshaking() || server.is_handshaking() {
            return Err("handshake never completed".to_string());
        }
        let agreed = |c: &Connection| c.negotiated_key_exchange_group().map(|g| g.name());
        match (agreed(&client), agreed(&server)) {
            (Some(c), Some(s)) if c == s => Ok(c),
            other => Err(format!("the two sides disagree on the group: {other:?}")),
        }
    }

    fn pump(from: &mut Connection, to: &mut Connection) -> Result<usize, String> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut cursor = std::io::Cursor::new(&buf[..]);
        while (cursor.position() as usize) < buf.len() {
            to.read_tls(&mut cursor).map_err(|e| e.to_string())?;
            to.process_new_packets().map_err(|e| e.to_string())?;
        }
        Ok(buf.len())
    }
}
