//! Rust SDK for the macula mesh on wire 1.0: node keys (ML-DSA-87, and the
//! LAMPS composite ML-DSA-87 + RSA-PSS-4096 in pq_hybrid), bindings and
//! signed objects, and a station dialed over QUIC with a post-quantum key
//! exchange.
//!
//! Mobile (iOS/Android via UniFFI, `macula-rust-ffi`) is the flagship
//! consumer, not the ceiling: nothing below the FFI layer is mobile-specific.

/// The wire this crate speaks, major.minor (macula docs/design/WIRE_1_0.md).
/// Every wire 1.x peer shares its frozen core: the handshake, the frame
/// envelope, the record types and their signing rules, and the `_dht.*`
/// procedures.
pub const WIRE_VERSION: &str = "1.0";

pub mod binding;
pub mod cbor;
pub mod frame;
pub mod group;
pub mod handshake;
pub mod keystore;
pub mod manifest;
pub mod node_key;
pub mod petname;
pub mod pool;
pub mod profile;
pub mod record;
pub mod seal;
pub mod signed_object;
pub mod statement_issuer;
pub mod station_link;
pub mod transport;
pub mod ucan;
mod uuid_v7;
#[cfg(test)]
mod wire_vectors;
