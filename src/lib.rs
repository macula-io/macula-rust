//! Rust port of macula's SDK (client/leaf) protocol — see
//! `plans/PLAN_WIRE_PROTOCOL.md` for the full wire-format spec this crate
//! is built against, traced directly to `macula-io/macula` source.
//!
//! Mobile (iOS/Android via UniFFI) is the flagship consumer driving this
//! work, not the ceiling on it — nothing below the eventual FFI binding
//! layer is mobile-specific.

pub mod bolt4;
pub mod cbor;
pub mod cert;
pub mod cert_chain;
pub mod connection;
pub mod content;
mod control_channel;
pub mod dht;
pub mod direct_dial;
pub mod frame;
pub mod identity;
pub mod keystore;
pub mod manifest;
mod open_sessions;
pub mod pool;
pub mod stream;
pub mod transport;
pub mod ucan;
