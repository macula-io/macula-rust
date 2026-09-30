//! UniFFI (Kotlin/Swift) bindings for [`macula_rust`] on the macula 12 wire.
//! A thin wrapper, not a reimplementation: everything here delegates to the
//! core crate's [`macula_rust::pool`], and nothing wire-level lives in this
//! crate. A separate crate keeps the core free of any UniFFI dependency or
//! FFI-shaped type, so it stays as usable from plain Rust or a CLI.
//!
//! What is wrapped: a node key ([`FfiNodeKey`]: generated in either
//! profile, kept in a key file or the platform's secure store), and a pool
//! of station links ([`FfiPool`]) with everything a node does through it:
//! calls to a provider at its own station, serving a procedure with a
//! handler the foreign side implements ([`FfiCallHandler`]), pubsub
//! ([`FfiSubscription`]), streaming sessions on either side ([`FfiStream`],
//! [`FfiStreamHandler`]), node-served content (`share_content`,
//! `get_content`, [`FfiContentOptions`]), and DHT records.
//!
//! [`FfiValue`] mirrors every variant [`macula_rust::cbor::Value`] has,
//! narrowed only where the FFI boundary forces it: `Int` is `i64`, and an
//! integer outside it is [`FfiError::UnrepresentableValue`], never
//! truncated. Every 32-byte id crosses as bytes and is checked here
//! ([`FfiError::WrongByteLength`]).
//!
//! Generate the bindings with the `uniffi-bindgen` binary this crate also
//! builds, e.g.:
//! ```text
//! cargo build -p macula-rust-ffi --release
//! cargo run -p macula-rust-ffi --bin uniffi-bindgen -- generate \
//!     --library target/release/libmacula_rust_ffi.so \
//!     --language kotlin --out-dir bindings/kotlin
//! ```

mod content;
mod node_key;
mod pool;
mod pubsub;
mod serve;
mod stream;

pub use content::FfiContentOptions;
pub use node_key::{FfiNodeKey, FfiProfile};
pub use pool::{
    own_procedure, FfiLinkStatus, FfiPool, FfiPoolOptions, FfiProvider, FfiRealmKey, FfiRecord,
    FfiSeed,
};
pub use pubsub::{FfiEvent, FfiSubscription};
pub use serve::{FfiCallHandler, FfiRequest, FfiServed};
pub use stream::{FfiStream, FfiStreamEncoding, FfiStreamEvent, FfiStreamHandler, FfiStreamMode};

use macula_rust::pool::PoolError;
use macula_rust::station_link::LinkError;

uniffi::setup_scaffolding!();

/// Why an operation failed, as Kotlin and Swift see it.
#[derive(Debug, Clone, PartialEq, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// An argument outside what the operation takes.
    #[error("invalid argument: {message}")]
    InvalidArgument { message: String },
    /// A byte string of the wrong length, where a 32-byte id belongs.
    #[error("expected exactly {expected} bytes, got {actual}")]
    WrongByteLength { expected: u32, actual: u32 },
    /// A value the FFI boundary cannot carry, such as an integer outside i64.
    #[error("a value could not cross the FFI boundary: {message}")]
    UnrepresentableValue { message: String },
    /// A node key that could not be made, saved or loaded.
    #[error("node key: {message}")]
    Key { message: String },
    /// Nothing is stored under this keystore identity.
    #[error("no key is stored under this keystore identity")]
    KeystoreNotFound,
    /// The platform's secure store failed.
    #[error("platform secure store: {message}")]
    Keystore { message: String },
    /// No station link came up, or none is up to carry the operation.
    #[error("no station link: {message}")]
    NoLink { message: String },
    /// A realm the pool pins no key for: nothing in it is served or trusted.
    #[error("no realm key is pinned for the realm")]
    NoRealmKey,
    /// No trusted provider advertises or answered the procedure.
    #[error("{message}")]
    NoProvider { message: String },
    /// The provider's own ERROR: its code, detail, and who responded.
    #[error("the provider answered {code}")]
    Provider {
        code: String,
        detail: Option<String>,
        responded_by: Vec<u8>,
    },
    /// The connected station could not relay the call.
    #[error("the station could not relay the call: {code}")]
    Relay { code: String },
    /// No answer within the timeout.
    #[error("timed out")]
    Timeout,
    /// A call or an open that could not be kept confidential, so nothing was
    /// sent: macula's reason (`no_kem_key`) and the 8-byte key ids the
    /// trusted providers' advertisements named.
    #[error("confidentiality: {reason}")]
    Confidentiality {
        reason: String,
        advertised: Vec<Vec<u8>>,
    },
    /// A record the DHT does not hold.
    #[error("record not found")]
    RecordNotFound,
    /// A stream ended by an error: the peer's, the station's, or this side's.
    #[error("stream error {code}: {message}")]
    Stream { code: String, message: String },
    /// A stream that ended normally.
    #[error("end of stream")]
    EndOfStream,
    /// A handler the foreign side implements refused, or failed.
    #[error("handler: {message}")]
    Handler { message: String },
    /// An operation on a closed pool, subscription, stream or serving.
    #[error("closed")]
    Closed,
    /// Content no node announces in the realm.
    #[error("the content is not shared")]
    NotShared,
    /// Content every announcing sharer failed to give, and why each failed:
    /// content that does not match its id, is over the fetch's bounds, or a
    /// sharer that could not be reached.
    #[error("{message}")]
    ContentUnavailable { message: String },
    /// Anything else the core crate reports, as its text.
    #[error("{message}")]
    Other { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiError {
    /// A foreign handler that threw something other than an FfiError.
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        FfiError::Handler { message: e.reason }
    }
}

impl From<LinkError> for FfiError {
    fn from(e: LinkError) -> Self {
        match e {
            LinkError::Provider {
                responded_by,
                code,
                detail,
            } => FfiError::Provider {
                code,
                detail,
                responded_by: responded_by.to_vec(),
            },
            LinkError::Relay { code, .. } => FfiError::Relay { code },
            LinkError::CallTimeout | LinkError::HandshakeTimeout => FfiError::Timeout,
            LinkError::RecordNotFound => FfiError::RecordNotFound,
            LinkError::Stream { code, message, .. } => FfiError::Stream { code, message },
            LinkError::EndOfStream => FfiError::EndOfStream,
            LinkError::Closed | LinkError::StreamClosed | LinkError::Stopped => FfiError::Closed,
            other => FfiError::Other {
                message: other.to_string(),
            },
        }
    }
}

impl From<PoolError> for FfiError {
    fn from(e: PoolError) -> Self {
        match e {
            PoolError::Link(link) => link.into(),
            PoolError::NoRealmKey => FfiError::NoRealmKey,
            PoolError::Closed => FfiError::Closed,
            PoolError::NotShared => FfiError::NotShared,
            PoolError::Confidentiality(e) => FfiError::Confidentiality {
                reason: e.reason.name().to_string(),
                advertised: e.advertised.iter().map(|id| id.to_vec()).collect(),
            },
            e @ PoolError::ContentUnavailable(_) => FfiError::ContentUnavailable {
                message: e.to_string(),
            },
            e @ PoolError::NoProvider(_) => FfiError::NoProvider {
                message: e.to_string(),
            },
            e @ PoolError::NoLink(_) => FfiError::NoLink {
                message: e.to_string(),
            },
            e @ (PoolError::NoSeeds
            | PoolError::SeedNotPinned(_)
            | PoolError::TooManySeeds { .. }
            | PoolError::RealmTrustInvalid(_)
            | PoolError::InvalidOpts(_)) => FfiError::InvalidArgument {
                message: e.to_string(),
            },
            other => FfiError::Other {
                message: other.to_string(),
            },
        }
    }
}

/// `Vec<u8>` to `[u8; 32]`, reporting both lengths on a mismatch: UniFFI has
/// no fixed-size byte array, so every id crosses as bytes and is checked
/// here.
pub(crate) fn to_32(bytes: Vec<u8>) -> Result<[u8; 32], FfiError> {
    let actual = bytes.len() as u32;
    bytes.try_into().map_err(|_| FfiError::WrongByteLength {
        expected: 32,
        actual,
    })
}

/// A timeout in milliseconds, zero for the core crate's default.
pub(crate) fn millis(ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms)
}

/// A mirror of [`macula_rust::cbor::Value`], narrowed only where the
/// FFI boundary itself forces it: `Int` is `i64` not `i128` (UniFFI has
/// no 128-bit integer type; an out-of-range value returns
/// [`FfiError::UnrepresentableValue`] rather than silently truncating —
/// see [`FfiValue::try_from`]). `Items`/`Fields` recurse through `Vec`,
/// which UniFFI 0.32 generates correctly in both Kotlin and Swift —
/// confirmed by this crate's own round-trip tests, a real
/// `compileDebugKotlin` run, and `macula-apps/macula-cam2me`'s own
/// Android AND iOS CI (real `xcodebuild` against real Xcode on
/// `macos-latest`) both going green against the generated bindings —
/// the recursion itself was never the obstacle, only finding time to
/// wire it up.
///
/// Named `Items`/`Fields` rather than mirroring [`macula_rust::cbor::Value`]'s own
/// `List`/`Map` exactly: UniFFI's Kotlin codegen emits an unqualified
/// `List<T>`/`Map<T>` field type for a `Vec`/dictionary-shaped variant,
/// and inside `FfiValue`'s own sealed class body that unqualified name
/// resolves to the SIBLING variant class of the same name, not
/// `kotlin.collections.List` — confirmed by compiling the generated
/// bindings (`No type arguments expected for data class List :
/// FfiValue`) before this rename. `Array`/`Dictionary` would trade that
/// collision for the identical one against Swift's own stdlib types, so
/// neither language's collection type names are reused here.
///
/// [`Fields`](FfiValue::Fields) uses [`FfiMapEntry`] rather than
/// `HashMap<String, FfiValue>`: [`macula_rust::cbor::Value::Map`]'s own keys are
/// arbitrary values, not just text (Part 6 §9's integer-keyed sub-maps
/// are real, not hypothetical — mpong's per-wall game state is one), and
/// UniFFI's dictionary type requires a hashable, non-recursive key.
#[derive(uniffi::Enum, Debug, Clone, PartialEq)]
pub enum FfiValue {
    Null,
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Float(f64),
    Items(Vec<FfiValue>),
    Fields(Vec<FfiMapEntry>),
}

/// One key/value pair of an [`FfiValue::Fields`], in insertion order —
/// mirrors [`macula_rust::cbor::Value::Map`]'s own `Vec<(Value, Value)>` exactly,
/// including that canonical key sort happens at encode time, not here.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiMapEntry {
    pub key: FfiValue,
    pub value: FfiValue,
}

impl From<FfiValue> for macula_rust::cbor::Value {
    fn from(v: FfiValue) -> Self {
        use macula_rust::cbor::Value;
        match v {
            FfiValue::Null => Value::Null,
            FfiValue::Int(n) => Value::Int(n as i128),
            FfiValue::Bytes(b) => Value::Bytes(b),
            FfiValue::Text(t) => Value::Text(t),
            FfiValue::Float(f) => Value::Float(f),
            FfiValue::Items(items) => Value::List(items.into_iter().map(Into::into).collect()),
            FfiValue::Fields(entries) => Value::Map(
                entries
                    .into_iter()
                    .map(|e| (e.key.into(), e.value.into()))
                    .collect(),
            ),
        }
    }
}

impl TryFrom<macula_rust::cbor::Value> for FfiValue {
    type Error = FfiError;

    fn try_from(v: macula_rust::cbor::Value) -> Result<Self, FfiError> {
        use macula_rust::cbor::Value;
        match v {
            Value::Null => Ok(FfiValue::Null),
            Value::Int(n) => {
                i64::try_from(n)
                    .map(FfiValue::Int)
                    .map_err(|_| FfiError::UnrepresentableValue {
                        message: format!("integer {n} is outside i64 range"),
                    })
            }
            Value::Bytes(b) => Ok(FfiValue::Bytes(b)),
            Value::Text(t) => Ok(FfiValue::Text(t)),
            Value::Float(f) => Ok(FfiValue::Float(f)),
            Value::List(items) => items
                .into_iter()
                .map(FfiValue::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map(FfiValue::Items),
            Value::Map(pairs) => pairs
                .into_iter()
                .map(|(k, val)| {
                    Ok(FfiMapEntry {
                        key: FfiValue::try_from(k)?,
                        value: FfiValue::try_from(val)?,
                    })
                })
                .collect::<Result<Vec<_>, FfiError>>()
                .map(FfiValue::Fields),
        }
    }
}
