//! UniFFI (Kotlin/Swift) bindings for [`macula_rust`]. A thin wrapper,
//! not a reimplementation — everything here delegates straight to the
//! core crate; nothing wire-level lives in this crate at all.
//!
//! Structure mirrors `iroh-ffi`'s relationship to `iroh`: a separate
//! crate depending on the core one, so the core crate carries zero
//! UniFFI dependency and zero FFI-shaped types. That separation is what
//! keeps `macula-rust` itself just as usable from plain Rust, a CLI,
//! or WASM as it was before this crate existed.
//!
//! Every application primitive the core crate has is wrapped: identity,
//! CONNECT/HELLO (either [`FfiTrust::Pinned`] or [`FfiTrust::WebPki`] —
//! see that type's own doc for when each applies), CALL/RESULT/ERROR as
//! both caller AND provider (`call`/[`FfiSession::serve_one_call`]),
//! UCAN-gated serving ([`FfiSession::serve_one_call_gated`]/
//! [`FfiSession::call_with_ucan`]) and the standalone `ucan_*` mint/verify/
//! introspect functions, PUBLISH/SUBSCRIBE/EVENT (including the supervised
//! [`FfiSession::run_publisher`]), content transfer, streaming RPC — both
//! the caller/consumer role (§13.1) and the provider role (§13.2/§6.9,
//! `advertise`/`accept_stream`), direct-dial resolution
//! ([`FfiSession::resolve_direct`]/[`call_direct`](FfiSession::call_direct)/
//! [`advertise_direct`](FfiSession::advertise_direct)) and its cert-chain-
//! authorized variants (`*_with_cert_chain`), and direct-dial streaming/
//! content transfer ([`FfiSession::open_stream_direct`]/
//! [`FfiSession::put_direct`]/[`FfiSession::get_direct`]).
//!
//! Not exposed, each a real, reasoned decision rather than an oversight:
//! `Trust::Insecure` — see [`FfiTrust`]'s own doc; the core crate's
//! `keep_advertised`/`keep_advertised_direct` background-loop helpers —
//! see [`FfiSession::advertise_direct`]'s own doc for why a native
//! background timer is the wrong shape for a mobile app and what to do
//! instead; `Session::run_subscriber` — same reasoning as
//! `keep_advertised` (it takes a generic `stop: impl Future` and
//! `handler: impl FnMut`, neither of which crosses the UniFFI boundary,
//! and a native long-lived receive loop fights mobile app-lifecycle
//! management the same way a background timer does) — its full external
//! behavior (subscribe once, receive resiliently, unsubscribe when done)
//! is still achievable by composing the already-exposed
//! [`FfiSession::subscribe`]/[`FfiSession::recv_event`]/
//! [`FfiSession::unsubscribe`] on the foreign side, catching and retrying
//! past a non-EVENT-frame error the way `run_subscriber` does internally
//! — nothing is lost, only where that retry loop lives.
//!
//! [`FfiValue`] mirrors every variant [`macula_rust::cbor::Value`]
//! has, including recursive list/map shapes (`Items`/`Fields`, via
//! `Vec` — see the type's own doc for why they aren't named `List`/
//! `Map` like the core type), narrowed only where the FFI boundary
//! forces it: `Int` is `i64` not `i128` (out-of-range values round-trip
//! as an [`FfiError::UnrepresentableValue`] rather than silently
//! truncating).
//!
//! Generate the bindings with the `uniffi-bindgen` binary this crate
//! also builds, e.g.:
//! ```text
//! cargo build -p macula-rust-ffi --release
//! cargo run -p macula-rust-ffi --bin uniffi-bindgen -- generate \
//!     --library target/release/libmacula_rust_ffi.so \
//!     --language kotlin --out-dir bindings/kotlin
//! ```

uniffi::setup_scaffolding!();

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("connecting to the station: {reason}")]
    Connect { reason: String },
    #[error("the call failed: {reason}")]
    Call { reason: String },
    #[error("sending a frame failed: {reason}")]
    Send { reason: String },
    #[error("receiving failed: {reason}")]
    Recv { reason: String },
    #[error("content operation failed: {reason}")]
    Content { reason: String },
    #[error("a value could not cross the FFI boundary: {reason}")]
    UnrepresentableValue { reason: String },
    #[error("expected exactly {expected} bytes, got {actual}")]
    WrongByteLength { expected: u32, actual: u32 },
    #[error("this session is already closed")]
    Closed,
    #[error("the call handler failed: {reason}")]
    CallHandlerFailed { reason: String },
    #[error("direct-dial resolution failed: {reason}")]
    Resolve { reason: String },
    #[error("direct-dial trust violation: the dialed peer's proven identity did not match the resolved station (see resolved/dialed fields)")]
    DirectDialTrustViolation { resolved: Vec<u8>, dialed: Vec<u8> },
    #[error("UCAN operation failed: {reason}")]
    Ucan { reason: String },
    #[error("no seed is stored under this keystore identity")]
    KeystoreNotFound,
    #[error("platform secure store error: {reason}")]
    Keystore { reason: String },
}

impl From<macula_rust::ucan::UcanError> for FfiError {
    fn from(e: macula_rust::ucan::UcanError) -> Self {
        FfiError::Ucan {
            reason: e.to_string(),
        }
    }
}

impl From<macula_rust::keystore::KeyStoreError> for FfiError {
    fn from(e: macula_rust::keystore::KeyStoreError) -> Self {
        match e {
            macula_rust::keystore::KeyStoreError::NotFound => FfiError::KeystoreNotFound,
            other => FfiError::Keystore {
                reason: other.to_string(),
            },
        }
    }
}

/// `Vec<u8>` -> `[u8; 32]`, with both lengths actually reported on
/// mismatch — UniFFI has no fixed-size byte array type, so every 32-byte
/// field (`realm`, node ids) crosses the boundary as `Vec<u8>` and gets
/// validated here.
fn to_32(bytes: Vec<u8>) -> Result<[u8; 32], FfiError> {
    let actual = bytes.len() as u32;
    bytes.try_into().map_err(|_| FfiError::WrongByteLength {
        expected: 32,
        actual,
    })
}

/// `Vec<u8>` -> `[u8; 34]` — same as [`to_32`], for an MCID
/// (`<<Version:8, Codec:8, Hash:32/binary>>`, `plans/PLAN_WIRE_PROTOCOL.md`
/// §12.1).
fn to_mcid(bytes: Vec<u8>) -> Result<macula_rust::manifest::Mcid, FfiError> {
    let actual = bytes.len() as u32;
    bytes.try_into().map_err(|_| FfiError::WrongByteLength {
        expected: 34,
        actual,
    })
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
                        reason: format!("integer {n} is outside i64 range"),
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

/// The result of a CALL: a mirror of
/// [`macula_rust::frame::CallResponse`].
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiCallResponse {
    Result {
        payload: FfiValue,
        responded_by: Vec<u8>,
    },
    Error {
        code: u8,
        name: String,
        reported_by: Vec<u8>,
        detail: Option<String>,
    },
}

impl TryFrom<macula_rust::frame::CallResponse> for FfiCallResponse {
    type Error = FfiError;

    fn try_from(r: macula_rust::frame::CallResponse) -> Result<Self, FfiError> {
        use macula_rust::frame::CallResponse;
        match r {
            CallResponse::Result {
                payload,
                responded_by,
            } => Ok(FfiCallResponse::Result {
                payload: FfiValue::try_from(payload)?,
                responded_by: responded_by.to_vec(),
            }),
            CallResponse::Error {
                code,
                name,
                reported_by,
                detail,
            } => Ok(FfiCallResponse::Error {
                code,
                name,
                reported_by: reported_by.to_vec(),
                detail,
            }),
        }
    }
}

/// A resolved direct-dial target — a mirror of
/// [`macula_rust::direct_dial::Resolved`]: the station's own node id
/// (32 bytes) plus its dialable host/port. Returned by
/// [`FfiSession::resolve_direct`]; [`FfiSession::call_direct`] does this
/// same resolution internally, so most callers never need this type
/// directly — it's exposed for a caller that wants to resolve once and
/// decide what to do with the target itself (e.g. displaying it, or
/// dialing via a mechanism this crate doesn't cover).
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiResolved {
    pub station: Vec<u8>,
    pub host: String,
    pub port: u16,
}

impl From<macula_rust::direct_dial::Resolved> for FfiResolved {
    fn from(r: macula_rust::direct_dial::Resolved) -> Self {
        FfiResolved {
            station: r.station.to_vec(),
            host: r.host,
            port: r.port,
        }
    }
}

impl From<macula_rust::direct_dial::ResolveError> for FfiError {
    fn from(e: macula_rust::direct_dial::ResolveError) -> Self {
        FfiError::Resolve {
            reason: e.to_string(),
        }
    }
}

impl From<macula_rust::direct_dial::CallError> for FfiError {
    fn from(e: macula_rust::direct_dial::CallError) -> Self {
        use macula_rust::direct_dial::CallError;
        match e {
            CallError::Resolve(re) => re.into(),
            CallError::TrustViolation { resolved, dialed } => FfiError::DirectDialTrustViolation {
                resolved: resolved.to_vec(),
                dialed: dialed.to_vec(),
            },
            other => FfiError::Call {
                reason: other.to_string(),
            },
        }
    }
}

impl From<macula_rust::direct_dial::AdvertiseDirectError> for FfiError {
    fn from(e: macula_rust::direct_dial::AdvertiseDirectError) -> Self {
        FfiError::Send {
            reason: e.to_string(),
        }
    }
}

/// One entry in a UCAN token's capability list — mirrors
/// [`macula_rust::ucan::Capability`].
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiCapability {
    pub with: String,
    pub can: String,
}

impl From<macula_rust::ucan::Capability> for FfiCapability {
    fn from(c: macula_rust::ucan::Capability) -> Self {
        FfiCapability {
            with: c.with,
            can: c.can,
        }
    }
}

impl From<FfiCapability> for macula_rust::ucan::Capability {
    fn from(c: FfiCapability) -> Self {
        macula_rust::ucan::Capability {
            with: c.with,
            can: c.can,
        }
    }
}

/// A UCAN token's decoded claims — a mirror of
/// [`macula_rust::ucan::Payload`], minus `facts`: the core type's
/// `facts` field is an arbitrary `serde_json::Value` map, which has no
/// UniFFI-representable shape (unlike [`FfiValue`], which exists
/// specifically to give CBOR values one) — the same class of narrowing
/// [`FfiValue::Int`] already documents for `i128`. A caller needing the
/// raw `fct` claim can decode the token bytes on the foreign side with any
/// JSON library.
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiUcanPayload {
    pub issuer: String,
    pub audience: String,
    pub capabilities: Vec<FfiCapability>,
    pub expires_at: Option<i64>,
    pub not_before: Option<i64>,
    pub nonce: String,
    pub proofs: Vec<String>,
}

impl From<macula_rust::ucan::Payload> for FfiUcanPayload {
    fn from(p: macula_rust::ucan::Payload) -> Self {
        FfiUcanPayload {
            issuer: p.issuer,
            audience: p.audience,
            capabilities: p.capabilities.into_iter().map(Into::into).collect(),
            expires_at: p.expires_at,
            not_before: p.not_before,
            nonce: p.nonce,
            proofs: p.proofs,
        }
    }
}

/// Mints a new UCAN token, self-issued and signed by `identity` — see
/// [`macula_rust::ucan::create`]'s own doc for the full contract
/// (`issuer`/`audience` are opaque strings, not validated here). A token
/// for a UCAN-gated procedure must name the calling node as its `audience`:
/// that node's id as lowercase hex.
#[uniffi::export]
pub fn ucan_create(
    issuer: String,
    audience: String,
    capabilities: Vec<FfiCapability>,
    identity: &FfiKeyPair,
    expires_at: Option<i64>,
    not_before: Option<i64>,
) -> Result<Vec<u8>, FfiError> {
    let opts = macula_rust::ucan::CreateOpts {
        expires_at,
        not_before,
        ..Default::default()
    };
    macula_rust::ucan::create(
        &issuer,
        &audience,
        capabilities.into_iter().map(Into::into).collect(),
        &identity.0,
        opts,
    )
    .map_err(FfiError::from)
}

/// Verifies `token`'s signature against `public_key` (32 bytes) and its
/// `exp`/`nbf` claims against the current time — see
/// [`macula_rust::ucan::verify`]'s own doc, including its check order.
/// Only a successful [`ucan_verify`] result should ever back an
/// authorization decision — [`ucan_decode`] and the `ucan_get_*` getters
/// below never check the signature.
#[uniffi::export]
pub fn ucan_verify(token: Vec<u8>, public_key: Vec<u8>) -> Result<FfiUcanPayload, FfiError> {
    let key = to_32(public_key)?;
    macula_rust::ucan::verify(&token, &key)
        .map(FfiUcanPayload::from)
        .map_err(FfiError::from)
}

/// Parses `token`'s payload WITHOUT verifying its signature or checking
/// expiration — see [`ucan_verify`]'s doc for why that distinction matters.
#[uniffi::export]
pub fn ucan_decode(token: Vec<u8>) -> Result<FfiUcanPayload, FfiError> {
    macula_rust::ucan::decode(&token)
        .map(FfiUcanPayload::from)
        .map_err(FfiError::from)
}

/// `token`'s `iss` claim, unverified — see [`ucan_verify`]'s doc.
#[uniffi::export]
pub fn ucan_get_issuer(token: Vec<u8>) -> Result<String, FfiError> {
    macula_rust::ucan::get_issuer(&token).map_err(FfiError::from)
}

/// `token`'s `aud` claim, unverified — see [`ucan_verify`]'s doc.
#[uniffi::export]
pub fn ucan_get_audience(token: Vec<u8>) -> Result<String, FfiError> {
    macula_rust::ucan::get_audience(&token).map_err(FfiError::from)
}

/// `token`'s `cap` claim, unverified — see [`ucan_verify`]'s doc.
#[uniffi::export]
pub fn ucan_get_capabilities(token: Vec<u8>) -> Result<Vec<FfiCapability>, FfiError> {
    macula_rust::ucan::get_capabilities(&token)
        .map(|caps| caps.into_iter().map(Into::into).collect())
        .map_err(FfiError::from)
}

/// `token`'s `exp` claim, unverified — see [`ucan_verify`]'s doc.
#[uniffi::export]
pub fn ucan_get_expiration(token: Vec<u8>) -> Result<Option<i64>, FfiError> {
    macula_rust::ucan::get_expiration(&token).map_err(FfiError::from)
}

/// `token`'s `prf` claim, unverified — see [`ucan_verify`]'s doc.
#[uniffi::export]
pub fn ucan_get_proofs(token: Vec<u8>) -> Result<Vec<String>, FfiError> {
    macula_rust::ucan::get_proofs(&token).map_err(FfiError::from)
}

/// Whether `token`'s `exp` claim is in the past, unverified — see
/// [`ucan_verify`]'s doc. A token with no `exp` claim is never expired.
#[uniffi::export]
pub fn ucan_is_expired(token: Vec<u8>) -> Result<bool, FfiError> {
    macula_rust::ucan::is_expired(&token).map_err(FfiError::from)
}

/// `token`'s content identifier (SHA-256, base64url-no-pad) — used only
/// for proof-chain references between UCANs. See
/// [`macula_rust::ucan::compute_cid`]'s own doc.
#[uniffi::export]
pub fn ucan_compute_cid(token: Vec<u8>) -> String {
    macula_rust::ucan::compute_cid(&token)
}

/// What a provider requires to answer one inbound CALL — a mirror of
/// [`macula_rust::ucan::Policy`], passed to
/// [`FfiSession::serve_one_call_gated`]. `Open` is what
/// [`FfiSession::serve_one_call`] uses internally.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiPolicy {
    Open,
    Required { issuer: Vec<u8> },
}

impl TryFrom<FfiPolicy> for macula_rust::ucan::Policy {
    type Error = FfiError;

    fn try_from(p: FfiPolicy) -> Result<Self, FfiError> {
        Ok(match p {
            FfiPolicy::Open => macula_rust::ucan::Policy::open(),
            FfiPolicy::Required { issuer } => macula_rust::ucan::Policy::required(to_32(issuer)?),
        })
    }
}

/// Provider role: implement this trait on the foreign side (Kotlin,
/// Swift) to serve inbound unary CALLs — see
/// [`FfiSession::serve_one_call`]. Adapts
/// [`macula_rust::connection::CallHandler`] for the FFI boundary:
/// `handle` receives the full inbound call (`procedure`/`realm`/
/// `payload`) rather than being looked up from a table first, since a
/// UniFFI foreign trait can't be handed a plain Rust closure the way
/// the core crate's `CallLookup` is — do your own procedure routing
/// inside `handle` if a single session serves more than one procedure.
///
/// An `Err` reply is always sent as a BOLT#4 `unknown_error` (0x0F)
/// with `reason` as its `detail` — this trait has no way to
/// distinguish "unknown procedure" from any other application-level
/// failure the way the core crate's `CallLookup` can (a synchronous,
/// local table lookup that either finds a handler or doesn't, checked
/// *before* any handler runs): that distinction would need the foreign
/// side to answer a synchronous "do I handle this?" question ahead of
/// the necessarily-async `handle` call, which UniFFI foreign traits
/// don't support today. Nothing behavioral is lost either way — BOLT#4
/// `unknown_next_peer` and `unknown_error` carry the identical retry
/// classification (`plans/PLAN_WIRE_PROTOCOL.md` §9) — only diagnostic
/// precision.
///
/// A panic inside `handle` is caught the same way the core crate's own
/// `serve_one_call` catches one (via `tokio::spawn` +
/// `JoinError::is_panic()`) and reported to the caller as BOLT#4
/// `temporary_relay_failure`, not propagated across the FFI boundary as
/// a Rust panic.
#[uniffi::export(foreign)]
#[async_trait::async_trait]
pub trait FfiCallHandler: Send + Sync {
    async fn handle(
        &self,
        procedure: String,
        realm: Vec<u8>,
        payload: FfiValue,
    ) -> Result<FfiValue, FfiError>;
}

/// What a subscriber receives: a mirror of
/// [`macula_rust::frame::EventInfo`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiEvent {
    pub topic: String,
    pub realm: Vec<u8>,
    pub publisher: Vec<u8>,
    pub seq: u64,
    pub payload: FfiValue,
    pub delivered_via: String,
}

impl TryFrom<macula_rust::frame::EventInfo> for FfiEvent {
    type Error = FfiError;

    fn try_from(e: macula_rust::frame::EventInfo) -> Result<Self, FfiError> {
        Ok(FfiEvent {
            topic: e.topic,
            realm: e.realm.to_vec(),
            publisher: e.publisher.to_vec(),
            seq: e.seq,
            payload: FfiValue::try_from(e.payload)?,
            delivered_via: e.delivered_via,
        })
    }
}

/// `mode` on a stream — mirrors [`macula_rust::frame::StreamMode`].
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiStreamMode {
    ServerStream,
    ClientStream,
    Bidi,
}

impl From<FfiStreamMode> for macula_rust::frame::StreamMode {
    fn from(m: FfiStreamMode) -> Self {
        match m {
            FfiStreamMode::ServerStream => macula_rust::frame::StreamMode::ServerStream,
            FfiStreamMode::ClientStream => macula_rust::frame::StreamMode::ClientStream,
            FfiStreamMode::Bidi => macula_rust::frame::StreamMode::Bidi,
        }
    }
}

impl From<macula_rust::frame::StreamMode> for FfiStreamMode {
    fn from(m: macula_rust::frame::StreamMode) -> Self {
        match m {
            macula_rust::frame::StreamMode::ServerStream => FfiStreamMode::ServerStream,
            macula_rust::frame::StreamMode::ClientStream => FfiStreamMode::ClientStream,
            macula_rust::frame::StreamMode::Bidi => FfiStreamMode::Bidi,
        }
    }
}

/// `encoding` on a stream chunk — mirrors
/// [`macula_rust::frame::StreamEncoding`]. A semantic hint, not a
/// second wire codec — see that type's own doc.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiStreamEncoding {
    Raw,
    Msgpack,
}

impl From<FfiStreamEncoding> for macula_rust::frame::StreamEncoding {
    fn from(e: FfiStreamEncoding) -> Self {
        match e {
            FfiStreamEncoding::Raw => macula_rust::frame::StreamEncoding::Raw,
            FfiStreamEncoding::Msgpack => macula_rust::frame::StreamEncoding::Msgpack,
        }
    }
}

impl From<macula_rust::frame::StreamEncoding> for FfiStreamEncoding {
    fn from(e: macula_rust::frame::StreamEncoding) -> Self {
        match e {
            macula_rust::frame::StreamEncoding::Raw => FfiStreamEncoding::Raw,
            macula_rust::frame::StreamEncoding::Msgpack => FfiStreamEncoding::Msgpack,
        }
    }
}

/// One item received from a stream: a chunk, or a clean end-of-stream.
/// Mirrors [`macula_rust::stream::StreamItem`].
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiStreamItem {
    Data {
        seq: u64,
        encoding: FfiStreamEncoding,
        body: FfiValue,
    },
    Eof,
}

/// The terminal result of a `client_stream`/`bidi` exchange — the pair
/// [`macula_rust::stream::StreamHandle::await_reply`] returns.
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiStreamReply {
    pub payload: FfiValue,
    pub responded_by: Vec<u8>,
}

/// Provider role: the fields of an inbound STREAM_OPEN needed to decide
/// how to handle it (which procedure, whose call, what arguments) —
/// mirrors [`macula_rust::frame::StreamOpenInfo`].
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiStreamOpenInfo {
    pub stream_id: Vec<u8>,
    pub procedure: String,
    pub realm: Vec<u8>,
    pub mode: FfiStreamMode,
    pub args: FfiValue,
    pub deadline_ms: i64,
    pub caller: Vec<u8>,
}

impl TryFrom<macula_rust::frame::StreamOpenInfo> for FfiStreamOpenInfo {
    type Error = FfiError;

    fn try_from(o: macula_rust::frame::StreamOpenInfo) -> Result<Self, FfiError> {
        Ok(FfiStreamOpenInfo {
            stream_id: o.stream_id.to_vec(),
            procedure: o.procedure,
            realm: o.realm.to_vec(),
            mode: o.mode.into(),
            args: FfiValue::try_from(o.args)?,
            deadline_ms: o.deadline_ms as i64,
            caller: o.caller.to_vec(),
        })
    }
}

/// What [`FfiSession::accept_stream`] hands back: a ready-to-use
/// [`FfiStream`] plus the STREAM_OPEN info that came with it.
#[derive(uniffi::Record)]
pub struct FfiAcceptedStream {
    pub stream: std::sync::Arc<FfiStream>,
    pub info: FfiStreamOpenInfo,
}

/// What [`FfiSession::open_stream_direct`]/
/// [`FfiSession::open_stream_direct_with_cert_chain`] hand back: the fresh
/// [`FfiSession`] dialed for this stream, and the [`FfiStream`] itself.
/// Unlike [`FfiAcceptedStream`] (a stream on an EXISTING session), a
/// direct-dial stream opens a brand new session — the caller owns it and
/// must close it once done, alongside the stream.
#[derive(uniffi::Record)]
pub struct FfiOpenedDirectStream {
    pub session: std::sync::Arc<FfiSession>,
    pub stream: std::sync::Arc<FfiStream>,
}

/// How to trust whatever certificate the station presents — mirrors
/// [`macula_rust::transport::Trust`], minus `Insecure`.
///
/// `Insecure` (skip TLS verification entirely) is deliberately NOT
/// exposed here: it's a development/diagnostic escape hatch in the core
/// crate, never something a shipped mobile app should be able to
/// select — a stray debug flag left on in production would silently
/// disable all transport security. Reach into the core crate directly
/// (outside this FFI boundary) for that one, if a test harness genuinely
/// needs it.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiTrust {
    /// Pin the station's known Ed25519 pubkey (its macula node_id, 32
    /// bytes) — the right mode once a station's identity is known
    /// (DHT-resolved, or configured directly), and the ONLY mode that
    /// works at all for a station without a CA-issued cert, e.g. a
    /// self-hosted/home station outside the public demo fleet — WebPki
    /// has no chain to validate there.
    Pinned { node_id: Vec<u8> },
    /// Standard CA-bundle + hostname validation, for a station whose
    /// TLS is terminated by real PKI (e.g. Let's Encrypt) — what the
    /// public `station-de-frankfurt.macula.io` demo fleet presents.
    WebPki,
}

impl TryFrom<FfiTrust> for macula_rust::transport::Trust {
    type Error = FfiError;

    fn try_from(t: FfiTrust) -> Result<Self, FfiError> {
        match t {
            FfiTrust::Pinned { node_id } => {
                Ok(macula_rust::transport::Trust::Pinned(to_32(node_id)?))
            }
            FfiTrust::WebPki => Ok(macula_rust::transport::Trust::WebPki),
        }
    }
}

/// An Ed25519 identity, puzzle-hardened by construction — see
/// [`macula_rust::identity::KeyPair::generate_with_default_puzzle`]'s
/// own doc for why this is always the right default despite its (small,
/// one-time) CPU cost.
#[derive(uniffi::Object)]
pub struct FfiKeyPair(macula_rust::identity::KeyPair);

#[uniffi::export]
impl FfiKeyPair {
    #[uniffi::constructor]
    pub fn generate() -> Self {
        Self(macula_rust::identity::KeyPair::generate_with_default_puzzle())
    }

    /// Reconstruct a keypair from its 32-byte seed (see
    /// [`FfiKeyPair::private_bytes`]) — deterministic, the same seed
    /// always yields the same node_id. The seed came from a
    /// puzzle-hardened [`generate`](Self::generate) call, so
    /// reconstructing from it stays puzzle-valid too; puzzle validity is
    /// a property of the public key this seed determines, not something
    /// re-checked at reconstruction time.
    #[uniffi::constructor]
    pub fn from_seed_bytes(seed: Vec<u8>) -> Result<Self, FfiError> {
        Ok(Self(macula_rust::identity::KeyPair::from_seed_bytes(
            to_32(seed)?,
        )))
    }

    /// This identity's node_id (its Ed25519 public key), 32 bytes.
    pub fn node_id(&self) -> Vec<u8> {
        self.0.node_id().to_vec()
    }

    /// This identity's 32-byte seed. Persist it to restore the SAME
    /// identity (same node_id) across restarts via
    /// [`FfiKeyPair::from_seed_bytes`] — treat it like a private key,
    /// since it deterministically reconstructs this keypair.
    pub fn private_bytes(&self) -> Vec<u8> {
        self.0.private_bytes().to_vec()
    }

    /// Persist this identity's seed to the platform's native secure store
    /// — Keychain on macOS/iOS, Secret Service on Linux, Credential
    /// Manager on Windows, Keystore on Android — instead of handling the
    /// raw bytes from [`private_bytes`](Self::private_bytes) yourself. See
    /// `macula_rust::keystore`'s module doc for the full platform
    /// story, including Android's one-time `initializeNdkContext` setup
    /// requirement (unrelated to this method itself — a property of that
    /// platform's Keystore, not something this crate can do for you).
    ///
    /// `service`/`account` address the credential the same way every
    /// `keyring` consumer does — e.g. `("com.example.myapp",
    /// "macula-identity")` — pick values scoped to your application, since
    /// the underlying store is a shared OS-wide facility, not sandboxed to
    /// this crate.
    pub fn save_to_keystore(&self, service: String, account: String) -> Result<(), FfiError> {
        let store = macula_rust::keystore::KeyringStore::new(&service, &account)?;
        self.0.save_to_keystore(&store)?;
        Ok(())
    }

    /// Reconstruct a keypair previously persisted with
    /// [`save_to_keystore`](Self::save_to_keystore). Fails with
    /// [`FfiError::KeystoreNotFound`] if nothing has been stored yet under
    /// this `service`/`account` pair.
    #[uniffi::constructor]
    pub fn load_from_keystore(service: String, account: String) -> Result<Self, FfiError> {
        let store = macula_rust::keystore::KeyringStore::new(&service, &account)?;
        Ok(Self(macula_rust::identity::KeyPair::load_from_keystore(
            &store,
        )?))
    }
}

/// A handshaked connection to a macula-station. Wraps
/// [`macula_rust::connection::Session`] behind a mutex — UniFFI
/// object methods take `&self`, but the wrapped methods need `&mut
/// self`, so this crate's only job here is bridging that, not adding
/// behavior.
#[derive(uniffi::Object)]
pub struct FfiSession(tokio::sync::Mutex<Option<macula_rust::connection::Session>>);

#[uniffi::export(async_runtime = "tokio")]
impl FfiSession {
    /// Dial `host:port` and complete the CONNECT/HELLO handshake, using
    /// `trust` to validate the station's TLS certificate — see
    /// [`FfiTrust`]'s own doc for which mode fits which station.
    #[uniffi::constructor]
    pub async fn connect(
        host: String,
        port: u16,
        trust: FfiTrust,
        identity: &FfiKeyPair,
    ) -> Result<Self, FfiError> {
        let session = macula_rust::connection::connect(&host, port, trust.try_into()?, &identity.0)
            .await
            .map_err(|e| FfiError::Connect {
                reason: e.to_string(),
            })?;
        Ok(Self(tokio::sync::Mutex::new(Some(session))))
    }

    /// This session's own connected station's node id (32 bytes), as
    /// proven by the HELLO frame's own signature during the handshake.
    /// Needed to call [`put_direct`](Self::put_direct) against "whatever
    /// station this session is already on" — the common case, and
    /// otherwise unreachable through this FFI surface without a
    /// [`resolve_direct`](Self::resolve_direct) result to read a station
    /// id from instead.
    pub async fn station_id(&self) -> Vec<u8> {
        let guard = self.0.lock().await;
        guard
            .as_ref()
            .map(|s| s.station.node_id.to_vec())
            .unwrap_or_default()
    }

    /// Send a signed CALL and wait for the matching RESULT or ERROR.
    /// `realm` must be exactly 32 bytes. `timeout_ms` bounds both the
    /// wait for a response and the frame's own `deadline_ms` field
    /// (`now + timeout_ms`).
    pub async fn call(
        &self,
        procedure: String,
        realm: Vec<u8>,
        payload: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiCallResponse, FfiError> {
        let realm = to_32(realm)?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;

        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let response = session
            .call(
                &procedure,
                realm,
                payload.into(),
                deadline_ms,
                &identity.0,
                std::time::Duration::from_millis(timeout_ms),
            )
            .await
            .map_err(|e| FfiError::Call {
                reason: e.to_string(),
            })?;
        FfiCallResponse::try_from(response)
    }

    /// The provider role's counterpart to [`call`](Self::call): block
    /// for the next inbound CALL frame, bounded by `timeout_ms`, and
    /// dispatch it to `handler` — see [`FfiCallHandler`].
    ///
    /// Same "control stream, one thing at a time" limitation
    /// [`call`](Self::call) itself carries, and the same lock-holding
    /// behavior [`accept_stream`](Self::accept_stream) already
    /// documents: no other method on this `FfiSession` can run
    /// concurrently while a call to this one is in flight.
    pub async fn serve_one_call(
        &self,
        handler: std::sync::Arc<dyn FfiCallHandler>,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        self.serve_one_call_gated(handler, FfiPolicy::Open, timeout_ms, identity)
            .await
    }

    /// [`serve_one_call`](Self::serve_one_call), additionally gating the
    /// inbound CALL through `policy` BEFORE `handler` ever runs — see
    /// [`FfiPolicy`]. A rejected caller gets a BOLT#4 `unauthorized` error
    /// and never reaches `handler`; `handler` itself never sees the raw
    /// UCAN token either way, matching
    /// [`macula_rust::connection::Session::serve_one_call_gated`]'s own
    /// contract exactly.
    pub async fn serve_one_call_gated(
        &self,
        handler: std::sync::Arc<dyn FfiCallHandler>,
        policy: FfiPolicy,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let policy: macula_rust::ucan::Policy = policy.try_into()?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;

        let lookup = move |realm: &[u8; 32], procedure: &str| {
            let handler = handler.clone();
            let realm = realm.to_vec();
            let procedure = procedure.to_string();
            let core_handler: macula_rust::connection::CallHandler =
                std::sync::Arc::new(move |payload: macula_rust::cbor::Value| {
                    let handler = handler.clone();
                    let realm = realm.clone();
                    let procedure = procedure.clone();
                    Box::pin(async move {
                        let ffi_payload = FfiValue::try_from(payload).map_err(|e| e.to_string())?;
                        let reply = handler
                            .handle(procedure, realm, ffi_payload)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(macula_rust::cbor::Value::from(reply))
                    })
                        as macula_rust::connection::BoxFuture<
                            'static,
                            Result<macula_rust::cbor::Value, String>,
                        >
                });
            Some(core_handler)
        };

        session
            .serve_one_call_gated(
                lookup,
                move |_, _| policy.clone(),
                &identity.0,
                std::time::Duration::from_millis(timeout_ms),
            )
            .await
            .map_err(|e| FfiError::Recv {
                reason: e.to_string(),
            })
    }

    /// Send a signed PUBLISH. Fire-and-forget — no reply is expected on
    /// the wire; a subscriber (this session included, if subscribed to
    /// the same topic/realm) receives it asynchronously via
    /// [`recv_event`](Self::recv_event).
    ///
    /// `seq` and `published_at_ms` are caller-supplied rather than
    /// tracked internally — unlike streaming RPC's per-stream counter,
    /// PUBLISH's `seq` is a per-publisher, per-topic sequence the mesh
    /// uses for gap detection, and a client publishing to several topics
    /// has to own that bookkeeping itself; this crate doesn't
    /// second-guess it.
    pub async fn publish(
        &self,
        topic: String,
        realm: Vec<u8>,
        seq: u64,
        payload: FfiValue,
        published_at_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::PublishSpec::new(
            topic,
            realm,
            identity.0.node_id(),
            seq,
            payload.into(),
            published_at_ms,
        );
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .publish(&spec, &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Send a signed SUBSCRIBE. Fire-and-forget — deliveries arrive via
    /// [`recv_event`](Self::recv_event).
    pub async fn subscribe(
        &self,
        topic: String,
        realm: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::SubscribeSpec::new(topic, realm, identity.0.node_id());
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .subscribe(&spec, &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Send a signed UNSUBSCRIBE. Fire-and-forget.
    pub async fn unsubscribe(
        &self,
        topic: String,
        realm: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::UnsubscribeSpec::new(topic, realm, identity.0.node_id());
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .unsubscribe(&spec, &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Send a signed ADVERTISE (§6.9) — registers this session as the
    /// handler for `procedure` under `realm`. Fire-and-forget; the
    /// station then routes inbound STREAM_OPENs for it back to us as a
    /// fresh dedicated stream — see
    /// [`accept_stream`](Self::accept_stream).
    pub async fn advertise(
        &self,
        procedure: String,
        realm: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::AdvertiseSpec::new(realm, procedure, identity.0.node_id());
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .advertise(&spec, &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Send a signed UNADVERTISE. Fire-and-forget.
    pub async fn unadvertise(
        &self,
        procedure: String,
        realm: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::UnadvertiseSpec::new(realm, procedure, identity.0.node_id());
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .unadvertise(&spec, &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Direct-dial resolution: finds `procedure`'s currently-advertised
    /// serving station and its dialable host/port via the mesh DHT,
    /// through this session (used only to query the DHT — it does not
    /// need to be connected to the station that will end up serving the
    /// call). The provider must have advertised via
    /// [`advertise_direct`](Self::advertise_direct) — a plain
    /// [`advertise`](Self::advertise) publishes no discoverable record.
    /// Most callers want [`call_direct`](Self::call_direct) instead,
    /// which does this resolution internally; this is exposed separately
    /// for a caller that wants the resolved target itself.
    pub async fn resolve_direct(
        &self,
        procedure: String,
        realm: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<FfiResolved, FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let resolved =
            macula_rust::direct_dial::resolve(session, &identity.0, realm, &procedure).await?;
        Ok(resolved.into())
    }

    /// Resolves `procedure`'s provider via direct-dial (through this
    /// session, used only to query the DHT) and calls it there, in one
    /// hop, in a SEPARATE connection from this session — see
    /// [`macula_rust::direct_dial::call`]'s own doc for the full trust
    /// model. Use this instead of [`call`](Self::call) when the provider
    /// is reachable only via [`advertise_direct`](Self::advertise_direct)
    /// (e.g. no ordinary advertise-gossip route has propagated between
    /// the two stations involved).
    pub async fn call_direct(
        &self,
        procedure: String,
        realm: Vec<u8>,
        payload: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiCallResponse, FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let response = macula_rust::direct_dial::call(
            session,
            &identity.0,
            realm,
            &procedure,
            payload.into(),
            std::time::Duration::from_millis(timeout_ms),
        )
        .await?;
        FfiCallResponse::try_from(response)
    }

    /// Publishes a signed direct-dial advertisement for `procedure` naming
    /// this session's own currently-connected station — sends the
    /// ordinary ADVERTISE frame first (so an inbound CALL routed here the
    /// normal way still works, matching
    /// [`advertise`](Self::advertise)'s own effect), then publishes a
    /// signed `procedure_advertisement` DHT record so a caller on a
    /// different station can [`resolve_direct`](Self::resolve_direct)/
    /// [`call_direct`](Self::call_direct) here directly, skipping
    /// inter-station gossip propagation. `ttl_ms` is the DHT record's
    /// lifetime — this call does not repeat itself; a long-lived provider
    /// must call it again on its own schedule before `ttl_ms` elapses
    /// (deliberately not wrapped in a background loop here — see this
    /// crate's own module doc for why: unlike the core crate's
    /// `keep_advertised_direct`, a native background timer inside a
    /// mobile app fights the OS's own app-lifecycle/background-execution
    /// model; the foreign side should drive its own periodic re-advertise
    /// using whatever scheduling mechanism its platform provides, calling
    /// this method each time).
    pub async fn advertise_direct(
        &self,
        procedure: String,
        realm: Vec<u8>,
        ttl_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        macula_rust::direct_dial::advertise_direct(
            session,
            &identity.0,
            realm,
            &procedure,
            std::time::Duration::from_millis(ttl_ms),
        )
        .await
        .map_err(FfiError::from)
    }

    /// As [`call`](Self::call), attaching `ucan_token` (e.g. from
    /// [`ucan_create`]) to the outgoing CALL — for invoking a procedure
    /// gated by a [`FfiPolicy::Required`] policy on the provider side.
    pub async fn call_with_ucan(
        &self,
        procedure: String,
        realm: Vec<u8>,
        payload: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
        ucan_token: Vec<u8>,
    ) -> Result<FfiCallResponse, FfiError> {
        let realm = to_32(realm)?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let response = session
            .call_with_ucan(
                &procedure,
                realm,
                payload.into(),
                deadline_ms,
                &identity.0,
                std::time::Duration::from_millis(timeout_ms),
                ucan_token,
            )
            .await
            .map_err(|e| FfiError::Call {
                reason: e.to_string(),
            })?;
        FfiCallResponse::try_from(response)
    }

    /// The supervised counterpart to the bare [`publish`](Self::publish)
    /// primitive — see
    /// [`macula_rust::connection::Session::run_publisher`]'s own doc.
    /// `announce` controls whether `pubsub.publish_started_v1`/
    /// `pubsub.publish_completed_v1` facts are published around this
    /// publish (a fact-publish failure never fails the underlying publish
    /// either way).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_publisher(
        &self,
        topic: String,
        realm: Vec<u8>,
        seq: u64,
        payload: FfiValue,
        published_at_ms: u64,
        announce: bool,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let spec = macula_rust::frame::PublishSpec::new(
            topic,
            realm,
            identity.0.node_id(),
            seq,
            payload.into(),
            published_at_ms,
        );
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        session
            .run_publisher(&spec, &identity.0, announce)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// [`resolve_direct`](Self::resolve_direct) plus Slice 7c Direction B
    /// managed-realm authorization: only an advertisement whose embedded
    /// cert chain validates to `realm_ca_pem` and names `expected_org` is
    /// trusted. Opt-in — [`resolve_direct`](Self::resolve_direct) itself is
    /// unaffected.
    pub async fn resolve_direct_with_cert_chain(
        &self,
        procedure: String,
        realm: Vec<u8>,
        realm_ca_pem: Vec<u8>,
        expected_org: String,
        identity: &FfiKeyPair,
    ) -> Result<FfiResolved, FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let resolved = macula_rust::direct_dial::resolve_with_cert_chain(
            session,
            &identity.0,
            realm,
            &procedure,
            &realm_ca_pem,
            &expected_org,
        )
        .await?;
        Ok(resolved.into())
    }

    /// [`call_direct`](Self::call_direct), resolved via
    /// [`resolve_direct_with_cert_chain`](Self::resolve_direct_with_cert_chain)
    /// instead of [`resolve_direct`](Self::resolve_direct) — see both for
    /// the full contract. Opt-in managed-realm authorization;
    /// [`call_direct`](Self::call_direct) itself is unaffected.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_direct_with_cert_chain(
        &self,
        procedure: String,
        realm: Vec<u8>,
        realm_ca_pem: Vec<u8>,
        expected_org: String,
        payload: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiCallResponse, FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let response = macula_rust::direct_dial::call_with_cert_chain(
            session,
            &identity.0,
            realm,
            &procedure,
            &realm_ca_pem,
            &expected_org,
            payload.into(),
            std::time::Duration::from_millis(timeout_ms),
        )
        .await?;
        FfiCallResponse::try_from(response)
    }

    /// [`advertise_direct`](Self::advertise_direct) plus an embedded X.509
    /// service-cert chain, for Slice 7c Direction B managed-realm
    /// authorization — see
    /// [`resolve_direct_with_cert_chain`](Self::resolve_direct_with_cert_chain)/
    /// [`call_direct_with_cert_chain`](Self::call_direct_with_cert_chain)
    /// for the corresponding checks. Opt-in:
    /// [`advertise_direct`](Self::advertise_direct) itself is unaffected.
    pub async fn advertise_direct_with_cert_chain(
        &self,
        procedure: String,
        realm: Vec<u8>,
        ttl_ms: u64,
        cert_chain_pem: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let realm = to_32(realm)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        macula_rust::direct_dial::advertise_direct_with_cert_chain(
            session,
            &identity.0,
            realm,
            &procedure,
            std::time::Duration::from_millis(ttl_ms),
            cert_chain_pem,
        )
        .await
        .map_err(FfiError::from)
    }

    /// Resolves `procedure`'s provider via direct-dial (through this
    /// session, used only to query the DHT) and opens a stream to it
    /// there, in one hop, in a SEPARATE session from this one — mirrors
    /// [`call_direct`](Self::call_direct)'s own resolve-then-dial shape for
    /// [`stream_open`](Self::stream_open) instead of
    /// [`call`](Self::call). The caller owns BOTH the returned
    /// [`FfiOpenedDirectStream::session`] and
    /// [`FfiOpenedDirectStream::stream`] — unlike a unary call, which owns
    /// its dial for exactly one request/reply, a stream outlives this
    /// function call, so the returned session must be closed once the
    /// stream (and any other work on it) is done.
    pub async fn open_stream_direct(
        &self,
        procedure: String,
        realm: Vec<u8>,
        mode: FfiStreamMode,
        args: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiOpenedDirectStream, FfiError> {
        let realm = to_32(realm)?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let (opened_session, handle) = macula_rust::direct_dial::open_stream_direct(
            session,
            &identity.0,
            realm,
            &procedure,
            mode.into(),
            args.into(),
            deadline_ms,
            std::time::Duration::from_millis(timeout_ms),
        )
        .await
        .map_err(|e| FfiError::Resolve {
            reason: e.to_string(),
        })?;
        Ok(FfiOpenedDirectStream {
            session: std::sync::Arc::new(FfiSession(tokio::sync::Mutex::new(Some(opened_session)))),
            stream: std::sync::Arc::new(FfiStream(tokio::sync::Mutex::new(Some(handle)))),
        })
    }

    /// [`open_stream_direct`](Self::open_stream_direct), resolved via
    /// [`resolve_direct_with_cert_chain`](Self::resolve_direct_with_cert_chain)
    /// instead of [`resolve_direct`](Self::resolve_direct) — see both for
    /// the full contract. Opt-in managed-realm authorization;
    /// [`open_stream_direct`](Self::open_stream_direct) itself is
    /// unaffected.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_stream_direct_with_cert_chain(
        &self,
        procedure: String,
        realm: Vec<u8>,
        realm_ca_pem: Vec<u8>,
        expected_org: String,
        mode: FfiStreamMode,
        args: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiOpenedDirectStream, FfiError> {
        let realm = to_32(realm)?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let (opened_session, handle) =
            macula_rust::direct_dial::open_stream_direct_with_cert_chain(
                session,
                &identity.0,
                realm,
                &procedure,
                &realm_ca_pem,
                &expected_org,
                mode.into(),
                args.into(),
                deadline_ms,
                std::time::Duration::from_millis(timeout_ms),
            )
            .await
            .map_err(|e| FfiError::Resolve {
                reason: e.to_string(),
            })?;
        Ok(FfiOpenedDirectStream {
            session: std::sync::Arc::new(FfiSession(tokio::sync::Mutex::new(Some(opened_session)))),
            stream: std::sync::Arc::new(FfiStream(tokio::sync::Mutex::new(Some(handle)))),
        })
    }

    /// Stores `data` at a KNOWN `station` (32 bytes) directly, in one hop,
    /// instead of going through whatever station this session happens to
    /// be connected to — see
    /// [`macula_rust::direct_dial::put_direct`]'s own doc, including
    /// its identity-collision caveat when this session is already
    /// connected to `station` (use a different identity for this session
    /// than `identity` if so).
    pub async fn put_direct(
        &self,
        station: Vec<u8>,
        data: Vec<u8>,
        name: String,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<Vec<u8>, FfiError> {
        let station = to_32(station)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let mcid = macula_rust::direct_dial::put_direct(
            session,
            &identity.0,
            station,
            &data,
            name,
            std::time::Duration::from_millis(timeout_ms),
        )
        .await
        .map_err(|e| FfiError::Content {
            reason: e.to_string(),
        })?;
        Ok(mcid.to_vec())
    }

    /// Fetches the content addressed by `mcid` (34 bytes) directly from
    /// whichever station announced it, resolved via this session's DHT
    /// query — see [`macula_rust::direct_dial::get_direct`]'s own doc.
    /// Unlike [`put_direct`](Self::put_direct), no `station` is needed: a
    /// `content_announcement` names its own announcer.
    pub async fn get_direct(
        &self,
        mcid: Vec<u8>,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<Vec<u8>, FfiError> {
        let mcid = to_mcid(mcid)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        macula_rust::direct_dial::get_direct(
            session,
            &identity.0,
            mcid,
            std::time::Duration::from_millis(timeout_ms),
        )
        .await
        .map_err(|e| FfiError::Content {
            reason: e.to_string(),
        })
    }

    /// Provider role: block for the next inbound STREAM_OPEN, bounded by
    /// `timeout_ms`. Only ever succeeds after
    /// [`advertise`](Self::advertise) has registered at least one
    /// procedure — otherwise the station has nothing to route here.
    ///
    /// Holds this session's lock for as long as it waits: no other
    /// method on this `FfiSession` can run concurrently while a call to
    /// `accept_stream` is in flight, matching the core crate's own
    /// `Session` (its control stream is single-owner by construction —
    /// this isn't an extra restriction the FFI layer adds).
    pub async fn accept_stream(&self, timeout_ms: u64) -> Result<FfiAcceptedStream, FfiError> {
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let (handle, info) = macula_rust::stream::StreamHandle::accept(
            session,
            std::time::Duration::from_millis(timeout_ms),
        )
        .await
        .map_err(|e| FfiError::Recv {
            reason: e.to_string(),
        })?;
        Ok(FfiAcceptedStream {
            stream: std::sync::Arc::new(FfiStream(tokio::sync::Mutex::new(Some(handle)))),
            info: FfiStreamOpenInfo::try_from(info)?,
        })
    }

    /// Block for the next EVENT delivery, bounded by `timeout_ms`. Any
    /// non-EVENT frame received first is an error, not silently skipped
    /// — matches [`macula_rust::connection::Session::recv_event`]'s
    /// own contract.
    pub async fn recv_event(&self, timeout_ms: u64) -> Result<FfiEvent, FfiError> {
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let event = session
            .recv_event(std::time::Duration::from_millis(timeout_ms))
            .await
            .map_err(|e| FfiError::Recv {
                reason: e.to_string(),
            })?;
        FfiEvent::try_from(event)
    }

    /// Store `data` under a content-address, returning its MCID (34
    /// bytes). `name` is attached to the manifest when `data` is large
    /// enough to be chunked; silently unused for a single block, which
    /// is addressed purely by content hash — see
    /// [`macula_rust::content::put`]'s own doc.
    pub async fn content_put(
        &self,
        data: Vec<u8>,
        name: String,
        identity: &FfiKeyPair,
    ) -> Result<Vec<u8>, FfiError> {
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let mcid = macula_rust::content::put(session, &data, name, &identity.0)
            .await
            .map_err(|e| FfiError::Content {
                reason: e.to_string(),
            })?;
        Ok(mcid.to_vec())
    }

    /// Fetch and verify the content addressed by `mcid` (34 bytes).
    pub async fn content_get(
        &self,
        mcid: Vec<u8>,
        identity: &FfiKeyPair,
    ) -> Result<Vec<u8>, FfiError> {
        let mcid = to_mcid(mcid)?;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        macula_rust::content::get(session, mcid, &identity.0)
            .await
            .map_err(|e| FfiError::Content {
                reason: e.to_string(),
            })
    }

    /// Open a dedicated stream and send a signed STREAM_OPEN. `realm`
    /// must be exactly 32 bytes. `timeout_ms` bounds the frame's own
    /// `deadline_ms` field (`now + timeout_ms`); there's no open-time
    /// acknowledgement to wait for on the wire — the provider starts
    /// reacting to it directly.
    pub async fn stream_open(
        &self,
        procedure: String,
        realm: Vec<u8>,
        mode: FfiStreamMode,
        args: FfiValue,
        timeout_ms: u64,
        identity: &FfiKeyPair,
    ) -> Result<FfiStream, FfiError> {
        let realm = to_32(realm)?;
        let deadline_ms = (now_ms() + timeout_ms) as i128;
        let mut guard = self.0.lock().await;
        let session = guard.as_mut().ok_or(FfiError::Closed)?;
        let handle = macula_rust::stream::StreamHandle::open(
            session,
            &procedure,
            realm,
            mode.into(),
            args.into(),
            deadline_ms,
            &identity.0,
        )
        .await
        .map_err(|e| FfiError::Send {
            reason: e.to_string(),
        })?;
        Ok(FfiStream(tokio::sync::Mutex::new(Some(handle))))
    }

    /// Close the session with a GOODBYE frame. A no-op if already closed.
    pub async fn close(&self, identity: &FfiKeyPair) {
        let mut guard = self.0.lock().await;
        if let Some(session) = guard.take() {
            session.close("normal", None, &identity.0).await;
        }
    }
}

/// A streaming RPC exchange, caller/consumer role — wraps
/// [`macula_rust::stream::StreamHandle`] the same way [`FfiSession`]
/// wraps [`macula_rust::connection::Session`]: a mutex bridges
/// UniFFI's `&self` methods to the core type's `&mut self` ones. Created
/// via [`FfiSession::stream_open`].
#[derive(uniffi::Object)]
pub struct FfiStream(tokio::sync::Mutex<Option<macula_rust::stream::StreamHandle>>);

#[uniffi::export(async_runtime = "tokio")]
impl FfiStream {
    /// Send one chunk.
    pub async fn send_data(
        &self,
        encoding: FfiStreamEncoding,
        body: FfiValue,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let mut guard = self.0.lock().await;
        let handle = guard.as_mut().ok_or(FfiError::Closed)?;
        handle
            .send_data(encoding.into(), body.into(), &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Half-close: signal this side is done sending. For
    /// `client_stream`/`bidi` modes, follow with
    /// [`await_reply`](Self::await_reply).
    pub async fn close_send(&self, identity: &FfiKeyPair) -> Result<(), FfiError> {
        let mut guard = self.0.lock().await;
        let handle = guard.as_mut().ok_or(FfiError::Closed)?;
        handle
            .close_send(&identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Receive the next chunk or end-of-stream, bounded by `timeout_ms`.
    pub async fn recv(&self, timeout_ms: u64) -> Result<FfiStreamItem, FfiError> {
        let mut guard = self.0.lock().await;
        let handle = guard.as_mut().ok_or(FfiError::Closed)?;
        let item = handle
            .recv(std::time::Duration::from_millis(timeout_ms))
            .await
            .map_err(|e| FfiError::Recv {
                reason: e.to_string(),
            })?;
        Ok(match item {
            macula_rust::stream::StreamItem::Data {
                seq,
                encoding,
                body,
            } => FfiStreamItem::Data {
                seq,
                encoding: encoding.into(),
                body: FfiValue::try_from(body)?,
            },
            macula_rust::stream::StreamItem::Eof => FfiStreamItem::Eof,
        })
    }

    /// Block for the provider's terminal STREAM_REPLY (`client_stream`/
    /// `bidi` modes only) — call after [`close_send`](Self::close_send).
    pub async fn await_reply(&self, timeout_ms: u64) -> Result<FfiStreamReply, FfiError> {
        let mut guard = self.0.lock().await;
        let handle = guard.as_mut().ok_or(FfiError::Closed)?;
        let (payload, responded_by) = handle
            .await_reply(std::time::Duration::from_millis(timeout_ms))
            .await
            .map_err(|e| FfiError::Recv {
                reason: e.to_string(),
            })?;
        Ok(FfiStreamReply {
            payload: FfiValue::try_from(payload)?,
            responded_by: responded_by.to_vec(),
        })
    }

    /// Provider role: send the terminal STREAM_REPLY a `client_stream`/
    /// `bidi` caller's own `await_reply` is waiting on, once this side
    /// has fully consumed and verified whatever the caller streamed.
    pub async fn send_reply(
        &self,
        payload: FfiValue,
        identity: &FfiKeyPair,
    ) -> Result<(), FfiError> {
        let mut guard = self.0.lock().await;
        let handle = guard.as_mut().ok_or(FfiError::Closed)?;
        handle
            .send_reply(payload.into(), &identity.0)
            .await
            .map_err(|e| FfiError::Send {
                reason: e.to_string(),
            })
    }

    /// Non-normal termination: send an explicit STREAM_ERROR abort,
    /// rather than just dropping the stream — the peer's only signal to
    /// tell a cancellation/failure apart from a dropped connection
    /// (`plans/PLAN_WIRE_PROTOCOL.md` §13.1, point 4). A no-op if
    /// already closed/aborted.
    pub async fn abort(&self, code: String, message: String, identity: &FfiKeyPair) {
        let mut guard = self.0.lock().await;
        if let Some(handle) = guard.take() {
            handle.abort(code, message, &identity.0).await;
        }
    }
}

#[cfg(test)]
mod ffi_value_tests {
    use super::{FfiError, FfiMapEntry, FfiValue};
    use macula_rust::cbor::Value;

    fn round_trip(v: FfiValue) -> Result<FfiValue, FfiError> {
        let core: Value = v.into();
        FfiValue::try_from(core)
    }

    #[test]
    fn scalars_still_round_trip() {
        for v in [
            FfiValue::Null,
            FfiValue::Int(-7),
            FfiValue::Bytes(vec![1, 2, 3]),
            FfiValue::Text("station".to_string()),
            FfiValue::Float(1.5),
        ] {
            assert_eq!(round_trip(v.clone()).unwrap(), v);
        }
    }

    #[test]
    fn empty_list_and_map_round_trip() {
        assert_eq!(
            round_trip(FfiValue::Items(vec![])).unwrap(),
            FfiValue::Items(vec![])
        );
        assert_eq!(
            round_trip(FfiValue::Fields(vec![])).unwrap(),
            FfiValue::Fields(vec![])
        );
    }

    #[test]
    fn flat_list_round_trips() {
        let v = FfiValue::Items(vec![
            FfiValue::Int(1),
            FfiValue::Text("two".to_string()),
            FfiValue::Null,
        ]);
        assert_eq!(round_trip(v.clone()).unwrap(), v);
    }

    #[test]
    fn flat_map_round_trips() {
        let v = FfiValue::Fields(vec![
            FfiMapEntry {
                key: FfiValue::Text("city".to_string()),
                value: FfiValue::Text("Milan".to_string()),
            },
            FfiMapEntry {
                key: FfiValue::Text("lat".to_string()),
                value: FfiValue::Float(45.4642),
            },
        ]);
        assert_eq!(round_trip(v.clone()).unwrap(), v);
    }

    /// The actual shape `hecate_stations.list_stations` returns:
    /// `#{stations => [#{city => ..., lat => ..., ...}, ...]}` — a map
    /// containing a list of maps. This is the case that motivated the
    /// fix; a shallow test alone wouldn't have caught a bug in either
    /// recursive call.
    #[test]
    fn map_containing_list_of_maps_round_trips() {
        let station = |city: &str| {
            FfiValue::Fields(vec![
                FfiMapEntry {
                    key: FfiValue::Text("city".to_string()),
                    value: FfiValue::Text(city.to_string()),
                },
                FfiMapEntry {
                    key: FfiValue::Text("capabilities".to_string()),
                    value: FfiValue::Int(0),
                },
            ])
        };
        let v = FfiValue::Fields(vec![FfiMapEntry {
            key: FfiValue::Text("stations".to_string()),
            value: FfiValue::Items(vec![station("Milan"), station("Paris")]),
        }]);
        assert_eq!(round_trip(v.clone()).unwrap(), v);
    }

    /// A non-text map key must survive too — `Value::Map`'s keys are
    /// arbitrary values, not just text (see `FfiValue::Fields`'s own doc).
    #[test]
    fn integer_keyed_map_round_trips() {
        let v = FfiValue::Fields(vec![
            FfiMapEntry {
                key: FfiValue::Int(0),
                value: FfiValue::Text("a".to_string()),
            },
            FfiMapEntry {
                key: FfiValue::Int(1),
                value: FfiValue::Text("b".to_string()),
            },
        ]);
        assert_eq!(round_trip(v.clone()).unwrap(), v);
    }

    /// `i128` values outside `i64` range must still fail cleanly even
    /// nested inside a list -- the recursive `?`/`map_err` chain must
    /// propagate the error rather than swallowing or panicking.
    #[test]
    fn out_of_range_int_inside_list_errors_not_panics() {
        let too_big = Value::List(vec![Value::Int(i128::MAX)]);
        let err = FfiValue::try_from(too_big).unwrap_err();
        assert!(matches!(err, FfiError::UnrepresentableValue { .. }));
    }
}
