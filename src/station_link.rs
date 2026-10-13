//! A client's link to one macula station, as macula_station_link and
//! macula-go's stationlink are: a QUIC connection dialed to the station its
//! target pins, one bidirectional control stream, the wire 1.0 connection
//! handshake on it, then status statements both ways and every frame of the
//! session.
//!
//! After HELLO the link sends its own status statement at every reissue of
//! the node's statement issuer, and ends when the station's statement is five
//! minutes past its expiry or the station's TLS binding reaches its
//! not_after. No frame carries a neighbour signature: the session proofs
//! authenticated the station once. Every frame is read as wire 1.0 reads it
//! (WIRE_1_0.md section 3): one of a type the link does not act on is
//! dropped and counted, one with an unknown critical extension is dropped and
//! counted as `extension_unsupported`, both with the link left up; one that
//! does not read ends the link as malformed. A liveness probe every 30
//! seconds ends the link after two misses in a row.

mod admission;
mod authorize;
mod call;
mod confidential;
mod dht;
mod framing;
mod pubsub;
mod report;
mod serve;
mod stream;
mod versions;

pub use admission::{Admission, AdmissionLimits};
pub use call::{Call, DEFAULT_CALL_TIMEOUT, MAX_CALL_TIMEOUT};
pub use confidential::{
    is_clear_refusal, Confidentiality, ConfidentialityError, ConfidentialityReason, Seal,
};
pub use pubsub::{Event, EventDedup, Publication, PublicationSeq, SignedPublication, Subscription};
pub use report::{Report, ReportError};
pub use serve::{handler, BoxFuture, Handler, Offer, Request, Served, StreamOffer};
pub(crate) use stream::Reseal;
pub use stream::{
    stream_handler, Stream, StreamCall, StreamEvent, StreamHandler, DEFAULT_STREAM_DEADLINE,
};
pub use versions::handshake_counters;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::watch;

use crate::cbor::{self, Value};
use crate::frame::{self, Envelope, FrameError, Liveness};
use crate::handshake::{self, ClientSession, Exporter, HandshakeError, Peer, Station, VERSION_5};
use crate::node_key::NodeKey;
use crate::profile::Profile;
use crate::record::RecordError;
use crate::seal::Keyring;
use crate::statement_issuer::{
    ConnectMaterial, IssuerError, StatementIssuer, StatementSubscription,
};
use crate::transport::{self, DialError, Target};

use framing::{read_frame, FrameWriter, HANDSHAKE_FRAME_BYTES, MAX_FRAME_BYTES};

/// How long the handshake may take, as macula's 30 seconds.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long Close waits, after its GOODBYE, for the station to close the
/// connection before closing it itself.
const CLOSE_LINGER: Duration = Duration::from_secs(1);

/// How long past a statement's expiry the link keeps a station whose next
/// statement has not arrived: macula's five minutes.
const STATUS_GRACE_MS: i64 = 5 * 60 * 1000;

/// Why a link or one of its operations failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The configuration cannot be dialed: a key of another profile than the
    /// target's, or admission limits macula would not start with.
    InvalidConfig(String),
    /// The dial failed.
    Dial(String),
    /// The handshake refused, or was refused.
    Handshake(HandshakeError),
    /// The handshake did not finish within [`HANDSHAKE_TIMEOUT`].
    HandshakeTimeout,
    /// The issuer had no CONNECT material in force.
    Issuer(IssuerError),
    /// The QUIC connection or a stream failed.
    Io(String),
    /// A frame longer than the cap in force.
    FrameTooLarge(usize),
    /// A frame that could not be built, or one received that does not
    /// verify.
    Frame(FrameError),
    /// A record that could not be built, or one found that does not verify.
    Record(RecordError),
    /// The station's status statement lapsed past the grace.
    StatusExpired,
    /// The station's TLS binding reached its not_after.
    BindingExpired,
    /// The link was closed by its owner.
    Closed,
    /// The station ended the link with a GOODBYE, for this reason.
    Goodbye(String),
    /// The station missed two liveness probes in a row.
    LivenessLost,
    /// No verified reply answered the call within its timeout.
    CallTimeout,
    /// A provider's ERROR for the call.
    Provider {
        responded_by: [u8; 32],
        code: String,
        detail: Option<String>,
    },
    /// A relay error the connected station reported for the call.
    Relay { reported_by: [u8; 32], code: String },
    /// A find_record the station answered not_found.
    RecordNotFound,
    /// A station reply to a DHT call in a shape that call never answers with.
    UnexpectedReply(String),
    /// An offer without exactly one handler, or an org procedure's without
    /// the realm key.
    InvalidOffer,
    /// A procedure without a namespace, which nobody can authorize.
    NoOrg,
    /// A procedure already served on this link.
    AlreadyServed,
    /// A required-confidential procedure on a link whose `kem_advertise` is
    /// off: it would name no key and refuse every clear call.
    KemAdvertiseDisabled,
    /// A served procedure withdrawn by its owner.
    Stopped,
    /// The station refused an ADVERTISE or SUBSCRIBE (REGISTER_ACK,
    /// WIRE_1_0.md section 3.5): what it answered, and its reason.
    RegisterRefused {
        kind: frame::RegisterKind,
        reason: String,
    },
    /// A stream ended by a STREAM_ERROR: the peer's, the station's relay
    /// error (`relay`), or this side's own abort.
    Stream {
        code: String,
        message: String,
        relay: bool,
    },
    /// A stream that ended normally.
    EndOfStream,
    /// A send on a stream this side has ended.
    StreamClosed,
    /// A STREAM_OPEN over the 1 MiB a peer reads of one.
    StreamOpenTooLarge(usize),
    /// A call or an open that could not be kept confidential, so it was not
    /// made, or failed rather than be taken in the clear.
    Confidentiality(ConfidentialityError),
    /// The provider's sealed_refused: it could not open the request. `named`
    /// is the key it holds now, `None` when it holds none.
    SealedRefused { named: Option<[u8; 8]> },
    /// A clear answer to a sealed request that nothing clear may give: not a
    /// relay error, not a refusal from the closed set, not sealed_refused.
    /// Refused, never taken as the answer.
    ClearAnswerToSealed,
    /// A provider's sealed stream that has sealed all the frames GCM's
    /// bound allows under random nonces: another would pass it.
    SealedFramesExhausted,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Provider {
                code,
                detail: Some(d),
                ..
            } => write!(f, "the provider answered {code}: {d}"),
            LinkError::Provider { code, .. } => write!(f, "the provider answered {code}"),
            LinkError::Relay { code, .. } => {
                write!(f, "the station could not relay the call: {code}")
            }
            LinkError::Stream { code, message, .. } if !message.is_empty() => {
                write!(f, "stream error {code}: {message}")
            }
            LinkError::Stream { code, .. } => write!(f, "stream error {code}"),
            LinkError::Handshake(e) => write!(f, "handshake: {e}"),
            LinkError::Frame(e) => write!(f, "frame: {e}"),
            LinkError::Record(e) => write!(f, "record: {e}"),
            LinkError::Issuer(e) => write!(f, "{e}"),
            LinkError::Goodbye(reason) => write!(f, "the station said goodbye: {reason}"),
            LinkError::RegisterRefused { kind, reason } => {
                write!(f, "the station refused the {kind:?}: {reason}")
            }
            LinkError::Confidentiality(e) => write!(f, "{e}"),
            LinkError::SealedRefused { named: Some(id) } => write!(
                f,
                "the provider could not open the request; it holds key {}",
                id.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            LinkError::SealedRefused { named: None } => {
                f.write_str("the provider opens no sealed payload")
            }
            LinkError::ClearAnswerToSealed => f.write_str("a clear answer to a sealed request"),
            LinkError::KemAdvertiseDisabled => {
                f.write_str("a required-confidential procedure needs kem_advertise on")
            }
            LinkError::SealedFramesExhausted => {
                f.write_str("this sealed stream has sealed all the frames it may")
            }
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<FrameError> for LinkError {
    fn from(e: FrameError) -> Self {
        LinkError::Frame(e)
    }
}

impl From<RecordError> for LinkError {
    fn from(e: RecordError) -> Self {
        LinkError::Record(e)
    }
}

impl From<HandshakeError> for LinkError {
    fn from(e: HandshakeError) -> Self {
        LinkError::Handshake(e)
    }
}

impl From<DialError> for LinkError {
    fn from(e: DialError) -> Self {
        LinkError::Dial(e.to_string())
    }
}

/// What a link is dialed with: the station to reach, the node's identity
/// key, the statement issuer that holds its CONNECT key and statements, and
/// the realm membership endorsement to present, empty for none. Links of one
/// node share their publication seq, admission and dedup; a link given none
/// makes its own.
pub struct Config {
    pub target: Target,
    pub identity: Arc<NodeKey>,
    pub issuer: StatementIssuer,
    pub member_endorsement: Vec<u8>,
    pub publication_seq: Option<Arc<PublicationSeq>>,
    pub admission: Option<Arc<Admission>>,
    pub dedup: Option<Arc<EventDedup>>,
    /// This link's place in the admission: the station it dialed, host:port,
    /// when `None`.
    pub share: Option<String>,
    /// This identity's KEM keys (macula 13, E2E design amendment A1): with
    /// them the link opens sealed requests; without them it refuses them,
    /// holding no key. Links of one identity share one.
    pub keyring: Option<Arc<Keyring>>,
    /// Names the keyring's current key in the advertisements of procedures
    /// served confidentially ([`Confidentiality::Preferred`] or
    /// [`Confidentiality::Required`]). Off by default: switch it on only once
    /// every station runs macula 12.11 or later, which stores and routes a
    /// keyed advertisement, and every caller runs 13. It needs a keyring.
    pub kem_advertise: bool,
}

impl Config {
    /// A link's configuration with none of the shared parts.
    pub fn new(target: Target, identity: Arc<NodeKey>, issuer: StatementIssuer) -> Config {
        Config {
            target,
            identity,
            issuer,
            member_endorsement: Vec::new(),
            publication_seq: None,
            admission: None,
            dedup: None,
            share: None,
            keyring: None,
            kem_advertise: false,
        }
    }
}

/// A handshaked link to one station. Cloning it shares the link.
#[derive(Clone)]
pub struct Link {
    inner: Arc<Inner>,
}

struct Inner {
    /// Distinct for every link a process dials.
    serial: u64,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    control: FrameWriter,
    profile: Profile,
    key: Arc<NodeKey>,
    self_id: [u8; 32],
    station: Station,
    station_capabilities: u64,
    /// Liveness answers, for the probe.
    pongs: tokio::sync::mpsc::Sender<[u8; frame::LIVENESS_NONCE_SIZE]>,
    /// A liveness_pong is being written (macula-rust#9): at most one is in
    /// flight, so a station's pings cannot pile up tasks on this link.
    pong_in_flight: AtomicBool,
    pongs_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<[u8; frame::LIVENESS_NONCE_SIZE]>>,
    status_deadline: AtomicI64,
    publication_seq: Arc<PublicationSeq>,
    admission: Arc<Admission>,
    dedup: Arc<EventDedup>,
    share: String,
    keyring: Option<Arc<Keyring>>,
    kem_advertise: bool,
    state: Mutex<State>,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
}

struct State {
    ended: Option<LinkError>,
    /// The owner is closing the link: however it then ends, it ends
    /// [`LinkError::Closed`].
    closing: bool,
    unrouted: HashMap<String, u64>,
    pending: HashMap<[u8; 16], call::Pending>,
    subs: HashMap<([u8; 32], String), Vec<pubsub::SubscriberSlot>>,
    served: HashMap<([u8; 32], String), serve::ServedEntry>,
    streams: Vec<std::sync::Weak<stream::StreamInner>>,
}

impl Link {
    /// Dials `cfg.target`, runs the handshake as a client, and returns the
    /// link once the station's HELLO accepts it, within
    /// [`HANDSHAKE_TIMEOUT`].
    pub async fn dial(cfg: Config) -> Result<Link, LinkError> {
        if cfg.identity.profile() != cfg.target.profile {
            return Err(LinkError::InvalidConfig(
                "the identity key is of another profile than the target's".into(),
            ));
        }
        if let Some(admission) = &cfg.admission {
            admission.limits().validate()?;
        }
        if cfg
            .keyring
            .as_ref()
            .is_some_and(|k| k.profile() != cfg.target.profile)
        {
            return Err(LinkError::InvalidConfig(
                "the keyring is of another profile than the target's".into(),
            ));
        }
        if cfg.kem_advertise && cfg.keyring.is_none() {
            return Err(LinkError::InvalidConfig(
                "kem_advertise names a key: it needs a keyring".into(),
            ));
        }
        dial_once(&cfg, VERSION_5).await
    }

    /// The handshake version the link completed.
    pub fn handshake_version(&self) -> i64 {
        self.inner.station.version
    }

    /// The node_id of the station the link reached.
    pub fn station_node_id(&self) -> [u8; 32] {
        self.inner.station.node_id
    }

    /// A number distinct for every link this process dials.
    pub fn serial(&self) -> u64 {
        self.inner.serial
    }

    /// The node_id this link connected as.
    pub fn node_id(&self) -> [u8; 32] {
        self.inner.self_id
    }

    /// The capability bits the station's HELLO announced.
    pub fn station_capabilities(&self) -> u64 {
        self.inner.station_capabilities
    }

    /// The profile the link runs.
    pub fn profile(&self) -> Profile {
        self.inner.profile
    }

    /// Why the link ended, or `None` while it runs.
    pub fn error(&self) -> Option<LinkError> {
        self.inner.lock().ended.clone()
    }

    /// Waits until the link has ended, and says why.
    pub async fn done(&self) -> LinkError {
        let mut done = self.inner.done_rx.clone();
        let _ = done.wait_for(|ended| *ended).await;
        self.error().unwrap_or(LinkError::Closed)
    }

    /// The frames received that nothing on this link handles, by what they
    /// were.
    pub fn unrouted(&self) -> HashMap<String, u64> {
        self.inner.lock().unrouted.clone()
    }

    /// Sends a GOODBYE with `reason`, closes the control stream's sending
    /// side, waits up to a second for the station to close the connection,
    /// and ends the link. Closing an ended link does nothing.
    pub async fn close(&self, reason: &str) -> Result<(), LinkError> {
        if !self.inner.mark_closing() {
            return Ok(());
        }
        let goodbye = frame::goodbye_frame(reason, None)?;
        let sent = self.inner.send_control(&goodbye).await;
        if sent.is_ok() {
            self.inner.control.finish().await;
            let _ = tokio::time::timeout(CLOSE_LINGER, self.inner.connection.closed()).await;
        }
        self.inner.end(LinkError::Closed);
        sent
    }
}

/// One QUIC connection and one handshake in `version`, within
/// [`HANDSHAKE_TIMEOUT`]. A failed handshake closes its connection.
async fn dial_once(cfg: &Config, version: i64) -> Result<Link, LinkError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let dialed = transport::dial_target(&cfg.target).await?;
        let connection = dialed.connection.clone();
        let linked = handshaken(cfg, dialed, version).await;
        if let Err(e) = &linked {
            versions::count_refusal(e);
            connection.close(0u32.into(), b"handshake failed");
        }
        linked
    })
    .await
    .map_err(|_| LinkError::HandshakeTimeout)
    .and_then(|linked| linked)
}

/// Runs the client's side of the handshake, in `version`, on a new control
/// stream of `dialed`.
async fn handshaken(
    cfg: &Config,
    dialed: transport::Dialed,
    version: i64,
) -> Result<Link, LinkError> {
    let export = keying_exporter(dialed.connection.clone());
    let export: &Exporter = &export;
    let (send, mut recv) = dialed
        .connection
        .open_bi()
        .await
        .map_err(|e| LinkError::Io(format!("open the control stream: {e}")))?;
    let control = FrameWriter::new(send);
    control
        .write(&handshake::opener(), HANDSHAKE_FRAME_BYTES)
        .await?;
    let challenge = read_frame(&mut recv, HANDSHAKE_FRAME_BYTES).await?;
    let material = cfg.issuer.connect_material().map_err(LinkError::Issuer)?;
    let (connect, station) = handshake::answer_challenge(
        &challenge,
        &client_session(cfg, &dialed.leaf, &material, version, export),
    )?;
    control.write(&connect, HANDSHAKE_FRAME_BYTES).await?;
    let hello = read_frame(&mut recv, HANDSHAKE_FRAME_BYTES).await?;
    let capabilities = handshake::read_hello(&hello, &station)?;
    let self_id = cfg
        .identity
        .node_id()
        .map_err(|e| LinkError::InvalidConfig(e.to_string()))?;
    let statements = cfg
        .issuer
        .subscribe(&material.binding)
        .map_err(LinkError::Issuer)?;
    let inner = new_inner(cfg, dialed, control, station, capabilities, self_id);
    spawn_link_tasks(&inner, statements, recv);
    Ok(Link { inner })
}

/// The TLS exporter of `connection`, as the v5 handshake asks for keying
/// material.
fn keying_exporter(
    connection: quinn::Connection,
) -> impl Fn(&str, &[u8], usize) -> Option<Vec<u8>> + Send + Sync {
    move |label: &str, context: &[u8], length: usize| {
        let mut out = vec![0; length];
        connection
            .export_keying_material(&mut out, label.as_bytes(), context)
            .ok()?;
        Some(out)
    }
}

/// What the client brings to the handshake in `version`: the configured
/// identity and target, the leaf it received, and the issuer's CONNECT
/// material, at the time now.
fn client_session<'a>(
    cfg: &Config,
    leaf: &'a [u8],
    material: &'a ConnectMaterial,
    version: i64,
    export: &'a Exporter,
) -> ClientSession<'a> {
    ClientSession {
        profile: cfg.target.profile,
        expected_node_id: cfg.target.expected_node_id,
        leaf,
        identity_key: cfg.identity.public_key(),
        connect_key: &material.key,
        connect_binding: &material.binding,
        connect_status: &material.status,
        capabilities: 0,
        now_ms: now_ms(),
        member_endorsement: cfg.member_endorsement.clone(),
        version,
        export: Some(export),
    }
}

/// The state of a link whose handshake completed with `station` on the
/// control stream `control` of `dialed`, numbered with the next serial.
fn new_inner(
    cfg: &Config,
    dialed: transport::Dialed,
    control: FrameWriter,
    station: Station,
    capabilities: u64,
    self_id: [u8; 32],
) -> Arc<Inner> {
    let (done_tx, done_rx) = watch::channel(false);
    let share = cfg
        .share
        .clone()
        .unwrap_or_else(|| format!("{}:{}", cfg.target.host, cfg.target.port));
    let (pongs, pongs_rx) = tokio::sync::mpsc::channel(1);
    static SERIALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    Arc::new(Inner {
        serial: SERIALS.fetch_add(1, Ordering::Relaxed),
        connection: dialed.connection,
        _endpoint: dialed.endpoint,
        control,
        profile: cfg.target.profile,
        key: cfg.identity.clone(),
        self_id,
        status_deadline: AtomicI64::new(station.status_expires_at + STATUS_GRACE_MS),
        station_capabilities: capabilities,
        pongs,
        pong_in_flight: AtomicBool::new(false),
        pongs_rx: tokio::sync::Mutex::new(pongs_rx),
        station,
        publication_seq: cfg.publication_seq.clone().unwrap_or_default(),
        admission: cfg
            .admission
            .clone()
            .unwrap_or_else(|| Arc::new(Admission::new(AdmissionLimits::default()))),
        dedup: cfg.dedup.clone().unwrap_or_default(),
        share,
        keyring: cfg.keyring.clone(),
        kem_advertise: cfg.kem_advertise,
        state: Mutex::new(State {
            ended: None,
            closing: false,
            unrouted: HashMap::new(),
            pending: HashMap::new(),
            subs: HashMap::new(),
            served: HashMap::new(),
            streams: Vec::new(),
        }),
        done_tx,
        done_rx,
    })
}

/// Starts the tasks a linked link runs: its statements, its control
/// stream's reader, the streams it accepts, its liveness probe, and the
/// watches on its expiries and its connection.
fn spawn_link_tasks(
    inner: &Arc<Inner>,
    statements: StatementSubscription,
    recv: quinn::RecvStream,
) {
    tokio::spawn(send_statements(Arc::downgrade(inner), statements));
    tokio::spawn(read_control(inner.clone(), recv));
    tokio::spawn(stream::accept_streams(Arc::downgrade(inner)));
    tokio::spawn(call::probe(Arc::downgrade(inner)));
    tokio::spawn(watch_expiries(Arc::downgrade(inner)));
    tokio::spawn(watch_connection(Arc::downgrade(inner)));
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn count(&self, what: &str) {
        *self.lock().unrouted.entry(what.to_string()).or_default() += 1;
    }

    /// Marks the link closing, so it ends as closed: false when it has
    /// already ended.
    fn mark_closing(&self) -> bool {
        let mut state = self.lock();
        if state.ended.is_some() {
            return false;
        }
        state.closing = true;
        true
    }

    /// A frame on the control stream, as it is.
    async fn send_control(&self, v: &Value) -> Result<(), LinkError> {
        let encoded =
            cbor::encode(v).map_err(|e| LinkError::Frame(FrameError::Payload(e.to_string())))?;
        self.control.write(&encoded, MAX_FRAME_BYTES).await
    }

    /// Ends the link once, with `err`: pending calls, subscriptions, served
    /// procedures and streams end with it, and the connection closes.
    fn end(&self, err: LinkError) {
        let mut state = self.lock();
        let Some(err) = state.mark_ended(err) else {
            return;
        };
        let pending = std::mem::take(&mut state.pending);
        let subs = std::mem::take(&mut state.subs);
        let served = std::mem::take(&mut state.served);
        let streams = std::mem::take(&mut state.streams);
        drop(state);
        for (_, p) in pending {
            let _ = p.outcome.send(Err(err.clone()));
        }
        drop(subs);
        for s in served.into_values() {
            s.end(err.clone());
        }
        for s in streams.into_iter().filter_map(|w| w.upgrade()) {
            stream::StreamInner::end(&s, Some(err.clone()));
        }
        self.connection.close(0u32.into(), b"link ended");
        let _ = self.done_tx.send_replace(true);
    }
}

impl State {
    /// Marks the link ended once, with `err`, or as closed when its owner was
    /// closing it: the error it ended with, or `None` when it had already
    /// ended.
    fn mark_ended(&mut self, err: LinkError) -> Option<LinkError> {
        if self.ended.is_some() {
            return None;
        }
        let err = if self.closing { LinkError::Closed } else { err };
        self.ended = Some(err.clone());
        Some(err)
    }
}

/// Sends each statement the issuer reissues as a STATUS, until the link
/// ends. A STATUS carries no neighbour signature and takes no seq.
async fn send_statements(link: std::sync::Weak<Inner>, mut statements: StatementSubscription) {
    loop {
        let Some(done) = link.upgrade().map(|l| l.done_rx.clone()) else {
            return;
        };
        let mut done = done;
        let statement = tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            statement = statements.recv() => statement,
        };
        let (Some(statement), Some(inner)) = (statement, link.upgrade()) else {
            return;
        };
        if let Err(e) = inner
            .control
            .write(&handshake::status_frame(&statement), MAX_FRAME_BYTES)
            .await
        {
            inner.end(e);
            return;
        }
    }
}

/// The frame types the link acts on from the station's control stream; any
/// other is read past, counted.
const CONTROL_FRAME_TYPES: &[&str] = &[
    "status",
    "liveness_ping",
    "liveness_pong",
    "event",
    "result",
    "error",
    "call",
    "goodbye",
    "register_ack",
];

/// Reads the station's frames until the link ends.
async fn read_control(inner: Arc<Inner>, mut recv: quinn::RecvStream) {
    let mut done = inner.done_rx.clone();
    loop {
        let payload = tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            payload = read_frame(&mut recv, MAX_FRAME_BYTES) => payload,
        };
        let outcome = match payload {
            Ok(payload) => received(&inner, &payload),
            Err(e) => Err(e),
        };
        if let Err(e) = outcome {
            inner.end(e);
            return;
        }
    }
}

/// A frame from the station's control stream as wire 1.0 reads it
/// (WIRE_1_0.md section 3): its envelope, and the frame through its type's
/// table when it is a control frame; `None` for a type the link does not act
/// on, counted as `wire_unknown_frame_type`.
fn control_frame(payload: &[u8]) -> Result<Option<Envelope>, FrameError> {
    let v = cbor::decode(payload).map_err(|_| FrameError::Malformed)?;
    let envelope = frame::read_envelope(&v)?;
    if frame::unknown_frame_type(&envelope, CONTROL_FRAME_TYPES).is_some() {
        return Ok(None);
    }
    if frame::is_control_frame(&envelope.frame_type) {
        frame::read_control(&envelope.frame)?;
    }
    Ok(Some(envelope))
}

/// One frame from the station, read by [`control_frame`]: one of a type the
/// link does not act on, or with an unknown critical extension, is dropped
/// and counted with the link left up; one that does not read ends the link.
/// Then a STATUS renews the station's statement, a liveness frame is
/// answered or handed to the probe, and a GOODBYE ends the link.
fn received(inner: &Arc<Inner>, payload: &[u8]) -> Result<(), LinkError> {
    let envelope = match control_frame(payload) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            inner.count("unknown_frame_type");
            return Ok(());
        }
        Err(FrameError::ExtensionUnsupported(_)) => {
            inner.count("extension_unsupported");
            return Ok(());
        }
        Err(e) => return Err(LinkError::Frame(e)),
    };
    let v = envelope.frame;
    match envelope.frame_type.as_str() {
        "status" => {
            let expires_at = handshake::read_status(
                payload,
                &Peer {
                    profile: inner.profile,
                    identity_key: inner.station.identity_key.clone(),
                    binding: inner.station.tls_binding.clone(),
                    now_ms: now_ms(),
                },
            )?;
            inner
                .status_deadline
                .store(expires_at + STATUS_GRACE_MS, Ordering::SeqCst);
        }
        "liveness_ping" | "liveness_pong" => {
            if let Some((kind, nonce)) = frame::liveness_nonce(&v) {
                return liveness(inner, kind, nonce);
            }
        }
        "event" => pubsub::evented(inner, &v),
        "result" | "error" => call::replied(inner, &v),
        "call" => serve::called(inner, &v),
        "register_ack" => registered(inner, &v)?,
        "goodbye" => {
            let reason = match v.get("reason") {
                Some(Value::Text(r)) => r.clone(),
                _ => String::new(),
            };
            return Err(LinkError::Goodbye(reason));
        }
        other => inner.count(other),
    }
    Ok(())
}

/// The station's REGISTER_ACK: a refused ADVERTISE of the served
/// procedure's current record ends that serving, a refused SUBSCRIBE ends the
/// subscription, and every ack is counted by its kind and outcome. One of a
/// kind this crate does not know is read past, counted.
fn registered(inner: &Arc<Inner>, v: &Value) -> Result<(), LinkError> {
    let Some(ack) = frame::read_register_ack(v)? else {
        inner.count("register_ack_unknown_kind");
        return Ok(());
    };
    let outcome = ack.refusal.as_deref().unwrap_or("accepted");
    inner.count(&format!("register_ack_{:?}_{outcome}", ack.kind).to_lowercase());
    let Some(reason) = ack.refusal.clone() else {
        return Ok(());
    };
    let refused = LinkError::RegisterRefused {
        kind: ack.kind,
        reason,
    };
    match (ack.kind, &ack.answered) {
        (frame::RegisterKind::Advertise, frame::Answered::Advertisement { record_version }) => {
            serve::advertise_refused(
                inner,
                &(ack.realm, ack.name.clone()),
                record_version,
                refused,
            )
        }
        (frame::RegisterKind::Subscribe, _) => {
            pubsub::subscribe_refused(inner, &(ack.realm, ack.name.clone()))
        }
        _ => {}
    }
    Ok(())
}

/// Answers the station's liveness_ping with a liveness_pong of the same
/// nonce, and hands a liveness_pong to the probe. Neither goes further.
fn liveness(
    inner: &Arc<Inner>,
    kind: Liveness,
    nonce: [u8; frame::LIVENESS_NONCE_SIZE],
) -> Result<(), LinkError> {
    match kind {
        // A ping while a pong is still being written is not answered again:
        // the station's probe needs one answer per interval, not one per
        // ping, and a burst of pings starts one task, not one each.
        Liveness::Ping if !pong_slot(&inner.pong_in_flight) => {}
        Liveness::Ping => {
            tokio::spawn(send_pong(inner.clone(), nonce));
        }
        Liveness::Pong => {
            let _ = inner.pongs.try_send(nonce);
        }
    }
    Ok(())
}

/// Writes the liveness_pong of `nonce`, gives back the pong slot, and ends
/// the link when the write failed.
async fn send_pong(inner: Arc<Inner>, nonce: [u8; frame::LIVENESS_NONCE_SIZE]) {
    let sent = inner
        .send_control(&frame::liveness_pong_frame(&nonce))
        .await;
    inner.pong_in_flight.store(false, Ordering::Release);
    if let Err(e) = sent {
        inner.end(e);
    }
}

/// Takes the one pong slot: true when no pong was in flight, and it is now.
fn pong_slot(in_flight: &AtomicBool) -> bool {
    !in_flight.swap(true, Ordering::AcqRel)
}

/// Ends the link when the station's statement lapses past the grace, or its
/// TLS binding reaches its not_after.
async fn watch_expiries(link: std::sync::Weak<Inner>) {
    loop {
        let Some(inner) = link.upgrade() else { return };
        let now = now_ms();
        if now >= inner.station.binding_not_after {
            inner.end(LinkError::BindingExpired);
            return;
        }
        let status_deadline = inner.status_deadline.load(Ordering::SeqCst);
        if now >= status_deadline {
            inner.end(LinkError::StatusExpired);
            return;
        }
        let wait = (status_deadline.min(inner.station.binding_not_after) - now).clamp(1, 60_000);
        let mut done = inner.done_rx.clone();
        drop(inner);
        tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            _ = tokio::time::sleep(Duration::from_millis(wait as u64)) => {}
        }
    }
}

/// Ends the link when its QUIC connection closes.
async fn watch_connection(link: std::sync::Weak<Inner>) {
    let Some(connection) = link.upgrade().map(|l| l.connection.clone()) else {
        return;
    };
    let cause = connection.closed().await;
    if let Some(inner) = link.upgrade() {
        inner.end(LinkError::Io(cause.to_string()));
    }
}

fn now_ms() -> i64 {
    crate::uuid_v7::now_ms() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// macula-rust#9: a burst of pings takes one pong slot until its pong is
    /// written.
    #[test]
    fn a_burst_of_pings_starts_one_pong_at_a_time() {
        let in_flight = AtomicBool::new(false);
        let taken = (0..1000).filter(|_| pong_slot(&in_flight)).count();
        assert_eq!(taken, 1);
        in_flight.store(false, Ordering::Release);
        assert!(pong_slot(&in_flight), "free again once the pong is written");
    }

    /// The wire 1.0 envelope vectors (macula#99): what the link does with each
    /// frame after HELLO, on the control stream or a dedicated stream, and
    /// with a length header alone.
    #[test]
    fn the_wire_1_0_envelope_vectors() {
        let file = crate::wire_vectors::load("envelope");
        for c in &file.cases {
            let before = frame::wire_counters();
            let (outcome, reason, quic_code) = envelope_verdict(c);
            let after = frame::wire_counters();
            assert_eq!((outcome, reason), (c.outcome(), c.reason()), "{}", c.id);
            let code = c.expect_int("quic_code");
            assert!(
                code.is_none() || code == quic_code.map(i64::from),
                "{}",
                c.id
            );
            assert!(
                counted(c.expect_text("count"), &before, &after),
                "{}: not counted",
                c.id
            );
        }
    }

    /// Whether the counter a case names went up; a case that names none
    /// passes.
    fn counted(name: &str, before: &frame::WireCounts, after: &frame::WireCounts) -> bool {
        let ext = |w: &frame::WireCounts| w.ext_ignored.values().sum::<u64>();
        match name {
            "wire_unknown_frame_type" => after.unknown_frame_type > before.unknown_frame_type,
            "wire_ext_ignored" => ext(after) > ext(before),
            "wire_ext_refused" => {
                let refused = |w: &frame::WireCounts| w.ext_refused.values().sum::<u64>();
                refused(after) > refused(before)
            }
            _ => true,
        }
    }

    /// The link's verdict on one envelope case, in the vectors' terms.
    fn envelope_verdict(
        c: &crate::wire_vectors::Case,
    ) -> (&'static str, &'static str, Option<u32>) {
        if c.has("length_header") {
            let length = u32::from_be_bytes(c.hex("length_header").try_into().unwrap());
            return match framing::length_within(length as usize, MAX_FRAME_BYTES) {
                Ok(()) => ("accept", "", None),
                Err(_) => ("refuse", "frame_too_large", None),
            };
        }
        let payload = c.hex("frame");
        if c.text("position") == "dedicated_stream" {
            return match stream::unknown_on_stream(&payload) {
                Some(code) => ("abort_stream", "", Some(code)),
                None => ("accept", "", None),
            };
        }
        match control_frame(&payload) {
            Ok(Some(_)) => ("accept", "", None),
            Ok(None) => ("ignore", "", None),
            Err(FrameError::ExtensionUnsupported(_)) => ("refuse", "extension_unsupported", None),
            Err(_) => ("refuse", "malformed_frame", None),
        }
    }
}
