//! A client's link to one macula station, as macula_station_link and
//! macula-go's stationlink are: a QUIC connection dialed to the station its
//! target pins, one bidirectional control stream, the connection handshake on
//! it (v5, or v4 once after a station refuses v5), then status statements
//! both ways and every frame of the session.
//!
//! After HELLO the link sends its own status statement at every reissue of
//! the node's statement issuer, and ends when the station's statement is five
//! minutes past its expiry or the station's TLS binding reaches its
//! not_after. On a v5 link no frame carries a neighbour signature: the
//! session proofs authenticated the station once, and a neighbour-signed
//! frame ends the link. On a v4 link, in pq_hybrid, every control frame is
//! neighbour-signed with a sequence number per direction, from 0 after HELLO;
//! a frame out of sequence ends the link. A liveness probe every 30 seconds
//! ends the link after two misses in a row: on v5 a liveness_ping, on v4 a
//! `_macula.ping` call.

mod admission;
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
pub use stream::{
    stream_handler, Stream, StreamCall, StreamEvent, StreamHandler, DEFAULT_STREAM_DEADLINE,
};
pub use versions::{forget_v5_peer, handshake_counters};

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sha2::{Digest, Sha384};
use tokio::sync::watch;

use crate::cbor::{self, Value};
use crate::frame::{self, FrameError, Liveness, NeighbourLink, NeighbourPeer};
use crate::handshake::{
    self, ClientSession, Exporter, HandshakeError, Peer, RefusalCode, Station, VERSION, VERSION_5,
};
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
    /// A station this process completed handshake v5 with that now answers
    /// v4, or a v4 link to it that a v5 completion ended: refused, not
    /// retried, until [`forget_v5_peer`].
    V5DowngradeRefused,
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
    connection_hash: [u8; 48],
    /// The handshake version the link completed: 4 or 5.
    version: i64,
    /// v5 liveness answers, for the probe.
    pongs: tokio::sync::mpsc::Sender<[u8; frame::LIVENESS_NONCE_SIZE]>,
    /// A liveness_pong is being written (macula-rust#9): at most one is in
    /// flight, so a station's pings cannot pile up tasks on this link.
    pong_in_flight: AtomicBool,
    pongs_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<[u8; frame::LIVENESS_NONCE_SIZE]>>,
    /// Orders a neighbour signature's seq with its write.
    send_seq: tokio::sync::Mutex<u64>,
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
    /// link once the station's HELLO accepts it. It dials with version 5
    /// unless the station refused v5 in the last 10 minutes; a station never
    /// seen on v5 that refuses v5 with `unsupported_version` is dialled once
    /// more, on a new connection, with v4. A station seen on v5 that answers
    /// v4 is [`LinkError::V5DowngradeRefused`]. Each handshake is bounded by
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
        let node_id = cfg.target.expected_node_id;
        let version = versions::dial_version(&node_id, std::time::Instant::now());
        let linked = dial_once(&cfg, version).await;
        let v5_refused = matches!(
            linked,
            Err(LinkError::Handshake(HandshakeError::Refused(
                RefusalCode::UnsupportedVersion
            )))
        ) && version == VERSION_5;
        if !v5_refused {
            return linked;
        }
        if !versions::unsupported_version(&node_id, std::time::Instant::now()) {
            return Err(LinkError::V5DowngradeRefused);
        }
        dial_once(&cfg, VERSION).await
    }

    /// The handshake version the link completed: 4 or 5.
    pub fn handshake_version(&self) -> i64 {
        self.inner.version
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
    let inner = new_inner(
        cfg,
        dialed,
        control,
        station,
        capabilities,
        &challenge,
        self_id,
    );
    let station_node_id = inner.station.node_id;
    versions::completed(&station_node_id, &inner)?;
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
    challenge: &[u8],
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
        connection_hash: Sha384::digest(challenge).into(),
        version: station.version,
        pongs,
        pong_in_flight: AtomicBool::new(false),
        pongs_rx: tokio::sync::Mutex::new(pongs_rx),
        station,
        send_seq: tokio::sync::Mutex::new(0),
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

    /// A version-2 frame on the control stream: on v5 as it is, on v4
    /// neighbour-signed with the next seq when the profile signs its type.
    async fn send_control(&self, v: &Value) -> Result<(), LinkError> {
        if self.version == VERSION_5 {
            return self.write_control(v).await;
        }
        let mut seq = self.send_seq.lock().await;
        let signed = frame::sign_neighbour(
            v,
            &self.key,
            &NeighbourLink {
                connection: self.connection_hash,
                seq: *seq,
            },
        )?;
        if frame::neighbour_signed(self.profile, &frame_type_of(v)) {
            *seq += 1;
        }
        self.write_control(&signed).await
    }

    /// A frame on the control stream as it is: a data frame, which carries
    /// its own end-to-end signature and no neighbour signature.
    async fn write_control(&self, v: &Value) -> Result<(), LinkError> {
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
        if self.version == VERSION {
            versions::v4_ended(&self.station.node_id, self.serial);
        }
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

/// Reads the station's frames until the link ends.
async fn read_control(inner: Arc<Inner>, mut recv: quinn::RecvStream) {
    let mut recv_seq = 0u64;
    let mut done = inner.done_rx.clone();
    loop {
        let payload = tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            payload = read_frame(&mut recv, MAX_FRAME_BYTES) => payload,
        };
        let outcome = match payload {
            Ok(payload) => received(&inner, &payload, &mut recv_seq),
            Err(e) => Err(e),
        };
        if let Err(e) = outcome {
            inner.end(e);
            return;
        }
    }
}

/// One frame from the station: a STATUS renews the station's statement, a
/// liveness frame is answered or handed to the probe, every other frame is
/// opened (on v4 from its neighbour signature at the next seq), and a GOODBYE
/// ends the link.
fn received(inner: &Arc<Inner>, payload: &[u8], recv_seq: &mut u64) -> Result<(), LinkError> {
    let v = cbor::decode(payload).map_err(|_| LinkError::Frame(FrameError::Malformed))?;
    let frame_type = frame_type_of(&v);
    if frame_type == "status" {
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
        return Ok(());
    }
    if let Some((kind, nonce)) = liveness_frame(inner.version, &v)? {
        return liveness(inner, kind, nonce);
    }
    let opened = opened(inner, &v, &frame_type, recv_seq)?;
    match frame_type.as_str() {
        "event" => pubsub::evented(inner, &opened),
        "result" | "error" => call::replied(inner, &opened),
        "call" => serve::called(inner, &opened),
        "goodbye" => {
            let reason = match opened.get("reason") {
                Some(Value::Text(r)) => r.clone(),
                _ => String::new(),
            };
            return Err(LinkError::Goodbye(reason));
        }
        _ => inner.count(&frame_type),
    }
    Ok(())
}

/// A received frame as the link reads it: on v5 with no neighbour signature,
/// on v4 opened from its neighbour signature at the next seq.
fn opened(
    inner: &Inner,
    v: &Value,
    frame_type: &str,
    recv_seq: &mut u64,
) -> Result<Value, LinkError> {
    if inner.version == VERSION_5 {
        return Ok(frame::verify_session_frame(v)?);
    }
    let opened = frame::verify_neighbour(
        v,
        &NeighbourPeer {
            profile: inner.profile,
            peer_key: inner.station.identity_key.clone(),
            connection: inner.connection_hash,
            seq: *recv_seq,
        },
    )?;
    if frame::neighbour_signed(inner.profile, frame_type) {
        *recv_seq += 1;
    }
    Ok(opened)
}

/// A liveness frame as a link of `version` reads it: its kind and nonce, or
/// `None` for any other frame. It exists only on v5, and there it is read as
/// every v5 frame is, so one that carries a neighbour signature ends the link
/// as malformed, as on v4 any liveness frame does.
fn liveness_frame(
    version: i64,
    v: &Value,
) -> Result<Option<(Liveness, [u8; frame::LIVENESS_NONCE_SIZE])>, LinkError> {
    let Some(found) = frame::liveness_nonce(v) else {
        return Ok(None);
    };
    if version != VERSION_5 {
        return Err(LinkError::Frame(FrameError::Malformed));
    }
    frame::verify_session_frame(v)?;
    Ok(Some(found))
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

fn frame_type_of(v: &Value) -> String {
    match v.get("frame_type") {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    }
}

fn now_ms() -> i64 {
    crate::uuid_v7::now_ms() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_neighbour(v: Value) -> Value {
        let Value::Map(mut pairs) = v else {
            panic!("a frame is a map");
        };
        pairs.push((Value::text("neighbour"), Value::Map(Vec::new())));
        Value::Map(pairs)
    }

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

    /// macula-go 2294f25: liveness frames are read after the session-mode
    /// check, so a neighbour-signed one ends a v5 link.
    #[test]
    fn a_liveness_frame_is_read_as_every_v5_frame_and_exists_only_on_v5() {
        let nonce = [9; frame::LIVENESS_NONCE_SIZE];
        let ping = frame::liveness_ping_frame(&nonce);
        let pong = frame::liveness_pong_frame(&nonce);
        assert_eq!(
            liveness_frame(VERSION_5, &ping),
            Ok(Some((Liveness::Ping, nonce)))
        );
        assert_eq!(
            liveness_frame(VERSION_5, &pong),
            Ok(Some((Liveness::Pong, nonce)))
        );
        for signed in [with_neighbour(ping.clone()), with_neighbour(pong.clone())] {
            assert_eq!(
                liveness_frame(VERSION_5, &signed),
                Err(LinkError::Frame(FrameError::Malformed))
            );
        }
        assert_eq!(
            liveness_frame(VERSION, &ping),
            Err(LinkError::Frame(FrameError::Malformed))
        );
        let goodbye = frame::goodbye_frame("bye", None).unwrap();
        assert_eq!(liveness_frame(VERSION_5, &goodbye), Ok(None));
    }
}
