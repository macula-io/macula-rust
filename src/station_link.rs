//! A client's link to one macula 12 station, as macula_station_link and
//! macula-go's stationlink are: a QUIC connection dialed to the station its
//! target pins, one bidirectional control stream, the v4 handshake on it, then
//! status statements both ways and every frame of the session.
//!
//! After HELLO the link sends its own status statement at every reissue of
//! the node's statement issuer, and ends when the station's statement is five
//! minutes past its expiry or the station's TLS binding reaches its
//! not_after. In pq_hybrid every control frame is neighbour-signed with a
//! sequence number per direction, from 0 after HELLO; a frame out of sequence
//! ends the link. A liveness probe, a `_macula.ping` call every 30 seconds,
//! ends the link after two misses in a row.

mod admission;
mod call;
mod dht;
mod framing;
mod pubsub;
mod serve;
mod stream;

pub use admission::{Admission, AdmissionLimits};
pub use call::{Call, DEFAULT_CALL_TIMEOUT, MAX_CALL_TIMEOUT};
pub use pubsub::{Event, EventDedup, Publication, PublicationSeq, SignedPublication, Subscription};
pub use serve::{handler, BoxFuture, Handler, Offer, Request, Served, StreamOffer};
pub use stream::{
    stream_handler, Stream, StreamCall, StreamEvent, StreamHandler, DEFAULT_STREAM_DEADLINE,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sha2::{Digest, Sha384};
use tokio::sync::watch;

use crate::cbor::{self, Value};
use crate::frame::{self, FrameError, NeighbourLink, NeighbourPeer};
use crate::handshake::{self, ClientSession, HandshakeError, Peer, Station};
use crate::node_key::NodeKey;
use crate::profile::Profile;
use crate::record::RecordError;
use crate::statement_issuer::{IssuerError, StatementIssuer, StatementSubscription};
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
    /// Orders a neighbour signature's seq with its write.
    send_seq: tokio::sync::Mutex<u64>,
    status_deadline: AtomicI64,
    publication_seq: Arc<PublicationSeq>,
    admission: Arc<Admission>,
    dedup: Arc<EventDedup>,
    share: String,
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
    /// Dials `cfg.target`, runs the v4 handshake as a client, and returns the
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
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshaken(cfg))
            .await
            .map_err(|_| LinkError::HandshakeTimeout)
            .and_then(|linked| linked)
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
        {
            let mut state = self.inner.lock();
            if state.ended.is_some() {
                return Ok(());
            }
            state.closing = true;
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

async fn handshaken(cfg: Config) -> Result<Link, LinkError> {
    let dialed = transport::dial_target(&cfg.target).await?;
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
        &ClientSession {
            profile: cfg.target.profile,
            expected_node_id: cfg.target.expected_node_id,
            leaf: &dialed.leaf,
            identity_key: cfg.identity.public_key(),
            connect_key: &material.key,
            connect_binding: &material.binding,
            connect_status: &material.status,
            capabilities: 0,
            now_ms: now_ms(),
            member_endorsement: cfg.member_endorsement.clone(),
        },
    )?;
    control.write(&connect, HANDSHAKE_FRAME_BYTES).await?;
    let hello = read_frame(&mut recv, HANDSHAKE_FRAME_BYTES).await?;
    let capabilities = handshake::read_hello(&hello)?;
    let self_id = cfg
        .identity
        .node_id()
        .map_err(|e| LinkError::InvalidConfig(e.to_string()))?;
    let statements = cfg
        .issuer
        .subscribe(&material.binding)
        .map_err(LinkError::Issuer)?;
    let (done_tx, done_rx) = watch::channel(false);
    let share = cfg
        .share
        .unwrap_or_else(|| format!("{}:{}", cfg.target.host, cfg.target.port));
    static SERIALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let inner = Arc::new(Inner {
        serial: SERIALS.fetch_add(1, Ordering::Relaxed),
        connection: dialed.connection,
        _endpoint: dialed.endpoint,
        control,
        profile: cfg.target.profile,
        key: cfg.identity,
        self_id,
        status_deadline: AtomicI64::new(station.status_expires_at + STATUS_GRACE_MS),
        station_capabilities: capabilities,
        connection_hash: Sha384::digest(&challenge).into(),
        station,
        send_seq: tokio::sync::Mutex::new(0),
        publication_seq: cfg.publication_seq.unwrap_or_default(),
        admission: cfg
            .admission
            .unwrap_or_else(|| Arc::new(Admission::new(AdmissionLimits::default()))),
        dedup: cfg.dedup.unwrap_or_default(),
        share,
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
    });
    tokio::spawn(send_statements(Arc::downgrade(&inner), statements));
    tokio::spawn(read_control(inner.clone(), recv));
    tokio::spawn(stream::accept_streams(Arc::downgrade(&inner)));
    tokio::spawn(call::probe(Arc::downgrade(&inner)));
    tokio::spawn(watch_expiries(Arc::downgrade(&inner)));
    tokio::spawn(watch_connection(Arc::downgrade(&inner)));
    Ok(Link { inner })
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

    /// A version-2 frame on the control stream, neighbour-signed with the
    /// next seq when the profile signs its type.
    async fn send_control(&self, v: &Value) -> Result<(), LinkError> {
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
        let (err, pending, subs, served, streams) = {
            let mut state = self.lock();
            if state.ended.is_some() {
                return;
            }
            let err = if state.closing {
                LinkError::Closed
            } else {
                err
            };
            state.ended = Some(err.clone());
            (
                err,
                std::mem::take(&mut state.pending),
                std::mem::take(&mut state.subs),
                std::mem::take(&mut state.served),
                std::mem::take(&mut state.streams),
            )
        };
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

/// One frame from the station: a STATUS renews the station's statement,
/// every other frame is opened from its neighbour signature at the next seq,
/// and a GOODBYE ends the link.
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
    let opened = frame::verify_neighbour(
        &v,
        &NeighbourPeer {
            profile: inner.profile,
            peer_key: inner.station.identity_key.clone(),
            connection: inner.connection_hash,
            seq: *recv_seq,
        },
    )?;
    if frame::neighbour_signed(inner.profile, &frame_type) {
        *recv_seq += 1;
    }
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
