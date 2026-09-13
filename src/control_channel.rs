//! One session's control stream: a single reader that routes every frame,
//! and writers that take turns. [`Session`](crate::connection::Session) is
//! the public face of this; the machinery lives here.
//!
//! The reader hands a RESULT or ERROR to the call waiting on its `call_id`,
//! an EVENT to every subscription whose realm is the event's and whose topic
//! pattern matches it (the station's rule: both split on "/", equal segment
//! counts, and "*" matches exactly one whole segment), and a CALL signed by
//! the caller it names to the inbound call queue. GOODBYE, HELLO or CONNECT
//! after the handshake, and a frame that can't be decoded end the session.
//! Any other frame is dropped and counted by type, with at most one log line
//! per type per minute.
//!
//! Writers take turns. Waiting for a turn is bounded by the caller's own
//! deadline: a call's timeout, and the send timeout for every other frame.
//! A write in progress is bounded by the send timeout, and one that stalls
//! past it ends the session. The reader never waits on a write: the frames a
//! session sends on its own account, the replies the reader makes and the
//! RPC telemetry facts, go to a writer of their own, and one is dropped when
//! 64 already wait there.
//!
//! When the session ends, every waiting call, every subscription, the
//! inbound call queue and every later operation report why, the end is
//! logged once with that reason and both node ids, and the session's
//! `on_ended` runs once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::bolt4;
use crate::cbor::Value;
use crate::frame::{self, CallInfo, CallResponse, CallSpec, Decoded, EventInfo, SubscribeSpec};
use crate::identity::KeyPair;
use drop_warning::{DropWarnings, Kind, Reason, Subject};

pub(crate) type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Runs once when a session ends, with why and whether it was closed here.
pub(crate) type OnEnded = Box<dyn FnOnce(&SessionEndReason, bool) + Send>;

/// How many events one subscription holds before it falls behind.
pub(crate) const EVENT_QUEUE_CAPACITY: usize = 256;
/// How many inbound CALLs wait to be served before an extra one is refused.
pub(crate) const CALL_QUEUE_CAPACITY: usize = 64;
/// How many frames a session's own writer holds before it drops one.
pub(crate) const HAND_OFF_CAPACITY: usize = 64;
/// How long a send waits for its turn to write, and how long any write may
/// take before it ends the session.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(30);

const LOG_INTERVAL: Duration = Duration::from_secs(60);
const READ_CHUNK: usize = 64 * 1024;

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEndReason {
    /// The station sent GOODBYE.
    Goodbye {
        reason: String,
        detail: Option<String>,
    },
    /// The station sent HELLO or CONNECT, which only belong to the
    /// handshake, after it.
    ProtocolViolation { frame_type: String },
    /// A write on the control stream stalled for longer than the send
    /// timeout, so a frame may be half written.
    SendTimeout,
    /// The station sent a frame that couldn't be decoded, so nothing after it
    /// could be read in step.
    Malformed(String),
    /// The control stream ended or failed.
    StreamFailed(String),
    /// The session was closed or dropped here.
    Closed,
}

impl std::fmt::Display for SessionEndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionEndReason::Goodbye {
                reason,
                detail: None,
            } => write!(f, "the station said goodbye: {reason}"),
            SessionEndReason::Goodbye {
                reason,
                detail: Some(detail),
            } => write!(f, "the station said goodbye: {reason} ({detail})"),
            SessionEndReason::ProtocolViolation { frame_type } => {
                write!(f, "the station sent {frame_type} after the handshake")
            }
            SessionEndReason::SendTimeout => write!(
                f,
                "a write on the control stream stalled past the send timeout"
            ),
            SessionEndReason::Malformed(why) => {
                write!(
                    f,
                    "the station sent a frame that could not be decoded: {why}"
                )
            }
            SessionEndReason::StreamFailed(why) => write!(f, "the control stream failed: {why}"),
            SessionEndReason::Closed => write!(f, "the session was closed"),
        }
    }
}

/// Why a frame couldn't be sent on a session.
#[derive(Debug)]
pub enum SendError {
    /// No turn to write came within the send timeout. The frame was not
    /// sent, and the session carries on.
    Timeout,
    /// This frame's own write stalled past the send timeout, and the session
    /// ended.
    SendTimeout,
    /// The session had ended, or ended while the frame waited for its turn.
    SessionEnded(SessionEndReason),
    Encode(frame::EncodeFrameError),
    /// Writing to the control stream failed.
    Write(std::io::Error),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Timeout => write!(
                f,
                "no turn to write came within the send timeout, so the frame was not sent"
            ),
            SendError::SendTimeout => write!(
                f,
                "the write stalled past the send timeout, and the session ended"
            ),
            SendError::SessionEnded(reason) => write!(f, "the session has ended: {reason}"),
            SendError::Encode(e) => write!(f, "encoding the frame: {e}"),
            SendError::Write(e) => write!(f, "writing to the control stream: {e}"),
        }
    }
}

impl std::error::Error for SendError {}

/// Why a call on a session got no reply.
#[derive(Debug)]
pub enum CallError {
    /// The call's own timeout ran out. `write_started` is false when the
    /// CALL was still waiting for its turn to write, so it was never sent,
    /// and true once its write had started, so the station may have it. A
    /// reply that arrives later is counted as unrouted.
    Timeout {
        write_started: bool,
    },
    /// The session ended before a reply came. `write_started` means the same
    /// as for [`CallError::Timeout`].
    SessionEnded {
        reason: SessionEndReason,
        write_started: bool,
    },
    /// This call's own write stalled past the send timeout, and the session
    /// ended. The station may have part of the CALL.
    SendTimeout,
    Encode(frame::EncodeFrameError),
    /// Writing the CALL failed.
    Write(std::io::Error),
    /// A reply carried this call's `call_id` but wasn't a RESULT or ERROR.
    MalformedReply(frame::ParseCallResponseError),
}

impl CallError {
    /// Whether the CALL was never sent, so trying it elsewhere can't run it
    /// twice.
    pub fn not_sent(&self) -> bool {
        matches!(
            self,
            CallError::Timeout {
                write_started: false
            } | CallError::SessionEnded {
                write_started: false,
                ..
            } | CallError::Encode(_)
        )
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Timeout {
                write_started: false,
            } => write!(
                f,
                "no turn to write the CALL came in time, so it was not sent"
            ),
            CallError::Timeout {
                write_started: true,
            } => write!(f, "timed out waiting for a RESULT or ERROR"),
            CallError::SessionEnded {
                reason,
                write_started: false,
            } => write!(f, "the session ended before the CALL was sent: {reason}"),
            CallError::SessionEnded {
                reason,
                write_started: true,
            } => write!(f, "the session ended while awaiting a reply: {reason}"),
            CallError::SendTimeout => write!(
                f,
                "the CALL's write stalled past the send timeout, and the session ended"
            ),
            CallError::Encode(e) => write!(f, "encoding the CALL: {e}"),
            CallError::Write(e) => write!(f, "writing the CALL: {e}"),
            CallError::MalformedReply(e) => write!(f, "the reply was malformed: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

/// Why a subscription produced no event.
#[derive(Debug)]
pub enum RecvEventError {
    /// No event arrived in time.
    Timeout,
    /// This subscription fell more than 256 events behind. The events it had
    /// queued were read first; it receives nothing more, but keeps the
    /// station subscribed until it is closed, so a replacement subscribed
    /// first takes over without a gap. The session carries on.
    Overflow,
    /// The session ended.
    SessionEnded(SessionEndReason),
}

impl std::fmt::Display for RecvEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvEventError::Timeout => write!(f, "timed out waiting for an event"),
            RecvEventError::Overflow => write!(
                f,
                "the subscription fell more than {EVENT_QUEUE_CAPACITY} events behind"
            ),
            RecvEventError::SessionEnded(reason) => write!(f, "the session has ended: {reason}"),
        }
    }
}

impl std::error::Error for RecvEventError {}

/// The calls waiting for their reply, by call id.
type PendingCalls =
    HashMap<[u8; 16], oneshot::Sender<Result<CallResponse, frame::ParseCallResponseError>>>;

/// The routing and writing state of one session's control stream, shared by
/// the session's handles, its reader task and its hand-off writer.
pub(crate) struct Channel {
    identity: KeyPair,
    station: [u8; 32],
    send_timeout: Duration,
    /// Holding this lock is the turn to write.
    writer: Arc<tokio::sync::Mutex<BoxWrite>>,
    calls: Mutex<PendingCalls>,
    subscriptions: Mutex<Vec<Entry>>,
    /// Subscribing and closing take turns across the count change and the
    /// SUBSCRIBE or UNSUBSCRIBE it sends, so the frames reach the station in
    /// the order the counts changed.
    subscription_turn: tokio::sync::Mutex<()>,
    next_subscription: AtomicU64,
    inbound_tx: Mutex<Option<mpsc::Sender<CallInfo>>>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<CallInfo>>,
    hand_off: Mutex<Option<mpsc::Sender<Value>>>,
    unrouted: Mutex<HashMap<String, u64>>,
    reported: Mutex<HashMap<String, (u64, Option<std::time::Instant>)>>,
    /// The bounded warnings for dropped CALLs and replies and refused streams.
    drop_warnings: DropWarnings,
    ended: OnceLock<SessionEndReason>,
    ended_tx: watch::Sender<bool>,
    on_ended: Mutex<Option<OnEnded>>,
}

/// One subscription as the reader sees it. `events` is dropped when the
/// subscription overflows or the session ends, which is how its receiver
/// learns it gets nothing more.
struct Entry {
    id: u64,
    realm: [u8; 32],
    topic: String,
    subscriber: [u8; 32],
    events: Option<mpsc::Sender<EventInfo>>,
    overflowed: Arc<AtomicBool>,
}

impl Entry {
    fn holds(&self, realm: &[u8; 32], topic: &str) -> bool {
        self.realm == *realm && self.topic == topic
    }
}

/// Why a writer got no turn.
enum Refused {
    Timeout,
    Ended(SessionEndReason),
}

/// How a write that got its turn went.
enum Written {
    Whole,
    Stalled,
    Failed(std::io::Error),
}

// A panic elsewhere while a lock was held leaves the data itself intact.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text_field(frame: &Value, key: &str) -> Option<String> {
    match frame.get(key)? {
        Value::Text(text) => Some(text.clone()),
        Value::Bytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        _ => None,
    }
}

/// The station's topic rule: both split on "/", equal segment counts, and
/// each pattern segment equal to the topic's or "*", which matches exactly
/// one whole segment.
pub(crate) fn topic_matches(pattern: &str, topic: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let topic: Vec<&str> = topic.split('/').collect();
    pattern.len() == topic.len()
        && pattern
            .iter()
            .zip(&topic)
            .all(|(segment, actual)| *segment == "*" || segment == actual)
}

impl Channel {
    /// Starts the reader and the hand-off writer on a control stream whose
    /// handshake is done. `leftover` is what the handshake read past HELLO.
    /// `identity` signs the frames the session sends on its own account.
    pub(crate) fn start(
        reader: BoxRead,
        leftover: Vec<u8>,
        writer: BoxWrite,
        identity: KeyPair,
        station: [u8; 32],
        send_timeout: Duration,
        on_ended: OnEnded,
    ) -> Arc<Channel> {
        let (inbound_tx, inbound_rx) = mpsc::channel(CALL_QUEUE_CAPACITY);
        let (hand_off_tx, hand_off_rx) = mpsc::channel(HAND_OFF_CAPACITY);
        let (ended_tx, _) = watch::channel(false);
        let channel = Arc::new(Channel {
            identity,
            station,
            send_timeout,
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
            calls: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(Vec::new()),
            subscription_turn: tokio::sync::Mutex::new(()),
            next_subscription: AtomicU64::new(0),
            inbound_tx: Mutex::new(Some(inbound_tx)),
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            hand_off: Mutex::new(Some(hand_off_tx)),
            unrouted: Mutex::new(HashMap::new()),
            reported: Mutex::new(HashMap::new()),
            drop_warnings: DropWarnings::new(station),
            ended: OnceLock::new(),
            ended_tx,
            on_ended: Mutex::new(Some(on_ended)),
        });
        tokio::spawn(read(channel.clone(), reader, leftover));
        tokio::spawn(write_handed_off(channel.clone(), hand_off_rx));
        channel
    }

    /// Why the session ended, once it has.
    pub(crate) fn end_reason(&self) -> Option<SessionEndReason> {
        self.ended.get().cloned()
    }

    /// Resolves once the session has ended, with why.
    pub(crate) async fn ended(&self) -> SessionEndReason {
        let mut ended = self.ended_tx.subscribe();
        let _ = ended.wait_for(|ended| *ended).await;
        self.end_reason().unwrap_or(SessionEndReason::Closed)
    }

    /// How many frames of each type arrived with nothing to route them to.
    pub(crate) fn unrouted_frame_counts(&self) -> HashMap<String, u64> {
        lock(&self.unrouted).clone()
    }

    /// The bounded warnings for frames this session drops and streams it
    /// refuses.
    pub(crate) fn drop_warnings(&self) -> &DropWarnings {
        &self.drop_warnings
    }

    /// Sends an already signed frame whole. Waiting for the turn to write is
    /// bounded by the send timeout; the write itself runs in a task of its
    /// own, so a caller that stops waiting never leaves a frame half written.
    pub(crate) async fn send(self: &Arc<Self>, signed: &Value) -> Result<(), SendError> {
        let bytes = frame::encode(signed).map_err(SendError::Encode)?;
        let write = self
            .start_write(bytes, self.send_timeout, None)
            .await
            .map_err(|refused| match refused {
                Refused::Timeout => SendError::Timeout,
                Refused::Ended(reason) => SendError::SessionEnded(reason),
            })?;
        match write.await {
            Ok(Written::Whole) => Ok(()),
            Ok(Written::Stalled) => Err(SendError::SendTimeout),
            Ok(Written::Failed(e)) => Err(SendError::Write(e)),
            Err(join) => Err(SendError::Write(std::io::Error::other(join))),
        }
    }

    /// Hands an unsigned frame to the writer of the frames the session sends
    /// on its own account, without waiting. It is dropped when 64 frames
    /// already wait there, or the session ended.
    pub(crate) fn hand_off(&self, frame: Value) {
        if let Some(frames) = lock(&self.hand_off).as_ref() {
            let _ = frames.try_send(frame);
        }
    }

    /// Sends `spec` as a CALL signed by `identity` and waits for its reply,
    /// all within `timeout`, its turn to write included. `after_written`, an
    /// unsigned frame, is handed off once the CALL is written.
    pub(crate) async fn call(
        self: &Arc<Self>,
        spec: &CallSpec,
        identity: &KeyPair,
        timeout: Duration,
        after_written: Option<Value>,
    ) -> Result<CallResponse, CallError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let bytes =
            frame::encode(&frame::sign(frame::call(spec), identity)).map_err(CallError::Encode)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        lock(&self.calls).insert(spec.call_id, reply_tx);
        let _waiting = Waiting {
            channel: self,
            call_id: spec.call_id,
        };
        let write = match self.start_write(bytes, timeout, after_written).await {
            Ok(write) => write,
            Err(Refused::Timeout) => {
                return Err(CallError::Timeout {
                    write_started: false,
                })
            }
            Err(Refused::Ended(reason)) => {
                return Err(CallError::SessionEnded {
                    reason,
                    write_started: false,
                })
            }
        };
        match tokio::time::timeout_at(deadline, write).await {
            Err(_) => {
                return Err(CallError::Timeout {
                    write_started: true,
                })
            }
            Ok(Ok(Written::Whole)) => {}
            Ok(Ok(Written::Stalled)) => return Err(CallError::SendTimeout),
            Ok(Ok(Written::Failed(e))) => {
                return Err(match self.end_reason() {
                    Some(reason) => CallError::SessionEnded {
                        reason,
                        write_started: true,
                    },
                    None => CallError::Write(e),
                })
            }
            Ok(Err(join)) => return Err(CallError::Write(std::io::Error::other(join))),
        }
        match tokio::time::timeout_at(deadline, reply_rx).await {
            Err(_) => Err(CallError::Timeout {
                write_started: true,
            }),
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(malformed))) => Err(CallError::MalformedReply(malformed)),
            Ok(Err(_)) => Err(CallError::SessionEnded {
                reason: self.end_reason().unwrap_or(SessionEndReason::Closed),
                write_started: true,
            }),
        }
    }

    /// The next inbound CALL signed by its caller. Once the session ended and
    /// the queued calls are served, why it ended.
    pub(crate) async fn next_inbound_call(&self) -> Result<CallInfo, SessionEndReason> {
        let mut calls = self.inbound_rx.lock().await;
        calls
            .recv()
            .await
            .ok_or_else(|| self.end_reason().unwrap_or(SessionEndReason::Closed))
    }

    /// Starts a subscription, sending SUBSCRIBE signed by `identity` unless
    /// another subscription on this session already holds that realm and
    /// topic at the station.
    pub(crate) async fn subscribe(
        self: &Arc<Self>,
        spec: &SubscribeSpec,
        identity: &KeyPair,
    ) -> Result<Subscription, SendError> {
        let _turn = self.subscription_turn.lock().await;
        if let Some(reason) = self.end_reason() {
            return Err(SendError::SessionEnded(reason));
        }
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let overflowed = Arc::new(AtomicBool::new(false));
        let id = self.next_subscription.fetch_add(1, Ordering::Relaxed);
        let first = {
            let mut entries = lock(&self.subscriptions);
            let first = !entries
                .iter()
                .any(|entry| entry.holds(&spec.realm, &spec.topic));
            entries.push(Entry {
                id,
                realm: spec.realm,
                topic: spec.topic.clone(),
                subscriber: spec.subscriber,
                events: Some(events_tx),
                overflowed: overflowed.clone(),
            });
            first
        };
        if first {
            if let Err(e) = self
                .send(&frame::sign(frame::subscribe(spec), identity))
                .await
            {
                lock(&self.subscriptions).retain(|entry| entry.id != id);
                return Err(e);
            }
        }
        Ok(Subscription {
            channel: self.clone(),
            id,
            realm: spec.realm,
            topic: spec.topic.clone(),
            events: events_rx,
            overflowed,
            closed: false,
        })
    }

    /// Ends a subscription, and sends UNSUBSCRIBE when no other subscription
    /// on this session still holds its realm and topic.
    async fn remove_subscription(self: &Arc<Self>, id: u64) {
        let _turn = self.subscription_turn.lock().await;
        let removed = {
            let mut entries = lock(&self.subscriptions);
            entries
                .iter()
                .position(|entry| entry.id == id)
                .map(|index| {
                    let entry = entries.remove(index);
                    let last = !entries
                        .iter()
                        .any(|other| other.holds(&entry.realm, &entry.topic));
                    (entry, last)
                })
        };
        let Some((entry, true)) = removed else {
            return;
        };
        if self.end_reason().is_some() {
            return;
        }
        let spec = frame::UnsubscribeSpec::new(entry.topic, entry.realm, entry.subscriber);
        // Not sent in time, or the session ended; a station drops a
        // connection's subscriptions together with the connection.
        let _ = self
            .send(&frame::sign(frame::unsubscribe(&spec), &self.identity))
            .await;
    }

    /// Closes the session here: GOODBYE, as best it can within the send
    /// timeout, then the stream's sending side, then the end itself.
    pub(crate) async fn close(self: &Arc<Self>, goodbye: &Value) {
        let _ = self.send(goodbye).await;
        if let Ok(mut writer) = tokio::time::timeout(self.send_timeout, self.writer.lock()).await {
            let _ = tokio::time::timeout(self.send_timeout, writer.shutdown()).await;
        }
        self.end(SessionEndReason::Closed, true);
    }

    /// Ends the session with `reason`, once: logs it, fails every waiting
    /// call, ends every subscription and the inbound call queue, stops the
    /// reader and the hand-off writer, and runs `on_ended`.
    pub(crate) fn end(&self, reason: SessionEndReason, closed_here: bool) {
        if self.ended.set(reason.clone()).is_err() {
            return;
        }
        // Every end is reported once, so why a session went away can be found
        // afterwards: a warning when the station or the connection ended it,
        // information when it was closed here.
        let report = format!(
            "macula: session {} to station {} ended: {reason}",
            hex(&self.identity.node_id()),
            hex(&self.station)
        );
        if closed_here {
            log::info!("{report}");
        } else {
            log::warn!("{report}");
        }
        self.ended_tx.send_replace(true);
        lock(&self.calls).clear();
        for entry in lock(&self.subscriptions).iter_mut() {
            entry.events = None;
        }
        lock(&self.inbound_tx).take();
        lock(&self.hand_off).take();
        if let Some(on_ended) = lock(&self.on_ended).take() {
            on_ended(&reason, closed_here);
        }
    }

    /// Waits up to `wait` for the turn to write, then writes `bytes` in a task
    /// of its own that gives the turn back when done, bounded by the send
    /// timeout. A write that stalls past it ends the session before the turn
    /// is given back, so nothing is written after a half-written frame.
    async fn start_write(
        self: &Arc<Self>,
        bytes: Vec<u8>,
        wait: Duration,
        after_written: Option<Value>,
    ) -> Result<JoinHandle<Written>, Refused> {
        if let Some(reason) = self.end_reason() {
            return Err(Refused::Ended(reason));
        }
        let mut ended = self.ended_tx.subscribe();
        let turn = tokio::select! {
            biased;
            _ = ended.wait_for(|ended| *ended) => {
                return Err(Refused::Ended(self.end_reason().unwrap_or(SessionEndReason::Closed)));
            }
            turn = tokio::time::timeout(wait, self.writer.clone().lock_owned()) => {
                turn.map_err(|_| Refused::Timeout)?
            }
        };
        if let Some(reason) = self.end_reason() {
            return Err(Refused::Ended(reason));
        }
        let channel = self.clone();
        Ok(tokio::spawn(async move {
            let mut writer = turn;
            let written = tokio::time::timeout(channel.send_timeout, async {
                writer.write_all(&bytes).await?;
                writer.flush().await
            })
            .await;
            let outcome = match written {
                Ok(Ok(())) => Written::Whole,
                Ok(Err(e)) => Written::Failed(e),
                Err(_) => {
                    channel.end(SessionEndReason::SendTimeout, false);
                    Written::Stalled
                }
            };
            drop(writer);
            if let (Written::Whole, Some(frame)) = (&outcome, after_written) {
                channel.hand_off(frame);
            }
            outcome
        }))
    }

    // Routes one frame, returning why when the frame ends the session.
    fn route(&self, frame: Value) -> Option<SessionEndReason> {
        let frame_type = text_field(&frame, "frame_type").unwrap_or_else(|| "unknown".to_string());
        match frame_type.as_str() {
            "result" | "error" => {
                self.complete_call(&frame_type, &frame);
                None
            }
            "event" => {
                self.deliver_event(&frame);
                None
            }
            "call" => {
                self.queue_inbound_call(&frame);
                None
            }
            "goodbye" => Some(SessionEndReason::Goodbye {
                reason: text_field(&frame, "reason")
                    .unwrap_or_else(|| "no reason given".to_string()),
                detail: text_field(&frame, "detail"),
            }),
            "hello" | "connect" => Some(SessionEndReason::ProtocolViolation { frame_type }),
            _ => {
                self.drop_unrouted(&frame_type);
                None
            }
        }
    }

    fn complete_call(&self, frame_type: &str, frame: &Value) {
        let call_id = frame::frame_call_id(frame);
        let waiting = call_id.and_then(|call_id| lock(&self.calls).remove(&call_id));
        match (waiting, call_id) {
            (Some(reply), _) => {
                let _ = reply.send(frame::parse_call_response(frame));
            }
            (None, Some(call_id)) => {
                self.drop_reply(frame_type, Reason::UnknownCallId, Subject::CallId(call_id))
            }
            (None, None) => self.drop_reply(frame_type, Reason::Malformed, Subject::Nothing),
        }
    }

    /// Counts a RESULT or ERROR no call waits for, with a bounded warning.
    fn drop_reply(&self, frame_type: &str, reason: Reason, subject: Subject) {
        self.count_unrouted(frame_type);
        self.drop_warnings
            .record(Kind::DroppedReply, reason, subject);
    }

    fn deliver_event(&self, frame: &Value) {
        let Ok(event) = frame::parse_event(frame) else {
            self.drop_unrouted("event");
            return;
        };
        let mut matched = false;
        for entry in lock(&self.subscriptions).iter_mut() {
            let Some(events) = entry.events.as_ref() else {
                continue;
            };
            if entry.realm != event.realm || !topic_matches(&entry.topic, &event.topic) {
                continue;
            }
            matched = true;
            if let Err(mpsc::error::TrySendError::Full(_)) = events.try_send(event.clone()) {
                entry.overflowed.store(true, Ordering::Release);
                entry.events = None;
            }
        }
        if !matched {
            self.drop_unrouted("event");
        }
    }

    fn queue_inbound_call(&self, frame: &Value) {
        // A CALL that isn't signed by the caller it names gets no reply, and
        // nothing else looks at it first, as in macula_station_link.erl's
        // on_inbound_call/3.
        if let Err(reason) = drop_warning::signed_caller(frame) {
            self.drop_call(reason, frame);
            return;
        }
        let Ok(call) = frame::parse_call(frame) else {
            self.drop_call(Reason::Malformed, frame);
            return;
        };
        let refused = match lock(&self.inbound_tx).as_ref() {
            Some(calls) => match calls.try_send(call) {
                Err(mpsc::error::TrySendError::Full(call)) => Some(call.call_id),
                _ => None,
            },
            None => None,
        };
        // A CALL that doesn't fit gets temporary_relay_failure, as a handler
        // crash does: the handler never ran, so the caller may try again
        // instead of waiting out its deadline. Serving carries on with the
        // calls queued, and when the hand-off is full too, the refusal is
        // dropped and the caller's deadline covers it.
        if let Some(call_id) = refused {
            self.hand_off(frame::call_error(&frame::CallErrorSpec::new(
                call_id,
                bolt4::Code::TemporaryRelayFailure,
                self.identity.node_id(),
            )));
        }
    }

    /// Counts a dropped inbound CALL, with a bounded warning.
    fn drop_call(&self, reason: Reason, frame: &Value) {
        self.count_unrouted("call");
        self.drop_warnings
            .record(Kind::DroppedCall, reason, drop_warning::procedure_of(frame));
    }

    fn count_unrouted(&self, frame_type: &str) {
        *lock(&self.unrouted)
            .entry(frame_type.to_string())
            .or_default() += 1;
    }

    /// Counts a frame nothing routes, with at most one warning line per frame
    /// type a minute.
    fn drop_unrouted(&self, frame_type: &str) {
        self.count_unrouted(frame_type);
        let mut reported = lock(&self.reported);
        let (dropped, last) = reported.entry(frame_type.to_string()).or_insert((0, None));
        *dropped += 1;
        let now = std::time::Instant::now();
        if last.is_none_or(|last| now.duration_since(last) >= LOG_INTERVAL) {
            log::warn!(
                "macula: dropped {dropped} unrouted {frame_type} frame(s) in the last minute (station {})",
                hex(&self.station)
            );
            *dropped = 0;
            *last = Some(now);
        }
    }
}

/// Removes a call's reply slot however the call ends, so a late reply is
/// counted as unrouted.
struct Waiting<'a> {
    channel: &'a Channel,
    call_id: [u8; 16],
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        lock(&self.channel.calls).remove(&self.call_id);
    }
}

async fn read(channel: Arc<Channel>, mut reader: BoxRead, mut buf: Vec<u8>) {
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut ended = channel.ended_tx.subscribe();
    loop {
        loop {
            match frame::decode(&buf) {
                Ok(Decoded::Frame(value, consumed)) => {
                    buf.drain(..consumed);
                    if let Some(reason) = channel.route(value) {
                        channel.end(reason, false);
                        return;
                    }
                }
                Ok(Decoded::More(_)) => break,
                Err(e) => {
                    // Nothing after a frame that can't be decoded can be read
                    // in step.
                    channel.end(SessionEndReason::Malformed(e.to_string()), false);
                    return;
                }
            }
        }
        let read = tokio::select! {
            _ = ended.wait_for(|ended| *ended) => return,
            read = reader.read(&mut chunk) => read,
        };
        match read {
            Ok(0) => {
                channel.end(
                    SessionEndReason::StreamFailed(
                        "the station closed the control stream".to_string(),
                    ),
                    false,
                );
                return;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                channel.end(
                    SessionEndReason::StreamFailed(format!("reading: {e}")),
                    false,
                );
                return;
            }
        }
    }
}

// Sends the frames handed off, one at a time, until the session ends.
async fn write_handed_off(channel: Arc<Channel>, mut frames: mpsc::Receiver<Value>) {
    while let Some(frame) = frames.recv().await {
        // Not sent in time, or the session ended. Nothing waits on these
        // frames: a caller's own deadline covers a missing reply, and a fact
        // is best effort.
        let _ = channel.send(&frame::sign(frame, &channel.identity)).await;
    }
}

/// One subscription on a [`Session`](crate::connection::Session): every
/// EVENT whose realm is this subscription's and whose topic matches its
/// pattern is copied into a queue of its own of 256 events. Several
/// subscriptions on one session each get their own copy.
///
/// A subscription that falls more than 256 events behind gets its queued
/// events, then [`RecvEventError::Overflow`], and nothing more, while the
/// session and its other subscriptions carry on. It keeps the station
/// subscribed until it is closed. Close it, or drop it, to stop: the session
/// sends UNSUBSCRIBE once no other subscription on it holds that realm and
/// topic.
pub struct Subscription {
    channel: Arc<Channel>,
    id: u64,
    realm: [u8; 32],
    topic: String,
    events: mpsc::Receiver<EventInfo>,
    overflowed: Arc<AtomicBool>,
    closed: bool,
}

impl Subscription {
    pub fn realm(&self) -> [u8; 32] {
        self.realm
    }

    /// The topic pattern this subscription matches.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Whether this subscription fell behind and receives nothing more.
    pub fn is_overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    /// Waits up to `timeout` for the next event.
    pub async fn recv_event(&mut self, timeout: Duration) -> Result<EventInfo, RecvEventError> {
        match tokio::time::timeout(timeout, self.events.recv()).await {
            Err(_) => Err(RecvEventError::Timeout),
            Ok(Some(event)) => Ok(event),
            Ok(None) if self.is_overflowed() => Err(RecvEventError::Overflow),
            Ok(None) => Err(RecvEventError::SessionEnded(
                self.channel
                    .end_reason()
                    .unwrap_or(SessionEndReason::Closed),
            )),
        }
    }

    /// Ends this subscription, and sends UNSUBSCRIBE when no other
    /// subscription on the session holds its realm and topic.
    pub async fn close(mut self) {
        self.closed = true;
        self.channel.remove_subscription(self.id).await;
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let (channel, id) = (self.channel.clone(), self.id);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move { channel.remove_subscription(id).await });
            }
            // Outside a runtime nothing can be sent; the station drops the
            // subscription with the connection.
            Err(_) => lock(&channel.subscriptions).retain(|entry| entry.id != id),
        }
    }
}

pub(crate) mod drop_warning;

#[cfg(test)]
pub(crate) mod fake_station;

#[cfg(test)]
mod tests {
    //! The session reader, over in-memory pipes. The names match the Go and
    //! .NET tests.
    use super::fake_station::*;
    use super::*;

    #[tokio::test]
    async fn concurrent_calls_on_one_session_each_get_their_own_reply() {
        let (channel, mut station, _ended) = connect();
        let procedures: Vec<String> = (0..10).map(|i| format!("app/echo_{i}")).collect();

        let calls: Vec<_> = procedures
            .iter()
            .map(|procedure| spawn_call(&channel, call(procedure), WAIT))
            .collect();
        let mut sent = Vec::new();
        for _ in &procedures {
            sent.push(station.next("call").await);
        }
        for frame in sent.iter().rev() {
            let procedure = text_field(frame, "procedure").expect("a CALL names its procedure");
            station.reply(frame, &procedure).await;
        }

        for (procedure, call) in procedures.iter().zip(calls) {
            assert_eq!(reply_text(call.await.unwrap().unwrap()), *procedure);
        }
    }

    #[tokio::test]
    async fn an_event_arriving_during_a_call_reaches_its_subscriber() {
        let (channel, mut station, _ended) = connect();
        let mut subscription = channel
            .subscribe(&subscribe("app/orders/placed"), &KeyPair::generate())
            .await
            .unwrap();

        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next("call").await;
        station.send_event("app/orders/placed", "order 1").await;
        station.reply(&sent, "echoed").await;

        assert_eq!(reply_text(pending.await.unwrap().unwrap()), "echoed");
        assert_eq!(
            event_text(subscription.recv_event(WAIT).await.unwrap()),
            "order 1"
        );
    }

    #[tokio::test]
    async fn serving_a_call_while_calling_on_the_same_session() {
        let (channel, mut station, _ended) = connect();

        let served = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.next_inbound_call().await })
        };
        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next("call").await;
        station.send_inbound_call("app/greet", Signer::Caller).await;
        station.reply(&sent, "echoed").await;

        assert_eq!(served.await.unwrap().unwrap().procedure, "app/greet");
        assert_eq!(reply_text(pending.await.unwrap().unwrap()), "echoed");
    }

    #[tokio::test]
    async fn a_queued_call_past_its_deadline_is_still_served() {
        let (channel, mut station, _ended) = connect();

        station
            .send_inbound_call_due("app/echo", Signer::Caller, now_ms() - 1_000)
            .await;

        let call = tokio::time::timeout(WAIT, channel.next_inbound_call())
            .await
            .unwrap()
            .unwrap();
        let echo: crate::connection::CallHandler = Arc::new(|payload: Value| {
            Box::pin(async move { Ok(payload) })
                as crate::connection::BoxFuture<'static, Result<Value, String>>
        });
        let lookup =
            move |_: &[u8; 32], procedure: &str| (procedure == "app/echo").then(|| echo.clone());
        let reply = crate::connection::build_call_reply(
            call,
            &lookup,
            &|_: &[u8; 32], _: &str| crate::ucan::Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await;
        assert!(matches!(
            frame::parse_call_response(&reply),
            Ok(CallResponse::Result { .. })
        ));
    }

    #[tokio::test]
    async fn two_subscribers_with_different_topics_each_get_only_their_events() {
        let (channel, mut station, _ended) = connect();
        let id = KeyPair::generate();
        let mut orders = channel
            .subscribe(&subscribe("app/orders"), &id)
            .await
            .unwrap();
        let mut invoices = channel
            .subscribe(&subscribe("app/invoices"), &id)
            .await
            .unwrap();

        station.send_event("app/orders", "order 1").await;
        station.send_event("app/invoices", "invoice 1").await;

        assert_eq!(
            event_text(orders.recv_event(WAIT).await.unwrap()),
            "order 1"
        );
        assert_eq!(
            event_text(invoices.recv_event(WAIT).await.unwrap()),
            "invoice 1"
        );
        let short = Duration::from_millis(200);
        assert!(matches!(
            orders.recv_event(short).await,
            Err(RecvEventError::Timeout)
        ));
        assert!(matches!(
            invoices.recv_event(short).await,
            Err(RecvEventError::Timeout)
        ));
    }

    #[tokio::test]
    async fn a_wildcard_subscription_matches_exactly_one_segment() {
        let (channel, mut station, _ended) = connect();
        let mut placed = channel
            .subscribe(&subscribe("app/*/placed"), &KeyPair::generate())
            .await
            .unwrap();

        station
            .send_event("app/orders/eu/placed", "two segments")
            .await;
        station.send_event("app/placed", "no segment").await;
        station.send_event("app/orders/placed", "one segment").await;

        assert_eq!(
            event_text(placed.recv_event(WAIT).await.unwrap()),
            "one segment"
        );
        assert!(matches!(
            placed.recv_event(Duration::from_millis(200)).await,
            Err(RecvEventError::Timeout)
        ));
    }

    #[tokio::test]
    async fn closing_the_last_subscription_for_a_topic_unsubscribes() {
        let (channel, mut station, _ended) = connect();
        let id = KeyPair::generate();
        let first = channel
            .subscribe(&subscribe("app/orders"), &id)
            .await
            .unwrap();
        let second = channel
            .subscribe(&subscribe("app/orders"), &id)
            .await
            .unwrap();
        assert_eq!(frame_type(&station.next_frame().await), "subscribe");

        first.close().await;
        // A call right after shows what the session sent in between: nothing.
        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next_frame().await;
        assert_eq!(frame_type(&sent), "call");
        station.reply(&sent, "echoed").await;
        pending.await.unwrap().unwrap();

        second.close().await;
        assert_eq!(frame_type(&station.next_frame().await), "unsubscribe");
    }

    #[tokio::test]
    async fn an_overflowed_subscription_keeps_the_station_subscribed_until_it_is_closed() {
        let (channel, mut station, _ended) = connect();
        let behind = channel
            .subscribe(&subscribe("app/ticks"), &KeyPair::generate())
            .await
            .unwrap();
        assert_eq!(frame_type(&station.next_frame().await), "subscribe");

        // The call's reply comes after every event, so by the time it
        // arrives the reader has routed all of them.
        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next_frame().await;
        for i in 0..=EVENT_QUEUE_CAPACITY {
            station.send_event("app/ticks", &format!("tick {i}")).await;
        }
        station.reply(&sent, "echoed").await;
        pending.await.unwrap().unwrap();
        assert!(behind.is_overflowed());

        // A call right after shows what the session sent since: nothing.
        let probe = spawn_call(&channel, call("app/echo"), WAIT);
        let next = station.next_frame().await;
        assert_eq!(frame_type(&next), "call");
        station.reply(&next, "echoed").await;
        probe.await.unwrap().unwrap();

        behind.close().await;
        assert_eq!(frame_type(&station.next_frame().await), "unsubscribe");
    }

    #[tokio::test]
    async fn a_stalled_event_consumer_does_not_stall_call_replies() {
        let (channel, mut station, _ended) = connect();
        let _stalled = channel
            .subscribe(&subscribe("app/ticks"), &KeyPair::generate())
            .await
            .unwrap();

        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next("call").await;
        for i in 0..EVENT_QUEUE_CAPACITY + 44 {
            station.send_event("app/ticks", &format!("tick {i}")).await;
        }
        station.reply(&sent, "echoed").await;

        assert_eq!(reply_text(pending.await.unwrap().unwrap()), "echoed");
    }

    #[tokio::test]
    async fn an_overflowing_event_consumer_ends_with_an_overflow_error_and_the_session_stays_up() {
        let (channel, mut station, _ended) = connect();
        let id = KeyPair::generate();
        let mut behind = channel
            .subscribe(&subscribe("app/ticks"), &id)
            .await
            .unwrap();

        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next("call").await;
        for i in 0..=EVENT_QUEUE_CAPACITY {
            station.send_event("app/ticks", &format!("tick {i}")).await;
        }
        station.reply(&sent, "echoed").await;
        pending.await.unwrap().unwrap();

        for i in 0..EVENT_QUEUE_CAPACITY {
            assert_eq!(
                event_text(behind.recv_event(WAIT).await.unwrap()),
                format!("tick {i}")
            );
        }
        assert!(matches!(
            behind.recv_event(WAIT).await,
            Err(RecvEventError::Overflow)
        ));

        let mut fresh = channel
            .subscribe(&subscribe("app/ticks"), &id)
            .await
            .unwrap();
        station.send_event("app/ticks", "after the overflow").await;
        assert_eq!(
            event_text(fresh.recv_event(WAIT).await.unwrap()),
            "after the overflow"
        );
    }

    #[tokio::test]
    async fn an_overflowing_call_queue_answers_the_extra_call_and_keeps_serving() {
        let (channel, mut station, _ended) = connect();

        let mut inbound = Vec::new();
        for i in 0..=CALL_QUEUE_CAPACITY {
            inbound.push(
                station
                    .send_inbound_call(&format!("app/job_{i}"), Signer::Caller)
                    .await,
            );
        }

        let refusal = station.next("error").await;
        assert_eq!(frame::frame_call_id(&refusal), inbound.last().copied());
        match frame::parse_call_response(&refusal) {
            Ok(CallResponse::Error { name, .. }) => assert_eq!(name, "temporary_relay_failure"),
            other => panic!("expected an ERROR, got {other:?}"),
        }

        // Serving carries on: the queued calls, then the next one to arrive.
        for i in 0..CALL_QUEUE_CAPACITY {
            let served = tokio::time::timeout(WAIT, channel.next_inbound_call())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(served.procedure, format!("app/job_{i}"));
        }
        station
            .send_inbound_call("app/after_the_overflow", Signer::Caller)
            .await;
        let served = tokio::time::timeout(WAIT, channel.next_inbound_call())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(served.procedure, "app/after_the_overflow");
    }

    #[tokio::test]
    async fn a_call_that_cannot_get_the_write_lock_in_time_times_out_and_the_session_stays_up() {
        let (channel, mut station, mut ended) = connect();
        station.stall_session_writes();
        let publishing = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.send(&publish("app/ticks")).await })
        };
        turn_taken(&channel).await;

        let timed_out = channel
            .call(
                &call("app/echo"),
                &KeyPair::generate(),
                Duration::from_millis(100),
                None,
            )
            .await;
        assert!(
            matches!(
                timed_out,
                Err(CallError::Timeout {
                    write_started: false
                })
            ),
            "{timed_out:?}"
        );
        assert!(ended.try_recv().is_err(), "the session stays up");

        station.resume_session_writes();
        publishing.await.unwrap().unwrap();
        assert_eq!(frame_type(&station.next_frame().await), "publish");
        let next = call("app/echo");
        let call_id = next.call_id;
        let pending = spawn_call(&channel, next, WAIT);
        let sent = station.next_frame().await;
        assert_eq!(frame::frame_call_id(&sent), Some(call_id));
        station.reply(&sent, "echoed").await;
        assert_eq!(reply_text(pending.await.unwrap().unwrap()), "echoed");
    }

    #[tokio::test]
    async fn a_write_stalled_past_the_send_timeout_ends_the_session() {
        let (channel, station, ended) = connect_with(Duration::from_millis(200));
        station.stall_session_writes();

        let published = tokio::time::timeout(WAIT, channel.send(&publish("app/ticks")))
            .await
            .unwrap();
        assert!(
            matches!(published, Err(SendError::SendTimeout)),
            "{published:?}"
        );
        let (reason, _) = tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();
        assert_eq!(reason, SessionEndReason::SendTimeout);
        let called = channel
            .call(&call("app/echo"), &KeyPair::generate(), WAIT, None)
            .await;
        assert!(
            matches!(
                called,
                Err(CallError::SessionEnded {
                    reason: SessionEndReason::SendTimeout,
                    write_started: false
                })
            ),
            "{called:?}"
        );
    }

    #[tokio::test]
    async fn the_reader_keeps_delivering_while_a_write_is_stalled() {
        let (channel, mut station, _ended) = connect();
        let mut ticks = channel
            .subscribe(&subscribe("app/ticks"), &KeyPair::generate())
            .await
            .unwrap();
        station.next("subscribe").await;
        station.stall_session_writes();

        // The extra calls' refusals can't go out while writes are stalled.
        for i in 0..CALL_QUEUE_CAPACITY + 4 {
            station
                .send_inbound_call(&format!("app/job_{i}"), Signer::Caller)
                .await;
        }
        station.send_event("app/ticks", "tick 1").await;

        assert_eq!(event_text(ticks.recv_event(WAIT).await.unwrap()), "tick 1");
        station.resume_session_writes();
    }

    #[tokio::test]
    async fn a_call_timing_out_while_its_frame_is_being_written_reports_it_may_have_been_sent() {
        let (channel, station, mut ended) = connect();
        station.stall_session_writes();

        let called = channel
            .call(
                &call("app/echo"),
                &KeyPair::generate(),
                Duration::from_millis(100),
                None,
            )
            .await;

        assert!(
            matches!(
                called,
                Err(CallError::Timeout {
                    write_started: true
                })
            ),
            "{called:?}"
        );
        assert!(ended.try_recv().is_err(), "the session stays up");
        station.resume_session_writes();
    }

    #[tokio::test]
    async fn a_frame_that_cannot_be_decoded_ends_the_session() {
        let (channel, mut station, ended) = connect();
        let pending = spawn_call(&channel, call("app/echo"), Duration::from_secs(10));
        station.next("call").await;

        // A one-byte frame whose CBOR initial byte uses a reserved value.
        station.send_raw(&[0, 0, 0, 1, 0x1C]).await;

        let (reason, closed_here) = tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();
        assert!(
            matches!(reason, SessionEndReason::Malformed(_)),
            "{reason:?}"
        );
        assert!(!closed_here);
        let called = pending.await.unwrap();
        assert!(
            matches!(
                called,
                Err(CallError::SessionEnded {
                    write_started: true,
                    ..
                })
            ),
            "{called:?}"
        );
    }

    #[tokio::test]
    async fn a_call_on_a_session_that_has_ended_reports_it_was_not_sent() {
        let (channel, station, ended) = connect();
        drop(station);
        tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();

        let called = channel
            .call(&call("app/echo"), &KeyPair::generate(), WAIT, None)
            .await;

        assert!(
            matches!(
                called,
                Err(CallError::SessionEnded {
                    write_started: false,
                    ..
                })
            ),
            "{called:?}"
        );
    }

    #[tokio::test]
    async fn a_call_waiting_for_the_write_lock_when_the_session_ends_reports_it_was_not_sent() {
        let (channel, mut station, _ended) = connect();
        station.stall_session_writes();
        let _publishing = {
            let channel = channel.clone();
            tokio::spawn(async move { channel.send(&publish("app/ticks")).await })
        };
        turn_taken(&channel).await;
        let pending = spawn_call(&channel, call("app/echo"), Duration::from_secs(30));

        station.send(&frame::goodbye("maintenance", None)).await;

        // Well before the call's own 30 second deadline.
        let called = tokio::time::timeout(WAIT, pending).await.unwrap().unwrap();
        assert!(
            matches!(
                called,
                Err(CallError::SessionEnded {
                    write_started: false,
                    ..
                })
            ),
            "{called:?}"
        );
        station.resume_session_writes();
    }

    #[tokio::test]
    async fn a_goodbye_from_the_station_fails_pending_calls_and_ends_the_session() {
        let (channel, mut station, ended) = connect();
        let pending = spawn_call(&channel, call("app/echo"), Duration::from_secs(10));
        station.next("call").await;

        station.send(&frame::goodbye("maintenance", None)).await;

        match pending.await.unwrap() {
            Err(CallError::SessionEnded {
                reason: SessionEndReason::Goodbye { reason, .. },
                write_started: true,
            }) => assert_eq!(reason, "maintenance"),
            other => panic!("expected the goodbye to end the call, got {other:?}"),
        }
        let (reason, _) = tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();
        assert!(
            matches!(reason, SessionEndReason::Goodbye { ref reason, .. } if reason == "maintenance"),
            "{reason:?}"
        );
    }

    #[tokio::test]
    async fn a_hello_after_the_handshake_ends_the_session() {
        let (channel, mut station, ended) = connect();
        let pending = spawn_call(&channel, call("app/echo"), Duration::from_secs(10));
        station.next("call").await;

        station
            .send(&Value::Map(vec![(
                Value::text("frame_type"),
                Value::text("hello"),
            )]))
            .await;

        assert!(
            matches!(
                pending.await.unwrap(),
                Err(CallError::SessionEnded {
                    reason: SessionEndReason::ProtocolViolation { .. },
                    ..
                })
            ),
            "a HELLO after the handshake ends the call"
        );
        let (reason, _) = tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();
        assert!(
            matches!(reason, SessionEndReason::ProtocolViolation { .. }),
            "{reason:?}"
        );
    }

    #[tokio::test]
    async fn a_session_end_is_logged_once_with_its_reason() {
        capture_logs();

        let (ended_by_station, mut station, ended) = connect();
        let station_id = station.identity.node_id();
        station.send(&frame::goodbye("maintenance", None)).await;
        tokio::time::timeout(WAIT, ended).await.unwrap().unwrap();
        ended_by_station.end(SessionEndReason::Closed, true);

        let (ended_here, _other_station, _) = connect();
        ended_here.end(SessionEndReason::Closed, true);

        let by_station = logged_about(&ended_by_station.identity.node_id());
        assert_eq!(by_station.len(), 1, "{by_station:?}");
        assert_eq!(by_station[0].0, log::Level::Warn);
        assert!(by_station[0].1.contains("maintenance"), "{by_station:?}");
        assert!(
            by_station[0].1.contains(&hex(&station_id)),
            "{by_station:?}"
        );
        let by_us = logged_about(&ended_here.identity.node_id());
        assert_eq!(by_us.len(), 1, "{by_us:?}");
        assert_eq!(by_us[0].0, log::Level::Info);
    }

    #[tokio::test]
    async fn an_unrouted_frame_is_counted_by_type() {
        let (channel, mut station, _ended) = connect();

        let pending = spawn_call(&channel, call("app/echo"), WAIT);
        let sent = station.next("call").await;
        let advertise = Value::Map(vec![(Value::text("frame_type"), Value::text("advertise"))]);
        station.send(&advertise).await;
        station.send(&advertise).await;
        let stray = frame::result(&frame::ResultSpec::new(
            rand::random(),
            Value::Null,
            station.identity.node_id(),
        ));
        station.send(&stray).await;
        station.reply(&sent, "echoed").await;
        pending.await.unwrap().unwrap();

        let counts = channel.unrouted_frame_counts();
        assert_eq!(counts.get("advertise"), Some(&2));
        assert_eq!(counts.get("result"), Some(&1));
    }

    struct OpenSession;

    impl crate::open_sessions::Live for OpenSession {
        fn is_live(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_session_whose_connection_ends_is_no_longer_found_for_reuse() {
        let (identity, station_id): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
        let open = Arc::new(crate::open_sessions::OpenSessions::<OpenSession>::default());
        let session = Arc::new(OpenSession);
        open.register(identity, station_id, &session);
        let (ended_tx, ended_rx) = oneshot::channel();
        let (registry, registered) = (open.clone(), session.clone());
        let (_channel, station) = connect_ending(
            SEND_TIMEOUT,
            Box::new(move |reason, _| {
                registry.unregister(identity, station_id, &registered);
                let _ = ended_tx.send(reason.clone());
            }),
        );

        drop(station);

        let reason = tokio::time::timeout(WAIT, ended_rx).await.unwrap().unwrap();
        assert!(
            matches!(reason, SessionEndReason::StreamFailed(_)),
            "{reason:?}"
        );
        assert!(open.find(identity, station_id).is_none());
    }

    // Guards moved here from the serve tests with the signature check itself:
    // a CALL that isn't signed by the caller it names never reaches serving
    // and gets no reply, as in macula_station_link.erl's on_inbound_call/3.

    #[tokio::test]
    async fn an_inbound_call_not_signed_by_its_caller_is_dropped() {
        let (channel, mut station, _ended) = connect();

        station
            .send_inbound_call("app/forged", Signer::Other(Box::new(KeyPair::generate())))
            .await;
        station
            .send_inbound_call("app/genuine", Signer::Caller)
            .await;

        let served = tokio::time::timeout(WAIT, channel.next_inbound_call())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(served.procedure, "app/genuine");
        assert_eq!(channel.unrouted_frame_counts().get("call"), Some(&1));
    }

    #[tokio::test]
    async fn an_unsigned_inbound_call_is_dropped() {
        let (channel, mut station, _ended) = connect();

        station
            .send_inbound_call("app/unsigned", Signer::Nobody)
            .await;
        station
            .send_inbound_call("app/genuine", Signer::Caller)
            .await;

        let served = tokio::time::timeout(WAIT, channel.next_inbound_call())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(served.procedure, "app/genuine");
        assert_eq!(channel.unrouted_frame_counts().get("call"), Some(&1));
    }

    #[test]
    fn a_topic_pattern_matches_by_whole_segments() {
        assert!(topic_matches("app/orders", "app/orders"));
        assert!(topic_matches("app/*/placed", "app/orders/placed"));
        assert!(!topic_matches("app/*/placed", "app/orders/eu/placed"));
        assert!(!topic_matches("app/*", "app"));
        assert!(!topic_matches("app/orders", "app/order"));
    }
}
