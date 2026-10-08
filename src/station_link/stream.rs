//! Streaming RPC, as macula 12's link does it. Each session has a QUIC stream
//! of its own: the caller opens it with a signed STREAM_OPEN naming its mode,
//! the station opens one of its own to the provider and relays between them.
//! After the open, each side sends frames signed by its own key (the
//! provider's under MACULA-PQ-STREAM-V1, the caller's under
//! MACULA-PQ-CALLER-STREAM-V1), each numbered from 0 on its side and bound to
//! the open's request hash.
//!
//! A stream is released, both its QUIC directions finished, on every path:
//! when it ends normally, when either side aborts or refuses it, when its
//! inbox is over its bound, when its link ends, and when an open or an
//! accepted stream fails before a session exists. The bounds are macula
//! 12.3.0's: an open of at most 1 MiB, read within 10 seconds of a stream
//! being opened to the provider, and at most 16 MiB of a stream's frames
//! received and not yet read.
//!
//! A caller's sealed stream a pool opened reopens itself once when the
//! provider refuses its open sealed_refused before this side has sent
//! anything, after the provider's KEM key rotated: sealed to the key the
//! refusal names, on a new session, behind the same handle; never in the
//! clear (macula's stream reseal, E2E design Amendment A1, macula-rust#21).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use crate::cbor::{self, Value};
use crate::frame::{
    self, RequestSpec, StreamEncoding, StreamFields, StreamMode, StreamRole, StreamState,
    VerifiedRequest,
};
use crate::seal::KEY_ID_SIZE;

use super::admission::{Admission, SessionPlace, Verdict};
use super::authorize::authorize;
use super::confidential::{
    clear_allowed, opened_request, refused_key, sealed_request, stated, unsealed, Seal, StreamSeal,
    CODE_SEALED_REFUSED, CODE_SEALED_REQUIRED,
};
use super::framing::{read_frame, FrameWriter, MAX_FRAME_BYTES};
use super::serve::{
    bounded_detail, without_caller, BoxFuture, Offer, StreamOffer, CODE_REQUEST_COPY,
};
use super::{frame_type_of, now_ms, Inner, Link, LinkError};

const STREAM_OPEN_BYTES: usize = 1024 * 1024;
const STREAM_OPEN_WAIT: Duration = Duration::from_secs(10);
const STREAM_INBOX: usize = 16 * 1024 * 1024;

/// How far ahead a STREAM_OPEN's deadline lies when its [`StreamCall`] names
/// none, as macula's default.
pub const DEFAULT_STREAM_DEADLINE: Duration = Duration::from_secs(30);

/// The refusal codes of a STREAM_OPEN, besides the admission's own, as
/// macula's refuse_open sends them, and the code of a failed handler.
const CODE_STREAM_NOT_FOUND: &str = "not_found";
const CODE_MODE_MISMATCH: &str = "mode_mismatch";
const CODE_TOO_MANY_SESSIONS: &str = "too_many_sessions";
const CODE_STREAM_HANDLER_ERROR: &str = "error";

/// Serves one streaming session. When it returns `Ok` and has not ended the
/// stream, the stream is closed on both sides; an `Err` or a panic aborts it
/// with code `error` and the error's text, as macula aborts a stream whose
/// handler failed. A handler still running when its stream ends is dropped.
pub type StreamHandler = Arc<dyn Fn(Stream) -> BoxFuture<Result<(), String>> + Send + Sync>;

/// A [`StreamHandler`] from an async closure.
pub fn stream_handler<F, Fut>(f: F) -> StreamHandler
where
    F: Fn(Stream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    Arc::new(move |s| Box::pin(f(s)))
}

/// A streaming session to open: the realm and procedure, the provider it
/// targets, the mode, the open's payload, how far ahead its deadline lies
/// ([`DEFAULT_STREAM_DEADLINE`] when zero), a UCAN and its proofs for a gated
/// procedure, and how it is kept, which an open must state as a call does
/// (see [`super::Call`]). Its default mode is server_stream.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamCall {
    pub realm: [u8; 32],
    pub procedure: String,
    pub target: [u8; 32],
    pub mode: StreamMode,
    pub payload: Value,
    pub deadline: Duration,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub seal: Option<Seal>,
}

impl Default for StreamCall {
    fn default() -> Self {
        StreamCall {
            realm: [0; 32],
            procedure: String::new(),
            target: [0; 32],
            mode: StreamMode::ServerStream,
            payload: Value::Map(Vec::new()),
            deadline: Duration::ZERO,
            token: None,
            proofs: Vec::new(),
            seal: None,
        }
    }
}

/// One frame the peer sent, verified: a chunk, the peer's end (role `Send`
/// ends its sending only, `Both` the stream), or the provider's terminal
/// value.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    Data {
        encoding: StreamEncoding,
        body: Value,
    },
    End {
        role: StreamRole,
    },
    Reply {
        payload: Value,
    },
}

/// One streaming session, on either side. Cloning it shares the session.
#[derive(Clone)]
pub struct Stream {
    pub(super) inner: Arc<StreamInner>,
}

/// What a caller's sealed stream runs, once, when its open is refused
/// sealed_refused before it has sent anything: given the key id the refusal
/// names (`None` for none), the stream reopened sealed to that key, or why
/// there is none. It never opens in the clear.
pub(crate) type Reseal = Box<
    dyn FnOnce(
            Option<[u8; KEY_ID_SIZE]>,
        ) -> Pin<Box<dyn Future<Output = Result<Stream, LinkError>> + Send>>
        + Send,
>;

/// What a served stream's inbox holds is charged to its caller's budget in
/// the node's admission, and the session holds its place there.
struct Budget {
    admission: Arc<Admission>,
    caller: [u8; 32],
    place: Option<SessionPlace>,
}

pub(super) struct StreamInner {
    link: Arc<Inner>,
    writer: FrameWriter,
    pub(super) open: VerifiedRequest,
    pub(super) caller: bool,
    /// This side's keys when the stream is sealed.
    pub(super) sealing: Option<StreamSeal>,
    /// Orders a frame's seq with its write.
    send_seq: tokio::sync::Mutex<u64>,
    state: Mutex<StreamSide>,
    budget: Mutex<Option<Budget>>,
    notify: Notify,
    done_tx: watch::Sender<bool>,
    /// A caller's sealed stream's one reseal, until it is spent.
    reseal: Mutex<Option<Reseal>>,
}

#[derive(Default)]
pub(super) struct StreamSide {
    /// The reseal is running: this session reads and writes no more.
    reopening: bool,
    /// The session the stream reopened on, which carries it from now on.
    successor: Option<Arc<StreamInner>>,
    /// This side sent its last frame, or will send no more.
    sent_end: bool,
    /// The peer sent its last frame.
    peer_ended: bool,
    inbox: VecDeque<(StreamEvent, usize)>,
    held: usize,
    ended: bool,
    err: Option<LinkError>,
    /// A caller's seal report has settled (see [`Stream::report`]).
    pub(super) settled: bool,
}

impl Stream {
    /// The stream's verified STREAM_OPEN: its caller, procedure, mode and
    /// payload. On a provider's side of a sealed stream the payload is the
    /// open's opened plaintext, and on a provider's side a map payload has
    /// no text "caller" key: the caller is `caller`, as verified.
    pub fn request(&self) -> &VerifiedRequest {
        &self.inner.open
    }

    /// Whether the stream is sealed end to end: every chunk, reply and
    /// error after the open travels sealed.
    pub fn sealed(&self) -> bool {
        self.inner.sealing.is_some()
    }

    /// Sends a raw chunk.
    pub async fn send(&self, body: &[u8]) -> Result<(), LinkError> {
        let at = |seq| StreamFields::Data {
            seq,
            encoding: StreamEncoding::Raw,
            body: Value::Bytes(body.to_vec()),
        };
        self.sent(at, false).await.1
    }

    /// Sends a structured chunk.
    pub async fn send_value(&self, v: Value) -> Result<(), LinkError> {
        let at = |seq| StreamFields::Data {
            seq,
            encoding: StreamEncoding::Msgpack,
            body: v.clone(),
        };
        self.sent(at, false).await.1
    }

    /// Ends this side's sending; the peer may still send.
    pub async fn close_send(&self) -> Result<(), LinkError> {
        let at = |seq| StreamFields::End {
            seq,
            role: StreamRole::Send,
        };
        self.sent(at, true).await.1
    }

    /// Ends the stream on both sides.
    pub async fn close(&self) -> Result<(), LinkError> {
        let at = |seq| StreamFields::End {
            seq,
            role: StreamRole::Both,
        };
        let (inner, sent) = self.sent(at, true).await;
        StreamInner::end(&inner, None);
        sent
    }

    /// Sends the provider's terminal value and ends the stream.
    pub async fn reply(&self, payload: Value) -> Result<(), LinkError> {
        let at = |seq| StreamFields::Reply {
            seq,
            payload: payload.clone(),
        };
        let (inner, sent) = self.sent(at, true).await;
        StreamInner::end(&inner, None);
        sent
    }

    /// Ends the stream with a STREAM_ERROR of `code` and `message`.
    pub async fn abort(&self, code: &str, message: &str) -> Result<(), LinkError> {
        let at = |seq| StreamFields::Error {
            seq,
            code: code.to_string(),
            message: message.to_string(),
        };
        let (inner, sent) = self.sent(at, true).await;
        StreamInner::end(&inner, Some(aborted(code, message)));
        sent
    }

    /// The next frame the peer sent. After the stream ends, once every event
    /// before it is read, it returns [`LinkError::EndOfStream`] for a normal
    /// end and the error that ended it otherwise.
    pub async fn recv(&self) -> Result<StreamEvent, LinkError> {
        loop {
            let inner = self.live().await;
            let notified = inner.notify.notified();
            match inner.next_event() {
                Some(outcome) => return outcome,
                None => notified.await,
            }
        }
    }

    /// Waits until the stream has ended and been released, and says why:
    /// `None` for a normal end.
    pub async fn done(&self) -> Option<LinkError> {
        let mut inner = self.live().await;
        while !inner.released().await {
            inner = self.live().await;
        }
        let err = inner.side().err.clone();
        err
    }

    /// The fields `at` builds, sent on the session that carries the stream
    /// now, and that session.
    async fn sent(
        &self,
        at: impl Fn(u64) -> StreamFields,
        last: bool,
    ) -> (Arc<StreamInner>, Result<(), LinkError>) {
        let mut inner = self.live().await;
        let mut sent = inner.send_here(&at, last).await;
        while sent.is_none() {
            inner = self.live().await;
            sent = inner.send_here(&at, last).await;
        }
        (inner, sent.unwrap_or(Err(LinkError::StreamClosed)))
    }

    /// The session that carries the stream: the one it opened on, or the
    /// one it reopened on after a reseal, waited for while the reseal runs.
    async fn live(&self) -> Arc<StreamInner> {
        let mut at = self.current();
        while at.side().reopening {
            at.reopen_awaited().await;
            at = self.current();
        }
        at
    }

    /// The session that carries the stream now, without waiting.
    pub(super) fn current(&self) -> Arc<StreamInner> {
        let mut at = self.inner.clone();
        loop {
            let next = at.side().successor.clone();
            match next {
                Some(next) => at = next,
                None => return at,
            }
        }
    }
}

/// The error a stream this side aborted ends with.
fn aborted(code: &str, message: &str) -> LinkError {
    LinkError::Stream {
        code: code.to_string(),
        message: message.to_string(),
        relay: false,
    }
}

impl StreamInner {
    fn new(
        link: Arc<Inner>,
        send: quinn::SendStream,
        open: VerifiedRequest,
        caller: bool,
        sealing: Option<StreamSeal>,
    ) -> Arc<StreamInner> {
        Arc::new(StreamInner {
            link,
            writer: FrameWriter::new(send),
            open,
            caller,
            sealing,
            send_seq: tokio::sync::Mutex::new(0),
            state: Mutex::new(StreamSide::default()),
            budget: Mutex::new(None),
            notify: Notify::new(),
            done_tx: watch::channel(false).0,
            reseal: Mutex::new(None),
        })
    }

    pub(super) fn side(&self) -> MutexGuard<'_, StreamSide> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn budget(&self) -> MutexGuard<'_, Option<Budget>> {
        self.budget.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The inbox's next event, its room given back; once the stream has
    /// ended and nothing is queued, why it ended ([`LinkError::EndOfStream`]
    /// for a normal end); `None` while there is nothing yet.
    fn next_event(&self) -> Option<Result<StreamEvent, LinkError>> {
        let mut side = self.side();
        if let Some((event, size)) = side.inbox.pop_front() {
            side.held -= size;
            drop(side);
            self.release_inbox(size);
            return Some(Ok(event));
        }
        if side.ended {
            return Some(Err(side.err.clone().unwrap_or(LinkError::EndOfStream)));
        }
        None
    }

    /// Signs the fields `at(seq)` builds at this side's next seq and writes
    /// them; `last` marks this side's last frame, after which its QUIC
    /// direction is finished. On a sealed stream the seq is spent before
    /// anything is sealed under it: a frame that then fails to go out ends
    /// this side's sending, so nothing is ever sealed twice under one
    /// (key, seq).
    async fn send(
        self: &Arc<Self>,
        at: impl FnOnce(u64) -> StreamFields,
        last: bool,
    ) -> Result<(), LinkError> {
        let seq = self.send_seq.lock().await;
        self.send_at(seq, at, last).await
    }

    /// [`StreamInner::send`], unless a reseal has taken the stream off this
    /// session: then `None`, nothing sent, and the frame goes on the
    /// session it reopens on.
    async fn send_here(
        self: &Arc<Self>,
        at: &impl Fn(u64) -> StreamFields,
        last: bool,
    ) -> Option<Result<(), LinkError>> {
        let seq = self.send_seq.lock().await;
        if self.side().reopening || self.side().successor.is_some() {
            return None;
        }
        Some(self.send_at(seq, at, last).await)
    }

    async fn send_at(
        self: &Arc<Self>,
        mut seq: tokio::sync::MutexGuard<'_, u64>,
        at: impl FnOnce(u64) -> StreamFields,
        last: bool,
    ) -> Result<(), LinkError> {
        if self.side().sent_end {
            return Err(LinkError::StreamClosed);
        }
        let fields = at(*seq);
        let plain = match &self.sealing {
            Some(sealing) => sealing.plain_of(&fields)?,
            None => None,
        };
        let spent = plain.is_some();
        let fields = match (&self.sealing, plain) {
            (Some(sealing), Some(plain)) => {
                *seq += 1;
                let sealed = sealing.sealed(fields, plain);
                sealed.inspect_err(|_| self.side().sent_end = true)?
            }
            _ => fields,
        };
        let encoded = self
            .signed(&fields)
            .inspect_err(|_| self.unsent_after_spending(spent))?;
        if let Err(e) = self.writer.write(&encoded, MAX_FRAME_BYTES).await {
            self.side().sent_end = true;
            return Err(e);
        }
        if !spent {
            *seq += 1;
        }
        if last {
            self.sent_last().await;
        }
        Ok(())
    }

    /// Ends this side's sending when a frame that spent its seq did not go
    /// out, so nothing is ever sealed twice under one (key, seq).
    fn unsent_after_spending(&self, spent: bool) {
        if spent {
            self.side().sent_end = true;
        }
    }

    /// After this side's last frame: its QUIC direction finished, and the
    /// stream ended when the peer had ended too.
    async fn sent_last(self: &Arc<Self>) {
        let peer_ended = {
            let mut side = self.side();
            side.sent_end = true;
            side.peer_ended
        };
        self.writer.finish().await;
        if peer_ended {
            StreamInner::end(self, None);
        }
    }

    /// `fields` signed by this side's key and encoded.
    fn signed(&self, fields: &StreamFields) -> Result<Vec<u8>, LinkError> {
        let signed = if self.caller {
            frame::sign_caller_stream(fields, &self.open, &self.link.key)?
        } else {
            frame::sign_provider_stream(fields, &self.open, &self.link.key)?
        };
        cbor::encode(&signed)
            .map_err(|e| LinkError::Frame(frame::FrameError::Payload(e.to_string())))
    }

    async fn abort(self: &Arc<Self>, code: &str, message: &str) -> Result<(), LinkError> {
        let sent = self
            .send(
                |seq| StreamFields::Error {
                    seq,
                    code: code.to_string(),
                    message: message.to_string(),
                },
                true,
            )
            .await;
        StreamInner::end(self, Some(aborted(code, message)));
        sent
    }

    /// Waits until this session has ended and been released: true when the
    /// stream ended with it, false when it went on on a reopened session.
    async fn released(&self) -> bool {
        let mut done = self.done_tx.subscribe();
        let _ = done.wait_for(|ended| *ended).await;
        self.side().successor.is_none()
    }

    /// Returns once this session's reseal has ended, either way.
    async fn reopen_awaited(&self) {
        let notified = self.notify.notified();
        // Checked again once registered, so the reseal's end is not missed
        // between the two.
        if self.side().reopening {
            notified.await;
        }
    }

    fn reseal_slot(&self) -> MutexGuard<'_, Option<Reseal>> {
        self.reseal.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The provider refused the open sealed_refused, naming `detail`'s key:
    /// a caller's sealed stream holding its reseal, and that has sent
    /// nothing, starts it and reads no more on this session (true).
    /// Checked and marked under the send lock, so no frame goes out on this
    /// session after it. Otherwise the refusal ends the stream (false).
    async fn reopened(self: &Arc<Self>, detail: &str) -> bool {
        let Some(reseal) = self.reseal_slot().take() else {
            return false;
        };
        let seq = self.send_seq.lock().await;
        if *seq != 0 || self.side().sent_end {
            return false;
        }
        self.side().reopening = true;
        drop(seq);
        self.notify.notify_waiters();
        let s = self.clone();
        let named = refused_key(Some(detail));
        tokio::spawn(async move {
            let outcome = reseal(named).await;
            s.adopt(outcome);
        });
        true
    }

    /// Carries the stream on the session its reseal reopened, this one
    /// released; or ends it with why there is none.
    fn adopt(self: &Arc<Self>, outcome: Result<Stream, LinkError>) {
        let reopened = {
            let mut side = self.side();
            side.reopening = false;
            outcome.map(|next| side.successor = Some(next.inner))
        };
        match reopened {
            Ok(()) => StreamInner::end(self, None),
            Err(e) => self.peer_finished(Some(e)),
        }
        // Whatever waits on the reseal goes on, even when this session had
        // ended before (its link ended meanwhile), when end wakes nobody.
        self.notify.notify_waiters();
    }

    /// Queues `event` for recv, refusing it when it would take the inbox, or
    /// the node's budget for served streams, past its bound.
    fn deliver(&self, event: StreamEvent, size: usize) -> bool {
        if !self.queue(event, size) {
            return false;
        }
        self.notify.notify_one();
        true
    }

    /// Puts `event` in the inbox, unless it would take the inbox, or the
    /// node's budget for served streams, past its bound.
    fn queue(&self, event: StreamEvent, size: usize) -> bool {
        let mut side = self.side();
        if side.held + size > STREAM_INBOX {
            return false;
        }
        if !self.charge_inbox(size) {
            return false;
        }
        side.inbox.push_back((event, size));
        side.held += size;
        true
    }

    /// Charges `size` to a served stream's caller's inbox budget, and
    /// whether it fits; a stream with no budget always fits.
    fn charge_inbox(&self, size: usize) -> bool {
        let budget = self.budget();
        let Some(budget) = &*budget else {
            return true;
        };
        budget.admission.charge_inbox(budget.caller, size)
    }

    fn release_inbox(&self, size: usize) {
        if let Some(budget) = &*self.budget() {
            budget.admission.release_inbox(budget.caller, size);
        }
    }

    /// Ends the stream after the peer's last frame: this side sends no more,
    /// and `err` is why it ended, `None` for a normal end.
    fn peer_finished(self: &Arc<Self>, err: Option<LinkError>) {
        self.side().peer_ended = true;
        StreamInner::end(self, err);
    }

    /// Aborts the stream from this side for a fault it found in what the
    /// peer sent, or an inbox over its bound, telling the peer when it still
    /// can.
    async fn fail(self: &Arc<Self>, code: &str, cause: Option<String>) {
        let message = cause
            .as_deref()
            .map(bounded_detail)
            .unwrap_or("")
            .to_string();
        let _ = self.abort(code, &message).await;
    }

    /// Releases the stream once: its sending side finished after this side's
    /// last frame and reset otherwise, its reader stopped, what its inbox
    /// held and its session's place given back.
    pub(super) fn end(this: &Arc<StreamInner>, err: Option<LinkError>) {
        let Some(graceful) = this.mark_ended(err) else {
            return;
        };
        if !graceful {
            StreamInner::reset_sending(this);
        }
        if let Some(budget) = this.budget().take() {
            let held = std::mem::take(&mut this.side().held);
            budget.admission.release_inbox(budget.caller, held);
            drop(budget.place);
        }
        this.link
            .lock()
            .streams
            .retain(|w| w.strong_count() > 0 && !std::ptr::eq(w.as_ptr(), Arc::as_ptr(this)));
        let _ = this.done_tx.send_replace(true);
        this.notify.notify_waiters();
        this.notify.notify_one();
    }
}

impl StreamInner {
    /// Marks the stream ended, keeping `err` unless an error is kept
    /// already, and this side's sending with it; whether this side had sent
    /// its last frame, or `None` when the stream had ended before.
    fn mark_ended(&self, err: Option<LinkError>) -> Option<bool> {
        let mut side = self.side();
        if side.ended {
            return None;
        }
        side.ended = true;
        if side.err.is_none() {
            side.err = err;
        }
        let graceful = side.sent_end;
        side.sent_end = true;
        Some(graceful)
    }

    /// Resets this side's sending direction, on the runtime when there is
    /// one.
    fn reset_sending(this: &Arc<StreamInner>) {
        let released = this.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move { released.writer.reset().await });
    }
}

/// Keeps `s` among the link's streams, ended with the link; false once the
/// link has ended.
fn hold_stream(inner: &Inner, s: &Arc<StreamInner>) -> bool {
    let mut state = inner.lock();
    if state.ended.is_some() {
        return false;
    }
    state.streams.push(Arc::downgrade(s));
    true
}

/// Releases a QUIC stream no session holds, in both directions.
fn abandon(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let _ = send.reset(0u32.into());
    let _ = recv.stop(0u32.into());
}

impl Link {
    /// Opens a streaming session: a QUIC stream of its own, on which it
    /// writes the signed STREAM_OPEN. A stream it opens but cannot write the
    /// open on is released before the error returns.
    pub async fn open_stream(&self, c: StreamCall) -> Result<Stream, LinkError> {
        self.open_stream_resealing(c, None).await
    }

    /// [`Link::open_stream`], the stream holding `reseal` for a
    /// sealed_refused of its open (see the module's docs).
    pub(crate) async fn open_stream_resealing(
        &self,
        c: StreamCall,
        reseal: Option<Reseal>,
    ) -> Result<Stream, LinkError> {
        let inner = &self.inner;
        stated(&c.target, &inner.station.node_id, &c.seal)?;
        let deadline = if c.deadline.is_zero() {
            DEFAULT_STREAM_DEADLINE
        } else {
            c.deadline
        };
        let mut request_id = [0u8; 16];
        aws_lc_rs::rand::fill(&mut request_id)
            .map_err(|_| LinkError::Io("no randomness".into()))?;
        let deadline = (now_ms() + deadline.as_millis() as i64) as u64;
        let (sealed, sealing) = sealed_open(inner, &c, request_id, deadline)?;
        let signed = frame::sign_stream_open(
            &RequestSpec {
                request_id,
                realm: c.realm,
                procedure: c.procedure,
                target: c.target,
                deadline,
                payload: c.payload,
                sealed,
                mode: Some(c.mode),
                token: c.token,
                proofs: c.proofs,
                source_route: None,
                retry_budget: None,
            },
            &inner.key,
        )?;
        let encoded = cbor::encode(&signed)
            .map_err(|e| LinkError::Frame(frame::FrameError::Payload(e.to_string())))?;
        if encoded.len() > STREAM_OPEN_BYTES {
            return Err(LinkError::StreamOpenTooLarge(encoded.len()));
        }
        let open = frame::verify_request(&signed, inner.profile)?;
        let state = frame::open_stream(&open)?;
        let (send, recv) = inner
            .connection
            .open_bi()
            .await
            .map_err(|e| LinkError::Io(format!("open a stream: {e}")))?;
        let s = StreamInner::new(inner.clone(), send, open, true, sealing);
        let held = hold_stream(inner, &s);
        let written = match held {
            true => s.writer.write(&encoded, STREAM_OPEN_BYTES).await,
            false => Err(inner.lock().ended.clone().unwrap_or(LinkError::Closed)),
        };
        if let Err(e) = written {
            StreamInner::end(&s, Some(e.clone()));
            let mut recv = recv;
            let _ = recv.stop(0u32.into());
            return Err(e);
        }
        *s.reseal_slot() = reseal;
        tokio::spawn(read(s.clone(), recv, state));
        Ok(Stream { inner: s })
    }
}

/// The open's payload sealed to the key its seal names, with the caller's
/// keys for the stream; nothing when the stream goes clear.
fn sealed_open(
    inner: &Inner,
    c: &StreamCall,
    request_id: [u8; 16],
    deadline: u64,
) -> Result<(Option<frame::Sealed>, Option<StreamSeal>), LinkError> {
    match &c.seal {
        Some(Seal::To(key)) => {
            let (sealed, s) = sealed_request(
                inner.profile,
                key,
                crate::seal::FRAME_STREAM_OPEN,
                c.realm,
                &c.procedure,
                inner.self_id,
                c.target,
                request_id,
                deadline,
                &c.payload,
            )?;
            Ok((Some(sealed), Some(StreamSeal::caller(&s))))
        }
        _ => Ok((None, None)),
    }
}

/// Takes each stream the station opens to this link, until the link ends.
pub(super) async fn accept_streams(link: Weak<Inner>) {
    let Some(connection) = link.upgrade().map(|l| l.connection.clone()) else {
        return;
    };
    while let Ok((send, recv)) = connection.accept_bi().await {
        tokio::spawn(incoming(link.clone(), send, recv));
    }
}

/// Reads a stream's first frame within 10 seconds and starts the session it
/// opens, or refuses it. A stream that fails before a session exists is
/// released: one that does not deliver a STREAM_OPEN in time, whose first
/// frame is not one, that does not verify or targets another node is dropped
/// without a word, and one the provider refuses is told why at seq 0.
async fn incoming(link: Weak<Inner>, send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let Some(inner) = link.upgrade() else { return };
    let Some((open, state)) = read_open(&inner, &mut recv).await else {
        abandon(send, recv);
        return;
    };
    let offer = inner
        .lock()
        .served
        .get(&(open.realm, open.procedure.clone()))
        .map(|s| s.offer.clone());
    let refuse_clear = |code: &str, message: &str, send: quinn::SendStream, recv| {
        let s = StreamInner::new(inner.clone(), send, open.clone(), false, None);
        let (code, message) = (code.to_string(), message.to_string());
        async move { refuse(&s, &code, &message, recv).await }
    };
    // Before the open is opened, so a caller over its admission or at its
    // session cap costs no decapsulation: in the clear, from the closed set.
    let place = match admit_stream(&inner, &open) {
        Ok(place) => place,
        Err(code) => return refuse_clear(code, "", send, recv).await,
    };
    let (session_open, sealing) = match session_open(&inner, &open, offer.as_ref()) {
        Ok(opened) => opened,
        Err((code, message)) => return refuse_clear(code, &message, send, recv).await,
    };
    // From here a refusal of a sealed open goes sealed.
    let s = StreamInner::new(inner.clone(), send, session_open, false, sealing);
    let Some((offer, policy)) = offer.and_then(|o| Some((o.stream?, o.policy))) else {
        return refuse(&s, CODE_STREAM_NOT_FOUND, "", recv).await;
    };
    if let Some(code) = authorize(inner.profile, policy.as_ref(), &open) {
        return refuse(&s, code, "", recv).await;
    }
    if Some(offer.mode) != open.mode {
        return refuse(&s, CODE_MODE_MISMATCH, "", recv).await;
    }
    *s.budget() = Some(Budget {
        admission: inner.admission.clone(),
        caller: open.caller,
        place: Some(place),
    });
    if !hold_stream(&inner, &s) {
        StreamInner::end(&s, Some(LinkError::Closed));
        let _ = recv.stop(0u32.into());
        return;
    }
    tokio::spawn(read(s.clone(), recv, state));
    tokio::spawn(serve(s, offer));
}

/// Reads a stream's first frame within 10 seconds: its verified STREAM_OPEN
/// for this node and the verifier state it starts, or `None`, counted, when
/// the stream does not deliver one.
async fn read_open(
    inner: &Inner,
    recv: &mut quinn::RecvStream,
) -> Option<(VerifiedRequest, StreamState)> {
    let payload =
        match tokio::time::timeout(STREAM_OPEN_WAIT, read_frame(recv, STREAM_OPEN_BYTES)).await {
            Ok(Ok(payload)) => payload,
            _ => {
                inner.count("stream_open_unread");
                return None;
            }
        };
    let v = match cbor::decode(&payload) {
        Ok(v) if frame_type_of(&v) == "stream_open" => v,
        _ => {
            inner.count("stream_open_malformed");
            return None;
        }
    };
    let Ok(open) = frame::verify_request(&v, inner.profile) else {
        inner.count("stream_open_unverified");
        return None;
    };
    if open.target != inner.self_id {
        inner.count("stream_for_another_node");
        return None;
    }
    let state = frame::open_stream(&open).ok()?;
    Some((open, state))
}

/// The open as its session sees it, opened when it came sealed, with the
/// provider's keys for the stream; or the code and message to refuse it with
/// in the clear: a sealed open that does not open, or a clear one to a
/// procedure past its keyless window. A map payload loses a text "caller"
/// key (macula-rust#13), clear or opened.
fn session_open(
    inner: &Inner,
    open: &VerifiedRequest,
    offer: Option<&Offer>,
) -> Result<(VerifiedRequest, Option<StreamSeal>), (&'static str, String)> {
    match &open.sealed {
        Some(_) => opened_request(inner.keyring.as_deref(), open)
            .map(|(payload, sealed)| {
                (
                    VerifiedRequest {
                        payload: without_caller(payload),
                        ..open.clone()
                    },
                    Some(StreamSeal::provider(&sealed)),
                )
            })
            .map_err(|detail| (CODE_SEALED_REFUSED, detail)),
        None if offer
            .is_some_and(|o| !clear_allowed(o.confidential, inner.keyed_since(o), now_ms())) =>
        {
            let message = "this procedure takes sealed opens only";
            Err((CODE_SEALED_REQUIRED, message.to_string()))
        }
        None => Ok((
            VerifiedRequest {
                payload: without_caller(open.payload.clone()),
                ..open.clone()
            },
            None,
        )),
    }
}

/// Admits an open as macula's link does, before anything of it is opened:
/// one run per request, the deadline window and its bounds, then a place
/// among the caller's sessions. The place, or the code to refuse with.
fn admit_stream(inner: &Inner, open: &VerifiedRequest) -> Result<SessionPlace, &'static str> {
    match inner.admission.admit(open, &inner.share, now_ms()) {
        Verdict::Refused(code) => return Err(code),
        Verdict::Copy(_) => return Err(CODE_REQUEST_COPY),
        Verdict::New => {}
    }
    inner
        .admission
        .open_session(open.caller)
        .ok_or(CODE_TOO_MANY_SESSIONS)
}

/// Answers an open with a STREAM_ERROR of `code` and `message` at seq 0 and
/// releases the stream.
async fn refuse(s: &Arc<StreamInner>, code: &str, message: &str, mut recv: quinn::RecvStream) {
    s.link.count(&format!("stream_refused_{code}"));
    let _ = s.abort(code, message).await;
    let _ = recv.stop(0u32.into());
}

/// Runs the handler for the session, and ends the stream as the handler
/// leaves it: closed when it returns `Ok` without ending it, aborted with its
/// error or panic. A handler still running when the stream ends is dropped.
async fn serve(s: Arc<StreamInner>, offer: StreamOffer) {
    let stream = Stream { inner: s.clone() };
    let mut running = tokio::spawn((offer.handler)(stream.clone()));
    let mut done = s.done_tx.subscribe();
    let outcome = tokio::select! {
        outcome = &mut running => outcome,
        _ = done.wait_for(|ended| *ended) => {
            running.abort();
            return;
        }
    };
    match outcome {
        Ok(Ok(())) => {
            let _ = stream.close().await;
        }
        Ok(Err(e)) => {
            let _ = stream
                .abort(CODE_STREAM_HANDLER_ERROR, bounded_detail(&e))
                .await;
        }
        Err(panicked) => {
            let _ = stream
                .abort(
                    CODE_STREAM_HANDLER_ERROR,
                    bounded_detail(&panicked.to_string()),
                )
                .await;
        }
    }
}

/// Verifies the peer's frames until the stream ends. It is the stream's one
/// reader, the only holder of its verifier state; when it returns, its
/// receiving side is dropped, which stops it.
async fn read(s: Arc<StreamInner>, mut recv: quinn::RecvStream, mut state: StreamState) {
    let mut done = s.done_tx.subscribe();
    loop {
        let payload = tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            payload = read_frame(&mut recv, MAX_FRAME_BYTES) => payload,
        };
        let payload = match payload {
            Ok(payload) => payload,
            Err(e) => return read_ended(&s, e),
        };
        match received(&s, &payload, &state).await {
            Some(next) => state = next,
            None => return,
        }
    }
}

/// Ends a stream whose peer direction finished: after the peer's last frame
/// that is expected, and before it the stream was lost.
fn read_ended(s: &Arc<StreamInner>, e: LinkError) {
    if s.side().peer_ended {
        return;
    }
    let err = s.link.lock().ended.clone().unwrap_or(e);
    StreamInner::end(s, Some(err));
}

/// Handles one frame from the peer; the next verifier state, or `None` when
/// reading stops.
async fn received(
    s: &Arc<StreamInner>,
    payload: &[u8],
    state: &StreamState,
) -> Option<StreamState> {
    let v = match cbor::decode(payload) {
        Ok(v) => v,
        Err(e) => {
            s.fail("malformed_frame", Some(e.to_string())).await;
            return None;
        }
    };
    if s.caller && v.get("relay_error").is_some() {
        relay_failed(s, &v).await;
        return None;
    }
    let verified = if s.caller {
        frame::verify_provider_stream(&v, state, s.link.profile)
    } else {
        frame::verify_caller_stream(&v, state, s.link.profile)
    };
    let (verified, next) = match verified {
        Ok(verified) => verified,
        Err(e) => {
            s.fail("malformed_frame", Some(e.to_string())).await;
            return None;
        }
    };
    let size = payload.len();
    let fields = match unsealed(verified, s.sealing.as_ref()) {
        Ok(fields) => fields,
        Err(e) => {
            StreamInner::end(s, Some(e));
            return None;
        }
    };
    // Before the frame is delivered, so a recv that returns it sees the
    // report settled.
    if s.caller && settles(&fields, s.sealing.is_some()) {
        s.side().settled = true;
    }
    taken(s, fields, size, next).await
}

/// Ends a caller's stream on the station's relay error once it verifies, or
/// fails the stream on one that does not.
async fn relay_failed(s: &Arc<StreamInner>, v: &Value) {
    match frame::verify_relay_error(v, &s.open, s.link.profile, &s.link.station.node_id) {
        Ok(relayed) => s.peer_finished(Some(LinkError::Stream {
            code: relayed.code,
            message: String::new(),
            relay: true,
        })),
        Err(e) => s.fail("malformed_frame", Some(e.to_string())).await,
    }
}

/// Acts on one verified, unsealed frame of `size` bytes from the peer; the
/// next verifier state, or `None` when reading stops.
async fn taken(
    s: &Arc<StreamInner>,
    fields: StreamFields,
    size: usize,
    next: StreamState,
) -> Option<StreamState> {
    match fields {
        StreamFields::Error {
            seq: 0,
            ref code,
            ref message,
        } if s.caller && code == CODE_SEALED_REFUSED && s.reopened(message).await => None,
        StreamFields::Error { code, message, .. } => {
            s.peer_finished(Some(LinkError::Stream {
                code,
                message,
                relay: false,
            }));
            None
        }
        StreamFields::Reply { payload, .. } => {
            s.deliver(StreamEvent::Reply { payload }, size);
            s.peer_finished(None);
            None
        }
        StreamFields::End { role, .. } => {
            s.deliver(StreamEvent::End { role }, size);
            if role == StreamRole::Both {
                s.peer_finished(None);
                return None;
            }
            let mine = {
                let mut side = s.side();
                side.peer_ended = true;
                side.sent_end
            };
            if mine {
                StreamInner::end(s, None);
            }
            None
        }
        StreamFields::Data { encoding, body, .. } => {
            if !s.deliver(StreamEvent::Data { encoding, body }, size) {
                s.fail("resource_exhausted", None).await;
                return None;
            }
            Some(next)
        }
        // unsealed opens every sealed frame or refuses it.
        StreamFields::SealedData { .. }
        | StreamFields::SealedError { .. }
        | StreamFields::SealedReply { .. } => {
            StreamInner::end(s, Some(LinkError::ClearAnswerToSealed));
            None
        }
    }
}

/// Whether a provider's frame settles its caller's seal report: on a sealed
/// stream a data or reply frame, which [`unsealed`] returns only once it
/// opened under the stream's key; on a clear stream a data, reply or end
/// frame. A sealed stream's end travels clear and settles nothing, and no
/// error settles a stream.
fn settles(fields: &StreamFields, sealed: bool) -> bool {
    match fields {
        StreamFields::Data { .. } | StreamFields::Reply { .. } => true,
        StreamFields::End { .. } => !sealed,
        _ => false,
    }
}
