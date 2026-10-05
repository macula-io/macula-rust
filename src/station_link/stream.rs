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

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use crate::cbor::{self, Value};
use crate::frame::{
    self, RequestSpec, StreamEncoding, StreamFields, StreamMode, StreamRole, StreamState,
    VerifiedRequest,
};

use super::admission::{Admission, SessionPlace, Verdict};
use super::confidential::{
    sealed_request, stated, unsealed, Seal, StreamSeal, CODE_SEALED_REFUSED, NO_KEY_DETAIL,
};
use super::framing::{read_frame, FrameWriter, MAX_FRAME_BYTES};
use super::serve::{bounded_detail, BoxFuture, StreamOffer, CODE_REQUEST_COPY};
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
    inner: Arc<StreamInner>,
}

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
    open: VerifiedRequest,
    caller: bool,
    /// This side's keys when the stream is sealed.
    sealing: Option<StreamSeal>,
    /// Orders a frame's seq with its write.
    send_seq: tokio::sync::Mutex<u64>,
    state: Mutex<StreamSide>,
    budget: Mutex<Option<Budget>>,
    notify: Notify,
    done_tx: watch::Sender<bool>,
}

#[derive(Default)]
struct StreamSide {
    /// This side sent its last frame, or will send no more.
    sent_end: bool,
    /// The peer sent its last frame.
    peer_ended: bool,
    inbox: VecDeque<(StreamEvent, usize)>,
    held: usize,
    ended: bool,
    err: Option<LinkError>,
}

impl Stream {
    /// The stream's verified STREAM_OPEN: its caller, procedure, mode and
    /// payload.
    pub fn request(&self) -> &VerifiedRequest {
        &self.inner.open
    }

    /// Sends a raw chunk.
    pub async fn send(&self, body: &[u8]) -> Result<(), LinkError> {
        self.inner
            .send(
                |seq| StreamFields::Data {
                    seq,
                    encoding: StreamEncoding::Raw,
                    body: Value::Bytes(body.to_vec()),
                },
                false,
            )
            .await
    }

    /// Sends a structured chunk.
    pub async fn send_value(&self, v: Value) -> Result<(), LinkError> {
        self.inner
            .send(
                |seq| StreamFields::Data {
                    seq,
                    encoding: StreamEncoding::Msgpack,
                    body: v.clone(),
                },
                false,
            )
            .await
    }

    /// Ends this side's sending; the peer may still send.
    pub async fn close_send(&self) -> Result<(), LinkError> {
        self.inner
            .send(
                |seq| StreamFields::End {
                    seq,
                    role: StreamRole::Send,
                },
                true,
            )
            .await
    }

    /// Ends the stream on both sides.
    pub async fn close(&self) -> Result<(), LinkError> {
        let sent = self
            .inner
            .send(
                |seq| StreamFields::End {
                    seq,
                    role: StreamRole::Both,
                },
                true,
            )
            .await;
        StreamInner::end(&self.inner, None);
        sent
    }

    /// Sends the provider's terminal value and ends the stream.
    pub async fn reply(&self, payload: Value) -> Result<(), LinkError> {
        let sent = self
            .inner
            .send(
                |seq| StreamFields::Reply {
                    seq,
                    payload: payload.clone(),
                },
                true,
            )
            .await;
        StreamInner::end(&self.inner, None);
        sent
    }

    /// Ends the stream with a STREAM_ERROR of `code` and `message`.
    pub async fn abort(&self, code: &str, message: &str) -> Result<(), LinkError> {
        self.inner.abort(code, message).await
    }

    /// The next frame the peer sent. After the stream ends, once every event
    /// before it is read, it returns [`LinkError::EndOfStream`] for a normal
    /// end and the error that ended it otherwise.
    pub async fn recv(&self) -> Result<StreamEvent, LinkError> {
        loop {
            let notified = self.inner.notify.notified();
            {
                let mut side = self.inner.side();
                if let Some((event, size)) = side.inbox.pop_front() {
                    side.held -= size;
                    drop(side);
                    self.inner.release_inbox(size);
                    return Ok(event);
                }
                if side.ended {
                    return Err(side.err.clone().unwrap_or(LinkError::EndOfStream));
                }
            }
            notified.await;
        }
    }

    /// Waits until the stream has ended and been released, and says why:
    /// `None` for a normal end.
    pub async fn done(&self) -> Option<LinkError> {
        let mut done = self.inner.done_tx.subscribe();
        let _ = done.wait_for(|ended| *ended).await;
        self.inner.side().err.clone()
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
        })
    }

    fn side(&self) -> MutexGuard<'_, StreamSide> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn budget(&self) -> MutexGuard<'_, Option<Budget>> {
        self.budget.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Signs the fields `at(seq)` builds at this side's next seq and writes
    /// them; `last` marks this side's last frame, after which its QUIC
    /// direction is finished.
    async fn send(
        self: &Arc<Self>,
        at: impl FnOnce(u64) -> StreamFields,
        last: bool,
    ) -> Result<(), LinkError> {
        let mut seq = self.send_seq.lock().await;
        if self.side().sent_end {
            return Err(LinkError::StreamClosed);
        }
        let fields = match &self.sealing {
            Some(sealing) => sealing.sealed(at(*seq))?,
            None => at(*seq),
        };
        let signed = if self.caller {
            frame::sign_caller_stream(&fields, &self.open, &self.link.key)?
        } else {
            frame::sign_provider_stream(&fields, &self.open, &self.link.key)?
        };
        let encoded = cbor::encode(&signed)
            .map_err(|e| LinkError::Frame(frame::FrameError::Payload(e.to_string())))?;
        if let Err(e) = self.writer.write(&encoded, MAX_FRAME_BYTES).await {
            self.side().sent_end = true;
            return Err(e);
        }
        *seq += 1;
        if last {
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
        Ok(())
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
        StreamInner::end(
            self,
            Some(LinkError::Stream {
                code: code.to_string(),
                message: message.to_string(),
                relay: false,
            }),
        );
        sent
    }

    /// Queues `event` for recv, refusing it when it would take the inbox, or
    /// the node's budget for served streams, past its bound.
    fn deliver(&self, event: StreamEvent, size: usize) -> bool {
        {
            let mut side = self.side();
            if side.held + size > STREAM_INBOX {
                return false;
            }
            if let Some(budget) = &*self.budget() {
                if !budget.admission.charge_inbox(budget.caller, size) {
                    return false;
                }
            }
            side.inbox.push_back((event, size));
            side.held += size;
        }
        self.notify.notify_one();
        true
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
        let graceful = {
            let mut side = this.side();
            if side.ended {
                return;
            }
            side.ended = true;
            if side.err.is_none() {
                side.err = err;
            }
            let graceful = side.sent_end;
            side.sent_end = true;
            graceful
        };
        if !graceful {
            let released = this.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { released.writer.reset().await });
            }
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
        let (sealed, sealing) = match &c.seal {
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
                (Some(sealed), Some(StreamSeal::caller(&s)))
            }
            _ => (None, None),
        };
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
        tokio::spawn(read(s.clone(), recv, state));
        Ok(Stream { inner: s })
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
    let payload = match tokio::time::timeout(
        STREAM_OPEN_WAIT,
        read_frame(&mut recv, STREAM_OPEN_BYTES),
    )
    .await
    {
        Ok(Ok(payload)) => payload,
        _ => {
            inner.count("stream_open_unread");
            abandon(send, recv);
            return;
        }
    };
    let v = match cbor::decode(&payload) {
        Ok(v) if frame_type_of(&v) == "stream_open" => v,
        _ => {
            inner.count("stream_open_malformed");
            abandon(send, recv);
            return;
        }
    };
    let Ok(open) = frame::verify_request(&v, inner.profile) else {
        inner.count("stream_open_unverified");
        abandon(send, recv);
        return;
    };
    if open.target != inner.self_id {
        inner.count("stream_for_another_node");
        abandon(send, recv);
        return;
    }
    let Ok(state) = frame::open_stream(&open) else {
        abandon(send, recv);
        return;
    };
    let s = StreamInner::new(inner.clone(), send, open.clone(), false, None);
    let offer = match admit_stream(&inner, &open) {
        Ok(offer) => offer,
        Err(code) => return refuse(&s, code, "", recv).await,
    };
    // This node opens no sealed payload: a sealed open is refused, never
    // served on a payload it cannot read.
    if open.sealed.is_some() {
        return refuse(&s, CODE_SEALED_REFUSED, NO_KEY_DETAIL, recv).await;
    }
    let Some(place) = inner.admission.open_session(open.caller) else {
        return refuse(&s, CODE_TOO_MANY_SESSIONS, "", recv).await;
    };
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

/// Judges an open as macula's link does, in its order: the admission (one
/// run per request, the deadline window, its bounds), the procedure served
/// here as a stream, and its mode. The offer, or the code to refuse with.
fn admit_stream(inner: &Inner, open: &VerifiedRequest) -> Result<StreamOffer, &'static str> {
    match inner.admission.admit(open, &inner.share, now_ms()) {
        Verdict::Refused(code) => return Err(code),
        Verdict::Copy(_) => return Err(CODE_REQUEST_COPY),
        Verdict::New => {}
    }
    let state = inner.lock();
    let offer = state
        .served
        .get(&(open.realm, open.procedure.clone()))
        .and_then(|s| s.offer.stream.clone())
        .ok_or(CODE_STREAM_NOT_FOUND)?;
    if Some(offer.mode) != open.mode {
        return Err(CODE_MODE_MISMATCH);
    }
    Ok(offer)
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
        match frame::verify_relay_error(&v, &s.open, s.link.profile, &s.link.station.node_id) {
            Ok(relayed) => s.peer_finished(Some(LinkError::Stream {
                code: relayed.code,
                message: String::new(),
                relay: true,
            })),
            Err(e) => s.fail("malformed_frame", Some(e.to_string())).await,
        }
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
    match fields {
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
