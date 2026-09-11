//! The CONNECT/HELLO handshake and the application-frame stream
//! abstraction, ported from `src/peering/macula_peering_conn.erl`
//! (`macula-io/macula`) — see `plans/PLAN_WIRE_PROTOCOL.md` §3.
//!
//! Only the client role's `connecting -> handshaking -> connected` path
//! is implemented. [`Session`] is the handshaked connection: one reader
//! routes every frame on its control stream, so calls, subscriptions and
//! serving run on it at the same time. [`FrameStream`] is the "send/receive
//! signed application frames on one QUIC stream" primitive that
//! [`Session::open_dedicated_stream`] hands out for content transfer (§12)
//! and streaming RPC (§13), which both run on dedicated streams rather than
//! the control stream.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::bolt4;
use crate::cbor::Value;
use crate::control_channel::{self, Channel};
use crate::frame::{self, Decoded, HelloInfo};
use crate::identity::KeyPair;
use crate::transport::{self, ConnectError, Trust};

pub use crate::control_channel::{
    CallError, RecvEventError, SendError, SessionEndReason, Subscription,
};

/// A boxed, `'static` future — hand-rolled rather than pulling in the
/// `futures` crate for one type alias.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Answers one inbound CALL. `Ok(payload)` sends a RESULT; `Err(reason)`
/// sends an ERROR (BOLT#4 `unknown_error`, `detail = reason`); a panic
/// inside the handler (caught via [`tokio::spawn`], the same "one
/// transient task per call" shape `macula_station_link.erl` uses one
/// process per call for) is sent as ERROR `temporary_relay_failure` —
/// matching that module's own `safe_invoke_handler/4` mapping exactly
/// (including sending no `detail` on a crash, since the reference
/// doesn't either — it only logs locally).
///
/// A map payload arrives with the caller's 32-byte node id under
/// `"caller"`: the caller the CALL's signature was verified against,
/// replacing any `"caller"` the sender put in the payload. A payload that
/// isn't a map arrives unchanged and carries no caller.
pub type CallHandler =
    Arc<dyn Fn(Value) -> BoxFuture<'static, Result<Value, String>> + Send + Sync>;

/// Matches `HANDSHAKE_TIMEOUT_MS` in `macula_peering_conn.erl`: CONNECT
/// -> HELLO is sub-second on a healthy peer; this is generous. The most
/// common real-world trigger for hitting it is a protocol version
/// mismatch — bytes accumulate but never form a valid frame, so the
/// station-side symptom and this crate's symptom are the same shape.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for a single CALL awaiting its RESULT/ERROR. Not from
/// the reference source (macula's own CALL timeout is caller-supplied
/// per-call via `deadline_ms` inside the frame itself, not a transport-
/// level default) — a reasonable local default for this crate's API.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on a single read from a QUIC stream while accumulating a frame.
/// Not a protocol limit — just how much to ask the stream for at once;
/// `frame::decode`'s own `MAX_FRAME_BYTES` is the real cap.
const READ_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------
// FrameStream — send/receive signed application frames on one dedicated
// QUIC stream (content transfer, streaming RPC).
// ---------------------------------------------------------------------

pub struct FrameStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Bytes read but not yet consumed by a decoded frame — carried
    /// over between reads so nothing is ever dropped.
    buf: Vec<u8>,
}

#[derive(Debug)]
pub enum SendFrameError {
    Encode(frame::EncodeFrameError),
    Write(quinn::WriteError),
}

impl std::fmt::Display for SendFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendFrameError::Encode(e) => write!(f, "encoding frame: {e}"),
            SendFrameError::Write(e) => write!(f, "writing to stream: {e}"),
        }
    }
}

impl std::error::Error for SendFrameError {}

#[derive(Debug)]
pub enum RecvFrameError {
    Read(quinn::ReadError),
    StreamClosed,
    Decode(frame::DecodeFrameError),
    Timeout,
}

impl std::fmt::Display for RecvFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvFrameError::Read(e) => write!(f, "reading from stream: {e}"),
            RecvFrameError::StreamClosed => write!(f, "peer closed the stream"),
            RecvFrameError::Decode(e) => write!(f, "decoding a frame: {e}"),
            RecvFrameError::Timeout => write!(f, "timed out waiting for a frame"),
        }
    }
}

impl std::error::Error for RecvFrameError {}

/// Why a CALL on a dedicated stream got no reply.
#[derive(Debug)]
pub enum StreamCallError {
    Send(SendFrameError),
    Recv(RecvFrameError),
}

impl std::fmt::Display for StreamCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamCallError::Send(e) => write!(f, "sending CALL: {e}"),
            StreamCallError::Recv(e) => write!(f, "awaiting RESULT/ERROR: {e}"),
        }
    }
}

impl std::error::Error for StreamCallError {}

impl FrameStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            buf: Vec::new(),
        }
    }

    /// Any bytes already read past the last decoded frame.
    pub fn leftover_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Aborts both halves with `code`, writing nothing: RESET_STREAM on the
    /// send half and STOP_SENDING on the receive half. Stopping has to be
    /// explicit, since a receive half dropped unread sends STOP_SENDING with
    /// code 0.
    pub(crate) fn abort_both(mut self, code: u32) {
        let code = quinn::VarInt::from_u32(code);
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
    }

    /// Finishes the send half, so what was written still reaches the peer,
    /// and stops the receive half with `code`.
    pub(crate) fn finish_and_stop_reading(mut self, code: u32) {
        let _ = self.send.finish();
        let _ = self.recv.stop(quinn::VarInt::from_u32(code));
    }

    pub async fn send_frame(&mut self, frame: Value) -> Result<(), SendFrameError> {
        let encoded = frame::encode(&frame).map_err(SendFrameError::Encode)?;
        self.send
            .write_all(&encoded)
            .await
            .map_err(SendFrameError::Write)
    }

    /// Read the next complete application frame, using (and updating)
    /// any bytes already buffered.
    pub async fn recv_frame(&mut self) -> Result<Value, RecvFrameError> {
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            match frame::decode(&self.buf) {
                Ok(Decoded::Frame(value, consumed)) => {
                    self.buf.drain(..consumed);
                    return Ok(value);
                }
                Ok(Decoded::More(_)) => {}
                Err(e) => return Err(RecvFrameError::Decode(e)),
            }
            let n = self
                .recv
                .read(&mut chunk)
                .await
                .map_err(RecvFrameError::Read)?
                .ok_or(RecvFrameError::StreamClosed)?;
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// As [`recv_frame`](Self::recv_frame), bounded by `timeout`.
    pub async fn recv_frame_timeout(&mut self, timeout: Duration) -> Result<Value, RecvFrameError> {
        tokio::time::timeout(timeout, self.recv_frame())
            .await
            .unwrap_or(Err(RecvFrameError::Timeout))
    }

    /// Send a signed CALL for `procedure` and wait for the matching
    /// RESULT or ERROR, correlated by `call_id`. A dedicated stream carries
    /// only its own exchange, so a frame with another `call_id` is skipped.
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, StreamCallError> {
        let call_id: [u8; 16] = rand::random();
        let spec = frame::CallSpec::new(
            call_id,
            procedure,
            realm,
            payload,
            deadline_ms,
            identity.node_id(),
        );
        let signed = frame::sign(frame::call(&spec), identity);
        self.send_frame(signed)
            .await
            .map_err(StreamCallError::Send)?;

        tokio::time::timeout(timeout, self.await_call_response(call_id))
            .await
            .unwrap_or(Err(StreamCallError::Recv(RecvFrameError::Timeout)))
    }

    /// As [`call`](Self::call), additionally attaching `ucan_token` to the
    /// outgoing CALL frame — for invoking a procedure gated by a
    /// [`crate::ucan::Policy::required`] policy. A procedure that isn't
    /// gated ignores the token; one that is checks it (see
    /// [`Session::serve_one_call_gated`]) before ever running its
    /// handler, so an invalid/missing token comes back as a BOLT#4
    /// `unauthorized` error frame, not a Rust error from this call.
    ///
    /// One parameter over [`call`](Self::call)'s own count, for the one
    /// new thing this adds — same reasoning
    /// [`crate::direct_dial::keep_advertised_direct`] already gives for
    /// its own allow.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_with_ucan(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
        ucan_token: Vec<u8>,
    ) -> Result<frame::CallResponse, StreamCallError> {
        let call_id: [u8; 16] = rand::random();
        let mut spec = frame::CallSpec::new(
            call_id,
            procedure,
            realm,
            payload,
            deadline_ms,
            identity.node_id(),
        );
        spec.ucan_token = ucan_token;
        let signed = frame::sign(frame::call(&spec), identity);
        self.send_frame(signed)
            .await
            .map_err(StreamCallError::Send)?;

        tokio::time::timeout(timeout, self.await_call_response(call_id))
            .await
            .unwrap_or(Err(StreamCallError::Recv(RecvFrameError::Timeout)))
    }

    async fn await_call_response(
        &mut self,
        call_id: [u8; 16],
    ) -> Result<frame::CallResponse, StreamCallError> {
        loop {
            let value = self.recv_frame().await.map_err(StreamCallError::Recv)?;
            if frame::frame_call_id(&value) != Some(call_id) {
                continue;
            }
            if let Ok(response) = frame::parse_call_response(&value) {
                return Ok(response);
            }
            // Matching call_id but not a result/error shape: keep
            // waiting rather than erroring, since nothing else in the
            // protocol is expected to carry this call's id.
        }
    }
}

// ---------------------------------------------------------------------
// Session — the handshaked connection. One reader routes every frame on
// its control stream, and writers take turns: see control_channel.rs.
// ---------------------------------------------------------------------

/// A completed, handshaked connection to a macula-station, and a handle to
/// it: clones share the one connection. Calls, subscriptions and serving
/// run on it at the same time, because one reader routes every frame on its
/// control stream to whatever waits for it: a RESULT or ERROR to its call,
/// an EVENT to each matching [`Subscription`], and an inbound CALL signed by
/// its caller to a queue of 64. GOODBYE, HELLO or CONNECT after the
/// handshake, a frame that can't be decoded, or a write that stalls past
/// the 30 second send timeout ends the session; every later operation then
/// reports [`SessionEndReason`], the connection closes, and the end is
/// logged once through the `log` facade. Other frames nothing waits for are
/// counted ([`unrouted_frame_counts`](Self::unrouted_frame_counts)).
///
/// **Always call [`close`](Self::close) before the last handle goes out of
/// scope, not just after your own logic is done with it -- especially right
/// after a send-then-return call like [`publish`](Self::publish) or
/// [`serve_one_call`](Self::serve_one_call).** Dropping the last handle
/// ends the session and tears the connection down at once (flushing
/// outstanding QUIC stream data needs `.await`, which `Drop` can't do), with
/// no guarantee the last write actually reached the peer -- see
/// [`close`](Self::close)'s own doc for the mechanism, and
/// [`serve_one_call`](Self::serve_one_call)'s for the specific,
/// confirmed-live way this bites a spawned provider task.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
    pub station: HelloInfo,
}

/// What every handle of one session shares.
pub(crate) struct SessionInner {
    /// Direct dial opens dedicated streams on it when it reuses this session.
    connection: Arc<quinn::Connection>,
    channel: Arc<Channel>,
    hello: HelloInfo,
    /// The requests using this session, when direct dial dialed it for them.
    leases: Option<crate::open_sessions::Leases>,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        // The last handle went without close: end the session, which stops
        // its reader and writers, and close the connection at once.
        self.channel.end(SessionEndReason::Closed, true);
        self.connection.close(0u32.into(), b"dropped");
    }
}

impl crate::open_sessions::Live for SessionInner {
    fn is_live(&self) -> bool {
        self.channel.end_reason().is_none() && self.connection.close_reason().is_none()
    }
}

impl crate::open_sessions::Leased for Session {
    fn leases(&self) -> Option<&crate::open_sessions::Leases> {
        self.inner.leases.as_ref()
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    Transport(ConnectError),
    OpenStream(quinn::ConnectionError),
    Write(quinn::WriteError),
    Read(quinn::ReadError),
    /// The peer closed the stream before a complete frame arrived.
    StreamClosed,
    Timeout,
    Encode(frame::EncodeFrameError),
    Decode(frame::DecodeFrameError),
    /// Received a frame, but it wasn't a HELLO — a station is never
    /// expected to send anything else at this point in the handshake.
    UnexpectedFrameType(frame::ParseHelloError),
    /// The HELLO frame's own signature didn't verify against the
    /// node_id it claims — proves nothing about who actually sent it.
    SignatureInvalid(frame::VerifyError),
    /// The station completed the handshake but refused the connection
    /// (`accepted = false`), e.g. a puzzle-invalid or unrecognized
    /// identity.
    Refused {
        refusal_code: Option<i128>,
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Transport(e) => write!(f, "transport: {e}"),
            HandshakeError::OpenStream(e) => write!(f, "opening control stream: {e}"),
            HandshakeError::Write(e) => write!(f, "sending CONNECT: {e}"),
            HandshakeError::Read(e) => write!(f, "reading from control stream: {e}"),
            HandshakeError::StreamClosed => {
                write!(f, "station closed the stream before HELLO arrived")
            }
            HandshakeError::Timeout => write!(
                f,
                "no HELLO within {HANDSHAKE_TIMEOUT:?} (likely a protocol mismatch)"
            ),
            HandshakeError::Encode(e) => write!(f, "encoding CONNECT: {e}"),
            HandshakeError::Decode(e) => write!(f, "decoding the station's response: {e}"),
            HandshakeError::UnexpectedFrameType(e) => write!(f, "expected a HELLO frame: {e}"),
            HandshakeError::SignatureInvalid(e) => write!(f, "HELLO signature check failed: {e}"),
            HandshakeError::Refused { refusal_code } => {
                write!(
                    f,
                    "station refused the connection (refusal_code = {refusal_code:?})"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Dial `host:port` and complete the full CONNECT/HELLO handshake:
/// open a QUIC connection, open the control stream, send a signed
/// CONNECT built from `identity`, and wait for a HELLO whose own
/// signature verifies against the node_id it claims. The session's reader
/// starts right after.
///
/// `identity` **must** be puzzle-hardened
/// ([`KeyPair::generate_with_puzzle`](crate::identity::KeyPair::generate_with_puzzle))
/// — see that function's own doc and `plans/PLAN_WIRE_PROTOCOL.md` §5's
/// callout: an unhardened identity fails this handshake silently (the
/// QUIC/TLS layer looks healthy right up until the HELLO never accepts).
pub async fn connect(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
) -> Result<Session, HandshakeError> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_inner(host, port, trust, identity, None),
    )
    .await
    .unwrap_or(Err(HandshakeError::Timeout))
}

/// [`connect`], for a session direct dial dials for its own requests. The
/// session counts the requests using it, starting with the one that dialed
/// it ([`Leases`](crate::open_sessions::Leases)), so a request that finds it
/// open shares it, and it closes when the last one is done.
pub(crate) async fn connect_leased(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
) -> Result<Session, HandshakeError> {
    let leases = Some(crate::open_sessions::Leases::new());
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_inner(host, port, trust, identity, leases),
    )
    .await
    .unwrap_or(Err(HandshakeError::Timeout))
}

async fn connect_inner(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
    leases: Option<crate::open_sessions::Leases>,
) -> Result<Session, HandshakeError> {
    let connection = transport::connect(host, port, trust)
        .await
        .map_err(HandshakeError::Transport)?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(HandshakeError::OpenStream)?;

    let connect_spec =
        crate::frame::ConnectSpec::new(identity.node_id(), identity.puzzle_evidence());
    let connect_frame = frame::sign(frame::connect(&connect_spec), identity);
    let encoded = frame::encode(&connect_frame).map_err(HandshakeError::Encode)?;
    send.write_all(&encoded)
        .await
        .map_err(HandshakeError::Write)?;

    let (hello_value, buf) = read_one_frame(&mut recv).await?;

    let station = frame::parse_hello(&hello_value).map_err(HandshakeError::UnexpectedFrameType)?;
    frame::verify(&hello_value, &station.node_id).map_err(HandshakeError::SignatureInvalid)?;

    if !station.accepted {
        return Err(HandshakeError::Refused {
            refusal_code: station.refusal_code,
        });
    }

    let connection = Arc::new(connection);
    let (identity_node, station_node) = (identity.node_id(), station.node_id);
    // The session signs the frames it sends on its own account (replies its
    // reader makes, UNSUBSCRIBE on a dropped subscription) with its own copy
    // of the identity it connected under.
    let own_identity = KeyPair::from_seed_bytes(identity.private_bytes());
    let hello = station.clone();
    let inner = Arc::new_cyclic(|this: &Weak<SessionInner>| {
        let (this, ended_connection) = (this.clone(), connection.clone());
        let channel = Channel::start(
            Box::new(recv),
            buf,
            Box::new(send),
            own_identity,
            station_node,
            control_channel::SEND_TIMEOUT,
            Box::new(move |reason: &SessionEndReason, closed_here: bool| {
                // A session whose control stream ended is no longer offered
                // for reuse, and its connection closes.
                crate::open_sessions::live().unregister_weak(identity_node, station_node, &this);
                if !closed_here {
                    ended_connection.close(0u32.into(), reason.to_string().as_bytes());
                }
            }),
        );
        SessionInner {
            connection,
            channel,
            hello,
            leases,
        }
    });
    crate::open_sessions::live().register(identity_node, station_node, &inner);
    Ok(Session { inner, station })
}

/// Read from `recv` until one complete frame has been decoded, returning
/// it along with any leftover bytes already read that belong to the
/// *next* frame, which the session's reader starts from.
async fn read_one_frame(recv: &mut quinn::RecvStream) -> Result<(Value, Vec<u8>), HandshakeError> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        match frame::decode(&buf) {
            Ok(Decoded::Frame(value, consumed)) => {
                buf.drain(..consumed);
                return Ok((value, buf));
            }
            Ok(Decoded::More(_)) => {}
            Err(e) => return Err(HandshakeError::Decode(e)),
        }
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(HandshakeError::Read)?
            .ok_or(HandshakeError::StreamClosed)?;
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Errors from [`Session::serve_one_call`].
#[derive(Debug)]
pub enum ServeCallError {
    /// No inbound CALL arrived within the requested timeout.
    Timeout,
    /// The session ended.
    SessionEnded(SessionEndReason),
    /// Sending the reply failed.
    Send(SendError),
}

impl std::fmt::Display for ServeCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeCallError::Timeout => write!(f, "timed out waiting for an inbound CALL"),
            ServeCallError::SessionEnded(reason) => write!(f, "the session has ended: {reason}"),
            ServeCallError::Send(e) => write!(f, "sending the reply: {e}"),
        }
    }
}

impl std::error::Error for ServeCallError {}

/// Errors from [`Session::run_subscriber`].
#[derive(Debug)]
pub enum RunSubscriberError {
    Subscribe(SendError),
    Recv(RecvEventError),
}

impl std::fmt::Display for RunSubscriberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunSubscriberError::Subscribe(e) => write!(f, "subscribing: {e}"),
            RunSubscriberError::Recv(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunSubscriberError {}

impl Session {
    /// A handle to a session found open in this process's open sessions.
    pub(crate) fn from_open(inner: Arc<SessionInner>) -> Session {
        Session {
            station: inner.hello.clone(),
            inner,
        }
    }

    /// Whether `other` is a handle to this same session.
    pub(crate) fn is_same_session(&self, other: &Session) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// The remote address this session's connection is with.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.inner.connection.remote_address()
    }

    /// Why this session ended, once it has.
    pub fn end_reason(&self) -> Option<SessionEndReason> {
        self.inner.channel.end_reason()
    }

    /// Resolves once this session has ended, with why.
    pub async fn ended(&self) -> SessionEndReason {
        self.inner.channel.ended().await
    }

    /// How many frames of each type the station sent that nothing on this
    /// session was waiting for, such as the station's own advertise
    /// broadcasts. They are dropped, and at most one log line per type per
    /// minute reports them, except a dropped CALL, RESULT or ERROR, which gets
    /// a drop warning instead (see
    /// [`drop_warning_interval`](Self::drop_warning_interval)).
    pub fn unrouted_frame_counts(&self) -> HashMap<String, u64> {
        self.inner.channel.unrouted_frame_counts()
    }

    /// How long this session's drop warning intervals last. The first inbound
    /// CALL or reply of an interval this session drops, and the first stream
    /// it refuses, is logged at once with the reason; the rest of the same
    /// kind in that interval are counted into one closing line when it ends.
    /// Defaults to 60 seconds.
    pub fn drop_warning_interval(&self) -> Duration {
        self.inner.channel.drop_warnings().interval()
    }

    /// Sets [`drop_warning_interval`](Self::drop_warning_interval), for the
    /// intervals that start after this.
    pub fn set_drop_warning_interval(&self, interval: Duration) {
        self.inner.channel.drop_warnings().set_interval(interval);
    }

    pub(crate) fn drop_warnings(&self) -> &crate::control_channel::drop_warning::DropWarnings {
        self.inner.channel.drop_warnings()
    }

    /// Open a new dedicated QUIC stream on this same connection, separate
    /// from the control stream — the mechanism content transfer (§12)
    /// and streaming RPC (§13), both use instead of the control stream.
    pub async fn open_dedicated_stream(&self) -> Result<FrameStream, quinn::ConnectionError> {
        let (send, recv) = self.inner.connection.open_bi().await?;
        Ok(FrameStream::new(send, recv))
    }

    /// Accept the next dedicated stream the *peer* opens toward us —
    /// e.g. the station routing an inbound STREAM_OPEN for a procedure
    /// this session has [`advertise`](Self::advertise)d (§13.2). Blocks
    /// until one arrives.
    ///
    /// The receiving side has no advance notice of why a new stream
    /// arrived; §7 of `plans/PLAN_WIRE_PROTOCOL.md` says to read the
    /// stream's own first frame to learn its purpose, which is exactly
    /// what a caller of this method does next via the returned
    /// `FrameStream`'s own `recv_frame`. The reference (`quicer`-backed
    /// Erlang) has a documented race here — the peer's first bytes can
    /// arrive before the owning process is notified the stream exists at
    /// all, because its NIF stream resources start passive and only
    /// begin delivering once explicitly armed *after* the notification.
    /// That race doesn't apply here: `quinn`/QUIC buffers inbound stream
    /// data at the transport layer regardless of whether or when the
    /// application starts reading, so nothing analogous to arm before
    /// read is needed on this side.
    pub async fn accept_dedicated_stream(&self) -> Result<FrameStream, quinn::ConnectionError> {
        let (send, recv) = self.inner.connection.accept_bi().await?;
        Ok(FrameStream::new(send, recv))
    }

    /// Send a signed CALL on the control stream and wait for the matching
    /// RESULT or ERROR, correlated by `call_id`. Other calls, subscriptions
    /// and serving on this session carry on meanwhile. `timeout` covers the
    /// whole call, its turn to write included; when it runs out the call
    /// returns [`CallError::Timeout`], and when the session ends first
    /// [`CallError::SessionEnded`]. Both say whether the CALL may have
    /// reached the station. Announces `rpc.sent_v1` once the CALL is written
    /// and `rpc.completed_v1` when the call returns, through this session's
    /// own writer, so the facts never cost the call time — see
    /// `RPC_SENT_TOPIC` for why these are always on.
    pub async fn call(
        &self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        let spec = frame::CallSpec::new(
            rand::random(),
            procedure,
            realm,
            payload,
            deadline_ms,
            identity.node_id(),
        );
        self.announced_call(&spec, identity, timeout).await
    }

    /// As [`call`](Self::call), attaching `ucan_token` (e.g. from
    /// [`crate::ucan::create`]) to the outgoing CALL — for invoking a
    /// procedure gated by a [`crate::ucan::Policy::required`] policy on
    /// the provider side. A procedure that isn't gated ignores the token;
    /// one that is checks it before ever running its handler, so an
    /// invalid or missing token comes back as a BOLT#4 `unauthorized` ERROR
    /// frame, not a Rust error from this call. Announces
    /// `rpc.sent_v1`/`rpc.completed_v1` the same way [`call`](Self::call)
    /// does.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_with_ucan(
        &self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
        ucan_token: Vec<u8>,
    ) -> Result<frame::CallResponse, CallError> {
        let mut spec = frame::CallSpec::new(
            rand::random(),
            procedure,
            realm,
            payload,
            deadline_ms,
            identity.node_id(),
        );
        spec.ucan_token = ucan_token;
        self.announced_call(&spec, identity, timeout).await
    }

    async fn announced_call(
        &self,
        spec: &frame::CallSpec,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        let request_id: [u8; 16] = rand::random();
        let sent = rpc_fact(
            RPC_SENT_TOPIC,
            spec.realm,
            identity,
            request_id_payload(request_id),
        );
        let result = self
            .inner
            .channel
            .call(spec, identity, timeout, Some(sent))
            .await;
        self.inner
            .channel
            .hand_off(rpc_completed(spec.realm, identity, request_id, &result));
        result
    }

    /// A CALL on this session without RPC telemetry facts, for a pool
    /// calling on its links, as macula's pool calls through
    /// `macula_station_link:call`.
    pub(crate) async fn link_call(
        &self,
        spec: &frame::CallSpec,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        self.inner.channel.call(spec, identity, timeout, None).await
    }

    /// Send a signed PUBLISH, carrying the end-to-end `publisher_sig`
    /// (over topic/realm/publisher/seq/payload, independent of frame
    /// type) so the resulting EVENT survives being relayed beyond one
    /// hop — a station verifies an EVENT's per-hop `signature` against
    /// whichever station forwarded it, which only matches on hop 1;
    /// every hop after that needs `publisher_sig` instead. Matches the
    /// Erlang reference SDK's own default (`pubsub_emit_publisher_sig`,
    /// true since macula 4.6.0). Fire-and-forget — no reply is expected
    /// on the wire; a subscriber (this session included, if subscribed
    /// to the same topic/realm) receives an EVENT asynchronously, through
    /// its [`Subscription`].
    pub async fn publish(
        &self,
        spec: &frame::PublishSpec,
        identity: &KeyPair,
    ) -> Result<(), SendError> {
        let unsigned = frame::publish(spec);
        let with_publisher_sig = frame::sign_publisher(unsigned, identity);
        let signed = frame::sign(with_publisher_sig, identity);
        self.inner.channel.send(&signed).await
    }

    /// Starts a subscription with its own queue of 256 events. It receives
    /// every EVENT whose realm is `spec`'s and whose topic matches `spec`'s
    /// topic by the station's rule: both split on "/", equal segment counts,
    /// and each segment equal or "*", which matches exactly one whole
    /// segment. SUBSCRIBE goes to the station unless another subscription on
    /// this session already holds that realm and topic, and closing or
    /// dropping the last one sends UNSUBSCRIBE.
    pub async fn subscribe(
        &self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
    ) -> Result<Subscription, SendError> {
        self.inner.channel.subscribe(spec, identity).await
    }

    /// Send a signed ADVERTISE (§6.9) — registers this connection as the
    /// handler for `spec`'s `(realm, procedure)`. Fire-and-forget on the
    /// wire; the station then routes inbound CALLs (control stream) and
    /// STREAM_OPENs (a fresh dedicated stream — see
    /// [`accept_dedicated_stream`](Self::accept_dedicated_stream)) for
    /// that procedure back to this connection.
    pub async fn advertise(
        &self,
        spec: &frame::AdvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendError> {
        let signed = frame::sign(frame::advertise(spec), identity);
        self.inner.channel.send(&signed).await
    }

    /// Send a signed UNADVERTISE. Fire-and-forget.
    pub async fn unadvertise(
        &self,
        spec: &frame::UnadvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendError> {
        let signed = frame::sign(frame::unadvertise(spec), identity);
        self.inner.channel.send(&signed).await
    }

    /// Sends an ADVERTISE for `spec` immediately, then again every
    /// `interval`, until `stop` resolves. [`advertise`](Self::advertise)'s
    /// own doc notes the station's registration is tied to the connection
    /// that sent it — a long-lived server needs to keep re-asserting it.
    /// [`advertise`](Self::advertise) is a stateless, side-effect-free-on-
    /// repeat wire send (unlike the Erlang reference's `advertise/5`, which
    /// spawns a real per-call OTP supervisor and so needs a `reuse_sup`
    /// option to avoid leaking one per tick), so there is nothing
    /// equivalent to worry about leaking here — same reasoning
    /// `macula-go`'s `KeepAdvertised` already applied and verified
    /// live.
    ///
    /// A failed tick is reported via `on_error` but does not stop the
    /// loop — it tries again at the next interval regardless. This cannot
    /// repair a dead session on its own; if the session has ended, every
    /// tick will keep failing until `stop` resolves. See
    /// [`crate::direct_dial::keep_advertised_direct`] for the direct-dial
    /// equivalent (same shape, same reasoning).
    pub async fn keep_advertised<F>(
        &self,
        spec: &frame::AdvertiseSpec,
        identity: &KeyPair,
        interval: Duration,
        stop: F,
        on_error: impl Fn(SendError),
    ) where
        F: std::future::Future<Output = ()>,
    {
        tokio::pin!(stop);
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = &mut stop => return,
                _ = ticker.tick() => {
                    if let Err(e) = self.advertise(spec, identity).await {
                        on_error(e);
                    }
                }
            }
        }
    }

    /// The provider role's counterpart to [`call`](Self::call): wait for
    /// the next inbound CALL, bounded by `timeout`, look it up via
    /// `lookup`, invoke the matching handler, and send the resulting RESULT
    /// or ERROR back over this same connection — see
    /// `plans/PLAN_WIRE_PROTOCOL.md` §6.9's routing description and
    /// `macula_station_link.erl`'s `handle_inbound_call/2`, which this
    /// mirrors field for field, including its BOLT#4 error-code mapping.
    ///
    /// Inbound CALLs wait in this session's queue of 64 until served, while
    /// calls and subscriptions on the same session carry on. A CALL that
    /// doesn't fit gets `temporary_relay_failure` at once, and serving
    /// carries on with the calls already queued. The reader queues only a
    /// CALL whose signature verifies against the `caller` it names.
    ///
    /// A caller wanting a long-lived server loops on this:
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # async fn example(session: &macula_rust::connection::Session, identity: &macula_rust::identity::KeyPair, lookup: impl Fn(&[u8; 32], &str) -> Option<macula_rust::connection::CallHandler>) {
    /// loop {
    ///     if let Err(e) = session.serve_one_call(&lookup, identity, Duration::from_secs(30)).await {
    ///         // ServeCallError::Timeout just means nothing arrived -- keep looping.
    ///         eprintln!("{e}");
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// **Do not let the last handle to this `Session` drop right after this
    /// call returns -- call [`close`](Self::close) on it explicitly first.**
    /// This is the single most common way to lose the RESULT/ERROR you just
    /// sent: `serve_one_call` returning `Ok(())` only means the reply was
    /// handed to quinn's own send-scheduling machinery, exactly like
    /// [`close`](Self::close)'s own doc explains for `write_all`/`finish`
    /// -- dropping the last handle does nothing to wait for that to reach
    /// the peer before the connection is torn down, while `close` has a
    /// deliberate bounded drain for precisely this. Confirmed live
    /// 2026-09-05 with the single most natural-looking way to hit it:
    /// spawning the only handle into its own `tokio::spawn` task with
    /// nothing following the `.await` -- the task can complete and drop it
    /// within microseconds of the write, deterministically under a
    /// multi-threaded runtime, losing the reply every time. Keep a handle
    /// outside the task and close it explicitly instead, same as this
    /// crate's own `tests/live_station.rs` does for every spawned provider
    /// role.
    pub async fn serve_one_call<L>(
        &self,
        lookup: L,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
    {
        self.serve_one_call_gated(
            lookup,
            |_, _| crate::ucan::Policy::open(),
            identity,
            timeout,
        )
        .await
    }

    /// [`serve_one_call`](Self::serve_one_call), additionally gating each
    /// inbound CALL through `policy` BEFORE `lookup` runs — mirrors
    /// `macula_station_link.erl`'s `handle_inbound_call/2` exactly: an
    /// open policy (the default [`serve_one_call`](Self::serve_one_call)
    /// uses) behaves identically; a [`crate::ucan::Policy::required`]
    /// policy demands a CALL's `ucan_token` verify against the required
    /// issuer and name the CALL's `caller` as its audience, and refuses
    /// with BOLT#4 `unauthorized` WITHOUT ever invoking `lookup` or a
    /// handler if it doesn't — a [`CallHandler`] never sees the raw token
    /// either way, matching the reference's own handler contract (payload
    /// only).
    ///
    /// Before any policy runs, the CALL's signature must verify against the
    /// `caller` it names; the session's reader drops a CALL that doesn't,
    /// with no reply, as `macula_station_link.erl`'s `on_inbound_call/3`
    /// does.
    pub async fn serve_one_call_gated<L, P>(
        &self,
        lookup: L,
        policy: P,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
        P: Fn(&[u8; 32], &str) -> crate::ucan::Policy,
    {
        tokio::time::timeout(timeout, async {
            let call = self
                .inner
                .channel
                .next_inbound_call()
                .await
                .map_err(ServeCallError::SessionEnded)?;
            let reply = build_call_reply(call, &lookup, &policy, identity, Some(self)).await;
            self.inner
                .channel
                .send(&frame::sign(reply, identity))
                .await
                .map_err(ServeCallError::Send)
        })
        .await
        .unwrap_or(Err(ServeCallError::Timeout))
    }

    /// Bounds how long [`close`](Self::close) waits after its last write
    /// before hard-closing the connection -- see that method's own doc
    /// for why this exists at all. Short relative to the Erlang
    /// reference's own 5s draining-state upper bound
    /// (`macula_peering.erl`, `?DRAIN_TIMEOUT_MS`): this side only needs
    /// to cover quinn's own internal send-scheduling latency, not a full
    /// round trip's worth of protocol drain.
    const CLOSE_DRAIN: Duration = Duration::from_millis(250);

    /// Close the control stream and connection gracefully with a GOODBYE
    /// frame, matching `macula_peering_conn.erl`'s `connected -> draining`
    /// transition (minus the full drain-timeout bookkeeping, since this
    /// crate isn't holding a supervisor to clean up). Every handle to this
    /// session sees it end.
    ///
    /// `write_all(...).await` and `finish()` both only guarantee the data
    /// was handed to quinn's own send-scheduling machinery, not that it
    /// reached the peer -- `Connection::close` is abrupt and does not
    /// wait for outstanding stream data to be delivered. Found live
    /// 2026-08-29 in the Go port of this exact pattern
    /// (macula-go's connection.Session.Close): a PUBLISH sent
    /// immediately before Close intermittently never reached the peer,
    /// root-caused to this race. Fixed proactively here before it was
    /// independently rediscovered against this crate -- same doc
    /// comment ("minus the drain-timeout bookkeeping"), same
    /// write-then-immediately-abort-connection shape, so the same race
    /// applies. Closing the stream via `finish()` first, then giving the
    /// background sender a bounded window before hard-closing the
    /// connection, mirrors the Erlang reference's own bounded-drain
    /// approach.
    pub async fn close(&self, reason: &str, detail: Option<&str>, identity: &KeyPair) {
        let goodbye = frame::sign(frame::goodbye(reason, detail), identity);
        self.inner.channel.close(&goodbye).await;
        tokio::time::sleep(Self::CLOSE_DRAIN).await;
        self.inner.connection.close(0u32.into(), reason.as_bytes());
    }

    /// The supervised counterpart to the bare [`publish`](Self::publish)
    /// primitive, matching `macula_publisher.erl` in spirit: publishes
    /// `pubsub.publish_started_v1` before the publish and
    /// `pubsub.publish_completed_v1` after, both under `spec`'s own realm.
    /// Fact-publish failures are silently discarded — matching
    /// `macula_publisher.erl`'s own `publish/5` helper, which throws away
    /// its result unconditionally (`_ = macula:publish(...), ok`).
    ///
    /// Unlike Erlang's version — a supervised worker process a caller can
    /// kill mid-flight — this crate's bare `publish` is already a
    /// synchronous, near-instant frame send (no ack on this wire, no
    /// network round-trip to await), so there is no meaningful "cancel
    /// before it starts" window worth a dedicated mechanism. Await this
    /// directly, or wrap it in `tokio::select!`/`tokio::time::timeout`
    /// yourself if you need to abandon it early — dropping a `Future` IS
    /// real cancellation in Rust; Erlang has to simulate that by killing a
    /// worker process.
    pub async fn run_publisher(
        &self,
        spec: &frame::PublishSpec,
        identity: &KeyPair,
        announce: bool,
    ) -> Result<(), SendError> {
        let publish_id: [u8; 16] = rand::random();
        if announce {
            let payload = Value::Map(vec![])
                .with_field("publish_id", Value::Bytes(publish_id.to_vec()))
                .with_field("topic", Value::Bytes(spec.topic.as_bytes().to_vec()));
            let fact = frame::PublishSpec::new(
                "pubsub.publish_started_v1",
                spec.realm,
                identity.node_id(),
                rand::random(),
                payload,
                now_ms(),
            );
            let _ = self.publish(&fact, identity).await;
        }

        let result = self.publish(spec, identity).await;

        if announce {
            let payload =
                Value::Map(vec![]).with_field("publish_id", Value::Bytes(publish_id.to_vec()));
            let payload = match &result {
                Ok(()) => payload.with_field("outcome", Value::text("completed")),
                Err(e) => payload
                    .with_field("outcome", Value::text("failed"))
                    .with_field("reason", Value::text(e.to_string())),
            };
            let fact = frame::PublishSpec::new(
                "pubsub.publish_completed_v1",
                spec.realm,
                identity.node_id(),
                rand::random(),
                payload,
                now_ms(),
            );
            let _ = self.publish(&fact, identity).await;
        }

        result
    }

    /// The supervised counterpart to a bare [`Subscription`], matching
    /// `macula_subscriber.erl` in spirit: subscribes once, then hands every
    /// matching EVENT to `handler` until `stop` resolves, instead of
    /// requiring the caller to hand-roll a receive loop. Closes the
    /// subscription on return, including on cancellation, which sends
    /// UNSUBSCRIBE when no other subscription on the session holds that
    /// realm and topic. Other frames on the session never reach this loop:
    /// the session's reader routes each one to whatever waits for it.
    ///
    /// Returns an error when the subscription falls behind
    /// ([`RecvEventError::Overflow`]) or the session ends.
    ///
    /// No OTP pid to address a running subscriber by; `stop` plays that
    /// role — matches [`keep_advertised`](Self::keep_advertised)'s own
    /// cancellation shape exactly, not a new one. `handler` cannot itself
    /// stop the loop (no return value) — by the same design `keep_advertised`
    /// already established, where `on_error` can only report, not halt;
    /// stopping is always external, via `stop`.
    pub async fn run_subscriber<F>(
        &self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
        stop: F,
        mut handler: impl FnMut(frame::EventInfo),
    ) -> Result<(), RunSubscriberError>
    where
        F: std::future::Future<Output = ()>,
    {
        let mut subscription = self
            .subscribe(spec, identity)
            .await
            .map_err(RunSubscriberError::Subscribe)?;

        tokio::pin!(stop);
        let result = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                received = subscription.recv_event(SUBSCRIBER_POLL_INTERVAL) => match received {
                    Ok(event) => handler(event),
                    Err(RecvEventError::Timeout) => {}
                    Err(e) => break Err(RunSubscriberError::Recv(e)),
                },
            }
        };

        subscription.close().await;
        result
    }
}

/// How long [`Session::run_subscriber`] waits on its subscription at a
/// time. Not a wire timeout: nothing is sent when it runs out, the loop just
/// waits again.
const SUBSCRIBER_POLL_INTERVAL: Duration = Duration::from_secs(3600);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as u64
}

// RPC telemetry auto-facts, matching `macula_request.erl` (caller side:
// rpc.sent_v1/rpc.completed_v1) and `macula_response.erl` (provider side:
// rpc.received_v1/rpc.replied_v1) exactly -- same topic names, same
// `request_id` field (16 fresh random bytes per call, independent of the
// wire CALL frame's own `call_id` -- the reference tracks its own request
// lifecycle separately from the wire frame, and this does too), same realm
// as the call itself, fire-and-forget: each fact goes to the session's own
// writer, so it never costs the call or serve it describes any time and
// never fails it, matching `macula_response.erl`'s own
// `_ = macula:publish(...), ok` and `macula_request.erl`'s identical
// `publish/5` helper. A fact is dropped when 64 frames already wait for that
// writer.
//
// Always on, matching the reference's ACTUAL behavior on each side, not
// just a blanket claim -- checked directly rather than assumed:
// `macula_request.erl`'s `start_link/7` and `start_link_direct/8` both
// hardcode `true` literally at the tuple-construction call site; there is
// no `Opts` key or parameter that reaches it at all on the caller side.
// `macula_response.erl`'s `advertise/6` DOES read `announce` from its
// `Opts` map with a `true` default (`maps:get(announce, Opts, true)`) --
// technically overridable -- but the one real caller in this workspace
// (`hecate_om_capabilities.erl`'s `advertise_opts/1`) never sets it to
// `false`. Matching Go's `macula-go` decision here: no toggle exposed
// on either side, since exposing one on `call`/`serve_one_call_gated` --
// this crate's two most heavily used functions -- for an option nothing
// in the reference ecosystem actually flips would be a real-blast-radius
// signature change for no practical benefit.
const RPC_SENT_TOPIC: &str = "rpc.sent_v1";
const RPC_COMPLETED_TOPIC: &str = "rpc.completed_v1";
const RPC_RECEIVED_TOPIC: &str = "rpc.received_v1";
const RPC_REPLIED_TOPIC: &str = "rpc.replied_v1";

fn request_id_payload(request_id: [u8; 16]) -> Value {
    Value::Map(vec![]).with_field("request_id", Value::Bytes(request_id.to_vec()))
}

/// A fact's PUBLISH, carrying its `publisher_sig`; the session's own writer
/// signs the envelope when it sends it.
fn rpc_fact(topic: &str, realm: [u8; 32], identity: &KeyPair, payload: Value) -> Value {
    let spec = frame::PublishSpec::new(
        topic,
        realm,
        identity.node_id(),
        rand::random(),
        payload,
        now_ms(),
    );
    frame::sign_publisher(frame::publish(&spec), identity)
}

/// Matches `macula_request.erl`'s `outcome_fields/2`: `completed` (no Rust
/// error, not a bolt4 ERROR frame) or `failed` (either). Erlang
/// additionally has a `cancelled` outcome from its own
/// gen_server-cancellable `macula_request:cancel/1` -- this crate's plain
/// `call` has no cancellation concept independent of an ordinary
/// error/timeout at this layer, so that outcome is not reachable here and
/// is not fabricated (same reasoning Go's port already documented).
fn rpc_completed(
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
    result: &Result<frame::CallResponse, CallError>,
) -> Value {
    let payload = request_id_payload(request_id);
    let payload = match result {
        Err(e) => payload
            .with_field("outcome", Value::text("failed"))
            .with_field("reason", Value::text(e.to_string())),
        Ok(frame::CallResponse::Error { name, .. }) => payload
            .with_field("outcome", Value::text("failed"))
            .with_field("reason", Value::text(name.clone())),
        Ok(frame::CallResponse::Result { .. }) => {
            payload.with_field("outcome", Value::text("completed"))
        }
    };
    rpc_fact(RPC_COMPLETED_TOPIC, realm, identity, payload)
}

/// Matches `macula_response.erl`'s `outcome_fields/2`: `replied` (`{ok,
/// _}`) or `failed` (`{error, Reason}`). A handler panic is deliberately
/// NOT announced here at all -- matching the reference exactly, where a
/// crashing `Module:handle_request/2` crashes the whole per-request child
/// before its own `publish_replied/2` call is ever reached, so
/// `REQUEST_REPLIED` is never published for a crash there either.
fn rpc_replied(
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
    handler_err: Option<&str>,
) -> Value {
    let payload = request_id_payload(request_id);
    let payload = match handler_err {
        Some(reason) => payload
            .with_field("outcome", Value::text("failed"))
            .with_field("reason", Value::text(reason)),
        None => payload.with_field("outcome", Value::text("replied")),
    };
    rpc_fact(RPC_REPLIED_TOPIC, realm, identity, payload)
}

/// Build the RESULT/ERROR reply for one inbound CALL — mirrors
/// `macula_station_link.erl`'s `handle_inbound_call/2` +
/// `safe_invoke_handler/4` exactly: `policy` is checked FIRST (a
/// rejection is BOLT#4 `unauthorized`, and `lookup`/a handler never run
/// at all); then a lookup miss is `unknown_next_peer`; the handler
/// running to completion produces a RESULT (`Ok`) or `unknown_error` with
/// `detail` (`Err`); a handler panic — caught via `tokio::spawn`, the
/// same "one transient task per call" shape the reference's own "one
/// process per call" uses — is `temporary_relay_failure`, with no
/// `detail`, matching the reference not sending one on a crash either.
///
/// Announces `rpc.received_v1`/`rpc.replied_v1` around dispatch through
/// `session`'s own writer when `session` is `Some` -- `None` for the pure
/// dispatch-logic unit tests below, which deliberately exercise this
/// function with no network at all (mirrors `macula-go`'s identical
/// nil-session-safe `announceFact`). `rpc.received_v1` fires only after
/// `policy` and `lookup` both pass, matching `macula_response.erl`'s own
/// per-request child only starting once the raw advertise mechanism
/// already decided to dispatch to a real handler -- a UCAN-rejected or
/// unadvertised-procedure CALL announces neither fact.
/// The payload a CALL's handler receives: a map payload with `caller`, the
/// node id the CALL's signature was verified against, under `"caller"`,
/// replacing a `"caller"` the sender put there under a text or byte-string
/// key; any other payload unchanged. Mirrors
/// `macula_station_link:with_caller/2`.
pub(crate) fn with_caller(payload: Value, caller: [u8; 32]) -> Value {
    match payload {
        Value::Map(mut fields) => {
            fields.retain(|(key, _)| !is_caller_key(key));
            fields.push((Value::text("caller"), Value::Bytes(caller.to_vec())));
            Value::Map(fields)
        }
        other => other,
    }
}

fn is_caller_key(key: &Value) -> bool {
    match key {
        Value::Text(text) => text == "caller",
        Value::Bytes(bytes) => bytes.as_slice() == b"caller",
        _ => false,
    }
}

pub(crate) async fn build_call_reply<L, P>(
    call_info: frame::CallInfo,
    lookup: &L,
    policy: &P,
    identity: &KeyPair,
    session: Option<&Session>,
) -> Value
where
    L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
    P: Fn(&[u8; 32], &str) -> crate::ucan::Policy,
{
    let self_pub = identity.node_id();

    if policy(&call_info.realm, &call_info.procedure)
        .check(&call_info.ucan_token, &call_info.caller)
        .is_err()
    {
        return frame::call_error(&frame::CallErrorSpec::new(
            call_info.call_id,
            bolt4::Code::Unauthorized,
            self_pub,
        ));
    }

    let Some(handler) = lookup(&call_info.realm, &call_info.procedure) else {
        return frame::call_error(&frame::CallErrorSpec::new(
            call_info.call_id,
            bolt4::Code::UnknownNextPeer,
            self_pub,
        ));
    };

    let request_id: [u8; 16] = rand::random();
    if let Some(session) = session {
        session.inner.channel.hand_off(rpc_fact(
            RPC_RECEIVED_TOPIC,
            call_info.realm,
            identity,
            request_id_payload(request_id),
        ));
    }

    let payload = with_caller(call_info.payload, call_info.caller);
    let outcome = tokio::spawn(async move { handler(payload).await }).await;
    match outcome {
        Ok(Ok(value)) => {
            if let Some(session) = session {
                session.inner.channel.hand_off(rpc_replied(
                    call_info.realm,
                    identity,
                    request_id,
                    None,
                ));
            }
            frame::result(&frame::ResultSpec::new(call_info.call_id, value, self_pub))
        }
        Ok(Err(reason)) => {
            if let Some(session) = session {
                session.inner.channel.hand_off(rpc_replied(
                    call_info.realm,
                    identity,
                    request_id,
                    Some(&reason),
                ));
            }
            let mut spec =
                frame::CallErrorSpec::new(call_info.call_id, bolt4::Code::UnknownError, self_pub);
            spec.detail = Some(reason);
            frame::call_error(&spec)
        }
        Err(_join_error) => frame::call_error(&frame::CallErrorSpec::new(
            call_info.call_id,
            bolt4::Code::TemporaryRelayFailure,
            self_pub,
        )),
    }
}

#[cfg(test)]
mod ucan_gating_tests {
    //! Proves `serve_one_call_gated`'s policy wiring end-to-end WITHOUT a
    //! network — `build_call_reply` is a plain async function of
    //! `(CallInfo, lookup, policy, self_pub)`, so its dispatch/reply logic
    //! is fully testable in isolation. Mirrors `macula-go`'s own 4
    //! connection-level UCAN-gating unit tests (`serve_ucan_test.go`).
    use super::*;
    use crate::identity::KeyPair;
    use crate::ucan::{self, Policy};

    fn call_info(ucan_token: Vec<u8>) -> frame::CallInfo {
        frame::CallInfo {
            call_id: [1; 16],
            procedure: "test.proc".into(),
            realm: [0; 32],
            payload: Value::Null,
            deadline_ms: 0,
            caller: [2; 32],
            ucan_token,
        }
    }

    fn never_called_lookup() -> impl Fn(&[u8; 32], &str) -> Option<CallHandler> {
        |_, _| panic!("handler lookup must not run when policy rejects the call")
    }

    fn echo_lookup() -> impl Fn(&[u8; 32], &str) -> Option<CallHandler> {
        |_, _| {
            Some(Arc::new(|payload: Value| {
                Box::pin(async move { Ok(payload) })
            }))
        }
    }

    #[tokio::test]
    async fn open_policy_never_gates_dispatch() {
        let identity = KeyPair::generate();
        let reply = build_call_reply(
            call_info(Vec::new()),
            &echo_lookup(),
            &|_, _| Policy::open(),
            &identity,
            None,
        )
        .await;
        assert!(matches!(
            frame::parse_call_response(&reply),
            Ok(frame::CallResponse::Result { .. })
        ));
    }

    #[tokio::test]
    async fn required_policy_refuses_a_call_with_no_token_before_lookup_runs() {
        let id = KeyPair::generate();
        let identity = KeyPair::generate();
        let reply = build_call_reply(
            call_info(Vec::new()),
            &never_called_lookup(),
            &move |_, _| Policy::required(id.node_id()),
            &identity,
            None,
        )
        .await;
        match frame::parse_call_response(&reply) {
            Ok(frame::CallResponse::Error { code, .. }) => {
                assert_eq!(code, bolt4::Code::Unauthorized as u8)
            }
            other => panic!("expected an Unauthorized ERROR frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn required_policy_refuses_a_token_from_the_wrong_issuer_before_lookup_runs() {
        let required_issuer = KeyPair::generate();
        let impostor = KeyPair::generate();
        let bad_token = ucan::create(
            "did:iss",
            "did:aud",
            vec![],
            &impostor,
            ucan::CreateOpts::default(),
        )
        .unwrap();
        let identity = KeyPair::generate();
        let reply = build_call_reply(
            call_info(bad_token),
            &never_called_lookup(),
            &move |_, _| Policy::required(required_issuer.node_id()),
            &identity,
            None,
        )
        .await;
        match frame::parse_call_response(&reply) {
            Ok(frame::CallResponse::Error { code, .. }) => {
                assert_eq!(code, bolt4::Code::Unauthorized as u8)
            }
            other => panic!("expected an Unauthorized ERROR frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn required_policy_lets_a_valid_token_reach_the_handler() {
        let id = KeyPair::generate();
        let good_token = ucan::create(
            "did:iss",
            &hex::encode(call_info(Vec::new()).caller),
            vec![],
            &id,
            ucan::CreateOpts::default(),
        )
        .unwrap();
        let identity = KeyPair::generate();
        let reply = build_call_reply(
            call_info(good_token),
            &echo_lookup(),
            &move |_, _| Policy::required(id.node_id()),
            &identity,
            None,
        )
        .await;
        assert!(matches!(
            frame::parse_call_response(&reply),
            Ok(frame::CallResponse::Result { .. })
        ));
    }

    // A handler receives the verified caller in a map payload. The names
    // match macula-go's.

    async fn payload_seen_by_the_handler(payload: Value, caller: [u8; 32]) -> Value {
        let info = frame::CallInfo {
            payload,
            caller,
            ..call_info(Vec::new())
        };
        let reply = build_call_reply(
            info,
            &echo_lookup(),
            &|_, _| Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await;
        match frame::parse_call_response(&reply) {
            Ok(frame::CallResponse::Result { payload, .. }) => payload,
            other => panic!("expected a RESULT, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_inbound_call_threads_its_caller_into_the_payload() {
        let caller = KeyPair::generate().node_id();
        let payload = Value::Map(vec![(Value::text("n"), Value::Int(21))]);

        let seen = payload_seen_by_the_handler(payload, caller).await;

        assert_eq!(seen.get("caller"), Some(&Value::Bytes(caller.to_vec())));
        assert_eq!(seen.get("n"), Some(&Value::Int(21)));
    }

    #[tokio::test]
    async fn a_caller_the_sender_put_in_the_payload_is_replaced_by_the_verified_caller() {
        let (caller, claimed) = (KeyPair::generate().node_id(), KeyPair::generate().node_id());
        let payload = Value::Map(vec![
            (Value::text("caller"), Value::Bytes(claimed.to_vec())),
            (
                Value::Bytes(b"caller".to_vec()),
                Value::Bytes(claimed.to_vec()),
            ),
        ]);

        let seen = payload_seen_by_the_handler(payload, caller).await;

        assert_eq!(
            seen,
            Value::Map(vec![(Value::text("caller"), Value::Bytes(caller.to_vec()))])
        );
    }

    #[tokio::test]
    async fn a_non_map_payload_carries_no_caller() {
        let caller = KeyPair::generate().node_id();

        let seen = payload_seen_by_the_handler(Value::text("hello"), caller).await;

        assert_eq!(seen, Value::text("hello"));
    }

    // The provider side of an inbound CALL: a gated policy accepts a token
    // only from the caller it was minted for. The names match macula-go's
    // connection/serve_caller_test.go. That a CALL reaches serving only when
    // its signature verifies against the caller it names is checked by the
    // session's reader; see control_channel.rs.

    fn call_info_from(caller: [u8; 32], ucan_token: Vec<u8>) -> frame::CallInfo {
        frame::CallInfo {
            caller,
            ..call_info(ucan_token)
        }
    }

    fn token_for(issuer: &KeyPair, audience: &str) -> Vec<u8> {
        ucan::create(
            "did:iss",
            audience,
            vec![],
            issuer,
            ucan::CreateOpts::default(),
        )
        .unwrap()
    }

    fn is_unauthorized(reply: &Value) -> bool {
        matches!(
            frame::parse_call_response(reply),
            Ok(frame::CallResponse::Error { code, .. }) if code == bolt4::Code::Unauthorized as u8
        )
    }

    #[tokio::test]
    async fn build_call_reply_gated_policy_refuses_a_token_presented_by_another_caller() {
        let (issuer, audience, presenter) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let token = token_for(&issuer, &hex::encode(audience.node_id()));

        let reply = build_call_reply(
            call_info_from(presenter.node_id(), token),
            &never_called_lookup(),
            &move |_, _| Policy::required(issuer.node_id()),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(
            is_unauthorized(&reply),
            "{:?}",
            frame::parse_call_response(&reply)
        );
    }

    #[tokio::test]
    async fn build_call_reply_gated_policy_accepts_a_token_from_its_audience() {
        let (issuer, caller) = (KeyPair::generate(), KeyPair::generate());
        let token = token_for(&issuer, &hex::encode(caller.node_id()));

        let reply = build_call_reply(
            call_info_from(caller.node_id(), token),
            &echo_lookup(),
            &move |_, _| Policy::required(issuer.node_id()),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(matches!(
            frame::parse_call_response(&reply),
            Ok(frame::CallResponse::Result { .. })
        ));
    }

    #[tokio::test]
    async fn build_call_reply_gated_policy_refuses_a_token_without_audience() {
        let (issuer, caller) = (KeyPair::generate(), KeyPair::generate());
        let token = token_for(&issuer, "");

        let reply = build_call_reply(
            call_info_from(caller.node_id(), token),
            &never_called_lookup(),
            &move |_, _| Policy::required(issuer.node_id()),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(
            is_unauthorized(&reply),
            "{:?}",
            frame::parse_call_response(&reply)
        );
    }
}
