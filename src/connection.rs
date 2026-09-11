//! The CONNECT/HELLO handshake and the application-frame stream
//! abstraction, ported from `src/peering/macula_peering_conn.erl`
//! (`macula-io/macula`) — see `plans/PLAN_WIRE_PROTOCOL.md` §3.
//!
//! Only the client role's `connecting -> handshaking -> connected` path
//! is implemented. [`FrameStream`] is the reusable "send/receive signed
//! application frames on one QUIC stream" primitive — [`Session`] wraps
//! one for the control stream, and [`Session::open_dedicated_stream`]
//! hands out fresh ones for content transfer (§12) and streaming RPC
//! (§13), which both run on dedicated streams rather than the control
//! stream.

use std::sync::Arc;
use std::time::Duration;

use crate::bolt4;
use crate::cbor::Value;
use crate::frame::{self, Decoded, HelloInfo};
use crate::identity::KeyPair;
use crate::transport::{self, ConnectError, Trust};

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
// FrameStream — send/receive signed application frames on one QUIC
// stream. The control stream (inside Session) and every dedicated
// stream (content transfer, streaming RPC) are each one of these.
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

#[derive(Debug)]
pub enum CallError {
    Send(SendFrameError),
    Recv(RecvFrameError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Send(e) => write!(f, "sending CALL: {e}"),
            CallError::Recv(e) => write!(f, "awaiting RESULT/ERROR: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

impl FrameStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::with_buf(send, recv, Vec::new())
    }

    fn with_buf(send: quinn::SendStream, recv: quinn::RecvStream, buf: Vec<u8>) -> Self {
        Self { send, recv, buf }
    }

    /// Any bytes already read past the last decoded frame — for the
    /// control stream specifically, this starts with whatever was left
    /// over from the handshake itself.
    pub fn leftover_bytes(&self) -> &[u8] {
        &self.buf
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
    /// RESULT or ERROR, correlated by `call_id`.
    ///
    /// **Known v1 limitation (control stream only):** any frame that
    /// arrives before the match (e.g. an EVENT from an active
    /// SUBSCRIBE) is discarded, not queued or dispatched elsewhere —
    /// correct for a client doing one thing at a time on the control
    /// stream, not yet correct for CALL and PUBLISH/SUBSCRIBE used
    /// concurrently on it. Harmless on a **dedicated** stream (content
    /// transfer, streaming RPC), since nothing else ever arrives there
    /// to discard.
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
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
        self.send_frame(signed).await.map_err(CallError::Send)?;

        tokio::time::timeout(timeout, self.await_call_response(call_id))
            .await
            .unwrap_or(Err(CallError::Recv(RecvFrameError::Timeout)))
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
    ) -> Result<frame::CallResponse, CallError> {
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
        self.send_frame(signed).await.map_err(CallError::Send)?;

        tokio::time::timeout(timeout, self.await_call_response(call_id))
            .await
            .unwrap_or(Err(CallError::Recv(RecvFrameError::Timeout)))
    }

    async fn await_call_response(
        &mut self,
        call_id: [u8; 16],
    ) -> Result<frame::CallResponse, CallError> {
        loop {
            let value = self.recv_frame().await.map_err(CallError::Recv)?;
            if frame::frame_call_id(&value) != Some(call_id) {
                continue; // not ours — see call()'s doc on this limitation
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
// Session — the handshaked connection, wrapping the control stream.
// ---------------------------------------------------------------------

/// A completed, handshaked connection to a macula-station. Holds the
/// open control stream (CONNECT/HELLO already exchanged) and the
/// station's identity as verified by the HELLO frame's own signature.
///
/// **Always call [`close`](Self::close) before this goes out of scope,
/// not just after your own logic is done with it -- especially right
/// after a send-then-return call like [`publish`](Self::publish) or
/// [`serve_one_call`](Self::serve_one_call).** There is deliberately no
/// `Drop` impl (flushing outstanding QUIC stream data needs `.await`,
/// which `Drop` can't do), so a bare drop tears down the connection
/// immediately with no guarantee the last write actually reached the
/// peer -- see [`close`](Self::close)'s own doc for the mechanism, and
/// [`serve_one_call`](Self::serve_one_call)'s for the specific,
/// confirmed-live way this bites a spawned provider task.
pub struct Session {
    /// Held only weakly by `open_sessions`, where direct dial finds it to
    /// open dedicated streams on, so dropping the session still drops the
    /// connection.
    connection: Arc<quinn::Connection>,
    control: FrameStream,
    /// The node id this session connected under.
    identity: [u8; 32],
    pub station: HelloInfo,
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
/// signature verifies against the node_id it claims.
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
        connect_inner(host, port, trust, identity),
    )
    .await
    .unwrap_or(Err(HandshakeError::Timeout))
}

async fn connect_inner(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
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
    crate::open_sessions::live().register(identity.node_id(), station.node_id, &connection);
    Ok(Session {
        connection,
        control: FrameStream::with_buf(send, recv, buf),
        identity: identity.node_id(),
        station,
    })
}

/// Read from `recv` until one complete frame has been decoded, returning
/// it along with any leftover bytes already read that belong to the
/// *next* frame (so a caller can carry them forward instead of losing
/// them). Handshake-only — [`FrameStream::recv_frame`] is the
/// post-handshake equivalent.
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

/// Open a dedicated QUIC stream on `connection`: what
/// [`Session::open_dedicated_stream`] does, for code that holds only the
/// connection, such as direct dial reusing another session's.
pub(crate) async fn dedicated_stream_on(
    connection: &quinn::Connection,
) -> Result<FrameStream, quinn::ConnectionError> {
    let (send, recv) = connection.open_bi().await?;
    Ok(FrameStream::new(send, recv))
}

impl Session {
    /// The remote address this session's connection is with.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    /// Open a new dedicated QUIC stream on this same connection, separate
    /// from the control stream — the mechanism content transfer (§12)
    /// and streaming RPC (§13) both use instead of the control stream.
    pub async fn open_dedicated_stream(&mut self) -> Result<FrameStream, quinn::ConnectionError> {
        dedicated_stream_on(&self.connection).await
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
    pub async fn accept_dedicated_stream(&mut self) -> Result<FrameStream, quinn::ConnectionError> {
        let (send, recv) = self.connection.accept_bi().await?;
        Ok(FrameStream::new(send, recv))
    }

    /// Any bytes already read past the HELLO frame during the handshake
    /// (belonging to whatever the station sent next) that a caller
    /// building further protocol handling on top of this `Session`
    /// should treat as already-received.
    pub fn leftover_bytes(&self) -> &[u8] {
        self.control.leftover_bytes()
    }

    /// Read the next complete application frame from the control stream.
    pub async fn recv_frame(&mut self) -> Result<Value, RecvFrameError> {
        self.control.recv_frame().await
    }

    /// As [`recv_frame`](Self::recv_frame), bounded by `timeout`.
    pub async fn recv_frame_timeout(&mut self, timeout: Duration) -> Result<Value, RecvFrameError> {
        self.control.recv_frame_timeout(timeout).await
    }

    /// Send a signed CALL on the control stream and wait for the
    /// matching RESULT or ERROR — see [`FrameStream::call`]. Announces
    /// `rpc.sent_v1`/`rpc.completed_v1` around the call — see
    /// `announce_rpc_sent` for why these are always on.
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        let request_id: [u8; 16] = rand::random();
        announce_rpc_sent(&mut *self, realm, identity, request_id).await;
        let result = self
            .control
            .call(procedure, realm, payload, deadline_ms, identity, timeout)
            .await;
        announce_rpc_completed(&mut *self, realm, identity, request_id, &result).await;
        result
    }

    /// As [`call`](Self::call), attaching `ucan_token` (e.g. from
    /// [`crate::ucan::create`]) to the outgoing CALL — for invoking a
    /// procedure gated by a [`crate::ucan::Policy::required`] policy on
    /// the provider side. See [`FrameStream::call_with_ucan`] for the
    /// full contract. Announces `rpc.sent_v1`/`rpc.completed_v1` the same
    /// way [`call`](Self::call) does.
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
    ) -> Result<frame::CallResponse, CallError> {
        let request_id: [u8; 16] = rand::random();
        announce_rpc_sent(&mut *self, realm, identity, request_id).await;
        let result = self
            .control
            .call_with_ucan(
                procedure,
                realm,
                payload,
                deadline_ms,
                identity,
                timeout,
                ucan_token,
            )
            .await;
        announce_rpc_completed(&mut *self, realm, identity, request_id, &result).await;
        result
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
    /// to the same topic/realm) receives an EVENT asynchronously, read
    /// via [`recv_frame`](Self::recv_frame) /
    /// [`recv_event`](Self::recv_event).
    pub async fn publish(
        &mut self,
        spec: &frame::PublishSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let unsigned = frame::publish(spec);
        let with_publisher_sig = frame::sign_publisher(unsigned, identity);
        let signed = frame::sign(with_publisher_sig, identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed SUBSCRIBE. Fire-and-forget.
    pub async fn subscribe(
        &mut self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::subscribe(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed UNSUBSCRIBE. Fire-and-forget.
    pub async fn unsubscribe(
        &mut self,
        spec: &frame::UnsubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::unsubscribe(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed ADVERTISE (§6.9) — registers this connection as the
    /// handler for `spec`'s `(realm, procedure)`. Fire-and-forget on the
    /// wire; the station then routes inbound CALLs (control stream) and
    /// STREAM_OPENs (a fresh dedicated stream — see
    /// [`accept_dedicated_stream`](Self::accept_dedicated_stream)) for
    /// that procedure back to this connection.
    pub async fn advertise(
        &mut self,
        spec: &frame::AdvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::advertise(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed UNADVERTISE. Fire-and-forget.
    pub async fn unadvertise(
        &mut self,
        spec: &frame::UnadvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::unadvertise(spec), identity);
        self.control.send_frame(signed).await
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
    /// detect or repair a dead session on its own; if the underlying
    /// connection has actually gone down, every tick will keep failing
    /// until `stop` resolves. See
    /// [`crate::direct_dial::keep_advertised_direct`] for the direct-dial
    /// equivalent (same shape, same reasoning).
    pub async fn keep_advertised<F>(
        &mut self,
        spec: &frame::AdvertiseSpec,
        identity: &KeyPair,
        interval: Duration,
        stop: F,
        on_error: impl Fn(SendFrameError),
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

    /// Read the next frame and parse it as an EVENT, bounded by
    /// `timeout`. Any non-EVENT frame received first is an error, not
    /// silently skipped — unlike [`call`](Self::call)'s response wait,
    /// a caller waiting specifically for a pubsub delivery has no reason
    /// to expect anything else to legitimately arrive first.
    pub async fn recv_event(
        &mut self,
        timeout: Duration,
    ) -> Result<frame::EventInfo, RecvEventError> {
        let value = self
            .control
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvEventError::Recv)?;
        frame::parse_event(&value).map_err(RecvEventError::Parse)
    }

    /// The provider role's counterpart to [`call`](Self::call): block
    /// for the next inbound CALL frame on the control stream, bounded
    /// by `timeout`, look it up via `lookup`, invoke the matching
    /// handler, and send the resulting RESULT or ERROR back over this
    /// same connection — see `plans/PLAN_WIRE_PROTOCOL.md` §6.9's
    /// routing description and `macula_station_link.erl`'s
    /// `handle_inbound_call/2`, which this mirrors field for field,
    /// including its BOLT#4 error-code mapping.
    ///
    /// Any non-CALL frame that arrives first (e.g. a stray EVENT from
    /// an active [`subscribe`](Self::subscribe), or a RESULT/ERROR for
    /// some other in-flight [`call`](Self::call)) is discarded, not
    /// queued — the same "control stream, one thing at a time"
    /// limitation [`call`](Self::call)'s own doc already carries. A
    /// session that needs to serve CALLs and also act as a
    /// caller/subscriber concurrently should use a second `Session`,
    /// exactly like this crate's own streaming-provider live test does.
    ///
    /// A caller wanting a long-lived server loops on this:
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # async fn example(session: &mut macula_rust::connection::Session, identity: &macula_rust::identity::KeyPair, lookup: impl Fn(&[u8; 32], &str) -> Option<macula_rust::connection::CallHandler>) {
    /// loop {
    ///     if let Err(e) = session.serve_one_call(&lookup, identity, Duration::from_secs(30)).await {
    ///         // ServeCallError::Timeout just means nothing arrived -- keep looping.
    ///         eprintln!("{e}");
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// **Do not let this `Session` drop right after this call returns --
    /// call [`close`](Self::close) on it explicitly first.** This is the
    /// single most common way to lose the RESULT/ERROR you just sent:
    /// `serve_one_call` returning `Ok(())` only means the reply was
    /// handed to quinn's own send-scheduling machinery, exactly like
    /// [`close`](Self::close)'s own doc explains for `write_all`/`finish`
    /// -- a bare `Drop` (this type intentionally has none) does nothing
    /// to wait for that to actually reach the peer before the underlying
    /// resources are torn down, while `close` has a deliberate bounded
    /// drain for precisely this. Confirmed live 2026-09-05 with the
    /// single most natural-looking way to hit it: spawning this session
    /// into its own `tokio::spawn` task with nothing following the
    /// `.await` -- the task (and this `Session` with it) can complete
    /// and drop within microseconds of the write, deterministically
    /// under a multi-threaded runtime, losing the reply every time. Move
    /// the session back out of the task and close it explicitly instead,
    /// same as this crate's own `tests/live_station.rs` does for every
    /// spawned provider role.
    pub async fn serve_one_call<L>(
        &mut self,
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
    /// `caller` it names; a CALL that doesn't is dropped with no reply, as
    /// `macula_station_link.erl`'s `on_inbound_call/3` does, and this keeps
    /// waiting for the next one.
    pub async fn serve_one_call_gated<L, P>(
        &mut self,
        lookup: L,
        policy: P,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
        P: Fn(&[u8; 32], &str) -> crate::ucan::Policy,
    {
        tokio::time::timeout(
            timeout,
            self.serve_one_call_gated_inner(lookup, policy, identity),
        )
        .await
        .unwrap_or(Err(ServeCallError::Timeout))
    }

    async fn serve_one_call_gated_inner<L, P>(
        &mut self,
        lookup: L,
        policy: P,
        identity: &KeyPair,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
        P: Fn(&[u8; 32], &str) -> crate::ucan::Policy,
    {
        loop {
            let value = self
                .control
                .recv_frame()
                .await
                .map_err(ServeCallError::Recv)?;
            let Some(reply) =
                reply_to_frame(&value, &lookup, &policy, identity, Some(&mut *self)).await
            else {
                continue; // not a CALL signed by its caller -- see this method's doc
            };
            let signed = frame::sign(reply, identity);
            self.control
                .send_frame(signed)
                .await
                .map_err(ServeCallError::Send)?;
            return Ok(());
        }
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
    /// crate isn't holding a supervisor to clean up).
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
    pub async fn close(mut self, reason: &str, detail: Option<&str>, identity: &KeyPair) {
        crate::open_sessions::live().unregister(
            self.identity,
            self.station.node_id,
            &self.connection,
        );
        let goodbye = frame::sign(frame::goodbye(reason, detail), identity);
        if let Ok(encoded) = frame::encode(&goodbye) {
            let _ = self.control.send.write_all(&encoded).await;
        }
        let _ = self.control.send.finish();
        tokio::time::sleep(Self::CLOSE_DRAIN).await;
        self.connection.close(0u32.into(), reason.as_bytes());
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
        &mut self,
        spec: &frame::PublishSpec,
        identity: &KeyPair,
        announce: bool,
    ) -> Result<(), SendFrameError> {
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

    /// The supervised counterpart to the bare
    /// [`subscribe`](Self::subscribe)/[`recv_event`](Self::recv_event)
    /// primitives, matching `macula_subscriber.erl` in spirit: subscribes
    /// once, then dispatches every inbound EVENT to `handler` until `stop`
    /// resolves. Unsubscribes on return, including on cancellation.
    ///
    /// Mirrors [`serve_one_call`](Self::serve_one_call)'s own frame loop,
    /// not [`recv_event`](Self::recv_event): a shared control stream can
    /// carry other frame types between one EVENT and the next, so a
    /// wrong-frame-type parse failure is skipped and polling continues,
    /// exactly like `serve_one_call` skips a non-"call" frame — it is NOT
    /// treated as fatal the way `recv_event`'s own contract treats any
    /// parse failure. Confirmed live in the Go port of this exact pattern
    /// (`macula-go`'s `Session.RunSubscriber`): without this, a single
    /// non-EVENT frame arriving on the control stream aborted the whole
    /// subscriber loop.
    ///
    /// No OTP pid to address a running subscriber by; `stop` plays that
    /// role — matches [`keep_advertised`](Self::keep_advertised)'s own
    /// cancellation shape exactly, not a new one. `handler` cannot itself
    /// stop the loop (no return value) — by the same design `keep_advertised`
    /// already established, where `on_error` can only report, not halt;
    /// stopping is always external, via `stop`.
    pub async fn run_subscriber<F>(
        &mut self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
        stop: F,
        mut handler: impl FnMut(frame::EventInfo),
    ) -> Result<(), RunSubscriberError>
    where
        F: std::future::Future<Output = ()>,
    {
        self.subscribe(spec, identity)
            .await
            .map_err(RunSubscriberError::Subscribe)?;

        tokio::pin!(stop);
        let result = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                frame_result = self.control.recv_frame() => {
                    let value = match frame_result {
                        Ok(v) => v,
                        Err(e) => break Err(RunSubscriberError::Recv(e)),
                    };
                    let Ok(evt) = frame::parse_event(&value) else {
                        continue; // not ours -- see this method's doc on the limitation
                    };
                    handler(evt);
                }
            }
        };

        let _ = self
            .unsubscribe(
                &frame::UnsubscribeSpec::new(spec.topic.clone(), spec.realm, spec.subscriber),
                identity,
            )
            .await;

        result
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as u64
}

#[derive(Debug)]
pub enum RecvEventError {
    Recv(RecvFrameError),
    Parse(frame::ParseEventError),
}

impl std::fmt::Display for RecvEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvEventError::Recv(e) => write!(f, "{e}"),
            RecvEventError::Parse(e) => write!(f, "expected an EVENT frame: {e}"),
        }
    }
}

impl std::error::Error for RecvEventError {}

#[derive(Debug)]
pub enum ServeCallError {
    Recv(RecvFrameError),
    Send(SendFrameError),
    /// No inbound CALL arrived within the requested timeout.
    Timeout,
}

impl std::fmt::Display for ServeCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeCallError::Recv(e) => write!(f, "{e}"),
            ServeCallError::Send(e) => write!(f, "sending the reply: {e}"),
            ServeCallError::Timeout => write!(f, "timed out waiting for an inbound CALL"),
        }
    }
}

impl std::error::Error for ServeCallError {}

/// Errors from [`Session::run_subscriber`].
#[derive(Debug)]
pub enum RunSubscriberError {
    Subscribe(SendFrameError),
    Recv(RecvFrameError),
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
// RPC telemetry auto-facts, matching `macula_request.erl` (caller side:
// rpc.sent_v1/rpc.completed_v1) and `macula_response.erl` (provider side:
// rpc.received_v1/rpc.replied_v1) exactly -- same topic names, same
// `request_id` field (16 fresh random bytes per call, independent of the
// wire CALL frame's own `call_id` -- the reference tracks its own request
// lifecycle separately from the wire frame, and this does too), same realm
// as the call itself, fire-and-forget (a fact-publish failure here never
// fails the underlying `call`/`serve_one_call_gated`, matching
// `macula_response.erl`'s own `_ = macula:publish(...), ok` and
// `macula_request.erl`'s identical `publish/5` helper -- same pattern this
// crate's own `run_publisher` already uses for its pubsub facts).
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

async fn announce_fact(
    session: &mut Session,
    realm: [u8; 32],
    identity: &KeyPair,
    topic: &str,
    payload: Value,
) {
    let fact = frame::PublishSpec::new(
        topic,
        realm,
        identity.node_id(),
        rand::random(),
        payload,
        now_ms(),
    );
    let _ = session.publish(&fact, identity).await;
}

async fn announce_rpc_sent(
    session: &mut Session,
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
) {
    announce_fact(
        session,
        realm,
        identity,
        RPC_SENT_TOPIC,
        request_id_payload(request_id),
    )
    .await;
}

/// Matches `macula_request.erl`'s `outcome_fields/2`: `completed` (no Rust
/// error, not a bolt4 ERROR frame) or `failed` (either). Erlang
/// additionally has a `cancelled` outcome from its own
/// gen_server-cancellable `macula_request:cancel/1` -- this crate's plain
/// `call` has no cancellation concept independent of an ordinary
/// error/timeout at this layer, so that outcome is not reachable here and
/// is not fabricated (same reasoning Go's port already documented).
async fn announce_rpc_completed(
    session: &mut Session,
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
    result: &Result<frame::CallResponse, CallError>,
) {
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
    announce_fact(session, realm, identity, RPC_COMPLETED_TOPIC, payload).await;
}

async fn announce_rpc_received(
    session: &mut Session,
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
) {
    announce_fact(
        session,
        realm,
        identity,
        RPC_RECEIVED_TOPIC,
        request_id_payload(request_id),
    )
    .await;
}

/// Matches `macula_response.erl`'s `outcome_fields/2`: `replied` (`{ok,
/// _}`) or `failed` (`{error, Reason}`). A handler panic is deliberately
/// NOT announced here at all -- matching the reference exactly, where a
/// crashing `Module:handle_request/2` crashes the whole per-request child
/// before its own `publish_replied/2` call is ever reached, so
/// `REQUEST_REPLIED` is never published for a crash there either.
async fn announce_rpc_replied(
    session: &mut Session,
    realm: [u8; 32],
    identity: &KeyPair,
    request_id: [u8; 16],
    handler_err: Option<&str>,
) {
    let payload = request_id_payload(request_id);
    let payload = match handler_err {
        Some(reason) => payload
            .with_field("outcome", Value::text("failed"))
            .with_field("reason", Value::text(reason)),
        None => payload.with_field("outcome", Value::text("replied")),
    };
    announce_fact(session, realm, identity, RPC_REPLIED_TOPIC, payload).await;
}

/// The reply to one inbound frame, or `None` when there is nothing to
/// answer: the frame isn't a CALL, or its signature doesn't verify against
/// the `caller` it names. Mirrors `macula_station_link.erl`'s
/// `on_inbound_call/3`: a CALL that isn't signed by the caller it names
/// never reaches policy or a handler, and gets no reply. Otherwise
/// [`build_call_reply`].
async fn reply_to_frame<L, P>(
    value: &Value,
    lookup: &L,
    policy: &P,
    identity: &KeyPair,
    session: Option<&mut Session>,
) -> Option<Value>
where
    L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
    P: Fn(&[u8; 32], &str) -> crate::ucan::Policy,
{
    let call_info = frame::parse_call(value).ok()?;
    frame::verify(value, &call_info.caller).ok()?;
    Some(build_call_reply(call_info, lookup, policy, identity, session).await)
}

/// Fires `rpc.received_v1`/`rpc.replied_v1` around dispatch when `session`
/// is `Some` -- `None` for the pure dispatch-logic unit tests in
/// `ucan_gating_tests` below, which deliberately exercise this function
/// with no network at all (mirrors `macula-go`'s identical
/// nil-session-safe `announceFact`). `rpc.received_v1` fires only after
/// `policy` and `lookup` both pass, matching `macula_response.erl`'s own
/// per-request child only starting once the raw advertise mechanism
/// already decided to dispatch to a real handler -- a UCAN-rejected or
/// unadvertised-procedure CALL announces neither fact.
///
/// `#[allow(needless_option_as_deref)]`: the lint is right that
/// `Option<&mut Session>::as_deref_mut()`'s RETURN type is identical to
/// its input type, but wrong that the call is needless here -- three
/// separate call sites below each need their own short-lived reborrow
/// from the same `session` local; using `session` directly at any one of
/// them would move it out for the rest of the function, breaking the
/// other two.
#[allow(clippy::needless_option_as_deref)]
async fn build_call_reply<L, P>(
    call_info: frame::CallInfo,
    lookup: &L,
    policy: &P,
    identity: &KeyPair,
    mut session: Option<&mut Session>,
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
    if let Some(s) = session.as_deref_mut() {
        announce_rpc_received(s, call_info.realm, identity, request_id).await;
    }

    let payload = call_info.payload;
    let outcome = tokio::spawn(async move { handler(payload).await }).await;
    match outcome {
        Ok(Ok(value)) => {
            if let Some(s) = session.as_deref_mut() {
                announce_rpc_replied(s, call_info.realm, identity, request_id, None).await;
            }
            frame::result(&frame::ResultSpec::new(call_info.call_id, value, self_pub))
        }
        Ok(Err(reason)) => {
            if let Some(s) = session.as_deref_mut() {
                announce_rpc_replied(s, call_info.realm, identity, request_id, Some(&reason)).await;
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    // The provider side of an inbound CALL: a CALL reaches policy and a
    // handler only when its signature verifies against the caller it names,
    // and a gated policy accepts a token only from the caller it was minted
    // for. The names match macula-go's connection/serve_caller_test.go; the
    // behaviour matches macula_station_link.erl's on_inbound_call/3.

    fn call_frame(named_caller: &KeyPair) -> Value {
        frame::call(&frame::CallSpec::new(
            [3; 16],
            "test.proc",
            [0; 32],
            Value::text("hello"),
            0,
            named_caller.node_id(),
        ))
    }

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

    /// An echo handler that counts how often it ran.
    fn counting_lookup(
        invocations: Arc<AtomicUsize>,
    ) -> impl Fn(&[u8; 32], &str) -> Option<CallHandler> {
        move |_, _| {
            let invocations = invocations.clone();
            Some(Arc::new(move |payload: Value| {
                invocations.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(payload) })
            }))
        }
    }

    fn is_unauthorized(reply: &Value) -> bool {
        matches!(
            frame::parse_call_response(reply),
            Ok(frame::CallResponse::Error { code, .. }) if code == bolt4::Code::Unauthorized as u8
        )
    }

    #[tokio::test]
    async fn reply_to_frame_ignores_a_call_not_signed_by_its_caller() {
        let (named, signer) = (KeyPair::generate(), KeyPair::generate());
        let invocations = Arc::new(AtomicUsize::new(0));

        let reply = reply_to_frame(
            &frame::sign(call_frame(&named), &signer),
            &counting_lookup(invocations.clone()),
            &|_, _| Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(reply.is_none(), "{reply:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reply_to_frame_ignores_an_unsigned_call() {
        let invocations = Arc::new(AtomicUsize::new(0));

        let reply = reply_to_frame(
            &call_frame(&KeyPair::generate()),
            &counting_lookup(invocations.clone()),
            &|_, _| Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(reply.is_none(), "{reply:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reply_to_frame_answers_a_call_signed_by_its_caller() {
        let caller = KeyPair::generate();
        let invocations = Arc::new(AtomicUsize::new(0));

        let reply = reply_to_frame(
            &frame::sign(call_frame(&caller), &caller),
            &counting_lookup(invocations.clone()),
            &|_, _| Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await
        .expect("a CALL signed by its caller is answered");

        assert!(matches!(
            frame::parse_call_response(&reply),
            Ok(frame::CallResponse::Result { .. })
        ));
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
    }

    /// A `CallInfo` always carries a 32-byte caller, so a CALL without one
    /// can't reach the policy at all: the frame itself is dropped.
    #[tokio::test]
    async fn reply_to_frame_ignores_a_call_without_caller() {
        let caller = KeyPair::generate();
        let invocations = Arc::new(AtomicUsize::new(0));

        let reply = reply_to_frame(
            &frame::sign(call_frame(&caller).without(&["caller"]), &caller),
            &counting_lookup(invocations.clone()),
            &|_, _| Policy::open(),
            &KeyPair::generate(),
            None,
        )
        .await;

        assert!(reply.is_none(), "{reply:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
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
