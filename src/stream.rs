//! General-purpose streaming RPC, caller/consumer role (§13.1 of
//! `plans/PLAN_WIRE_PROTOCOL.md`), ported from `macula_stream_sink.erl`.
//! Like content transfer (`src/content.rs`), this is not a separate wire
//! mechanism: it runs the frame types built in `src/frame.rs` §13 over a
//! dedicated QUIC stream, opened via
//! [`Session::open_dedicated_stream`](crate::connection::Session::open_dedicated_stream)
//! rather than the control stream.
//!
//! **Both roles are built.** Caller/consumer (§13.1) opens a stream and
//! is the natural fit for pulling/pushing against a procedure that
//! already exists somewhere. Provider (§13.2) advertises a procedure
//! (§6.9, [`Session::advertise`](crate::connection::Session::advertise))
//! and answers inbound STREAM_OPENs the station routes back —
//! [`Session::accept_dedicated_stream`](crate::connection::Session::accept_dedicated_stream)
//! accepts the fresh dedicated stream the station opens toward us,
//! [`StreamHandle::accept`] reads and parses the STREAM_OPEN that's
//! always its first frame. Both roles end up holding the same
//! [`StreamHandle`] afterward — a stream's wire vocabulary
//! (STREAM_DATA/END/ERROR/REPLY) is symmetric regardless of which side
//! opened it, so `send_data`/`recv`/`close_send`/`abort` all mean the
//! same thing either way. [`StreamHandle::send_reply`] is the one
//! provider-only addition: sending the terminal STREAM_REPLY a
//! `client_stream`/`bidi` caller's own
//! [`await_reply`](StreamHandle::await_reply) is waiting on.
//!
//! Caller/consumer usage, matching the reference's own pattern:
//! 1. [`StreamHandle::open`] sends STREAM_OPEN and returns a handle once
//!    the frame is on the wire — there's no open-time acknowledgement to
//!    wait for; the provider starts reacting to it directly.
//! 2. Drive a receive loop with [`StreamHandle::recv`] until
//!    [`StreamItem::Eof`] or an error.
//! 3. For `client_stream`/`bidi` modes wanting a result:
//!    [`StreamHandle::send_data`] each chunk in order,
//!    [`StreamHandle::close_send`] when done, then
//!    [`StreamHandle::await_reply`].
//! 4. **Non-normal termination must call [`StreamHandle::abort`], not
//!    just drop the handle** — the peer's only signal to tell a
//!    cancellation/failure apart from a dropped connection
//!    (`plans/PLAN_WIRE_PROTOCOL.md` §13.1, point 4).
//!
//! Provider usage:
//! 1. [`Session::advertise`](crate::connection::Session::advertise) once
//!    per procedure this session will answer.
//! 2. Loop on [`StreamHandle::accept`], which blocks for the next
//!    inbound STREAM_OPEN and hands back a ready-to-use handle plus the
//!    parsed [`frame::StreamOpenInfo`] (check its `procedure` — a single
//!    connection's dedicated streams aren't partitioned by which
//!    procedure they're for, so a session that's advertised more than
//!    one needs this to route).
//! 3. Drive it exactly like the caller side, from the opposite chair:
//!    `server_stream` mode pushes with `send_data`/`close_send`;
//!    `client_stream` mode drains with `recv` and finishes with
//!    `send_reply`.

use std::time::Duration;

use crate::cbor::Value;
use crate::connection::{FrameStream, RecvFrameError, SendFrameError, Session};
use crate::control_channel::drop_warning::{self, Kind, Reason, Subject};
use crate::frame::{self, StreamEncoding, StreamMode, StreamRole};
use crate::identity::KeyPair;

pub struct StreamHandle {
    stream: FrameStream,
    pub stream_id: [u8; 16],
    pub mode: StreamMode,
    seq_out: u64,
}

#[derive(Debug)]
pub enum OpenError {
    OpenStream(quinn::ConnectionError),
    Send(SendFrameError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::OpenStream(e) => write!(f, "opening a dedicated stream: {e}"),
            OpenError::Send(e) => write!(f, "sending stream_open: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

#[derive(Debug)]
pub enum AcceptError {
    AcceptStream(quinn::ConnectionError),
    Timeout,
    Recv(RecvFrameError),
}

/// The application error code a refused inbound stream is aborted with, in
/// both directions: RESET_STREAM on its send half and STOP_SENDING on its
/// receive half. The same code in every Macula stack.
pub const REFUSED_STREAM: u32 = 2;

/// What became of an inbound dedicated stream that didn't open.
enum Inbound {
    /// Refused, with nothing written and no handler run.
    Refused {
        reason: Reason,
        subject: Subject,
    },
    Failed(AcceptError),
}

fn refuse(stream: FrameStream, reason: Reason, subject: Subject) -> Inbound {
    stream.abort_both(REFUSED_STREAM);
    Inbound::Refused { reason, subject }
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::AcceptStream(e) => write!(f, "accepting a dedicated stream: {e}"),
            AcceptError::Timeout => write!(f, "no inbound stream within the given timeout"),
            AcceptError::Recv(e) => write!(f, "reading the stream's first frame: {e}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// One item [`StreamHandle::recv`] hands back: a chunk, or a clean
/// end-of-stream.
#[derive(Debug, Clone)]
pub enum StreamItem {
    Data {
        seq: u64,
        encoding: StreamEncoding,
        body: Value,
    },
    Eof,
}

#[derive(Debug)]
pub enum RecvStreamError {
    Recv(RecvFrameError),
    Parse(frame::ParseStreamEventError),
    /// The peer sent an explicit STREAM_ERROR abort.
    PeerAborted {
        code: String,
        message: String,
    },
    /// A frame for a *different* stream_id arrived on this stream —
    /// never expected on a dedicated stream with a well-behaved peer,
    /// surfaced distinctly rather than silently accepted.
    StreamIdMismatch,
    /// A frame arrived that isn't valid in the context this call is
    /// waiting in — e.g. [`StreamHandle::recv`] got a STREAM_REPLY
    /// (only [`StreamHandle::await_reply`] expects one), or
    /// `await_reply` got a STREAM_DATA/STREAM_END before any reply.
    UnexpectedFrame,
}

impl std::fmt::Display for RecvStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvStreamError::Recv(e) => write!(f, "{e}"),
            RecvStreamError::Parse(e) => write!(f, "{e}"),
            RecvStreamError::PeerAborted { code, message } => {
                write!(f, "peer aborted the stream: {code} ({message})")
            }
            RecvStreamError::StreamIdMismatch => {
                write!(f, "received a frame for a different stream_id")
            }
            RecvStreamError::UnexpectedFrame => {
                write!(f, "received a frame not valid in this context")
            }
        }
    }
}

impl std::error::Error for RecvStreamError {}

impl StreamHandle {
    /// Open a dedicated stream on `session`'s connection and send a
    /// signed STREAM_OPEN. Fire-and-forget at the wire level — no reply
    /// is expected here; drive [`recv`](Self::recv) (for
    /// `server_stream`/`bidi`) or [`send_data`](Self::send_data) (for
    /// `client_stream`/`bidi`) next, depending on `mode`.
    pub async fn open(
        session: &Session,
        procedure: &str,
        realm: [u8; 32],
        mode: StreamMode,
        args: Value,
        deadline_ms: i128,
        identity: &KeyPair,
    ) -> Result<Self, OpenError> {
        let stream = session
            .open_dedicated_stream()
            .await
            .map_err(OpenError::OpenStream)?;
        Self::open_on(stream, procedure, realm, mode, args, deadline_ms, identity).await
    }

    /// [`open`](Self::open), over a dedicated stream already open to the
    /// station.
    pub(crate) async fn open_on(
        mut stream: FrameStream,
        procedure: &str,
        realm: [u8; 32],
        mode: StreamMode,
        args: Value,
        deadline_ms: i128,
        identity: &KeyPair,
    ) -> Result<Self, OpenError> {
        let stream_id: [u8; 16] = rand::random();
        let spec = frame::StreamOpenSpec::new(
            stream_id,
            procedure,
            realm,
            mode,
            args,
            deadline_ms,
            identity.node_id(),
        );
        let signed = frame::sign(frame::stream_open(&spec), identity);
        stream.send_frame(signed).await.map_err(OpenError::Send)?;
        Ok(Self {
            stream,
            stream_id,
            mode,
            seq_out: 0,
        })
    }

    /// Provider role: block for the next inbound STREAM_OPEN on
    /// `session`'s connection, bounded by `timeout`. Only ever succeeds
    /// after [`Session::advertise`](crate::connection::Session::advertise)
    /// has registered at least one procedure — otherwise the station has
    /// nothing to route here. Returns the ready-to-use handle alongside
    /// the parsed [`frame::StreamOpenInfo`] (check its `procedure` if
    /// this session advertised more than one).
    ///
    /// The app decides whether to serve a stream it accepts. One it refuses
    /// should get a STREAM_ERROR with macula's codes, `unauthorized` when the
    /// caller may not use the procedure and `not_found` for a procedure it
    /// doesn't serve, sent with [`refuse`](Self::refuse), so a caller sees the
    /// same refusal from every stack.
    pub async fn accept(
        session: &Session,
        timeout: Duration,
    ) -> Result<(Self, frame::StreamOpenInfo), AcceptError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let stream = tokio::time::timeout_at(deadline, session.accept_dedicated_stream())
                .await
                .map_err(|_| AcceptError::Timeout)?
                .map_err(AcceptError::AcceptStream)?;
            match tokio::time::timeout_at(deadline, Self::open_inbound(stream)).await {
                Err(_) => return Err(AcceptError::Timeout),
                Ok(Ok(opened)) => return Ok(opened),
                Ok(Err(Inbound::Refused { reason, subject })) => {
                    session
                        .drop_warnings()
                        .record(Kind::RefusedStreamOpen, reason, subject);
                }
                Ok(Err(Inbound::Failed(e))) => return Err(e),
            }
        }
    }

    /// Opens `stream`, an inbound dedicated stream, when its first frame is a
    /// STREAM_OPEN signed by the caller it names, with that caller in map
    /// args as a CALL handler gets it. Any other first frame gets the stream
    /// refused before anything else looks at it: both halves are aborted
    /// with [`REFUSED_STREAM`] and nothing is written, as macula does.
    async fn open_inbound(
        mut stream: FrameStream,
    ) -> Result<(Self, frame::StreamOpenInfo), Inbound> {
        let first = match stream.recv_frame().await {
            Ok(first) => first,
            Err(RecvFrameError::Decode(_)) => {
                return Err(refuse(stream, Reason::Malformed, Subject::Nothing))
            }
            Err(e) => return Err(Inbound::Failed(AcceptError::Recv(e))),
        };
        if !matches!(first.get("frame_type"), Some(Value::Text(t)) if t == "stream_open") {
            return Err(refuse(stream, Reason::NotAStreamOpen, Subject::Nothing));
        }
        if let Err(reason) = drop_warning::signed_caller(&first) {
            return Err(refuse(stream, reason, drop_warning::procedure_of(&first)));
        }
        let Ok(mut open) = frame::parse_stream_open(&first) else {
            return Err(refuse(
                stream,
                Reason::Malformed,
                drop_warning::procedure_of(&first),
            ));
        };
        open.args = crate::connection::with_caller(open.args, open.caller);
        let handle = Self {
            stream,
            stream_id: open.stream_id,
            mode: open.mode,
            seq_out: 0,
        };
        Ok((handle, open))
    }

    /// Provider role: send the terminal STREAM_REPLY a `client_stream`/
    /// `bidi` caller's own [`await_reply`](Self::await_reply) is waiting
    /// on, once this side has fully consumed and verified whatever the
    /// caller streamed.
    pub async fn send_reply(
        &mut self,
        payload: Value,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let spec = frame::StreamReplySpec::new(self.stream_id, payload, identity.node_id());
        let signed = frame::sign(frame::stream_reply(&spec), identity);
        self.stream.send_frame(signed).await
    }

    /// Send one chunk. `seq` is tracked internally, starting at 0 and
    /// incrementing per call — matches the reference's `seq_out` counter
    /// (a sanity/debugging signal, not used for reordering: frames
    /// arrive in order on a single QUIC stream by construction).
    pub async fn send_data(
        &mut self,
        encoding: StreamEncoding,
        body: Value,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let spec = frame::StreamDataSpec::new(
            self.stream_id,
            self.seq_out,
            encoding,
            body,
            Some(identity.public_bytes()),
        );
        self.seq_out += 1;
        let signed = frame::sign(frame::stream_data(&spec), identity);
        self.stream.send_frame(signed).await
    }

    /// Half-close: signal this side is done sending. For
    /// `client_stream`/`bidi` modes, follow with
    /// [`await_reply`](Self::await_reply).
    pub async fn close_send(&mut self, identity: &KeyPair) -> Result<(), SendFrameError> {
        let spec = frame::StreamEndSpec::new(
            self.stream_id,
            StreamRole::Send,
            Some(identity.public_bytes()),
        );
        let signed = frame::sign(frame::stream_end(&spec), identity);
        self.stream.send_frame(signed).await
    }

    /// Receive the next chunk or end-of-stream, bounded by `timeout`.
    pub async fn recv(&mut self, timeout: Duration) -> Result<StreamItem, RecvStreamError> {
        let value = self
            .stream
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvStreamError::Recv)?;
        match frame::parse_stream_event(&value).map_err(RecvStreamError::Parse)? {
            frame::StreamEvent::Data {
                stream_id,
                seq,
                encoding,
                body,
            } => {
                self.check_stream_id(stream_id)?;
                Ok(StreamItem::Data {
                    seq,
                    encoding,
                    body,
                })
            }
            frame::StreamEvent::End { stream_id, role: _ } => {
                self.check_stream_id(stream_id)?;
                Ok(StreamItem::Eof)
            }
            frame::StreamEvent::Error {
                stream_id,
                code,
                message,
            } => {
                self.check_stream_id(stream_id)?;
                Err(RecvStreamError::PeerAborted { code, message })
            }
            frame::StreamEvent::Reply { .. } => Err(RecvStreamError::UnexpectedFrame),
        }
    }

    /// Block for the provider's terminal STREAM_REPLY (`client_stream`/
    /// `bidi` modes only) — call after [`close_send`](Self::close_send).
    pub async fn await_reply(
        &mut self,
        timeout: Duration,
    ) -> Result<(Value, [u8; 32]), RecvStreamError> {
        let value = self
            .stream
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvStreamError::Recv)?;
        match frame::parse_stream_event(&value).map_err(RecvStreamError::Parse)? {
            frame::StreamEvent::Reply {
                stream_id,
                payload,
                responded_by,
            } => {
                self.check_stream_id(stream_id)?;
                Ok((payload, responded_by))
            }
            frame::StreamEvent::Error {
                stream_id,
                code,
                message,
            } => {
                self.check_stream_id(stream_id)?;
                Err(RecvStreamError::PeerAborted { code, message })
            }
            frame::StreamEvent::Data { .. } | frame::StreamEvent::End { .. } => {
                Err(RecvStreamError::UnexpectedFrame)
            }
        }
    }

    fn check_stream_id(&self, stream_id: [u8; 16]) -> Result<(), RecvStreamError> {
        if stream_id == self.stream_id {
            Ok(())
        } else {
            Err(RecvStreamError::StreamIdMismatch)
        }
    }

    /// Non-normal termination: explicitly tell the peer this stream is
    /// aborting, per §13.1 point 4 — the only signal the peer gets to
    /// distinguish a cancellation/failure from a dropped connection.
    /// Best-effort, like [`Session::close`](crate::connection::Session::close)'s
    /// GOODBYE — consumes `self` so the handle can't be used again after
    /// aborting.
    pub async fn abort(
        mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        identity: &KeyPair,
    ) {
        let spec = frame::StreamErrorSpec::new(
            self.stream_id,
            code,
            message,
            Some(identity.public_bytes()),
        );
        let signed = frame::sign(frame::stream_error(&spec), identity);
        let _ = self.stream.send_frame(signed).await;
    }

    /// Refuses a stream this provider accepted and won't serve: writes a
    /// STREAM_ERROR with `code` and `message`, macula's `unauthorized` or
    /// `not_found`, then finishes the send half so the error reaches the caller
    /// and stops reading with [`REFUSED_STREAM`]. When the STREAM_ERROR can't
    /// be written, the stream is aborted in both directions with
    /// [`REFUSED_STREAM`] instead.
    pub async fn refuse(
        mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let spec = frame::StreamErrorSpec::new(
            self.stream_id,
            code,
            message,
            Some(identity.public_bytes()),
        );
        let signed = frame::sign(frame::stream_error(&spec), identity);
        if let Err(e) = self.stream.send_frame(signed).await {
            self.stream.abort_both(REFUSED_STREAM);
            return Err(e);
        }
        self.stream.finish_and_stop_reading(REFUSED_STREAM);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! An inbound dedicated stream over a real QUIC connection to a local
    //! endpoint, so a refusal's abort codes reach the opener as they would
    //! from a station. The names match the Go, .NET and Erlang tests.
    use super::*;
    use crate::transport::Trust;

    const REALM: [u8; 32] = [7; 32];

    /// A connection to a local endpoint, the endpoint's side of it, and the
    /// endpoint, which has to outlive both.
    async fn local_connection() -> (quinn::Connection, quinn::Connection, quinn::Endpoint) {
        let key_pair = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params")
            .self_signed(&key_pair)
            .expect("a self-signed certificate");
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], key)
            .expect("a server certificate");
        // The client only talks to a peer that speaks macula's ALPN protocol.
        crypto.alpn_protocols = vec![crate::transport::ALPN.to_vec()];
        let config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .expect("a QUIC server config"),
        ));
        let endpoint =
            quinn::Endpoint::server(config, ([127, 0, 0, 1], 0).into()).expect("a local endpoint");
        let port = endpoint.local_addr().expect("a local address").port();
        let (opener, provider) = tokio::join!(
            crate::transport::connect("127.0.0.1", port, Trust::Insecure),
            async {
                endpoint
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("the connection completes")
            }
        );
        (opener.expect("the opener connects"), provider, endpoint)
    }

    /// Opens a stream from `opener` that starts with `first`, and takes the
    /// provider's side of it.
    async fn opened_with(
        opener: &quinn::Connection,
        provider: &quinn::Connection,
        first: &[u8],
    ) -> (quinn::SendStream, quinn::RecvStream, FrameStream) {
        let (mut send, recv) = opener.open_bi().await.expect("a stream opens");
        send.write_all(first)
            .await
            .expect("the first bytes are written");
        let (provider_send, provider_recv) =
            provider.accept_bi().await.expect("the stream arrives");
        (send, recv, FrameStream::new(provider_send, provider_recv))
    }

    fn stream_open(caller: &KeyPair, args: Value) -> Value {
        frame::stream_open(&frame::StreamOpenSpec::new(
            rand::random(),
            "app/stream",
            REALM,
            StreamMode::ServerStream,
            args,
            0,
            caller.node_id(),
        ))
    }

    fn encoded(frame: &Value) -> Vec<u8> {
        frame::encode(frame).expect("the frame encodes")
    }

    #[tokio::test]
    async fn a_stream_open_not_signed_by_its_caller_is_refused() {
        let (opener, provider, _endpoint) = local_connection().await;
        let caller = KeyPair::generate();
        let refused_code = quinn::VarInt::from_u32(REFUSED_STREAM);
        let first_frames = [
            (
                encoded(&frame::sign(
                    stream_open(&caller, Value::Null),
                    &KeyPair::generate(),
                )),
                Reason::InvalidSignature,
            ),
            (
                encoded(&stream_open(&caller, Value::Null)),
                Reason::Unsigned,
            ),
            (
                encoded(&Value::Map(vec![(
                    Value::text("frame_type"),
                    Value::text("call"),
                )])),
                Reason::NotAStreamOpen,
            ),
            // A one-byte frame whose CBOR initial byte uses a reserved value.
            (vec![0, 0, 0, 1, 0x1C], Reason::Malformed),
        ];

        for (first, expected) in first_frames {
            let (send, mut recv, inbound) = opened_with(&opener, &provider, &first).await;

            let refused = StreamHandle::open_inbound(inbound).await;

            assert!(
                matches!(refused, Err(Inbound::Refused { reason, .. }) if reason == expected),
                "expected the stream refused as {expected:?}"
            );
            assert!(matches!(send.stopped().await, Ok(Some(code)) if code == refused_code));
            assert!(matches!(
                recv.read(&mut [0; 1]).await,
                Err(quinn::ReadError::Reset(code)) if code == refused_code
            ));
        }

        let genuine = encoded(&frame::sign(stream_open(&caller, Value::Null), &caller));
        let (_send, _recv, inbound) = opened_with(&opener, &provider, &genuine).await;
        let opened = StreamHandle::open_inbound(inbound).await;
        assert!(matches!(opened, Ok((_, ref info)) if info.caller == caller.node_id()));
    }

    #[tokio::test]
    async fn a_refused_stream_writes_its_error_then_finishes_and_stops_reading() {
        let (opener, provider, _endpoint) = local_connection().await;
        let caller = KeyPair::generate();
        let first = encoded(&frame::sign(stream_open(&caller, Value::Null), &caller));
        let (send, recv, inbound) = opened_with(&opener, &provider, &first).await;
        let Ok((handle, _)) = StreamHandle::open_inbound(inbound).await else {
            panic!("a STREAM_OPEN signed by its caller opens");
        };
        let stopped = send.stopped();

        handle
            .refuse(
                "unauthorized",
                "not authorized for this procedure",
                &KeyPair::generate(),
            )
            .await
            .expect("the STREAM_ERROR is written");

        let mut opener_side = FrameStream::new(send, recv);
        let error = opener_side
            .recv_frame()
            .await
            .expect("the STREAM_ERROR arrives");
        assert!(matches!(
            frame::parse_stream_event(&error),
            Ok(frame::StreamEvent::Error { ref code, ref message, .. })
                if code == "unauthorized" && message == "not authorized for this procedure"
        ));
        assert!(
            matches!(
                opener_side.recv_frame().await,
                Err(RecvFrameError::StreamClosed)
            ),
            "the send half is finished, not reset"
        );
        assert!(matches!(
            stopped.await,
            Ok(Some(code)) if code == quinn::VarInt::from_u32(REFUSED_STREAM)
        ));
    }

    #[tokio::test]
    async fn a_stream_open_threads_its_caller_into_the_args() {
        let (opener, provider, _endpoint) = local_connection().await;
        let caller = KeyPair::generate();
        let claimed = KeyPair::generate().node_id();
        let args = Value::Map(vec![
            (Value::text("n"), Value::Int(21)),
            (Value::text("caller"), Value::Bytes(claimed.to_vec())),
        ]);
        let first = encoded(&frame::sign(stream_open(&caller, args), &caller));
        let (_send, _recv, inbound) = opened_with(&opener, &provider, &first).await;

        let Ok((_, info)) = StreamHandle::open_inbound(inbound).await else {
            panic!("a STREAM_OPEN signed by its caller opens");
        };

        assert_eq!(
            info.args.get("caller"),
            Some(&Value::Bytes(caller.node_id().to_vec()))
        );
        assert_eq!(info.args.get("n"), Some(&Value::Int(21)));
    }
}
