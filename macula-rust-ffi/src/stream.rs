//! Streaming sessions, on either side: opened at a provider through the
//! pool, or handed to a [`FfiStreamHandler`] the node serves with. Each side
//! sends chunks and ends its sending; a client_stream or bidi provider ends
//! the session with a reply.

use std::sync::Arc;

use macula_rust::frame::{StreamEncoding, StreamMode, StreamRole};
use macula_rust::pool::StreamCall;
use macula_rust::station_link::{Stream, StreamEvent};

use crate::pool::{FfiConfidentiality, FfiPool};
use crate::{millis, to_32, FfiError, FfiValue};

/// Who pushes data on a stream: the provider, the caller, or both.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiStreamMode {
    ServerStream,
    ClientStream,
    Bidi,
}

impl From<FfiStreamMode> for StreamMode {
    fn from(m: FfiStreamMode) -> Self {
        match m {
            FfiStreamMode::ServerStream => StreamMode::ServerStream,
            FfiStreamMode::ClientStream => StreamMode::ClientStream,
            FfiStreamMode::Bidi => StreamMode::Bidi,
        }
    }
}

/// How a chunk's body reads: raw bytes, or a structured value.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiStreamEncoding {
    Raw,
    Structured,
}

/// One frame the peer sent, verified: a chunk, the peer's end (`both` when
/// it ends the whole session, not just the peer's sending), or the
/// provider's terminal reply.
#[derive(uniffi::Enum, Debug, Clone, PartialEq)]
pub enum FfiStreamEvent {
    Data {
        encoding: FfiStreamEncoding,
        body: FfiValue,
    },
    End {
        both: bool,
    },
    Reply {
        payload: FfiValue,
    },
}

impl TryFrom<StreamEvent> for FfiStreamEvent {
    type Error = FfiError;

    fn try_from(e: StreamEvent) -> Result<Self, FfiError> {
        Ok(match e {
            StreamEvent::Data { encoding, body } => FfiStreamEvent::Data {
                encoding: match encoding {
                    StreamEncoding::Raw => FfiStreamEncoding::Raw,
                    StreamEncoding::Msgpack => FfiStreamEncoding::Structured,
                },
                body: body.try_into()?,
            },
            StreamEvent::End { role } => FfiStreamEvent::End {
                both: role == StreamRole::Both,
            },
            StreamEvent::Reply { payload } => FfiStreamEvent::Reply {
                payload: payload.try_into()?,
            },
        })
    }
}

/// Serves one streaming session, implemented in Kotlin or Swift. A session
/// it returns from without ending is closed on both sides; one it fails is
/// aborted with code `error` and the error's text.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait FfiStreamHandler: Send + Sync {
    async fn handle(&self, stream: Arc<FfiStream>) -> Result<(), FfiError>;
}

/// One streaming session, on either side.
#[derive(uniffi::Object)]
pub struct FfiStream(Stream);

impl FfiStream {
    pub(crate) fn new(s: Stream) -> FfiStream {
        FfiStream(s)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiPool {
    /// Opens a streaming session of `mode` at a provider of `procedure` in
    /// `realm` (`provider`, or any trusted one when `None`), its deadline
    /// `deadline_ms` ahead (0 for macula's 30 seconds). A refusal arrives on
    /// the first [`FfiStream::recv`].
    #[allow(clippy::too_many_arguments)]
    pub async fn open_stream(
        &self,
        realm: Vec<u8>,
        procedure: String,
        mode: FfiStreamMode,
        payload: FfiValue,
        provider: Option<Vec<u8>>,
        deadline_ms: u64,
        confidential: FfiConfidentiality,
    ) -> Result<Arc<FfiStream>, FfiError> {
        let stream = self
            .0
            .open_stream(StreamCall {
                realm: to_32(realm)?,
                procedure,
                provider: provider.map(to_32).transpose()?.unwrap_or([0; 32]),
                mode: mode.into(),
                payload: payload.into(),
                deadline: millis(deadline_ms),
                confidential: confidential.into(),
                ..StreamCall::default()
            })
            .await?;
        Ok(Arc::new(FfiStream(stream)))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiStream {
    /// The session's caller, its node_id.
    pub fn caller(&self) -> Vec<u8> {
        self.0.request().caller.to_vec()
    }

    /// Whether the session is sealed end to end.
    pub fn sealed(&self) -> bool {
        self.0.sealed()
    }

    /// The payload the session was opened with.
    pub fn open_payload(&self) -> Result<FfiValue, FfiError> {
        self.0.request().payload.clone().try_into()
    }

    /// Sends a raw chunk.
    pub async fn send(&self, body: Vec<u8>) -> Result<(), FfiError> {
        Ok(self.0.send(&body).await?)
    }

    /// Sends a structured chunk.
    pub async fn send_value(&self, value: FfiValue) -> Result<(), FfiError> {
        Ok(self.0.send_value(value.into()).await?)
    }

    /// Ends this side's sending; the peer may still send.
    pub async fn close_send(&self) -> Result<(), FfiError> {
        Ok(self.0.close_send().await?)
    }

    /// Ends the session on both sides.
    pub async fn close(&self) -> Result<(), FfiError> {
        Ok(self.0.close().await?)
    }

    /// Sends the provider's terminal value and ends the session.
    pub async fn reply(&self, payload: FfiValue) -> Result<(), FfiError> {
        Ok(self.0.reply(payload.into()).await?)
    }

    /// Ends the session with an error of `code` and `message`.
    pub async fn abort(&self, code: String, message: String) -> Result<(), FfiError> {
        Ok(self.0.abort(&code, &message).await?)
    }

    /// The next frame the peer sent, waiting up to `timeout_ms`
    /// ([`FfiError::Timeout`] past it). Once the session has ended and every
    /// frame before is read: [`FfiError::EndOfStream`] for a normal end,
    /// [`FfiError::Stream`] for an error.
    pub async fn recv(&self, timeout_ms: u64) -> Result<FfiStreamEvent, FfiError> {
        match tokio::time::timeout(millis(timeout_ms), self.0.recv()).await {
            Err(_) => Err(FfiError::Timeout),
            Ok(event) => event?.try_into(),
        }
    }
}
