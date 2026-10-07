//! Serving a procedure with a handler the foreign side implements, on every
//! link the pool holds and every link it dials later, until stopped. A
//! handler's [`FfiError`] reaches the caller as a handler_error with the
//! error's text; a handler that throws anything else, or panics, is answered
//! as macula answers a crashed handler.

use std::sync::Arc;

use macula_rust::cbor::Value;
use macula_rust::pool::{Offer, Served};
use macula_rust::station_link::{handler, stream_handler, Request, Stream};

use crate::pool::{FfiConfidentiality, FfiPool};
use crate::stream::{FfiStream, FfiStreamHandler, FfiStreamMode};
use crate::{to_32, FfiError, FfiValue};

/// A CALL a served procedure answers: the caller's node_id (the key its
/// signature verified under), what it asked for, and its deadline in unix
/// milliseconds.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiRequest {
    pub caller: Vec<u8>,
    pub realm: Vec<u8>,
    pub procedure: String,
    pub payload: FfiValue,
    pub deadline_ms: u64,
    /// Whether the request came sealed end to end; its answer goes back
    /// sealed.
    pub sealed: bool,
}

impl TryFrom<Request> for FfiRequest {
    type Error = FfiError;

    fn try_from(r: Request) -> Result<Self, FfiError> {
        Ok(FfiRequest {
            caller: r.caller.to_vec(),
            realm: r.realm.to_vec(),
            procedure: r.procedure,
            payload: r.payload.try_into()?,
            deadline_ms: r.deadline_ms,
            sealed: r.sealed,
        })
    }
}

/// Answers the CALLs of a procedure the node serves, implemented in Kotlin
/// or Swift.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait FfiCallHandler: Send + Sync {
    async fn handle(&self, request: FfiRequest) -> Result<FfiValue, FfiError>;
}

/// A procedure the node serves, until [`stop`](Self::stop).
#[derive(uniffi::Object)]
pub struct FfiServed(Served);

#[uniffi::export(async_runtime = "tokio")]
impl FfiPool {
    /// Serves `procedure` in `realm` with `handler` on every link, taking
    /// requests as `confidential` says. An org procedure needs its realm's
    /// key pinned; one in the node's own namespace (see
    /// [`own_procedure`](crate::own_procedure)) needs none.
    pub async fn serve(
        &self,
        realm: Vec<u8>,
        procedure: String,
        handler_impl: Arc<dyn FfiCallHandler>,
        confidential: FfiConfidentiality,
    ) -> Result<Arc<FfiServed>, FfiError> {
        let answer = handler(move |r: Request| answer_call(handler_impl.clone(), r));
        let mut offer = Offer::unary(to_32(realm)?, &procedure, answer);
        offer.confidential = confidential.into();
        let served = self.0.serve(offer).await?;
        Ok(Arc::new(FfiServed(served)))
    }

    /// Serves `procedure` in `realm` as a streaming procedure of `mode`,
    /// each session handed to `handler_impl`: a session it returns from
    /// without ending is closed, and one it fails is aborted.
    pub async fn serve_stream(
        &self,
        realm: Vec<u8>,
        procedure: String,
        mode: FfiStreamMode,
        handler_impl: Arc<dyn FfiStreamHandler>,
        confidential: FfiConfidentiality,
    ) -> Result<Arc<FfiServed>, FfiError> {
        let session = stream_handler(move |s| run_session(handler_impl.clone(), s));
        let mut offer = Offer::stream(to_32(realm)?, &procedure, mode.into(), session);
        offer.confidential = confidential.into();
        let served = self.0.serve(offer).await?;
        Ok(Arc::new(FfiServed(served)))
    }
}

/// Answers one CALL with the foreign handler, a refusal or failure as its
/// text.
async fn answer_call(handler_impl: Arc<dyn FfiCallHandler>, r: Request) -> Result<Value, String> {
    let request = FfiRequest::try_from(r).map_err(|e| e.to_string())?;
    let answered = handler_impl
        .handle(request)
        .await
        .map_err(|e| e.to_string())?;
    Ok(answered.into())
}

/// Hands one streaming session to the foreign handler, a failure as its text.
async fn run_session(handler_impl: Arc<dyn FfiStreamHandler>, s: Stream) -> Result<(), String> {
    handler_impl
        .handle(Arc::new(FfiStream::new(s)))
        .await
        .map_err(|e| e.to_string())
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiServed {
    /// Withdraws the procedure on every link.
    pub async fn stop(&self) -> Result<(), FfiError> {
        Ok(self.0.stop().await?)
    }
}
