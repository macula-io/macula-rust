//! Serving, as macula 12's provider does it. A procedure is served under an
//! org namespace: the realm's org directory names the org's key, the org's
//! procedure delegation names this node, both are found in the DHT, and the
//! signed procedure_advertisement carries them to the station in an
//! ADVERTISE, checked against the realm key before it goes out. Or it is
//! served in this node's own namespace, `~<node_id>/<name>` (D25 item 6): its
//! advertisement carries no authorization, its signature alone authorizes it,
//! and no realm key or record in the DHT is needed. The station routes CALLs
//! for the procedure to this link; each is admitted once per (caller,
//! request_id) and answered with a RESULT or ERROR signed by this node.
//! UNADVERTISE carries a tombstone of the advertisement.
//!
//! Only open procedures are served: a gated one needs a post-quantum UCAN
//! verifier, which this crate does not have.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::watch;

use crate::cbor::{self, Value};
use crate::frame::{self, StreamMode, VerifiedRequest};
use crate::record::{
    self, Authorization, ProcedureAdvertisementOptions, Reason, Record, RecordError,
    TombstoneOptions, Trust,
};

use super::admission::Verdict;
use super::confidential::{CODE_SEALED_REFUSED, NO_KEY_DETAIL};
use super::framing::MAX_FRAME_BYTES;
use super::stream::StreamHandler;
use super::{now_ms, Inner, Link, LinkError};

/// The provider codes of a served procedure's ERRORs: a handler's own
/// refusal, a handler that panicked, a procedure this link does not serve, a
/// copy of a request still running, and a result the wire cannot carry.
const CODE_HANDLER_ERROR: &str = "handler_error";
const CODE_HANDLER_CRASHED: &str = "temporary_relay_failure";
const CODE_UNKNOWN_PROCEDURE: &str = "unknown_next_peer";
pub(super) const CODE_REQUEST_COPY: &str = "request_copy";
const CODE_PAYLOAD_TOO_LARGE: &str = "payload_too_large";
const CODE_UNSENDABLE: &str = "unknown_error";

/// An ERROR's detail is at most 256 bytes, cut on a character boundary.
const MAX_DETAIL_BYTES: usize = 256;

/// macula's default and longest advertisement lifetime.
const MAX_ADVERTISEMENT_TTL: Duration = Duration::from_secs(5 * 60);
/// How soon a failed renewal is tried again, while the advertisement it
/// replaces still lives.
const REFRESH_RETRY: Duration = Duration::from_secs(10);

/// A future a handler returns.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Answers a [`Request`] with a result payload, or an error whose text the
/// caller receives as a handler_error's detail. A handler still running at
/// the request's deadline is dropped and answered handler_error.
pub type Handler = Arc<dyn Fn(Request) -> BoxFuture<Result<Value, String>> + Send + Sync>;

/// A [`Handler`] from an async closure.
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value, String>> + Send + 'static,
{
    Arc::new(move |r| Box::pin(f(r)))
}

/// A CALL a served procedure answers: the caller (the key id its signature
/// verified under), what it asked for, and its deadline in unix
/// milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub caller: [u8; 32],
    pub realm: [u8; 32],
    pub procedure: String,
    pub payload: Value,
    pub token: Option<Vec<u8>>,
    pub proofs: Option<Vec<Vec<u8>>>,
    pub deadline_ms: u64,
}

/// A procedure to serve: its realm and name, exactly one of a unary handler
/// and a stream offer, and, for an org procedure, the realm key the org
/// directory must be signed with, as the realm's members pin it; a procedure
/// in this node's own namespace needs none.
#[derive(Clone)]
pub struct Offer {
    pub realm: [u8; 32],
    pub procedure: String,
    pub handler: Option<Handler>,
    pub stream: Option<StreamOffer>,
    pub realm_key: Option<Vec<u8>>,
}

impl Offer {
    /// A unary procedure, with no realm key.
    pub fn unary(realm: [u8; 32], procedure: &str, handler: Handler) -> Offer {
        Offer {
            realm,
            procedure: procedure.to_string(),
            handler: Some(handler),
            stream: None,
            realm_key: None,
        }
    }

    /// A streaming procedure of `mode`, with no realm key.
    pub fn stream(
        realm: [u8; 32],
        procedure: &str,
        mode: StreamMode,
        handler: StreamHandler,
    ) -> Offer {
        Offer {
            realm,
            procedure: procedure.to_string(),
            handler: None,
            stream: Some(StreamOffer { mode, handler }),
            realm_key: None,
        }
    }
}

/// A streaming procedure's mode and handler. The advertisement is the one a
/// unary procedure sends, which names no mode: a STREAM_OPEN of another mode
/// is refused mode_mismatch.
#[derive(Clone)]
pub struct StreamOffer {
    pub mode: StreamMode,
    pub handler: StreamHandler,
}

/// A procedure a link serves, as the link holds it.
pub(super) type ServedEntry = Arc<ServedInner>;

pub(super) struct ServedInner {
    link: Weak<Inner>,
    key: ([u8; 32], String),
    pub(super) offer: Offer,
    latest: Mutex<Record>,
    err: Mutex<Option<LinkError>>,
    done_tx: watch::Sender<bool>,
}

/// A procedure this link serves, until [`Served::stop`] or the link ends, or
/// until its advertisement lapses because its authorization could not be
/// found again. Cloning it shares the serving.
#[derive(Clone)]
pub struct Served {
    inner: Arc<ServedInner>,
}

impl Link {
    /// Advertises `o`'s procedure on the link and answers its CALLs until
    /// stopped. For an org procedure it resolves the org directory and this
    /// node's procedure delegation from the DHT; a procedure in this node's
    /// own namespace needs neither, and another node's namespace is refused.
    /// It signs the advertisement with this node's identity key, naming the
    /// connected station as the serving station and living no longer than
    /// the records it carries nor 5 minutes, and checks its authorization
    /// (against the realm key for an org procedure) before sending it in an
    /// ADVERTISE and putting it in the DHT. The advertisement is renewed at
    /// half its lifetime.
    pub async fn serve(&self, o: Offer) -> Result<Served, LinkError> {
        let own = record::in_own_namespace(&o.procedure);
        if o.handler.is_some() == o.stream.is_some() || (!own && o.realm_key.is_none()) {
            return Err(LinkError::InvalidOffer);
        }
        if !matches!(record::procedure_org(&o.procedure), Ok(Some(_))) {
            return Err(LinkError::NoOrg);
        }
        let (advertisement, wire) = self.advertisement(&o, MAX_ADVERTISEMENT_TTL).await?;
        let key = (o.realm, o.procedure.clone());
        let (done_tx, _) = watch::channel(false);
        let served = Arc::new(ServedInner {
            link: Arc::downgrade(&self.inner),
            key: key.clone(),
            offer: o,
            latest: Mutex::new(advertisement),
            err: Mutex::new(None),
            done_tx,
        });
        {
            let mut state = self.inner.lock();
            if let Some(e) = &state.ended {
                return Err(e.clone());
            }
            if state.served.contains_key(&key) {
                return Err(LinkError::AlreadyServed);
            }
            state.served.insert(key, served.clone());
        }
        if let Err(e) = self.announce(&wire).await {
            served.end(e.clone());
            return Err(e);
        }
        tokio::spawn(renew(served.clone()));
        Ok(Served { inner: served })
    }

    /// `o`'s signed procedure_advertisement and its wire form, living at most
    /// `max_ttl`: with the authorization resolved from the DHT for an org
    /// procedure, with none in this node's own namespace.
    async fn advertisement(
        &self,
        o: &Offer,
        max_ttl: Duration,
    ) -> Result<(Record, Vec<u8>), LinkError> {
        let inner = &self.inner;
        let max_ttl_ms = max_ttl.as_millis() as u64;
        // This node opens no sealed request, so its advertisement names no
        // KEM key: callers reach it in the clear.
        let opts = if record::in_own_namespace(&o.procedure) {
            ProcedureAdvertisementOptions {
                authorization: Authorization::None,
                kem_key: None,
                ttl_ms: max_ttl_ms,
            }
        } else {
            let org = record::procedure_org(&o.procedure)?.ok_or(LinkError::NoOrg)?;
            let directory = self
                .find_record(&record::org_directory_key(&o.realm, org))
                .await?;
            let named = record::read_org_directory(directory.record())?;
            let delegation = self
                .find_record(&record::procedure_delegation_key(
                    &named.org_key,
                    &inner.self_id,
                ))
                .await?;
            let now = now_ms();
            let ttl = (max_ttl_ms as i64)
                .min(directory.record().expires_at as i64 - now)
                .min(delegation.record().expires_at as i64 - now);
            if ttl <= 0 {
                return Err(RecordError::AuthorizationOutlived.into());
            }
            ProcedureAdvertisementOptions {
                authorization: Authorization::Delegation {
                    org_directory: record::encode(directory.record())?,
                    procedure_delegation: record::encode(delegation.record())?,
                },
                kem_key: None,
                ttl_ms: ttl as u64,
            }
        };
        let unsigned = record::new_procedure_advertisement(
            &inner.self_id,
            &o.realm,
            &o.procedure,
            &inner.station.node_id,
            &opts,
        )?;
        // Signed, then checked as a caller will check it before it is sent
        // anywhere.
        let signed = record::sign(&unsigned, &inner.key)?;
        let wire = record::encode(&signed)?;
        let now = now_ms();
        let verified = record::verify(&wire, inner.profile, now)?;
        record::verify_authorization(
            &verified,
            &Trust {
                profile: inner.profile,
                realm_key: o.realm_key.clone(),
            },
            now,
        )?;
        Ok((signed, wire))
    }

    /// Sends an advertisement to the station in an ADVERTISE, which routes
    /// CALLs through it, and puts it in the DHT, where a caller resolving
    /// the procedure finds it, as macula's advertise_direct does both.
    async fn announce(&self, wire: &[u8]) -> Result<(), LinkError> {
        self.inner
            .send_control(&frame::advertise_frame(wire))
            .await?;
        self.put_record(wire).await
    }
}

impl Served {
    /// Withdraws the advertisement with an UNADVERTISE carrying its
    /// tombstone, signed by this node, puts the tombstone in the
    /// advertisement's DHT slot, and stops answering the procedure's CALLs.
    /// Stopping a procedure no longer served does nothing.
    pub async fn stop(&self) -> Result<(), LinkError> {
        if self.inner.is_done() {
            return Ok(());
        }
        self.inner.end(LinkError::Stopped);
        let Some(inner) = self.inner.link.upgrade() else {
            return Ok(());
        };
        let latest = self
            .inner
            .latest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let tombstone =
            record::new_tombstone(&latest, Reason::Shutdown, &TombstoneOptions::default())?;
        let wire = record::encode(&record::sign(&tombstone, &inner.key)?)?;
        inner.send_control(&frame::unadvertise_frame(&wire)).await?;
        Link { inner }.put_record(&wire).await
    }

    /// Waits until the procedure is no longer served, and says why.
    pub async fn done(&self) -> LinkError {
        let mut done = self.inner.done_tx.subscribe();
        let _ = done.wait_for(|ended| *ended).await;
        self.error().unwrap_or(LinkError::Stopped)
    }

    /// Why the procedure is no longer served: [`LinkError::Stopped`] after
    /// stop, the link's error when it ended, or the renewal's failure; `None`
    /// while served.
    pub fn error(&self) -> Option<LinkError> {
        self.inner
            .err
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl ServedInner {
    fn is_done(&self) -> bool {
        *self.done_tx.borrow()
    }

    /// Ends the serving once, with `err`: the link no longer routes the
    /// procedure's CALLs to its handler.
    pub(super) fn end(self: &Arc<Self>, err: LinkError) {
        {
            let mut held = self.err.lock().unwrap_or_else(|p| p.into_inner());
            if held.is_some() {
                return;
            }
            *held = Some(err);
        }
        if let Some(inner) = self.link.upgrade() {
            let mut state = inner.lock();
            if state
                .served
                .get(&self.key)
                .is_some_and(|s| Arc::ptr_eq(s, self))
            {
                state.served.remove(&self.key);
            }
        }
        let _ = self.done_tx.send_replace(true);
    }
}

/// Sends a fresh advertisement at half the current one's lifetime. A renewal
/// that fails is tried again every [`REFRESH_RETRY`] while the current one
/// lives; when it lapses unrenewed, the procedure is no longer served and its
/// error says why.
async fn renew(served: Arc<ServedInner>) {
    let mut current = served
        .latest
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let mut wait = half_life(&current);
    let mut last_err: Option<LinkError> = None;
    let mut stopped = served.done_tx.subscribe();
    loop {
        let Some(mut link_done) = served.link.upgrade().map(|l| l.done_rx.clone()) else {
            return;
        };
        tokio::select! {
            _ = stopped.wait_for(|ended| *ended) => return,
            _ = link_done.wait_for(|ended| *ended) => {
                let err = served.link.upgrade().and_then(|l| l.lock().ended.clone()).unwrap_or(LinkError::Closed);
                served.end(err);
                return;
            }
            _ = tokio::time::sleep(wait) => {}
        }
        if now_ms() >= current.expires_at as i64 {
            served.end(last_err.unwrap_or(LinkError::Stopped));
            return;
        }
        let Some(inner) = served.link.upgrade() else {
            return;
        };
        let link = Link { inner };
        let renewed = async {
            let (advertisement, wire) = link
                .advertisement(&served.offer, MAX_ADVERTISEMENT_TTL)
                .await?;
            link.announce(&wire).await?;
            Ok::<_, LinkError>(advertisement)
        }
        .await;
        match renewed {
            Ok(advertisement) => {
                *served.latest.lock().unwrap_or_else(|p| p.into_inner()) = advertisement.clone();
                wait = half_life(&advertisement);
                current = advertisement;
            }
            Err(e) => {
                last_err = Some(e);
                let left = (current.expires_at as i64 - now_ms()).max(0) as u64;
                wait = REFRESH_RETRY.min(Duration::from_millis(left));
            }
        }
    }
}

fn half_life(r: &Record) -> Duration {
    Duration::from_millis(r.expires_at.saturating_sub(r.created_at) / 2)
}

/// Answers a CALL the station routed to this link. A request that does not
/// verify, or targets another node, gets no reply and is counted. One that
/// verifies is judged by the admission, then answered by its handler, or by
/// an ERROR naming why not.
pub(super) fn called(inner: &Arc<Inner>, v: &Value) {
    let Ok(request) = frame::verify_request(v, inner.profile) else {
        inner.count("unverified_call");
        return;
    };
    if request.target != inner.self_id {
        inner.count("call_for_another_node");
        return;
    }
    let inner = inner.clone();
    match inner.admission.admit(&request, &inner.share, now_ms()) {
        Verdict::Refused(code) => {
            let reply = provider_error(&inner, &request, code, None);
            tokio::spawn(async move { send_reply(&inner, reply).await });
        }
        Verdict::Copy(None) => {
            let reply = provider_error(&inner, &request, CODE_REQUEST_COPY, None);
            tokio::spawn(async move { send_reply(&inner, reply).await });
        }
        Verdict::Copy(Some(stored)) => {
            tokio::spawn(async move {
                let _ = inner.control.write(&stored, MAX_FRAME_BYTES).await;
            });
        }
        // This node opens no sealed payload: a sealed request is refused,
        // never handed to a handler on a payload it cannot read.
        Verdict::New if request.sealed.is_some() => {
            let reply = provider_error(&inner, &request, CODE_SEALED_REFUSED, Some(NO_KEY_DETAIL));
            tokio::spawn(async move { send_reply(&inner, reply).await });
        }
        Verdict::New => {
            tokio::spawn(answer(inner, request));
        }
    }
}

/// Runs the request's handler and sends its signed reply, storing it for the
/// request's copies.
async fn answer(inner: Arc<Inner>, request: VerifiedRequest) {
    let handler = inner
        .lock()
        .served
        .get(&(request.realm, request.procedure.clone()))
        .and_then(|s| s.offer.handler.clone());
    let reply = match handler {
        None => provider_error(&inner, &request, CODE_UNKNOWN_PROCEDURE, None),
        Some(handler) => handled(&inner, handler, &request).await,
    };
    let Ok(encoded) = cbor::encode(&reply) else {
        inner.count("unencodable_reply");
        return;
    };
    inner.admission.store(&request, encoded.clone());
    let _ = inner.control.write(&encoded, MAX_FRAME_BYTES).await;
}

/// The handler's answer to `request` as a signed reply: its result, its
/// refusal as handler_error, a panic as temporary_relay_failure, or a result
/// the wire cannot carry as payload_too_large or unknown_error.
async fn handled(inner: &Inner, handler: Handler, request: &VerifiedRequest) -> Value {
    let running = tokio::spawn(handler(Request {
        caller: request.caller,
        realm: request.realm,
        procedure: request.procedure.clone(),
        payload: request.payload.clone(),
        token: request.token.clone(),
        proofs: request.proofs.clone(),
        deadline_ms: request.deadline,
    }));
    let abort = running.abort_handle();
    let left = (request.deadline as i64 - now_ms()).max(0) as u64;
    let outcome = tokio::time::timeout(Duration::from_millis(left), running).await;
    match outcome {
        Err(_) => {
            abort.abort();
            provider_error(
                inner,
                request,
                CODE_HANDLER_ERROR,
                Some("the request's deadline passed"),
            )
        }
        Ok(Err(_panicked)) => provider_error(inner, request, CODE_HANDLER_CRASHED, None),
        Ok(Ok(Err(refusal))) => provider_error(
            inner,
            request,
            CODE_HANDLER_ERROR,
            Some(bounded_detail(&refusal)),
        ),
        Ok(Ok(Ok(payload))) => match frame::sign_result(request, &payload, None, &inner.key) {
            Ok(signed) => signed,
            Err(_) if cbor::encode(&payload).is_ok_and(|e| e.len() > frame::MAX_FRAME_BYTES) => {
                provider_error(inner, request, CODE_PAYLOAD_TOO_LARGE, None)
            }
            Err(_) => provider_error(inner, request, CODE_UNSENDABLE, None),
        },
    }
}

/// This node's signed ERROR for `request`. The request verified with this
/// node as its target, so signing cannot fail on the key; a code or detail
/// out of bounds is a bug in this module.
fn provider_error(
    inner: &Inner,
    request: &VerifiedRequest,
    code: &str,
    detail: Option<&str>,
) -> Value {
    frame::sign_provider_error(request, code, detail, None, &inner.key)
        .unwrap_or_else(|e| panic!("station_link: a provider error that does not sign: {e}"))
}

async fn send_reply(inner: &Inner, reply: Value) {
    let _ = inner.write_control(&reply).await;
}

/// `text` cut to 256 bytes on a character boundary.
pub(super) fn bounded_detail(text: &str) -> &str {
    if text.len() <= MAX_DETAIL_BYTES {
        return text;
    }
    let mut cut = MAX_DETAIL_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    &text[..cut]
}
