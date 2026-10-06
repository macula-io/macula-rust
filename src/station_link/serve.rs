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
//! With `kem_advertise` on, a confidential procedure's advertisement names
//! this node's KEM key, and a request sealed to it is opened and answered
//! sealed (confidential.rs).
//!
//! A procedure is served open, or gated on a UCAN policy: a request whose
//! token the policy does not authorize is refused unauthorized
//! (authorize.rs).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::watch;

use crate::cbor::{self, Value};
use crate::frame::{self, StreamMode, VerifiedRequest};
use crate::node_key::NodeKey;
use crate::record::{
    self, Authorization, ProcedureAdvertisementOptions, Reason, Record, RecordError,
    TombstoneOptions, Trust,
};
use crate::seal;
use crate::ucan::Policy;

use super::admission::Verdict;
use super::authorize::authorize;
use super::confidential::{
    clear_allowed, opened_request, CallSeal, Confidentiality, CODE_SEALED_REFUSED,
    CODE_SEALED_REQUIRED,
};
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
/// A sealed answer this node could not seal: a refusal from the closed set,
/// which carries no application data.
const CODE_UNAVAILABLE: &str = "unavailable";

/// An ERROR's detail is at most 256 bytes, cut on a character boundary.
const MAX_DETAIL_BYTES: usize = 256;

/// macula's default and longest advertisement lifetime.
const MAX_ADVERTISEMENT_TTL: Duration =
    Duration::from_millis(super::confidential::MAX_ADVERTISEMENT_TTL_MS as u64);
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
    /// Whether the request came sealed end to end: `payload` is its opened
    /// plaintext, and the answer goes back sealed.
    pub sealed: bool,
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
    /// How the procedure takes its requests: whether its advertisement names
    /// this node's KEM key, with `kem_advertise` on, and whether it takes
    /// clear ones.
    pub confidential: Confidentiality,
    /// When the procedure was first advertised naming the key (unix ms),
    /// from which its keyless window runs; serving sets it to now when
    /// `None`. A pool keeps it across the links it serves on, so no link
    /// reopens the window.
    pub keyed_since_ms: Option<i64>,
    /// What the procedure requires of a request's UCAN: `None` serves any
    /// caller (an open procedure ignores any token), and a [`Policy`] serves
    /// only a request whose token it authorizes (authorize.rs).
    pub policy: Option<Policy>,
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
            confidential: Confidentiality::Preferred,
            keyed_since_ms: None,
            policy: None,
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
            confidential: Confidentiality::Preferred,
            keyed_since_ms: None,
            policy: None,
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
    pub async fn serve(&self, mut o: Offer) -> Result<Served, LinkError> {
        let own = record::in_own_namespace(&o.procedure);
        if o.handler.is_some() == o.stream.is_some()
            || (!own && o.realm_key.is_none())
            || o.policy.as_ref().is_some_and(|p| !p.valid())
        {
            return Err(LinkError::InvalidOffer);
        }
        if !matches!(record::procedure_org(&o.procedure), Ok(Some(_))) {
            return Err(LinkError::NoOrg);
        }
        let can_name_key = self.inner.kem_advertise && self.inner.keyring.is_some();
        if o.confidential == Confidentiality::Required && !can_name_key {
            return Err(LinkError::KemAdvertiseDisabled);
        }
        if self.inner.keyed(&o) && o.keyed_since_ms.is_none() {
            o.keyed_since_ms = Some(now_ms());
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
        route_calls(&self.inner, key, served.clone())?;
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
        // Each signing reads the keyring, so a renewal names a rotated key.
        let kem_key = inner.kem_key(o);
        let opts = if record::in_own_namespace(&o.procedure) {
            ProcedureAdvertisementOptions {
                authorization: Authorization::None,
                kem_key,
                ttl_ms: max_ttl_ms,
            }
        } else {
            self.org_advertisement_options(o, max_ttl_ms, kem_key)
                .await?
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

    /// The options of an org procedure's advertisement: its org directory and
    /// this node's procedure delegation, resolved from the DHT, and a lifetime
    /// no longer than either of them nor `max_ttl_ms`.
    async fn org_advertisement_options(
        &self,
        o: &Offer,
        max_ttl_ms: u64,
        kem_key: Option<Vec<u8>>,
    ) -> Result<ProcedureAdvertisementOptions, LinkError> {
        let inner = &self.inner;
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
        Ok(ProcedureAdvertisementOptions {
            authorization: Authorization::Delegation {
                org_directory: record::encode(directory.record())?,
                procedure_delegation: record::encode(delegation.record())?,
            },
            kem_key,
            ttl_ms: ttl as u64,
        })
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

/// Routes the procedure's CALLs on the link to `served`, unless the link has
/// ended or already serves the procedure.
fn route_calls(
    inner: &Inner,
    key: ([u8; 32], String),
    served: Arc<ServedInner>,
) -> Result<(), LinkError> {
    let mut state = inner.lock();
    if let Some(e) = &state.ended {
        return Err(e.clone());
    }
    if state.served.contains_key(&key) {
        return Err(LinkError::AlreadyServed);
    }
    state.served.insert(key, served);
    Ok(())
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
        if !self.hold_err(err) {
            return;
        }
        self.unroute();
        let _ = self.done_tx.send_replace(true);
    }

    /// Keeps `err` as why the serving ended, and whether it is the first;
    /// a later one is not kept.
    fn hold_err(&self, err: LinkError) -> bool {
        let mut held = self.err.lock().unwrap_or_else(|p| p.into_inner());
        if held.is_some() {
            return false;
        }
        *held = Some(err);
        true
    }

    /// Stops the link routing the procedure's CALLs here, when it still
    /// routes them to this serving and not a later one.
    fn unroute(self: &Arc<Self>) {
        let Some(inner) = self.link.upgrade() else {
            return;
        };
        let mut state = inner.lock();
        if state
            .served
            .get(&self.key)
            .is_some_and(|s| Arc::ptr_eq(s, self))
        {
            state.served.remove(&self.key);
        }
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
        Verdict::Refused(code) => refuse_call(inner, &request, code),
        Verdict::Copy(None) => refuse_call(inner, &request, CODE_REQUEST_COPY),
        Verdict::Copy(Some(stored)) => {
            tokio::spawn(async move {
                let _ = inner.control.write(&stored, MAX_FRAME_BYTES).await;
            });
        }
        Verdict::New => {
            tokio::spawn(answer(inner, request));
        }
    }
}

/// Sends this node's ERROR for `request` with `code`, or counts it
/// unsignable_reply when it does not sign.
fn refuse_call(inner: Arc<Inner>, request: &VerifiedRequest, code: &'static str) {
    let Some(reply) = provider_error(&inner.signer(), request, code, None) else {
        inner.count("unsignable_reply");
        return;
    };
    tokio::spawn(async move { send_reply(&inner, reply).await });
}

/// Serves a request and sends its signed reply, storing it for the
/// request's copies.
async fn answer(inner: Arc<Inner>, request: VerifiedRequest) {
    let offer = inner
        .lock()
        .served
        .get(&(request.realm, request.procedure.clone()))
        .map(|s| s.offer.clone());
    let Some(reply) = reply(&inner, &request, offer).await else {
        inner.count("unsignable_reply");
        return;
    };
    let Ok(encoded) = cbor::encode(&reply) else {
        inner.count("unencodable_reply");
        return;
    };
    inner.admission.store(&request, encoded.clone());
    let _ = inner.control.write(&encoded, MAX_FRAME_BYTES).await;
}

/// The signed reply to `request`, served by `offer` (`None` when this link
/// serves no such procedure), in macula 13's order: a sealed request opened
/// first, or refused sealed_refused in the clear when it does not open; a
/// clear one to a procedure past its keyless window refused sealed_required;
/// then the procedure, its policy and its handler, answered sealed when the
/// request was.
async fn reply(inner: &Inner, request: &VerifiedRequest, offer: Option<Offer>) -> Option<Value> {
    let (payload, sealing) = match &request.sealed {
        Some(_) => match opened_request(inner.keyring.as_deref(), request) {
            Ok((payload, sealing)) => (payload, Some(sealing)),
            Err(detail) => {
                return provider_error(&inner.signer(), request, CODE_SEALED_REFUSED, Some(&detail))
            }
        },
        None => {
            let refused = offer
                .as_ref()
                .is_some_and(|o| !clear_allowed(o.confidential, inner.keyed_since(o), now_ms()));
            if refused {
                return provider_error(&inner.signer(), request, CODE_SEALED_REQUIRED, None);
            }
            (request.payload.clone(), None)
        }
    };
    let outcome = match gated(inner.profile, offer, request) {
        Ok(handler) => handled(handler, request, without_caller(payload), sealing.is_some()).await,
        Err(code) => Outcome::Refused(code, None),
    };
    answered(&inner.signer(), request, sealing.as_ref(), outcome)
}

/// The handler that serves `request` under `offer`'s policy, or the code it
/// is refused with: unknown_procedure when this link serves no such unary
/// procedure, and the policy's refusal when its token does not authorize it.
fn gated(
    profile: crate::profile::Profile,
    offer: Option<Offer>,
    request: &VerifiedRequest,
) -> Result<Handler, &'static str> {
    let Some(Offer {
        handler: Some(handler),
        policy,
        ..
    }) = offer
    else {
        return Err(CODE_UNKNOWN_PROCEDURE);
    };
    authorize(profile, policy.as_ref(), request).map_or(Ok(handler), Err)
}

/// `payload` as a handler receives it: a map loses a text "caller" key, so
/// the only caller a handler can learn is the verified one
/// ([`Request::caller`]), as macula's `with_caller/2` and macula-go's
/// `withoutCaller` arrange (macula-rust#13). Any other payload is untouched.
pub(super) fn without_caller(payload: Value) -> Value {
    match payload {
        Value::Map(_) => payload.without(&["caller"]),
        other => other,
    }
}

/// What answers a request: a RESULT's payload, or an ERROR's code and
/// detail.
enum Outcome {
    Result(Value),
    Refused(&'static str, Option<String>),
}

/// The handler's answer to `request`, on `payload`: its result, its refusal
/// as handler_error, a panic as temporary_relay_failure, or handler_error
/// when it is still running at the deadline.
async fn handled(
    handler: Handler,
    request: &VerifiedRequest,
    payload: Value,
    sealed: bool,
) -> Outcome {
    let running = tokio::spawn(handler(Request {
        caller: request.caller,
        realm: request.realm,
        procedure: request.procedure.clone(),
        payload,
        token: request.token.clone(),
        proofs: request.proofs.clone(),
        deadline_ms: request.deadline,
        sealed,
    }));
    let abort = running.abort_handle();
    let left = (request.deadline as i64 - now_ms()).max(0) as u64;
    match tokio::time::timeout(Duration::from_millis(left), running).await {
        Err(_) => {
            abort.abort();
            Outcome::Refused(
                CODE_HANDLER_ERROR,
                Some("the request's deadline passed".into()),
            )
        }
        Ok(Err(_panicked)) => Outcome::Refused(CODE_HANDLER_CRASHED, None),
        Ok(Ok(Err(refusal))) => Outcome::Refused(
            CODE_HANDLER_ERROR,
            Some(bounded_detail(&refusal).to_string()),
        ),
        Ok(Ok(Ok(payload))) => Outcome::Result(payload),
    }
}

/// What signs this node's replies: its identity key and its node id, the
/// replies' responded_by.
pub(super) struct Signer<'a> {
    pub(super) key: &'a NodeKey,
    pub(super) self_id: [u8; 32],
}

impl Inner {
    /// This node's [`Signer`].
    fn signer(&self) -> Signer<'_> {
        Signer {
            key: &self.key,
            self_id: self.self_id,
        }
    }
}

/// An outcome as the clear signed reply to a clear `request`.
fn clear_answer(signer: &Signer, request: &VerifiedRequest, outcome: Outcome) -> Option<Value> {
    match outcome {
        Outcome::Refused(code, detail) => provider_error(signer, request, code, detail.as_deref()),
        Outcome::Result(payload) => clear_result(signer, request, &payload),
    }
}

/// A result as the signed RESULT to a clear `request`, or payload_too_large
/// or unknown_error when the wire cannot carry it.
fn clear_result(signer: &Signer, request: &VerifiedRequest, payload: &Value) -> Option<Value> {
    match frame::sign_result(request, payload, None, signer.key) {
        Ok(signed) => Some(signed),
        Err(_) if cbor::encode(payload).is_ok_and(|e| e.len() > frame::MAX_FRAME_BYTES) => {
            provider_error(signer, request, CODE_PAYLOAD_TOO_LARGE, None)
        }
        Err(_) => provider_error(signer, request, CODE_UNSENDABLE, None),
    }
}

/// An outcome as the signed reply to `request`: clear to a clear request,
/// sealed to a sealed one. A result the wire cannot carry is answered
/// payload_too_large or unknown_error, as macula answers it. `None` when no
/// reply signs: the request is left unanswered (macula-rust#14).
fn answered(
    signer: &Signer,
    request: &VerifiedRequest,
    sealing: Option<&CallSeal>,
    outcome: Outcome,
) -> Option<Value> {
    let Some(sealing) = sealing else {
        return clear_answer(signer, request, outcome);
    };
    let payload = match outcome {
        Outcome::Refused(code, detail) => {
            return sealed_error(signer, request, sealing, code, detail.as_deref())
        }
        Outcome::Result(payload) => payload,
    };
    let plain = frame::check_payload(&payload)
        .ok()
        .and_then(|_| cbor::encode(&payload).ok());
    let Some(plain) = plain else {
        return sealed_error(signer, request, sealing, CODE_UNSENDABLE, None);
    };
    let signed = sealing
        .sealed_answer(
            seal::FRAME_RESULT,
            &plain,
            &request.request_hash,
            &signer.self_id,
        )
        .and_then(|sealed| {
            frame::sign_sealed_result(request, &sealed, None, signer.key).map_err(LinkError::from)
        });
    match sealed_result_refusal(signed) {
        Ok(reply) => Some(reply),
        Err(Refusal::Sealed(code)) => sealed_error(signer, request, sealing, code, None),
        Err(Refusal::Clear(code)) => provider_error(signer, request, code, None),
    }
}

/// How a sealed RESULT that cannot go is refused: sealed, or in the clear
/// from the closed set.
#[derive(Debug, PartialEq)]
enum Refusal {
    Sealed(&'static str),
    Clear(&'static str),
}

/// A signed sealed RESULT, or how to refuse it: payload_too_large sealed when
/// it is over the frame cap, unavailable in the clear when it could not be
/// sealed (no randomness), unknown_error sealed when it did not sign
/// (macula-rust#14).
fn sealed_result_refusal(signed: Result<Value, LinkError>) -> Result<Value, Refusal> {
    match signed {
        Ok(reply) if cbor::encode(&reply).is_ok_and(|e| e.len() <= frame::MAX_FRAME_BYTES) => {
            Ok(reply)
        }
        Ok(_) => Err(Refusal::Sealed(CODE_PAYLOAD_TOO_LARGE)),
        Err(LinkError::Io(_)) => Err(Refusal::Clear(CODE_UNAVAILABLE)),
        Err(_) => Err(Refusal::Sealed(CODE_UNSENDABLE)),
    }
}

/// This node's ERROR for a sealed request, its code and detail sealed as
/// cbor([code, detail]). One that cannot be sealed (no randomness) or does
/// not sign is answered unavailable in the clear, from the closed set: never
/// the code or detail in the clear (macula-rust#14).
fn sealed_error(
    signer: &Signer,
    request: &VerifiedRequest,
    sealing: &CallSeal,
    code: &str,
    detail: Option<&str>,
) -> Option<Value> {
    let plain = seal::error_plain(code, detail.unwrap_or(""));
    sealing
        .sealed_answer(
            seal::FRAME_ERROR,
            &plain,
            &request.request_hash,
            &signer.self_id,
        )
        .ok()
        .and_then(|sealed| {
            frame::sign_sealed_provider_error(request, &sealed, None, signer.key).ok()
        })
        .or_else(|| provider_error(signer, request, CODE_UNAVAILABLE, None))
}

impl Inner {
    /// Whether `o`'s advertisements name this node's KEM key.
    pub(super) fn keyed(&self, o: &Offer) -> bool {
        self.kem_advertise && self.keyring.is_some() && o.confidential != Confidentiality::Off
    }

    /// When `o` was first keyed, `None` while its advertisements name no
    /// key.
    pub(super) fn keyed_since(&self, o: &Offer) -> Option<i64> {
        o.keyed_since_ms.filter(|_| self.keyed(o))
    }

    /// The key `o`'s advertisement names now, as carried, `None` for none.
    fn kem_key(&self, o: &Offer) -> Option<Vec<u8>> {
        let keyring = self.keyring.as_ref().filter(|_| self.keyed(o))?;
        Some(keyring.current().public_key().carried().to_vec())
    }
}

/// This node's signed ERROR for `request`, `None` when it does not sign: a
/// request this key cannot answer, or a key that fails to sign. Either leaves
/// the request unanswered, counted by the caller of this, never a panic.
fn provider_error(
    signer: &Signer,
    request: &VerifiedRequest,
    code: &str,
    detail: Option<&str>,
) -> Option<Value> {
    frame::sign_provider_error(request, code, detail, None, signer.key).ok()
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

#[cfg(test)]
mod tests {
    //! A provider's sealed answer on its error paths (macula-rust#14): a
    //! RESULT is called payload_too_large only when it is over the frame cap,
    //! and an answer that does not sign never panics.

    use super::*;
    use crate::frame::{FrameError, RequestType};
    use crate::node_key::NodeKey;
    use crate::profile::Profile;
    use crate::seal::Keyring;
    use crate::station_link::confidential::sealed_request;

    const CALLER: [u8; 32] = [1; 32];

    /// A call sealed to `keyring` and targeting `target`, as its provider
    /// verified it, and the provider's keys for the answer.
    fn sealed_call(keyring: &Keyring, target: [u8; 32]) -> (VerifiedRequest, CallSeal) {
        let to = keyring.current().public_key().carried().to_vec();
        let (sealed, _) = sealed_request(
            keyring.profile(),
            &to,
            seal::FRAME_CALL,
            [3; 32],
            "~ring",
            CALLER,
            target,
            [4; 16],
            1_790_000_000_000,
            &Value::text("secret"),
        )
        .unwrap();
        let request = VerifiedRequest {
            frame_type: RequestType::Call,
            key: Vec::new(),
            request_hash: [5; 48],
            caller: CALLER,
            request_id: [4; 16],
            realm: [3; 32],
            procedure: "~ring".into(),
            target,
            deadline: 1_790_000_000_000,
            payload: Value::Null,
            sealed: Some(sealed),
            mode: None,
            token: None,
            proofs: None,
        };
        let (_, sealing) = opened_request(Some(keyring), &request).unwrap();
        (request, sealing)
    }

    #[test]
    fn only_a_result_over_the_frame_cap_is_payload_too_large() {
        let oversize = Value::Bytes(vec![0; frame::MAX_FRAME_BYTES + 1]);
        assert_eq!(
            sealed_result_refusal(Ok(oversize)),
            Err(Refusal::Sealed(CODE_PAYLOAD_TOO_LARGE))
        );
        assert_eq!(
            sealed_result_refusal(Err(LinkError::Io("no randomness".into()))),
            Err(Refusal::Clear(CODE_UNAVAILABLE))
        );
        assert_eq!(
            sealed_result_refusal(Err(LinkError::Frame(FrameError::Unsignable))),
            Err(Refusal::Sealed(CODE_UNSENDABLE))
        );
        assert_eq!(
            sealed_result_refusal(Ok(Value::text("fits"))),
            Ok(Value::text("fits"))
        );
    }

    #[test]
    fn a_sealed_answer_that_does_not_sign_does_not_panic() {
        let profile = Profile::PqPure;
        let keyring = Keyring::system(profile).unwrap();
        let key = NodeKey::generate_identity(profile, 0).unwrap();
        let signer = Signer {
            key: &key,
            self_id: key.key_id(),
        };
        // Answered as this node, the request names another node as its
        // target, so no reply to it signs.
        let (request, sealing) = sealed_call(&keyring, [2; 32]);
        let refused = Outcome::Refused(CODE_HANDLER_ERROR, Some("no".into()));
        assert_eq!(answered(&signer, &request, Some(&sealing), refused), None);
        let result = Outcome::Result(Value::text("answer"));
        assert_eq!(answered(&signer, &request, Some(&sealing), result), None);
        // Targeting this node, the same answers sign, sealed.
        let (request, sealing) = sealed_call(&keyring, key.key_id());
        let result = Outcome::Result(Value::text("answer"));
        let reply = answered(&signer, &request, Some(&sealing), result).unwrap();
        assert!(reply.get("reply").is_some(), "{reply:?}");
    }
}
