//! Calls on a link: a CALL signed with the link's identity key, answered by
//! the RESULT or ERROR that verifies for it: a provider reply signed by its
//! target, or a relay error the connected station signed. A reply that does
//! not verify is counted and ignored, and the call keeps waiting, as macula's
//! link does. On a v4 link the liveness probe is a call too.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::cbor::Value;
use crate::frame::{self, RequestSpec, VerifiedRequest};
use crate::handshake::VERSION_5;

use super::confidential::{reply_outcome, sealed_request, stated, CallSeal, Seal};
use super::{now_ms, Inner, Link, LinkError};
use crate::seal;

/// macula's default timeout for a call.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest a call waits: the far edge of a provider's deadline window.
pub const MAX_CALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const LIVENESS_EVERY: Duration = Duration::from_secs(30);
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(30);
const LIVENESS_PROCEDURE: &str = "_macula.ping";

/// One request: the realm and procedure, the node it targets (the station
/// itself when zero, as for `_dht.*`; the provider's node_id otherwise), its
/// payload, how long to wait (the default when zero), a UCAN token and its
/// delegation chain's proofs for a gated procedure, and how it is kept. A
/// call to a provider must state `seal`: sealed to the key its verified
/// advertisement names, or clear by the application's decision; one that
/// states neither is refused no_signed_state before anything is sent. A call
/// to the station is always clear.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub realm: [u8; 32],
    pub procedure: String,
    pub target: [u8; 32],
    pub payload: Value,
    pub timeout: Duration,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub seal: Option<Seal>,
}

impl Default for Call {
    fn default() -> Self {
        Call {
            realm: [0; 32],
            procedure: String::new(),
            target: [0; 32],
            payload: Value::Map(Vec::new()),
            timeout: Duration::ZERO,
            token: None,
            proofs: Vec::new(),
            seal: None,
        }
    }
}

/// A call waiting for its reply, with what its sealed request agreed.
pub(super) struct Pending {
    pub(super) request: VerifiedRequest,
    pub(super) seal: Option<CallSeal>,
    pub(super) outcome: oneshot::Sender<Result<Value, LinkError>>,
}

impl Link {
    /// Signs `c` as a CALL, sends it, and waits for the RESULT or ERROR that
    /// verifies for it.
    pub async fn call(&self, c: Call) -> Result<Value, LinkError> {
        call(&self.inner, c).await
    }
}

pub(super) async fn call(inner: &Arc<Inner>, c: Call) -> Result<Value, LinkError> {
    let timeout = if c.timeout.is_zero() {
        DEFAULT_CALL_TIMEOUT
    } else {
        c.timeout.min(MAX_CALL_TIMEOUT)
    };
    stated(&c.target, &inner.station.node_id, &c.seal)?;
    let target = if c.target == [0; 32] {
        inner.station.node_id
    } else {
        c.target
    };
    let mut request_id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut request_id).map_err(|_| LinkError::Io("no randomness".into()))?;
    let deadline = (now_ms() + timeout.as_millis() as i64) as u64;
    let (sealed, call_seal) = sealed_call(inner, &c, target, request_id, deadline)?;
    let signed = frame::sign_call(
        &RequestSpec {
            request_id,
            realm: c.realm,
            procedure: c.procedure,
            target,
            deadline,
            payload: c.payload,
            sealed,
            mode: None,
            token: c.token,
            proofs: c.proofs,
            source_route: None,
            retry_budget: None,
        },
        &inner.key,
    )?;
    let request = frame::verify_request(&signed, inner.profile)?;
    let (outcome_tx, outcome) = oneshot::channel();
    await_reply(
        inner,
        request_id,
        Pending {
            request,
            seal: call_seal,
            outcome: outcome_tx,
        },
    )?;
    let forget = || {
        inner.lock().pending.remove(&request_id);
    };
    if let Err(e) = inner.write_control(&signed).await {
        forget();
        return Err(e);
    }
    let answered = tokio::time::timeout(timeout, outcome).await;
    forget();
    match answered {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => Err(inner.lock().ended.clone().unwrap_or(LinkError::Closed)),
        Err(_) => Err(LinkError::CallTimeout),
    }
}

/// The call's payload sealed to the key its seal names, with what the sealing
/// agreed; nothing when the call goes clear.
fn sealed_call(
    inner: &Inner,
    c: &Call,
    target: [u8; 32],
    request_id: [u8; 16],
    deadline: u64,
) -> Result<(Option<frame::Sealed>, Option<CallSeal>), LinkError> {
    match &c.seal {
        Some(Seal::To(key)) => {
            let (sealed, s) = sealed_request(
                inner.profile,
                key,
                seal::FRAME_CALL,
                c.realm,
                &c.procedure,
                inner.self_id,
                target,
                request_id,
                deadline,
                &c.payload,
            )?;
            Ok((Some(sealed), Some(s)))
        }
        _ => Ok((None, None)),
    }
}

/// Files the call as pending under its request id, unless the link has
/// ended, in which case its end is the call's error.
fn await_reply(inner: &Inner, request_id: [u8; 16], pending: Pending) -> Result<(), LinkError> {
    let mut state = inner.lock();
    if let Some(e) = &state.ended {
        return Err(e.clone());
    }
    state.pending.insert(request_id, pending);
    Ok(())
}

/// A RESULT or ERROR matched to its pending call by the ids it claims, and
/// handed on only once it verifies for that call's request.
pub(super) fn replied(inner: &Arc<Inner>, v: &Value) {
    let Ok((request_id, _)) = frame::claimed_reply_ids(v) else {
        inner.count("malformed_reply");
        return;
    };
    let (request, seal) = match inner.lock().pending.get(&request_id) {
        Some(p) => (p.request.clone(), p.seal.clone()),
        None => {
            inner.count("unmatched_reply");
            return;
        }
    };
    let Some(outcome) = verified_outcome(inner, v, &request, seal.as_ref()) else {
        inner.count("unverified_reply");
        return;
    };
    if let Some(p) = inner.lock().pending.remove(&request_id) {
        let _ = p.outcome.send(outcome);
    }
}

fn verified_outcome(
    inner: &Inner,
    v: &Value,
    request: &VerifiedRequest,
    seal: Option<&CallSeal>,
) -> Option<Result<Value, LinkError>> {
    if v.get("reply").is_some() {
        let reply = frame::verify_reply(v, request, inner.profile).ok()?;
        return Some(reply_outcome(reply, request, seal));
    }
    let relayed =
        frame::verify_relay_error(v, request, inner.profile, &inner.station.node_id).ok()?;
    Some(Err(LinkError::Relay {
        reported_by: relayed.reported_by,
        code: relayed.code,
    }))
}

/// A liveness probe every 30 seconds; two misses in a row end the link. On v5
/// the probe is a liveness_ping, answered by the station's connection with a
/// liveness_pong of its nonce, and nothing is signed. On v4 it is a
/// `_macula.ping` call: any verified answer counts, a provider's or a relay
/// error from the station alike, as it proves the station is there.
pub(super) async fn probe(link: Weak<Inner>) {
    let mut misses = 0;
    loop {
        let Some(mut done) = link.upgrade().map(|l| l.done_rx.clone()) else {
            return;
        };
        tokio::select! {
            _ = done.wait_for(|ended| *ended) => return,
            _ = tokio::time::sleep(LIVENESS_EVERY) => {}
        }
        let Some(inner) = link.upgrade() else { return };
        let outcome = match inner.version {
            VERSION_5 => probe_v5(&inner).await,
            _ => call(
                &inner,
                Call {
                    procedure: LIVENESS_PROCEDURE.to_string(),
                    timeout: LIVENESS_TIMEOUT,
                    ..Call::default()
                },
            )
            .await
            .map(|_| ()),
        };
        misses = if matches!(outcome, Err(LinkError::CallTimeout)) {
            misses + 1
        } else {
            0
        };
        if misses >= 2 {
            inner.end(LinkError::LivenessLost);
            return;
        }
    }
}

/// One v5 liveness probe: answered when a liveness_pong of its nonce arrives
/// within [`LIVENESS_TIMEOUT`], [`LinkError::CallTimeout`] when none does.
async fn probe_v5(inner: &Inner) -> Result<(), LinkError> {
    let mut nonce = [0u8; frame::LIVENESS_NONCE_SIZE];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| LinkError::Io("no randomness".into()))?;
    let mut pongs = inner.pongs_rx.lock().await;
    // A pong that arrived after its probe's deadline must not take the place
    // of this probe's.
    while pongs.try_recv().is_ok() {}
    inner
        .send_control(&frame::liveness_ping_frame(&nonce))
        .await?;
    let mut done = inner.done_rx.clone();
    let answered = pong_of(&mut pongs, nonce);
    tokio::select! {
        _ = done.wait_for(|ended| *ended) => Err(LinkError::Closed),
        outcome = tokio::time::timeout(LIVENESS_TIMEOUT, answered) => {
            outcome.unwrap_or(Err(LinkError::CallTimeout))
        }
    }
}

/// Waits for the liveness_pong of `nonce`, passing over any other;
/// [`LinkError::Closed`] when the pongs stop.
async fn pong_of(
    pongs: &mut tokio::sync::mpsc::Receiver<[u8; frame::LIVENESS_NONCE_SIZE]>,
    nonce: [u8; frame::LIVENESS_NONCE_SIZE],
) -> Result<(), LinkError> {
    while let Some(pong) = pongs.recv().await {
        if pong == nonce {
            return Ok(());
        }
    }
    Err(LinkError::Closed)
}
