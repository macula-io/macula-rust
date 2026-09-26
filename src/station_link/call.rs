//! Calls on a link: a CALL signed with the link's identity key, answered by
//! the RESULT or ERROR that verifies for it: a provider reply signed by its
//! target, or a relay error the connected station signed. A reply that does
//! not verify is counted and ignored, and the call keeps waiting, as macula's
//! link does. The liveness probe is a call too.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::cbor::Value;
use crate::frame::{self, ReplyType, RequestSpec, VerifiedRequest};

use super::{now_ms, Inner, Link, LinkError};

/// macula's default timeout for a call.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest a call waits: the far edge of a provider's deadline window.
pub const MAX_CALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const LIVENESS_EVERY: Duration = Duration::from_secs(30);
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(30);
const LIVENESS_PROCEDURE: &str = "_macula.ping";

/// One request: the realm and procedure, the node it targets (the station
/// itself when zero, as for `_dht.*`; the provider's node_id otherwise), its
/// payload, how long to wait (the default when zero), and a UCAN token and
/// its delegation chain's proofs for a gated procedure.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub realm: [u8; 32],
    pub procedure: String,
    pub target: [u8; 32],
    pub payload: Value,
    pub timeout: Duration,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
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
        }
    }
}

/// A call waiting for its reply.
pub(super) struct Pending {
    pub(super) request: VerifiedRequest,
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
    let target = if c.target == [0; 32] {
        inner.station.node_id
    } else {
        c.target
    };
    let mut request_id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut request_id).map_err(|_| LinkError::Io("no randomness".into()))?;
    let signed = frame::sign_call(
        &RequestSpec {
            request_id,
            realm: c.realm,
            procedure: c.procedure,
            target,
            deadline: (now_ms() + timeout.as_millis() as i64) as u64,
            payload: c.payload,
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
    {
        let mut state = inner.lock();
        if let Some(e) = &state.ended {
            return Err(e.clone());
        }
        state.pending.insert(
            request_id,
            Pending {
                request,
                outcome: outcome_tx,
            },
        );
    }
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

/// A RESULT or ERROR matched to its pending call by the ids it claims, and
/// handed on only once it verifies for that call's request.
pub(super) fn replied(inner: &Arc<Inner>, v: &Value) {
    let Ok((request_id, _)) = frame::claimed_reply_ids(v) else {
        inner.count("malformed_reply");
        return;
    };
    let request = match inner.lock().pending.get(&request_id) {
        Some(p) => p.request.clone(),
        None => {
            inner.count("unmatched_reply");
            return;
        }
    };
    let Some(outcome) = verified_outcome(inner, v, &request) else {
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
) -> Option<Result<Value, LinkError>> {
    if v.get("reply").is_some() {
        let reply = frame::verify_reply(v, request, inner.profile).ok()?;
        return Some(match reply.frame_type {
            ReplyType::Result => Ok(reply.payload.unwrap_or(Value::Null)),
            ReplyType::Error => Err(LinkError::Provider {
                responded_by: reply.responded_by,
                code: reply.code.unwrap_or_default(),
                detail: reply.detail,
            }),
        });
    }
    let relayed =
        frame::verify_relay_error(v, request, inner.profile, &inner.station.node_id).ok()?;
    Some(Err(LinkError::Relay {
        reported_by: relayed.reported_by,
        code: relayed.code,
    }))
}

/// A liveness probe every 30 seconds; two misses in a row end the link. Any
/// verified answer counts: it proves the station is there.
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
        let outcome = call(
            &inner,
            Call {
                procedure: LIVENESS_PROCEDURE.to_string(),
                timeout: LIVENESS_TIMEOUT,
                ..Call::default()
            },
        )
        .await;
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
