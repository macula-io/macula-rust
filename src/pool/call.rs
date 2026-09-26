//! Calls and streams that reach a provider at its own station, and the DHT
//! through the pool's links.
//!
//! A call resolves the procedure's advertisements from the DHT, keeps those
//! the realm's pinned key authorizes (or, in a node's own namespace, those
//! that node signed), and tries the freshest first: it dials the serving
//! station the advertisement names, pinned by its node_id from the station's
//! own station_endpoint record, and calls the provider there. It moves on to
//! the next candidate when a station cannot be reached or reports it cannot
//! relay the call, and returns a provider's own answer or error as it is. A
//! candidate that answered is remembered until its advertisement expires.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::cbor::Value;
use crate::frame::StreamMode;
use crate::record::{self, RecordType, Trust, Verified};
use crate::station_link::{self, Link, LinkError, Stream, DEFAULT_CALL_TIMEOUT};
use crate::transport::Target;

use super::{Pool, PoolError, PoolInner};

/// No candidate gets less than a second of a call's time.
const MIN_CANDIDATE_SHARE: Duration = Duration::from_secs(1);

/// A call to a procedure: its realm and name, the provider to call (any
/// trusted one when zero), the payload, how long to wait
/// ([`DEFAULT_CALL_TIMEOUT`] when zero), and a UCAN and its proofs for a
/// gated procedure.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub realm: [u8; 32],
    pub procedure: String,
    pub provider: [u8; 32],
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
            provider: [0; 32],
            payload: Value::Map(Vec::new()),
            timeout: Duration::ZERO,
            token: None,
            proofs: Vec::new(),
        }
    }
}

/// A streaming session to open: its realm and name, the provider (any
/// trusted one when zero), the mode, the open's payload, its deadline (the
/// link's default when zero), and a UCAN and its proofs for a gated
/// procedure. Its default mode is server_stream.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamCall {
    pub realm: [u8; 32],
    pub procedure: String,
    pub provider: [u8; 32],
    pub mode: StreamMode,
    pub payload: Value,
    pub deadline: Duration,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
}

impl Default for StreamCall {
    fn default() -> Self {
        StreamCall {
            realm: [0; 32],
            procedure: String::new(),
            provider: [0; 32],
            mode: StreamMode::ServerStream,
            payload: Value::Map(Vec::new()),
            deadline: Duration::ZERO,
            token: None,
            proofs: Vec::new(),
        }
    }
}

/// A node serving a procedure, and the station it serves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Provider {
    pub node: [u8; 32],
    pub station: [u8; 32],
}

/// A trusted advertisement: its provider, serving station and times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Candidate {
    provider: Provider,
    expires_at: u64,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ResolvedKey {
    realm: [u8; 32],
    procedure: String,
    provider: [u8; 32],
}

impl Pool {
    /// Calls a procedure at a provider that serves it, as macula 12 calls
    /// one. A provider's ERROR comes back as
    /// `PoolError::Link(LinkError::Provider { .. })`; when no candidate
    /// answers, [`PoolError::NoProvider`] names each one tried.
    pub async fn call(&self, c: Call) -> Result<Value, PoolError> {
        let inner = &self.inner;
        let realm_key = inner.realm_key_for(&c.realm, &c.procedure)?;
        let timeout = if c.timeout.is_zero() {
            DEFAULT_CALL_TIMEOUT
        } else {
            c.timeout
        };
        let deadline = Instant::now() + timeout;
        let key = ResolvedKey {
            realm: c.realm,
            procedure: c.procedure.clone(),
            provider: c.provider,
        };
        let candidates = bounded(deadline, inner.candidates(&key, realm_key)).await?;
        let mut tried = Vec::new();
        let count = candidates.len();
        for (i, cand) in candidates.into_iter().enumerate() {
            let share = candidate_share(deadline, count - i);
            let outcome = bounded(share, inner.call_at(&cand, &c, share)).await;
            match outcome {
                Ok(v) => {
                    inner.remember(key, cand);
                    return Ok(v);
                }
                Err(e @ PoolError::Link(LinkError::Provider { .. })) => {
                    inner.remember(key, cand);
                    return Err(e);
                }
                Err(e) => {
                    inner.forget(&key);
                    tried.push((cand.provider, e));
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        Err(PoolError::NoProvider(tried))
    }

    /// Every provider whose advertisement of `procedure` in `realm` the
    /// realm's pinned key authorizes, with the station each serves from,
    /// freshest first.
    pub async fn providers(
        &self,
        realm: &[u8; 32],
        procedure: &str,
    ) -> Result<Vec<Provider>, PoolError> {
        let realm_key = self.inner.realm_key_for(realm, procedure)?;
        let key = ResolvedKey {
            realm: *realm,
            procedure: procedure.to_string(),
            provider: [0; 32],
        };
        let found = self.inner.resolve(&key, realm_key).await?;
        Ok(found.into_iter().map(|c| c.provider).collect())
    }

    /// Opens a streaming session at a provider of the procedure, reached as
    /// [`Pool::call`] reaches one. The stream is open once its STREAM_OPEN
    /// is sent; a provider's or station's refusal arrives on its first recv.
    pub async fn open_stream(&self, c: StreamCall) -> Result<Stream, PoolError> {
        let inner = &self.inner;
        let realm_key = inner.realm_key_for(&c.realm, &c.procedure)?;
        let deadline = Instant::now() + DEFAULT_CALL_TIMEOUT;
        let key = ResolvedKey {
            realm: c.realm,
            procedure: c.procedure.clone(),
            provider: c.provider,
        };
        let candidates = bounded(deadline, inner.candidates(&key, realm_key)).await?;
        let mut tried = Vec::new();
        let count = candidates.len();
        for (i, cand) in candidates.into_iter().enumerate() {
            let share = candidate_share(deadline, count - i);
            match bounded(share, inner.open_at(&cand, &c, share)).await {
                Ok(stream) => {
                    inner.remember(key, cand);
                    return Ok(stream);
                }
                Err(e) => {
                    inner.forget(&key);
                    tried.push((cand.provider, e));
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        Err(PoolError::NoProvider(tried))
    }

    /// Where `station` is dialed, from the station_endpoint record the
    /// station signed itself; one another key signed is refused.
    pub async fn station_target(&self, station: &[u8; 32]) -> Result<Target, PoolError> {
        self.inner.station_target(station).await
    }

    /// A link to `station`: one the pool holds, or a direct link it dials to
    /// the address in the station's own endpoint record, pinned by its
    /// node_id, within the default call timeout. A direct link that does not
    /// come up on its first dial is not kept.
    pub async fn link_to(&self, station: &[u8; 32]) -> Result<Link, PoolError> {
        let deadline = Instant::now() + DEFAULT_CALL_TIMEOUT;
        self.inner.link_to(station, deadline).await
    }

    /// The record under `key`, verified, from the first link that answers.
    pub async fn find_record(&self, key: &[u8; 32]) -> Result<Verified, PoolError> {
        self.inner
            .first_answer(|l| async move { l.find_record(key).await })
            .await
    }

    /// The records under `key` that verify, and how many did not, from the
    /// first link that answers.
    pub async fn find_records(&self, key: &[u8; 32]) -> Result<(Vec<Verified>, usize), PoolError> {
        self.inner
            .first_answer(|l| async move { l.find_records(key).await })
            .await
    }

    /// The records of type `t` that verify, and how many did not, from the
    /// first link that answers.
    pub async fn find_records_by_type(
        &self,
        t: RecordType,
    ) -> Result<(Vec<Verified>, usize), PoolError> {
        self.inner
            .first_answer(|l| async move { l.find_records_by_type(t).await })
            .await
    }

    /// Puts a signed record through the first link whose station takes it.
    pub async fn put_record(&self, wire: &[u8]) -> Result<(), PoolError> {
        self.inner
            .first_answer(|l| async move { l.put_record(wire).await })
            .await
    }
}

impl PoolInner {
    fn remember(&self, key: ResolvedKey, cand: Candidate) {
        self.lock().remember.insert(key, cand);
    }

    fn forget(&self, key: &ResolvedKey) {
        self.lock().remember.remove(key);
    }

    /// The remembered candidate while it lives and its station is linked,
    /// else the procedure's trusted advertisements from the DHT.
    async fn candidates(
        &self,
        key: &ResolvedKey,
        realm_key: Option<Vec<u8>>,
    ) -> Result<Vec<Candidate>, PoolError> {
        let remembered = self.lock().remember.get(key).copied();
        if let Some(cand) = remembered {
            if cand.expires_at as i64 > now_ms() && self.linked_to(&cand.provider.station).is_some()
            {
                return Ok(vec![cand]);
            }
        }
        self.resolve(key, realm_key).await
    }

    /// The procedure's advertisements the realm key authorizes, by
    /// `key.provider` when it is set, freshest first.
    async fn resolve(
        &self,
        key: &ResolvedKey,
        realm_key: Option<Vec<u8>>,
    ) -> Result<Vec<Candidate>, PoolError> {
        let slot = record::procedure_key(&key.realm, &key.procedure);
        let (found, _) = self
            .first_answer(|l| async move { l.find_records(&slot).await })
            .await?;
        let now = now_ms();
        let trust = Trust {
            profile: self.opts.identity.profile(),
            realm_key,
        };
        let mut out: Vec<Candidate> = found
            .iter()
            .filter(|v| v.record().record_type == RecordType::PROCEDURE_ADVERTISEMENT)
            .filter_map(|v| {
                let ad = record::read_procedure_advertisement(v.record()).ok()?;
                let wanted = ad.realm_id == key.realm
                    && ad.procedure == key.procedure
                    && (key.provider == [0; 32] || ad.advertiser_node == key.provider);
                if !wanted || record::verify_authorization(v, &trust, now).is_err() {
                    return None;
                }
                Some(Candidate {
                    provider: Provider {
                        node: ad.advertiser_node,
                        station: ad.serving_station,
                    },
                    expires_at: v.record().expires_at,
                    created_at: v.record().created_at,
                })
            })
            .collect();
        if out.is_empty() {
            return Err(PoolError::NoProvider(Vec::new()));
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(out)
    }

    async fn call_at(
        self: &Arc<Self>,
        cand: &Candidate,
        c: &Call,
        share: Instant,
    ) -> Result<Value, PoolError> {
        let link = self.link_to(&cand.provider.station, share).await?;
        let left = share.saturating_duration_since(Instant::now());
        Ok(link
            .call(station_link::Call {
                realm: c.realm,
                procedure: c.procedure.clone(),
                target: cand.provider.node,
                payload: c.payload.clone(),
                timeout: left.max(Duration::from_millis(1)),
                token: c.token.clone(),
                proofs: c.proofs.clone(),
            })
            .await?)
    }

    async fn open_at(
        self: &Arc<Self>,
        cand: &Candidate,
        c: &StreamCall,
        share: Instant,
    ) -> Result<Stream, PoolError> {
        let link = self.link_to(&cand.provider.station, share).await?;
        Ok(link
            .open_stream(station_link::StreamCall {
                realm: c.realm,
                procedure: c.procedure.clone(),
                target: cand.provider.node,
                mode: c.mode,
                payload: c.payload.clone(),
                deadline: c.deadline,
                token: c.token.clone(),
                proofs: c.proofs.clone(),
            })
            .await?)
    }

    /// The link up now to `station`, if any.
    fn linked_to(&self, station: &[u8; 32]) -> Option<Link> {
        self.links()
            .into_iter()
            .find(|l| l.station_node_id() == *station)
    }

    pub(super) async fn link_to(
        self: &Arc<Self>,
        station: &[u8; 32],
        deadline: Instant,
    ) -> Result<Link, PoolError> {
        if let Some(link) = self.linked_to(station) {
            return Ok(link);
        }
        let (existing, direct) = {
            let state = self.lock();
            if state.closed {
                return Err(PoolError::Closed);
            }
            let existing = state
                .members
                .iter()
                .find(|m| m.target.expected_node_id == *station)
                .cloned();
            (existing, state.members.iter().filter(|m| m.direct).count())
        };
        let fresh = existing.is_none();
        let member = match existing {
            Some(m) => m,
            None => {
                if direct >= self.opts.max_direct_links {
                    return Err(PoolError::DirectLinksFull);
                }
                let target = bounded(deadline, self.station_target(station)).await?;
                self.start_member(target, true)
            }
        };
        if let Some(link) = member.await_up(deadline, fresh).await {
            return Ok(link);
        }
        if fresh {
            self.drop_member(&member);
        }
        Err(PoolError::StationNotReached {
            station: *station,
            cause: member.last_error(),
        })
    }

    async fn station_target(&self, station: &[u8; 32]) -> Result<Target, PoolError> {
        let slot = record::station_endpoint_key(station);
        let verified = self
            .first_answer(|l| async move { l.find_record(&slot).await })
            .await
            .map_err(|e| match e {
                PoolError::Link(link) => PoolError::NoStationEndpoint(Some(link)),
                other => other,
            })?;
        let r = verified.record();
        let signer = r.signed.as_ref().map(|s| s.key_id);
        let endpoint = record::read_station_endpoint(r)
            .map_err(|e| PoolError::NoStationEndpoint(Some(e.into())))?;
        match (signer, endpoint.host_advertised.first()) {
            (Some(signer), Some(host)) if signer == *station && endpoint.quic_port != 0 => {
                Ok(Target {
                    host: host.clone(),
                    port: endpoint.quic_port,
                    profile: self.opts.identity.profile(),
                    expected_node_id: *station,
                })
            }
            _ => Err(PoolError::NoStationEndpoint(None)),
        }
    }

    /// Runs `ask` on the links in selection order and returns the first
    /// answer, moving on only when a link could not carry the request: a
    /// station's own answer, not_found included, is final.
    pub(super) async fn first_answer<'a, T, F, Fut>(&self, ask: F) -> Result<T, PoolError>
    where
        F: Fn(Link) -> Fut,
        Fut: Future<Output = Result<T, LinkError>> + 'a,
    {
        let links = self.links();
        if links.is_empty() {
            return Err(PoolError::NoLink(Vec::new()));
        }
        let mut errors = Vec::new();
        for link in links {
            match ask(link).await {
                Err(e) if unreachable(&e) => errors.push(e),
                answered => return answered.map_err(PoolError::Link),
            }
        }
        Err(PoolError::NoLink(errors))
    }
}

/// A failure of the link to carry a request, as opposed to the station's
/// answer: no reply in time, or the link ended.
fn unreachable(e: &LinkError) -> bool {
    matches!(
        e,
        LinkError::CallTimeout
            | LinkError::Closed
            | LinkError::LivenessLost
            | LinkError::Io(_)
            | LinkError::Goodbye(_)
            | LinkError::StatusExpired
            | LinkError::BindingExpired
    )
}

/// One candidate's part of what is left before `deadline` with `left`
/// candidates to try, at least a second, as macula shares it, and never past
/// `deadline` itself.
fn candidate_share(deadline: Instant, left: usize) -> Instant {
    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    (now + (remaining / left.max(1) as u32).max(MIN_CANDIDATE_SHARE)).min(deadline)
}

/// `work` bounded by `deadline`: past it, the call timed out.
async fn bounded<T>(
    deadline: Instant,
    work: impl Future<Output = Result<T, PoolError>>,
) -> Result<T, PoolError> {
    tokio::time::timeout_at(deadline, work)
        .await
        .unwrap_or(Err(PoolError::Link(LinkError::CallTimeout)))
}

fn now_ms() -> i64 {
    crate::uuid_v7::now_ms() as i64
}
