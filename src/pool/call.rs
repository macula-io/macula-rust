//! Calls and streams that reach a provider at its own station, and the DHT
//! through the pool's links.
//!
//! A call resolves the procedure's advertisements from the DHT, keeps those
//! the realm's pinned key authorizes (or, in a node's own namespace, those
//! that node signed), and tries the freshest first: it dials the serving
//! station the advertisement names, pinned by its node_id from the station's
//! own station_endpoint record, and calls the provider there. It moves on to
//! the next candidate only when a station cannot be reached within that
//! candidate's share of the deadline, before anything is sent: once the CALL
//! or STREAM_OPEN has gone out, under the whole deadline, its outcome is
//! returned as it is, a timeout included, so one call reaches a provider at
//! most once (macula's call_work and failure_scope/1). A candidate that
//! answered is remembered until its advertisement expires.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::time::Instant;

use crate::cbor::Value;
use crate::frame::StreamMode;
use crate::record::{self, RecordType, Trust, Verified};
use crate::seal::KEY_ID_SIZE;
use crate::station_link::{
    self, Confidentiality, ConfidentialityError, ConfidentialityReason, Link, LinkError, Report,
    Reseal, Seal, Stream, DEFAULT_CALL_TIMEOUT,
};
use crate::transport::Target;

use super::member::Member;
use super::{Pool, PoolError, PoolInner};

/// No candidate gets less than a second of a call's time.
const MIN_CANDIDATE_SHARE: Duration = Duration::from_secs(1);

/// A call to a procedure: its realm and name, the provider to call (any
/// trusted one when zero), the payload, how long to wait
/// ([`DEFAULT_CALL_TIMEOUT`] when zero), a UCAN and its proofs for a gated
/// procedure, and how it must be kept.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub realm: [u8; 32],
    pub procedure: String,
    pub provider: [u8; 32],
    pub payload: Value,
    pub timeout: Duration,
    pub token: Option<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub confidential: Confidentiality,
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
            confidential: Confidentiality::Preferred,
        }
    }
}

/// A streaming session to open: its realm and name, the provider (any
/// trusted one when zero), the mode, the open's payload, its deadline (the
/// link's default when zero), a UCAN and its proofs for a gated procedure,
/// and how it must be kept. Its default mode is server_stream.
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
    pub confidential: Confidentiality,
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
            confidential: Confidentiality::Preferred,
        }
    }
}

/// A node serving a procedure, and the station it serves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Provider {
    pub node: [u8; 32],
    pub station: [u8; 32],
}

/// A trusted advertisement: its provider, serving station, times, and the
/// KEM key it names, as carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Candidate {
    provider: Provider,
    expires_at: u64,
    created_at: u64,
    kem_key: Option<Vec<u8>>,
}

impl Candidate {
    /// How a call to this candidate is kept: sealed to the key its
    /// advertisement names, or clear when it names none.
    fn seal(&self) -> Seal {
        match &self.kem_key {
            Some(key) => Seal::To(key.clone()),
            None => Seal::Clear,
        }
    }

    fn kem_key_id(&self) -> Option<[u8; KEY_ID_SIZE]> {
        self.kem_key.as_deref().map(crate::seal::key_id)
    }
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
        self.call_report(c).await.map(|(result, _)| result)
    }

    /// [`Pool::call`], returning with its result the call's seal report
    /// (macula's DESIGN_E2E_SEAL_REPORT): `sealed` 1 with the id of the key
    /// the request was sealed to, which is the key its answer opened under,
    /// or 0 and no key for a clear call; `provider` is the node the call was
    /// addressed to. An error comes with no report. It states that sealing
    /// ran on this exchange, nothing more.
    pub async fn call_report(&self, c: Call) -> Result<(Value, Report), PoolError> {
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
        let candidates = bounded(deadline, inner.candidates(&key, realm_key.clone())).await?;
        let candidates = callable(candidates, c.confidential)?;
        let (link, cand) = first_reached(inner, &key, candidates, deadline).await?;
        let outcome = bounded(deadline, inner.call_at(&link, &cand, &c, deadline)).await;
        let sent = Sent {
            link: &link,
            call: &c,
            realm_key,
            deadline,
        };
        let (cand, outcome) = inner.resealed(&key, cand, &sent, outcome).await;
        inner.settled(key, cand, outcome)
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
    /// [`Pool::call`] reaches one: the next candidate only when a station
    /// cannot be reached, and the link's own outcome is final. The stream is
    /// open once its STREAM_OPEN is sent; a provider's or station's refusal
    /// arrives on its first recv. A sealed stream refused sealed_refused
    /// after its provider's key rotated, before it has sent anything,
    /// reopens once behind the same handle, sealed to the key the provider
    /// names, as a call reseals ([`Pool::call`]); never in the clear.
    pub async fn open_stream(&self, c: StreamCall) -> Result<Stream, PoolError> {
        let inner = &self.inner;
        let realm_key = inner.realm_key_for(&c.realm, &c.procedure)?;
        let deadline = Instant::now() + DEFAULT_CALL_TIMEOUT;
        let key = ResolvedKey {
            realm: c.realm,
            procedure: c.procedure.clone(),
            provider: c.provider,
        };
        let candidates = bounded(deadline, inner.candidates(&key, realm_key.clone())).await?;
        let candidates = callable(candidates, c.confidential)?;
        let (link, cand) = first_reached(inner, &key, candidates, deadline).await?;
        let reseal = inner.stream_reseal(&key, &cand, &c, realm_key, &link);
        let outcome = bounded(deadline, inner.open_at(&link, &cand, &c, reseal)).await;
        inner.settled(key, cand, outcome)
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
        let remembered = self.lock().remember.get(key).cloned();
        let live = remembered.filter(|cand| {
            cand.expires_at as i64 > now_ms() && self.linked_to(&cand.provider.station).is_some()
        });
        if let Some(cand) = live {
            return Ok(vec![cand]);
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
            .filter_map(|v| trusted_candidate(v, key, &trust, now))
            .collect();
        if out.is_empty() {
            return Err(PoolError::NoProvider(Vec::new()));
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(out)
    }

    /// A link to the candidate's serving station, reached by `share`.
    /// Nothing is sent.
    async fn reach(self: &Arc<Self>, cand: &Candidate, share: Instant) -> Result<Link, PoolError> {
        bounded(share, self.link_to(&cand.provider.station, share)).await
    }

    /// The outcome of a call or stream sent to `cand`, final whatever it is:
    /// a CALL that went out is never sent again elsewhere. A candidate whose
    /// provider answered is remembered, one that did not is forgotten.
    fn settled<T>(
        &self,
        key: ResolvedKey,
        cand: Candidate,
        outcome: Result<T, PoolError>,
    ) -> Result<T, PoolError> {
        match &outcome {
            Ok(_) | Err(PoolError::Link(LinkError::Provider { .. })) => self.remember(key, cand),
            Err(_) => self.forget(&key),
        }
        outcome
    }

    /// Calls the candidate's provider on `link`, under what is left before
    /// `deadline`, and reports the call: a sealed call's result is only ever
    /// one its answer opened under the key it was sealed to (the link
    /// refuses any other), so `sealed` 1 names that key.
    async fn call_at(
        &self,
        link: &Link,
        cand: &Candidate,
        c: &Call,
        deadline: Instant,
    ) -> Result<(Value, Report), PoolError> {
        let left = deadline.saturating_duration_since(Instant::now());
        let result = link
            .call(station_link::Call {
                realm: c.realm,
                procedure: c.procedure.clone(),
                target: cand.provider.node,
                payload: c.payload.clone(),
                timeout: left.max(Duration::from_millis(1)),
                token: c.token.clone(),
                proofs: c.proofs.clone(),
                seal: Some(cand.seal()),
            })
            .await?;
        Ok((result, Report::of(cand.provider.node, cand.kem_key_id())))
    }

    /// A sealed call refused sealed_refused after its provider's key rotated,
    /// sealed again once, as macula's `resealed/7` does (E2E design §5.1,
    /// Amendment A1; macula-rust#20): ONE fresh lookup of the provider's own
    /// trusted advertisements, then a new request sealed to the one naming
    /// exactly the key the refusal named, or, from a provider that named
    /// none, to the first key it advertises. A second refusal is the result.
    /// Any other key fails key_mismatch naming both, none fails no_kem_key;
    /// never the clear. Any other outcome is returned as it is. The
    /// candidate the outcome came from, and the outcome.
    async fn resealed(
        &self,
        key: &ResolvedKey,
        cand: Candidate,
        sent: &Sent<'_>,
        outcome: Result<(Value, Report), PoolError>,
    ) -> (Candidate, Result<(Value, Report), PoolError>) {
        let named = match &outcome {
            Err(PoolError::Link(LinkError::SealedRefused { named })) if cand.kem_key.is_some() => {
                *named
            }
            _ => return (cand, outcome),
        };
        let own = ResolvedKey {
            provider: cand.provider.node,
            ..key.clone()
        };
        let fresh = bounded(sent.deadline, self.resolve(&own, sent.realm_key.clone())).await;
        let next = match reseal_to(fresh, named) {
            Ok(next) => next,
            Err(e) => return (cand, Err(e)),
        };
        let resent = self.call_at(sent.link, &next, sent.call, sent.deadline);
        let outcome = bounded(sent.deadline, resent).await;
        (next, outcome)
    }

    /// Opens the stream at the candidate's provider on `link`, holding
    /// `reseal` for a sealed_refused of its open.
    async fn open_at(
        &self,
        link: &Link,
        cand: &Candidate,
        c: &StreamCall,
        reseal: Option<Reseal>,
    ) -> Result<Stream, PoolError> {
        Ok(link
            .open_stream_resealing(
                station_link::StreamCall {
                    realm: c.realm,
                    procedure: c.procedure.clone(),
                    target: cand.provider.node,
                    mode: c.mode,
                    payload: c.payload.clone(),
                    deadline: c.deadline,
                    token: c.token.clone(),
                    proofs: c.proofs.clone(),
                    seal: Some(cand.seal()),
                },
                reseal,
            )
            .await?)
    }

    /// A sealed stream's one reseal, on a call's terms (see
    /// [`PoolInner::resealed`]): one fresh lookup of the provider's own
    /// trusted advertisements, then the stream reopened on `link` sealed
    /// only to the key the refusal named (another fails naming both, none
    /// fails closed), or, after a keyless refusal, to the first key the
    /// provider now names. The reopened stream holds no reseal: a second
    /// refusal ends it. None for a clear candidate.
    fn stream_reseal(
        self: &Arc<Self>,
        key: &ResolvedKey,
        cand: &Candidate,
        c: &StreamCall,
        realm_key: Option<Vec<u8>>,
        link: &Link,
    ) -> Option<Reseal> {
        cand.kem_key.as_ref()?;
        let pool = Arc::downgrade(self);
        let r = Resealing {
            own: ResolvedKey {
                provider: cand.provider.node,
                ..key.clone()
            },
            key: key.clone(),
            c: c.clone(),
            link: link.clone(),
            realm_key,
        };
        Some(Box::new(move |named| {
            Box::pin(resealed_stream(pool, r, named))
        }))
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
        let (existing, direct) = self.member_for(station)?;
        let fresh = existing.is_none();
        let member = match existing {
            Some(m) => m,
            None => self.start_direct(station, direct, deadline).await?,
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

    /// The member already linking to `station`, if any, and how many direct
    /// links the pool holds; [`PoolError::Closed`] on a closed pool.
    fn member_for(&self, station: &[u8; 32]) -> Result<(Option<Arc<Member>>, usize), PoolError> {
        let state = self.lock();
        if state.closed {
            return Err(PoolError::Closed);
        }
        let existing = state
            .members
            .iter()
            .find(|m| m.target.expected_node_id == *station)
            .cloned();
        Ok((existing, state.members.iter().filter(|m| m.direct).count()))
    }

    /// Starts a direct link to `station`, at the address its own endpoint
    /// record names, when fewer than `max_direct_links` are held.
    async fn start_direct(
        self: &Arc<Self>,
        station: &[u8; 32],
        direct: usize,
        deadline: Instant,
    ) -> Result<Arc<Member>, PoolError> {
        if direct >= self.opts.max_direct_links {
            return Err(PoolError::DirectLinksFull);
        }
        let target = bounded(deadline, self.station_target(station)).await?;
        Ok(self.start_member(target, true))
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

/// A call that went out: the link it went on, the call, the realm key its
/// candidates were trusted under, and its deadline.
struct Sent<'a> {
    link: &'a Link,
    call: &'a Call,
    realm_key: Option<Vec<u8>>,
    deadline: Instant,
}

/// The advertisement a refused sealed call is sealed to again, from the
/// provider's fresh advertisements (`found`): the one naming exactly the key
/// the refusal `named`, searched for since the DHT may still serve an older
/// one, or, when the refusal named none, the first that names a key. When
/// the named key is not among them, key_mismatch naming both; when none
/// names a key, no_kem_key.
/// What a stream's reseal reopens: the provider's own key, the key the pool
/// remembers it under, the open, and its link and realm key.
struct Resealing {
    own: ResolvedKey,
    key: ResolvedKey,
    c: StreamCall,
    link: Link,
    realm_key: Option<Vec<u8>>,
}

/// The stream reopened as [`PoolInner::stream_reseal`] says.
async fn resealed_stream(
    pool: Weak<PoolInner>,
    r: Resealing,
    named: Option<[u8; KEY_ID_SIZE]>,
) -> Result<Stream, LinkError> {
    let pool = pool.upgrade().ok_or(LinkError::Closed)?;
    let deadline = Instant::now() + DEFAULT_CALL_TIMEOUT;
    let fresh = bounded(deadline, pool.resolve(&r.own, r.realm_key)).await;
    let reopened = match reseal_to(fresh, named) {
        Ok(next) => bounded(deadline, pool.open_at(&r.link, &next, &r.c, None))
            .await
            .map(|stream| (stream, next)),
        Err(e) => Err(e),
    };
    // As a call settles: the provider's new key is remembered, and a stale
    // one is forgotten, so the next open looks it up afresh.
    match reopened {
        Ok((stream, next)) => {
            pool.remember(r.key, next);
            Ok(stream)
        }
        Err(e) => {
            pool.forget(&r.key);
            Err(as_link_error(e))
        }
    }
}

/// A pool error as the stream it ends carries it.
fn as_link_error(e: PoolError) -> LinkError {
    match e {
        PoolError::Link(e) => e,
        PoolError::Confidentiality(e) => LinkError::Confidentiality(e),
        other => LinkError::Io(other.to_string()),
    }
}

fn reseal_to(
    found: Result<Vec<Candidate>, PoolError>,
    named: Option<[u8; KEY_ID_SIZE]>,
) -> Result<Candidate, PoolError> {
    let keyed: Vec<Candidate> = found
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.kem_key.is_some())
        .collect();
    let advertised: Vec<[u8; KEY_ID_SIZE]> =
        keyed.iter().filter_map(Candidate::kem_key_id).collect();
    let chosen = match named {
        Some(id) => keyed.into_iter().find(|c| c.kem_key_id() == Some(id)),
        None => keyed.into_iter().next(),
    };
    let reason = match advertised.is_empty() {
        true => ConfidentialityReason::NoKemKey,
        false => ConfidentialityReason::KeyMismatch,
    };
    chosen.ok_or(PoolError::Confidentiality(ConfidentialityError {
        reason,
        advertised,
        named,
    }))
}

/// The first of `candidates` whose serving station is reached within its
/// share of `deadline`, and the link to it; nothing is sent. A candidate not
/// reached is forgotten and named in [`PoolError::NoProvider`], and none is
/// tried once `deadline` has passed.
async fn first_reached(
    inner: &Arc<PoolInner>,
    key: &ResolvedKey,
    candidates: Vec<Candidate>,
    deadline: Instant,
) -> Result<(Link, Candidate), PoolError> {
    let mut tried = Vec::new();
    let count = candidates.len();
    for (i, cand) in candidates.into_iter().enumerate() {
        match inner
            .reach(&cand, candidate_share(deadline, count - i))
            .await
        {
            Ok(link) => return Ok((link, cand)),
            Err(PoolError::Closed) => return Err(PoolError::Closed),
            Err(e) => {
                inner.forget(key);
                tried.push((cand.provider, e));
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    Err(PoolError::NoProvider(tried))
}

/// The candidate an advertisement under `key`'s slot makes, when it is one
/// of `key`'s procedure (by `key.provider` when it is set) and `trust`
/// authorizes it at `now`.
fn trusted_candidate(
    v: &Verified,
    key: &ResolvedKey,
    trust: &Trust,
    now: i64,
) -> Option<Candidate> {
    let ad = record::read_procedure_advertisement(v.record()).ok()?;
    let wanted = ad.realm_id == key.realm
        && ad.procedure == key.procedure
        && (key.provider == [0; 32] || ad.advertiser_node == key.provider);
    if !wanted || record::verify_authorization(v, trust, now).is_err() {
        return None;
    }
    Some(Candidate {
        provider: Provider {
            node: ad.advertiser_node,
            station: ad.serving_station,
        },
        expires_at: v.record().expires_at,
        created_at: v.record().created_at,
        kem_key: ad.kem_key.map(|(key, _)| key),
    })
}

/// A failure of the link to carry a request, as opposed to the station's
/// answer: no reply in time, or the link ended.
fn unreachable(e: &LinkError) -> bool {
    matches!(
        e,
        LinkError::CallTimeout
            | LinkError::Closed
            | LinkError::LivenessLost
            | LinkError::V5DowngradeRefused
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

/// The candidates a call or an open under `confidential` may reach, in their
/// order, before anything is sent. A candidate whose advertisement names a
/// KEM key is called sealed to it. Under `Preferred` a keyless one is called
/// in the clear, unless its provider names a key in another advertisement
/// the DHT still serves (it rotated onto `kem_advertise`): a provider that
/// names a key is never called in the clear. Under `Required` only keyed
/// candidates are called. None left is a [`ConfidentialityError`] naming the
/// advertised key ids. `Off` is refused: a clear call is an explicit
/// target's, made on a link with [`Seal::Clear`].
fn callable(
    candidates: Vec<Candidate>,
    confidential: Confidentiality,
) -> Result<Vec<Candidate>, PoolError> {
    if confidential == Confidentiality::Off {
        return Err(PoolError::InvalidOpts(
            "confidential off is refused for a pool call or open: it is preferred or required"
                .into(),
        ));
    }
    let advertised: Vec<[u8; KEY_ID_SIZE]> = candidates
        .iter()
        .filter_map(Candidate::kem_key_id)
        .collect();
    let keyed: HashSet<[u8; 32]> = candidates
        .iter()
        .filter(|c| c.kem_key.is_some())
        .map(|c| c.provider.node)
        .collect();
    let kept: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| match (confidential, &c.kem_key) {
            (_, Some(_)) => true,
            (Confidentiality::Preferred, None) => !keyed.contains(&c.provider.node),
            (_, None) => false,
        })
        .collect();
    if kept.is_empty() {
        return Err(PoolError::Confidentiality(ConfidentialityError {
            reason: ConfidentialityReason::NoKemKey,
            advertised,
            named: None,
        }));
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(node: u8, kem_key: Option<u8>) -> Candidate {
        Candidate {
            provider: Provider {
                node: [node; 32],
                station: [9; 32],
            },
            expires_at: 0,
            created_at: 0,
            kem_key: kem_key.map(|k| vec![k; 1568]),
        }
    }

    fn refused(r: Result<Vec<Candidate>, PoolError>) -> ConfidentialityError {
        match r {
            Err(PoolError::Confidentiality(e)) => e,
            other => panic!("not a confidentiality refusal: {other:?}"),
        }
    }

    fn key_id_of(k: u8) -> [u8; KEY_ID_SIZE] {
        crate::seal::key_id(&[k; 1568])
    }

    #[test]
    fn a_refused_call_is_sealed_again_only_to_the_key_named() {
        let found = || Ok(vec![cand(1, None), cand(1, Some(7)), cand(1, Some(8))]);
        let next = reseal_to(found(), Some(key_id_of(8))).unwrap();
        assert_eq!(next, cand(1, Some(8)));
        let e = refused(reseal_to(found(), Some(key_id_of(9))).map(|c| vec![c]));
        assert_eq!(e.reason, ConfidentialityReason::KeyMismatch);
        assert_eq!(e.named, Some(key_id_of(9)));
        assert_eq!(e.advertised, vec![key_id_of(7), key_id_of(8)]);
        // A provider that named no key is sealed to the first it advertises.
        assert_eq!(reseal_to(found(), None).unwrap(), cand(1, Some(7)));
        // Nothing keyed, or nothing found: no_kem_key, never the clear.
        let e = refused(reseal_to(Ok(vec![cand(1, None)]), Some(key_id_of(8))).map(|c| vec![c]));
        assert_eq!(e.reason, ConfidentialityReason::NoKemKey);
        let e = refused(reseal_to(Err(PoolError::NoProvider(Vec::new())), None).map(|c| vec![c]));
        assert_eq!(e.reason, ConfidentialityReason::NoKemKey);
    }

    #[test]
    fn preferred_seals_to_a_keyed_provider_and_calls_a_keyless_one_in_the_clear() {
        let kept = callable(
            vec![cand(1, Some(7)), cand(2, None), cand(3, None)],
            Confidentiality::Preferred,
        )
        .unwrap();
        assert_eq!(kept, vec![cand(1, Some(7)), cand(2, None), cand(3, None)]);
        assert_eq!(kept[0].seal(), Seal::To(vec![7; 1568]));
        assert_eq!(kept[1].seal(), Seal::Clear);
    }

    #[test]
    fn a_provider_that_names_a_key_is_not_called_through_its_older_keyless_ad() {
        let kept = callable(
            vec![cand(1, Some(7)), cand(1, None), cand(2, None)],
            Confidentiality::Preferred,
        )
        .unwrap();
        assert_eq!(kept, vec![cand(1, Some(7)), cand(2, None)]);
    }

    #[test]
    fn required_calls_only_keyed_providers_and_refuses_when_there_are_none() {
        let kept = callable(
            vec![cand(1, None), cand(2, Some(7))],
            Confidentiality::Required,
        )
        .unwrap();
        assert_eq!(kept, vec![cand(2, Some(7))]);
        let e = refused(callable(vec![cand(1, None)], Confidentiality::Required));
        assert_eq!(e.reason, ConfidentialityReason::NoKemKey);
        assert!(e.advertised.is_empty());
        assert_eq!(e.to_string(), "confidentiality: no_kem_key");
    }

    #[test]
    fn confidential_parses_and_off_is_refused_for_a_pool_call() {
        assert_eq!(Confidentiality::default(), Confidentiality::Preferred);
        for (text, parsed) in [
            ("", Confidentiality::Preferred),
            ("preferred", Confidentiality::Preferred),
            ("required", Confidentiality::Required),
            ("off", Confidentiality::Off),
        ] {
            assert_eq!(text.parse::<Confidentiality>(), Ok(parsed), "{text}");
        }
        for refused in ["Required", "none", "optional"] {
            assert!(refused.parse::<Confidentiality>().is_err(), "{refused}");
        }
        assert!(matches!(
            callable(vec![cand(1, Some(7))], Confidentiality::Off),
            Err(PoolError::InvalidOpts(_))
        ));
    }
}
