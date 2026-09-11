//! Direct-dial resolve-and-call: resolving a signed `procedure_advertisement`
//! DHT record and its serving station's own signed `station_endpoint`, then
//! dialing that station in one hop — instead of depending on ordinary
//! advertise-gossip having propagated a route between whichever two
//! stations happen to be involved.
//!
//! Ported from `macula-io/macula`'s `macula_direct_dial.erl`, cross-checked
//! against `macula-go`'s own port of the same reference
//! (`directdial/directdial.go`) — see that file's doc for the fuller
//! reasoning behind each design choice made here.
//!
//! **Trust model** (see `macula_direct_dial.erl`'s module doc for the full
//! reasoning): every candidate `procedure_advertisement` must carry a valid
//! Ed25519 signature before its `serving_station` is trusted at all, and
//! the resolved `station_endpoint` must be signed by the station itself.
//! The actual QUIC dial trusts neither the TLS certificate (a production
//! station's TLS is terminated by an unrelated PKI) nor nothing — trust is
//! enforced at the application layer, by checking the freshly dialed
//! session's own signature-verified HELLO identity against the exact
//! pubkey the signed DHT chain resolved.
//!
//! **Candidates:** every advertisement (or content announcement) that
//! verifies is a candidate, tried in the order the DHT returned them. A
//! candidate whose endpoint record doesn't resolve, whose dial fails, or
//! whose dialed identity doesn't match is skipped for the next one, because
//! nothing has reached the provider yet. Once a CALL or STREAM_OPEN has gone
//! out, its result is the call's result and it is never sent again. When a
//! query fails, no candidate qualifies, or every one failed before sending,
//! the DHT is queried again with a backoff of 100 ms doubling to 1 s; within
//! one call a
//! station that already failed is dialed again only once its advertisement
//! or endpoint record has changed. The call's `timeout` bounds all of it,
//! and each candidate gets a share of what remains for its endpoint lookup
//! and dial. At the deadline, the most recent candidate failure is returned
//! as it was raised; a later query that finds nothing, or fails, never
//! replaces it. When no candidate was ever tried, the call returns why the
//! latest answered query found none, else the latest failed query's error,
//! else a timeout: an absence nobody observed is never reported.
//!
//! **Reuse:** a station keeps one connection per identity and closes the
//! older one when a newer one arrives. So when this process already has a
//! session open to the provider's station under the same identity
//! (`resolve_via` itself, or a [`Pool`](crate::pool::Pool) link),
//! [`open_stream_direct`], [`put_direct`] and [`get_direct`] run on that
//! session, on a dedicated QUIC stream of their own, instead of dialing,
//! and never close it. They need no `station_endpoint` lookup either.
//! [`call`] and its variants still dial.
//!
//! `cert_chain`-based org/realm authorization (Slice 7c Direction B,
//! `macula_record:verify_advertisement_cert_chain/3` on the Erlang side) is
//! opt-in here too, matching the reference and `macula-go`'s own port —
//! see [`resolve_with_cert_chain`]/[`call_with_cert_chain`]/
//! [`advertise_direct_with_cert_chain`]. Plain [`resolve`]/[`call`]/
//! [`advertise_direct`] are completely unaffected.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{ready, Future};
use std::time::Duration;

use tokio::time::Instant;

use crate::cbor::Value;
use crate::cert_chain::{self, CertChainError};
use crate::connection::{self, FrameStream, Session};
use crate::content;
use crate::dht::{self, DhtError, Record};
use crate::frame::{CallResponse, StreamMode};
use crate::identity::KeyPair;
use crate::manifest::Mcid;
use crate::open_sessions::{self, Leased, Leases};
use crate::stream::{self, StreamHandle};
use crate::transport::Trust;

fn now_ms() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i128
}

/// Matches `macula_direct_dial.erl`'s `?RESOLVE_RETRY_MS` — a record just
/// published on the provider's station has not necessarily replicated to
/// the resolving station yet, so the first miss is not treated as failure.
/// The endpoint lookup retries at this cadence within a candidate's share,
/// and re-queries start at it.
const RESOLVE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Re-queries back off from [`RESOLVE_RETRY_DELAY`], doubling up to this
/// cap, so a call waiting out a missing or refusing provider doesn't keep
/// loading the DHT.
const MAX_REQUERY_PAUSE: Duration = Duration::from_secs(1);

/// Every candidate gets at least this much of the remaining time for its
/// endpoint lookup and dial, or all of it when less than this remains.
const MIN_CANDIDATE_SHARE: Duration = Duration::from_secs(1);

/// The time budget [`resolve`] and [`resolve_with_cert_chain`] get, since
/// neither takes a timeout of its own. Matches `macula-go`'s
/// `DefaultResolveTimeout`.
const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ResolveError {
    /// Every `find_records` attempt came back empty after retrying past
    /// DHT propagation lag.
    ProcedureNotAdvertised,
    /// Records were found, but none had a valid signature.
    NoTrustedAdvertisement,
    /// A resolved station published no reachable (or no longer valid)
    /// `station_endpoint` after retrying.
    StationEndpointNotFound,
    /// A `station_endpoint` record was found under the right key, but its
    /// signer didn't match the station it's supposed to describe.
    StationEndpointSignerMismatch,
    /// The station's `station_endpoint` record verified but named no
    /// dialable address, and it was the latest answer before the deadline.
    /// Matches `macula_direct_dial`'s `malformed_station_endpoint`.
    MalformedStationEndpoint,
    Dht(DhtError),
    /// [`resolve_with_cert_chain`] only: at least one candidate
    /// advertisement's envelope signature verified (otherwise
    /// [`ResolveError::NoTrustedAdvertisement`] would apply instead), but
    /// none passed cert-chain authorization for the expected org — carries
    /// the specific [`CertChainError`] from the LAST candidate tried
    /// (absent chain, wrong org, untrusted chain, etc.).
    NoAuthorizedAdvertisement(CertChainError),
    /// The timeout ran out before any DHT lookup was answered or failed, or
    /// before any candidate could be tried.
    Timeout,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::ProcedureNotAdvertised => {
                write!(
                    f,
                    "direct_dial: procedure has no direct-dial advertisement in the DHT"
                )
            }
            ResolveError::NoTrustedAdvertisement => write!(
                f,
                "direct_dial: every candidate advertisement failed signature verification"
            ),
            ResolveError::StationEndpointNotFound => write!(
                f,
                "direct_dial: resolved station published no reachable station_endpoint"
            ),
            ResolveError::StationEndpointSignerMismatch => {
                write!(f, "direct_dial: station_endpoint signer mismatch")
            }
            ResolveError::MalformedStationEndpoint => write!(
                f,
                "direct_dial: the station_endpoint record names no dialable address"
            ),
            ResolveError::Dht(e) => write!(f, "direct_dial: {e}"),
            ResolveError::NoAuthorizedAdvertisement(e) => write!(
                f,
                "direct_dial: no candidate advertisement is cert-chain-authorized for the expected org: {e}"
            ),
            ResolveError::Timeout => write!(
                f,
                "direct_dial: the timeout ran out before a provider was resolved"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// One resolved direct-dial target: the station's own node id plus a
/// dialable host/port.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub station: [u8; 32],
    pub host: String,
    pub port: u16,
}

/// The two DHT lookups direct-dial resolution makes, behind a trait so the
/// resolution logic runs unchanged against a fake DHT in tests.
pub(crate) trait DhtLookups {
    async fn find_records(&mut self, key: [u8; 32]) -> Result<Vec<Record>, DhtError>;
    async fn find_record(&mut self, key: [u8; 32]) -> Result<Record, DhtError>;
}

/// The real lookups: DHT queries over `session`.
struct Via<'a> {
    session: &'a Session,
    id: &'a KeyPair,
}

impl DhtLookups for Via<'_> {
    async fn find_records(&mut self, key: [u8; 32]) -> Result<Vec<Record>, DhtError> {
        dht::find_records(self.session, self.id, key).await
    }

    async fn find_record(&mut self, key: [u8; 32]) -> Result<Record, DhtError> {
        dht::find_record(self.session, self.id, key).await
    }
}

/// The realm CA and org an advertisement's cert chain must satisfy, on the
/// `*_with_cert_chain` paths.
#[derive(Clone, Copy)]
pub(crate) struct CertChainCheck<'a> {
    pub(crate) realm_ca_pem: &'a [u8],
    pub(crate) expected_org: &'a str,
}

/// Why a resolving call failed: resolution itself, the dial of the last
/// candidate tried, or the request once it was sent. Each public function
/// maps this to its own error type.
#[derive(Debug)]
pub(crate) enum Failure<DE, RE> {
    Resolve(ResolveError),
    Dial(DE),
    Request(RE),
}

/// Why a direct content fetch failed; mapped to [`GetDirectError`].
#[derive(Debug)]
pub(crate) enum ContentFailure<DE, RE> {
    Dht(DhtError),
    NotAnnounced,
    EndpointParse(String),
    Dial(DE),
    Fetch(RE),
    /// The deadline cut a transfer off; carries the failure before it.
    Timeout(Option<Box<ContentFailure<DE, RE>>>),
}

/// One call's time budget. It covers resolution, every endpoint lookup,
/// every dial and the request itself.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallDeadline {
    at: Instant,
}

impl CallDeadline {
    pub(crate) fn after(budget: Duration) -> Self {
        Self {
            at: Instant::now() + budget,
        }
    }

    /// Less than a millisecond left counts as none, so a pause at the
    /// deadline edge never shrinks to a zero-length sleep that lets the
    /// re-query loop spin.
    pub(crate) fn remaining(&self) -> Duration {
        let left = self.at.saturating_duration_since(Instant::now());
        if left >= Duration::from_millis(1) {
            left
        } else {
            Duration::ZERO
        }
    }

    pub(crate) fn passed(&self) -> bool {
        self.remaining().is_zero()
    }

    /// The next candidate's share of what remains, for its endpoint lookup
    /// and dial: an even split across the candidates not yet tried, but
    /// never less than [`MIN_CANDIDATE_SHARE`] unless less than that
    /// remains.
    pub(crate) fn share_for(&self, untried: usize) -> CallDeadline {
        let remaining = self.remaining();
        let even = remaining / u32::try_from(untried.max(1)).unwrap_or(u32::MAX);
        CallDeadline::after(even.max(remaining.min(MIN_CANDIDATE_SHARE)))
    }
}

/// A qualified advertisement: its signer and record version identify the
/// candidate, and `station` serves it.
struct ProcedureCandidate {
    signer: [u8; 32],
    version: [u8; 16],
    station: [u8; 32],
}

/// A qualified content announcement: its announcer and record version
/// identify the candidate, and `endpoint` is where to dial it.
struct ContentCandidate {
    announcer: [u8; 32],
    version: [u8; 16],
    endpoint: String,
}

/// A candidate that failed before sending, within one call: the version of
/// the record that made it a candidate, the endpoint record version it
/// failed on (`None` when none was found), and the error.
struct Remembered<F> {
    record_version: [u8; 16],
    endpoint_version: Option<[u8; 16]>,
    error: F,
}

/// The failure a call reports at its deadline, the first of: the remembered
/// failure of the last candidate tried, why the latest answered query found
/// no candidate, and the latest failed query's error. With none of them the
/// call reports a timeout.
enum Last<F> {
    Candidate([u8; 32]),
    NoneQualified(F),
    LookupFailed(F),
}

fn take_last<F>(
    last: Option<Last<F>>,
    failures: &mut HashMap<[u8; 32], Remembered<F>>,
) -> Option<F> {
    match last? {
        Last::Candidate(key) => failures.remove(&key).map(|remembered| remembered.error),
        Last::NoneQualified(failure) | Last::LookupFailed(failure) => Some(failure),
    }
}

/// Records why an answered query found no candidate: over a failed query's
/// error, never over a candidate's failure.
fn record_none_qualified<F>(last: &mut Option<Last<F>>, reason: F) {
    if !matches!(last, Some(Last::Candidate(_))) {
        *last = Some(Last::NoneQualified(reason));
    }
}

/// Records a failed query's error, only while no candidate has failed and no
/// query was answered.
fn record_lookup_failure<F>(last: &mut Option<Last<F>>, error: F) {
    if matches!(last, None | Some(Last::LookupFailed(_))) {
        *last = Some(Last::LookupFailed(error));
    }
}

/// What one DHT query came to.
enum Lookup {
    Answered(Vec<Record>),
    Failed(DhtError),
    /// Cut off by the deadline: it learned nothing.
    CutOff,
}

async fn query<D: DhtLookups>(dht: &mut D, key: [u8; 32], deadline: CallDeadline) -> Lookup {
    match tokio::time::timeout(deadline.remaining(), dht.find_records(key)).await {
        Ok(Ok(recs)) => Lookup::Answered(recs),
        Ok(Err(e)) => Lookup::Failed(e),
        Err(_) => Lookup::CutOff,
    }
}

/// Resolves `procedure`'s provider, dials it with `dial`, and sends it one
/// request with `request`, all within `timeout` — see the module doc's
/// "Candidates" for how providers are tried in turn.
///
/// A candidate whose station `already_open` has a session for gets the
/// request on that session, with no endpoint lookup and no dial.
///
/// `dial` and `request` are plain closures returning futures (not async
/// closures) so the public functions built on this keep `Send` futures.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reach_procedure<D, S, T, DE, RE, DF, RF>(
    dht: &mut D,
    realm: [u8; 32],
    procedure: &str,
    cert_chain: Option<CertChainCheck<'_>>,
    mut already_open: impl FnMut(&[u8; 32]) -> Option<S>,
    mut dial: impl FnMut(Resolved, Duration) -> DF,
    request: impl FnOnce(S, Duration) -> RF,
    timeout: Duration,
) -> Result<T, Failure<DE, RE>>
where
    D: DhtLookups,
    DF: Future<Output = Result<S, DE>>,
    RF: Future<Output = Result<T, RE>>,
{
    let deadline = CallDeadline::after(timeout);
    let key = dht::procedure_key(&dht::discovery_uri(realm, procedure));
    let mut request = Some(request);
    let mut failures: HashMap<[u8; 32], Remembered<Failure<DE, RE>>> = HashMap::new();
    let mut last: Option<Last<Failure<DE, RE>>> = None;
    let mut pause = RESOLVE_RETRY_DELAY;
    loop {
        let candidates = match query(dht, key, deadline).await {
            Lookup::Answered(recs) => {
                let (candidates, unresolved) = if recs.is_empty() {
                    (Vec::new(), ResolveError::ProcedureNotAdvertised)
                } else if let Some(check) = cert_chain {
                    authorized_advertisements(&recs, check)
                } else {
                    trusted_advertisements(&recs)
                };
                if candidates.is_empty() {
                    record_none_qualified(&mut last, Failure::Resolve(unresolved));
                }
                candidates
            }
            // A failed query teaches nothing, and is retried like one that
            // found no candidate.
            Lookup::Failed(e) => {
                record_lookup_failure(&mut last, Failure::Resolve(ResolveError::Dht(e)));
                Vec::new()
            }
            Lookup::CutOff => Vec::new(),
        };
        for (tried, candidate) in candidates.iter().enumerate() {
            if deadline.passed() {
                break;
            }
            if let Some(target) = reused(&mut already_open, &candidate.station) {
                let request = request
                    .take()
                    .expect("the request is sent at most once, and sending it ends the call");
                return request(target, deadline.remaining())
                    .await
                    .map_err(Failure::Request);
            }
            let share = deadline.share_for(candidates.len() - tried);
            // An unchanged advertisement that already failed gets a single
            // endpoint lookup, and its station is dialed again only if that
            // lookup shows a different endpoint version. A lookup that got
            // no answer teaches nothing.
            let failed_on = failures
                .get(&candidate.signer)
                .filter(|remembered| remembered.record_version == candidate.version)
                .map(|remembered| remembered.endpoint_version);
            let lookup =
                lookup_station_endpoint(dht, candidate.station, share, failed_on.is_none()).await;
            if failed_on
                .is_some_and(|failed_on| !lookup.answered || lookup.seen_version == failed_on)
            {
                last = Some(Last::Candidate(candidate.signer));
                continue;
            }
            let failure = match lookup.outcome {
                Ok(resolved) => match dial(resolved, share.remaining()).await {
                    Ok(target) => {
                        let request = request.take().expect(
                            "the request is sent at most once, and sending it ends the call",
                        );
                        return request(target, deadline.remaining())
                            .await
                            .map_err(Failure::Request);
                    }
                    Err(e) => Failure::Dial(e),
                },
                Err(e) => Failure::Resolve(e),
            };
            failures.insert(
                candidate.signer,
                Remembered {
                    record_version: candidate.version,
                    endpoint_version: lookup.seen_version,
                    error: failure,
                },
            );
            last = Some(Last::Candidate(candidate.signer));
        }
        if deadline.passed() {
            break;
        }
        tokio::time::sleep(pause.min(deadline.remaining())).await;
        pause = (pause * 2).min(MAX_REQUERY_PAUSE);
        if deadline.passed() {
            break;
        }
    }
    // With nothing observed at all, the deadline ran out before any query
    // was answered or any candidate could be tried.
    Err(take_last(last, &mut failures).unwrap_or(Failure::Resolve(ResolveError::Timeout)))
}

/// Resolves a known station's endpoint, dials it with `dial`, and sends it
/// one request with `request`. `timeout` bounds the endpoint lookup and the
/// dial; the request gets whatever remains and may ignore it. When
/// `already_open` has a session for the station, the request runs on it
/// instead, with no endpoint lookup and no dial.
pub(crate) async fn reach_station<D, S, T, DE, RE, DF, RF>(
    dht: &mut D,
    station: [u8; 32],
    already_open: impl FnOnce(&[u8; 32]) -> Option<S>,
    dial: impl FnOnce(Resolved, Duration) -> DF,
    request: impl FnOnce(S, Duration) -> RF,
    timeout: Duration,
) -> Result<T, Failure<DE, RE>>
where
    D: DhtLookups,
    DF: Future<Output = Result<S, DE>>,
    RF: Future<Output = Result<T, RE>>,
{
    let deadline = CallDeadline::after(timeout);
    if let Some(target) = reused(already_open, &station) {
        return request(target, deadline.remaining())
            .await
            .map_err(Failure::Request);
    }
    let resolved = lookup_station_endpoint(dht, station, deadline, true)
        .await
        .outcome
        .map_err(Failure::Resolve)?;
    let target = dial(resolved, deadline.remaining())
        .await
        .map_err(Failure::Dial)?;
    request(target, deadline.remaining())
        .await
        .map_err(Failure::Request)
}

/// Finds `mcid`'s announced providers and fetches the content from the
/// first one that serves it, dialing each with `dial` and fetching with
/// `fetch`, all within `timeout`. Any failure moves on to the next
/// provider, since a fetch is verified against its MCID and safe to repeat
/// elsewhere; a provider that failed is skipped on later passes unless its
/// announcement changed. A provider whose station `already_open` has a
/// session for is fetched from on that session, with no dial.
pub(crate) async fn fetch_content<D, S, T, DE, RE, DF, FF>(
    dht: &mut D,
    mcid: Mcid,
    mut already_open: impl FnMut(&[u8; 32]) -> Option<S>,
    mut dial: impl FnMut(Resolved, Duration) -> DF,
    mut fetch: impl FnMut(S, Duration) -> FF,
    timeout: Duration,
) -> Result<T, ContentFailure<DE, RE>>
where
    D: DhtLookups,
    DF: Future<Output = Result<S, DE>>,
    FF: Future<Output = Result<T, RE>>,
{
    let deadline = CallDeadline::after(timeout);
    let key = dht::content_key(mcid);
    let mut failures: HashMap<[u8; 32], Remembered<ContentFailure<DE, RE>>> = HashMap::new();
    let mut last: Option<Last<ContentFailure<DE, RE>>> = None;
    let mut pause = RESOLVE_RETRY_DELAY;
    loop {
        let providers = match query(dht, key, deadline).await {
            Lookup::Answered(recs) => {
                let providers = trusted_content_providers(&recs);
                if providers.is_empty() {
                    record_none_qualified(&mut last, ContentFailure::NotAnnounced);
                }
                providers
            }
            // A failed query teaches nothing, and is retried like one that
            // found no provider.
            Lookup::Failed(e) => {
                record_lookup_failure(&mut last, ContentFailure::Dht(e));
                Vec::new()
            }
            Lookup::CutOff => Vec::new(),
        };
        for (tried, provider) in providers.iter().enumerate() {
            if deadline.passed() {
                break;
            }
            let share = deadline.share_for(providers.len() - tried);
            let already_failed = failures
                .get(&provider.announcer)
                .is_some_and(|remembered| remembered.record_version == provider.version);
            if !already_failed {
                let failure =
                    match reach_provider(provider, &mut already_open, &mut dial, share).await {
                        Err(failure) => failure,
                        Ok(target) => match tokio::time::timeout(
                            deadline.remaining(),
                            fetch(target, deadline.remaining()),
                        )
                        .await
                        {
                            Ok(Ok(content)) => return Ok(content),
                            Ok(Err(e)) => ContentFailure::Fetch(e),
                            Err(_) => {
                                return Err(ContentFailure::Timeout(
                                    take_last(last, &mut failures).map(Box::new),
                                ))
                            }
                        },
                    };
                failures.insert(
                    provider.announcer,
                    Remembered {
                        record_version: provider.version,
                        endpoint_version: None,
                        error: failure,
                    },
                );
            }
            last = Some(Last::Candidate(provider.announcer));
        }
        if deadline.passed() {
            break;
        }
        tokio::time::sleep(pause.min(deadline.remaining())).await;
        pause = (pause * 2).min(MAX_REQUERY_PAUSE);
        if deadline.passed() {
            break;
        }
    }
    // With nothing observed at all, the deadline ran out before any query
    // was answered or any provider could be tried.
    Err(take_last(last, &mut failures).unwrap_or(ContentFailure::Timeout(None)))
}

/// Reaches one content provider: on the session `already_open` has for its
/// station when there is one, otherwise by dialing its announced endpoint
/// within `share`.
async fn reach_provider<S, DE, RE, DF>(
    provider: &ContentCandidate,
    already_open: impl FnOnce(&[u8; 32]) -> Option<S>,
    dial: impl FnOnce(Resolved, Duration) -> DF,
    share: CallDeadline,
) -> Result<S, ContentFailure<DE, RE>>
where
    DF: Future<Output = Result<S, DE>>,
{
    if let Some(target) = reused(already_open, &provider.announcer) {
        return Ok(target);
    }
    let (host, port) = parse_seed_url(&provider.endpoint)
        .ok_or_else(|| ContentFailure::EndpointParse(provider.endpoint.clone()))?;
    let resolved = Resolved {
        station: provider.announcer,
        host,
        port,
    };
    dial(resolved, share.remaining())
        .await
        .map_err(ContentFailure::Dial)
}

/// The session already open to `station` that a request runs on instead of
/// dialing, if any.
fn reused<S>(already_open: impl FnOnce(&[u8; 32]) -> Option<S>, station: &[u8; 32]) -> Option<S> {
    already_open(station)
}

/// No session to reuse: a call, and resolution alone, always dial.
fn no_open_session<S>(_station: &[u8; 32]) -> Option<S> {
    None
}

/// Resolution alone: the "dial" and the "request" hand the resolved
/// endpoint straight back.
pub(crate) async fn resolve_within<D: DhtLookups>(
    dht: &mut D,
    realm: [u8; 32],
    procedure: &str,
    cert_chain: Option<CertChainCheck<'_>>,
    timeout: Duration,
) -> Result<Resolved, ResolveError> {
    reach_procedure(
        dht,
        realm,
        procedure,
        cert_chain,
        no_open_session::<Resolved>,
        |resolved: Resolved, _share: Duration| ready(Ok::<_, Infallible>(resolved)),
        |resolved: Resolved, _remaining: Duration| ready(Ok::<_, Infallible>(resolved)),
        timeout,
    )
    .await
    .map_err(|failure| match failure {
        Failure::Resolve(e) => e,
        Failure::Dial(never) | Failure::Request(never) => match never {},
    })
}

/// Finds `procedure`'s currently-advertised serving station and its
/// dialable host/port, retrying past DHT propagation lag for up to 10
/// seconds. `realm` and `procedure` must match exactly what the provider
/// passed to [`advertise_direct`] (or the Erlang equivalent) — the
/// discovery URI they derive must agree. `session` is used only to query
/// the DHT; it does not need to be connected to the same station that will
/// end up serving the call. The first candidate whose station endpoint
/// resolves is returned.
pub async fn resolve(
    session: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
) -> Result<Resolved, ResolveError> {
    resolve_within(
        &mut Via { session, id },
        realm,
        procedure,
        None,
        DEFAULT_RESOLVE_TIMEOUT,
    )
    .await
}

/// Every advertisement whose signature and expiry verify and whose payload
/// parses, in DHT order, and the error to report if none does.
fn trusted_advertisements(recs: &[Record]) -> (Vec<ProcedureCandidate>, ResolveError) {
    let candidates = recs
        .iter()
        .filter_map(|rec| {
            dht::verify(rec).ok()?;
            let adv = dht::read_procedure_advertisement(rec).ok()?;
            Some(ProcedureCandidate {
                signer: rec.key,
                version: rec.version,
                station: adv.serving_station,
            })
        })
        .collect();
    (candidates, ResolveError::NoTrustedAdvertisement)
}

/// [`resolve`] plus Slice 7c Direction B managed-realm authorization: only
/// an advertisement whose embedded cert chain validates to `realm_ca_pem`
/// and names `expected_org` is trusted. Opt-in — [`resolve`] itself is
/// unaffected and remains the right choice for unmanaged realms.
pub async fn resolve_with_cert_chain(
    session: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
) -> Result<Resolved, ResolveError> {
    resolve_within(
        &mut Via { session, id },
        realm,
        procedure,
        Some(CertChainCheck {
            realm_ca_pem,
            expected_org,
        }),
        DEFAULT_RESOLVE_TIMEOUT,
    )
    .await
}

/// [`trusted_advertisements`] plus the cert-chain check. Matches Go's
/// `firstAuthorizedAdvertisement`: if every candidate fails even the plain
/// envelope-signature check, report [`ResolveError::NoTrustedAdvertisement`]
/// (same as the plain path); only report
/// [`ResolveError::NoAuthorizedAdvertisement`] once at least one candidate's
/// signature verified but none passed cert-chain authorization.
fn authorized_advertisements(
    recs: &[Record],
    check: CertChainCheck<'_>,
) -> (Vec<ProcedureCandidate>, ResolveError) {
    let mut candidates = Vec::new();
    let mut last_cert_err: Option<CertChainError> = None;
    for rec in recs {
        if dht::verify(rec).is_err() {
            continue;
        }
        match cert_chain::verify_advertisement_cert_chain(
            check.realm_ca_pem,
            rec,
            check.expected_org,
        ) {
            Ok(()) => {
                if let Ok(adv) = dht::read_procedure_advertisement(rec) {
                    candidates.push(ProcedureCandidate {
                        signer: rec.key,
                        version: rec.version,
                        station: adv.serving_station,
                    });
                }
            }
            Err(e) => last_cert_err = Some(e),
        }
    }
    let unresolved = match last_cert_err {
        Some(e) => ResolveError::NoAuthorizedAdvertisement(e),
        None => ResolveError::NoTrustedAdvertisement,
    };
    (candidates, unresolved)
}

/// One `station_endpoint` lookup within a budget: the resolved endpoint or
/// why it failed, the version of the last record the DHT returned, and
/// whether the DHT answered at all (a record or not_found) rather than
/// failing or being cut off.
struct EndpointLookup {
    outcome: Result<Resolved, ResolveError>,
    seen_version: Option<[u8; 16]>,
    answered: bool,
}

/// What the latest answered `station_endpoint` lookup found instead of a
/// usable record.
#[derive(Clone, Copy)]
enum Answered {
    NotFound,
    Malformed,
}

/// With `retry_within_budget`, a lookup that found no usable record (absent,
/// expired, or naming no dialable address) or that failed is looked up again
/// every [`RESOLVE_RETRY_DELAY`] until `budget` runs out — the DHT can hand
/// back a replica that hasn't been evicted yet even though the station's own
/// current publish is live. A record that doesn't verify ends the lookup.
/// When no usable record turns up, the lookup reports what it observed, as
/// `macula_direct_dial`'s `endpoint_recorded/3` does: the latest answered
/// lookup (not found, or the malformed record), else the latest failed
/// lookup's error, else a timeout.
async fn lookup_station_endpoint<D: DhtLookups>(
    dht: &mut D,
    station: [u8; 32],
    budget: CallDeadline,
    retry_within_budget: bool,
) -> EndpointLookup {
    let key = dht::station_endpoint_key(station);
    let mut seen_version = None;
    let mut answered = None;
    let mut failed = None;
    loop {
        match tokio::time::timeout(budget.remaining(), dht.find_record(key)).await {
            Ok(Ok(rec)) => {
                seen_version = Some(rec.version);
                // The station_endpoint record for `station` must be SIGNED BY
                // `station` itself — checking the signature and that the
                // signer is exactly `station`, not just any valid signature,
                // is what makes pinning the dial's expected identity
                // meaningful.
                if rec.key != station {
                    return EndpointLookup {
                        outcome: Err(ResolveError::StationEndpointSignerMismatch),
                        seen_version,
                        answered: true,
                    };
                }
                match dht::verify(&rec) {
                    Ok(()) => match read_endpoint(station, &rec) {
                        Some(resolved) => {
                            return EndpointLookup {
                                outcome: Ok(resolved),
                                seen_version,
                                answered: true,
                            }
                        }
                        None => answered = Some(Answered::Malformed),
                    },
                    Err(dht::VerifyError::Expired) => answered = Some(Answered::NotFound),
                    Err(_) => {
                        return EndpointLookup {
                            outcome: Err(ResolveError::NoTrustedAdvertisement),
                            seen_version,
                            answered: true,
                        }
                    }
                }
            }
            Ok(Err(DhtError::NotFound)) => answered = Some(Answered::NotFound),
            // A failed lookup teaches nothing: looked up again like an absent
            // record.
            Ok(Err(e)) => failed = Some(e),
            // Cut off by the budget: nothing learned.
            Err(_) => {}
        }
        if !retry_within_budget || budget.passed() {
            let unresolved = match (answered, failed) {
                (Some(Answered::NotFound), _) => ResolveError::StationEndpointNotFound,
                (Some(Answered::Malformed), _) => ResolveError::MalformedStationEndpoint,
                (None, Some(e)) => ResolveError::Dht(e),
                (None, None) => ResolveError::Timeout,
            };
            return EndpointLookup {
                outcome: Err(unresolved),
                seen_version,
                answered: answered.is_some(),
            };
        }
        tokio::time::sleep(RESOLVE_RETRY_DELAY.min(budget.remaining())).await;
    }
}

/// The dialable address a verified `station_endpoint` record names, or
/// `None` when it names none.
fn read_endpoint(station: [u8; 32], rec: &Record) -> Option<Resolved> {
    let ep = dht::read_station_endpoint(rec).ok()?;
    let host = ep.host_advertised.into_iter().next()?;
    Some(Resolved {
        station,
        host,
        port: ep.quic_port,
    })
}

#[derive(Debug)]
pub enum CallError {
    Resolve(ResolveError),
    Dial(connection::HandshakeError),
    /// The dialed peer's own signature-verified HELLO identity didn't
    /// match the pubkey the signed DHT chain resolved — a trust violation,
    /// not a retryable error.
    TrustViolation {
        resolved: [u8; 32],
        dialed: [u8; 32],
    },
    Call(connection::CallError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Resolve(e) => write!(f, "{e}"),
            CallError::Dial(e) => write!(f, "direct_dial: dialing resolved station: {e}"),
            CallError::TrustViolation { resolved, dialed } => write!(
                f,
                "direct_dial: trust violation -- resolved station {} but the dialed peer proved identity {}",
                hex_of(resolved),
                hex_of(dialed)
            ),
            CallError::Call(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

fn hex_of(b: &[u8; 32]) -> String {
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn call_failure(failure: Failure<DialAndVerifyError, connection::CallError>) -> CallError {
    match failure {
        Failure::Resolve(e) => CallError::Resolve(e),
        Failure::Dial(DialAndVerifyError::Dial(e)) => CallError::Dial(e),
        Failure::Dial(DialAndVerifyError::TrustViolation { resolved, dialed }) => {
            CallError::TrustViolation { resolved, dialed }
        }
        Failure::Request(e) => CallError::Call(e),
    }
}

/// The live dial every direct-dial shape uses: [`dial_and_verify`] against
/// a resolved endpoint within `timeout`.
async fn dial_verified(
    resolved: Resolved,
    id: &KeyPair,
    timeout: Duration,
) -> Result<Session, DialAndVerifyError> {
    dial_and_verify(&resolved.host, resolved.port, resolved.station, id, timeout).await
}

/// Sends one CALL on the target with whatever remains of the deadline, then
/// gives back the target's lease, closing a dialed session when no other
/// direct-dial request still uses it.
async fn call_then_release(
    target: StationTarget,
    remaining: Duration,
    id: &KeyPair,
    procedure: &str,
    realm: [u8; 32],
    payload: Value,
    ucan_token: Option<Vec<u8>>,
) -> Result<CallResponse, connection::CallError> {
    let deadline_ms = now_ms() + remaining.as_millis() as i128;
    let (result, last) = run_then_release(target, move |session: Session| async move {
        match ucan_token {
            None => {
                session
                    .call(procedure, realm, payload, deadline_ms, id, remaining)
                    .await
            }
            Some(token) => {
                session
                    .call_with_ucan(procedure, realm, payload, deadline_ms, id, remaining, token)
                    .await
            }
        }
    })
    .await;
    close_last(last, id).await;
    result
}

/// Resolves `procedure`'s provider via direct-dial (through `resolve_via`,
/// used only to query the DHT) and calls it there, in one hop, in a
/// SEPARATE connection from `resolve_via`. The provider must have
/// advertised via [`advertise_direct`] (or the Erlang
/// `macula_response:advertise_direct/6,7`) — a plain `advertise` publishes
/// no discoverable record and the call returns
/// [`ResolveError::ProcedureNotAdvertised`].
///
/// `timeout` bounds the whole call: finding the provider, each candidate's
/// endpoint lookup and dial, and the CALL itself. See the module doc's
/// "Candidates" for how providers are tried in turn.
///
/// A call always dials its own connection, even when this process already
/// has a session open to the provider's station under `id`; the station
/// then closes that session.
///
/// The dial itself uses [`Trust::Insecure`] (no TLS verification) because
/// trust is enforced at the application layer instead — see the module
/// doc's "Trust model". After the dial, the freshly connected session's own
/// signature-verified HELLO identity is checked against the exact pubkey
/// the signed DHT chain resolved; a mismatch is
/// [`CallError::TrustViolation`], and that candidate is skipped.
pub async fn call(
    resolve_via: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    payload: Value,
    timeout: Duration,
) -> Result<CallResponse, CallError> {
    reach_procedure(
        &mut Via {
            session: resolve_via,
            id,
        },
        realm,
        procedure,
        None,
        no_open_session::<StationTarget>,
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, remaining: Duration| {
            call_then_release(target, remaining, id, procedure, realm, payload, None)
        },
        timeout,
    )
    .await
    .map_err(call_failure)
}

/// [`call`], presenting `ucan_token` to a provider gated with
/// `{ucan_required, Issuer}`. Every hecate-om capability is advertised via
/// [`advertise_direct`], so this is the only way a UCAN-gated capability
/// is reachable through this crate at all -- [`call`] itself has no token
/// parameter, and [`Session::call_with_ucan`] is the plain, non-direct
/// path, which cannot resolve a direct-dial-only advertisement to begin
/// with.
pub async fn call_with_ucan(
    resolve_via: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    payload: Value,
    timeout: Duration,
    ucan_token: Vec<u8>,
) -> Result<CallResponse, CallError> {
    reach_procedure(
        &mut Via {
            session: resolve_via,
            id,
        },
        realm,
        procedure,
        None,
        no_open_session::<StationTarget>,
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, remaining: Duration| {
            call_then_release(
                target,
                remaining,
                id,
                procedure,
                realm,
                payload,
                Some(ucan_token),
            )
        },
        timeout,
    )
    .await
    .map_err(call_failure)
}

/// [`call`], resolved via [`resolve_with_cert_chain`] instead of
/// [`resolve`] — see both for the full contract. Opt-in managed-realm
/// authorization; [`call`] itself is unaffected.
#[allow(clippy::too_many_arguments)]
pub async fn call_with_cert_chain(
    resolve_via: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
    payload: Value,
    timeout: Duration,
) -> Result<CallResponse, CallError> {
    reach_procedure(
        &mut Via {
            session: resolve_via,
            id,
        },
        realm,
        procedure,
        Some(CertChainCheck {
            realm_ca_pem,
            expected_org,
        }),
        no_open_session::<StationTarget>,
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, remaining: Duration| {
            call_then_release(target, remaining, id, procedure, realm, payload, None)
        },
        timeout,
    )
    .await
    .map_err(call_failure)
}

/// Publishes a signed `procedure_advertisement` naming `session`'s own
/// currently-connected station (`session.station.node_id`) as `procedure`'s
/// server, discoverable by any caller's [`resolve`]/[`call`]. Mirrors
/// `macula_response:advertise_direct/6,7` +
/// `macula_direct_dial:publish_advertisement/4,5` — unlike the Erlang
/// reference's pool (many links, one chosen by `connected_station/1`), a
/// [`Session`] is always exactly one connection, so there is no
/// link-selection step: the session's own verified HELLO identity IS the
/// serving station.
///
/// **Sends the ordinary ADVERTISE frame first, then publishes the DHT
/// record** — matching `macula_response:advertise_direct/7`'s own body
/// exactly (`case advertise(Pool, Realm, Procedure, Module, Args, Opts) of
/// {ok, Sup} -> ... macula_direct_dial:publish_advertisement(...)`). The
/// DHT record is an ADDITIONAL discovery path for a caller on a different
/// station to skip inter-station gossip propagation — it is not a
/// substitute for the station actually knowing to route inbound CALLs
/// here. **Found live, 2026-08-30**: an earlier version of this function
/// (and its `macula-go` port, same gap, not yet fixed there as of this
/// writing) published only the DHT record — a direct-dial caller could
/// resolve and dial the right station, but the station itself had never
/// been told to route the call anywhere, so every call still failed with
/// `unknown_next_peer` despite a perfectly valid, resolvable, trusted
/// advertisement. Caught by a live test that, unlike the earlier
/// direct-dial verification, actually tried to get a real RESULT back
/// instead of accepting `unknown_next_peer` as the expected terminal state.
///
/// Unlike the Erlang SDK's supervised `macula_response`, this does not
/// itself keep anything alive — it does not spawn a responder process, so
/// a caller still needs its own [`Session::serve_one_call`](crate::connection::Session::serve_one_call)
/// loop to actually answer what gets routed here. A station's registration
/// for a procedure does not survive the connection that sent it being
/// replaced, so a long-lived server needs to call this again on its own
/// schedule; see [`keep_advertised_direct`] for that loop.
pub async fn advertise_direct(
    session: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
) -> Result<(), AdvertiseDirectError> {
    let advertise_spec = crate::frame::AdvertiseSpec::new(realm, procedure, id.node_id());
    session
        .advertise(&advertise_spec, id)
        .await
        .map_err(AdvertiseDirectError::Advertise)?;

    let uri = dht::discovery_uri(realm, procedure);
    let rec = dht::new_procedure_advertisement(id.node_id(), uri, session.station.node_id, ttl);
    let rec = dht::sign(rec, id);
    dht::put_record(session, id, &rec)
        .await
        .map_err(AdvertiseDirectError::Dht)
}

/// [`advertise_direct`] plus an embedded X.509 service-cert chain, for
/// Slice 7c Direction B managed-realm authorization — see
/// [`resolve_with_cert_chain`]/[`call_with_cert_chain`] for the
/// corresponding checks. Opt-in: plain [`advertise_direct`] is unaffected.
pub async fn advertise_direct_with_cert_chain(
    session: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
    cert_chain_pem: Vec<u8>,
) -> Result<(), AdvertiseDirectError> {
    let advertise_spec = crate::frame::AdvertiseSpec::new(realm, procedure, id.node_id());
    session
        .advertise(&advertise_spec, id)
        .await
        .map_err(AdvertiseDirectError::Advertise)?;

    let uri = dht::discovery_uri(realm, procedure);
    let rec = dht::new_procedure_advertisement_with_cert_chain(
        id.node_id(),
        uri,
        session.station.node_id,
        ttl,
        cert_chain_pem,
    );
    let rec = dht::sign(rec, id);
    dht::put_record(session, id, &rec)
        .await
        .map_err(AdvertiseDirectError::Dht)
}

#[derive(Debug)]
pub enum AdvertiseDirectError {
    /// The ordinary station-side ADVERTISE frame failed to send.
    Advertise(connection::SendError),
    /// The ordinary ADVERTISE succeeded, but publishing the direct-dial
    /// DHT record failed — the procedure IS now reachable via ordinary
    /// advertise-gossip, just not via direct-dial resolution.
    Dht(DhtError),
}

impl std::fmt::Display for AdvertiseDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvertiseDirectError::Advertise(e) => write!(f, "direct_dial: sending ADVERTISE: {e}"),
            AdvertiseDirectError::Dht(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for AdvertiseDirectError {}

/// Calls [`advertise_direct`] immediately, then again every `interval`,
/// until `stop` resolves. Rust has nothing equivalent to
/// `macula_response`'s `reuse_sup` to worry about here, because
/// [`advertise_direct`] (unlike Erlang's `advertise/5`, which spawns a real
/// per-call OTP supervisor) is already a stateless, side-effect-free-on-
/// repeat async function: nothing is created per tick that could leak —
/// same reasoning `macula-go`'s `KeepAdvertisedDirect` already applied
/// and verified live.
///
/// `interval` should leave real margin before `ttl` expires — production
/// practice in `hecate-om`'s own capability re-advertise loop (the actual
/// consumer of `advertise_direct`'s `reuse_sup` option on the Erlang side)
/// uses a 4x margin: a 30s republish interval against a 120s record TTL.
///
/// A failed tick (network blip, connection genuinely dead, etc.) is
/// reported via `on_error` but does NOT stop the loop; it tries again at
/// the next interval regardless, matching `hecate-om`'s own log-and-continue
/// practice around every DHT publish. This loop cannot detect or repair a
/// dead `session` on its own — if its underlying connection has actually
/// gone down, every tick will keep failing the same way until `stop`
/// resolves; reconnecting a dead session is a separate, larger concern this
/// does not attempt to solve.
///
/// 8 parameters: a target (`session`/`realm`/`procedure`), a re-advertise
/// schedule (`id`/`ttl`/`interval`), and two independent callbacks
/// (`stop`/`on_error`) with no natural sub-grouping — folding any of them
/// into a synthetic struct would relocate the count, not reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn keep_advertised_direct<F>(
    session: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
    interval: Duration,
    stop: F,
    on_error: impl Fn(AdvertiseDirectError),
) where
    F: Future<Output = ()>,
{
    tokio::pin!(stop);
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = &mut stop => return,
            _ = ticker.tick() => {
                if let Err(e) = advertise_direct(session, id, realm, procedure, ttl).await {
                    on_error(e);
                }
            }
        }
    }
}

/// The dial-then-pin sequence every direct-dial call shape needs after
/// resolving: dial `resolved`'s host:port, then check the freshly
/// connected session's own signature-verified HELLO identity against
/// `resolved.station` — factored out here because [`call`]/
/// [`open_stream_direct`]/[`put_direct`]/[`get_direct`] all need the
/// identical sequence against a station identity that isn't necessarily
/// reached via [`resolve`].
#[derive(Debug)]
pub enum DialAndVerifyError {
    Dial(connection::HandshakeError),
    /// The dialed peer's own signature-verified HELLO identity didn't
    /// match the pubkey the signed DHT chain resolved — a trust
    /// violation, not a retryable error.
    TrustViolation {
        resolved: [u8; 32],
        dialed: [u8; 32],
    },
}

impl std::fmt::Display for DialAndVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialAndVerifyError::Dial(e) => write!(f, "direct_dial: dialing resolved station: {e}"),
            DialAndVerifyError::TrustViolation { resolved, dialed } => write!(
                f,
                "direct_dial: trust violation -- resolved station {} but the dialed peer proved identity {}",
                hex_of(resolved),
                hex_of(dialed)
            ),
        }
    }
}

impl std::error::Error for DialAndVerifyError {}

async fn dial_and_verify(
    host: &str,
    port: u16,
    station: [u8; 32],
    id: &KeyPair,
    timeout: Duration,
) -> Result<Session, DialAndVerifyError> {
    let target = tokio::time::timeout(
        timeout,
        connection::connect_leased(host, port, Trust::Insecure, id),
    )
    .await
    .unwrap_or(Err(connection::HandshakeError::Timeout))
    .map_err(DialAndVerifyError::Dial)?;

    if target.station.node_id != station {
        let dialed = target.station.node_id;
        target.close("trust_violation", None, id).await;
        return Err(DialAndVerifyError::TrustViolation {
            resolved: station,
            dialed,
        });
    }
    Ok(target)
}

/// The session a request runs on, and whether the request holds a lease on
/// it. A session direct dial dialed comes with the request's lease; a
/// session this process already had open under its owner, such as
/// `resolve_via` or a pool link, comes with none, so the request never
/// releases or closes it.
struct StationTarget<S = Session> {
    session: S,
    leased: bool,
}

impl<S: Leased> StationTarget<S> {
    /// The target for a session direct dial just dialed, holding the lease
    /// the dial took.
    fn dialed(session: S) -> Self {
        let leased = session.leases().is_some();
        Self { session, leased }
    }

    /// The target for reusing a session found open to a station: without a
    /// lease when its owner opened it, with a new lease when direct dial
    /// dialed it, and none at all when its last lease was already released.
    fn reuse(found: S) -> Option<Self> {
        let leased = match found.leases() {
            None => false,
            Some(leases) if leases.try_lease() => true,
            Some(_) => return None,
        };
        Some(Self {
            session: found,
            leased,
        })
    }

    /// Gives back the request's lease, if it holds one. Returns the session
    /// when that was its last lease, for the caller to close.
    fn release_lease(self) -> Option<S> {
        let last = self.leased && self.session.leases().is_some_and(Leases::release);
        last.then_some(self.session)
    }
}

impl StationTarget {
    async fn open_dedicated_stream(&self) -> Result<FrameStream, quinn::ConnectionError> {
        self.session.open_dedicated_stream().await
    }

    /// Gives back the request's lease, closing a session direct dial dialed
    /// when no other direct-dial request still uses it.
    async fn release(self, id: &KeyPair) {
        close_last(self.release_lease(), id).await;
    }
}

/// Runs `request` on the target's session, then gives the target's lease
/// back whatever the outcome. Returns the request's result, and the session
/// when that was its last lease, for the caller to close.
async fn run_then_release<S, T, Fut>(
    target: StationTarget<S>,
    request: impl FnOnce(S) -> Fut,
) -> (T, Option<S>)
where
    S: Leased + Clone,
    Fut: Future<Output = T>,
{
    let result = request(target.session.clone()).await;
    (result, target.release_lease())
}

/// Closes `last`, a session whose last lease was just given back.
async fn close_last(last: Option<Session>, id: &KeyPair) {
    if let Some(session) = last {
        session.close("normal", None, id).await;
    }
}

/// Dials a resolved station for a request that could have reused an open
/// session instead.
async fn dial_target(
    resolved: Resolved,
    id: &KeyPair,
    timeout: Duration,
) -> Result<StationTarget, DialAndVerifyError> {
    dial_verified(resolved, id, timeout)
        .await
        .map(StationTarget::dialed)
}

/// The connection of a session this process already has open to `station`
/// under `id`, such as `resolve_via` or a pool link, reused instead of
/// dialing: a second connection under the same identity would make the
/// station close that session. A session direct dial dialed for another
/// request is reused with a lease of its own, and not at all once it is
/// closing.
fn open_session_to(id: &KeyPair, station: &[u8; 32]) -> Option<StationTarget> {
    open_sessions::live()
        .find(id.node_id(), *station)
        .and_then(|open| StationTarget::reuse(Session::from_open(open)))
}

/// A stream [`open_stream_direct`] opened, and its use of the session it
/// runs on.
pub struct OpenedStream {
    pub stream: StreamHandle,
    /// Release it once the stream is done.
    pub lease: SessionLease,
}

/// A direct-dial stream's use of the session it runs on. A session direct
/// dial dialed stays open while any direct-dial request still uses it and
/// closes when the last one is released; a session this process already had
/// open under its owner, such as `resolve_via` or a
/// [`Pool`](crate::pool::Pool) link, stays open. A lease dropped without
/// being released leaves a dialed session open until its last handle is
/// gone, which then closes it without a GOODBYE.
pub struct SessionLease {
    target: StationTarget,
}

impl SessionLease {
    /// The session the stream runs on.
    pub fn session(&self) -> &Session {
        &self.target.session
    }

    /// Gives back this use of the session, closing a session direct dial
    /// dialed when no other direct-dial request still uses it.
    pub async fn release(self, id: &KeyPair) {
        self.target.release(id).await;
    }
}

#[derive(Debug)]
pub enum OpenStreamDirectError {
    Resolve(ResolveError),
    Dial(DialAndVerifyError),
    Open(stream::OpenError),
}

impl std::fmt::Display for OpenStreamDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenStreamDirectError::Resolve(e) => write!(f, "{e}"),
            OpenStreamDirectError::Dial(e) => write!(f, "{e}"),
            OpenStreamDirectError::Open(e) => write!(f, "direct_dial: open stream: {e}"),
        }
    }
}

impl std::error::Error for OpenStreamDirectError {}

fn open_stream_failure(
    failure: Failure<DialAndVerifyError, stream::OpenError>,
) -> OpenStreamDirectError {
    match failure {
        Failure::Resolve(e) => OpenStreamDirectError::Resolve(e),
        Failure::Dial(e) => OpenStreamDirectError::Dial(e),
        Failure::Request(e) => OpenStreamDirectError::Open(e),
    }
}

/// Opens the stream on the target and hands it to the caller with the
/// target's lease. Gives the lease back only if the open itself fails.
async fn open_stream_on(
    target: StationTarget,
    id: &KeyPair,
    procedure: &str,
    realm: [u8; 32],
    mode: StreamMode,
    args: Value,
    deadline_ms: i128,
) -> Result<OpenedStream, stream::OpenError> {
    let opened = match target.open_dedicated_stream().await {
        Ok(dedicated) => {
            StreamHandle::open_on(dedicated, procedure, realm, mode, args, deadline_ms, id).await
        }
        Err(e) => Err(stream::OpenError::OpenStream(e)),
    };
    match opened {
        Ok(stream) => Ok(OpenedStream {
            stream,
            lease: SessionLease { target },
        }),
        Err(e) => {
            target.release(id).await;
            Err(e)
        }
    }
}

/// Resolves `procedure`'s provider via direct-dial (through `resolve_via`,
/// used only to query the DHT) and opens a stream there, in one hop — the
/// streaming-RPC counterpart to [`call`]. The provider must have advertised
/// via [`advertise_direct`]:
/// streaming's provider side (`macula_streamer.erl`) shares the identical
/// `procedure_advertisement` mechanism RPC uses (confirmed against
/// `macula_streamer.erl`/`macula_stream_sink.erl`'s own `advertise_direct`/
/// `start_link_direct` — both are `macula_response:advertise_direct`/
/// `macula_direct_dial:call_stream` under the hood, nothing stream-specific
/// added), so no separate stream-shaped advertise function exists or is
/// needed.
///
/// `timeout` bounds finding the provider, each candidate's endpoint lookup
/// and dial, and opening the stream; `deadline_ms` is the stream's own
/// deadline, sent to the provider. A failure once the station is reached is
/// never retried elsewhere, because STREAM_OPEN may already be out.
///
/// The stream runs on a session this process already has open to the
/// provider's station under `id` when there is one (`resolve_via`, a
/// [`Pool`](crate::pool::Pool) link, or a session direct dial dialed for
/// another request), on a dedicated QUIC stream of its own; otherwise direct
/// dial dials a session for it. Release [`OpenedStream::lease`] once the
/// stream is done.
#[allow(clippy::too_many_arguments)]
pub async fn open_stream_direct(
    resolve_via: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    mode: StreamMode,
    args: Value,
    deadline_ms: i128,
    timeout: Duration,
) -> Result<OpenedStream, OpenStreamDirectError> {
    reach_procedure(
        &mut Via {
            session: resolve_via,
            id,
        },
        realm,
        procedure,
        None,
        move |station: &[u8; 32]| open_session_to(id, station),
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, _remaining: Duration| {
            open_stream_on(target, id, procedure, realm, mode, args, deadline_ms)
        },
        timeout,
    )
    .await
    .map_err(open_stream_failure)
}

/// [`open_stream_direct`], resolved via [`resolve_with_cert_chain`]
/// instead of [`resolve`] — see both for the full contract. Opt-in
/// managed-realm authorization; [`open_stream_direct`] itself is
/// unaffected.
#[allow(clippy::too_many_arguments)]
pub async fn open_stream_direct_with_cert_chain(
    resolve_via: &Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
    mode: StreamMode,
    args: Value,
    deadline_ms: i128,
    timeout: Duration,
) -> Result<OpenedStream, OpenStreamDirectError> {
    reach_procedure(
        &mut Via {
            session: resolve_via,
            id,
        },
        realm,
        procedure,
        Some(CertChainCheck {
            realm_ca_pem,
            expected_org,
        }),
        move |station: &[u8; 32]| open_session_to(id, station),
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, _remaining: Duration| {
            open_stream_on(target, id, procedure, realm, mode, args, deadline_ms)
        },
        timeout,
    )
    .await
    .map_err(open_stream_failure)
}

#[derive(Debug)]
pub enum PutDirectError {
    Resolve(ResolveError),
    Dial(DialAndVerifyError),
    Put(content::PutError),
}

impl std::fmt::Display for PutDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutDirectError::Resolve(e) => write!(f, "{e}"),
            PutDirectError::Dial(e) => write!(f, "{e}"),
            PutDirectError::Put(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for PutDirectError {}

/// Stores `data` on the target, then gives back the target's lease, closing
/// a dialed session when no other direct-dial request still uses it.
async fn put_then_release(
    target: StationTarget,
    id: &KeyPair,
    data: &[u8],
    name: String,
) -> Result<Mcid, content::PutError> {
    let (result, last) = run_then_release(target, move |session: Session| async move {
        match session.open_dedicated_stream().await {
            Ok(dedicated) => content::put_on(dedicated, data, name, id).await,
            Err(e) => Err(content::PutError::OpenStream(e)),
        }
    })
    .await;
    close_last(last, id).await;
    result
}

/// Stores `data` at a KNOWN `station` directly, in one hop, instead of
/// going through whatever station `resolve_via` happens to be connected
/// to. Mirrors `macula_feeder:start_link_direct/5,6`, which — unlike
/// procedure/stream direct-dial — takes the target station's pubkey
/// directly rather than resolving one via a `procedure_advertisement`:
/// content has no "procedure" to advertise, so there is nothing to
/// resolve here beyond the station's own `station_endpoint`.
/// `resolve_via` is used only to query the DHT for `station`'s
/// `station_endpoint`; it does not need to already be connected to
/// `station`.
///
/// `timeout` bounds the station's endpoint lookup and the dial; the upload
/// itself runs without one, as before.
///
/// When this process already has a session open to `station` under `id`
/// (`resolve_via` itself, or a [`Pool`](crate::pool::Pool) link), the
/// upload runs on that session, on a dedicated QUIC stream, with no
/// endpoint lookup or dial, and the session stays open. Otherwise direct
/// dial dials a session for the upload and closes it afterwards, unless
/// another direct-dial request still uses it.
pub async fn put_direct(
    resolve_via: &Session,
    id: &KeyPair,
    station: [u8; 32],
    data: &[u8],
    name: impl Into<String>,
    timeout: Duration,
) -> Result<Mcid, PutDirectError> {
    let name = name.into();
    reach_station(
        &mut Via {
            session: resolve_via,
            id,
        },
        station,
        move |station: &[u8; 32]| open_session_to(id, station),
        move |resolved: Resolved, remaining: Duration| dial_target(resolved, id, remaining),
        move |target: StationTarget, _remaining: Duration| put_then_release(target, id, data, name),
        timeout,
    )
    .await
    .map_err(|failure| match failure {
        Failure::Resolve(e) => PutDirectError::Resolve(e),
        Failure::Dial(e) => PutDirectError::Dial(e),
        Failure::Request(e) => PutDirectError::Put(e),
    })
}

/// `mcid` has no live, verifiable `content_announcement` in the DHT —
/// either nobody announced it (common: a single-block content put alone is
/// never announced, matching `macula_content_transfer:put_single_block/3`),
/// or every candidate found failed signature/self-consistency
/// verification.
#[derive(Debug)]
pub struct ContentNotAnnounced;

impl std::fmt::Display for ContentNotAnnounced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "direct_dial: content has no verifiable announcement in the DHT"
        )
    }
}

impl std::error::Error for ContentNotAnnounced {}

#[derive(Debug)]
pub enum GetDirectError {
    Dht(DhtError),
    NotAnnounced(ContentNotAnnounced),
    /// A `content_announcement`'s `endpoint` field wasn't a dialable
    /// `host:port` or URL.
    EndpointParse(String),
    Dial(DialAndVerifyError),
    Get(content::GetError),
    /// The timeout ran out before the content arrived: during a content
    /// transfer, or before any provider lookup was answered. `last` is the
    /// failure before a cut-off transfer, if any — for example the provider
    /// tried first serving content that didn't verify — and is also this
    /// error's [`source`](std::error::Error::source).
    Timeout {
        last: Option<Box<GetDirectError>>,
    },
}

impl std::fmt::Display for GetDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetDirectError::Dht(e) => write!(f, "direct_dial: find content providers: {e}"),
            GetDirectError::NotAnnounced(e) => write!(f, "{e}"),
            GetDirectError::EndpointParse(endpoint) => {
                write!(
                    f,
                    "direct_dial: content provider endpoint {endpoint:?}: not a URL or host:port"
                )
            }
            GetDirectError::Dial(e) => write!(f, "{e}"),
            GetDirectError::Get(e) => write!(f, "direct_dial: {e}"),
            GetDirectError::Timeout { last: None } => {
                write!(
                    f,
                    "direct_dial: the timeout ran out before the content arrived"
                )
            }
            GetDirectError::Timeout { last: Some(last) } => write!(
                f,
                "direct_dial: the timeout ran out during the content transfer, after: {last}"
            ),
        }
    }
}

impl std::error::Error for GetDirectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GetDirectError::Timeout { last: Some(last) } => Some(last.as_ref()),
            _ => None,
        }
    }
}

fn get_direct_failure(
    failure: ContentFailure<DialAndVerifyError, content::GetError>,
) -> GetDirectError {
    match failure {
        ContentFailure::Dht(e) => GetDirectError::Dht(e),
        ContentFailure::NotAnnounced => GetDirectError::NotAnnounced(ContentNotAnnounced),
        ContentFailure::EndpointParse(endpoint) => GetDirectError::EndpointParse(endpoint),
        ContentFailure::Dial(e) => GetDirectError::Dial(e),
        ContentFailure::Fetch(e) => GetDirectError::Get(e),
        ContentFailure::Timeout(last) => GetDirectError::Timeout {
            last: last.map(|failure| Box::new(get_direct_failure(*failure))),
        },
    }
}

/// Fetches `mcid` on the target, then gives back the target's lease, closing
/// a dialed session when no other direct-dial request still uses it.
async fn get_then_release(
    target: StationTarget,
    id: &KeyPair,
    mcid: Mcid,
) -> Result<Vec<u8>, content::GetError> {
    let (result, last) = run_then_release(target, move |session: Session| async move {
        match session.open_dedicated_stream().await {
            Ok(dedicated) => content::get_on(dedicated, mcid, id).await,
            Err(e) => Err(content::GetError::OpenStream(e)),
        }
    })
    .await;
    close_last(last, id).await;
    result
}

/// Fetches and verifies the content addressed by `mcid` from whichever
/// station a signed `content_announcement` names as its host, dialing
/// that station in one hop instead of relaying through `resolve_via`'s own
/// station. Mirrors `macula_direct_dial:get_content/3`.
///
/// `timeout` bounds the whole fetch: finding providers, each dial and each
/// transfer. A provider whose dial or transfer fails, including content
/// that doesn't verify against `mcid`, is skipped for the next one. When
/// the timeout cuts a transfer off, [`GetDirectError::Timeout`] carries the
/// previous failure, and a session dialed for that transfer is dropped
/// without a GOODBYE. A provider whose station this process already has a
/// session open to under `id` is fetched from on that session, which stays
/// open.
///
/// **Architectural note this module's other direct-dial functions don't
/// need**: a `content_announcement`'s `endpoint` is the FINAL dial target
/// directly (see `macula_record:read_content_announcement/1`'s `endpoint`
/// field and `macula:get_content_station/5`'s use of it as-is) — unlike
/// `procedure_advertisement`, there is no station-relay indirection, so
/// the announcer must genuinely BE independently dialable there. A plain
/// outbound-only leaf (everything this SDK's own identity/session model
/// supports) cannot legitimately publish one of these about itself — only
/// something with its own listening identity (`macula-station`, or a
/// dedicated content-serving relay) can; confirmed directly against
/// `macula.erl`, which states a `content_announcement` is made
/// "automatically by the station on receipt," not by an arbitrary
/// publisher. This crate therefore does not expose a client-facing
/// "announce content direct": [`dht::new_content_announcement`] stays a
/// low-level primitive (mirroring `macula_record.erl`'s own export) for
/// that kind of infrastructure-tier code, not ordinary leaf use.
/// [`get_direct`] itself has no such limitation — resolving and fetching
/// FROM an already-announced provider is a perfectly ordinary leaf
/// operation.
pub async fn get_direct(
    resolve_via: &Session,
    id: &KeyPair,
    mcid: Mcid,
    timeout: Duration,
) -> Result<Vec<u8>, GetDirectError> {
    fetch_content(
        &mut Via {
            session: resolve_via,
            id,
        },
        mcid,
        move |station: &[u8; 32]| open_session_to(id, station),
        move |resolved: Resolved, share: Duration| dial_target(resolved, id, share),
        move |target: StationTarget, _remaining: Duration| get_then_release(target, id, mcid),
        timeout,
    )
    .await
    .map_err(get_direct_failure)
}

/// Every content announcement that verifies, in DHT order. Mirrors
/// `macula.erl`'s `decode_provider/1`: the record's OWN signature must
/// verify, AND the payload's claimed `announcer_node` must equal the
/// record's own envelope key — a record merely stored under the right key
/// but self-signed by a different identity would otherwise still be
/// trusted.
fn trusted_content_providers(recs: &[Record]) -> Vec<ContentCandidate> {
    recs.iter()
        .filter_map(|rec| {
            dht::verify(rec).ok()?;
            let adv = dht::read_content_announcement(rec).ok()?;
            (adv.announcer_node == rec.key).then_some(ContentCandidate {
                announcer: adv.announcer_node,
                version: rec.version,
                endpoint: adv.endpoint,
            })
        })
        .collect()
}

/// Splits a `content_announcement`'s `endpoint` (a dialable seed URL, e.g.
/// `"https://host:4433"` — `macula_client:seed()`'s own format) into the
/// host/port pair [`connection::connect`] wants. Distinct from
/// `station_endpoint`'s already-split `host_advertised`/`quic_port`
/// fields — `content_announcement` embeds a single ready-to-dial URL
/// instead. Tolerates a bare `host:port` with no scheme too, matching this
/// crate's own tolerance elsewhere for a station config given without one.
fn parse_seed_url(seed: &str) -> Option<(String, u16)> {
    if let Some(rest) = seed
        .strip_prefix("https://")
        .or_else(|| seed.strip_prefix("http://"))
    {
        let hostport = rest.split('/').next().unwrap_or(rest);
        let (host, port_str) = hostport.rsplit_once(':')?;
        return Some((host.to_string(), port_str.parse().ok()?));
    }
    let (host, port_str) = seed.rsplit_once(':')?;
    Some((host.to_string(), port_str.parse().ok()?))
}

/// Direct-dial candidate selection with no network: a fake DHT answers with
/// real signed records, and fake dials and requests remember which stations
/// were reached. The cases and names match `macula-go`'s
/// `directdial/candidates_test.go` and `macula-dotnet`'s
/// `DirectDialCandidatesTests`, so every SDK in the family is held to the
/// same behaviour.
#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::*;
    use crate::cert_chain::fixtures::{pem_bundle, test_ca, test_leaf};

    const REALM: [u8; 32] = [0; 32];
    const PROCEDURE: &str = "macula_rust.candidates_test.echo";
    const ORG: &str = "acme-corp";
    /// Leaves time for every candidate.
    const ROOMY: Duration = Duration::from_secs(3);
    /// The deadline of the timeout-bound cases.
    const SHORT: Duration = Duration::from_millis(300);
    /// How long the timeout-bound cases may take to return.
    const SHORT_BOUND: Duration = Duration::from_secs(1);
    const CONTENT: &[u8] = b"the content";

    fn procedure_key() -> [u8; 32] {
        dht::procedure_key(&dht::discovery_uri(REALM, PROCEDURE))
    }

    /// A provider: its own advertisement signer (the DHT keeps one record
    /// per signer) and the station serving it at `host`.
    struct Provider {
        host: String,
        advertiser: KeyPair,
        station: KeyPair,
    }

    impl Provider {
        fn new(host: &str) -> Self {
            Self {
                host: host.to_string(),
                advertiser: KeyPair::generate(),
                station: KeyPair::generate(),
            }
        }
    }

    fn advertisement(p: &Provider) -> Record {
        advertisement_expiring_in(p, 120_000)
    }

    fn advertisement_expiring_in(p: &Provider, expires_in_ms: i128) -> Record {
        let mut rec = dht::new_procedure_advertisement(
            p.advertiser.node_id(),
            dht::discovery_uri(REALM, PROCEDURE),
            p.station.node_id(),
            Duration::from_secs(120),
        );
        rec.expires_at = now_ms() + expires_in_ms;
        dht::sign(rec, &p.advertiser)
    }

    fn authorized_advertisement(
        p: &Provider,
        ca: &rcgen::Issuer<'static, rcgen::KeyPair>,
        org: &str,
    ) -> Record {
        let leaf = test_leaf(
            ca,
            p.advertiser.node_id(),
            org,
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let rec = dht::new_procedure_advertisement_with_cert_chain(
            p.advertiser.node_id(),
            dht::discovery_uri(REALM, PROCEDURE),
            p.station.node_id(),
            Duration::from_secs(120),
            pem_bundle(&[leaf]),
        );
        dht::sign(rec, &p.advertiser)
    }

    /// A `station_endpoint` advertising `host`, signed by `signer` —
    /// normally the station itself. Each call is a new record version.
    fn station_endpoint(signer: &KeyPair, host: &str) -> Record {
        let created_at = now_ms();
        dht::sign(
            Record {
                record_type: dht::TYPE_STATION_ENDPOINT,
                key: signer.node_id(),
                version: *uuid::Uuid::now_v7().as_bytes(),
                created_at,
                expires_at: created_at + 600_000,
                payload: Value::Map(vec![
                    (Value::text("quic_port"), Value::Int(4433)),
                    (
                        Value::text("host_advertised"),
                        Value::List(vec![Value::Bytes(host.as_bytes().to_vec())]),
                    ),
                ]),
                signature: Vec::new(),
            },
            signer,
        )
    }

    /// A `station_endpoint` signed by `signer` that advertises no host, so it
    /// names no dialable address.
    fn malformed_station_endpoint(signer: &KeyPair) -> Record {
        let created_at = now_ms();
        dht::sign(
            Record {
                record_type: dht::TYPE_STATION_ENDPOINT,
                key: signer.node_id(),
                version: *uuid::Uuid::now_v7().as_bytes(),
                created_at,
                expires_at: created_at + 600_000,
                payload: Value::Map(vec![
                    (Value::text("quic_port"), Value::Int(4433)),
                    (Value::text("host_advertised"), Value::List(vec![])),
                ]),
                signature: Vec::new(),
            },
            signer,
        )
    }

    fn announcement(p: &Provider, mcid: Mcid) -> Record {
        dht::sign(
            dht::new_content_announcement(
                p.station.node_id(),
                mcid,
                format!("https://{}:4433", p.host),
                Duration::from_secs(120),
            ),
            &p.station,
        )
    }

    fn new_mcid() -> Mcid {
        std::array::from_fn(|_| rand::random())
    }

    /// This process has no session open to any station.
    fn nothing_open(_station: &[u8; 32]) -> Option<String> {
        None
    }

    #[tokio::test]
    async fn call_reports_the_last_candidate_failure_when_a_later_pass_finds_none() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)], vec![]]);
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let result = call(&dht, &stations, Duration::from_secs(1)).await;

        assert!(
            matches!(&result, Err(Failure::Dial(e)) if e.contains("refused")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn call_reports_the_last_candidate_failure_when_a_later_lookup_fails() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        dht.fail_lookups_after(procedure_key(), 1);
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let result = call(&dht, &stations, Duration::from_secs(1)).await;

        assert!(
            matches!(&result, Err(Failure::Dial(e)) if e.contains("refused")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn get_direct_reports_the_last_candidate_failure_when_a_later_lookup_fails() {
        let p = Provider::new("p.test");
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(dht::content_key(mcid), vec![vec![announcement(&p, mcid)]]);
        dht.fail_lookups_after(dht::content_key(mcid), 1);
        let stations = FakeStations::default();
        stations.refuse(&p.host);

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(&result, Err(ContentFailure::Dial(e)) if e.contains("refused")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn call_retries_after_a_lookup_fails() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        dht.fail_first_lookups(procedure_key(), 1);
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        let stations = FakeStations::default();

        let reply = call(&dht, &stations, ROOMY)
            .await
            .expect("a answers once a lookup is answered");

        assert_eq!(reply, "reply from a.test");
        assert_eq!(dht.asked_at(procedure_key()).len(), 2);
    }

    #[tokio::test]
    async fn get_direct_retries_after_a_lookup_fails() {
        let p = Provider::new("p.test");
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(dht::content_key(mcid), vec![vec![announcement(&p, mcid)]]);
        dht.fail_first_lookups(dht::content_key(mcid), 1);
        let stations = FakeStations::default();

        let content = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            ROOMY,
        )
        .await
        .expect("p serves the content once a lookup is answered");

        assert_eq!(content, CONTENT);
        assert_eq!(stations.reached(), ["p.test"]);
    }

    #[tokio::test]
    async fn call_reports_a_failed_lookup_at_its_deadline_when_no_candidate_was_tried() {
        let dht = FakeDht::new();
        dht.fail_first_lookups(procedure_key(), usize::MAX);
        let started = Instant::now();

        let result = call(&dht, &FakeStations::default(), SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Dht(_)))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(
            dht.asked_at(procedure_key()).len() > 1,
            "a failed lookup is retried until the deadline"
        );
    }

    #[tokio::test]
    async fn get_direct_reports_a_failed_lookup_at_its_deadline_when_no_provider_was_tried() {
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.fail_first_lookups(dht::content_key(mcid), usize::MAX);
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            SHORT,
        )
        .await;

        assert!(matches!(result, Err(ContentFailure::Dht(_))), "{result:?}");
        assert_returned_within(SHORT_BOUND, started);
        assert!(
            dht.asked_at(dht::content_key(mcid)).len() > 1,
            "a failed lookup is retried until the deadline"
        );
    }

    #[tokio::test]
    async fn call_reports_not_advertised_when_a_lookup_answered_before_later_ones_failed() {
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![]]);
        dht.fail_lookups_after(procedure_key(), 1);

        let result = call(&dht, &FakeStations::default(), SHORT).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::ProcedureNotAdvertised))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn call_reports_a_timeout_when_no_lookup_was_answered_in_time() {
        let dht = FakeDht::new();
        dht.never_answer(procedure_key());
        let started = Instant::now();

        let result = call(&dht, &FakeStations::default(), SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Timeout))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    #[tokio::test]
    async fn call_keeps_a_lookup_error_when_a_later_lookup_is_cut_off_by_the_deadline() {
        let dht = FakeDht::new();
        dht.fail_first_lookups(procedure_key(), 1);
        dht.never_answer(procedure_key());

        let result = call(&dht, &FakeStations::default(), SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Dht(_)))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn get_direct_reports_not_announced_when_a_lookup_answered_before_later_ones_failed() {
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(dht::content_key(mcid), vec![vec![]]);
        dht.fail_lookups_after(dht::content_key(mcid), 1);
        let stations = FakeStations::default();

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            SHORT,
        )
        .await;

        assert!(
            matches!(result, Err(ContentFailure::NotAnnounced)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn get_direct_reports_a_timeout_when_no_lookup_was_answered_in_time() {
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.never_answer(dht::content_key(mcid));
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            SHORT,
        )
        .await;

        assert!(
            matches!(result, Err(ContentFailure::Timeout(None))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    /// A DHT that answers `find_records` on a key with successive replies,
    /// repeating the last, and `find_record` with the `station_endpoint`
    /// published under that key (not_found otherwise). Clones share state,
    /// so a test can publish while a call is running.
    #[derive(Clone)]
    struct FakeDht(Arc<Mutex<DhtState>>);

    struct DhtState {
        started: Instant,
        replies: HashMap<[u8; 32], Vec<Vec<Record>>>,
        asked: HashMap<[u8; 32], Vec<Duration>>,
        fail_after: HashMap<[u8; 32], usize>,
        fail_first: HashMap<[u8; 32], usize>,
        never_answered: HashSet<[u8; 32]>,
        endpoint_asked: HashMap<[u8; 32], usize>,
        endpoints: HashMap<[u8; 32], Record>,
        endpoints_in_turn: HashMap<[u8; 32], Vec<Record>>,
    }

    impl FakeDht {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(DhtState {
                started: Instant::now(),
                replies: HashMap::new(),
                asked: HashMap::new(),
                fail_after: HashMap::new(),
                fail_first: HashMap::new(),
                never_answered: HashSet::new(),
                endpoint_asked: HashMap::new(),
                endpoints: HashMap::new(),
                endpoints_in_turn: HashMap::new(),
            })))
        }

        fn answer(&self, key: [u8; 32], replies: Vec<Vec<Record>>) {
            self.0.lock().unwrap().replies.insert(key, replies);
        }

        fn publish_endpoint(&self, station: &KeyPair, endpoint: Record) {
            self.0
                .lock()
                .unwrap()
                .endpoints
                .insert(dht::station_endpoint_key(station.node_id()), endpoint);
        }

        /// `find_record` for `station`'s `station_endpoint` answers with
        /// `endpoints` in turn, repeating the last.
        fn publish_endpoints_in_turn(&self, station: &KeyPair, endpoints: Vec<Record>) {
            self.0
                .lock()
                .unwrap()
                .endpoints_in_turn
                .insert(dht::station_endpoint_key(station.node_id()), endpoints);
        }

        /// When `find_records` was asked for `key`, since this DHT was
        /// created.
        fn asked_at(&self, key: [u8; 32]) -> Vec<Duration> {
            self.0
                .lock()
                .unwrap()
                .asked
                .get(&key)
                .cloned()
                .unwrap_or_default()
        }

        /// After `answered_lookups` lookups, `find_records` on `key` fails,
        /// the way a query over a resolver session that has dropped does.
        fn fail_lookups_after(&self, key: [u8; 32], answered_lookups: usize) {
            self.0
                .lock()
                .unwrap()
                .fail_after
                .insert(key, answered_lookups);
        }

        /// The first `failed_lookups` lookups of `key` fail, the way a query
        /// the station doesn't answer in time does; later ones are answered.
        fn fail_first_lookups(&self, key: [u8; 32], failed_lookups: usize) {
            self.0
                .lock()
                .unwrap()
                .fail_first
                .insert(key, failed_lookups);
        }

        /// Lookups of `key` never get an answer once any
        /// `fail_first_lookups` have failed; only the caller's deadline ends
        /// them.
        fn never_answer(&self, key: [u8; 32]) {
            self.0.lock().unwrap().never_answered.insert(key);
        }

        /// Answers one `find_records` lookup of `key` at once, or `None` when
        /// `key` is never answered.
        fn lookup_now(&self, key: [u8; 32]) -> Option<Result<Vec<Record>, DhtError>> {
            let mut state = self.0.lock().unwrap();
            let elapsed = state.started.elapsed();
            let asked = state.asked.entry(key).or_default();
            asked.push(elapsed);
            let turn = asked.len() - 1;
            if state
                .fail_first
                .get(&key)
                .is_some_and(|failed| turn < *failed)
            {
                return Some(Err(DhtError::Remote(
                    "the station did not answer the lookup".to_string(),
                )));
            }
            if state.never_answered.contains(&key) {
                return None;
            }
            if state
                .fail_after
                .get(&key)
                .is_some_and(|answered| turn >= *answered)
            {
                return Some(Err(DhtError::Remote(
                    "the resolver session is gone".to_string(),
                )));
            }
            Some(Ok(state
                .replies
                .get(&key)
                .map(|replies| replies[turn.min(replies.len() - 1)].clone())
                .unwrap_or_default()))
        }

        /// How many times `find_record` was asked for `station`'s
        /// `station_endpoint`.
        fn endpoint_lookups_of(&self, station: &KeyPair) -> usize {
            self.0
                .lock()
                .unwrap()
                .endpoint_asked
                .get(&dht::station_endpoint_key(station.node_id()))
                .copied()
                .unwrap_or(0)
        }

        /// Answers one `find_record` lookup of `key` at once, or `None` when
        /// `key` is never answered. `fail_first_lookups` and `never_answer`
        /// apply to `station_endpoint` keys too.
        fn endpoint_lookup_now(&self, key: [u8; 32]) -> Option<Result<Record, DhtError>> {
            let mut state = self.0.lock().unwrap();
            let asked = state.endpoint_asked.entry(key).or_default();
            *asked += 1;
            let turn = *asked - 1;
            if state
                .fail_first
                .get(&key)
                .is_some_and(|failed| turn < *failed)
            {
                return Some(Err(DhtError::Remote(
                    "the station did not answer the lookup".to_string(),
                )));
            }
            if state.never_answered.contains(&key) {
                return None;
            }
            if let Some(in_turn) = state.endpoints_in_turn.get(&key) {
                return Some(Ok(in_turn[turn.min(in_turn.len() - 1)].clone()));
            }
            Some(state.endpoints.get(&key).cloned().ok_or(DhtError::NotFound))
        }
    }

    impl DhtLookups for FakeDht {
        async fn find_records(&mut self, key: [u8; 32]) -> Result<Vec<Record>, DhtError> {
            match self.lookup_now(key) {
                Some(answer) => answer,
                None => std::future::pending().await,
            }
        }

        async fn find_record(&mut self, key: [u8; 32]) -> Result<Record, DhtError> {
            match self.endpoint_lookup_now(key) {
                Some(answer) => answer,
                None => std::future::pending().await,
            }
        }
    }

    /// Fake dials: remembers every host it is asked to reach, in order, and
    /// refuses the hosts marked as refusing before anything is sent.
    #[derive(Clone, Default)]
    struct FakeStations(Arc<Mutex<StationsState>>);

    #[derive(Default)]
    struct StationsState {
        reached: Vec<String>,
        refusing: HashSet<String>,
    }

    impl FakeStations {
        fn refuse(&self, host: &str) {
            self.0.lock().unwrap().refusing.insert(host.to_string());
        }

        fn reached(&self) -> Vec<String> {
            self.0.lock().unwrap().reached.clone()
        }

        fn dial(&self, station: &Resolved) -> Result<String, String> {
            let mut state = self.0.lock().unwrap();
            state.reached.push(station.host.clone());
            if state.refusing.contains(&station.host) {
                Err(format!("{} refused the connection", station.host))
            } else {
                Ok(station.host.clone())
            }
        }
    }

    async fn call(
        dht: &FakeDht,
        stations: &FakeStations,
        timeout: Duration,
    ) -> Result<String, Failure<String, String>> {
        reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            None,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| ready(Ok(format!("reply from {host}"))),
            timeout,
        )
        .await
    }

    async fn call_with_cert_chain(
        dht: &FakeDht,
        stations: &FakeStations,
        realm_ca_pem: &[u8],
        timeout: Duration,
    ) -> Result<String, Failure<String, String>> {
        reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            Some(CertChainCheck {
                realm_ca_pem,
                expected_org: ORG,
            }),
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| ready(Ok(format!("reply from {host}"))),
            timeout,
        )
        .await
    }

    fn two_providers_with_endpoints() -> (FakeDht, Provider, Provider) {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![advertisement(&a), advertisement(&b)]],
        );
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        (dht, a, b)
    }

    fn assert_returned_within(bound: Duration, started: Instant) {
        let took = started.elapsed();
        assert!(
            took < bound,
            "expected to return within {bound:?}, took {took:?}"
        );
    }

    #[tokio::test]
    async fn call_tries_the_next_advertisement_when_a_station_has_no_endpoint() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![advertisement(&a), advertisement(&b)]],
        );
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        let stations = FakeStations::default();

        let reply = call(&dht, &stations, ROOMY).await.expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["b.test"]);
    }

    #[tokio::test]
    async fn call_retries_when_no_advertisement_qualifies() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![
                vec![advertisement_expiring_in(&a, -1_000)],
                vec![advertisement(&b)],
            ],
        );
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        let stations = FakeStations::default();

        let reply = call(&dht, &stations, ROOMY).await.expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["b.test"]);
    }

    #[tokio::test]
    async fn call_tries_the_next_station_when_a_dial_fails() {
        let (dht, a, _b) = two_providers_with_endpoints();
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let reply = call(&dht, &stations, ROOMY).await.expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["a.test", "b.test"]);
    }

    /// A guard, green before and after the fix: once the CALL has gone out,
    /// its failure is the call's result.
    #[tokio::test]
    async fn call_never_sends_the_request_twice() {
        let (dht, _a, _b) = two_providers_with_endpoints();
        let stations = FakeStations::default();

        let result = reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            None,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| {
                ready(Err::<String, _>(format!(
                    "{host} reset the stream after the CALL went out"
                )))
            },
            ROOMY,
        )
        .await;

        assert!(
            matches!(&result, Err(Failure::Request(e)) if e.starts_with("a.test")),
            "{result:?}"
        );
        assert_eq!(stations.reached(), ["a.test"]);
    }

    #[tokio::test]
    async fn call_timeout_bounds_resolution() {
        let started = Instant::now();

        let result = call(&FakeDht::new(), &FakeStations::default(), SHORT).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::ProcedureNotAdvertised))
            ),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    #[tokio::test]
    async fn call_timeout_bounds_the_endpoint_lookup() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = call(&dht, &stations, SHORT).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::StationEndpointNotFound))
            ),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn open_stream_direct_tries_the_next_station_when_a_dial_fails() {
        let (dht, a, _b) = two_providers_with_endpoints();
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let stream = reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            None,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| {
                ready(Ok::<_, String>(format!("stream at {host}")))
            },
            ROOMY,
        )
        .await
        .expect("b opens");

        assert_eq!(stream, "stream at b.test");
        assert_eq!(stations.reached(), ["a.test", "b.test"]);
    }

    /// A guard, green before and after the fix: STREAM_OPEN may already be
    /// out once the station is dialed, so a failure there is never retried.
    #[tokio::test]
    async fn open_stream_direct_never_opens_the_stream_twice() {
        let (dht, _a, _b) = two_providers_with_endpoints();
        let stations = FakeStations::default();

        let result = reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            None,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| {
                ready(Err::<String, _>(format!(
                    "{host} failed after STREAM_OPEN may have gone out"
                )))
            },
            ROOMY,
        )
        .await;

        assert!(
            matches!(&result, Err(Failure::Request(e)) if e.starts_with("a.test")),
            "{result:?}"
        );
        assert_eq!(stations.reached(), ["a.test"]);
    }

    #[tokio::test]
    async fn get_direct_retries_when_no_provider_qualifies() {
        let p = Provider::new("p.test");
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(
            dht::content_key(mcid),
            vec![vec![], vec![announcement(&p, mcid)]],
        );
        let stations = FakeStations::default();

        let content = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            ROOMY,
        )
        .await
        .expect("p serves the content");

        assert_eq!(content, CONTENT);
        assert_eq!(stations.reached(), ["p.test"]);
    }

    #[tokio::test]
    async fn get_direct_tries_the_next_provider_after_a_failed_fetch() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(
            dht::content_key(mcid),
            vec![vec![announcement(&a, mcid), announcement(&b, mcid)]],
        );
        let stations = FakeStations::default();

        let content = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| {
                ready(if host == "a.test" {
                    Err("fetched content does not hash to its MCID".to_string())
                } else {
                    Ok(CONTENT.to_vec())
                })
            },
            ROOMY,
        )
        .await
        .expect("b serves the content");

        assert_eq!(content, CONTENT);
        assert_eq!(stations.reached(), ["a.test", "b.test"]);
    }

    #[tokio::test]
    async fn get_direct_timeout_bounds_resolution() {
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = fetch_content(
            &mut FakeDht::new(),
            new_mcid(),
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| ready(Ok::<_, String>(CONTENT.to_vec())),
            SHORT,
        )
        .await;

        assert!(
            matches!(result, Err(ContentFailure::NotAnnounced)),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    async fn put(
        dht: &FakeDht,
        stations: &FakeStations,
        station: &KeyPair,
        timeout: Duration,
    ) -> Result<String, Failure<String, String>> {
        reach_station(
            &mut dht.clone(),
            station.node_id(),
            nothing_open,
            |r: Resolved, _remaining: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| {
                ready(Ok::<_, String>(format!("stored on {host}")))
            },
            timeout,
        )
        .await
    }

    #[tokio::test]
    async fn put_direct_reports_no_station_endpoint_when_a_lookup_answered_not_found() {
        let result = put(
            &FakeDht::new(),
            &FakeStations::default(),
            &KeyPair::generate(),
            SHORT,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::StationEndpointNotFound))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn put_direct_retries_an_endpoint_lookup_that_fails() {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.publish_endpoint(&station, station_endpoint(&station, "s.test"));
        dht.fail_first_lookups(dht::station_endpoint_key(station.node_id()), 1);

        let stored = put(&dht, &FakeStations::default(), &station, ROOMY)
            .await
            .expect("s stores once its endpoint lookup is answered");

        assert_eq!(stored, "stored on s.test");
    }

    #[tokio::test]
    async fn put_direct_reports_a_failed_endpoint_lookup_when_every_lookup_failed() {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.fail_first_lookups(dht::station_endpoint_key(station.node_id()), usize::MAX);
        let started = Instant::now();

        let result = put(&dht, &FakeStations::default(), &station, SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Dht(_)))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(
            dht.endpoint_lookups_of(&station) > 1,
            "a failed endpoint lookup is retried within the budget"
        );
    }

    #[tokio::test]
    async fn put_direct_reports_a_timeout_when_no_endpoint_lookup_was_answered_in_time() {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.never_answer(dht::station_endpoint_key(station.node_id()));
        let started = Instant::now();

        let result = put(&dht, &FakeStations::default(), &station, SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Timeout))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    #[tokio::test]
    async fn put_direct_keeps_a_lookup_error_when_a_later_endpoint_lookup_is_cut_off_by_the_deadline(
    ) {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.fail_first_lookups(dht::station_endpoint_key(station.node_id()), 1);
        dht.never_answer(dht::station_endpoint_key(station.node_id()));

        let result = put(&dht, &FakeStations::default(), &station, SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Dht(_)))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn put_direct_asks_again_past_a_malformed_endpoint_record() {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.publish_endpoints_in_turn(
            &station,
            vec![
                malformed_station_endpoint(&station),
                station_endpoint(&station, "s.test"),
            ],
        );

        let stored = put(&dht, &FakeStations::default(), &station, ROOMY)
            .await
            .expect("s stores once a lookup finds its good endpoint record");

        assert_eq!(stored, "stored on s.test");
    }

    #[tokio::test]
    async fn put_direct_reports_a_malformed_endpoint_record_at_its_deadline() {
        let station = KeyPair::generate();
        let dht = FakeDht::new();
        dht.publish_endpoint(&station, malformed_station_endpoint(&station));
        let started = Instant::now();

        let result = put(&dht, &FakeStations::default(), &station, SHORT).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::MalformedStationEndpoint))
            ),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(
            dht.endpoint_lookups_of(&station) > 1,
            "a malformed endpoint record is asked again within the budget"
        );
    }

    #[tokio::test]
    async fn call_reports_a_timeout_when_no_endpoint_lookup_was_answered_in_time() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        dht.never_answer(dht::station_endpoint_key(a.station.node_id()));
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = call(&dht, &stations, SHORT).await;

        assert!(
            matches!(result, Err(Failure::Resolve(ResolveError::Timeout))),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn put_direct_timeout_bounds_the_endpoint_lookup() {
        let station = KeyPair::generate();
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = reach_station(
            &mut FakeDht::new(),
            station.node_id(),
            nothing_open,
            |r: Resolved, _remaining: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| ready(Ok::<_, String>(host)),
            SHORT,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::StationEndpointNotFound))
            ),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn open_stream_direct_reuses_an_open_session_to_the_provider_station() {
        let a = Provider::new("a.test");
        let a_station = a.station.node_id();
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        let stations = FakeStations::default();

        let stream = reach_procedure(
            &mut dht.clone(),
            REALM,
            PROCEDURE,
            None,
            |station: &[u8; 32]| {
                (*station == a_station).then(|| "the caller's session to a".to_string())
            },
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |session: String, _remaining: Duration| {
                ready(Ok::<_, String>(format!("stream on {session}")))
            },
            Duration::from_secs(1),
        )
        .await
        .expect("the stream opens on the open session");

        assert_eq!(stream, "stream on the caller's session to a");
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn get_direct_reuses_an_open_session_to_the_provider_station() {
        let p = Provider::new("p.test");
        let p_station = p.station.node_id();
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(dht::content_key(mcid), vec![vec![announcement(&p, mcid)]]);
        let stations = FakeStations::default();
        stations.refuse(&p.host);

        let content = fetch_content(
            &mut dht.clone(),
            mcid,
            |station: &[u8; 32]| {
                (*station == p_station).then(|| "the caller's session to p".to_string())
            },
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |session: String, _remaining: Duration| {
                ready(if session == "the caller's session to p" {
                    Ok(CONTENT.to_vec())
                } else {
                    Err(format!("{session} does not serve the content"))
                })
            },
            Duration::from_secs(1),
        )
        .await
        .expect("p serves the content on the open session");

        assert_eq!(content, CONTENT);
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn put_direct_reuses_an_open_session_to_the_station() {
        let station = KeyPair::generate().node_id();
        let stations = FakeStations::default();

        let stored = reach_station(
            &mut FakeDht::new(),
            station,
            |open: &[u8; 32]| {
                (*open == station).then(|| "the caller's session to the station".to_string())
            },
            |r: Resolved, _remaining: Duration| ready(stations.dial(&r)),
            |session: String, _remaining: Duration| {
                ready(Ok::<_, String>(format!("stored on {session}")))
            },
            SHORT,
        )
        .await
        .expect("stored on the open session");

        assert_eq!(stored, "stored on the caller's session to the station");
        assert!(stations.reached().is_empty());
    }

    // Sharing a session direct dial dialed between the requests that reuse
    // it. The names match the .NET and Go tests.

    #[derive(Clone)]
    struct FakeSession {
        leases: Option<std::sync::Arc<Leases>>,
    }

    impl Leased for FakeSession {
        fn leases(&self) -> Option<&Leases> {
            self.leases.as_deref()
        }
    }

    fn dialed_session() -> FakeSession {
        FakeSession {
            leases: Some(std::sync::Arc::new(Leases::new())),
        }
    }

    #[tokio::test]
    async fn a_dialed_session_is_closed_after_the_request_even_when_it_fails() {
        let target = StationTarget::dialed(dialed_session());

        let (result, closed) = run_then_release(target, |_session| {
            ready(Err::<(), _>("reset after the request went out"))
        })
        .await;

        assert!(result.is_err());
        assert!(closed.is_some(), "the dialed session is closed");
    }

    #[tokio::test]
    async fn a_reused_session_is_never_closed_by_the_request() {
        let owned = FakeSession { leases: None };
        let target = StationTarget::reuse(owned).expect("an owner's open session is reused");

        let (_, closed) = run_then_release(target, |_session| ready("answered")).await;

        assert!(closed.is_none());
    }

    #[test]
    fn a_dialed_session_stays_open_until_its_last_lease_is_released() {
        let leases = Leases::new();
        assert!(leases.try_lease());

        assert!(!leases.release(), "one lease is still out");
        assert!(leases.release(), "the last lease closes the session");
    }

    #[test]
    fn a_session_that_is_closing_is_not_reused() {
        let session = dialed_session();
        assert!(StationTarget::dialed(session.clone())
            .release_lease()
            .is_some());

        assert!(StationTarget::reuse(session).is_none());
    }

    #[tokio::test]
    async fn two_concurrent_transfers_to_one_station_share_the_dialed_session_until_both_finish() {
        let session = dialed_session();
        let first = StationTarget::dialed(session.clone());
        let second = StationTarget::reuse(session).expect("the dialed session is reused");

        let (_, closed) = run_then_release(first, |_session| ready("first stored")).await;
        assert!(closed.is_none(), "the second transfer still uses the session");

        let (_, closed) = run_then_release(second, |_session| ready("second stored")).await;
        assert!(closed.is_some(), "the last transfer closes the session");
    }

    #[tokio::test]
    async fn a_dialed_session_shared_by_a_stream_and_a_call_closes_only_when_both_release() {
        let session = dialed_session();
        let stream = StationTarget::dialed(session.clone());
        let call = StationTarget::reuse(session).expect("the dialed session is reused");

        let (_, closed) = run_then_release(call, |_session| ready("answered")).await;
        assert!(closed.is_none(), "the stream still uses the session");

        assert!(stream.release_lease().is_some());
    }

    #[tokio::test]
    async fn call_with_cert_chain_tries_the_next_advertisement_when_a_station_has_no_endpoint() {
        let (ca_pem, ca) = test_ca();
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![
                authorized_advertisement(&a, &ca, ORG),
                authorized_advertisement(&b, &ca, ORG),
            ]],
        );
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        let stations = FakeStations::default();

        let reply = call_with_cert_chain(&dht, &stations, &ca_pem, ROOMY)
            .await
            .expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["b.test"]);
    }

    #[tokio::test]
    async fn call_with_cert_chain_reports_the_authorization_failure_at_its_deadline() {
        let (ca_pem, ca) = test_ca();
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![authorized_advertisement(&a, &ca, "other-org")]],
        );
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        let stations = FakeStations::default();
        let started = Instant::now();

        let result = call_with_cert_chain(&dht, &stations, &ca_pem, SHORT).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::NoAuthorizedAdvertisement(_)))
            ),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
        assert!(stations.reached().is_empty());
    }

    #[tokio::test]
    async fn call_skips_a_station_whose_endpoint_is_signed_by_another_key() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![advertisement(&a), advertisement(&b)]],
        );
        dht.publish_endpoint(&a.station, station_endpoint(&KeyPair::generate(), &a.host));
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        let stations = FakeStations::default();

        let reply = call(&dht, &stations, ROOMY).await.expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["b.test"]);
    }

    #[tokio::test]
    async fn call_dials_a_refusing_station_once_per_endpoint_version() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let (result, ()) = tokio::join!(call(&dht, &stations, ROOMY), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(stations.reached(), ["a.test"]);
            dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        });

        assert!(
            matches!(&result, Err(Failure::Dial(e)) if e.contains("refused")),
            "{result:?}"
        );
        assert_eq!(stations.reached(), ["a.test", "a.test"]);
    }

    #[tokio::test]
    async fn call_tries_an_advertisement_that_appears_on_a_later_pass() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let ad_a = advertisement(&a);
        let dht = FakeDht::new();
        dht.answer(
            procedure_key(),
            vec![vec![ad_a.clone()], vec![ad_a, advertisement(&b)]],
        );
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        dht.publish_endpoint(&b.station, station_endpoint(&b.station, &b.host));
        let stations = FakeStations::default();
        stations.refuse(&a.host);

        let reply = call(&dht, &stations, ROOMY).await.expect("b answers");

        assert_eq!(reply, "reply from b.test");
        assert_eq!(stations.reached(), ["a.test", "b.test"]);
    }

    #[tokio::test]
    async fn resolution_backs_off_between_passes() {
        let dht = FakeDht::new();

        let result = call(&dht, &FakeStations::default(), ROOMY).await;

        assert!(
            matches!(
                result,
                Err(Failure::Resolve(ResolveError::ProcedureNotAdvertised))
            ),
            "{result:?}"
        );
        let asked = dht.asked_at(procedure_key());
        assert!(
            (5..=8).contains(&asked.len()),
            "expected 5 to 8 lookups, got {} at {asked:?}",
            asked.len()
        );
    }

    #[tokio::test]
    async fn get_direct_fetches_from_a_failing_provider_once_per_announcement() {
        let p = Provider::new("p.test");
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(dht::content_key(mcid), vec![vec![announcement(&p, mcid)]]);
        let stations = FakeStations::default();
        let fetches = Cell::new(0);

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |_host: String, _remaining: Duration| {
                fetches.set(fetches.get() + 1);
                ready(Err::<Vec<u8>, _>(
                    "fetched content does not hash to its MCID".to_string(),
                ))
            },
            Duration::from_secs(2),
        )
        .await;

        assert!(
            matches!(result, Err(ContentFailure::Fetch(_))),
            "{result:?}"
        );
        assert_eq!(fetches.get(), 1);
    }

    #[tokio::test]
    async fn call_picks_up_an_endpoint_record_that_changes_mid_deadline() {
        let a = Provider::new("a.test");
        let dht = FakeDht::new();
        dht.answer(procedure_key(), vec![vec![advertisement(&a)]]);
        dht.publish_endpoint(&a.station, station_endpoint(&a.station, "a-old.test"));
        let stations = FakeStations::default();
        stations.refuse("a-old.test");

        let (result, ()) = tokio::join!(call(&dht, &stations, ROOMY), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            dht.publish_endpoint(&a.station, station_endpoint(&a.station, &a.host));
        });

        assert_eq!(
            result.expect("a answers at its new endpoint"),
            "reply from a.test"
        );
        assert_eq!(stations.reached(), ["a-old.test", "a.test"]);
    }

    #[tokio::test]
    async fn resolve_timeout_bounds_resolution() {
        let started = Instant::now();

        let result = resolve_within(&mut FakeDht::new(), REALM, PROCEDURE, None, SHORT).await;

        assert!(
            matches!(result, Err(ResolveError::ProcedureNotAdvertised)),
            "{result:?}"
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    #[tokio::test]
    async fn resolve_station_endpoint_timeout_bounds_the_lookup() {
        let started = Instant::now();

        let lookup = lookup_station_endpoint(
            &mut FakeDht::new(),
            KeyPair::generate().node_id(),
            CallDeadline::after(SHORT),
            true,
        )
        .await;

        assert!(
            matches!(lookup.outcome, Err(ResolveError::StationEndpointNotFound)),
            "{:?}",
            lookup.outcome
        );
        assert_returned_within(SHORT_BOUND, started);
    }

    #[test]
    fn a_candidate_share_splits_what_remains_evenly_with_a_one_second_floor() {
        let slack = Duration::from_millis(100);
        let about = |share: CallDeadline, expected: Duration| {
            let remaining = share.remaining();
            assert!(
                remaining <= expected && remaining + slack >= expected,
                "expected about {expected:?}, got {remaining:?}"
            );
        };
        let roomy = CallDeadline::after(Duration::from_secs(3));
        let tight = CallDeadline::after(Duration::from_millis(300));

        about(roomy.share_for(2), Duration::from_millis(1500));
        about(roomy.share_for(10), Duration::from_secs(1));
        about(tight.share_for(3), Duration::from_millis(300));
    }

    #[tokio::test]
    async fn get_direct_timeout_during_a_transfer_carries_the_last_failure() {
        let (a, b) = (Provider::new("a.test"), Provider::new("b.test"));
        let mcid = new_mcid();
        let dht = FakeDht::new();
        dht.answer(
            dht::content_key(mcid),
            vec![vec![announcement(&a, mcid), announcement(&b, mcid)]],
        );
        let stations = FakeStations::default();

        let result = fetch_content(
            &mut dht.clone(),
            mcid,
            nothing_open,
            |r: Resolved, _share: Duration| ready(stations.dial(&r)),
            |host: String, _remaining: Duration| async move {
                if host == "a.test" {
                    return Err("fetched content does not hash to its MCID".to_string());
                }
                std::future::pending::<()>().await;
                Ok(CONTENT.to_vec())
            },
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(
                &result,
                Err(ContentFailure::Timeout(Some(last)))
                    if matches!(last.as_ref(), ContentFailure::Fetch(e) if e.contains("MCID"))
            ),
            "{result:?}"
        );
    }

    /// The public direct-dial futures must stay `Send`, so a caller can
    /// spawn them and the FFI crate, which requires it, keeps building. The
    /// check happens at compile time: the closure below is type-checked but
    /// never run, so it needs no live session.
    #[test]
    fn public_direct_dial_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        let _type_check_only = |session: &Session, id: &KeyPair, mode: StreamMode| {
            assert_send(&super::resolve(session, id, REALM, PROCEDURE));
            assert_send(&super::resolve_with_cert_chain(
                session, id, REALM, PROCEDURE, b"", ORG,
            ));
            assert_send(&super::call(
                session,
                id,
                REALM,
                PROCEDURE,
                Value::Null,
                ROOMY,
            ));
            assert_send(&super::call_with_ucan(
                session,
                id,
                REALM,
                PROCEDURE,
                Value::Null,
                ROOMY,
                Vec::new(),
            ));
            assert_send(&super::call_with_cert_chain(
                session,
                id,
                REALM,
                PROCEDURE,
                b"",
                ORG,
                Value::Null,
                ROOMY,
            ));
            assert_send(&super::open_stream_direct(
                session,
                id,
                REALM,
                PROCEDURE,
                mode,
                Value::Null,
                0,
                ROOMY,
            ));
            assert_send(&super::open_stream_direct_with_cert_chain(
                session,
                id,
                REALM,
                PROCEDURE,
                b"",
                ORG,
                mode,
                Value::Null,
                0,
                ROOMY,
            ));
            assert_send(&super::put_direct(session, id, [0; 32], b"", "name", ROOMY));
            assert_send(&super::get_direct(session, id, [0; 34], ROOMY));
            assert_send(&super::advertise_direct(
                session, id, REALM, PROCEDURE, ROOMY,
            ));
            assert_send(&super::advertise_direct_with_cert_chain(
                session,
                id,
                REALM,
                PROCEDURE,
                ROOMY,
                Vec::new(),
            ));
        };
    }
}
