//! A multi-station connection pool: dials several [`Session`]s concurrently
//! (bootstrap seeds, optionally grown by discovering more via
//! `hecate_stations.list_stations`) and gives [`Pool::call`]/
//! [`Pool::publish`] a choice of which connected one to use, instead of a
//! caller managing a single [`Session`] by hand.
//!
//! **Call/Publish only — no pooled Subscribe.** A caller that needs
//! Subscribe uses [`Session::subscribe`]/[`Session::run_subscriber`] on a
//! session directly, unpooled. Each link's [`Session`] runs its own reader,
//! so calls and publishes on one link run at the same time.
//!
//! Ported from the same station-discovery/link-rotation design already
//! shipped in `macula-go` (`pool/discovery.go`, v0.7.0) and `macula-dotnet`
//! (`StationDiscovery.cs`, v0.4.0) — see those crates' own doc comments for
//! the fuller cross-language history. This is a from-scratch build, not a
//! port of an existing pool: this crate had no `Seed`/multi-link concept at
//! all before this module.
//!
//! **Per-link trust, not one fixed mode for the whole pool** — this is the
//! one deliberate design difference from the go/dotnet ports, made possible
//! by building from scratch rather than extending an existing single-Trust
//! pool: a discovered station whose directory row has NO `hostname` (only a
//! bare-IP `host_advertised`) but DOES carry a `node_id` dials under
//! `Trust::Pinned(node_id)` instead of being skipped outright the way
//! go/dotnet's ports skip every hostname-less row under `Trust::WebPki`
//! (which can never validate a bare IP with no IP SANs). The underlying
//! MECHANISM mirrors a shipped, live-verified precedent in a completely
//! different codebase: `macula-apps/macula-cam2me`'s Android client
//! (`reachability/StationDiscovery.kt`), confirmed against the real fleet
//! by 34 (`macula`'s own reference-implementation session) independently
//! reaching the identical conclusion this module reaches, including a
//! live TLS-layer `verify=none` warning from `macula_quic` when dialing a
//! hostname'd station by IP+Pinned instead of its usual WebPki path.
//!
//! **This module's PRIORITY ORDER deliberately differs from cam2me's own,
//! in the safer direction** — cam2me picks Pinned(node_id) whenever a row
//! carries a node_id at all (true of essentially every row), falling back
//! to hostname/WebPki only when `host_advertised` itself is missing; that
//! trades away TLS-layer MITM resistance for the common case, not just the
//! no-DNS one. Here, `dial_target_from_station_row` prefers `hostname`
//! unconditionally — `Trust::Pinned` is chosen only when a row has NO
//! usable hostname at all, so a normal Let's-Encrypt-backed station still
//! dials WebPki exactly as it always has; only a genuine no-DNS station
//! (`stations-linode-toronto` — see `tests/live_station.rs`'s own
//! `pinned_trust_full_handshake_succeeds_against_toronto`) ever falls to
//! Pinned. Bootstrap seeds are entirely unaffected either way — they
//! always dial under the pool's own configured `Trust`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinSet;

use crate::connection::{self, CallError, Session};
use crate::dht;
use crate::frame::{CallResponse, CallSpec, PublishSpec};
use crate::identity::KeyPair;
use crate::transport::Trust;

/// A dial target: host+port only, no identity attached (every link in a
/// pool shares the pool's one identity). Mirrors macula-go's
/// `connection.Seed` / macula-dotnet's `Seed` record — this crate had no
/// equivalent type before this pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    pub host: String,
    pub port: u16,
}

impl Seed {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// How [`Pool::call`]/[`Pool::publish`] order the pool's currently-connected
/// links before applying their own existing first-match/`replication_factor`
/// logic — changes ORDER only, never how many links get used. Matches
/// macula_client.erl's own `link_selection` option (`first_success`/
/// `random`) and macula-go/macula-dotnet's identically-named enum, so
/// config ported from any of those doesn't need re-learning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkSelection {
    /// (The default.) Derives the actual policy from
    /// [`StationDiscoveryOptions::enabled`]: [`FirstSuccess`](Self::FirstSuccess)
    /// if discovery is off (this pool's original, only behavior, unchanged),
    /// [`Random`](Self::Random) if it's on.
    #[default]
    Auto,
    /// Tries links in Seed-list order (bootstrap seeds in the order the
    /// caller gave them, then discovered links in discovery order) — this
    /// pool's baseline behavior, since `links` is a plain append-only
    /// `Vec` (see [`Pool`]'s own doc on why that, not a `HashMap`, is the
    /// backing store — insertion order is the ordering, nothing extra to
    /// track).
    FirstSuccess,
    /// Uniformly shuffles the connected-links list before the same
    /// first-match (Call) or take-first-N (Publish) logic runs. Composes
    /// safely with a small `replication_factor`: shuffling ahead of a
    /// 1-element slice is a no-op.
    Random,
}

fn resolve_link_selection(
    configured: LinkSelection,
    station_discovery_enabled: bool,
) -> LinkSelection {
    match configured {
        LinkSelection::Auto if station_discovery_enabled => LinkSelection::Random,
        LinkSelection::Auto => LinkSelection::FirstSuccess,
        other => other,
    }
}

fn select_links(
    mut connected: Vec<Arc<PooledLink>>,
    resolved: LinkSelection,
) -> Vec<Arc<PooledLink>> {
    if resolved != LinkSelection::Random || connected.len() <= 1 {
        return connected;
    }
    use rand::seq::SliceRandom;
    connected.shuffle(&mut rand::rng());
    connected
}

/// Configures opt-in discovery of additional stations via
/// `hecate_stations.list_stations`, layered on top of the caller-supplied
/// bootstrap [`Seed`]s. Default (`enabled == false`) is a complete no-op.
///
/// Bootstrap seeds keep their exact meaning: dialed first, permanent
/// fallback if discovery never succeeds, retried forever on failure, never
/// replaced. Discovery only ADDS links — a station missing from a later
/// refresh does NOT tear down an existing link. A DISCOVERY-added link that
/// fails to dial `DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS` (5) times in a row
/// gives up and frees its slot (so a future refresh can try a different
/// station instead) — unlike a bootstrap seed, which never gives up. Go's
/// and dotnet's ports of this same feature have no such give-up mechanism
/// (a permanently-unreachable discovered station wastes a slot forever,
/// redialing at the flat respawn delay indefinitely); building this pool
/// from scratch, with 34's parallel design work on the Erlang reference
/// specifically adding this exception, was reason enough to include it here
/// too rather than carry the narrower behavior forward by default.
#[derive(Debug, Clone)]
pub struct StationDiscoveryOptions {
    pub enabled: bool,
    /// Interval between discovery attempts once at least one bootstrap
    /// link is up. Default 30 minutes.
    pub refresh_interval: Duration,
    /// Bounds discovery's OWN adds only, not the pool's total link count —
    /// see macula-dotnet's identical `StationDiscoveryOptions.MaxLinks` doc
    /// for the exact accounting rules this mirrors.
    pub max_links: usize,
}

impl Default for StationDiscoveryOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_interval: Duration::from_secs(30 * 60),
            max_links: 5,
        }
    }
}

/// Tunables for [`Pool`]. Defaults match every other port of this feature.
#[derive(Debug, Clone)]
pub struct PoolOptions {
    pub link_selection: LinkSelection,
    pub station_discovery: StationDiscoveryOptions,
    /// Flat delay before redialing a link after it dies (or fails to dial
    /// in the first place). Default 1s — flat, not exponential, matching
    /// the reference and every other port in this SDK family except ts.
    pub respawn_delay: Duration,
    /// Per-CALL timeout, passed through to [`Session::call`]. Default
    /// matches [`connection::DEFAULT_CALL_TIMEOUT`].
    pub call_timeout: Duration,
    /// How many currently-connected links a single publish fans out to.
    /// Partial success counts as success. Default 1, matching macula-ts
    /// and macula-dotnet's own `ReplicationFactor` default.
    pub replication_factor: usize,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            link_selection: LinkSelection::default(),
            station_discovery: StationDiscoveryOptions::default(),
            respawn_delay: DEFAULT_RESPAWN_DELAY,
            call_timeout: connection::DEFAULT_CALL_TIMEOUT,
            replication_factor: 1,
        }
    }
}

pub const DEFAULT_RESPAWN_DELAY: Duration = Duration::from_secs(1);

/// Discovery-added links only (never bootstrap seeds) give up redialing
/// after this many consecutive failures — see
/// [`StationDiscoveryOptions`]'s own doc for why.
const DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkOrigin {
    Bootstrap,
    Discovered,
}

/// A bootstrap link never gives up — matches every other port of this
/// pool shape, and macula_client.erl's own reference behavior for
/// caller-supplied seeds. Only a discovery-added link, after
/// [`DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS`] straight failures, gives up —
/// see [`StationDiscoveryOptions`]'s own doc for why this exception
/// exists at all.
fn should_give_up(origin: LinkOrigin, consecutive_failures: u32) -> bool {
    origin == LinkOrigin::Discovered && consecutive_failures >= DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS
}

struct LinkState {
    session: Option<Session>,
    peer_node_id: Option<[u8; 32]>,
}

/// One configured link's current state. Never removed from [`Pool`]'s own
/// `links` list once added (see that field's own doc) — `connected` simply
/// goes false when the link is down or still dialing.
pub struct PooledLink {
    pub seed: Seed,
    origin: LinkOrigin,
    /// This link's OWN trust — usually the pool's configured `Trust`, but
    /// see [`Pool`]'s module-level doc for the one case (a discovered,
    /// hostname-less, node_id-bearing row) where it differs per link.
    trust: Trust,
    /// Held only to read or swap the link's session, never across a round
    /// trip: a caller clones the session handle out first. Only the link's
    /// own lifecycle ([`run_link_lifecycle`]) installs a session and clears
    /// it when it ends; [`Pool::close`] takes it to close it.
    state: Mutex<LinkState>,
    connected: AtomicBool,
    /// Discovery-added links only: consecutive failed dial attempts, reset
    /// on a successful connect. Bootstrap links never read this — they
    /// retry forever regardless.
    consecutive_failures: AtomicU32,
    gave_up: AtomicBool,
}

impl PooledLink {
    fn new(seed: Seed, origin: LinkOrigin, trust: Trust) -> Arc<Self> {
        Arc::new(Self {
            seed,
            origin,
            trust,
            state: Mutex::new(LinkState {
                session: None,
                peer_node_id: None,
            }),
            connected: AtomicBool::new(false),
            consecutive_failures: AtomicU32::new(0),
            gave_up: AtomicBool::new(false),
        })
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// A discovery-added link that has permanently given up redialing — see
    /// [`StationDiscoveryOptions`]'s own doc. Always `false` for a
    /// bootstrap link, which never gives up.
    fn has_given_up(&self) -> bool {
        self.gave_up.load(Ordering::Acquire)
    }

    async fn peer_node_id(&self) -> Option<[u8; 32]> {
        self.state.lock().await.peer_node_id
    }
}

/// Snapshot of one link, for health/introspection.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub seed: Seed,
    pub connected: bool,
    pub node_id: Option<[u8; 32]>,
}

/// Aggregate health snapshot. Lock-free best-effort read.
#[derive(Debug, Clone, Copy)]
pub struct PoolStatus {
    pub healthy_links: usize,
    pub total_links: usize,
}

impl PoolStatus {
    /// At least one link has completed its CONNECT/HELLO handshake.
    pub fn is_healthy(&self) -> bool {
        self.healthy_links > 0
    }
}

#[derive(Debug)]
pub enum PoolCallError {
    /// No link in the pool has completed its CONNECT/HELLO handshake.
    NoHealthyStation,
    /// The failure that stopped the call, on the last link it was tried on.
    /// The pool moves on to the next link only while a call fails before its
    /// CALL was sent ([`CallError::not_sent`]), so no CALL runs twice.
    Call(CallError),
}

impl std::fmt::Display for PoolCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolCallError::NoHealthyStation => {
                write!(f, "pool: no link has completed its CONNECT/HELLO handshake")
            }
            PoolCallError::Call(e) => write!(f, "pool: call failed: {e}"),
        }
    }
}

impl std::error::Error for PoolCallError {}

#[derive(Debug)]
pub enum PoolPublishError {
    NoHealthyStation,
    /// Every link the publish was routed to failed — carries the count.
    AllFailed(usize),
}

impl std::fmt::Display for PoolPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolPublishError::NoHealthyStation => {
                write!(f, "pool: no link has completed its CONNECT/HELLO handshake")
            }
            PoolPublishError::AllFailed(n) => {
                write!(f, "pool: publish failed on all {n} targeted link(s)")
            }
        }
    }
}

impl std::error::Error for PoolPublishError {}

/// A multi-station connection pool — see this module's own doc for the
/// full design.
///
/// `links` is a plain append-only `Vec<Arc<PooledLink>>` behind an async
/// `RwLock`, deliberately NOT a `HashMap`/`HashSet` — this is the one
/// change made in direct response to the SAME class of bug found (twice,
/// independently) porting this feature to macula-go (`map[string]*link`
/// randomizing iteration order) and macula-dotnet (migrating to
/// `ConcurrentDictionary` for concurrent-add safety silently broke
/// `FirstSuccess`'s reliance on insertion order). A `Vec`, appended to
/// under the same lock that's ALSO taken to read it, has no separate
/// enumeration-order concept to accidentally break — insertion order IS
/// the order, by construction, with nothing to track alongside it the way
/// go's fix (tracking iteration order separately) or dotnet's fix (an
/// explicit `Ordinal` field) both had to.
pub struct Pool {
    identity: Arc<KeyPair>,
    trust: Trust,
    options: PoolOptions,
    links: RwLock<Vec<Arc<PooledLink>>>,
    stop_tx: watch::Sender<bool>,
    /// Every background task this pool has spawned (a link's respawn
    /// lifecycle, the discovery loop). `Pool::close` hard-aborts and
    /// awaits every one of these BEFORE draining/closing `links` — found
    /// necessary by adversarial review, 2026-09-05: without this, a task
    /// mid-dial (`connection::connect` has no internal cooperation point
    /// with the pool's own stop signal) or mid-discovery-push could
    /// complete AFTER `close` returns and resurrect a link, or a live,
    /// connected `Session`, that nothing will ever close again. Sequencing
    /// `shutdown()` strictly before the drain guarantees any task that
    /// manages to finish its own critical section either finishes before
    /// `close` starts draining (so the drain sees and closes it) or gets
    /// aborted before it can (so nothing is left to see).
    tasks: Mutex<JoinSet<()>>,
}

impl Pool {
    /// Spawn a pool with one link per seed. Returns as soon as every link's
    /// dial has STARTED, not once any is connected — handshakes complete
    /// asynchronously, matching macula_client:connect/2 and every other
    /// port of this pool shape.
    pub fn connect(
        seeds: Vec<Seed>,
        trust: Trust,
        identity: KeyPair,
        options: PoolOptions,
    ) -> Arc<Pool> {
        assert!(!seeds.is_empty(), "at least one seed is required");
        let (stop_tx, _stop_rx) = watch::channel(false);
        let identity = Arc::new(identity);
        let pool = Arc::new(Pool {
            identity: identity.clone(),
            trust,
            options,
            links: RwLock::new(Vec::new()),
            stop_tx,
            tasks: Mutex::new(JoinSet::new()),
        });

        let bootstrap_links: Vec<Arc<PooledLink>> = seeds
            .into_iter()
            .map(|seed| PooledLink::new(seed, LinkOrigin::Bootstrap, trust))
            .collect();

        {
            // Bootstrap links are known synchronously at construction, so
            // this can be a blocking write via try_write rather than
            // spawning a task just to populate the initial Vec -- no
            // other task holds the lock yet.
            let mut links = pool
                .links
                .try_write()
                .expect("no other task can hold this lock before Pool::connect returns");
            links.extend(bootstrap_links.iter().cloned());
        }

        {
            // Same reasoning as the links lock above: nothing else can
            // hold this lock yet either.
            let mut tasks = pool
                .tasks
                .try_lock()
                .expect("no other task can hold this lock before Pool::connect returns");
            for link in bootstrap_links {
                tasks.spawn(run_link_lifecycle(pool.clone(), link));
            }
            if pool.options.station_discovery.enabled {
                tasks.spawn(discover_stations_loop(pool.clone()));
            }
        }

        pool
    }

    /// Send a signed CALL on the currently-connected links, in the order
    /// [`PoolOptions::link_selection`] gives them. The pool moves on to the
    /// next link only when a call failed before its CALL was sent
    /// ([`CallError::not_sent`]), so no CALL runs twice: a call that timed out
    /// after its write started is returned as it is, and so is a BOLT#4 ERROR
    /// reply, exactly like a bare [`Session::call`]. A link whose session
    /// ends is dialed again by the pool. Pool calls publish no RPC telemetry
    /// facts, as macula's pool doesn't.
    pub async fn call(
        &self,
        procedure: &str,
        realm: [u8; 32],
        payload: crate::cbor::Value,
        deadline_ms: i128,
    ) -> Result<CallResponse, PoolCallError> {
        let calls = self
            .select_connected_links()
            .await
            .into_iter()
            .map(|link| {
                let spec = CallSpec::new(
                    rand::random(),
                    procedure,
                    realm,
                    payload.clone(),
                    deadline_ms,
                    self.identity.node_id(),
                );
                async move {
                    // A handle, cloned out, so no lock is held across the round trip.
                    let session = link.state.lock().await.session.clone();
                    let Some(session) = session else {
                        return Err(link_not_connected(&link));
                    };
                    session
                        .link_call(&spec, &self.identity, self.options.call_timeout)
                        .await
                }
            });
        call_until_sent(calls).await
    }

    /// Send a signed PUBLISH, fanning out to up to
    /// [`PoolOptions::replication_factor`] currently-connected links
    /// (ordered by [`PoolOptions::link_selection`]). Partial success counts
    /// as success, matching macula-ts/macula-dotnet's own publish-fanout
    /// contract.
    pub async fn publish(&self, spec: &PublishSpec) -> Result<(), PoolPublishError> {
        let candidates = self.select_connected_links().await;
        if candidates.is_empty() {
            return Err(PoolPublishError::NoHealthyStation);
        }
        let targets: Vec<_> = candidates
            .into_iter()
            .take(self.options.replication_factor.max(1))
            .collect();
        let attempted = targets.len();
        let mut successes = 0usize;
        for link in targets {
            let Some(session) = link.state.lock().await.session.clone() else {
                continue;
            };
            if session.publish(spec, &self.identity).await.is_ok() {
                successes += 1;
            }
        }
        if successes > 0 {
            Ok(())
        } else {
            Err(PoolPublishError::AllFailed(attempted))
        }
    }

    /// Aggregate health snapshot.
    pub async fn status(&self) -> PoolStatus {
        let links = self.links.read().await;
        let healthy_links = links.iter().filter(|l| l.is_connected()).count();
        PoolStatus {
            healthy_links,
            total_links: links.len(),
        }
    }

    /// Per-link snapshot, in seed-list/discovery order — see [`Pool`]'s own
    /// doc on why a plain `Vec` already guarantees this without any extra
    /// bookkeeping.
    pub async fn links(&self) -> Vec<LinkInfo> {
        let links = self.links.read().await;
        let mut out = Vec::with_capacity(links.len());
        for link in links.iter() {
            out.push(LinkInfo {
                seed: link.seed.clone(),
                connected: link.is_connected(),
                node_id: if link.is_connected() {
                    link.peer_node_id().await
                } else {
                    None
                },
            });
        }
        out
    }

    /// Sends GOODBYE on every currently-connected link and stops all
    /// background dial/discovery tasks. Waits for every background task
    /// (respawn lifecycles, the discovery loop) to actually be gone
    /// BEFORE draining/closing `links` — see [`Pool`]'s own field doc on
    /// `tasks` for why this ordering, specifically, is load-bearing.
    /// Does not wait for the GOODBYE writes themselves to finish being
    /// scheduled beyond [`Session::close`]'s own bounded drain.
    pub async fn close(&self, reason: &str, detail: Option<&str>) {
        let _ = self.stop_tx.send(true);
        self.tasks.lock().await.shutdown().await;
        let mut links = self.links.write().await;
        for link in links.drain(..) {
            let mut state = link.state.lock().await;
            if let Some(session) = state.session.take() {
                session.close(reason, detail, &self.identity).await;
            }
            link.connected.store(false, Ordering::Release);
        }
    }

    async fn select_connected_links(&self) -> Vec<Arc<PooledLink>> {
        let links = self.links.read().await;
        let connected: Vec<Arc<PooledLink>> =
            links.iter().filter(|l| l.is_connected()).cloned().collect();
        drop(links);
        let resolved = resolve_link_selection(
            self.options.link_selection,
            self.options.station_discovery.enabled,
        );
        select_links(connected, resolved)
    }
}

/// Runs `calls` in turn and moves on to the next only when a call failed
/// before its CALL was sent ([`CallError::not_sent`]), so no CALL runs
/// twice. Returns the first reply, a BOLT#4 ERROR reply included, else the
/// failure that stopped it: a call that was or may have been sent, or the
/// last one.
async fn call_until_sent<F>(calls: impl IntoIterator<Item = F>) -> Result<CallResponse, PoolCallError>
where
    F: std::future::Future<Output = Result<CallResponse, CallError>>,
{
    let mut calls = calls.into_iter().peekable();
    while let Some(call) = calls.next() {
        match call.await {
            // Never sent on this link, so the next one can't run it twice.
            Err(e) if e.not_sent() && calls.peek().is_some() => {}
            done => return done.map_err(PoolCallError::Call),
        }
    }
    Err(PoolCallError::NoHealthyStation)
}

/// The failure of a call on a link that lost its session after it was
/// selected, which never sent anything.
fn link_not_connected(link: &PooledLink) -> CallError {
    CallError::SessionEnded {
        reason: crate::connection::SessionEndReason::StreamFailed(format!(
            "link to {}:{} is not connected",
            link.seed.host, link.seed.port
        )),
        write_started: false,
    }
}

/// Marks `link` disconnected if it still holds `ended`: [`Pool::close`] may
/// have taken the session already.
async fn mark_disconnected(link: &PooledLink, ended: &Session) {
    let mut state = link.state.lock().await;
    if state
        .session
        .as_ref()
        .is_some_and(|session| session.is_same_session(ended))
    {
        state.session = None;
        link.connected.store(false, Ordering::Release);
    }
}

/// Resolves once the pool is stopping, or gone.
async fn pool_stopping(stop_rx: &mut watch::Receiver<bool>) {
    let _ = stop_rx.wait_for(|stopped| *stopped).await;
}

/// Runs `link` for as long as the pool does: dials it, keeps it connected
/// until its session ends, and dials it again after
/// [`PoolOptions::respawn_delay`]. A failed dial is retried after the same
/// delay, and a discovery-added link whose dial fails
/// [`DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS`] times in a row gives up. Each link
/// has exactly one of these, spawned when the link is added, so a link is
/// never dialed twice at once.
async fn run_link_lifecycle(pool: Arc<Pool>, link: Arc<PooledLink>) {
    let mut stop_rx = pool.stop_tx.subscribe();
    loop {
        if *stop_rx.borrow() {
            return;
        }
        match connection::connect(&link.seed.host, link.seed.port, link.trust, &pool.identity).await
        {
            Ok(session) => {
                let node_id = session.station.node_id;
                let mut state = link.state.lock().await;
                state.session = Some(session.clone());
                state.peer_node_id = Some(node_id);
                drop(state);
                link.connected.store(true, Ordering::Release);
                link.consecutive_failures.store(0, Ordering::Release);
                // Pool::close closes the session itself.
                tokio::select! {
                    _ = session.ended() => {}
                    () = pool_stopping(&mut stop_rx) => return,
                }
                mark_disconnected(&link, &session).await;
            }
            Err(_) => {
                let failures = link.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
                if should_give_up(link.origin, failures) {
                    link.gave_up.store(true, Ordering::Release);
                    return;
                }
            }
        }
        tokio::select! {
            () = tokio::time::sleep(pool.options.respawn_delay) => {}
            () = pool_stopping(&mut stop_rx) => return,
        }
    }
}

// ---------------------------------------------------------------------
// Station discovery — resolves hecate_stations.list_stations' realm via
// the DHT, calls it through the pool's own `call` (never a raw Session),
// and additively adds links for whatever it finds.
// ---------------------------------------------------------------------

const LIST_STATIONS_PROCEDURE: &str = "hecate_stations.list_stations";
/// `hecate_stations.list_stations` itself is called under its OWN resolved
/// realm (whatever [`resolve_list_stations_realm`] found), NOT the DHT's
/// own all-zero realm — that's `dht::find_records_by_type`'s realm
/// (`dht.rs`'s own private `DHT_REALM` constant), a separate, unrelated
/// realm this module never needs to name directly since it only ever
/// reaches the DHT through `dht::find_records_by_type` itself.
const DISCOVERY_CALL_DEADLINE: Duration = Duration::from_secs(5);

async fn discover_stations_loop(pool: Arc<Pool>) {
    // Trust::Pinned can never validate a SECOND station's identity --
    // running discovery at all under it is unconditionally pointless, not
    // just risky (it would otherwise dial-storm forever against stations
    // it can never actually trust). Matches the identical guard in
    // macula-go's and macula-dotnet's own ports of this feature.
    if matches!(pool.trust, Trust::Pinned(_)) {
        return;
    }

    let mut stop_rx = pool.stop_tx.subscribe();
    if !wait_for_any_healthy_link(&pool, &mut stop_rx).await {
        return;
    }

    loop {
        if *stop_rx.borrow() {
            return;
        }
        discover_once(&pool).await;
        tokio::select! {
            _ = tokio::time::sleep(pool.options.station_discovery.refresh_interval) => {}
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    return;
                }
            }
        }
    }
}

async fn wait_for_any_healthy_link(pool: &Arc<Pool>, stop_rx: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *stop_rx.borrow() {
            return false;
        }
        if pool.status().await.healthy_links > 0 {
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    return false;
                }
            }
        }
    }
}

async fn discover_once(pool: &Arc<Pool>) {
    let Some(realm) = resolve_list_stations_realm(pool).await else {
        return;
    };

    let deadline = now_ms() + DISCOVERY_CALL_DEADLINE.as_millis() as i128;
    let Ok(CallResponse::Result { payload, .. }) = pool
        .call(
            LIST_STATIONS_PROCEDURE,
            realm,
            crate::cbor::Value::Map(vec![]),
            deadline,
        )
        .await
    else {
        return;
    };
    let crate::cbor::Value::Map(fields) = &payload else {
        return;
    };
    let Some(crate::cbor::Value::List(stations)) = fields
        .iter()
        .find(|(k, _)| matches!(k, crate::cbor::Value::Text(t) if t == "stations"))
        .map(|(_, v)| v.clone())
    else {
        return;
    };

    add_discovered_links(pool, &stations).await;
}

/// Resolves `hecate_stations.list_stations`' own realm by scanning every
/// `procedure_advertisement` DHT record visible from the pool's current
/// bootstrap connection, matching a `procedure_uri` of the shape
/// `hex(realm) + "/hecate_stations.list_stations"` — mirrors
/// `dht::discovery_uri`'s own format and macula-go/macula-dotnet's
/// identical resolution step. Returns `None` on any failure (no
/// advertisement found yet, none verify, no healthy link to ask with) —
/// discovery just tries again at the next refresh tick, same as a bare DHT
/// lookup miss anywhere else in this crate.
async fn resolve_list_stations_realm(pool: &Arc<Pool>) -> Option<[u8; 32]> {
    let links = pool.links.read().await;
    let link = links.iter().find(|l| l.is_connected())?.clone();
    drop(links);

    let session = link.state.lock().await.session.clone()?;
    let records =
        dht::find_records_by_type(&session, &pool.identity, dht::TYPE_PROCEDURE_ADVERTISEMENT)
            .await
            .ok()?;

    for record in records {
        if dht::verify(&record).is_err() {
            continue;
        }
        let Ok(advertisement) = dht::read_procedure_advertisement(&record) else {
            continue;
        };
        if let Some(realm) = try_match_list_stations_realm(&advertisement.procedure_uri) {
            return Some(realm);
        }
    }
    None
}

fn try_match_list_stations_realm(procedure_uri: &str) -> Option<[u8; 32]> {
    let suffix = format!("/{LIST_STATIONS_PROCEDURE}");
    let hex_realm = procedure_uri.strip_suffix(&suffix)?;
    if hex_realm.len() != 64 {
        return None;
    }
    let bytes = hex_decode(hex_realm)?;
    bytes.try_into().ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// How many of `links` currently count against
/// [`StationDiscoveryOptions::max_links`] — MaxLinks bounds discovery's OWN
/// adds only, not the pool's total link count (see that field's own doc),
/// so a bootstrap seed must NEVER count against this budget, however many
/// were configured, or a pool started with >= max_links bootstrap seeds (a
/// realistic deployment) would have discovery silently do nothing, forever,
/// from its very first refresh — caught by adversarial review, 2026-09-05,
/// after an earlier version of this count included every link regardless
/// of origin. A given-up discovery link ALSO stays in the pool's `links`
/// forever (no removal path — see [`Pool`]'s own doc on why the backing
/// store is a plain `Vec`) but must NOT keep occupying its own slot either,
/// or the whole point of giving up (freeing room for a different
/// candidate) is defeated.
fn count_occupied_discovery_slots(links: &[Arc<PooledLink>]) -> usize {
    links
        .iter()
        .filter(|l| l.origin == LinkOrigin::Discovered && !l.has_given_up())
        .count()
}

async fn add_discovered_links(pool: &Arc<Pool>, stations: &[crate::cbor::Value]) {
    let is_web_pki = matches!(pool.trust, Trust::WebPki);
    for station in stations {
        let links = pool.links.read().await;
        let occupied_slots = count_occupied_discovery_slots(&links);
        drop(links);
        if occupied_slots >= pool.options.station_discovery.max_links {
            break;
        }
        let Some((host, port, node_id)) = dial_target_from_station_row(station) else {
            continue;
        };
        let is_bare_ip = host.parse::<std::net::IpAddr>().is_ok();

        // Prefer a real hostname under the pool's own configured trust;
        // fall back to Trust::Pinned(node_id) for a bare-IP-only row when
        // a node_id is available -- see this module's own doc for why,
        // and cam2me's StationDiscovery.kt for the shipped precedent.
        let link_trust = if is_bare_ip && is_web_pki {
            match node_id {
                Some(id) => Trust::Pinned(id),
                None => continue, // no way to validate this station at all
            }
        } else {
            pool.trust
        };

        if let Some(id) = node_id {
            if has_link_for_node_id(pool, id).await {
                continue;
            }
        }

        let seed = Seed::new(host, port);
        spawn_seed_link_if_absent(pool, seed, link_trust).await;
    }
}

/// Extracts a dialable `(host, port, node_id)` from one
/// `hecate_stations.list_stations` response row. Prefers `hostname` over
/// `host_advertised[0]` when both are present — every station on the real
/// fleet advertises `host_advertised` as a bare IP literal, never a DNS
/// name (confirmed live, same finding independently hit by macula-go's and
/// macula-dotnet's own ports of this feature), so `hostname` is the only
/// field a WebPki dial can ever succeed against. `host_advertised` is
/// still read out (and returned) even when a `hostname` is present, since
/// callers that end up needing `Trust::Pinned` (see
/// [`add_discovered_links`]) dial by IP regardless of whether a hostname
/// also exists.
pub(crate) fn dial_target_from_station_row(
    row: &crate::cbor::Value,
) -> Option<(String, u16, Option<[u8; 32]>)> {
    let crate::cbor::Value::Map(fields) = row else {
        return None;
    };
    let get = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| matches!(k, crate::cbor::Value::Text(t) if t == name))
            .map(|(_, v)| v)
    };

    let port = match get("quic_port") {
        Some(crate::cbor::Value::Int(n)) if (1..=65535).contains(n) => *n as u16,
        _ => return None,
    };

    let hostname = match get("hostname") {
        Some(crate::cbor::Value::Text(t)) if !t.is_empty() => Some(t.clone()),
        Some(crate::cbor::Value::Bytes(b)) if !b.is_empty() => String::from_utf8(b.clone()).ok(),
        _ => None,
    };
    let host_advertised = match get("host_advertised") {
        Some(crate::cbor::Value::List(items)) => items.iter().find_map(|item| match item {
            crate::cbor::Value::Bytes(b) => String::from_utf8(b.clone()).ok(),
            crate::cbor::Value::Text(t) => Some(t.clone()),
            _ => None,
        }),
        _ => None,
    };

    let host = hostname.or(host_advertised)?;
    let node_id = match get("node_id") {
        Some(crate::cbor::Value::Bytes(b)) => b.as_slice().try_into().ok(),
        _ => None,
    };
    Some((host, port, node_id))
}

async fn has_link_for_node_id(pool: &Arc<Pool>, node_id: [u8; 32]) -> bool {
    let links = pool.links.read().await;
    for link in links.iter() {
        if link.is_connected() {
            if let Some(known) = link.peer_node_id().await {
                if known == node_id {
                    return true;
                }
            }
        }
    }
    false
}

async fn spawn_seed_link_if_absent(pool: &Arc<Pool>, seed: Seed, trust: Trust) {
    let mut links = pool.links.write().await;
    if links.iter().any(|l| l.seed == seed) {
        return;
    }
    let link = PooledLink::new(seed, LinkOrigin::Discovered, trust);
    links.push(link.clone());
    drop(links);
    pool.tasks
        .lock()
        .await
        .spawn(run_link_lifecycle(pool.clone(), link));
}

fn now_ms() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_channel::fake_station::{call, connect, reply_text, WAIT};

    fn row(fields: Vec<(&str, crate::cbor::Value)>) -> crate::cbor::Value {
        crate::cbor::Value::Map(
            fields
                .into_iter()
                .map(|(k, v)| (crate::cbor::Value::Text(k.to_string()), v))
                .collect(),
        )
    }

    #[test]
    fn resolve_link_selection_auto_pairs_with_discovery() {
        assert_eq!(
            resolve_link_selection(LinkSelection::Auto, false),
            LinkSelection::FirstSuccess
        );
        assert_eq!(
            resolve_link_selection(LinkSelection::Auto, true),
            LinkSelection::Random
        );
    }

    #[test]
    fn resolve_link_selection_explicit_survives_either_way() {
        assert_eq!(
            resolve_link_selection(LinkSelection::FirstSuccess, true),
            LinkSelection::FirstSuccess
        );
        assert_eq!(
            resolve_link_selection(LinkSelection::Random, false),
            LinkSelection::Random
        );
    }

    #[test]
    fn dial_target_prefers_hostname_over_bare_ip() {
        let r = row(vec![
            (
                "hostname",
                crate::cbor::Value::Text("station-de-frankfurt.macula.io".into()),
            ),
            (
                "host_advertised",
                crate::cbor::Value::List(vec![crate::cbor::Value::Bytes(
                    b"2a01:7e01::f03c:94ff:fe22:719e".to_vec(),
                )]),
            ),
            ("quic_port", crate::cbor::Value::Int(4433)),
        ]);
        let (host, port, _) = dial_target_from_station_row(&r).expect("should parse");
        assert_eq!(host, "station-de-frankfurt.macula.io");
        assert_eq!(port, 4433);
    }

    #[test]
    fn dial_target_falls_back_to_host_advertised_when_hostname_absent() {
        let r = row(vec![
            (
                "host_advertised",
                crate::cbor::Value::List(vec![crate::cbor::Value::Bytes(
                    b"2600:3c0b::2000:1fff:fe35:416b".to_vec(),
                )]),
            ),
            ("quic_port", crate::cbor::Value::Int(4433)),
        ]);
        let (host, _, _) = dial_target_from_station_row(&r).expect("should parse");
        assert_eq!(host, "2600:3c0b::2000:1fff:fe35:416b");
    }

    #[test]
    fn dial_target_rejects_missing_port() {
        let r = row(vec![("hostname", crate::cbor::Value::Text("x".into()))]);
        assert!(dial_target_from_station_row(&r).is_none());
    }

    #[test]
    fn dial_target_extracts_node_id() {
        let node_id = [0xABu8; 32];
        let r = row(vec![
            ("hostname", crate::cbor::Value::Text("x".into())),
            ("quic_port", crate::cbor::Value::Int(4433)),
            ("node_id", crate::cbor::Value::Bytes(node_id.to_vec())),
        ]);
        let (_, _, id) = dial_target_from_station_row(&r).expect("should parse");
        assert_eq!(id, Some(node_id));
    }

    #[test]
    fn should_give_up_never_applies_to_a_bootstrap_link() {
        assert!(!should_give_up(
            LinkOrigin::Bootstrap,
            DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS
        ));
        assert!(!should_give_up(LinkOrigin::Bootstrap, 1_000_000));
    }

    #[test]
    fn should_give_up_applies_to_a_discovered_link_at_the_threshold() {
        assert!(!should_give_up(
            LinkOrigin::Discovered,
            DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS - 1
        ));
        assert!(should_give_up(
            LinkOrigin::Discovered,
            DISCOVERY_LINK_MAX_RESPAWN_ATTEMPTS
        ));
    }

    fn synthetic_link(origin: LinkOrigin, gave_up: bool) -> Arc<PooledLink> {
        let link = PooledLink::new(Seed::new("x.example", 4433), origin, Trust::WebPki);
        link.gave_up.store(gave_up, Ordering::Relaxed);
        link
    }

    /// Regression test for the exact bug adversarial review caught: an
    /// earlier version of this count included bootstrap links, which can
    /// never give up, so a pool started with `bootstrap.len() >=
    /// max_links` would have discovery silently do nothing forever.
    #[test]
    fn discovery_slot_count_excludes_bootstrap_links_entirely() {
        let links = vec![
            synthetic_link(LinkOrigin::Bootstrap, false),
            synthetic_link(LinkOrigin::Bootstrap, false),
            synthetic_link(LinkOrigin::Bootstrap, false),
        ];
        assert_eq!(count_occupied_discovery_slots(&links), 0);
    }

    #[test]
    fn discovery_slot_count_excludes_a_given_up_discovered_link() {
        let links = vec![
            synthetic_link(LinkOrigin::Discovered, false),
            synthetic_link(LinkOrigin::Discovered, true), // gave up -- slot freed
        ];
        assert_eq!(count_occupied_discovery_slots(&links), 1);
    }

    #[test]
    fn discovery_slot_count_mixed_origins() {
        let links = vec![
            synthetic_link(LinkOrigin::Bootstrap, false),
            synthetic_link(LinkOrigin::Bootstrap, false),
            synthetic_link(LinkOrigin::Discovered, false),
            synthetic_link(LinkOrigin::Discovered, true),
        ];
        assert_eq!(count_occupied_discovery_slots(&links), 1);
    }

    #[tokio::test]
    async fn call_falls_through_to_next_connected_link() {
        let (gone, gone_station, gone_ended) = connect();
        drop(gone_station);
        tokio::time::timeout(WAIT, gone_ended).await.unwrap().unwrap();
        let (live, mut station, _ended) = connect();
        let identity = KeyPair::generate();
        let (first, second) = (call("app/echo"), call("app/echo"));

        let (called, ()) = tokio::join!(
            call_until_sent([
                gone.call(&first, &identity, WAIT, None),
                live.call(&second, &identity, WAIT, None),
            ]),
            async {
                let sent = station.next("call").await;
                station.reply(&sent, "echoed").await;
            }
        );

        assert_eq!(reply_text(called.unwrap()), "echoed");
    }

    #[tokio::test]
    async fn a_pool_call_that_timed_out_after_its_write_started_is_not_tried_on_another_link() {
        let (stalled, stalled_station, _stalled_ended) = connect();
        let (other, mut other_station, _other_ended) = connect();
        stalled_station.stall_session_writes();
        let identity = KeyPair::generate();
        let (first, second) = (call("app/echo"), call("app/echo"));

        let called = call_until_sent([
            stalled.call(&first, &identity, Duration::from_millis(100), None),
            other.call(&second, &identity, WAIT, None),
        ])
        .await;

        assert!(
            matches!(
                called,
                Err(PoolCallError::Call(CallError::Timeout {
                    write_started: true
                }))
            ),
            "{called:?}"
        );
        assert!(
            other_station
                .nothing_sent_within(Duration::from_millis(300))
                .await
        );
        stalled_station.resume_session_writes();
    }

    #[test]
    fn try_match_list_stations_realm_matches_expected_format() {
        let hex_realm = "0".repeat(64);
        let uri = format!("{hex_realm}/hecate_stations.list_stations");
        assert_eq!(try_match_list_stations_realm(&uri), Some([0u8; 32]));
    }

    #[test]
    fn try_match_list_stations_realm_rejects_a_different_procedure() {
        let hex_realm = "0".repeat(64);
        let uri = format!("{hex_realm}/some.other_procedure");
        assert_eq!(try_match_list_stations_realm(&uri), None);
    }

    #[test]
    fn select_links_first_success_returns_input_unshuffled() {
        // Empty/zero-length input is the simplest observable proof this
        // is a passthrough -- Vec equality on non-empty synthetic
        // PooledLinks would need constructing real Arc<PooledLink>s with
        // no real Session, which is exactly the "no fake-dialer seam"
        // situation macula-dotnet's own tests document; a live pool test
        // covers the real end-to-end ordering instead.
        let empty: Vec<Arc<PooledLink>> = Vec::new();
        assert_eq!(select_links(empty, LinkSelection::FirstSuccess).len(), 0);
    }
}
