//! A macula 12 node's set of station links, as macula's client pool keeps
//! them: one link to each seed station, every seed pinned by its node_id,
//! all links of one node sharing its identity key, statement issuer, request
//! admission, publication seq and event dedup. A link that ends is dialed
//! again after the respawn delay and given back the node's subscriptions and
//! served procedures.
//!
//! Calls reach providers directly, as macula 12 calls them: the procedure's
//! advertisements are resolved from the DHT and checked against the realm key
//! the pool pins for the realm, the serving station an advertisement names is
//! dialed (pinned by its node_id, from its own station_endpoint record) and
//! the provider called there. Station procedures (`_dht.*`) go to the pool's
//! links.
//!
//! Station discovery beyond the seeds is not here: macula discovers stations
//! through mcl-stations/list_stations, which this pool does not call.

mod call;
mod content;
mod delivery;
mod group;
mod member;
mod pubsub;
mod resend;
mod serve;
mod tier;

pub use crate::station_link::Confidentiality;
use crate::station_link::SignedPublication;
pub use crate::station_link::{ConfidentialityError, ConfidentialityReason, Report, ReportError};
pub use call::{Call, Provider, StreamCall};
pub use content::{content_procedure_bound, ContentOptions, CONTENT_PROCEDURE};
pub use delivery::{Delivery, Gap, Interruption};
pub use pubsub::Subscription;
pub use serve::{Offer, Served};
pub use tier::{
    Redial, Tier, DEFAULT_REDIAL_BASE, DEFAULT_REDIAL_CAP, DEFAULT_REDIAL_FACTOR,
    DEFAULT_REDIAL_STEADY_UP,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::node_key::{carried_key_well_formed, NodeKey, Purpose};
use crate::seal::Keyring;
use crate::statement_issuer::{IssuerError, StatementIssuer};
use crate::station_link::{
    Admission, AdmissionLimits, EventDedup, Link, LinkError, PublicationSeq,
};
use crate::transport::Target;

use member::Member;

/// macula's defaults and caps for a pool's bounds.
pub const DEFAULT_REPLICATION_FACTOR: usize = 2;
pub const DEFAULT_RESPAWN_DELAY: Duration = Duration::from_secs(1);
pub const DEFAULT_MAX_SEEDS: usize = 16;
pub const DEFAULT_MAX_DIRECT_LINKS: usize = 8;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LINK_LIMIT: usize = 64;

/// Why a pool, or one of its operations, failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// A pool given no seed station.
    NoSeeds,
    /// A seed without the station's node_id, as host:port: a pool dials
    /// only stations it can check.
    SeedNotPinned(String),
    /// More seeds than `max_seeds`.
    TooManySeeds { given: usize, max: usize },
    /// A realm key that is not a well-formed key of the pool's profile, and
    /// its realm.
    RealmTrustInvalid([u8; 32]),
    /// A station named in both the public and the fallback list, which has no
    /// defined role.
    StationInBothTiers { station: [u8; 32] },
    /// An option out of its range, or a key that is no identity key.
    InvalidOpts(String),
    /// No link came up within the connect timeout, or none is up to carry an
    /// operation; each link's last error.
    NoLink(Vec<LinkError>),
    /// An operation on a closed pool.
    Closed,
    /// A realm the pool pins no key for: nothing in it is served or trusted.
    NoRealmKey,
    /// No provider the pinned realm key authorizes answered: each candidate
    /// tried and why it failed; none when there was no candidate at all.
    NoProvider(Vec<(Provider, PoolError)>),
    /// A serving station with no endpoint record it signed itself.
    NoStationEndpoint(Option<LinkError>),
    /// A serving station not yet linked while `max_direct_links` direct
    /// links are held.
    DirectLinksFull,
    /// A station that could not be linked, and the last dial's error.
    StationNotReached {
        station: [u8; 32],
        cause: Option<LinkError>,
    },
    /// A procedure no link would serve, and each link's error.
    NotServed(Vec<LinkError>),
    /// A link's own failure, or a provider's or station's answer.
    Link(LinkError),
    /// Content no node announces in the realm, or a sharer that does not
    /// hold it.
    NotShared,
    /// Content every announcing sharer failed to give: each sharer's node
    /// and why.
    ContentUnavailable(Vec<([u8; 32], PoolError)>),
    /// A block, manifest or whole that does not match the content id it was
    /// asked for by, and which.
    ContentMismatch(String),
    /// Content over the fetch's bounds, and how large.
    ContentTooLarge(String),
    /// An answer a sharer never gives, and what it was.
    ContentReply(String),
    /// A call or an open that could not be kept confidential, so nothing
    /// was sent.
    Confidentiality(ConfidentialityError),
    /// A publish in the clear under a prefix whose sealed group this node
    /// holds, and that prefix.
    GroupHeld(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::Link(e) => write!(f, "{e}"),
            PoolError::Confidentiality(e) => write!(f, "{e}"),
            PoolError::NoProvider(tried) if tried.is_empty() => {
                f.write_str("no trusted provider advertises the procedure")
            }
            PoolError::NoProvider(tried) => {
                f.write_str("no trusted provider answered:")?;
                write_providers_tried(f, tried)
            }
            PoolError::ContentUnavailable(tried) => {
                f.write_str("no sharer gave the content:")?;
                write_sharers_tried(f, tried)
            }
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for PoolError {}

impl From<LinkError> for PoolError {
    fn from(e: LinkError) -> Self {
        PoolError::Link(e)
    }
}

/// Each provider tried, at its station, and why it failed.
fn write_providers_tried(
    f: &mut fmt::Formatter<'_>,
    tried: &[(Provider, PoolError)],
) -> fmt::Result {
    for (p, e) in tried {
        write!(f, " [{} at {}: {e}]", short(&p.node), short(&p.station))?;
    }
    Ok(())
}

/// Each sharer tried and why it failed.
fn write_sharers_tried(f: &mut fmt::Formatter<'_>, tried: &[([u8; 32], PoolError)]) -> fmt::Result {
    for (node, e) in tried {
        write!(f, " [{}: {e}]", short(node))?;
    }
    Ok(())
}

fn short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// A station to link to: where it is dialed and the node_id it must prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub host: String,
    pub port: u16,
    pub node_id: [u8; 32],
}

/// The order calls, publications and DHT operations try the pool's links in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkSelection {
    /// The links in seed order.
    #[default]
    FirstSuccess,
    /// A fresh random order each time.
    Random,
}

/// A link coming up, or ending or failing to dial with its error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEvent {
    pub station: [u8; 32],
    /// The tier the station was named in: [`Tier::Public`] for a seed and for
    /// a station dialed directly, [`Tier::Fallback`] for a fallback seed.
    pub tier: Tier,
    pub direct: bool,
    pub up: bool,
    pub error: Option<LinkError>,
}

/// A pool's configuration. [`Opts::new`] gives macula's defaults; a zero
/// bound also means its default.
#[derive(Clone)]
pub struct Opts {
    /// The node's identity key; its profile is the pool's.
    pub identity: Arc<NodeKey>,
    /// Each realm's key as carried: an advertisement in a realm is trusted
    /// only when its authorization verifies against it, and an org
    /// procedure is served only in a realm it names.
    pub realm_trust: HashMap<[u8; 32], Vec<u8>>,
    pub replication_factor: usize,
    pub respawn_delay: Duration,
    /// The stations of the fallback tier: the LAN stations a node keeps for
    /// when no public station is up. Empty — the default — means one tier, and
    /// the pool behaves exactly as it did before there were tiers.
    pub fallback_seeds: Vec<Seed>,
    /// How a link whose tier is not active is redialed, and how long a link
    /// must stay up before its counter resets.
    pub redial: Redial,
    pub max_seeds: usize,
    pub max_direct_links: usize,
    /// How long [`Pool::connect`] waits for a first link.
    pub connect_timeout: Duration,
    /// Bounds on the requests the node's served procedures take; `None` is
    /// macula's defaults, with the cap one share per link the pool may hold.
    pub admission: Option<AdmissionLimits>,
    pub link_selection: LinkSelection,
    /// Gives the node a KEM keyring and names its current key in the
    /// advertisements of procedures served confidentially (macula 13, E2E
    /// design amendment A1), so callers seal to it. Off by default: switch it
    /// on only once every station runs macula 12.11 or later and every
    /// caller runs 13. Without it the node opens no sealed request.
    pub kem_advertise: bool,
    /// Hears every link coming up and going down, on a task of its own.
    pub on_link_event: Option<Arc<dyn Fn(LinkEvent) + Send + Sync>>,
    /// Hears each failure to reissue the node's status statements or rotate
    /// its CONNECT key; `None` writes it to stderr. Left failing, the links
    /// end when their statements lapse.
    pub on_issuer_error: Option<Arc<dyn Fn(IssuerError) + Send + Sync>>,
}

impl Opts {
    /// macula's defaults for `identity`, trusting no realm.
    pub fn new(identity: Arc<NodeKey>) -> Opts {
        Opts {
            identity,
            realm_trust: HashMap::new(),
            replication_factor: DEFAULT_REPLICATION_FACTOR,
            respawn_delay: DEFAULT_RESPAWN_DELAY,
            fallback_seeds: Vec::new(),
            redial: Redial::default(),
            max_seeds: DEFAULT_MAX_SEEDS,
            max_direct_links: DEFAULT_MAX_DIRECT_LINKS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            admission: None,
            link_selection: LinkSelection::FirstSuccess,
            kem_advertise: false,
            on_link_event: None,
            on_issuer_error: None,
        }
    }
}

/// A node's station links. Cloning it shares the pool; the pool closes when
/// [`Pool::close`] is called or its last handle is dropped.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

pub(crate) struct PoolInner {
    opts: Opts,
    self_id: [u8; 32],
    /// Whether a fallback list was configured at all: what tells a tier of
    /// "no public link up" from a pool that never had two tiers.
    has_fallback: bool,
    /// Each configured seed's role, by the station's node_id. A station not
    /// here — one dialed directly — is public.
    roles: HashMap<[u8; 32], Tier>,
    /// Tells every member waiting out a backoff that the active tier may have
    /// moved, so a retry of the tier that just became active can restart at
    /// the floor.
    tier_moved: tokio::sync::Notify,
    issuer: StatementIssuer,
    publication_seq: Arc<PublicationSeq>,
    admission: Arc<Admission>,
    dedup: Arc<EventDedup>,
    /// One node identity, one keyring, shared by every link.
    keyring: Option<Arc<Keyring>>,
    /// The sealed groups this node holds, made on the first join and pulling
    /// over this pool's own sealed calls.
    groups: Mutex<Option<crate::group::Keyring>>,
    state: Mutex<State>,
    ticks: tokio::task::JoinHandle<()>,
    content: content::Sharer,
    /// Publications accepted and never delivered (see [`Pool::unsent_publications`]).
    unsent: std::sync::atomic::AtomicU64,
}

struct State {
    members: Vec<Arc<Member>>,
    subs: HashMap<u64, Arc<pubsub::SubInner>>,
    served: HashMap<u64, Arc<serve::ServedInner>>,
    remember: HashMap<call::ResolvedKey, call::Candidate>,
    closed: bool,
    /// What ended links had not delivered, for the next link up.
    waiting: resend::Waiting,
}

/// What a closing pool ends: its links and its subscriptions.
type Closing = (Vec<Arc<Member>>, HashMap<u64, Arc<pubsub::SubInner>>);

/// One of the pool's links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatus {
    pub station: [u8; 32],
    /// The tier the station was named in.
    pub tier: Tier,
    pub host: String,
    pub port: u16,
    pub direct: bool,
    pub up: bool,
}

impl Pool {
    /// Checks `seeds` and `opts`, dials every seed, and returns once one link
    /// is up, or [`PoolError::NoLink`] with each link's last error when the
    /// connect timeout passes first. Links not yet up keep dialing.
    pub async fn connect(seeds: Vec<Seed>, opts: Opts) -> Result<Pool, PoolError> {
        let opts = checked(&seeds, opts)?;
        let pool = Pool {
            inner: PoolInner::open(&seeds, opts)?,
        };
        for seed in &seeds {
            pool.inner
                .start_member(pool.target(seed), false, Tier::Public);
        }
        for seed in &pool.inner.opts.fallback_seeds {
            pool.inner
                .start_member(pool.target(seed), false, Tier::Fallback);
        }
        let deadline = tokio::time::Instant::now() + pool.inner.opts.connect_timeout;
        if let Err(e) = pool.inner.await_up(deadline).await {
            pool.close().await;
            return Err(e);
        }
        Ok(pool)
    }

    fn target(&self, seed: &Seed) -> Target {
        Target {
            host: seed.host.clone(),
            port: seed.port,
            profile: self.inner.opts.identity.profile(),
            expected_node_id: seed.node_id,
        }
    }

    /// The node_id the pool links as.
    pub fn node_id(&self) -> [u8; 32] {
        self.inner.self_id
    }

    /// Every link the pool holds, seeds first.
    pub fn status(&self) -> Vec<LinkStatus> {
        let members = self.inner.lock().members.clone();
        members
            .iter()
            .map(|m| LinkStatus {
                station: m.target.expected_node_id,
                tier: m.tier,
                host: m.target.host.clone(),
                port: m.target.port,
                direct: m.direct,
                up: m.current().is_some(),
            })
            .collect()
    }

    /// The tier the pool's originating traffic belongs to: public the moment
    /// any public link is up, fallback only when none is and a fallback list
    /// was configured. A pool with no fallback list is public even with every
    /// link down, so "no link up" fails exactly as it did before there were
    /// tiers.
    ///
    /// A caller reads it to say which tier it is on — "offline: on the LAN
    /// fallback" — rather than failing silently. It decides nothing itself: an
    /// operation already selects from the active tier.
    pub fn active_tier(&self) -> Tier {
        self.inner.active_tier()
    }

    /// Ends every link with a GOODBYE and every subscription. It withdraws
    /// nothing: an advertisement lapses with its link.
    pub async fn close(&self) {
        let Some((members, subs)) = self.inner.mark_closed() else {
            return;
        };
        self.inner.ticks.abort();
        if let Some(groups) = self
            .inner
            .groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            groups.close();
        }
        for m in &members {
            m.retire();
        }
        for m in &members {
            m.stopped().await;
        }
        self.inner.give_up_waiting();
        for sub in subs.into_values() {
            let _ = sub.end().await;
        }
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("node_id", &short(&self.inner.self_id))
            .field("links", &self.status())
            .finish()
    }
}

impl PoolInner {
    /// Everything a pool needs before its first link is dialed: its node_id,
    /// its statement issuer, the key it seals to when it advertises KEM, and
    /// the state every member shares. `opts` must have been through `checked`.
    fn open(seeds: &[Seed], opts: Opts) -> Result<Arc<PoolInner>, PoolError> {
        let self_id = opts
            .identity
            .node_id()
            .map_err(|e| PoolError::InvalidOpts(e.to_string()))?;
        let issuer = StatementIssuer::with_wall_clock(opts.identity.clone())
            .map_err(|e| PoolError::InvalidOpts(e.to_string()))?;
        let on_error = opts.on_issuer_error.clone();
        let ticks = issuer.spawn_ticks(move |e| match &on_error {
            Some(f) => f(e),
            None => eprintln!("macula-rust pool: the statement issuer failed: {e}"),
        });
        let admission = opts.admission.expect("checked fills the admission limits");
        let keyring = match opts.kem_advertise {
            true => Some(Arc::new(
                Keyring::system(opts.identity.profile())
                    .map_err(|e| PoolError::InvalidOpts(e.to_string()))?,
            )),
            false => None,
        };
        Ok(Arc::new(PoolInner {
            self_id,
            has_fallback: !opts.fallback_seeds.is_empty(),
            roles: roles_of(seeds, &opts.fallback_seeds),
            tier_moved: tokio::sync::Notify::new(),
            issuer,
            publication_seq: Arc::default(),
            admission: Arc::new(Admission::new(admission)),
            dedup: Arc::default(),
            keyring,
            groups: Mutex::new(None),
            state: Mutex::new(State {
                members: Vec::new(),
                subs: HashMap::new(),
                served: HashMap::new(),
                remember: HashMap::new(),
                closed: false,
                waiting: resend::Waiting::new(),
            }),
            ticks,
            content: content::Sharer::default(),
            unsent: std::sync::atomic::AtomicU64::new(0),
            opts,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Marks the pool closed, forgets what it serves, and hands back its
    /// links and subscriptions to end; nothing when it was closed already.
    fn mark_closed(&self) -> Option<Closing> {
        let mut state = self.lock();
        if state.closed {
            return None;
        }
        state.closed = true;
        state.served.clear();
        Some((
            std::mem::take(&mut state.members),
            std::mem::take(&mut state.subs),
        ))
    }

    /// Sends a signed publication on the first `replication_factor` links of
    /// the active tier, in the pool's selection order, succeeding when one of
    /// them takes it. One live public link with a factor of two publishes to
    /// one station: the fan-out is a maximum *within* the active tier, never a
    /// reason to reach into the other one.
    pub(super) async fn send_signed(&self, signed: &SignedPublication) -> Result<(), PoolError> {
        let links = self.targets();
        if links.is_empty() {
            return Err(PoolError::NoLink(Vec::new()));
        }
        let mut errors = Vec::new();
        let mut sent = 0;
        for link in links.iter().take(self.opts.replication_factor) {
            match link.publish_signed(signed).await {
                Ok(()) => sent += 1,
                Err(e) => errors.push(e),
            }
        }
        if sent == 0 {
            return Err(PoolError::NoLink(errors));
        }
        Ok(())
    }

    /// The links up now, in the pool's selection order: every tier's, for a
    /// standing registration, which is state and belongs on every link.
    fn links(&self) -> Vec<Link> {
        let mut up = self.links_up();
        if self.opts.link_selection == LinkSelection::Random {
            shuffle(&mut up);
        }
        up
    }

    /// The links up now, in the order the members were started.
    fn links_up(&self) -> Vec<Link> {
        let members = self.lock().members.clone();
        members.iter().filter_map(|m| m.current()).collect()
    }

    /// The links up now on the pool's active tier, fastest first: what an
    /// originating operation — a publication, a station procedure, a content
    /// announcement, a re-sent publication — selects from. Never a standing
    /// registration, which takes every link of both tiers and never this.
    fn targets(&self) -> Vec<Link> {
        let active = self.active_tier();
        let links: Vec<Link> = self
            .links_up()
            .into_iter()
            .filter(|link| self.tier_of(&link.station_node_id()) == active)
            .collect();
        self.ordered(links)
    }

    /// The tier `station` was named in: its configured role, or public for a
    /// station dialed directly or already forgotten.
    fn tier_of(&self, station: &[u8; 32]) -> Tier {
        self.roles.get(station).copied().unwrap_or(Tier::Public)
    }

    /// The tier the pool's originating traffic belongs to. See
    /// [`Pool::active_tier`].
    fn active_tier(&self) -> Tier {
        let members = self.lock().members.clone();
        let public_up = members
            .iter()
            .any(|m| m.tier == Tier::Public && m.current().is_some());
        match public_up || !self.has_fallback {
            true => Tier::Public,
            false => Tier::Fallback,
        }
    }

    /// `links` in the pool's selection order: fastest measured round trip
    /// first, and the order they came in for `Random`, which discards the
    /// measurement by definition.
    fn ordered(&self, mut links: Vec<Link>) -> Vec<Link> {
        match self.opts.link_selection {
            LinkSelection::Random => shuffle(&mut links),
            LinkSelection::FirstSuccess => links.sort_by_key(|l| rtt_key(l.rtt())),
        }
        links
    }

    /// Tells every member waiting out a backoff that the active tier may have
    /// moved: the newly active tier's pending retries restart at the floor.
    fn tier_may_have_moved(&self) {
        self.tier_moved.notify_waiters();
    }

    /// Waits until a link is up, or `deadline` passes.
    async fn await_up(self: &Arc<Self>, deadline: tokio::time::Instant) -> Result<(), PoolError> {
        while self.links().is_empty() {
            self.before_deadline(deadline)?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// Nothing while `deadline` is ahead; past it, [`PoolError::NoLink`] with
    /// each link's last error.
    fn before_deadline(&self, deadline: tokio::time::Instant) -> Result<(), PoolError> {
        if tokio::time::Instant::now() < deadline {
            return Ok(());
        }
        let members = self.lock().members.clone();
        Err(PoolError::NoLink(
            members.iter().filter_map(|m| m.last_error()).collect(),
        ))
    }

    fn event(&self, e: LinkEvent) {
        let Some(f) = self.opts.on_link_event.clone() else {
            return;
        };
        tokio::spawn(async move { f(e) });
    }

    /// The key a procedure's authorization is checked against: the realm's
    /// pinned key, or none for a procedure in a node's own namespace, which
    /// its advertisement's signature alone authorizes.
    fn realm_key_for(
        &self,
        realm: &[u8; 32],
        procedure: &str,
    ) -> Result<Option<Vec<u8>>, PoolError> {
        if crate::record::in_own_namespace(procedure) {
            return Ok(None);
        }
        self.opts
            .realm_trust
            .get(realm)
            .cloned()
            .map(Some)
            .ok_or(PoolError::NoRealmKey)
    }
}

impl Drop for PoolInner {
    /// A pool whose last handle is dropped stops dialing and closes its links.
    fn drop(&mut self) {
        self.ticks.abort();
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        for m in &state.members {
            m.retire();
        }
    }
}

/// Refuses, before anything is dialed, what macula's pool refuses, and fills
/// in the defaults.
fn checked(seeds: &[Seed], mut opts: Opts) -> Result<Opts, PoolError> {
    refuse_bad_opts(&opts)?;
    fill_defaults(&mut opts)?;
    fill_admission(&mut opts)?;
    refuse_bad_seeds(seeds, &opts)?;
    Ok(opts)
}

/// Refuses an identity that is not one, a realm key of the wrong shape, and a
/// limit outside `1` to [`MAX_LINK_LIMIT`].
fn refuse_bad_opts(opts: &Opts) -> Result<(), PoolError> {
    if opts.identity.purpose() != Purpose::Identity {
        return Err(PoolError::InvalidOpts("an identity key is required".into()));
    }
    let profile = opts.identity.profile();
    for (realm, key) in &opts.realm_trust {
        if !carried_key_well_formed(key, profile) {
            return Err(PoolError::RealmTrustInvalid(*realm));
        }
    }
    for (name, limit) in [
        ("max_seeds", opts.max_seeds),
        ("max_direct_links", opts.max_direct_links),
        ("replication_factor", opts.replication_factor),
    ] {
        if limit > MAX_LINK_LIMIT {
            return Err(PoolError::InvalidOpts(format!(
                "{name} of {limit}, outside 1 to {MAX_LINK_LIMIT}"
            )));
        }
    }
    Ok(())
}

/// Fills a zero bound with its default, the redial schedule included: a
/// schedule that never backs off is refused here.
fn fill_defaults(opts: &mut Opts) -> Result<(), PoolError> {
    let or_default = |v: usize, d: usize| if v == 0 { d } else { v };
    opts.max_seeds = or_default(opts.max_seeds, DEFAULT_MAX_SEEDS);
    opts.max_direct_links = or_default(opts.max_direct_links, DEFAULT_MAX_DIRECT_LINKS);
    opts.replication_factor = or_default(opts.replication_factor, DEFAULT_REPLICATION_FACTOR);
    if opts.respawn_delay.is_zero() {
        opts.respawn_delay = DEFAULT_RESPAWN_DELAY;
    }
    if opts.connect_timeout.is_zero() {
        opts.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    }
    opts.redial = opts
        .redial
        .checked()
        .map_err(|why| PoolError::InvalidOpts(why.to_string()))?;
    Ok(())
}

/// Fills admission limits the caller left out from the link counts, and
/// refuses a set that cannot hold them.
fn fill_admission(opts: &mut Opts) -> Result<(), PoolError> {
    let limits = opts.admission.unwrap_or_else(|| {
        let mut limits = AdmissionLimits::default();
        limits.cap = limits.share * (opts.max_seeds + opts.max_direct_links);
        limits
    });
    limits
        .validate()
        .map_err(|e| PoolError::InvalidOpts(e.to_string()))?;
    opts.admission = Some(limits);
    Ok(())
}

/// Refuses a pool with no seed, more stations than `max_seeds` allows, a seed
/// that names no station, and a station named in both tiers.
fn refuse_bad_seeds(seeds: &[Seed], opts: &Opts) -> Result<(), PoolError> {
    if seeds.is_empty() {
        return Err(PoolError::NoSeeds);
    }
    let stations = seeds.len() + opts.fallback_seeds.len();
    if stations > opts.max_seeds {
        return Err(PoolError::TooManySeeds {
            given: stations,
            max: opts.max_seeds,
        });
    }
    for list in [seeds, opts.fallback_seeds.as_slice()] {
        if let Some(unpinned) = list.iter().find(|s| s.node_id == [0; 32]) {
            return Err(PoolError::SeedNotPinned(format!(
                "{}:{}",
                unpinned.host, unpinned.port
            )));
        }
    }
    match named_twice(seeds, &opts.fallback_seeds) {
        Some(seed) => Err(PoolError::StationInBothTiers {
            station: seed.node_id,
        }),
        None => Ok(()),
    }
}

/// A station named in both lists: the same node_id at any address, or the same
/// address under any node_id. One station holding two roles has no defined
/// behaviour, so the pool refuses it rather than picking one.
fn named_twice<'a>(public: &'a [Seed], fallback: &'a [Seed]) -> Option<&'a Seed> {
    fallback.iter().find(|f| {
        public
            .iter()
            .any(|p| p.node_id == f.node_id || (p.host == f.host && p.port == f.port))
    })
}

/// Fisher-Yates over the system's randomness.
fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let mut r = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut r).is_err() {
            return;
        }
        let j = (u64::from_le_bytes(r) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// A link's sort key: measured links by their round trip, ascending, and a
/// link with no measurement after every measured one (macula's
/// `rank_compare/2`).
fn rtt_key(rtt: Option<Duration>) -> (bool, Duration) {
    match rtt {
        Some(rtt) => (false, rtt),
        None => (true, Duration::ZERO),
    }
}

/// Each seed's role, by the station's node_id: the public list, then the
/// fallback one. A station in both is refused before this is called.
fn roles_of(public: &[Seed], fallback: &[Seed]) -> HashMap<[u8; 32], Tier> {
    let mut roles: HashMap<[u8; 32], Tier> = HashMap::new();
    for seed in public {
        roles.insert(seed.node_id, Tier::Public);
    }
    for seed in fallback {
        roles.insert(seed.node_id, Tier::Fallback);
    }
    roles
}
