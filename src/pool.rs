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
mod member;
mod pubsub;
mod serve;

pub use crate::station_link::Confidentiality;
pub use crate::station_link::{ConfidentialityError, ConfidentialityReason};
pub use call::{Call, Provider, StreamCall};
pub use content::{content_procedure_bound, ContentOptions, CONTENT_PROCEDURE};
pub use pubsub::Subscription;
pub use serve::{Offer, Served};

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
                for (p, e) in tried {
                    write!(f, " [{} at {}: {e}]", short(&p.node), short(&p.station))?;
                }
                Ok(())
            }
            PoolError::ContentUnavailable(tried) => {
                f.write_str("no sharer gave the content:")?;
                for (node, e) in tried {
                    write!(f, " [{}: {e}]", short(node))?;
                }
                Ok(())
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
    issuer: StatementIssuer,
    publication_seq: Arc<PublicationSeq>,
    admission: Arc<Admission>,
    dedup: Arc<EventDedup>,
    /// One node identity, one keyring, shared by every link.
    keyring: Option<Arc<Keyring>>,
    state: Mutex<State>,
    ticks: tokio::task::JoinHandle<()>,
    content: content::Sharer,
}

struct State {
    members: Vec<Arc<Member>>,
    subs: HashMap<u64, Arc<pubsub::SubInner>>,
    served: HashMap<u64, Arc<serve::ServedInner>>,
    remember: HashMap<call::ResolvedKey, call::Candidate>,
    closed: bool,
}

/// One of the pool's links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatus {
    pub station: [u8; 32],
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
        let inner = Arc::new(PoolInner {
            self_id,
            issuer,
            publication_seq: Arc::default(),
            admission: Arc::new(Admission::new(admission)),
            dedup: Arc::default(),
            keyring,
            state: Mutex::new(State {
                members: Vec::new(),
                subs: HashMap::new(),
                served: HashMap::new(),
                remember: HashMap::new(),
                closed: false,
            }),
            ticks,
            content: content::Sharer::default(),
            opts,
        });
        let pool = Pool { inner };
        for seed in &seeds {
            pool.inner.start_member(pool.target(seed), false);
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
                host: m.target.host.clone(),
                port: m.target.port,
                direct: m.direct,
                up: m.current().is_some(),
            })
            .collect()
    }

    /// Ends every link with a GOODBYE and every subscription. It withdraws
    /// nothing: an advertisement lapses with its link.
    pub async fn close(&self) {
        let (members, subs) = {
            let mut state = self.inner.lock();
            if state.closed {
                return;
            }
            state.closed = true;
            state.served.clear();
            (
                std::mem::take(&mut state.members),
                std::mem::take(&mut state.subs),
            )
        };
        self.inner.ticks.abort();
        for m in &members {
            m.retire();
        }
        for m in &members {
            m.stopped().await;
        }
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
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The links up now, in the pool's selection order.
    fn links(&self) -> Vec<Link> {
        let members = self.lock().members.clone();
        let mut up: Vec<Link> = members.iter().filter_map(|m| m.current()).collect();
        if self.opts.link_selection == LinkSelection::Random {
            shuffle(&mut up);
        }
        up
    }

    /// Waits until a link is up, or `deadline` passes.
    async fn await_up(self: &Arc<Self>, deadline: tokio::time::Instant) -> Result<(), PoolError> {
        loop {
            if !self.links().is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let members = self.lock().members.clone();
                return Err(PoolError::NoLink(
                    members.iter().filter_map(|m| m.last_error()).collect(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn event(&self, e: LinkEvent) {
        if let Some(f) = self.opts.on_link_event.clone() {
            tokio::spawn(async move { f(e) });
        }
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
    let admission = opts.admission.unwrap_or_else(|| {
        let mut limits = AdmissionLimits::default();
        limits.cap = limits.share * (opts.max_seeds + opts.max_direct_links);
        limits
    });
    admission
        .validate()
        .map_err(|e| PoolError::InvalidOpts(e.to_string()))?;
    opts.admission = Some(admission);
    if seeds.is_empty() {
        return Err(PoolError::NoSeeds);
    }
    if seeds.len() > opts.max_seeds {
        return Err(PoolError::TooManySeeds {
            given: seeds.len(),
            max: opts.max_seeds,
        });
    }
    if let Some(unpinned) = seeds.iter().find(|s| s.node_id == [0; 32]) {
        return Err(PoolError::SeedNotPinned(format!(
            "{}:{}",
            unpinned.host, unpinned.port
        )));
    }
    Ok(opts)
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
