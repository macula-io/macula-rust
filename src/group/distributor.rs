//! A sealed group's distributor (DESIGN_E2E_SEALED_PUBSUB.md sections 3 and
//! 5): the handler of `<org>/group_keys_v1` and the epochs of every group it
//! serves. The counterpart of macula's `macula_group_keys`, and the other half
//! of [`Keyring`](super::Keyring), which pulls from it.
//!
//! The application serves it as it serves any procedure, through
//! [`Pool::serve`](crate::pool::Pool::serve) with [`Distributor::offer`]: the
//! org's `group_keys` grant is checked by the pool before the handler runs
//! ([`ucan::Policy::RealmMemberRequired`](crate::ucan::Policy::RealmMemberRequired),
//! matched to the org key by its key id, as macula's
//! `{realm_member_required, OrgKeyId, <<"group_keys">>}` is), and the offer is
//! sealed only (`Confidentiality::Required`), so a clear pull is refused
//! `sealed_required` and a key never travels clear. A node whose
//! `kem_advertise` is off refuses to serve it at all
//! ([`LinkError::KemAdvertiseDisabled`](crate::station_link::LinkError::KemAdvertiseDisabled))
//! rather than advertise a keyless distributor: both sides enforce it, since
//! a member pulls sealed only too.
//!
//! The handler decides from the caller's wire-authenticated node id, and the
//! application answers two questions, both taking the group's prefix: one host
//! distributor serves several groups, and a per-caller answer would apply one
//! group's removal to another.
//!
//! - [`DistributorOptions::removed`] is asked first: a node in it is refused
//!   every epoch, past or current, whatever it shows. The set is the
//!   application's state, and the application keeps it across a restart: a set
//!   lost to one re-admits every removed member whose grant still verifies.
//!   It is asked again once the membership answer is back, so a node removed
//!   while its lookup ran is refused rather than admitted on an answer that was
//!   true when it was asked.
//! - [`DistributorOptions::membership`] is then read at the time of the call,
//!   for a past epoch too, and answers [in](Membership::In),
//!   [not a member](Membership::NotAMember) or
//!   [unknown](Membership::Unknown). A check that does not answer within
//!   [`DistributorOptions::membership_timeout`] is `membership_unknown`, never
//!   `not_a_member`, so the member retries rather than being told it is out.
//!   The pulls in flight share one lookup per group and caller, and past
//!   [`MAX_LOOKUPS`] of them a pull is `membership_unknown` rather than one
//!   more: one caller cannot put every other member's pulls behind an
//!   unbounded queue of lookups.
//!
//! A pull names the group (`prefix`) and the epoch: `current`, or a past one
//! by its 8-byte id. The reply carries the group's policy and the epochs: the
//! asked one, and inside the current's ahead window the next one too. Epoch
//! keys are kept in memory only, and never printed
//! ([`Epoch`](super::Epoch)'s `Debug` redacts them); a reply's key bytes are
//! wiped from memory once the reply is sealed. A refusal is one of the design's
//! five, named exactly as every SDK names it: `not_a_member`,
//! `membership_unknown`, `unknown_epoch`, `epoch_expired` and `unknown_group`.
//! A pull that did not arrive sealed is refused `sealed_required` by the
//! handler itself, whatever offer it was served under.
//!
//! **The store is bounded.** A pull names a group, and any caller the org's
//! grant admits may name a new one, so the epochs one host holds are what an
//! admitted caller can make it grow. [`Caps`] holds it to a number of groups
//! per member, a number of groups in all, and a number of epochs per group's
//! chain; a group nobody pulls is dropped once no epoch of it is kept, so
//! what it held comes back. Each cap names itself in the failure's detail
//! (`too_many_groups_member`, `too_many_groups`, `too_many_epochs`) and
//! none of them is one of the design's five, so a member reads a full
//! distributor as a failed pull and retries, never as a reason to stop.
//!
//! **A key is erased as soon as no event under it can be accepted**, and not
//! at the group's next pull: an epoch past its acceptance keeps only its id,
//! so a pull of it is still answered `epoch_expired` rather than
//! `unknown_epoch`, and that id is dropped a rotation later. The sweeper
//! started by the first pull that holds anything sleeps to the earliest of
//! those instants on the distributor's own clock, so the erasure happens on
//! an idle distributor too; [`Distributor::erase_spent`] does the same work
//! for an application that would rather time it.
//!
//! **The knobs are checked when the distributor is made.** A rotation outside
//! one millisecond to a day, a cap of zero, and an epoch cap below what one
//! group's chain needs at the configured rotation are each refused by
//! [`Distributor::new`]: every one of them leaves a distributor that answers
//! its first pulls and then cannot answer any, so an operator reads which one
//! it is at construction rather than from a member's failed pulls seventy
//! minutes later.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tokio::time::timeout;

use crate::cbor::Value;
use crate::pool::Offer;
use crate::seal::Clock;
use crate::station_link::{handler, Confidentiality, Handler, Request, CODE_SEALED_REQUIRED};
use crate::ucan::Policy as Grant;

use super::epoch::{for_publish, fresh, org_of, wall_clock, NoRandomness, TOLERANCE_MS};
use super::wire::{procedure, reply_value, Policy, Reply};
use super::{Epoch, DEFAULT_ROTATE_AFTER_MS, EVENT_LIFE_MS, ID_SIZE};

/// The capability an org's grant carries for its groups' keys (section 3).
pub const GROUP_KEYS_CAN: &str = "group_keys";

/// How long a distributor waits for the application's membership check before
/// it answers `membership_unknown`: macula's 12 seconds, past a slot read's 5
/// and inside a member's 15-second pull deadline, so no answer is made that no
/// member still waits for.
pub const DEFAULT_MEMBERSHIP_TIMEOUT: Duration = Duration::from_secs(12);

/// The most membership lookups one distributor runs at once, macula's
/// `MAX_LOOKUPS`. Every pull asks the application about its caller, so without
/// a bound one admitted caller's pulls — as many as the link admits — would
/// have every other member's pulls waiting on lookups behind them. Past it a
/// pull is answered `membership_unknown` and retried.
pub const MAX_LOOKUPS: usize = 64;

/// The longest rotation a distributor serves: a day of publishing. An epoch's
/// times are added to the distributor's clock, so `issued_at + rotation` and
/// the life past it are held to a value that cannot carry those sums past what
/// an `i64` holds for any clock a node is likely to read; and a day is far past
/// the quarter of an hour the design publishes an epoch for.
pub const MAX_ROTATE_AFTER_MS: i64 = 24 * 60 * 60 * 1000;

/// What the application's membership check answers for a caller in one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// A member of this group, at the time of the call.
    In,
    /// Not a member: no endorsement the realm vouches for, or the
    /// application's own list does not hold it.
    NotAMember,
    /// The membership could not be read: a lookup that failed or timed out,
    /// which is not the same answer as `not a member` and is retried.
    Unknown,
}

/// What the application answers on `membership(prefix, caller)`: read at the
/// time of the call, and for a past epoch too.
pub type MembershipCheck = Arc<dyn Fn(String, [u8; 32]) -> MembershipFuture + Send + Sync>;

/// A membership answer in flight.
pub type MembershipFuture = crate::station_link::BoxFuture<Membership>;

/// What the application answers on `removed(prefix, caller)`: whether this
/// node is in the group's removed set, which is absolute and kept across a
/// distributor restart.
pub type RemovedCheck = Arc<dyn Fn(&str, [u8; 32]) -> bool + Send + Sync>;

/// A distributor's knobs: its org, the policy it answers for its groups, how
/// long an epoch publishes and what a "now" is read from, and the
/// application's two questions.
pub struct DistributorOptions {
    /// The org whose groups this distributor serves: the second segment of
    /// every prefix it answers, and the `/group_keys_v1` procedure's first.
    pub org: String,
    /// The policy every one of its groups is answered with.
    pub policy: Policy,
    /// How long an epoch publishes, in milliseconds: between one and
    /// [`MAX_ROTATE_AFTER_MS`]. An epoch that publishes for no time at all is
    /// one a pull of the current epoch makes again for ever, and one that
    /// publishes for longer than a day adds times a clock's sum cannot carry.
    pub rotate_after_ms: i64,
    /// The clock its epochs' times are read from.
    pub now: Clock,
    /// The application's membership check. There is no default: a distributor
    /// that admitted everyone would hand a group's key to the realm.
    pub membership: MembershipCheck,
    /// How long the membership check is given before the pull is answered
    /// `membership_unknown`.
    pub membership_timeout: Duration,
    /// The application's removed set, absolute.
    pub removed: RemovedCheck,
    /// The limits the epoch store is kept to.
    pub caps: Caps,
}

impl DistributorOptions {
    /// The knobs for `org`'s groups answered under `policy`, with the default
    /// rotation, the wall clock, the default membership timeout, nobody
    /// removed and the default caps.
    pub fn new(org: &str, policy: Policy, membership: MembershipCheck) -> DistributorOptions {
        DistributorOptions {
            org: org.to_string(),
            policy,
            rotate_after_ms: DEFAULT_ROTATE_AFTER_MS,
            now: wall_clock(),
            membership,
            membership_timeout: DEFAULT_MEMBERSHIP_TIMEOUT,
            removed: Arc::new(|_, _| false),
            caps: Caps::default(),
        }
    }
}

/// The limits a distributor keeps its epoch store to, so no caller can make it
/// hold more than it was sized for. All three are needed: the first two bound
/// the prefixes, because a pull names one and any admitted caller may name a
/// new one; the third bounds one group's chain.
///
/// A group's room is charged to the caller whose pull first made the
/// distributor hold it, and stays charged to that caller for as long as the
/// group is held — whatever other callers pull it, and whoever keeps it alive
/// by pulling. Only a group nothing of which is kept any more is released,
/// with its charge.
///
/// A refusal from one of them is not a refusal of the design's: it names
/// itself in the `handler_error`'s detail (`too_many_groups_member`,
/// `too_many_groups`, `too_many_epochs`), so a member reads it as a failed
/// pull and retries rather than as one of the five reasons, and an operator
/// sees which limit was reached.
///
/// The total's name is macula's own: its `macula_group_keys` refuses a new
/// group `too_many_groups` past `max_groups` (1024, the same default), so a
/// member and an operator read one name for one condition whatever SDK served
/// it. The other two are the bounds macula does not keep yet, and take the
/// same family's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// How many prefixes one caller may cause the distributor to hold.
    pub per_member: usize,
    /// How many prefixes the distributor holds at all.
    pub total: usize,
    /// How many epochs one group's chain holds.
    ///
    /// A chain is at most [`chain_bound`] epochs long at a given rotation,
    /// which is 8 at the default quarter of an hour, so the default carries a
    /// rotation of 34 seconds and longer. A host rotating faster than that
    /// raises this to at least `chain_bound(rotate_after_ms)` and owns the
    /// memory: a chain is at most this many keys, and a distributor at most
    /// `total` of them. [`Distributor::new`] refuses a chain cap below what
    /// its rotation needs, because such a distributor answers for about
    /// seventy minutes and then refuses every pull for good.
    pub epochs: usize,
}

impl Default for Caps {
    fn default() -> Caps {
        Caps {
            per_member: 64,
            total: 1024,
            epochs: 128,
        }
    }
}

/// The most epochs one group's chain holds at `rotate_after_ms`: the epochs
/// whose events can still be accepted, the one publishing, the one the ahead
/// window hands out, and a third of a rotation of slack.
///
/// A chain, from its newest epoch back, spans a rotation of publishing, the
/// event life and the tolerance an event is accepted for, and one more
/// rotation of keeping. The bound is what [`Distributor::new`] holds
/// [`Caps::epochs`] to, and what an application rotating faster than the
/// default asks this for to size its own.
///
/// `rotate_after_ms` is positive, as a distributor's is: a rotation of zero or
/// less is refused before this is asked, and answers the bound of a one
/// millisecond rotation here.
pub fn chain_bound(rotate_after_ms: i64) -> usize {
    let rotation = i128::from(rotate_after_ms.max(1));
    let life = i128::from(EVENT_LIFE_MS + TOLERANCE_MS);
    let span = 3 * life + 7 * rotation;
    let per_rotation = 3 * rotation;
    let in_thirds = span / per_rotation + i128::from(span % per_rotation != 0);
    usize::try_from(in_thirds + 1).unwrap_or(usize::MAX)
}

/// Why a distributor was not made: knobs that leave one answering its first
/// pulls and then unable to answer any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misconfigured {
    /// A rotation outside `1..=`[`MAX_ROTATE_AFTER_MS`]: an epoch would publish
    /// for no time at all, so a pull of the current epoch would make another
    /// for ever, or for longer than an epoch's times can be added to a clock's.
    Rotation { rotate_after_ms: i64, longest: i64 },
    /// A cap of zero: a distributor sized for nothing refuses every pull.
    NoRoom { cap: &'static str },
    /// [`Caps::epochs`] below [`chain_bound`]: the chain would fill in about
    /// seventy minutes and refuse every pull for good after that.
    ChainBound {
        epochs: usize,
        needed: usize,
        rotate_after_ms: i64,
    },
}

impl fmt::Display for Misconfigured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Misconfigured::Rotation {
                rotate_after_ms,
                longest,
            } => write!(
                f,
                "rotate_after_ms is {rotate_after_ms}: an epoch publishes for between 1 and \
                 {longest} ms",
            ),
            Misconfigured::NoRoom { cap } => {
                write!(
                    f,
                    "caps.{cap} is zero: a distributor sized for nothing refuses every pull"
                )
            }
            Misconfigured::ChainBound {
                epochs,
                needed,
                rotate_after_ms,
            } => write!(
                f,
                "caps.epochs is {epochs}, below the {needed} epochs a chain needs at a \
                 {rotate_after_ms} ms rotation: it would fill and then refuse every pull",
            ),
        }
    }
}

impl std::error::Error for Misconfigured {}

/// Refuses the knobs that would leave a distributor answering at first and
/// then unable to answer at all.
fn check(opts: &DistributorOptions) -> Result<(), Misconfigured> {
    let rotate_after_ms = opts.rotate_after_ms;
    if rotate_after_ms <= 0 || rotate_after_ms > MAX_ROTATE_AFTER_MS {
        return Err(Misconfigured::Rotation {
            rotate_after_ms,
            longest: MAX_ROTATE_AFTER_MS,
        });
    }
    if let Some(cap) = first_zero_cap(opts.caps) {
        return Err(Misconfigured::NoRoom { cap });
    }
    let needed = chain_bound(rotate_after_ms);
    match opts.caps.epochs < needed {
        true => Err(Misconfigured::ChainBound {
            epochs: opts.caps.epochs,
            needed,
            rotate_after_ms,
        }),
        false => Ok(()),
    }
}

/// The first of the three caps that is zero, which is a distributor that
/// would hold nothing.
fn first_zero_cap(caps: Caps) -> Option<&'static str> {
    match caps {
        Caps { per_member: 0, .. } => Some("per_member"),
        Caps { total: 0, .. } => Some("total"),
        Caps { epochs: 0, .. } => Some("epochs"),
        _ => None,
    }
}

/// A distributor of its org's groups' keys: the epochs of every group it
/// serves, made on demand, contiguous, and held in memory only. Cloning shares
/// the epochs, so every handle of one distributor serves the same chain.
///
/// **One distributor serves one realm.** A prefix's realm segment is not
/// matched to the realm a pull arrived in: the chains a distributor holds are
/// the org's groups whichever of the realms it is served for named them, so
/// serving one distributor under several realms would hand one realm's group
/// key to a caller another realm's channel admitted. Serve one per realm, and
/// let each application's membership answer for that realm alone.
#[derive(Clone)]
pub struct Distributor {
    inner: Arc<Inner>,
}

struct Inner {
    org: String,
    policy: Policy,
    rotate_after_ms: i64,
    now: Clock,
    membership: MembershipCheck,
    membership_timeout: Duration,
    removed: RemovedCheck,
    groups: Mutex<Chains>,
    caps: Caps,
    /// Told when an epoch was held and when the last handle is dropped, so
    /// the sweeper re-reads the instant it waits for and leaves rather than
    /// sleeping past both.
    woken: Arc<Notify>,
    /// The sweeper, while one runs: started by the first pull that holds
    /// anything, and started again if the runtime it ran on has ended.
    sweeper: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The membership lookups in flight, one per group and caller, at most
    /// [`MAX_LOOKUPS`] of them.
    lookups: Mutex<InFlight>,
}

/// A membership lookup's key: the group it is about, and the caller.
type LookupKey = (String, [u8; 32]);

/// The membership lookups a distributor has in flight.
type InFlight = HashMap<LookupKey, Arc<Lookup>>;

impl Inner {
    /// The lock the groups are held under. A panic under it leaves the epochs
    /// as they were rather than poisoned: the whole state is replaced by what
    /// a pull makes of it, so there is nothing half-written to doubt.
    fn lock(&self) -> MutexGuard<'_, Chains> {
        self.groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The lock the in-flight lookups are held under, for the same reason.
    fn lookups(&self) -> MutexGuard<'_, InFlight> {
        self.lookups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The earliest instant at which one of the held epochs stops being what
    /// it is, if anything is held at all.
    fn deadline(&self) -> Option<i64> {
        self.lock().deadline(self.rotate_after_ms)
    }

    /// The times a store operation is made at: this distributor's clock, and
    /// the rotation its epochs publish for.
    fn times(&self) -> Times {
        Times {
            now: (self.now)(),
            rotation: self.rotate_after_ms,
        }
    }

    /// Erases the epoch keys whose acceptance has ended, and drops what is
    /// kept no longer: what the sweeper does when its deadline comes.
    fn sweep(&self) {
        let times = self.times();
        self.lock().reap(times);
    }
}

impl Drop for Inner {
    /// Wakes the sweeper so it finds no handle to upgrade and leaves, rather
    /// than sleeping until an epoch's acceptance ends.
    fn drop(&mut self) {
        self.woken.notify_one();
    }
}

/// A membership lookup in flight: the answer once the pull that ran it has
/// one, and the wake-up every pull waiting on it parks on.
struct Lookup {
    answer: watch::Sender<Option<Membership>>,
    hearing: watch::Receiver<Option<Membership>>,
}

impl Lookup {
    fn new() -> Lookup {
        let (answer, hearing) = watch::channel(None);
        Lookup { answer, hearing }
    }

    /// The answer, given to every pull waiting on this lookup. The first
    /// answer is the one kept.
    fn settle(&self, answer: Membership) {
        self.answer
            .send_if_modified(|kept| settle_once(kept, answer));
    }

    /// The answer, waiting for the pull that ran the lookup to have it. A
    /// lookup whose pull was dropped settles `unknown` as it goes, so this
    /// always answers.
    async fn waited(&self) -> Membership {
        let mut hearing = self.hearing.clone();
        match awaiting(&mut hearing).await {
            Some(answer) => answer,
            // Only a lookup whose sender went without an answer leaves this
            // with none, which is a membership nobody could read.
            None => Membership::Unknown,
        }
    }
}

/// Whether `answer` is the one kept: only the first settles a lookup.
fn settle_once(kept: &mut Option<Membership>, answer: Membership) -> bool {
    if kept.is_some() {
        return false;
    }
    *kept = Some(answer);
    true
}

/// The answer once the lookup has one, or `None` when the lookup went without
/// one: its pull was dropped and took the sender with it.
async fn awaiting(hearing: &mut watch::Receiver<Option<Membership>>) -> Option<Membership> {
    while hearing.borrow_and_update().is_none() {
        if hearing.changed().await.is_err() {
            return None;
        }
    }
    *hearing.borrow_and_update()
}

/// What a pull got when it asked for its caller's membership: a lookup it
/// runs, one it waits on, or none because as many are in flight as the
/// distributor runs.
enum Claim {
    Runs(Arc<Lookup>),
    Waits(Arc<Lookup>),
    Refused,
}

/// A lookup this pull runs: the answer is given to every pull waiting on it
/// at [`Running::settle`], and a pull dropped before that — its request's
/// deadline passed — still takes the lookup out of the in-flight set and
/// tells the waits `unknown`, so no pull waits on a lookup nobody runs.
struct Running {
    inner: Arc<Inner>,
    key: (String, [u8; 32]),
    lookup: Arc<Lookup>,
}

impl Running {
    /// The answer, given to every pull waiting on this lookup.
    fn settle(&self, answer: Membership) {
        self.lookup.settle(answer);
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.lookup.settle(Membership::Unknown);
        self.inner.lookups().remove(&self.key);
    }
}

/// The groups a distributor holds: each one's chain of epochs and the caller
/// that made it, and how many prefixes each caller holds.
#[derive(Default)]
struct Chains {
    chains: HashMap<String, Chain>,
    held_by: HashMap<[u8; 32], usize>,
}

/// One group's chain, oldest epoch first, and the caller whose pull made the
/// group be held.
struct Chain {
    epochs: Vec<Held>,
    made_by: [u8; 32],
}

/// What a chain holds of one epoch: its key while an event under it can still
/// be accepted, and only its id once none can.
enum Held {
    /// The epoch, key and all, while an event under it can be sealed or
    /// opened.
    Keyed(Epoch),
    /// An epoch whose acceptance has ended: the id a pull of it is answered
    /// `epoch_expired` with, and nothing else.
    Spent(Spent),
}

/// An epoch past its acceptance, as it is kept: never its key.
#[derive(Debug, Clone, Copy)]
struct Spent {
    id: [u8; ID_SIZE],
    accept_until: i64,
}

/// The moment a store is read or written at: the distributor's now, and how
/// long its epochs publish, which is how long past acceptance an epoch is
/// still kept.
#[derive(Debug, Clone, Copy)]
struct Times {
    now: i64,
    rotation: i64,
}

impl Held {
    /// The epoch's id, which is kept however its key fares.
    fn id(&self) -> [u8; ID_SIZE] {
        match self {
            Held::Keyed(epoch) => epoch.id,
            Held::Spent(spent) => spent.id,
        }
    }

    /// The last instant an event under this epoch is accepted.
    fn accept_until(&self) -> i64 {
        match self {
            Held::Keyed(epoch) => epoch.accept_until,
            Held::Spent(spent) => spent.accept_until,
        }
    }

    /// The epoch while an event under it can still be accepted, which is the
    /// only while its key is held.
    fn key_at(&self, now: i64) -> Option<Epoch> {
        match self {
            Held::Keyed(epoch) if epoch.acceptable(now) => Some(epoch.clone()),
            _ => None,
        }
    }

    /// What is kept of an epoch no longer accepted, while it is kept at all.
    fn spent_at(&self, times: Times) -> Option<Spent> {
        let accept_until = self.accept_until();
        match times.now {
            past if past > accept_until + TOLERANCE_MS
                && past <= kept_until(accept_until, times.rotation) =>
            {
                Some(Spent {
                    id: self.id(),
                    accept_until,
                })
            }
            _ => None,
        }
    }

    /// What this entry is at `times`: the epoch while it is accepted, its id
    /// once it is not, and nothing once that is kept no longer.
    fn next_at(&self, times: Times) -> Option<Held> {
        if let Some(epoch) = self.key_at(times.now) {
            return Some(Held::Keyed(epoch));
        }
        self.spent_at(times).map(Held::Spent)
    }

    /// The first instant at which this entry stops being what it is now:
    /// when the epoch's acceptance ends, and a rotation later for the id kept
    /// of it.
    fn next_change(&self, rotation: i64) -> i64 {
        let acceptance_ends = self.accept_until() + TOLERANCE_MS + 1;
        match self {
            Held::Keyed(_) => acceptance_ends,
            Held::Spent(_) => acceptance_ends + rotation,
        }
    }
}

impl Chain {
    /// The epochs still accepted at `times`, and what is kept of those past
    /// that, in the order they were issued in.
    fn at(&self, times: Times) -> (Vec<Epoch>, Vec<Spent>) {
        let keyed = self
            .epochs
            .iter()
            .filter_map(|held| held.key_at(times.now))
            .collect();
        let spent = self
            .epochs
            .iter()
            .filter_map(|held| held.spent_at(times))
            .collect();
        (keyed, spent)
    }
}

/// The last instant an epoch accepted until `accept_until` is kept at all:
/// a rotation past its acceptance, so a pull of it is answered `epoch_expired`
/// for a while rather than `unknown_epoch` at once.
fn kept_until(accept_until: i64, rotation: i64) -> i64 {
    accept_until + TOLERANCE_MS + rotation
}

impl Chains {
    /// What the group holds at `times`: the epochs still accepted, and the ids
    /// of those past that are kept a while longer.
    fn at(&self, prefix: &str, times: Times) -> (Vec<Epoch>, Vec<Spent>) {
        match self.chains.get(prefix) {
            Some(chain) => chain.at(times),
            None => (Vec::new(), Vec::new()),
        }
    }

    /// The epochs the store holds for the group, as they are: the tests hold
    /// the store to its caps and to its erasures with it. `None` is an epoch
    /// whose key is gone and whose id is all that is kept of it.
    #[cfg(test)]
    fn stored(&self, prefix: &str) -> Vec<Option<Epoch>> {
        match self.chains.get(prefix) {
            Some(chain) => chain
                .epochs
                .iter()
                .map(|held| match held {
                    Held::Keyed(epoch) => Some(epoch.clone()),
                    Held::Spent(_) => None,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// The earliest instant at which one of the held epochs stops being what
    /// it is, if any is held.
    fn deadline(&self, rotation: i64) -> Option<i64> {
        self.chains
            .values()
            .flat_map(|chain| chain.epochs.iter())
            .map(|held| held.next_change(rotation))
            .min()
    }

    /// Holds what the group is at `times`, charging `caller` for a group it
    /// did not hold yet. The groups with nothing left are reaped first, so an
    /// idle host's capacity comes back.
    ///
    /// The chain is kept to [`Caps::epochs`]: what would grow it past that is
    /// refused and the store is left as it was.
    fn hold(
        &mut self,
        prefix: &str,
        epochs: Vec<Epoch>,
        spent: Vec<Spent>,
        caller: [u8; 32],
        caps: &Caps,
        times: Times,
    ) -> Result<(), Capacity> {
        let entries = entries_of(epochs, spent);
        if entries.len() > caps.epochs {
            return Err(Capacity::Epochs);
        }
        self.reap(times);
        match self.chains.get_mut(prefix) {
            Some(chain) => {
                chain.epochs = entries;
                Ok(())
            }
            None => self.charge(prefix, entries, caller, caps),
        }
    }

    /// Takes a new group's chain, charging `caller` for it: past either cap it
    /// is not held.
    fn charge(
        &mut self,
        prefix: &str,
        epochs: Vec<Held>,
        caller: [u8; 32],
        caps: &Caps,
    ) -> Result<(), Capacity> {
        let held = self.held_by.get(&caller).copied().unwrap_or(0);
        if held >= caps.per_member {
            return Err(Capacity::PerMember);
        }
        if self.chains.len() >= caps.total {
            return Err(Capacity::Total);
        }
        self.held_by.insert(caller, held + 1);
        self.chains.insert(
            prefix.to_string(),
            Chain {
                epochs,
                made_by: caller,
            },
        );
        Ok(())
    }

    /// Rewrites every group's chain to what it is at `times`, and releases the
    /// groups with nothing left with the room their caller held for them: an
    /// epoch past its acceptance keeps only its id, and one kept no longer is
    /// dropped, so its key is erased.
    fn reap(&mut self, times: Times) {
        for chain in self.chains.values_mut() {
            chain.epochs = chain
                .epochs
                .iter()
                .filter_map(|held| held.next_at(times))
                .collect();
        }
        let idle: Vec<String> = self
            .chains
            .iter()
            .filter(|(_, chain)| chain.epochs.is_empty())
            .map(|(prefix, _)| prefix.clone())
            .collect();
        for prefix in idle {
            self.release_one(&prefix);
        }
    }

    /// Drops one group's chain, and the charge its maker held for it.
    fn release_one(&mut self, prefix: &str) {
        let Some(made_by) = self.chains.remove(prefix).map(|chain| chain.made_by) else {
            return;
        };
        self.uncharge(made_by);
    }

    /// Takes one prefix off what `caller` is charged for.
    fn uncharge(&mut self, caller: [u8; 32]) {
        let held = self.held_by.get(&caller).copied().unwrap_or(1);
        match held.saturating_sub(1) {
            0 => self.held_by.remove(&caller),
            left => self.held_by.insert(caller, left),
        };
    }
}

/// What a chain holds: the ids of the epochs past their acceptance before the
/// epochs still under theirs, which is the order they were issued in.
fn entries_of(epochs: Vec<Epoch>, spent: Vec<Spent>) -> Vec<Held> {
    let older = spent.into_iter().map(Held::Spent);
    let live = epochs.into_iter().map(Held::Keyed);
    older.chain(live).collect()
}

/// Which limit refused a pull: one of a distributor's own, none of them one of
/// the design's five refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capacity {
    /// The caller holds as many prefixes as one member may.
    PerMember,
    /// The distributor holds as many prefixes as it is sized for.
    Total,
    /// The group's chain would hold more epochs than it is sized for.
    Epochs,
}

impl Capacity {
    /// The name the failure carries, which a member reads as a failed pull
    /// rather than as a refusal.
    fn detail(self) -> &'static str {
        match self {
            Capacity::PerMember => "too_many_groups_member",
            Capacity::Total => "too_many_groups",
            Capacity::Epochs => "too_many_epochs",
        }
    }
}

/// Why a pull was not answered, as the design names it (section 5): exactly
/// the five refusals every SDK's distributor sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    NotAMember,
    MembershipUnknown,
    UnknownEpoch,
    EpochExpired,
    UnknownGroup,
}

impl Refusal {
    /// The five, in the order macula's `group_keys_v1` vectors name them, for
    /// the tests that hold this crate's distributor to that file.
    #[cfg(test)]
    pub(crate) const ALL: [Refusal; 5] = [
        Refusal::NotAMember,
        Refusal::MembershipUnknown,
        Refusal::UnknownEpoch,
        Refusal::EpochExpired,
        Refusal::UnknownGroup,
    ];

    /// The refusal as the wire names it, which is also the detail of the
    /// `handler_error` a provider answers with.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Refusal::NotAMember => "not_a_member",
            Refusal::MembershipUnknown => "membership_unknown",
            Refusal::UnknownEpoch => "unknown_epoch",
            Refusal::EpochExpired => "epoch_expired",
            Refusal::UnknownGroup => "unknown_group",
        }
    }
}

/// Why a pull has no answer: one of the design's refusals, one of this
/// distributor's own limits, this node's own randomness not answering, or a
/// pull that came in the clear. None but the first is a refusal of the
/// design's, so a member retries those as a failed pull rather than being told
/// it is out of the group.
enum Unanswered {
    Refused(Refusal),
    Capacity(Capacity),
    NoRandomness(NoRandomness),
    /// The pull did not arrive sealed, and a distributor hands keys sealed
    /// only: the same `sealed_required` a link sends a clear call to a sealed
    /// offer.
    Clear,
}

impl Unanswered {
    /// The detail of the `handler_error` that carries it. A failure that is
    /// not a refusal names something none of the design's five does, so a
    /// member reads it as a failed pull and retries rather than as a refusal.
    fn detail(&self) -> String {
        match self {
            Unanswered::Refused(refusal) => refusal.name().to_string(),
            Unanswered::Capacity(capacity) => capacity.detail().to_string(),
            Unanswered::NoRandomness(cause) => cause.to_string(),
            Unanswered::Clear => CODE_SEALED_REQUIRED.to_string(),
        }
    }
}

impl From<Refusal> for Unanswered {
    fn from(refusal: Refusal) -> Unanswered {
        Unanswered::Refused(refusal)
    }
}

impl From<Capacity> for Unanswered {
    fn from(capacity: Capacity) -> Unanswered {
        Unanswered::Capacity(capacity)
    }
}

impl From<NoRandomness> for Unanswered {
    fn from(cause: NoRandomness) -> Unanswered {
        Unanswered::NoRandomness(cause)
    }
}

impl Distributor {
    /// A distributor of `opts`' org's groups, holding no epoch yet: a group's
    /// first pull makes its current epoch at once.
    ///
    /// The knobs are checked here rather than at the pull that would break on
    /// them ([`Misconfigured`]): a distributor is refused rather than made
    /// into one that answers for seventy minutes and then refuses every pull.
    pub fn new(opts: DistributorOptions) -> Result<Distributor, Misconfigured> {
        check(&opts)?;
        Ok(Distributor {
            inner: Arc::new(Inner {
                org: opts.org,
                policy: opts.policy,
                rotate_after_ms: opts.rotate_after_ms,
                now: opts.now,
                membership: opts.membership,
                membership_timeout: opts.membership_timeout,
                removed: opts.removed,
                groups: Mutex::new(Chains::default()),
                caps: opts.caps,
                woken: Arc::new(Notify::new()),
                sweeper: Mutex::new(None),
                lookups: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Erases the keys of every epoch whose acceptance has ended, keeping only
    /// their ids, and drops what is kept no longer: what the sweeper does at
    /// its deadline, for an application that would rather the erasure
    /// happened at a moment of its own.
    pub fn erase_spent(&self) {
        self.inner.sweep();
    }

    /// The instant the sweeper waits for, which is when the first held epoch
    /// stops being what it is.
    #[cfg(test)]
    fn deadline(&self) -> Option<i64> {
        self.inner.deadline()
    }

    /// The procedure this distributor serves: `<org>/group_keys_v1`.
    pub fn procedure(&self) -> String {
        procedure(&self.inner.org)
    }

    /// The offer to serve for `realm`, under the org key `org_key_id`'s
    /// `group_keys` grant and sealed only: what the pool advertises, and what
    /// answers a pull.
    ///
    /// Serving it needs the realm key pinned for an org procedure, and
    /// `kem_advertise` on: with it off the pool refuses this offer rather than
    /// advertise a distributor a member could only pull from in the clear.
    pub fn offer(&self, realm: [u8; 32], org_key_id: [u8; 32]) -> Offer {
        let mut offer = Offer::unary(realm, &self.procedure(), self.handler());
        offer.confidential = Confidentiality::Required;
        offer.policy = Some(Grant::RealmMemberRequired {
            key_id: org_key_id,
            can: GROUP_KEYS_CAN.to_string(),
        });
        offer
    }

    /// The `<org>/group_keys_v1` handler to serve.
    ///
    /// Not public: a distributor hands its offer out with [`Distributor::offer`],
    /// which names the sealing and the grant, and a handler served without them
    /// would hand a group's key out under no offer's conditions.
    pub(crate) fn handler(&self) -> Handler {
        let distributor = self.clone();
        handler(move |request: Request| answering(distributor.clone(), request))
    }

    /// Answers one pull: the group's epochs to a caller the application admits
    /// to it.
    ///
    /// A pull that did not arrive sealed is refused: a distributor hands the
    /// org's group keys out, and a clear one would put a key on the wire where
    /// anyone on the path reads it. The named epoch is checked before the
    /// caller's membership is read, so a malformed pull costs no lookup.
    async fn pull(&self, request: Request) -> Result<Value, Unanswered> {
        if !request.sealed {
            return Err(Unanswered::Clear);
        }
        let prefix = self.owned(&request.payload)?;
        let asked = epoch_asked(&request.payload)?;
        self.admit(&prefix, request.caller).await?;
        let now = (self.inner.now)();
        let reply = match asked {
            EpochAsked::Current => self.current(&prefix, request.caller, now)?,
            EpochAsked::Past(id) => self.past(&prefix, &id, now)?,
        };
        Ok(reply_value(&reply))
    }

    /// The group a pull names, when this distributor's org owns it: at least
    /// two `/`-segments, none empty, the second this org. Anything else is
    /// `unknown_group`, which a member reads as no distributor of its group.
    fn owned(&self, payload: &Value) -> Result<String, Refusal> {
        let Some(Value::Text(prefix)) = payload.get("prefix") else {
            return Err(Refusal::UnknownGroup);
        };
        match org_of(prefix) {
            Ok(org) if org == self.inner.org => Ok(prefix.clone()),
            _ => Err(Refusal::UnknownGroup),
        }
    }

    /// Whether the application admits `caller` to `prefix`: its removed set
    /// first, which is absolute, then its membership, read now, and the
    /// removed set again once that answer has come.
    async fn admit(&self, prefix: &str, caller: [u8; 32]) -> Result<(), Refusal> {
        self.still_member(prefix, caller)?;
        match self.membership_of(prefix, caller).await {
            Membership::In => self.still_member(prefix, caller),
            Membership::NotAMember => Err(Refusal::NotAMember),
            Membership::Unknown => Err(Refusal::MembershipUnknown),
        }
    }

    /// Whether the application's removed set still holds `caller`: asked
    /// before its membership is read, and again once the answer is back, so a
    /// node removed while its lookup ran is refused rather than admitted on an
    /// answer that was true when it was asked.
    fn still_member(&self, prefix: &str, caller: [u8; 32]) -> Result<(), Refusal> {
        match (self.inner.removed)(prefix, caller) {
            true => Err(Refusal::NotAMember),
            false => Ok(()),
        }
    }

    /// The caller's membership of `prefix`, read at most once for the pulls in
    /// flight: the pull that finds no lookup runs it and the others wait on the
    /// same answer, and past [`MAX_LOOKUPS`] in flight a pull is
    /// `membership_unknown` rather than one more lookup.
    async fn membership_of(&self, prefix: &str, caller: [u8; 32]) -> Membership {
        let key = (prefix.to_string(), caller);
        match self.claim_lookup(&key) {
            Claim::Runs(lookup) => self.run_lookup(key, lookup).await,
            Claim::Waits(lookup) => lookup.waited().await,
            Claim::Refused => Membership::Unknown,
        }
    }

    /// The lookup this pull runs, waits on, or has no room for.
    fn claim_lookup(&self, key: &(String, [u8; 32])) -> Claim {
        let mut lookups = self.inner.lookups();
        if let Some(lookup) = lookups.get(key) {
            return Claim::Waits(Arc::clone(lookup));
        }
        if lookups.len() >= MAX_LOOKUPS {
            return Claim::Refused;
        }
        let lookup = Arc::new(Lookup::new());
        lookups.insert(key.clone(), Arc::clone(&lookup));
        Claim::Runs(lookup)
    }

    /// Runs the caller's lookup, with the application given
    /// [`DistributorOptions::membership_timeout`] to answer, and gives the
    /// answer to every pull waiting on it: a lookup that does not answer in
    /// time is `unknown`, never `not a member`.
    async fn run_lookup(&self, key: (String, [u8; 32]), lookup: Arc<Lookup>) -> Membership {
        let running = Running {
            inner: Arc::clone(&self.inner),
            key,
            lookup,
        };
        let asked = (self.inner.membership)(running.key.0.clone(), running.key.1);
        let answer = match timeout(self.inner.membership_timeout, asked).await {
            Ok(answer) => answer,
            Err(_elapsed) => Membership::Unknown,
        };
        running.settle(answer);
        answer
    }

    /// The group's epochs to a pull of its current one: the ones still
    /// accepted, advanced to `now`, with the next inside the current's ahead
    /// window; the ones past their acceptance are kept beside them as their
    /// ids alone, so an epoch key goes as soon as no event under it can be
    /// accepted.
    ///
    /// The chain is kept to [`Caps::epochs`]: a pull that would grow it past
    /// that is answered `too_many_epochs` and the store is left as it was, so
    /// no chain outgrows what the distributor was sized for.
    fn current(&self, prefix: &str, caller: [u8; 32], now: i64) -> Result<Reply, Unanswered> {
        let times = Times {
            now,
            rotation: self.inner.rotate_after_ms,
        };
        let caps = self.inner.caps;
        let mut groups = self.lock();
        let (keyed, spent) = groups.at(prefix, times);
        let epochs = ahead(advanced(keyed, times)?, times)?;
        let current = for_publish(&epochs, now).cloned();
        let issued_with = issued_with(&epochs, current.as_ref());
        groups.hold(prefix, epochs, spent, caller, &caps, times)?;
        drop(groups);
        self.note_held();
        // Only a clock that went backwards leaves no epoch covering `now`: no
        // epoch of this group is issued yet, which is the truth a pull is
        // answered with.
        let Some(current) = current else {
            return Err(Refusal::UnknownEpoch.into());
        };
        let mut answered = vec![current];
        answered.extend(issued_with);
        Ok(self.reply(prefix, answered))
    }

    /// The group's epoch `id` to a pull of a past one: answered while it is
    /// still accepted, `epoch_expired` while its id is kept past that so a
    /// subscriber learns why it could not catch up, and `unknown_epoch` once
    /// nothing of it is held (a distributor that restarted holds none).
    fn past(&self, prefix: &str, id: &[u8; ID_SIZE], now: i64) -> Result<Reply, Unanswered> {
        let times = Times {
            now,
            rotation: self.inner.rotate_after_ms,
        };
        let (keyed, spent) = {
            let groups = self.lock();
            groups.at(prefix, times)
        };
        let found = keyed.into_iter().find(|epoch| &epoch.id == id);
        if let Some(epoch) = found {
            return Ok(self.reply(prefix, vec![epoch]));
        }
        match spent.iter().any(|spent| &spent.id == id) {
            true => Err(Refusal::EpochExpired.into()),
            false => Err(Refusal::UnknownEpoch.into()),
        }
    }

    /// The reply for `prefix` with `epochs`, under the policy this distributor
    /// answers its groups with.
    fn reply(&self, prefix: &str, epochs: Vec<Epoch>) -> Reply {
        Reply {
            prefix: prefix.to_string(),
            policy: self.inner.policy,
            epochs,
        }
    }

    /// Something was held: the sweeper is told to re-read the instant it waits
    /// for, and is started the first time it is told, so a distributor made
    /// and never pulled starts no task. A sweeper whose runtime has ended is
    /// started again, so the erasure never falls back to the pulls alone.
    fn note_held(&self) {
        self.inner.woken.notify_one();
        let mut sweeper = self
            .inner
            .sweeper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if sweeper.as_ref().is_some_and(|handle| !handle.is_finished()) {
            return;
        }
        let woken = Arc::clone(&self.inner.woken);
        let distributor = Arc::downgrade(&self.inner);
        *sweeper = Some(tokio::spawn(sweep_until_dropped(distributor, woken)));
    }

    fn lock(&self) -> MutexGuard<'_, Chains> {
        self.inner.lock()
    }
}

/// The epoch a pull names: the group's current one, or a past one by its id.
enum EpochAsked {
    Current,
    Past([u8; ID_SIZE]),
}

/// What `payload` asks for: the current epoch, or a past one by its 8-byte id.
/// Anything else is `unknown_epoch`, checked before the caller's membership is
/// read so a malformed pull costs no lookup.
fn epoch_asked(payload: &Value) -> Result<EpochAsked, Refusal> {
    match payload.get("epoch") {
        Some(Value::Text(current)) if current == "current" => Ok(EpochAsked::Current),
        Some(Value::Bytes(id)) => match <[u8; ID_SIZE]>::try_from(id.as_slice()) {
            Ok(id) => Ok(EpochAsked::Past(id)),
            Err(_) => Err(Refusal::UnknownEpoch),
        },
        _ => Err(Refusal::UnknownEpoch),
    }
}

/// The epochs issued when `current` stopped publishing: the next one, which a
/// pull inside the ahead window carries too.
fn issued_with(epochs: &[Epoch], current: Option<&Epoch>) -> Vec<Epoch> {
    let Some(current) = current else {
        return Vec::new();
    };
    epochs
        .iter()
        .filter(|epoch| epoch.issued_at == current.publish_until)
        .cloned()
        .collect()
}

/// Erases the keys of the epochs whose acceptance has ended, and again at each
/// later instant one does, until the last handle to the distributor is gone.
///
/// It holds no handle of its own, only a `Weak` and the waker it parks on, so
/// it never keeps a dropped distributor alive; and it sleeps to the earliest
/// such instant rather than to a tick, so an idle distributor's keys go as soon
/// as they are of no use.
async fn sweep_until_dropped(distributor: Weak<Inner>, woken: Arc<Notify>) {
    loop {
        let Some(inner) = distributor.upgrade() else {
            return;
        };
        let now = (inner.now)();
        let deadline = inner.deadline();
        drop(inner);
        match deadline {
            Some(at) => {
                let sleeping = tokio::time::sleep(left_ms(at, now));
                tokio::select! {
                    _ = woken.notified() => {}
                    _ = sleeping => {}
                }
            }
            None => woken.notified().await,
        }
        let Some(inner) = distributor.upgrade() else {
            return;
        };
        inner.sweep();
    }
}

/// The time left until `at`, never less than none.
fn left_ms(at: i64, now: i64) -> Duration {
    Duration::from_millis(u64::try_from(at.saturating_sub(now)).unwrap_or(0))
}

/// One pull answered as a handler's future: the RESULT, or the detail of the
/// `handler_error` that carries the refusal.
async fn answering(distributor: Distributor, request: Request) -> Result<Value, String> {
    distributor
        .pull(request)
        .await
        .map_err(|unanswered| unanswered.detail())
}

/// The group's epochs up to one current at `times`: contiguous after the
/// newest, or a fresh one when the group sat idle for a whole rotation.
fn advanced(epochs: Vec<Epoch>, times: Times) -> Result<Vec<Epoch>, NoRandomness> {
    let Some(newest) = epochs.last().cloned() else {
        return Ok(vec![fresh(times.now, times.rotation)?]);
    };
    if times.now < newest.publish_until {
        return Ok(epochs);
    }
    advanced_past(epochs, newest, times)
}

/// `epochs` whose newest stopped publishing at `newest.publish_until`, which
/// is at or before `times.now`: one more epoch appended, and the same asked
/// again.
fn advanced_past(
    mut epochs: Vec<Epoch>,
    newest: Epoch,
    times: Times,
) -> Result<Vec<Epoch>, NoRandomness> {
    let made = match times.now - newest.publish_until >= times.rotation {
        true => fresh(times.now, times.rotation)?,
        false => newest.following(times.rotation)?,
    };
    epochs.push(made);
    advanced(epochs, times)
}

/// `epochs` with the next one appended when `times.now` is inside the newest's
/// ahead window, so a pull there hands out the epoch the group is about to
/// publish under and every holder re-pulls before it is needed.
fn ahead(epochs: Vec<Epoch>, times: Times) -> Result<Vec<Epoch>, NoRandomness> {
    let Some(newest) = epochs.last().cloned() else {
        return Ok(epochs);
    };
    match newest.in_ahead_window(times.now) {
        true => {
            let next = newest.following(times.rotation)?;
            Ok(epochs.into_iter().chain([next]).collect())
        }
        false => Ok(epochs),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

    use super::*;
    use crate::frame::Sealed;
    use crate::group::{
        by_id_request, current_request, open_event, parse_reply, seal_event, Fields, JoinOptions,
        Keyring, Options as KeyringOptions, Pull, PullError, Puller, Reason, EVENT_LIFE_MS,
        ID_SIZE,
    };

    const ORG: &str = "acme";
    const REALM: [u8; 32] = [7; 32];
    const ORG_KEY: [u8; 32] = [8; 32];
    const DISTRIBUTOR: [u8; 32] = [9; 32];
    const CALLER: [u8; 32] = [3; 32];
    const OTHER: [u8; 32] = [4; 32];
    const START: i64 = 1_790_000_000_000;
    const ROTATION: i64 = 15 * 60_000;
    const NOT_A_MEMBER: &str = "not_a_member";
    const MEMBERSHIP_UNKNOWN: &str = "membership_unknown";
    const UNKNOWN_EPOCH: &str = "unknown_epoch";
    const EXPIRED: &str = "epoch_expired";
    const UNKNOWN_GROUP: &str = "unknown_group";

    fn prefix() -> String {
        format!("io.macula/{ORG}/chat")
    }

    fn topic() -> String {
        format!("{}/said_v1", prefix())
    }

    /// The application's membership: this realm has two members.
    fn everyone(caller: [u8; 32]) -> Membership {
        match caller {
            CALLER | OTHER => Membership::In,
            _ => Membership::NotAMember,
        }
    }

    /// A membership answer that has already arrived.
    fn ready(answered: Membership) -> MembershipFuture {
        Box::pin(std::future::ready(answered))
    }

    /// A membership check answering what `answer` says about the caller.
    fn responding(answer: fn([u8; 32]) -> Membership) -> MembershipCheck {
        Arc::new(move |_prefix: String, caller: [u8; 32]| ready(answer(caller)))
    }

    /// A membership check answering `answered` for every caller.
    fn answering(answered: Membership) -> MembershipCheck {
        Arc::new(move |_prefix: String, _caller: [u8; 32]| ready(answered))
    }

    /// A membership check that never answers at all.
    fn never() -> MembershipCheck {
        Arc::new(|_prefix: String, _caller: [u8; 32]| {
            Box::pin(std::future::pending::<Membership>()) as MembershipFuture
        })
    }

    /// The application's removed set: this caller, once `removed` is set.
    fn removed_set(removed: &Arc<AtomicBool>) -> RemovedCheck {
        let removed = Arc::clone(removed);
        Arc::new(move |_prefix: &str, caller: [u8; 32]| {
            caller == CALLER && removed.load(Ordering::SeqCst)
        })
    }

    /// The knobs a test distributor is made of, with a clock the test moves.
    fn options(start: i64) -> (DistributorOptions, Arc<AtomicI64>) {
        let clock = Arc::new(AtomicI64::new(start));
        let mut opts = DistributorOptions::new(ORG, Policy::Required, responding(everyone));
        let read = Arc::clone(&clock);
        opts.now = Arc::new(move || read.load(Ordering::SeqCst));
        (opts, clock)
    }

    /// A distributor of those knobs, reading `clock`.
    fn distributor_of(mut opts: DistributorOptions, clock: &Arc<AtomicI64>) -> Distributor {
        let read = Arc::clone(clock);
        opts.now = Arc::new(move || read.load(Ordering::SeqCst));
        Distributor::new(opts).expect("the knobs are a distributor's")
    }

    /// A distributor reading a clock that starts at `start`.
    fn distributor(start: i64) -> (Distributor, Arc<AtomicI64>) {
        let (opts, clock) = options(start);
        (distributor_of(opts, &clock), clock)
    }

    /// One pull, through the handler the pool would serve.
    async fn pull(distributor: &Distributor, payload: Value) -> Result<Value, String> {
        pull_as(distributor, CALLER, payload).await
    }

    /// One pull, by `caller`.
    async fn pull_as(
        distributor: &Distributor,
        caller: [u8; 32],
        payload: Value,
    ) -> Result<Value, String> {
        let request = Request {
            caller,
            realm: REALM,
            procedure: distributor.procedure(),
            payload,
            token: None,
            proofs: None,
            deadline_ms: 0,
            sealed: true,
        };
        distributor.handler()(request).await
    }

    /// A pull of another group of this org, by `caller`.
    async fn pull_group(
        distributor: &Distributor,
        caller: [u8; 32],
        name: &str,
    ) -> Result<Value, String> {
        pull_as(distributor, caller, current_request(&group(name))).await
    }

    /// Another group of this org, by its name.
    fn group(name: &str) -> String {
        format!("io.macula/{ORG}/{name}")
    }

    /// The group `name`'s current epoch.
    async fn epoch_of(distributor: &Distributor, caller: [u8; 32], name: &str) -> Epoch {
        let answered = pull_group(distributor, caller, name)
            .await
            .expect("the distributor answers");
        let prefix = group(name);
        parse_reply(&prefix, &answered)
            .expect("the protocol's reply")
            .epochs[0]
            .clone()
    }

    /// A pull of the group's current epoch.
    async fn current(distributor: &Distributor) -> Result<Reply, String> {
        let answered = pull(distributor, current_request(&prefix())).await?;
        Ok(parse_reply(&prefix(), &answered).expect("the distributor answers the protocol"))
    }

    /// The group's current epoch, which a test then hands around.
    async fn epoch_now(distributor: &Distributor) -> Epoch {
        epoch_of(distributor, CALLER, "chat").await
    }

    /// A pull of one epoch by id.
    async fn by_id(distributor: &Distributor, id: &[u8; ID_SIZE]) -> Result<Reply, String> {
        let answered = pull(distributor, by_id_request(&prefix(), id)).await?;
        Ok(parse_reply(&prefix(), &answered).expect("the distributor answers the protocol"))
    }

    /// A pull of `payload` refused with `expected`.
    async fn refused_with(distributor: &Distributor, payload: Value, expected: &str) {
        assert_eq!(pull(distributor, payload).await, Err(expected.to_string()));
    }

    /// A keyring whose every pull goes through `distributor`, reading `clock`.
    fn member(distributor: &Distributor, clock: &Arc<AtomicI64>) -> Keyring {
        let read = Arc::clone(clock);
        Keyring::new(KeyringOptions {
            pull: puller(distributor),
            pull_timeout: Duration::from_secs(1),
            now: Arc::new(move || read.load(Ordering::SeqCst)),
            uniform: Arc::new(|| 0.5),
        })
    }

    /// The distributor as a member's puller.
    fn puller(distributor: &Distributor) -> Puller {
        let distributor = distributor.clone();
        Arc::new(move |pulled: Pull| Box::pin(pull_through(distributor.clone(), pulled)))
    }

    /// The distributor's answer as a member reads it: its RESULT, or its
    /// refusal by the reason that names it.
    async fn pull_through(
        distributor: Distributor,
        pulled: Pull,
    ) -> Result<(Value, [u8; 32]), PullError> {
        let request = Request {
            caller: CALLER,
            realm: pulled.realm,
            procedure: pulled.procedure,
            payload: pulled.payload,
            token: Some(pulled.token),
            proofs: None,
            deadline_ms: 0,
            sealed: true,
        };
        match distributor.handler()(request).await {
            Ok(result) => Ok((result, DISTRIBUTOR)),
            Err(detail) => refused(detail),
        }
    }

    /// A refusal as a member reads it: a reason the design names, or a failure
    /// of another kind that is retried.
    fn refused(detail: String) -> Result<(Value, [u8; 32]), PullError> {
        match Reason::from_refusal(&detail) {
            Some(reason) => Err(PullError::Refused {
                reason,
                cause: None,
            }),
            None => Err(PullError::Failed(detail.into())),
        }
    }

    /// What an event under this group is sealed with.
    fn fields() -> Fields {
        Fields {
            realm: REALM,
            topic: topic(),
            publisher: CALLER,
            seq: 1,
            published_at: START as u64,
        }
    }

    /// An event sealed under `epoch`.
    fn sealed(epoch: &Epoch) -> Sealed {
        seal_event(epoch, &fields(), &Value::text("the document")).expect("it seals")
    }

    /// The offer is the org's procedure, sealed only, under the org's
    /// `group_keys` grant: the three things that keep a key off the wire in the
    /// clear and out of a caller the org did not grant.
    #[test]
    fn the_offer_is_sealed_only_under_the_orgs_grant() {
        let (distributor, _clock) = distributor(START);
        let offer = distributor.offer(REALM, ORG_KEY);
        assert_eq!(offer.procedure, "acme/group_keys_v1");
        assert_eq!(offer.confidential, Confidentiality::Required);
        assert_eq!(
            offer.policy,
            Some(Grant::RealmMemberRequired {
                key_id: ORG_KEY,
                can: GROUP_KEYS_CAN.into()
            })
        );
        assert!(offer.handler.is_some());
        assert!(offer.stream.is_none());
    }

    /// A pull that did not arrive sealed is refused `sealed_required`: a
    /// distributor hands the org's group keys out, and a clear pull would put
    /// one on the wire where anything on the path reads it — whatever offer
    /// the handler was served under.
    #[tokio::test]
    async fn a_clear_pull_is_refused() {
        let (distributor, _clock) = distributor(START);
        let request = Request {
            caller: CALLER,
            realm: REALM,
            procedure: distributor.procedure(),
            payload: current_request(&prefix()),
            token: None,
            proofs: None,
            deadline_ms: 0,
            sealed: false,
        };
        assert_eq!(
            distributor.handler()(request).await,
            Err("sealed_required".to_string())
        );
        assert!(stored(&distributor).is_empty(), "and nothing is held");
    }

    /// A holder pulls the current epoch and opens under it: the key the
    /// distributor handed to the member is the key the event was sealed with.
    #[tokio::test]
    async fn a_holder_pulls_the_current_epoch_and_opens_under_it() {
        let (distributor, clock) = distributor(START);
        let keyring = member(&distributor, &clock);
        let policy = keyring
            .join(REALM, &prefix(), JoinOptions::default())
            .await
            .expect("a member is admitted");
        assert_eq!(policy, Policy::Required, "the policy comes with the keys");

        let epoch = epoch_now(&distributor).await;
        let opened = keyring
            .open_epoch(REALM, &prefix(), epoch.id, CALLER)
            .await
            .expect("the member holds the epoch it pulled");
        assert_eq!(opened, epoch, "the same epoch, key and times");
        let content = open_event(&opened, &fields(), &sealed(&epoch)).expect("it opens");
        assert_eq!(content, Value::text("the document"));
    }

    /// A caller the application does not admit is refused `not_a_member`, and
    /// nothing of the keys reaches it.
    #[tokio::test]
    async fn a_non_member_is_refused_not_a_member() {
        let (mut opts, clock) = options(START);
        opts.membership = answering(Membership::NotAMember);
        let distributor = distributor_of(opts, &clock);
        assert_eq!(current(&distributor).await, Err(NOT_A_MEMBER.into()));

        let keyring = member(&distributor, &clock);
        let refused = keyring
            .join(REALM, &prefix(), JoinOptions::default())
            .await
            .expect_err("a non-member is refused");
        assert_eq!(refused.reason(), Some(Reason::NotAMember));
        assert!(keyring.publish_epoch(REALM, &prefix()).await.is_err());
    }

    /// The removed set is absolute and is asked before membership: a node in
    /// it is refused every epoch, a past one included, whether it is still a
    /// member or not.
    #[tokio::test]
    async fn a_removed_node_is_refused_a_past_epoch_too() {
        let removed = Arc::new(AtomicBool::new(false));
        let (mut opts, clock) = options(START);
        opts.removed = removed_set(&removed);
        let distributor = distributor_of(opts, &clock);
        let held = member(&distributor, &clock);
        held.join(REALM, &prefix(), JoinOptions::default())
            .await
            .expect("it joined while a member");
        let epoch = epoch_now(&distributor).await;

        removed.store(true, Ordering::SeqCst);
        let again = by_id(&distributor, &epoch.id).await;
        assert_eq!(again, Err(NOT_A_MEMBER.into()), "the epoch it held");
        assert_eq!(current(&distributor).await, Err(NOT_A_MEMBER.into()));
        let asked = held
            .open_epoch(REALM, &prefix(), [0; ID_SIZE], CALLER)
            .await
            .expect_err("a removed node pulls nothing");
        assert_eq!(asked.reason(), Some(Reason::NotAMember));
    }

    /// A membership read that does not answer in time, and one that answers
    /// "could not read", are both `membership_unknown`, never `not_a_member`:
    /// a member retries rather than being told it is out of a group it is in.
    #[tokio::test]
    async fn a_membership_read_that_does_not_answer_is_unknown() {
        let (mut opts, clock) = options(START);
        opts.membership = never();
        opts.membership_timeout = Duration::from_millis(10);
        let hung = distributor_of(opts, &clock);
        assert_eq!(current(&hung).await, Err(MEMBERSHIP_UNKNOWN.into()));

        let (mut opts, clock) = options(START);
        opts.membership = answering(Membership::Unknown);
        let unread = distributor_of(opts, &clock);
        assert_eq!(current(&unread).await, Err(MEMBERSHIP_UNKNOWN.into()));
    }

    /// A node removed while its membership lookup was still running is
    /// refused: the removed set is asked again once the answer is back, so an
    /// answer that was true when it was asked does not admit a node the group
    /// has removed since.
    #[tokio::test]
    async fn a_node_removed_during_its_lookup_is_refused() {
        let removed = Arc::new(AtomicBool::new(false));
        let (mut opts, clock) = options(START);
        opts.removed = removed_set(&removed);
        opts.membership = removing_while_asked(&removed);
        let distributor = distributor_of(opts, &clock);
        assert_eq!(current(&distributor).await, Err(NOT_A_MEMBER.into()));
    }

    /// A membership check that answers [`everyone`], having removed the caller
    /// while it ran.
    fn removing_while_asked(removed: &Arc<AtomicBool>) -> MembershipCheck {
        let removed = Arc::clone(removed);
        Arc::new(move |_prefix: String, caller: [u8; 32]| {
            let answer = everyone(caller);
            Box::pin(removed_while_answering(Arc::clone(&removed), answer)) as MembershipFuture
        })
    }

    async fn removed_while_answering(removed: Arc<AtomicBool>, answer: Membership) -> Membership {
        removed.store(true, Ordering::SeqCst);
        answer
    }

    /// One caller's pulls in flight share one lookup: they all wait on the
    /// answer the first of them is running, rather than asking the application
    /// once each.
    #[tokio::test]
    async fn one_callers_pulls_share_one_lookup() {
        let asked = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let (mut opts, clock) = options(START);
        opts.membership = counted_and_gated(&asked, &gate);
        let distributor = distributor_of(opts, &clock);
        let pulls: Vec<_> = (0..8).map(|_| spawned_pull(&distributor, CALLER)).collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "one lookup for eight pulls"
        );
        gate.notify_waiters();
        let answers = futures_answers(pulls).await;
        assert!(
            answers.iter().all(Result::is_ok),
            "every pull is answered: {answers:?}"
        );
    }

    /// One pull of this group, by `caller`, spawned so its future runs beside
    /// another's.
    fn spawned_pull(
        distributor: &Distributor,
        caller: [u8; 32],
    ) -> tokio::task::JoinHandle<Result<Value, String>> {
        let distributor = distributor.clone();
        let payload = current_request(&prefix());
        tokio::spawn(async move { pull_as(&distributor, caller, payload).await })
    }

    /// A membership check that counts its lookups and answers `in` once `gate`
    /// wakes it.
    fn counted_and_gated(asked: &Arc<AtomicUsize>, gate: &Arc<Notify>) -> MembershipCheck {
        let asked = Arc::clone(asked);
        let gate = Arc::clone(gate);
        Arc::new(move |_prefix: String, _caller: [u8; 32]| {
            Box::pin(counted_once(Arc::clone(&asked), Arc::clone(&gate))) as MembershipFuture
        })
    }

    async fn counted_once(asked: Arc<AtomicUsize>, gate: Arc<Notify>) -> Membership {
        asked.fetch_add(1, Ordering::SeqCst);
        gate.notified().await;
        Membership::In
    }

    /// Past [`MAX_LOOKUPS`] in flight a pull is `membership_unknown` rather
    /// than one more lookup, so no caller can put every other member's pulls
    /// behind an unbounded queue of lookups.
    #[tokio::test]
    async fn past_the_lookups_in_flight_a_pull_is_unknown() {
        let started = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Notify::new());
        let (mut opts, clock) = options(START);
        opts.membership_timeout = Duration::from_secs(30);
        opts.membership = counted_and_held(&started, &open, &gate);
        let distributor = distributor_of(opts, &clock);
        let pulls: Vec<_> = (0..=MAX_LOOKUPS as u8)
            .map(|caller| spawned_pull(&distributor, [caller; 32]))
            .collect();
        wait_until(|| started.load(Ordering::SeqCst) == MAX_LOOKUPS).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let refused = pulls.iter().filter(|pull| pull.is_finished()).count();
        assert_eq!(refused, 1, "the pull past the cap started no lookup");
        open.store(true, Ordering::SeqCst);
        gate.notify_waiters();
        let answers: Vec<Result<Value, String>> = futures_answers(pulls).await;
        let unknown = answers
            .iter()
            .filter(|answer| **answer == Err(MEMBERSHIP_UNKNOWN.into()))
            .count();
        assert_eq!(unknown, 1, "and was answered membership_unknown");
    }

    /// Waits for `done` to hold, letting the tasks that make it hold run.
    async fn wait_until(done: impl Fn() -> bool) {
        while !done() {
            tokio::task::yield_now().await;
        }
    }

    /// A membership check that counts its lookups and answers `in` once `open`
    /// is set, parking every lookup that comes before that.
    fn counted_and_held(
        started: &Arc<AtomicUsize>,
        open: &Arc<AtomicBool>,
        gate: &Arc<Notify>,
    ) -> MembershipCheck {
        let started = Arc::clone(started);
        let open = Arc::clone(open);
        let gate = Arc::clone(gate);
        Arc::new(move |_prefix: String, _caller: [u8; 32]| {
            Box::pin(counted_and_waiting(
                Arc::clone(&started),
                Arc::clone(&open),
                Arc::clone(&gate),
            )) as MembershipFuture
        })
    }

    async fn counted_and_waiting(
        started: Arc<AtomicUsize>,
        open: Arc<AtomicBool>,
        gate: Arc<Notify>,
    ) -> Membership {
        started.fetch_add(1, Ordering::SeqCst);
        while !open.load(Ordering::SeqCst) {
            gate.notified().await;
        }
        Membership::In
    }

    /// Every spawned pull's answer, in the order they were spawned.
    async fn futures_answers(
        pulls: Vec<tokio::task::JoinHandle<Result<Value, String>>>,
    ) -> Vec<Result<Value, String>> {
        let mut answers = Vec::with_capacity(pulls.len());
        for pull in pulls {
            answers.push(pull.await.expect("the pull runs"));
        }
        answers
    }

    /// A subscriber that was offline across a rotation catches up: the
    /// distributor still holds the epoch it missed, answers it, and the event
    /// sealed under it opens.
    #[tokio::test]
    async fn a_subscriber_offline_across_a_rotation_pulls_the_past_epoch() {
        let (distributor, clock) = distributor(START);
        let missed = epoch_now(&distributor).await;

        clock.store(START + ROTATION, Ordering::SeqCst);
        let rotated = epoch_now(&distributor).await;
        assert_ne!(rotated.id, missed.id, "the group rotated");
        assert_eq!(rotated.issued_at, missed.publish_until, "and contiguous");

        let caught_up = by_id(&distributor, &missed.id).await.expect("it is held");
        assert_eq!(
            caught_up.epochs,
            vec![missed.clone()],
            "the epoch as it was"
        );
        let content = open_event(&caught_up.epochs[0], &fields(), &sealed(&missed))
            .expect("the caught-up epoch opens the event");
        assert_eq!(content, Value::text("the document"));
    }

    /// An epoch past its acceptance is kept a while longer and answered
    /// `epoch_expired`, so a member learns why it cannot catch up; held no
    /// longer it is `unknown_epoch`, and the group's chain carries on.
    #[tokio::test]
    async fn an_epoch_past_its_acceptance_is_expired_then_unknown() {
        let (distributor, clock) = distributor(START);
        let epoch = epoch_now(&distributor).await;

        clock.store(epoch.accept_until + TOLERANCE_MS + 1, Ordering::SeqCst);
        let expired = by_id(&distributor, &epoch.id).await;
        assert_eq!(expired, Err(EXPIRED.into()));

        clock.store(
            epoch.accept_until + TOLERANCE_MS + ROTATION + 1,
            Ordering::SeqCst,
        );
        let gone = by_id(&distributor, &epoch.id).await;
        assert_eq!(gone, Err(UNKNOWN_EPOCH.into()));
        assert_ne!(epoch_now(&distributor).await.id, epoch.id);
    }

    /// The key of an epoch goes when its acceptance ends, and not at the
    /// group's next pull: the id kept of it still tells a member
    /// `epoch_expired` rather than `unknown_epoch`.
    #[tokio::test]
    async fn a_key_is_erased_once_its_acceptance_ends() {
        let (distributor, clock) = distributor(START);
        let epoch = epoch_now(&distributor).await;

        clock.store(epoch.accept_until + TOLERANCE_MS + 1, Ordering::SeqCst);
        distributor.erase_spent();

        let held = stored(&distributor);
        assert_eq!(held.len(), 1, "the epoch is still kept");
        assert!(held[0].is_none(), "as its id alone, never its key");
        assert_eq!(by_id(&distributor, &epoch.id).await, Err(EXPIRED.into()));
    }

    /// The sweeper's instant is the first acceptance to end, so an idle
    /// distributor erases a key as soon as nothing under it can be accepted,
    /// rather than when a member next pulls.
    #[tokio::test]
    async fn the_sweeper_waits_for_the_first_acceptance_to_end() {
        let (distributor, _clock) = distributor(START);
        let epoch = epoch_now(&distributor).await;
        assert_eq!(
            distributor.deadline(),
            Some(epoch.accept_until + TOLERANCE_MS + 1)
        );
    }

    /// A sweeper the runtime it was started on has ended with is started
    /// again by the next pull: the erasure is never left to the pulls alone
    /// because the task a distributor started in one runtime is gone.
    #[test]
    fn a_sweeper_whose_runtime_ended_is_started_again() {
        let (opts, clock) = options(START);
        let distributor = distributor_of(opts, &clock);
        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        first.block_on(async {
            current(&distributor).await.expect("the first pull");
        });
        drop(first);
        assert!(!sweeping(&distributor), "the first sweeper ended with it");

        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        second.block_on(async {
            current(&distributor)
                .await
                .expect("a pull after the runtime ended");
        });
        assert!(sweeping(&distributor), "a sweeper runs again");
    }

    /// Whether the distributor has a sweeper still running.
    fn sweeping(distributor: &Distributor) -> bool {
        let sweeper = distributor
            .inner
            .sweeper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sweeper.as_ref().is_some_and(|handle| !handle.is_finished())
    }

    /// Past its keeping the id goes too: nothing of the epoch is held, and a
    /// pull of it is `unknown_epoch`.
    #[tokio::test]
    async fn nothing_of_an_epoch_is_kept_past_its_keeping() {
        let (distributor, clock) = distributor(START);
        let epoch = epoch_now(&distributor).await;

        clock.store(
            epoch.accept_until + TOLERANCE_MS + ROTATION + 1,
            Ordering::SeqCst,
        );
        distributor.erase_spent();
        assert!(stored(&distributor).is_empty(), "nothing is kept of it");
        assert_eq!(
            by_id(&distributor, &epoch.id).await,
            Err(UNKNOWN_EPOCH.into())
        );
    }

    /// A restarted distributor holds no epoch: the one a member asks for is
    /// `unknown_epoch`, and the current one is a fresh chain it made at once.
    #[tokio::test]
    async fn a_restarted_distributor_answers_unknown_epoch() {
        let (before, _clock) = distributor(START);
        let lost = epoch_now(&before).await;

        let (restarted, _clock) = distributor(START);
        let asked = by_id(&restarted, &lost.id).await;
        assert_eq!(asked, Err(UNKNOWN_EPOCH.into()));
        let made = epoch_now(&restarted).await;
        assert_ne!(made.id, lost.id);
        assert_eq!(made.issued_at, START, "a new current epoch at once");
    }

    /// A prefix another org owns is `unknown_group`, as is one that is not a
    /// group's at all.
    #[tokio::test]
    async fn a_prefix_this_org_does_not_own_is_unknown_group() {
        let (distributor, _clock) = distributor(START);
        refused_with(
            &distributor,
            current_request("io.macula/other/chat"),
            UNKNOWN_GROUP,
        )
        .await;
        refused_with(&distributor, current_request("io.macula"), UNKNOWN_GROUP).await;
        refused_with(
            &distributor,
            current_request("io.macula//chat"),
            UNKNOWN_GROUP,
        )
        .await;
        refused_with(
            &distributor,
            current_request("io.macula/acme/"),
            UNKNOWN_GROUP,
        )
        .await;
        refused_with(&distributor, Value::text("no prefix at all"), UNKNOWN_GROUP).await;
    }

    /// Inside the current epoch's ahead window a pull carries the next epoch
    /// too: contiguous with it, so every holder has it before it publishes.
    #[tokio::test]
    async fn the_ahead_window_hands_out_the_next_epoch() {
        let (distributor, clock) = distributor(START);
        let early = current(&distributor).await.expect("the first pull");
        assert_eq!(early.epochs.len(), 1, "outside the window, one epoch");

        let epoch = early.epochs[0].clone();
        clock.store(epoch.ahead_window().0, Ordering::SeqCst);
        let inside = current(&distributor)
            .await
            .expect("the pull inside the window");
        assert_eq!(inside.epochs.len(), 2, "the current one and the next");
        assert_eq!(inside.epochs[0], epoch);
        let next = &inside.epochs[1];
        assert_eq!(next.issued_at, epoch.publish_until, "contiguous");
        assert_eq!(next.publish_until, next.issued_at + ROTATION);
        assert_eq!(next.accept_until, next.publish_until + EVENT_LIFE_MS);
    }

    /// An epoch no longer kept is dropped from the store, so its key is erased
    /// rather than held in memory once no event under it can be accepted.
    #[tokio::test]
    async fn an_epoch_no_longer_kept_is_erased() {
        let (distributor, clock) = distributor(START);
        let first = epoch_now(&distributor).await;
        assert_eq!(stored(&distributor).len(), 1);

        clock.store(
            first.accept_until + TOLERANCE_MS + ROTATION + 1,
            Ordering::SeqCst,
        );
        let now = epoch_now(&distributor).await;
        let held = stored(&distributor);
        assert_eq!(held.len(), 1, "only the epoch that covers now is kept");
        let kept = held[0].clone().expect("its key, while it is accepted");
        assert_eq!(kept.id, now.id);
        assert_ne!(kept.id, first.id);
    }

    /// The epochs the distributor holds for this group, each `None` once only
    /// its id is kept of it.
    fn stored(distributor: &Distributor) -> Vec<Option<Epoch>> {
        let groups = distributor.lock();
        groups.stored(&prefix())
    }

    /// One member may not take the distributor's whole table: past its own cap
    /// a new group is refused, a group it already holds costs nothing more,
    /// and another member still has room of its own.
    #[tokio::test]
    async fn a_member_holds_no_more_groups_than_its_cap() {
        let (mut opts, clock) = options(START);
        opts.caps = Caps {
            per_member: 2,
            total: 4,
            epochs: 128,
        };
        let distributor = distributor_of(opts, &clock);
        assert!(pull_group(&distributor, CALLER, "one").await.is_ok());
        assert!(
            pull_group(&distributor, CALLER, "one").await.is_ok(),
            "a group it already holds is not charged again"
        );
        assert!(pull_group(&distributor, CALLER, "two").await.is_ok());
        assert_eq!(
            pull_group(&distributor, CALLER, "three").await,
            Err("too_many_groups_member".into())
        );
        assert!(
            pull_group(&distributor, OTHER, "three").await.is_ok(),
            "another member's own room"
        );
    }

    /// The distributor holds no more groups than it is sized for, whoever asks
    /// for them.
    #[tokio::test]
    async fn the_distributor_holds_no_more_groups_than_its_cap() {
        let (mut opts, clock) = options(START);
        opts.caps = Caps {
            per_member: 4,
            total: 2,
            epochs: 128,
        };
        let distributor = distributor_of(opts, &clock);
        assert!(pull_group(&distributor, CALLER, "one").await.is_ok());
        assert!(pull_group(&distributor, OTHER, "two").await.is_ok());
        assert_eq!(
            pull_group(&distributor, OTHER, "three").await,
            Err("too_many_groups".into())
        );
    }

    /// A group nobody has pulled since its last epoch stopped being kept gives
    /// its room back, so a host that has served many groups over time is not
    /// full of the ones it served first.
    #[tokio::test]
    async fn an_idle_group_releases_the_room_it_held() {
        let (mut opts, clock) = options(START);
        opts.caps = Caps {
            per_member: 1,
            total: 8,
            epochs: 128,
        };
        let distributor = distributor_of(opts, &clock);
        assert!(pull_group(&distributor, CALLER, "one").await.is_ok());
        assert_eq!(
            pull_group(&distributor, CALLER, "two").await,
            Err("too_many_groups_member".into())
        );

        let idle = epoch_of(&distributor, CALLER, "one").await;
        clock.store(
            idle.accept_until + TOLERANCE_MS + ROTATION + 1,
            Ordering::SeqCst,
        );
        assert!(
            pull_group(&distributor, CALLER, "two").await.is_ok(),
            "the idle group gave its room back"
        );
        assert!(
            stored(&distributor).len() <= 1,
            "and was dropped, not kept beside the new one"
        );
    }

    /// A chain that would grow past its cap is refused, and the store keeps
    /// what it had: no group's chain outgrows what the distributor was sized
    /// for, and the epoch members hold is still the one it answers with.
    ///
    /// [`Distributor::new`] refuses a cap below what the rotation needs, so
    /// this holds the store itself against a chain sized below that: the
    /// refusal is the last line the runtime keeps, and it keeps it.
    #[test]
    fn a_chain_past_its_cap_is_refused() {
        let caps = Caps {
            per_member: 4,
            total: 8,
            epochs: 1,
        };
        let mut chains = Chains::default();
        let first = fresh(START, ROTATION).expect("randomness answers");
        let times = Times {
            now: START,
            rotation: ROTATION,
        };
        chains
            .hold(
                &prefix(),
                vec![first.clone()],
                Vec::new(),
                CALLER,
                &caps,
                times,
            )
            .expect("one epoch fits");

        let grown = vec![
            first.clone(),
            fresh(START + ROTATION, ROTATION).expect("randomness answers"),
        ];
        let refused = chains.hold(&prefix(), grown, Vec::new(), CALLER, &caps, times);
        assert_eq!(
            refused,
            Err(Capacity::Epochs),
            "the second epoch is one too many"
        );
        let still = chains.stored(&prefix());
        assert_eq!(still.len(), 1, "the store keeps what it had");
        let kept = still[0].clone().expect("the epoch it held");
        assert_eq!(kept.id, first.id, "and the epoch members hold");
    }

    /// A rotation outside the bounds is refused when the distributor is made:
    /// one of zero or less would publish for no time at all, so a pull of the
    /// current epoch would make another, and another, with the groups locked,
    /// and one past a day would carry an epoch's times past what an `i64`
    /// holds.
    #[test]
    fn a_rotation_outside_the_bounds_is_refused() {
        let outside = [0, -1, -DEFAULT_ROTATE_AFTER_MS, MAX_ROTATE_AFTER_MS + 1];
        for rotate_after_ms in outside {
            let (mut opts, _clock) = options(START);
            opts.rotate_after_ms = rotate_after_ms;
            assert_eq!(
                Distributor::new(opts).err(),
                Some(Misconfigured::Rotation {
                    rotate_after_ms,
                    longest: MAX_ROTATE_AFTER_MS,
                })
            );
        }
        let (mut opts, _clock) = options(START);
        opts.rotate_after_ms = MAX_ROTATE_AFTER_MS;
        assert!(
            Distributor::new(opts).is_ok(),
            "the longest rotation is a distributor's"
        );
    }

    /// A cap of zero is refused too: a distributor sized for nothing refuses
    /// every pull, and the operator reads that when it is made.
    #[test]
    fn a_cap_of_zero_is_refused() {
        let zeros = [
            (
                Caps {
                    per_member: 0,
                    ..Caps::default()
                },
                "per_member",
            ),
            (
                Caps {
                    total: 0,
                    ..Caps::default()
                },
                "total",
            ),
            (
                Caps {
                    epochs: 0,
                    ..Caps::default()
                },
                "epochs",
            ),
        ];
        for (caps, cap) in zeros {
            let (mut opts, _clock) = options(START);
            opts.caps = caps;
            assert_eq!(
                Distributor::new(opts).err(),
                Some(Misconfigured::NoRoom { cap })
            );
        }
    }

    /// An epoch cap below what one group's chain needs at the rotation is
    /// refused, and raised to that bound it is a distributor: the chain would
    /// otherwise fill in about seventy minutes and refuse every pull for good.
    #[test]
    fn an_epoch_cap_below_the_chain_bound_is_refused() {
        let (mut opts, _clock) = options(START);
        opts.rotate_after_ms = 33_000;
        assert_eq!(
            Distributor::new(opts).err(),
            Some(Misconfigured::ChainBound {
                epochs: 128,
                needed: 131,
                rotate_after_ms: 33_000,
            })
        );

        let (mut opts, _clock) = options(START);
        opts.rotate_after_ms = 33_000;
        opts.caps = Caps {
            epochs: 131,
            ..Caps::default()
        };
        assert!(
            Distributor::new(opts).is_ok(),
            "raised to what the rotation needs"
        );
    }

    /// The bound is what a chain really needs: 8 at the default quarter of an
    /// hour, 127 at a 34-second rotation and 131 at 33, so the default caps
    /// carry a rotation of 34 seconds and longer.
    #[test]
    fn the_chain_bound_is_what_one_chain_needs() {
        assert_eq!(chain_bound(DEFAULT_ROTATE_AFTER_MS), 8);
        assert_eq!(chain_bound(34_000), 127);
        assert_eq!(chain_bound(33_000), 131);
    }

    /// An id the distributor does not hold, and an `epoch` field that is
    /// neither `current` nor an id, are both `unknown_epoch`.
    #[tokio::test]
    async fn an_id_it_does_not_hold_is_unknown_epoch() {
        let (distributor, _clock) = distributor(START);
        let _ = current(&distributor).await.expect("the first pull");
        let unknown = by_id(&distributor, &[0; ID_SIZE]).await;
        assert_eq!(unknown, Err(UNKNOWN_EPOCH.into()));
        refused_with(&distributor, asking(Value::text("later")), UNKNOWN_EPOCH).await;
        refused_with(
            &distributor,
            asking(Value::Bytes(vec![0; ID_SIZE - 1])),
            UNKNOWN_EPOCH,
        )
        .await;
        refused_with(&distributor, asking(Value::Int(1)), UNKNOWN_EPOCH).await;
    }

    /// A pull of this group asking for `epoch`.
    fn asking(epoch: Value) -> Value {
        Value::Map(vec![
            (Value::text("prefix"), Value::text(prefix())),
            (Value::text("epoch"), epoch),
        ])
    }

    /// The five refusals are the ones macula's vectors pin, so a refusal this
    /// distributor sends is never read as a failure of another kind; and a
    /// failure that is not a refusal names none of them.
    #[test]
    fn the_refusals_are_the_wires_five() {
        let named: Vec<&str> = Refusal::ALL.iter().map(|refusal| refusal.name()).collect();
        assert_eq!(
            named,
            [
                NOT_A_MEMBER,
                MEMBERSHIP_UNKNOWN,
                UNKNOWN_EPOCH,
                EXPIRED,
                UNKNOWN_GROUP
            ]
        );
        let mapped: Vec<bool> = named
            .iter()
            .map(|name| Reason::from_refusal(name).is_some())
            .collect();
        assert!(mapped.iter().all(|mapped| *mapped), "a member maps each");

        let no_randomness = Unanswered::NoRandomness(NoRandomness);
        assert_eq!(Reason::from_refusal(&no_randomness.detail()), None);
        let refused = Unanswered::from(Refusal::UnknownEpoch);
        assert_eq!(refused.detail(), UNKNOWN_EPOCH);
    }

    /// A reply's key bytes are wiped once they have been sealed: a
    /// distributor's answer carries the group's epoch keys, and dropping a
    /// value frees its bytes without clearing them.
    #[test]
    fn a_replys_keys_are_wiped_after_sealing() {
        let epoch = fresh(START, ROTATION).expect("randomness answers");
        let mut reply = reply_value(&Reply {
            prefix: prefix(),
            policy: Policy::Required,
            epochs: vec![epoch],
        });
        assert!(reply.get("epochs").is_some(), "the reply as it goes out");
        reply.zeroize_bytes();
        assert!(all_bytes_zero(&reply), "no key byte survives the wipe");
    }

    /// Whether every byte string in `v` is zero.
    fn all_bytes_zero(v: &Value) -> bool {
        match v {
            Value::Bytes(bytes) => bytes.iter().all(|byte| *byte == 0),
            Value::List(items) => items.iter().all(all_bytes_zero),
            Value::Map(pairs) => pairs
                .iter()
                .all(|(key, value)| all_bytes_zero(key) && all_bytes_zero(value)),
            _ => true,
        }
    }
}
