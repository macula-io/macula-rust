//! The sealed groups a node has joined: their epochs, their policy and their
//! re-pulls (DESIGN_E2E_SEALED_PUBSUB.md sections 4, 6 and 7). Publishing
//! under a current epoch, opening under a held one and reading a policy never
//! wait on a pull, and pulls are made one at a time. Every held group is
//! pulled again at a uniformly random instant in its newest epoch's ahead
//! window, event or no event, and a failed pull is retried with backoff,
//! doubling from a second up to a third of an epoch, until one succeeds. The
//! policy is monotonic: once preferred or required has been seen for a
//! prefix, off is ignored. Epoch keys are held in memory only, and erased
//! when no event under them can be accepted any more.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::cbor::Value;
use crate::seal::Clock;

use super::epoch::{for_publish, org_of, retain_live, under};
use super::wire::{
    by_id_request, current_request, parse_reply, procedure, zeroize_reply, Policy, Reply,
};
use super::{Cause, Epoch, GroupError, Reason, EVENT_LIFE_MS, ID_SIZE};

/// The default time a pull is given before it is abandoned.
const DEFAULT_PULL_TIMEOUT: Duration = Duration::from_secs(15);
/// The first backoff after a failed pull, in milliseconds, doubling from
/// there.
const FIRST_BACKOFF_MS: i64 = 1_000;
/// How many unknown-epoch pulls one publisher is charged per rotation.
const UNKNOWN_IDS_PER_PUBLISHER: usize = 3;

/// One pull of the distributor's epoch keys.
#[derive(Debug, Clone, PartialEq)]
pub struct Pull {
    pub realm: [u8; 32],
    pub procedure: String,
    pub payload: Value,
    /// The org's grant, presented as the call's UCAN.
    pub token: Vec<u8>,
    /// The distributor to ask, when one is pinned.
    pub provider: Option<[u8; 32]>,
}

/// Why a pull did not answer.
#[derive(Debug)]
pub enum PullError {
    /// No trusted distributor advertises the group's procedure.
    NotAdvertised(Cause),
    /// The distributor refused, by a reason of the design's.
    Refused {
        reason: Reason,
        cause: Option<Cause>,
    },
    /// The call itself did not complete.
    Failed(Cause),
}

/// What a pull resolves to: the RESULT and the node that answered.
pub type PullFuture = Pin<Box<dyn Future<Output = Result<(Value, [u8; 32]), PullError>> + Send>>;

/// Makes one pull. A pool implements this over its sealed calls; a test
/// implements it over canned replies.
pub type Puller = Arc<dyn Fn(Pull) -> PullFuture + Send + Sync>;

/// A keyring's own knobs: how it pulls, how long a pull is given, and the
/// clock and jitter a re-pull is scheduled with.
pub struct Options {
    pub pull: Puller,
    pub pull_timeout: Duration,
    pub now: Clock,
    /// A draw from `[0, 1)`, which places the re-pull in the ahead window.
    pub uniform: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl Options {
    /// The knobs a keyring pulling with `pull` uses, with the wall clock and
    /// the crate's own randomness.
    pub fn new(pull: Puller) -> Options {
        Options {
            pull,
            pull_timeout: DEFAULT_PULL_TIMEOUT,
            now: wall_clock(),
            uniform: Arc::new(uniform),
        }
    }
}

/// What a join carries: the org's grant, presented on every pull, and the
/// distributor's node id when it must be that node (required for a
/// `~<node_id>` group, available for an org's).
#[derive(Debug, Clone, Default)]
pub struct JoinOptions {
    pub ucan: Vec<u8>,
    pub distributor: Option<[u8; 32]>,
}

/// A group a node has joined, by its realm and prefix.
type GroupKey = ([u8; 32], String);

/// Whether the distributor is pinned, and by whom: a caller's own pin is
/// never dropped, an auto-pinned one is dropped when no trusted advertisement
/// holds it any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinKind {
    None,
    User,
    Auto,
}

/// How many unknown-epoch pulls one publisher has been charged in this
/// rotation.
#[derive(Debug, Clone, Copy)]
struct Budget {
    since: i64,
    count: usize,
}

/// What the keyring knows about an epoch id without pulling.
enum Known {
    Held(Epoch),
    Expired,
    Unknown,
}

/// What one pull needs from its group, taken under the lock and owned by the
/// pull. The group itself stays in the keyring for the whole of the pull, so
/// the policy it enforces does not lapse while the network is slow: a pull is
/// up to fifteen seconds, and an attacker who can make one take that long
/// must not thereby lift a required policy.
struct Request {
    org: String,
    ucan: Vec<u8>,
    provider: Option<[u8; 32]>,
}

impl Request {
    fn of(held: &Held) -> Request {
        Request {
            org: held.org.clone(),
            ucan: held.ucan.clone(),
            provider: match held.pin_kind {
                PinKind::None => None,
                PinKind::User | PinKind::Auto => Some(held.pin),
            },
        }
    }
}

/// What a pull came back with, to be applied to its group under the lock.
enum Outcome {
    /// The distributor answered, and its reply is the protocol's.
    Answered { reply: Reply, provider: [u8; 32] },
    /// No trusted distributor advertises the procedure, so an auto-pin this
    /// node took from an earlier answer is dropped.
    NotAdvertised(GroupError),
    /// The pull failed, by the reason it is held as.
    Failed(GroupError),
}

/// A held group's epochs and policy, without its timer.
struct Held {
    org: String,
    ucan: Vec<u8>,
    pin: [u8; 32],
    pin_kind: PinKind,
    policy: Option<Policy>,
    epochs: Vec<Epoch>,
    rotation: i64,
    unknown: HashMap<[u8; ID_SIZE], i64>,
    budget: HashMap<[u8; 32], Budget>,
    backoff: i64,
}

impl Held {
    fn new(org: &str, opts: &JoinOptions) -> Held {
        Held {
            org: org.to_string(),
            ucan: opts.ucan.clone(),
            pin: opts.distributor.unwrap_or([0; 32]),
            pin_kind: match opts.distributor {
                Some(_) => PinKind::User,
                None => PinKind::None,
            },
            policy: None,
            epochs: Vec::new(),
            rotation: 0,
            unknown: HashMap::new(),
            budget: HashMap::new(),
            backoff: FIRST_BACKOFF_MS,
        }
    }

    /// Takes a reply into the group: its policy monotonically, its rotation,
    /// and its epochs the group does not hold yet, oldest first.
    fn merge(&mut self, reply: &Reply) {
        self.policy = Some(reply.policy.following(self.policy));
        if let Some(first) = reply.epochs.first() {
            self.rotation = first.rotation();
        }
        for epoch in &reply.epochs {
            self.keep(epoch.clone());
        }
        self.epochs.sort_by_key(|e| e.issued_at);
    }

    /// Keeps an epoch the group does not hold yet: epochs are identified by
    /// their random id, so the same id twice is the same epoch.
    fn keep(&mut self, epoch: Epoch) {
        let held = self.epochs.iter().any(|held| held.id == epoch.id);
        if !held {
            self.epochs.push(epoch);
        }
    }

    /// Takes the answering node as the distributor, when none is pinned, and
    /// drops an auto-pin no advertisement holds any more.
    fn pin_answered(&mut self, provider: [u8; 32]) {
        if self.pin_kind == PinKind::None {
            self.pin = provider;
            self.pin_kind = PinKind::Auto;
        }
    }

    fn unpin_auto(&mut self) {
        if self.pin_kind == PinKind::Auto {
            self.pin_kind = PinKind::None;
        }
    }

    /// Remembers an id the distributor said it does not know, until a moment
    /// past which it could no longer be accepted anyway.
    fn forgot(&mut self, id: [u8; ID_SIZE], until: i64) {
        self.unknown.insert(id, until);
    }

    /// Charges one unknown-id pull to `publisher`, at most three per rotation.
    fn spend(&mut self, publisher: [u8; 32], now: i64) -> bool {
        match self.budget.get(&publisher).copied() {
            None => {
                self.budget.insert(
                    publisher,
                    Budget {
                        since: now,
                        count: 1,
                    },
                );
                true
            }
            Some(b) if now - b.since >= self.rotation => {
                self.budget.insert(
                    publisher,
                    Budget {
                        since: now,
                        count: 1,
                    },
                );
                true
            }
            Some(b) if b.count >= UNKNOWN_IDS_PER_PUBLISHER => false,
            Some(b) => {
                self.budget.insert(
                    publisher,
                    Budget {
                        since: b.since,
                        count: b.count + 1,
                    },
                );
                true
            }
        }
    }
}

/// A held group with its pending re-pull: the group, the task that will pull
/// it again, and the generation that task names.
struct Joined {
    held: Held,
    generation: u64,
    timer: Option<JoinHandle<()>>,
}

struct State {
    groups: HashMap<GroupKey, Joined>,
    closed: bool,
}

/// The sealed groups one node holds. It is safe to share between tasks, and
/// a clone shares the same groups.
#[derive(Clone)]
pub struct Keyring {
    inner: Arc<Inner>,
}

struct Inner {
    opts: Options,
    state: Mutex<State>,
    /// One pull at a time, across every group: a pull is a network call, and
    /// a member's pulls are serial.
    pulls: tokio::sync::Mutex<()>,
}

impl Keyring {
    /// A keyring pulling with `opts.pull`.
    pub fn new(opts: Options) -> Keyring {
        Keyring {
            inner: Arc::new(Inner {
                opts,
                state: Mutex::new(State {
                    groups: HashMap::new(),
                    closed: false,
                }),
                pulls: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Joins the group `prefix` in `realm`: pulls its current epoch and holds
    /// it. A group already held is not pulled again. It answers the group's
    /// policy, or the pull's refusal.
    pub async fn join(
        &self,
        realm: [u8; 32],
        prefix: &str,
        opts: JoinOptions,
    ) -> Result<Policy, GroupError> {
        self.inner.join(realm, prefix, opts).await
    }

    /// Stops holding the group and erases its keys.
    pub fn leave(&self, realm: [u8; 32], prefix: &str) {
        self.inner.leave(realm, prefix);
    }

    /// The joined group covering `topic` (its longest joined prefix) and that
    /// group's policy.
    pub fn policy(&self, realm: [u8; 32], topic: &str) -> Option<(String, Policy)> {
        self.inner.policy(realm, topic)
    }

    /// The epoch a publisher seals under now: the newest held epoch that has
    /// started and has not stopped publishing. With none, the group is pulled
    /// at once, and the publish fails closed with that pull's error.
    pub async fn publish_epoch(&self, realm: [u8; 32], prefix: &str) -> Result<Epoch, GroupError> {
        self.inner.publish_epoch(realm, prefix).await
    }

    /// The epoch an event was sealed under, if it may be opened now: a held
    /// one while it is acceptable; otherwise it is pulled by id, at most
    /// three unknown ids per publisher per rotation.
    pub async fn open_epoch(
        &self,
        realm: [u8; 32],
        prefix: &str,
        id: [u8; ID_SIZE],
        publisher: [u8; 32],
    ) -> Result<Epoch, GroupError> {
        self.inner.open_epoch(realm, prefix, id, publisher).await
    }

    /// Stops every pending re-pull and erases every group's keys.
    pub fn close(&self) {
        self.inner.close();
    }
}

impl Inner {
    async fn join(
        self: &Arc<Self>,
        realm: [u8; 32],
        prefix: &str,
        opts: JoinOptions,
    ) -> Result<Policy, GroupError> {
        let org = org_of(prefix)?;
        let key: GroupKey = (realm, prefix.to_string());
        if let Some(policy) = self.held_policy(&key) {
            return Ok(policy);
        }
        let _gate = self.pulls.lock().await;
        if let Some(policy) = self.held_policy(&key) {
            return Ok(policy);
        }
        let mut held = Held::new(org, &opts);
        let request = Request::of(&held);
        match self.pull(&key, &request, current_request(prefix)).await {
            Outcome::Answered { reply, provider } => {
                held.pin_answered(provider);
                held.merge(&reply);
            }
            Outcome::NotAdvertised(e) | Outcome::Failed(e) => return Err(e),
        }
        let policy = held.policy.unwrap_or(Policy::Off);
        let mut state = self.lock();
        if state.closed {
            return Err(GroupError::NotJoined);
        }
        state
            .groups
            .entry(key.clone())
            .or_insert_with(|| Joined::new(held));
        drop(state);
        self.schedule(&key);
        Ok(policy)
    }

    fn leave(&self, realm: [u8; 32], prefix: &str) {
        let key: GroupKey = (realm, prefix.to_string());
        if let Some(joined) = self.lock().groups.remove(&key) {
            abort(joined.timer);
        }
    }

    fn policy(&self, realm: [u8; 32], topic: &str) -> Option<(String, Policy)> {
        self.lock()
            .groups
            .iter()
            .filter(|((r, prefix), _)| *r == realm && under(topic, prefix))
            .max_by_key(|((_, prefix), _)| prefix.len())
            .and_then(|((_, prefix), joined)| joined.held.policy.map(|p| (prefix.clone(), p)))
    }

    async fn publish_epoch(
        self: &Arc<Self>,
        realm: [u8; 32],
        prefix: &str,
    ) -> Result<Epoch, GroupError> {
        let key: GroupKey = (realm, prefix.to_string());
        if let Some(epoch) = self.publishable(&key) {
            return Ok(epoch);
        }
        let _gate = self.pulls.lock().await;
        if let Some(epoch) = self.publishable(&key) {
            return Ok(epoch);
        }
        let request = self.request_of(&key)?;
        let outcome = self.pull(&key, &request, current_request(prefix)).await;
        if let Err(e) = self.applied(&key, outcome, None) {
            self.back_off(&key);
            return Err(e);
        }
        self.schedule(&key);
        self.publishable(&key)
            .ok_or_else(|| GroupError::of(Reason::NoDistributor))
    }

    async fn open_epoch(
        self: &Arc<Self>,
        realm: [u8; 32],
        prefix: &str,
        id: [u8; ID_SIZE],
        publisher: [u8; 32],
    ) -> Result<Epoch, GroupError> {
        let key: GroupKey = (realm, prefix.to_string());
        match self.known(&key, id)? {
            Known::Held(epoch) => return Ok(epoch),
            Known::Expired => return Err(GroupError::of(Reason::EpochExpired)),
            Known::Unknown => {}
        }
        let _gate = self.pulls.lock().await;
        match self.known(&key, id)? {
            Known::Held(epoch) => return Ok(epoch),
            Known::Expired => return Err(GroupError::of(Reason::EpochExpired)),
            Known::Unknown => {}
        }
        self.charge(&key, id, publisher)?;
        let request = self.request_of(&key)?;
        let outcome = self.pull(&key, &request, by_id_request(prefix, &id)).await;
        self.applied(&key, outcome, Some(id))?;
        match self.known(&key, id)? {
            Known::Held(epoch) => Ok(epoch),
            Known::Expired => Err(GroupError::of(Reason::EpochExpired)),
            Known::Unknown => Err(GroupError::of(Reason::NoDistributor)),
        }
    }

    /// Charges one unknown-id pull to `publisher`, at most three a rotation,
    /// and nothing at all for an id the distributor has already said it does
    /// not know, which is remembered until the id could no longer be accepted
    /// anyway.
    fn charge(
        &self,
        key: &GroupKey,
        id: [u8; ID_SIZE],
        publisher: [u8; 32],
    ) -> Result<(), GroupError> {
        let now = (self.opts.now)();
        let mut state = self.lock();
        let joined = state.groups.get_mut(key).ok_or(GroupError::NotJoined)?;
        let remembered = joined
            .held
            .unknown
            .get(&id)
            .is_some_and(|until| *until > now);
        if remembered || !joined.held.spend(publisher, now) {
            return Err(GroupError::of(Reason::UnknownEpoch));
        }
        Ok(())
    }

    /// Applies a pull's outcome to the group it was made for, which stayed in
    /// the keyring throughout: its policy and epochs, the distributor that
    /// answered, an auto-pin no advertisement holds any more, and an id the
    /// distributor said it does not know. The epochs no longer of use are
    /// erased here too.
    fn applied(
        &self,
        key: &GroupKey,
        outcome: Outcome,
        unknown_id: Option<[u8; ID_SIZE]>,
    ) -> Result<Reply, GroupError> {
        let now = (self.opts.now)();
        let mut state = self.lock();
        let joined = state.groups.get_mut(key).ok_or(GroupError::NotJoined)?;
        match outcome {
            Outcome::Answered { reply, provider } => {
                joined.held.pin_answered(provider);
                joined.held.merge(&reply);
                retain_live(&mut joined.held.epochs, now);
                Ok(reply)
            }
            Outcome::NotAdvertised(e) => {
                joined.held.unpin_auto();
                Err(e)
            }
            Outcome::Failed(e) => {
                let forgotten = e.is(Reason::UnknownEpoch).then_some(unknown_id).flatten();
                forgotten
                    .into_iter()
                    .for_each(|id| joined.held.forgot(id, now + EVENT_LIFE_MS));
                Err(e)
            }
        }
    }

    /// What a pull needs from the group, taken under the lock.
    fn request_of(&self, key: &GroupKey) -> Result<Request, GroupError> {
        let state = self.lock();
        let joined = state.groups.get(key).ok_or(GroupError::NotJoined)?;
        Ok(Request::of(&joined.held))
    }

    fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        for (_, joined) in state.groups.drain() {
            abort(joined.timer);
        }
    }

    fn held_policy(&self, key: &GroupKey) -> Option<Policy> {
        self.lock().groups.get(key).and_then(|j| j.held.policy)
    }

    /// The epoch to publish under, if the group holds one good at now.
    fn publishable(&self, key: &GroupKey) -> Option<Epoch> {
        let now = (self.opts.now)();
        let state = self.lock();
        for_publish(&state.groups.get(key)?.held.epochs, now).cloned()
    }

    /// What the keyring knows about an epoch id: a held one that is good now,
    /// a held one past its life, or nothing at all.
    fn known(&self, key: &GroupKey, id: [u8; ID_SIZE]) -> Result<Known, GroupError> {
        let now = (self.opts.now)();
        let state = self.lock();
        let joined = state.groups.get(key).ok_or(GroupError::NotJoined)?;
        Ok(
            match joined.held.epochs.iter().find(|epoch| epoch.id == id) {
                Some(epoch) if epoch.acceptable(now) => Known::Held(epoch.clone()),
                Some(_) => Known::Expired,
                None => Known::Unknown,
            },
        )
    }

    /// Makes one pull: under the group's grant, at its pinned distributor when
    /// it has one, within the pull timeout. The group is not touched here; the
    /// caller applies what comes back, under the lock, so the group and the
    /// policy it carries stay where they are for the whole of the pull.
    async fn pull(self: &Arc<Self>, key: &GroupKey, request: &Request, payload: Value) -> Outcome {
        let pull = Pull {
            realm: key.0,
            procedure: procedure(&request.org),
            payload,
            token: request.ucan.clone(),
            provider: request.provider,
        };
        let answer =
            match tokio::time::timeout(self.opts.pull_timeout, (self.opts.pull)(pull)).await {
                Ok(answer) => answer,
                Err(_) => {
                    return Outcome::Failed(GroupError::caused_by(Reason::NoDistributor, Elapsed))
                }
            };
        match answer {
            Ok((mut result, provider)) => {
                // A reply that is not the protocol's is no distributor's, as
                // macula holds it: the parse failure stays as the cause.
                let parsed = parse_reply(&key.1, &result);
                // The reply carried every epoch key as bytes: wipe them
                // whether or not it parsed.
                zeroize_reply(&mut result);
                match parsed {
                    Ok(reply) => Outcome::Answered { reply, provider },
                    Err(e) => Outcome::Failed(GroupError::caused_by(Reason::NoDistributor, e)),
                }
            }
            Err(PullError::NotAdvertised(cause)) => Outcome::NotAdvertised(GroupError::Refused {
                reason: Reason::NoDistributor,
                cause: Some(cause),
            }),
            Err(PullError::Refused { reason, cause }) => {
                Outcome::Failed(GroupError::Refused { reason, cause })
            }
            Err(PullError::Failed(cause)) => Outcome::Failed(GroupError::Refused {
                reason: Reason::NoDistributor,
                cause: Some(cause),
            }),
        }
    }

    /// The group's re-pull: the current epoch again. A wake-up that names an
    /// older generation than the group's does nothing, and so does one for a
    /// group that has been left or erased.
    async fn repull(self: Arc<Self>, key: GroupKey, generation: u64) {
        let _gate = self.pulls.lock().await;
        if !self.current_generation(&key, generation) {
            return;
        }
        let Ok(request) = self.request_of(&key) else {
            return;
        };
        let outcome = self.pull(&key, &request, current_request(&key.1)).await;
        match self.applied(&key, outcome, None) {
            Ok(_) => self.schedule(&key),
            Err(_) => self.back_off(&key),
        }
    }

    /// Whether the group is still held under the generation a wake-up names,
    /// and the keyring is open.
    fn current_generation(&self, key: &GroupKey, generation: u64) -> bool {
        let state = self.lock();
        !state.closed
            && state
                .groups
                .get(key)
                .is_some_and(|j| j.generation == generation)
    }

    /// Sets the group's one re-pull, at a random instant in its newest
    /// epoch's ahead window, and never sooner than the first backoff: a reply
    /// whose ahead window has already passed on this clock must not have the
    /// member pull again at once, over and over. A group with no epoch at all
    /// retries on its backoff.
    fn schedule(self: &Arc<Self>, key: &GroupKey) {
        let Some(delay) = self.reschedule(key, FIRST_BACKOFF_MS) else {
            return;
        };
        self.spawn_wake(key, delay);
    }

    /// Retries a failed pull after the group's backoff, then doubles it, up
    /// to a third of an epoch.
    fn back_off(self: &Arc<Self>, key: &GroupKey) {
        if let Some((generation, delay)) = self.schedule_back_off(key) {
            self.spawn_wake_for(key, generation, delay);
        }
    }

    /// Doubles the group's backoff, erases the epochs no longer of use, and
    /// answers the generation its next attempt must name, and how long until
    /// then. `None` when the group is gone.
    fn schedule_back_off(&self, key: &GroupKey) -> Option<(u64, i64)> {
        let now = (self.opts.now)();
        let mut state = self.lock();
        let joined = state.groups.get_mut(key)?;
        let delay = joined.held.backoff;
        let capped = (joined.held.rotation / 3).max(FIRST_BACKOFF_MS);
        joined.held.backoff = (joined.held.backoff * 2).min(capped);
        retain_live(&mut joined.held.epochs, now);
        joined.generation += 1;
        Some((joined.generation, delay))
    }

    /// Bumps the group's generation and answers how long until its next
    /// re-pull, or `None` when it is not held any more.
    fn reschedule(self: &Arc<Self>, key: &GroupKey, floor_ms: i64) -> Option<i64> {
        let mut state = self.lock();
        let joined = state.groups.get_mut(key)?;
        abort(joined.timer.take());
        let now = (self.opts.now)();
        let delay = match joined.held.epochs.last() {
            Some(newest) => (newest.repull_at((self.opts.uniform)()) - now).max(floor_ms),
            None => floor_ms,
        };
        joined.held.backoff = FIRST_BACKOFF_MS;
        joined.generation += 1;
        Some(delay)
    }

    fn spawn_wake(self: &Arc<Self>, key: &GroupKey, delay: i64) {
        let generation = {
            let state = self.lock();
            match state.groups.get(key) {
                Some(joined) => joined.generation,
                None => return,
            }
        };
        self.spawn_wake_for(key, generation, delay);
    }

    /// Spawns the re-pull. With no runtime to spawn it on, nothing is
    /// scheduled: publishing, opening and reading a policy still work, and no
    /// pull happens behind the caller's back.
    fn spawn_wake_for(self: &Arc<Self>, key: &GroupKey, generation: u64, delay: i64) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = Arc::clone(self);
        let scheduled = key.clone();
        let timer = runtime.spawn(async move {
            tokio::time::sleep(millis(delay)).await;
            inner.repull(scheduled, generation).await;
        });
        let mut state = self.lock();
        if let Some(joined) = state.groups.get_mut(key) {
            abort(joined.timer.replace(timer));
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Joined {
    fn new(held: Held) -> Joined {
        Joined {
            held,
            generation: 0,
            timer: None,
        }
    }
}

fn abort(timer: Option<JoinHandle<()>>) {
    if let Some(timer) = timer {
        timer.abort();
    }
}

fn millis(delay: i64) -> Duration {
    Duration::from_millis(u64::try_from(delay).unwrap_or(0))
}

/// The wall clock in Unix milliseconds.
fn wall_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

/// A draw from `[0, 1)`, from the crate's own randomness.
fn uniform() -> f64 {
    let mut bytes = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

/// A pull that did not answer within its timeout.
#[derive(Debug)]
pub(crate) struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the pull timed out")
    }
}

impl std::error::Error for Elapsed {}

// The test scaffolding here builds canned answers and fires scheduled
// re-pulls by hand.
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;
    use crate::group::wire::reply_value;
    use crate::group::KEY_SIZE;

    const PREFIX: &str = "io.macula/acme/chat";
    const NOW: i64 = 1_790_000_000_000;
    const PROVIDER: [u8; 32] = [9; 32];
    const PUBLISHER: [u8; 32] = [3; 32];

    /// An epoch of the protocol's, issued `ago_ms` before now and publishing
    /// for a rotation from there.
    fn epoch(id: u8, ago_ms: i64) -> Epoch {
        let issued_at = NOW - ago_ms;
        let publish_until = issued_at + 15 * 60_000;
        Epoch::new(
            [id; ID_SIZE],
            [id; KEY_SIZE],
            issued_at,
            publish_until,
            publish_until + EVENT_LIFE_MS,
        )
    }

    fn result(prefix: &str, policy: Policy, epochs: Vec<Epoch>) -> Value {
        reply_value(&Reply {
            prefix: prefix.into(),
            policy,
            epochs,
        })
    }

    /// What a test puller answers: a RESULT and the node that answered, or
    /// why it did not.
    type Answer = Result<(Value, [u8; 32]), PullError>;

    /// A distributor's answer, from its node.
    fn answered(policy: Policy, epochs: Vec<Epoch>) -> Answer {
        Ok((result(PREFIX, policy, epochs), PROVIDER))
    }

    /// A puller answering canned results in order, recording every pull it was
    /// asked, and failing once it has no answer left.
    struct Fake {
        answers: Mutex<VecDeque<Answer>>,
        asked: Mutex<Vec<Pull>>,
    }

    #[derive(Debug)]
    struct NoAnswer;

    impl std::fmt::Display for NoAnswer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the test puller had no answer left")
        }
    }

    impl std::error::Error for NoAnswer {}

    impl Fake {
        fn with(answers: Vec<Result<(Value, [u8; 32]), PullError>>) -> Arc<Fake> {
            Arc::new(Fake {
                answers: Mutex::new(answers.into()),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn puller(self: &Arc<Self>) -> Puller {
            let fake = Arc::clone(self);
            Arc::new(move |pull: Pull| Box::pin(Arc::clone(&fake).answer(pull)))
        }

        async fn answer(self: Arc<Self>, pull: Pull) -> Answer {
            self.asked.lock().unwrap().push(pull);
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(PullError::Failed(Box::new(NoAnswer))))
        }

        fn asked(&self) -> usize {
            self.asked.lock().unwrap().len()
        }

        fn last_asked(&self) -> Pull {
            self.asked.lock().unwrap().last().cloned().expect("a pull")
        }
    }

    /// The next canned answer. The first pull goes out at once; every later
    /// one waits on the gate, so a test can hold it in flight.
    async fn next_answer(
        answers: Arc<Mutex<VecDeque<Answer>>>,
        turns: Arc<AtomicUsize>,
        gate: Arc<tokio::sync::Semaphore>,
    ) -> Answer {
        if turns.fetch_add(1, Ordering::SeqCst) > 0 {
            let _turned = gate.acquire_owned().await;
        }
        let answer = answers.lock().unwrap().pop_front();
        answer.unwrap_or_else(|| Err(PullError::Failed(Box::new(NoAnswer))))
    }

    fn keyring(fake: &Arc<Fake>, now: &Arc<AtomicI64>) -> Keyring {
        let now = Arc::clone(now);
        Keyring::new(Options {
            pull: fake.puller(),
            pull_timeout: Duration::from_secs(5),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
            uniform: Arc::new(|| 0.5),
        })
    }

    fn clock() -> Arc<AtomicI64> {
        Arc::new(AtomicI64::new(NOW))
    }

    /// A keyring whose pulls wait on `gate` after the first, so a test can
    /// leave one in flight. It answers how many pulls it has been asked for.
    fn gated_keyring(
        answers: Vec<Answer>,
        gate: Arc<tokio::sync::Semaphore>,
        now: &Arc<AtomicI64>,
    ) -> (Keyring, Arc<AtomicUsize>) {
        let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
        let turns = Arc::new(AtomicUsize::new(0));
        let (pulled_answers, pulled_turns, pulled_gate) =
            (Arc::clone(&answers), Arc::clone(&turns), Arc::clone(&gate));
        let puller: Puller = Arc::new(move |_pull| {
            Box::pin(next_answer(
                Arc::clone(&pulled_answers),
                Arc::clone(&pulled_turns),
                Arc::clone(&pulled_gate),
            ))
        });
        let now = Arc::clone(now);
        let keyring = Keyring::new(Options {
            pull: puller,
            pull_timeout: Duration::from_secs(30),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
            uniform: Arc::new(|| 0.5),
        });
        (keyring, turns)
    }

    /// An open of one epoch, spawned so the test can leave it in flight.
    fn spawn_open(
        keyring: Keyring,
        id: [u8; ID_SIZE],
    ) -> tokio::task::JoinHandle<Result<Epoch, GroupError>> {
        tokio::spawn(async move { keyring.open_epoch([7; 32], PREFIX, id, PUBLISHER).await })
    }

    /// Waits until a test's own pulls have reached `wanted`, so an assertion
    /// is made while one is genuinely in flight.
    async fn until_asked(turns: &Arc<AtomicUsize>, wanted: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while turns.load(Ordering::SeqCst) < wanted && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(turns.load(Ordering::SeqCst), wanted, "the pull went out");
    }

    fn joined(ucan: Vec<u8>) -> JoinOptions {
        JoinOptions {
            ucan,
            distributor: None,
        }
    }

    /// Opens an epoch by id at the public API.
    async fn opened(keyring: &Keyring, id: u8) -> Epoch {
        keyring
            .open_epoch([7; 32], PREFIX, [id; ID_SIZE], PUBLISHER)
            .await
            .unwrap()
    }

    /// Runs the re-pull the timer would have run, for the group as it stands.
    async fn run_scheduled_repull(keyring: &Keyring) {
        let key = ([7; 32], PREFIX.to_string());
        let generation = {
            let state = keyring.inner.lock();
            state.groups.get(&key).map(|j| j.generation).expect("held")
        };
        Arc::clone(&keyring.inner).repull(key, generation).await;
    }

    /// A join pulls the group's current epoch, holds it, and answers the
    /// policy the distributor sent. The pull carries the org's grant and goes
    /// to the org's group_keys_v1.
    #[tokio::test]
    async fn a_join_pulls_the_current_epoch_and_holds_it() {
        let fake = Fake::with(vec![answered(Policy::Required, vec![epoch(1, 60_000)])]);
        let keyring = keyring(&fake, &clock());
        let grant = b"the org's grant".to_vec();

        let policy = keyring
            .join([7; 32], PREFIX, joined(grant.clone()))
            .await
            .unwrap();
        assert_eq!(policy, Policy::Required);
        assert_eq!(fake.asked(), 1);
        let pull = fake.last_asked();
        assert_eq!(pull.procedure, "acme/group_keys_v1");
        assert_eq!(pull.token, grant);
        assert_eq!(pull.provider, None);

        // The policy reads without a pull, and covers every topic under the
        // prefix and no other.
        let (prefix, policy) = keyring
            .policy([7; 32], &format!("{PREFIX}/room/said_v1"))
            .unwrap();
        assert_eq!((prefix.as_str(), policy), (PREFIX, Policy::Required));
        assert!(keyring.policy([7; 32], "io.macula/acme/chatter").is_none());
        assert!(keyring.policy([8; 32], PREFIX).is_none());
        assert_eq!(fake.asked(), 1, "reading a policy never pulls");
    }

    /// Publishing seals under the newest epoch that has started and has not
    /// stopped, and pulls only when the group holds none.
    #[tokio::test]
    async fn publishing_picks_a_held_epoch_and_pulls_only_without_one() {
        let fake = Fake::with(vec![
            answered(Policy::Required, vec![epoch(1, 60_000)]),
            answered(Policy::Required, vec![epoch(2, 0)]),
        ]);
        let keyring = keyring(&fake, &clock());
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();
        let epoch = keyring.publish_epoch([7; 32], PREFIX).await.unwrap();
        assert_eq!(epoch.id, [1; ID_SIZE]);
        assert_eq!(fake.asked(), 1, "a held epoch is published under at once");
    }

    /// The by-id pull of one epoch answers with that epoch.
    async fn assert_opens(keyring: &Keyring, id: u8) {
        assert_eq!(opened(keyring, id).await.id, [id; ID_SIZE]);
    }

    /// An unknown epoch is pulled by id, and one publisher is charged at most
    /// three of those pulls: the fourth is refused without asking at all.
    #[tokio::test]
    async fn an_unknown_epoch_is_pulled_by_id_three_times_a_publisher() {
        let current = answered(Policy::Required, vec![epoch(1, 60_000)]);
        let mut answers = vec![current];
        answers.extend([4u8, 5, 6].map(|id| answered(Policy::Required, vec![epoch(id, 0)])));
        let fake = Fake::with(answers);
        let keyring = keyring(&fake, &clock());
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();

        assert_opens(&keyring, 4).await;
        assert_opens(&keyring, 5).await;
        assert_opens(&keyring, 6).await;
        assert_eq!(fake.asked(), 4, "the join and three by-id pulls");

        let refused = keyring
            .open_epoch([7; 32], PREFIX, [7; ID_SIZE], PUBLISHER)
            .await
            .unwrap_err();
        assert!(refused.is(Reason::UnknownEpoch));
        assert_eq!(fake.asked(), 4, "the fourth is not asked for");
    }

    /// An epoch the distributor says it does not know is not asked for again
    /// while it could still be accepted, and the refusal is the distributor's
    /// own reason.
    #[tokio::test]
    async fn an_epoch_the_distributor_does_not_know_is_not_asked_again() {
        let fake = Fake::with(vec![
            answered(Policy::Required, vec![epoch(1, 60_000)]),
            Err(PullError::Refused {
                reason: Reason::UnknownEpoch,
                cause: None,
            }),
        ]);
        let keyring = keyring(&fake, &clock());
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();

        let refused = keyring
            .open_epoch([7; 32], PREFIX, [4; ID_SIZE], PUBLISHER)
            .await
            .unwrap_err();
        assert!(refused.is(Reason::UnknownEpoch));
        assert_eq!(fake.asked(), 2);
        assert!(keyring
            .open_epoch([7; 32], PREFIX, [4; ID_SIZE], PUBLISHER)
            .await
            .unwrap_err()
            .is(Reason::UnknownEpoch));
        assert_eq!(fake.asked(), 2, "the id is remembered as unknown");
    }

    /// A reply that is not the protocol's is refused `no_distributor`, the
    /// reason the closed set has for it, with the parse failure left as the
    /// cause: a caller never gets an error with no reason at all.
    #[tokio::test]
    async fn a_malformed_reply_is_no_distributor() {
        let fake = Fake::with(vec![Ok((
            Value::Map(vec![(Value::text("policy"), Value::text("sometimes"))]),
            PROVIDER,
        ))]);
        let keyring = keyring(&fake, &clock());
        let refused = keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap_err();
        assert!(refused.is(Reason::NoDistributor), "{refused}");
        assert_eq!(refused.reason(), Some(Reason::NoDistributor));
        assert!(refused.source().is_some(), "the parse failure is the cause");
    }

    /// A pull in flight does not take the group out of the keyring: the policy
    /// it carries is enforced for the whole of the pull, and the epochs it
    /// holds still open. An attacker who can make a pull take its full timeout
    /// cannot use that to lift a required policy, nor to have a held event
    /// read as one from a group this node does not hold.
    #[tokio::test]
    async fn a_pull_in_flight_does_not_lift_the_policy() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (keyring, turns) = gated_keyring(
            vec![answered(Policy::Required, vec![epoch(1, 60_000)])],
            Arc::clone(&gate),
            &clock(),
        );
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();

        // An id the group does not hold is pulled by id, and that pull waits.
        let pulling = spawn_open(keyring.clone(), [9; ID_SIZE]);
        until_asked(&turns, 2).await;

        assert_eq!(
            keyring.policy([7; 32], PREFIX).map(|(_, policy)| policy),
            Some(Policy::Required),
            "the policy holds while a pull is out"
        );
        let held = keyring
            .open_epoch([7; 32], PREFIX, [1; ID_SIZE], PUBLISHER)
            .await
            .expect("an epoch the group holds still opens");
        assert_eq!(held.id, [1; ID_SIZE]);
        let published = keyring
            .publish_epoch([7; 32], PREFIX)
            .await
            .expect("and one it can still publish under");
        assert_eq!(published.id, [1; ID_SIZE]);

        gate.add_permits(1);
        let refused = pulling.await.unwrap().unwrap_err();
        assert!(refused.is(Reason::NoDistributor), "{refused}");
    }

    /// A distributor that refuses with one of the design's reasons reaches the
    /// caller as that reason, on a join and on a publish alike.
    #[tokio::test]
    async fn a_refusal_reaches_the_caller_as_its_reason() {
        let fake = Fake::with(vec![Err(PullError::Refused {
            reason: Reason::NotAMember,
            cause: None,
        })]);
        let keyring = keyring(&fake, &clock());
        let refused = keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap_err();
        assert!(refused.is(Reason::NotAMember), "{refused}");
        assert_eq!(refused.to_string(), "group: not_a_member");

        // Nothing is held: a publish under the group fails closed, and the
        // group can be joined again once the distributor answers.
        assert!(matches!(
            keyring.publish_epoch([7; 32], PREFIX).await,
            Err(GroupError::NotJoined)
        ));
    }

    /// An epoch past its life is refused as expired, and is not kept.
    #[tokio::test]
    async fn an_epoch_past_its_life_is_refused_and_erased() {
        let now = clock();
        // Issued 90 minutes ago: its 15-minute publishing stretch and the
        // 65-minute life of an event under it are both past.
        let stale = epoch(1, 90 * 60_000);
        let fake = Fake::with(vec![
            Ok((result(PREFIX, Policy::Required, vec![stale]), PROVIDER)),
            Err(PullError::Refused {
                reason: Reason::UnknownEpoch,
                cause: None,
            }),
        ]);
        let keyring = keyring(&fake, &now);
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();

        let refused = keyring
            .open_epoch([7; 32], PREFIX, [1; ID_SIZE], PUBLISHER)
            .await
            .unwrap_err();
        assert!(refused.is(Reason::EpochExpired), "{refused}");

        // The stale epoch is dropped on the next pull, so the group holds no
        // epoch to publish under, and the pull that follows is refused by the
        // distributor that does not know the id.
        let refused = keyring.publish_epoch([7; 32], PREFIX).await.unwrap_err();
        assert!(refused.is(Reason::UnknownEpoch), "{refused}");
        let state = keyring.inner.lock();
        let held = state.groups.get(&([7; 32], PREFIX.to_string())).unwrap();
        assert!(held.held.epochs.iter().all(|e| e.id != [1; ID_SIZE]));
    }

    /// A policy never falls back: a reply of off after a preferred is held as
    /// preferred, and no reply lowers a required.
    #[tokio::test]
    async fn a_reply_never_lowers_the_policy() {
        let fake = Fake::with(vec![
            answered(Policy::Preferred, vec![epoch(1, 60_000)]),
            answered(Policy::Off, vec![epoch(2, 0)]),
        ]);
        let keyring = keyring(&fake, &clock());
        let policy = keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();
        assert_eq!(policy, Policy::Preferred);
        run_scheduled_repull(&keyring).await;
        let (_, policy) = keyring.policy([7; 32], PREFIX).unwrap();
        assert_eq!(policy, Policy::Preferred, "off does not lower it");
    }

    /// A failed pull leaves the group on its backoff, doubling each time, and
    /// a re-pull that answers clears it.
    #[tokio::test]
    async fn a_failed_pull_backs_off_and_doubles() {
        let fake = Fake::with(vec![
            answered(Policy::Required, vec![epoch(1, 60_000)]),
            Err(PullError::Failed(Box::new(NoAnswer))),
            Err(PullError::Failed(Box::new(NoAnswer))),
            answered(Policy::Required, vec![epoch(2, 0)]),
        ]);
        let keyring = keyring(&fake, &clock());
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();

        run_scheduled_repull(&keyring).await;
        assert_eq!(backoff(&keyring), 2_000, "the first backoff doubles");
        run_scheduled_repull(&keyring).await;
        assert_eq!(backoff(&keyring), 4_000, "and doubles again");
        run_scheduled_repull(&keyring).await;
        assert_eq!(backoff(&keyring), 1_000, "an answer clears it");
        assert_eq!(fake.asked(), 4);
    }

    fn backoff(keyring: &Keyring) -> i64 {
        let state = keyring.inner.lock();
        state
            .groups
            .get(&([7; 32], PREFIX.to_string()))
            .unwrap()
            .held
            .backoff
    }

    /// The node that answered is the group's distributor from then on, and
    /// that auto-pin is dropped when no trusted advertisement holds it.
    #[tokio::test]
    async fn the_answering_node_is_pinned_and_unpinned() {
        let now = clock();
        let fake = Fake::with(vec![
            answered(Policy::Required, vec![epoch(1, 0)]),
            Err(PullError::NotAdvertised(Box::new(NoAnswer))),
        ]);
        let keyring = keyring(&fake, &now);
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();
        assert_eq!(
            fake.last_asked().provider,
            None,
            "the join's own pull has no distributor to pin yet"
        );

        // Past the epoch's publishing stretch, so a publish must pull: it goes
        // to the node that answered, because that is now the pin.
        now.fetch_add(16 * 60_000, Ordering::SeqCst);
        keyring.publish_epoch([7; 32], PREFIX).await.ok();
        assert_eq!(fake.last_asked().provider, Some(PROVIDER));

        // That pull found no advertisement at the pin, so the auto-pin is
        // dropped and any trusted distributor may answer the next one.
        let state = keyring.inner.lock();
        let held = state.groups.get(&([7; 32], PREFIX.to_string())).unwrap();
        assert_eq!(held.held.pin_kind, PinKind::None);
    }

    /// Leaving a group erases its keys, and a publish under it fails closed.
    #[tokio::test]
    async fn leaving_a_group_erases_its_keys() {
        let fake = Fake::with(vec![answered(Policy::Required, vec![epoch(1, 60_000)])]);
        let keyring = keyring(&fake, &clock());
        keyring
            .join([7; 32], PREFIX, joined(Vec::new()))
            .await
            .unwrap();
        keyring.leave([7; 32], PREFIX);
        assert!(keyring.policy([7; 32], PREFIX).is_none());
        assert!(matches!(
            keyring.publish_epoch([7; 32], PREFIX).await,
            Err(GroupError::NotJoined)
        ));
    }
}
