//! A client's status statement issuer, the client side of macula's
//! macula_statement_issuer (D22), as macula-go's StatementIssuer. It holds the
//! identity key, the node's CONNECT bindings with the newest status statement
//! for each, and the current CONNECT key. Each tick issues a statement valid
//! for an hour for each binding whose not_after has not passed, and hands it
//! to that binding's subscribers, the links that connected with it. Every 5
//! days it rotates the CONNECT key: the new key's binding and statement exist
//! before [`StatementIssuer::connect_material`] hands the key out, and the
//! rotated-out binding keeps its statements until its not_after.
//! `connect_material` does work that is due itself, so a dial after missed
//! ticks, a sleep or a clock step still carries material in force. Nothing is
//! written to disk, so a new issuer starts with a new CONNECT key.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use sha2::{Digest, Sha384};
use tokio::sync::Notify;

use crate::binding::{connect_binding, status_statement, BindingError, SignedTbs};
use crate::node_key::{KeyError, NodeKey, Purpose};

/// How often statements are reissued.
pub const STATEMENT_EVERY_MS: i64 = 15 * 60 * 1000;
/// How long a status statement is valid.
pub const STATEMENT_VALID_MS: i64 = 60 * 60 * 1000;
/// How long a CONNECT binding is valid.
pub const CONNECT_BINDING_VALID_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// How often the CONNECT key rotates.
pub const CONNECT_ROTATE_EVERY_MS: i64 = 5 * 24 * 60 * 60 * 1000;
/// How long before the current binding's not_after a failed rotation is
/// reported as overdue.
pub const ROTATION_MARGIN_MS: i64 = 24 * 60 * 60 * 1000;

const TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// Why the issuer could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// The key given is not an identity key.
    NotAnIdentityKey,
    /// A subscription to a binding the issuer does not hold, or whose
    /// not_after has passed.
    UnknownBinding,
    /// No CONNECT binding and status statement in force, because the work
    /// that renews them failed.
    NoConnectMaterial(String),
    /// A rotation failed while the current binding expires within the
    /// rotation margin.
    RotationOverdue { failures: u64, left_ms: i64 },
    /// A key could not be made or could not sign.
    Key(KeyError),
    /// A binding or statement could not be issued.
    Binding(BindingError),
}

impl fmt::Display for IssuerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssuerError::NotAnIdentityKey => f.write_str("the issuer needs an identity key"),
            IssuerError::UnknownBinding => f.write_str("no binding in force has that hash"),
            IssuerError::NoConnectMaterial(why) => write!(f, "no CONNECT binding and status statement in force: {why}"),
            IssuerError::RotationOverdue { failures, left_ms } => write!(
                f,
                "the CONNECT key has not rotated: {failures} failed rotations, {left_ms} ms left on its binding"
            ),
            IssuerError::Key(e) => write!(f, "{e}"),
            IssuerError::Binding(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IssuerError {}

impl From<KeyError> for IssuerError {
    fn from(e: KeyError) -> Self {
        IssuerError::Key(e)
    }
}

impl From<BindingError> for IssuerError {
    fn from(e: BindingError) -> Self {
        IssuerError::Binding(e)
    }
}

/// What a new dial carries: the CONNECT key, its binding, and a status
/// statement for that binding.
#[derive(Debug, Clone)]
pub struct ConnectMaterial {
    pub key: Arc<NodeKey>,
    pub binding: SignedTbs,
    pub status: SignedTbs,
}

/// A clock in Unix milliseconds.
pub type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// A binding the issuer holds, with its newest statement, and its key while
/// it is the current binding.
struct StatedBinding {
    key: Option<Arc<NodeKey>>,
    binding: SignedTbs,
    statement: SignedTbs,
    bound_at: i64,
    stated_at: i64,
    not_after: i64,
}

impl StatedBinding {
    fn rotation_due(&self, now: i64) -> bool {
        now < self.bound_at - TOLERANCE_MS || now >= self.bound_at + CONNECT_ROTATE_EVERY_MS
    }

    fn restatement_due(&self, now: i64) -> bool {
        now < self.stated_at - TOLERANCE_MS || now >= self.stated_at + STATEMENT_EVERY_MS
    }

    fn in_force(&self, now: i64) -> bool {
        self.bound_at - TOLERANCE_MS <= now
            && now <= self.not_after
            && self.stated_at - TOLERANCE_MS <= now
            && now < self.stated_at + STATEMENT_VALID_MS
    }
}

/// A subscription's slot: at most the newest statement, whether it closed,
/// and the waker of a reader waiting for one.
struct Slot {
    newest: Mutex<(Option<SignedTbs>, bool)>,
    notify: Notify,
}

struct State {
    identity: Arc<NodeKey>,
    clock: Clock,
    current: [u8; 48],
    bindings: HashMap<[u8; 48], StatedBinding>,
    subscribers: HashMap<[u8; 48], Vec<Arc<Slot>>>,
    rotation_failures: u64,
}

/// A client's statement issuer, shared by every link of one node.
#[derive(Clone)]
pub struct StatementIssuer {
    state: Arc<Mutex<State>>,
}

impl StatementIssuer {
    /// An issuer for `identity`, reading the time from `clock`. It starts with
    /// a new CONNECT key, bound and stated.
    pub fn new(identity: Arc<NodeKey>, clock: Clock) -> Result<StatementIssuer, IssuerError> {
        if identity.purpose() != Purpose::Identity {
            return Err(IssuerError::NotAnIdentityKey);
        }
        let now = clock();
        let mut state = State {
            identity,
            clock,
            current: [0; 48],
            bindings: HashMap::new(),
            subscribers: HashMap::new(),
            rotation_failures: 0,
        };
        state.rotate_connect(now)?;
        Ok(StatementIssuer {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// An issuer on the wall clock.
    pub fn with_wall_clock(identity: Arc<NodeKey>) -> Result<StatementIssuer, IssuerError> {
        StatementIssuer::new(identity, Box::new(|| crate::uuid_v7::now_ms() as i64))
    }

    /// The current CONNECT key with its binding and a statement for it, both
    /// in force at the clock's time. Work that is due is done first.
    pub fn connect_material(&self) -> Result<ConnectMaterial, IssuerError> {
        let mut state = self.lock();
        let now = (state.clock)();
        let mut work = Ok(());
        let due = state
            .bindings
            .get(&state.current)
            .is_some_and(|b| b.rotation_due(now) || b.restatement_due(now));
        if due {
            work = state.tick(now);
        }
        let current = &state.bindings[&state.current];
        match &current.key {
            Some(key) if current.in_force(now) => Ok(ConnectMaterial {
                key: key.clone(),
                binding: current.binding.clone(),
                status: current.statement.clone(),
            }),
            _ => Err(IssuerError::NoConnectMaterial(match work {
                Err(e) => e.to_string(),
                Ok(()) => "the current binding is out of force".into(),
            })),
        }
    }

    /// How many rotations have failed since the last that succeeded.
    pub fn rotation_failures(&self) -> u64 {
        self.lock().rotation_failures
    }

    /// Hands over the newest statement for `binding` at every reissue. The
    /// subscription closes once a tick finds the binding's not_after passed,
    /// and unsubscribes when dropped.
    pub fn subscribe(&self, binding: &SignedTbs) -> Result<StatementSubscription, IssuerError> {
        let hash: [u8; 48] = Sha384::digest(&binding.tbs).into();
        let mut state = self.lock();
        let now = (state.clock)();
        match state.bindings.get(&hash) {
            Some(held) if held.not_after >= now => {}
            _ => return Err(IssuerError::UnknownBinding),
        }
        let slot = Arc::new(Slot {
            newest: Mutex::new((None, false)),
            notify: Notify::new(),
        });
        state
            .subscribers
            .entry(hash)
            .or_default()
            .push(slot.clone());
        Ok(StatementSubscription {
            slot,
            hash,
            issuer: Arc::downgrade(&self.state),
        })
    }

    /// The periodic work at the clock's time: a statement for each binding in
    /// force, a rotation when one is due, and the expired bindings let go.
    pub fn tick(&self) -> Result<(), IssuerError> {
        let mut state = self.lock();
        let now = (state.clock)();
        state.tick(now)
    }

    /// Ticks every 15 minutes until every handle to the issuer is dropped,
    /// handing a failed tick's error to `on_error`.
    pub fn spawn_ticks(
        &self,
        on_error: impl Fn(IssuerError) + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.state);
        tokio::spawn(tick_until_dropped(weak, on_error))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl State {
    fn tick(&mut self, now: i64) -> Result<(), IssuerError> {
        let reissued = self.reissue(now);
        let mut rotated = Ok(());
        if self
            .bindings
            .get(&self.current)
            .is_some_and(|b| b.rotation_due(now))
        {
            rotated = self.rotate(now);
        }
        self.drop_expired(now);
        reissued.and(rotated)
    }

    fn rotate(&mut self, now: i64) -> Result<(), IssuerError> {
        let Err(e) = self.rotate_connect(now) else {
            self.rotation_failures = 0;
            return Ok(());
        };
        self.rotation_failures += 1;
        let left = self
            .bindings
            .get(&self.current)
            .map_or(0, |b| b.not_after - now);
        if left < ROTATION_MARGIN_MS {
            return Err(IssuerError::RotationOverdue {
                failures: self.rotation_failures,
                left_ms: left,
            });
        }
        Err(e)
    }

    fn reissue(&mut self, now: i64) -> Result<(), IssuerError> {
        let mut first_error = Ok(());
        let unexpired = self
            .bindings
            .iter_mut()
            .filter(|(_, held)| held.not_after >= now);
        for (hash, held) in unexpired {
            let stated = restate(&self.identity, &self.subscribers, hash, held, now);
            first_error = first_error.and_then(|()| stated.map_err(IssuerError::from));
        }
        first_error
    }

    fn drop_expired(&mut self, now: i64) {
        let expired: Vec<[u8; 48]> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.not_after < now)
            .map(|(h, _)| *h)
            .collect();
        for hash in expired {
            self.let_go(hash);
        }
    }

    /// Closes an expired binding's subscriptions and forgets the binding,
    /// unless it is still the current one.
    fn let_go(&mut self, hash: [u8; 48]) {
        for slot in self.subscribers.remove(&hash).into_iter().flatten() {
            close(&slot);
        }
        if hash != self.current {
            self.bindings.remove(&hash);
        }
    }

    fn rotate_connect(&mut self, now: i64) -> Result<(), IssuerError> {
        let key = NodeKey::generate(Purpose::Connect, self.identity.profile())?;
        let not_after = now + CONNECT_BINDING_VALID_MS;
        let binding = connect_binding(&self.identity, &key.public_key(), now, not_after)?;
        let statement = status_statement(&self.identity, &binding, now, now + STATEMENT_VALID_MS)?;
        if let Some(previous) = self.bindings.get_mut(&self.current) {
            previous.key = None;
        }
        let hash: [u8; 48] = Sha384::digest(&binding.tbs).into();
        self.bindings.insert(
            hash,
            StatedBinding {
                key: Some(Arc::new(key)),
                binding,
                statement,
                bound_at: now,
                stated_at: now,
                not_after,
            },
        );
        self.current = hash;
        Ok(())
    }
}

/// Ticks every 15 minutes while some handle still holds the issuer's state,
/// handing a failed tick's error to `on_error`.
async fn tick_until_dropped(weak: Weak<Mutex<State>>, on_error: impl Fn(IssuerError)) {
    let mut ticks =
        tokio::time::interval(std::time::Duration::from_millis(STATEMENT_EVERY_MS as u64));
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let Some(state) = weak.upgrade() else { return };
        let issuer = StatementIssuer { state };
        if let Err(e) = issuer.tick() {
            on_error(e);
        }
    }
}

/// Issues a new statement for one binding in force, keeps it as the newest,
/// and hands it to the binding's subscribers.
fn restate(
    identity: &NodeKey,
    subscribers: &HashMap<[u8; 48], Vec<Arc<Slot>>>,
    hash: &[u8; 48],
    held: &mut StatedBinding,
    now: i64,
) -> Result<(), BindingError> {
    let statement = status_statement(identity, &held.binding, now, now + STATEMENT_VALID_MS)?;
    held.statement = statement.clone();
    held.stated_at = now;
    for slot in subscribers.get(hash).into_iter().flatten() {
        deliver(slot, statement.clone());
    }
    Ok(())
}

fn deliver(slot: &Slot, statement: SignedTbs) {
    let mut newest = slot.newest.lock().unwrap_or_else(|p| p.into_inner());
    newest.0 = Some(statement);
    drop(newest);
    slot.notify.notify_one();
}

fn close(slot: &Slot) {
    slot.newest.lock().unwrap_or_else(|p| p.into_inner()).1 = true;
    slot.notify.notify_one();
}

/// Why a subscription handed over no statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionEmpty {
    /// None has been issued since the last taken.
    Empty,
    /// The subscription has closed.
    Closed,
}

/// A subscription to one binding's statements, holding at most the newest.
pub struct StatementSubscription {
    slot: Arc<Slot>,
    hash: [u8; 48],
    issuer: Weak<Mutex<State>>,
}

impl StatementSubscription {
    /// The newest statement not yet taken.
    pub fn try_recv(&mut self) -> Result<SignedTbs, SubscriptionEmpty> {
        let mut newest = self.slot.newest.lock().unwrap_or_else(|p| p.into_inner());
        match newest.0.take() {
            Some(statement) => Ok(statement),
            None if newest.1 => Err(SubscriptionEmpty::Closed),
            None => Err(SubscriptionEmpty::Empty),
        }
    }

    /// The next statement, or `None` once the subscription has closed.
    pub async fn recv(&mut self) -> Option<SignedTbs> {
        let slot = self.slot.clone();
        loop {
            let notified = slot.notify.notified();
            match self.try_recv() {
                Ok(statement) => return Some(statement),
                Err(SubscriptionEmpty::Closed) => return None,
                Err(SubscriptionEmpty::Empty) => notified.await,
            }
        }
    }
}

impl Drop for StatementSubscription {
    fn drop(&mut self) {
        let Some(state) = self.issuer.upgrade() else {
            return;
        };
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slots) = state.subscribers.get_mut(&self.hash) {
            slots.retain(|s| !Arc::ptr_eq(s, &self.slot));
        }
    }
}
