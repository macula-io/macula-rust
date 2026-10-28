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
//! - [`DistributorOptions::membership`] is then read at the time of the call,
//!   for a past epoch too, and answers [in](Membership::In),
//!   [not a member](Membership::NotAMember) or
//!   [unknown](Membership::Unknown). A check that does not answer within
//!   [`DistributorOptions::membership_timeout`] is `membership_unknown`, never
//!   `not_a_member`, so the member retries rather than being told it is out.
//!
//! A pull names the group (`prefix`) and the epoch: `current`, or a past one
//! by its 8-byte id. The reply carries the group's policy and the epochs: the
//! asked one, and inside the current's ahead window the next one too. Epoch
//! keys are kept in memory only, and never printed
//! ([`Epoch`](super::Epoch)'s `Debug` redacts them). A refusal is one of the
//! design's five, named exactly as every SDK names it: `not_a_member`,
//! `membership_unknown`, `unknown_epoch`, `epoch_expired` and `unknown_group`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::timeout;

use crate::cbor::Value;
use crate::pool::Offer;
use crate::seal::Clock;
use crate::station_link::{handler, Confidentiality, Handler, Request};
use crate::ucan::Policy as Grant;

use super::epoch::{for_publish, fresh, org_of, wall_clock, NoRandomness, TOLERANCE_MS};
use super::wire::{procedure, reply_value, Policy, Reply};
use super::{Epoch, DEFAULT_ROTATE_AFTER_MS};

/// The capability an org's grant carries for its groups' keys (section 3).
pub const GROUP_KEYS_CAN: &str = "group_keys";

/// How long a distributor waits for the application's membership check before
/// it answers `membership_unknown`: macula's 12 seconds, past a slot read's 5
/// and inside a member's 15-second pull deadline, so no answer is made that no
/// member still waits for.
pub const DEFAULT_MEMBERSHIP_TIMEOUT: Duration = Duration::from_secs(12);

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
    /// How long an epoch publishes, in milliseconds.
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
}

impl DistributorOptions {
    /// The knobs for `org`'s groups answered under `policy`, with the default
    /// rotation, the wall clock, the default membership timeout and nobody
    /// removed.
    pub fn new(org: &str, policy: Policy, membership: MembershipCheck) -> DistributorOptions {
        DistributorOptions {
            org: org.to_string(),
            policy,
            rotate_after_ms: DEFAULT_ROTATE_AFTER_MS,
            now: wall_clock(),
            membership,
            membership_timeout: DEFAULT_MEMBERSHIP_TIMEOUT,
            removed: Arc::new(|_, _| false),
        }
    }
}

/// A distributor of its org's groups' keys: the epochs of every group it
/// serves, made on demand, contiguous, and held in memory only. Cloning shares
/// the epochs, so every handle of one distributor serves the same chain.
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
    groups: Mutex<HashMap<String, Vec<Epoch>>>,
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

/// Why a pull has no answer: one of the design's refusals, or this node's own
/// randomness not answering, which is no refusal of the design's and which a
/// member retries as a failed pull.
enum Unanswered {
    Refused(Refusal),
    NoRandomness(NoRandomness),
}

impl Unanswered {
    /// The detail of the `handler_error` that carries it. A failure that is
    /// not a refusal names something none of the design's five does, so a
    /// member reads it as a failed pull and retries rather than as a refusal.
    fn detail(&self) -> String {
        match self {
            Unanswered::Refused(refusal) => refusal.name().to_string(),
            Unanswered::NoRandomness(cause) => cause.to_string(),
        }
    }
}

impl From<Refusal> for Unanswered {
    fn from(refusal: Refusal) -> Unanswered {
        Unanswered::Refused(refusal)
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
    pub fn new(opts: DistributorOptions) -> Distributor {
        Distributor {
            inner: Arc::new(Inner {
                org: opts.org,
                policy: opts.policy,
                rotate_after_ms: opts.rotate_after_ms,
                now: opts.now,
                membership: opts.membership,
                membership_timeout: opts.membership_timeout,
                removed: opts.removed,
                groups: Mutex::new(HashMap::new()),
            }),
        }
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
    pub fn handler(&self) -> Handler {
        let distributor = self.clone();
        handler(move |request: Request| answering(distributor.clone(), request))
    }

    /// Answers one pull: the group's epochs to a caller the application admits
    /// to it.
    async fn pull(&self, request: Request) -> Result<Value, Unanswered> {
        let prefix = self.owned(&request.payload)?;
        self.admit(&prefix, request.caller).await?;
        let now = (self.inner.now)();
        let reply = match request.payload.get("epoch") {
            Some(Value::Text(current)) if current == "current" => self.current(&prefix, now)?,
            Some(Value::Bytes(id)) => self.past(&prefix, id, now)?,
            _ => Err(Refusal::UnknownEpoch)?,
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
    /// first, which is absolute, then its membership, read now.
    async fn admit(&self, prefix: &str, caller: [u8; 32]) -> Result<(), Refusal> {
        if (self.inner.removed)(prefix, caller) {
            return Err(Refusal::NotAMember);
        }
        let asked = (self.inner.membership)(prefix.to_string(), caller);
        match timeout(self.inner.membership_timeout, asked).await {
            Ok(Membership::In) => Ok(()),
            Ok(Membership::NotAMember) => Err(Refusal::NotAMember),
            Ok(Membership::Unknown) => Err(Refusal::MembershipUnknown),
            Err(_elapsed) => Err(Refusal::MembershipUnknown),
        }
    }

    /// The group's epochs to a pull of its current one: the ones still kept,
    /// advanced to `now`, with the next inside the current's ahead window, and
    /// the epochs list the current one and the next. The ones no longer kept
    /// are dropped here, so an epoch key is erased once no event under it can
    /// be accepted any more.
    fn current(&self, prefix: &str, now: i64) -> Result<Reply, Unanswered> {
        let rotation = self.inner.rotate_after_ms;
        let mut groups = self.lock();
        let kept = kept(&groups.remove(prefix).unwrap_or_default(), now, rotation);
        let epochs = ahead(advanced(kept, now, rotation)?, now, rotation)?;
        let Some(current) = for_publish(&epochs, now).cloned() else {
            groups.insert(prefix.to_string(), epochs);
            // Only a clock that went backwards leaves no epoch covering
            // `now`: no epoch of this group is issued yet, which is the
            // truth a pull is answered with.
            return Err(Refusal::UnknownEpoch.into());
        };
        let issued_with = epochs
            .iter()
            .filter(|epoch| epoch.issued_at == current.publish_until)
            .cloned()
            .collect::<Vec<_>>();
        let mut answered = vec![current];
        answered.extend(issued_with);
        groups.insert(prefix.to_string(), epochs);
        Ok(self.reply(prefix, answered))
    }

    /// The group's epoch `id` to a pull of a past one: answered while it is
    /// still accepted, `epoch_expired` while it is kept past that so a
    /// subscriber learns why it could not catch up, and `unknown_epoch` once
    /// it is held no longer (a distributor that restarted holds none).
    fn past(&self, prefix: &str, id: &[u8], now: i64) -> Result<Reply, Unanswered> {
        let rotation = self.inner.rotate_after_ms;
        let groups = self.lock();
        let held = groups.get(prefix).map(Vec::as_slice).unwrap_or_default();
        let Some(epoch) = kept(held, now, rotation)
            .into_iter()
            .find(|epoch| epoch.id.as_slice() == id)
        else {
            return Err(Refusal::UnknownEpoch.into());
        };
        if !epoch.acceptable(now) {
            return Err(Refusal::EpochExpired.into());
        }
        Ok(self.reply(prefix, vec![epoch]))
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

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Vec<Epoch>>> {
        self.inner
            .groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One pull answered as a handler's future: the RESULT, or the detail of the
/// `handler_error` that carries the refusal.
async fn answering(distributor: Distributor, request: Request) -> Result<Value, String> {
    distributor
        .pull(request)
        .await
        .map_err(|unanswered| unanswered.detail())
}

/// The group's epochs up to one current at `now`: contiguous after the newest,
/// or a fresh one when the group sat idle for a whole rotation.
fn advanced(epochs: Vec<Epoch>, now: i64, rotation: i64) -> Result<Vec<Epoch>, NoRandomness> {
    let Some(newest) = epochs.last().cloned() else {
        return Ok(vec![fresh(now, rotation)?]);
    };
    if now < newest.publish_until {
        return Ok(epochs);
    }
    advanced_past(epochs, newest, now, rotation)
}

/// `epochs` whose newest stopped publishing at `newest.publish_until`, which
/// is at or before `now`: one more epoch appended, and the same asked again.
fn advanced_past(
    mut epochs: Vec<Epoch>,
    newest: Epoch,
    now: i64,
    rotation: i64,
) -> Result<Vec<Epoch>, NoRandomness> {
    let made = match now - newest.publish_until >= rotation {
        true => fresh(now, rotation)?,
        false => newest.following(rotation)?,
    };
    epochs.push(made);
    advanced(epochs, now, rotation)
}

/// `epochs` with the next one appended when `now` is inside the newest's ahead
/// window, so a pull there hands out the epoch the group is about to publish
/// under and every holder re-pulls before it is needed.
fn ahead(epochs: Vec<Epoch>, now: i64, rotation: i64) -> Result<Vec<Epoch>, NoRandomness> {
    let Some(newest) = epochs.last().cloned() else {
        return Ok(epochs);
    };
    match newest.in_ahead_window(now) {
        true => {
            let next = newest.following(rotation)?;
            Ok(epochs.into_iter().chain([next]).collect())
        }
        false => Ok(epochs),
    }
}

/// The group's epochs still kept at `now`: until acceptance, plus one rotation
/// past it, so a pull of one that is no longer accepted is answered
/// `epoch_expired` for that while rather than `unknown_epoch`.
fn kept(epochs: &[Epoch], now: i64, rotation: i64) -> Vec<Epoch> {
    epochs
        .iter()
        .filter(|epoch| now <= epoch.accept_until + TOLERANCE_MS + rotation)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

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
        Distributor::new(opts)
    }

    /// A distributor reading a clock that starts at `start`.
    fn distributor(start: i64) -> (Distributor, Arc<AtomicI64>) {
        let (opts, clock) = options(start);
        (distributor_of(opts, &clock), clock)
    }

    /// One pull, through the handler the pool would serve.
    async fn pull(distributor: &Distributor, payload: Value) -> Result<Value, String> {
        let request = Request {
            caller: CALLER,
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

    /// A pull of the group's current epoch.
    async fn current(distributor: &Distributor) -> Result<Reply, String> {
        let answered = pull(distributor, current_request(&prefix())).await?;
        Ok(parse_reply(&prefix(), &answered).expect("the distributor answers the protocol"))
    }

    /// The group's current epoch, which a test then hands around.
    async fn epoch_now(distributor: &Distributor) -> Epoch {
        current(distributor)
            .await
            .expect("the distributor answers")
            .epochs[0]
            .clone()
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
        assert_eq!(held[0].id, now.id);
        assert_ne!(held[0].id, first.id);
    }

    /// The epochs the distributor holds for this group.
    fn stored(distributor: &Distributor) -> Vec<Epoch> {
        let groups = distributor.lock();
        groups.get(&prefix()).cloned().unwrap_or_default()
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
}
