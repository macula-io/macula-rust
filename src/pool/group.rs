//! Sealed groups through the pool (DESIGN_E2E_SEALED_PUBSUB.md section 7):
//! joining a group with the org's grant, publishing sealed under its current
//! epoch, and subscribing where each sealed event is opened under the group
//! and delivered once, or delivered once unopened with the reason it could
//! not be. The pool holds one keyring per node identity, pulling over its own
//! sealed calls.

use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::cbor::Value;
use crate::frame::Payload;
use crate::group::{
    self, Group, GroupError, Keyring, Options as KeyringOptions, Policy, Pull, PullError, Reason,
};
use crate::station_link::{self, Confidentiality, LinkError};

use super::{Call, Pool, PoolError, PoolInner, Subscription};

/// The code a provider answers a refusal of its own with.
const HANDLER_ERROR: &str = "handler_error";

/// A call the pool could not complete, kept as the cause of a pull's failure.
#[derive(Debug)]
pub(crate) struct CallFailed(PoolError);

impl std::fmt::Display for CallFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for CallFailed {}

impl PoolInner {
    /// The pool's keyring: made with the pool on the first join, pulling over
    /// the pool's own sealed calls, and shared from then on.
    pub(super) fn groups(self: &Arc<Self>) -> Keyring {
        let mut held = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let keyring = held.clone().unwrap_or_else(|| self.make_groups());
        if held.is_none() {
            *held = Some(keyring.clone());
        }
        keyring
    }

    /// A keyring pulling over this pool's own sealed calls, closed already
    /// when the pool is: a pool that has closed holds nothing, so every join
    /// is refused and no re-pull is scheduled.
    fn make_groups(self: &Arc<Self>) -> Keyring {
        let keyring = Keyring::new(KeyringOptions::new(group_puller(self)));
        if self.lock().closed {
            keyring.close();
        }
        keyring
    }

    /// The pool's keyring, `None` while no group was ever joined.
    pub(super) fn held_groups(&self) -> Option<Keyring> {
        self.groups.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// One key pull: a call sealed to the distributor's own KEM key, never in
    /// the clear, carrying the org's grant. Only a call no trusted
    /// distributor answered at all is "not advertised"; a candidate that
    /// could not be reached keeps the group's distributor, as macula keeps
    /// it on anything but `provider_not_advertised`.
    pub(super) async fn pull_group_keys(
        self: &Arc<Self>,
        pull: Pull,
    ) -> Result<(Value, [u8; 32]), PullError> {
        let call = Call {
            realm: pull.realm,
            procedure: pull.procedure,
            provider: pull.provider.unwrap_or([0; 32]),
            payload: pull.payload,
            timeout: Duration::ZERO,
            token: Some(pull.token),
            proofs: Vec::new(),
            confidential: Confidentiality::Required,
        };
        let pool = Pool {
            inner: Arc::clone(self),
        };
        match pool.call_report(call).await {
            Ok((result, report)) => Ok((result, report.provider)),
            Err(e) => Err(pull_error(e)),
        }
    }

    /// The prefix of a group this node holds that covers `topic`, whichever
    /// its policy: a clear publish under it is refused rather than sent in
    /// the clear or silently sealed, as macula refuses it.
    pub(super) fn held_prefix(&self, realm: &[u8; 32], topic: &str) -> Option<String> {
        let (prefix, _) = self.held_groups()?.policy(*realm, topic)?;
        Some(prefix)
    }
}

/// The pool as a group puller: it reaches the pool weakly, so a keyring held
/// by the pool does not keep the pool alive.
fn group_puller(inner: &Arc<PoolInner>) -> group::Puller {
    let pool: Weak<PoolInner> = Arc::downgrade(inner);
    Arc::new(move |pull: Pull| Box::pin(pull_through(pool.clone(), pull)))
}

/// One pull, and `PoolClosed` when the pool went while it was in flight.
async fn pull_through(
    pool: Weak<PoolInner>,
    pull: Pull,
) -> Result<(Value, [u8; 32]), PullError> {
    let pool = pool
        .upgrade()
        .ok_or_else(|| PullError::Failed(Box::new(PoolClosed)))?;
    pool.pull_group_keys(pull).await
}

/// A pool that has gone while a pull was in flight.
#[derive(Debug)]
struct PoolClosed;

impl std::fmt::Display for PoolClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the pool has closed")
    }
}

impl std::error::Error for PoolClosed {}

/// Why a failed call is held as a pull's failure: a refusal the distributor
/// named, no advertisement at all, or the call itself.
fn pull_error(e: PoolError) -> PullError {
    let refusal = match &e {
        PoolError::Link(LinkError::Provider { code, detail, .. }) if code == HANDLER_ERROR => {
            detail.as_deref().and_then(Reason::from_refusal)
        }
        _ => None,
    };
    match (refusal, e) {
        (Some(reason), e) => PullError::Refused {
            reason,
            cause: Some(Box::new(CallFailed(e))),
        },
        (None, e @ PoolError::NoProvider(_)) => PullError::NotAdvertised(Box::new(CallFailed(e))),
        (None, e) => PullError::Failed(Box::new(CallFailed(e))),
    }
}

impl Pool {
    /// Joins the sealed group `g` in `realm` with the org's grant, holding its
    /// epochs from then on. It answers the group's policy, or the pull's
    /// refusal.
    pub async fn join_group(&self, realm: &[u8; 32], g: &Group) -> Result<Policy, GroupError> {
        group::org_of(&g.prefix)?;
        self.inner
            .groups()
            .join(*realm, &g.prefix, g.join_options())
            .await
    }

    /// Stops holding the group and erases its epochs.
    pub fn leave_group(&self, realm: &[u8; 32], prefix: &str) {
        if let Some(groups) = self.inner.held_groups() {
            groups.leave(*realm, prefix);
        }
    }

    /// The joined group covering `topic` and its policy.
    pub fn group_policy(&self, realm: &[u8; 32], topic: &str) -> Option<(String, Policy)> {
        self.inner.held_groups()?.policy(*realm, topic)
    }

    /// Publishes `payload` sealed under `g`'s current epoch: joining the
    /// group first when it is not held, then sealing with the publisher's own
    /// subkey of the epoch key, a fresh nonce and the event AAD. A publisher
    /// whose epochs have all stopped publishing pulls at once, and the
    /// publish fails closed with that pull's error.
    pub async fn publish_group(
        &self,
        realm: &[u8; 32],
        topic: &str,
        g: &Group,
        payload: Value,
    ) -> Result<(), GroupError> {
        g.covering(topic)?;
        let groups = self.inner.groups();
        groups.join(*realm, &g.prefix, g.join_options()).await?;
        let epoch = groups.publish_epoch(*realm, &g.prefix).await?;
        // The seq and the time are fixed before the seal, because the event
        // AAD binds both: sealing first and letting the signer pick its own
        // would bind a seq and a time the publication does not carry.
        let key = &self.inner.opts.identity;
        let seq = self.inner.publication_seq.next();
        let published_at = u64::try_from(crate::station_link::now_ms()).unwrap_or(0);
        let sealed = group::seal_event(
            &epoch,
            &group::Fields {
                realm: *realm,
                topic: topic.to_string(),
                publisher: key.key_id(),
                seq,
                published_at,
            },
            &payload,
        )?;
        let signed = station_link::SignedPublication::sign_at(
            key,
            seq,
            published_at,
            station_link::Publication {
                realm: *realm,
                topic: topic.to_string(),
                payload: Payload::Sealed(sealed),
                ttl_ms: None,
            },
        )
        .map_err(|e| GroupError::Pool(Box::new(e)))?;
        self.inner
            .send_signed(&signed)
            .await
            .map_err(|e| GroupError::Pool(Box::new(e)))
    }

    /// Subscribes to `topic` in `realm` under `g`: it joins the group first,
    /// failing with the join's refusal, and each sealed event is then opened
    /// under the group and delivered once, or delivered once unopened with
    /// the reason it could not be opened. A clear event under a required
    /// group this node holds is refused, and counted.
    pub async fn subscribe_group(
        &self,
        realm: &[u8; 32],
        topic: &str,
        g: &Group,
    ) -> Result<Subscription, GroupError> {
        g.covering(topic)?;
        let groups = self.inner.groups();
        groups.join(*realm, &g.prefix, g.join_options()).await?;
        self.subscribe_under(realm, topic, Some(g.prefix.clone()))
            .await
            .map_err(|e| GroupError::Pool(Box::new(e)))
    }
}

/// A received event as a subscription under a group delivers it: a sealed
/// event opened under the group, or delivered once marked unopened with the
/// reason it could not be opened. A clear event under a required group this
/// node holds is refused outright, and answers `None`.
pub(super) async fn open_delivered(
    groups: &Keyring,
    prefix: Option<&str>,
    event: station_link::Event,
) -> Option<station_link::Event> {
    let sealed = match &event.payload {
        Payload::Clear(_) => {
            let refused = groups
                .policy(event.realm, &event.topic)
                .is_some_and(|(_, policy)| policy == Policy::Required);
            return (!refused).then_some(event);
        }
        Payload::Sealed(sealed) => sealed.clone(),
    };
    let Some(prefix) = prefix else {
        return Some(unopened(event, Reason::NoGroup));
    };
    if !sealed.known_scheme() {
        return Some(unopened(event, Reason::TagInvalid));
    }
    let id = sealed.key_id;
    let epoch = match groups
        .open_epoch(event.realm, prefix, id, event.publisher)
        .await
    {
        Ok(epoch) => epoch,
        Err(e) => return Some(unopened(event, e.reason().unwrap_or(Reason::NoGroup))),
    };
    match group::open_event(&epoch, &fields_of(&event), &sealed) {
        Ok(payload) => Some(station_link::Event {
            payload: Payload::Clear(payload),
            ..event
        }),
        Err(_) => Some(unopened(event, Reason::TagInvalid)),
    }
}

/// The event marked unopened, with the reason it could not be opened. Its
/// payload stays the ciphertext, so nothing was read.
fn unopened(mut event: station_link::Event, reason: Reason) -> station_link::Event {
    event.unopened = Some(reason);
    event
}

/// What an event's seal is bound to.
fn fields_of(event: &station_link::Event) -> group::Fields {
    group::Fields {
        realm: event.realm,
        topic: event.topic.clone(),
        publisher: event.publisher,
        seq: event.seq,
        published_at: event.published_at,
    }
}

/// An event under a subscription whose group holds nothing to open it with.
pub(super) fn unopened_no_group(event: station_link::Event) -> station_link::Event {
    unopened(event, Reason::NoGroup)
}
