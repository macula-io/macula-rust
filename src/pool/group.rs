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
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
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
async fn pull_through(pool: Weak<PoolInner>, pull: Pull) -> Result<(Value, [u8; 32]), PullError> {
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
    /// the reason it could not be opened.
    ///
    /// An event that could not be opened arrives once with `unopened` set to
    /// the reason and a null payload, so an application that reads a payload
    /// without checking `unopened` is handed nothing rather than a
    /// ciphertext; `seal_key_id` still names the epoch it was sealed under.
    ///
    /// A clear event under a required group this node holds is refused, and
    /// counted. Under any other policy (preferred or off) a clear event is
    /// delivered as it arrives, so **a subscriber that needs every event
    /// under the group sealed must check the event itself**: its
    /// `seal_key_id` is `None`, or its payload `Payload::Clear`, exactly when
    /// the event arrived in the clear. Only a required policy refuses one.
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

/// The event marked unopened, with the reason it could not be opened and no
/// payload: the same shape the other SDKs deliver, so an application that
/// reads a payload without checking `unopened` is handed nothing rather than
/// a ciphertext that looks like one. `seal_key_id` stays, which names the
/// epoch it could not be opened under.
fn unopened(mut event: station_link::Event, reason: Reason) -> station_link::Event {
    event.unopened = Some(reason);
    event.payload = Payload::Clear(Value::Null);
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

/// An event under a pool that holds no group at all: a sealed one is marked
/// unopened `no_group`, since nothing here can open it, and a clear one is
/// delivered as it arrives, there being no policy to refuse it.
pub(super) fn without_a_group(event: station_link::Event) -> station_link::Event {
    match event.payload {
        Payload::Sealed(_) => unopened(event, Reason::NoGroup),
        Payload::Clear(_) => event,
    }
}

// The test scaffolding here builds canned replies and canned events, which
// nests a block or two deeper than the gate allows. The gate still holds the
// crate's own code to its limit.
#[cfg(test)]
#[allow(clippy::excessive_nesting)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use tokio::sync::Semaphore;

    use super::*;
    use crate::group::{
        seal_event, Epoch, Fields, JoinOptions, Keyring, Options as KeyringOptions, Policy, Puller,
        Reply, EVENT_LIFE_MS, ID_SIZE, KEY_SIZE,
    };

    const PREFIX: &str = "io.macula/acme/chat";
    const NOW: i64 = 1_790_000_000_000;
    const PROVIDER: [u8; 32] = [9; 32];
    const PUBLISHER: [u8; 32] = [3; 32];
    const REALM: [u8; 32] = [7; 32];

    fn our_epoch() -> Epoch {
        let issued_at = NOW - 60_000;
        let publish_until = issued_at + 15 * 60_000;
        Epoch::new(
            [1; ID_SIZE],
            [2; KEY_SIZE],
            issued_at,
            publish_until,
            publish_until + EVENT_LIFE_MS,
        )
    }

    /// What an event's seal is bound to, as the delivered event carries it.
    fn fields(topic: &str) -> Fields {
        Fields {
            realm: REALM,
            topic: topic.to_string(),
            publisher: PUBLISHER,
            seq: 1,
            published_at: NOW as u64,
        }
    }

    /// A pool-free keyring holding `PREFIX` under `policy`, joined with a
    /// distributor that answers the one canned reply.
    async fn keyring(policy: Policy) -> Keyring {
        let reply = crate::group::reply_value(&Reply {
            prefix: PREFIX.into(),
            policy,
            epochs: vec![our_epoch()],
        });
        let puller: Puller = Arc::new(move |_pull| Box::pin(canned(reply.clone())));
        let mut opts = KeyringOptions::new(puller);
        opts.now = Arc::new(|| NOW);
        let keyring = Keyring::new(opts);
        keyring
            .join(REALM, PREFIX, JoinOptions::default())
            .await
            .expect("the join is answered");
        keyring
    }

    /// The one answer a test distributor gives.
    async fn canned(
        reply: crate::cbor::Value,
    ) -> Result<(crate::cbor::Value, [u8; 32]), PullError> {
        Ok((reply, PROVIDER))
    }

    fn topic() -> String {
        format!("{PREFIX}/said_v1")
    }

    fn event(payload: Payload) -> station_link::Event {
        station_link::Event {
            publisher: PUBLISHER,
            realm: REALM,
            topic: topic(),
            seq: 1,
            published_at: NOW as u64,
            seal_key_id: payload.sealed().map(|s| s.key_id),
            payload,
            delivered_via: "direct".into(),
            unopened: None,
        }
    }

    /// A keyring holding `PREFIX` at required, whose pulls after the first
    /// wait on `gate`, so a test can leave one in flight.
    fn gated_keyring(gate: Arc<Semaphore>, turns: &Arc<AtomicUsize>) -> Keyring {
        let reply = crate::group::reply_value(&Reply {
            prefix: PREFIX.into(),
            policy: Policy::Required,
            epochs: vec![our_epoch()],
        });
        let turns = Arc::clone(turns);
        let puller: Puller = Arc::new(move |_pull| {
            let reply = reply.clone();
            let turns = Arc::clone(&turns);
            let gate = Arc::clone(&gate);
            Box::pin(async move {
                if turns.fetch_add(1, Ordering::SeqCst) > 0 {
                    let _turned = Arc::clone(&gate).acquire_owned().await;
                }
                Ok((reply, PROVIDER))
            })
        });
        Keyring::new(KeyringOptions {
            pull: puller,
            pull_timeout: Duration::from_secs(30),
            now: Arc::new(|| NOW),
            uniform: Arc::new(|| 0.5),
        })
    }

    /// A pull in flight does not lift the policy on a plain subscription
    /// either: while the group's epoch is being pulled by id, a clear event
    /// under its prefix is still refused, which is what stops a forged one
    /// being delivered behind a pull an attacker can make take its timeout.
    #[tokio::test]
    async fn a_pull_in_flight_does_not_let_a_clear_event_through_a_plain_subscription() {
        let gate = Arc::new(Semaphore::new(0));
        let turns = Arc::new(AtomicUsize::new(0));
        let keyring = gated_keyring(Arc::clone(&gate), &turns);
        keyring
            .join(REALM, PREFIX, JoinOptions::default())
            .await
            .expect("the join is answered");

        let pulling = {
            let keyring = keyring.clone();
            tokio::spawn(async move {
                keyring
                    .open_epoch(REALM, PREFIX, [9; ID_SIZE], PUBLISHER)
                    .await
            })
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while turns.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(turns.load(Ordering::SeqCst), 2, "the by-id pull went out");

        assert!(
            open_delivered(&keyring, None, event(Payload::Clear(Value::text("forged"))))
                .await
                .is_none(),
            "a plain subscription refuses it while the pull is out too"
        );

        gate.add_permits(1);
        let _ = pulling.await;
    }

    /// A group that is not required delivers a clear event as it arrives, so
    /// a subscriber that needs every event sealed has to check it itself.
    #[tokio::test]
    async fn a_clear_event_is_delivered_under_a_preferred_group() {
        for policy in [Policy::Preferred, Policy::Off] {
            let keyring = keyring(policy).await;
            let delivered = open_delivered(
                &keyring,
                Some(PREFIX),
                event(Payload::Clear(Value::text("clear"))),
            )
            .await
            .expect("a group that is not required delivers a clear event");
            assert_eq!(delivered.unopened, None);
            assert_eq!(
                delivered.seal_key_id, None,
                "a clear event names no epoch, which is how a subscriber tells"
            );
            assert_eq!(delivered.payload, Payload::Clear(Value::text("clear")));
        }
    }

    /// A required group refuses a clear event outright: it is never
    /// delivered, and the subscription counts it.
    #[tokio::test]
    async fn a_clear_event_is_refused_under_a_required_group() {
        let keyring = keyring(Policy::Required).await;
        assert!(open_delivered(
            &keyring,
            Some(PREFIX),
            event(Payload::Clear(Value::text("clear")))
        )
        .await
        .is_none());
    }

    /// The policy holds on a subscription that is not under the group too: a
    /// plain subscription covering a prefix this node holds at `required`
    /// refuses a clear event as well, so no forged clear event under a held
    /// group is delivered to anyone, and a sealed event on it is delivered
    /// unopened, `no_group`, since nothing on that subscription can open it.
    #[tokio::test]
    async fn a_required_group_refuses_a_clear_event_on_a_plain_subscription() {
        let keyring = keyring(Policy::Required).await;
        assert!(
            open_delivered(&keyring, None, event(Payload::Clear(Value::text("forged"))))
                .await
                .is_none(),
            "a plain subscription refuses a clear event under the held prefix"
        );

        let sealed = seal_event(&our_epoch(), &fields(&topic()), &Value::text("sealed")).unwrap();
        let delivered = open_delivered(&keyring, None, event(Payload::Sealed(sealed)))
            .await
            .expect("a sealed event is delivered");
        assert_eq!(delivered.unopened, Some(Reason::NoGroup));
        assert_eq!(delivered.payload, Payload::Clear(Value::Null));
    }

    /// A clear event under a group that is not required reaches a plain
    /// subscription as it is: only `required` refuses one.
    #[tokio::test]
    async fn a_plain_subscription_takes_a_clear_event_under_a_preferred_group() {
        let keyring = keyring(Policy::Preferred).await;
        let delivered = open_delivered(&keyring, None, event(Payload::Clear(Value::text("clear"))))
            .await
            .expect("a preferred group does not refuse it");
        assert_eq!(delivered.payload, Payload::Clear(Value::text("clear")));
        assert_eq!(delivered.unopened, None);
    }

    /// A pool that holds no group at all delivers a clear event as it arrives
    /// and marks a sealed one unopened, there being nothing here to open it.
    #[test]
    fn a_pool_without_a_group_marks_a_sealed_event_only() {
        let clear = without_a_group(event(Payload::Clear(Value::text("clear"))));
        assert_eq!(clear.payload, Payload::Clear(Value::text("clear")));
        assert_eq!(clear.unopened, None);

        let sealed = seal_event(&our_epoch(), &fields(&topic()), &Value::text("sealed")).unwrap();
        let sealed = without_a_group(event(Payload::Sealed(sealed)));
        assert_eq!(sealed.unopened, Some(Reason::NoGroup));
        assert_eq!(sealed.payload, Payload::Clear(Value::Null));
    }

    /// A sealed event under a held epoch is opened and delivered in the shape
    /// a clear one arrives in, still naming the epoch it was sealed under.
    #[tokio::test]
    async fn a_sealed_event_is_opened_and_names_its_epoch() {
        let keyring = keyring(Policy::Required).await;
        let sealed = seal_event(&our_epoch(), &fields(&topic()), &Value::text("sealed")).unwrap();
        let delivered = open_delivered(&keyring, Some(PREFIX), event(Payload::Sealed(sealed)))
            .await
            .expect("a sealed event is delivered");
        assert_eq!(delivered.unopened, None);
        assert_eq!(delivered.seal_key_id, Some([1; ID_SIZE]));
        assert_eq!(delivered.payload, Payload::Clear(Value::text("sealed")));
    }

    /// A sealed event that does not open under the epoch it names is still
    /// delivered once, unopened, with the reason, and with no payload: an
    /// application that reads a payload without checking `unopened` is handed
    /// nothing rather than a ciphertext.
    #[tokio::test]
    async fn a_sealed_event_that_does_not_open_is_delivered_unopened() {
        let keyring = keyring(Policy::Required).await;
        // Sealed under another topic's AAD, so it cannot open under this one.
        let sealed = seal_event(
            &our_epoch(),
            &fields("io.macula/acme/chat/other_v1"),
            &Value::text("x"),
        )
        .unwrap();
        let delivered = open_delivered(
            &keyring,
            Some(PREFIX),
            event(Payload::Sealed(sealed.clone())),
        )
        .await
        .expect("an event that does not open is still delivered");
        assert_eq!(delivered.unopened, Some(Reason::TagInvalid));
        assert_eq!(
            delivered.seal_key_id,
            Some([1; ID_SIZE]),
            "the epoch it could not be opened under is still named"
        );
        assert_eq!(delivered.payload, Payload::Clear(Value::Null));

        // And under an epoch the group does not hold, which the keyring pulls
        // by id and the distributor does not answer with.
        let elsewhere = Epoch::new(
            [4; ID_SIZE],
            [5; KEY_SIZE],
            NOW - 60_000,
            NOW + 15 * 60_000,
            NOW + 15 * 60_000 + EVENT_LIFE_MS,
        );
        let sealed = seal_event(&elsewhere, &fields(&topic()), &Value::text("x")).unwrap();
        let delivered = open_delivered(&keyring, Some(PREFIX), event(Payload::Sealed(sealed)))
            .await
            .expect("an event under an unknown epoch is still delivered");
        assert_eq!(delivered.unopened, Some(Reason::NoDistributor));
    }
}
