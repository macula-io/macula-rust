//! PubSub, as macula 12's link does it. A PUBLISH carries a publication
//! signed with the link's identity key; SUBSCRIBE and UNSUBSCRIBE are control
//! frames naming the realm, the topic and this node, with no
//! acknowledgement; an EVENT carries a publication that is verified before it
//! is delivered, and delivered once however many copies arrive, until it
//! expires.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::mpsc;

use crate::cbor::Value;
use crate::frame::{self, Payload, PublicationSpec};
use crate::node_key::NodeKey;

use super::{now_ms, Inner, Link, LinkError};

/// How many events a subscription holds that its reader has not taken; an
/// event arriving at a full subscription is dropped and counted.
const EVENT_BUFFER: usize = 64;

/// What [`Link::publish`] sends: the realm and topic, the payload, and its
/// time to live, `None` for macula's 10 minutes.
#[derive(Debug, Clone, PartialEq)]
pub struct Publication {
    pub realm: [u8; 32],
    pub topic: String,
    pub payload: Payload,
    pub ttl_ms: Option<u64>,
}

/// A publication a subscription heard, verified: who published it (the key
/// id its signature verified under), where, its seq and time, the payload,
/// and how it arrived (direct or plumtree). A sealed group event's payload is
/// the ciphertext: opening it is [`crate::group`]'s, and an event that could
/// not be opened is delivered once with the reason it could not be.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub publisher: [u8; 32],
    pub realm: [u8; 32],
    pub topic: String,
    pub seq: u64,
    pub published_at: u64,
    pub payload: Payload,
    pub delivered_via: String,
    /// The epoch a sealed event names, as the delivery metadata reports it:
    /// `Some` on every event that arrived sealed, opened or not, and `None`
    /// on one that arrived clear.
    pub seal_key_id: Option<[u8; 8]>,
    /// Why a sealed event was not opened, on a subscription under a group.
    /// `None` on every event that arrived clear, and on one that opened.
    pub unopened: Option<crate::group::Reason>,
}

/// Numbers one publisher's publications: the first is the wall clock in
/// microseconds, and each after is one more than the last, or the clock,
/// whichever is later, as macula_publication_seq does. Links of one identity
/// key share one, so their seqs never repeat.
#[derive(Debug, Default)]
pub struct PublicationSeq {
    last: Mutex<u64>,
}

impl PublicationSeq {
    /// The seq for the next publication.
    pub fn next(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        *last = now.max(*last + 1);
        *last
    }
}

/// Remembers the publications a node delivered, by publication hash, until
/// each expires, so an event heard on several links, or twice on one, is
/// delivered once. The links of one node share one.
#[derive(Debug, Default)]
pub struct EventDedup {
    seen: Mutex<HashMap<[u8; 48], u64>>,
}

impl EventDedup {
    /// Whether `hash` is new at `now_ms`, remembering it until `expires_at`.
    fn first(&self, hash: [u8; 48], expires_at: u64, now_ms: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.contains_key(&hash) {
            return false;
        }
        seen.retain(|_, until| *until >= now_ms as u64);
        seen.insert(hash, expires_at);
        true
    }
}

/// A PUBLISH signed once, to be sent on several links of one node: every copy
/// is the same publication, so a subscriber hearing it on several links
/// delivers it once.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedPublication {
    frame: Value,
}

impl SignedPublication {
    /// Signs `p` with `key` at the next seq of `seq`.
    pub fn sign(
        key: &NodeKey,
        seq: &PublicationSeq,
        p: Publication,
    ) -> Result<SignedPublication, LinkError> {
        Self::sign_at(key, seq.next(), now_ms() as u64, p)
    }

    /// Signs `p` with `key` at a seq and time the caller fixed, which is what
    /// a sealed group event needs: the event AAD binds the publication's seq
    /// and published_at, so both are fixed before the payload is sealed, and
    /// the seal and the publication carry the same two.
    pub(crate) fn sign_at(
        key: &NodeKey,
        seq: u64,
        published_at: u64,
        p: Publication,
    ) -> Result<SignedPublication, LinkError> {
        let frame = frame::sign_publish(
            &PublicationSpec {
                realm: p.realm,
                topic: p.topic,
                seq,
                published_at,
                payload: p.payload,
                ttl_ms: p.ttl_ms,
            },
            key,
        )?;
        Ok(SignedPublication { frame })
    }
}

static NEXT_SUBSCRIBER: AtomicU64 = AtomicU64::new(1);

/// One subscriber of a realm and topic on a link.
pub(super) struct SubscriberSlot {
    id: u64,
    events: mpsc::Sender<Event>,
}

/// Ends every subscription to `key` on the link when the station refused
/// its SUBSCRIBE: their events stop, and each one's `recv` gives `None`.
pub(super) fn subscribe_refused(inner: &Inner, key: &([u8; 32], String)) {
    inner.lock().subs.remove(key);
}

/// One subscription to a realm and topic on a link, until
/// [`Subscription::unsubscribe`] or the link ends.
pub struct Subscription {
    link: Weak<Inner>,
    key: ([u8; 32], String),
    id: u64,
    events: mpsc::Receiver<Event>,
    unsubscribed: bool,
}

impl Subscription {
    /// The next event, or `None` once the subscription has ended.
    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// Ends the subscription, and sends UNSUBSCRIBE once no other
    /// subscription on the link holds its realm and topic.
    pub async fn unsubscribe(mut self) -> Result<(), LinkError> {
        self.unsubscribed = true;
        let Some(inner) = self.link.upgrade() else {
            return Ok(());
        };
        if drop_subscriber(&inner, &self.key, self.id) {
            let frame =
                frame::unsubscribe_frame(self.key.1.as_bytes(), &self.key.0, &inner.self_id)?;
            inner.send_control(&frame).await?;
        }
        Ok(())
    }
}

impl Drop for Subscription {
    /// A subscription dropped without unsubscribing unsubscribes as it goes.
    fn drop(&mut self) {
        if self.unsubscribed {
            return;
        }
        let Some(inner) = self.link.upgrade() else {
            return;
        };
        if !drop_subscriber(&inner, &self.key, self.id) {
            return;
        }
        let key = self.key.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(unsubscribe_dropped(inner, key));
        }
    }
}

/// Sends the UNSUBSCRIBE of a subscription dropped without unsubscribing,
/// for whatever it is worth now.
async fn unsubscribe_dropped(inner: Arc<Inner>, key: ([u8; 32], String)) {
    if let Ok(frame) = frame::unsubscribe_frame(key.1.as_bytes(), &key.0, &inner.self_id) {
        let _ = inner.send_control(&frame).await;
    }
}

/// Adds a subscriber, and whether it is the first on its realm and topic;
/// the link's end when it has ended.
fn add_subscriber(
    inner: &Inner,
    key: &([u8; 32], String),
    id: u64,
    events: mpsc::Sender<Event>,
) -> Result<bool, LinkError> {
    let mut state = inner.lock();
    if let Some(e) = &state.ended {
        return Err(e.clone());
    }
    let slots = state.subs.entry(key.clone()).or_default();
    slots.push(SubscriberSlot { id, events });
    Ok(slots.len() == 1)
}

/// Sends the SUBSCRIBE for `topic` in `realm`.
async fn send_subscribe(inner: &Inner, realm: &[u8; 32], topic: &str) -> Result<(), LinkError> {
    let frame = frame::subscribe_frame(topic.as_bytes(), realm, &inner.self_id);
    match frame {
        Ok(frame) => inner.send_control(&frame).await,
        Err(e) => Err(e.into()),
    }
}

/// Removes a subscriber, and whether it was the last on its realm and topic.
fn drop_subscriber(inner: &Inner, key: &([u8; 32], String), id: u64) -> bool {
    let mut state = inner.lock();
    let Some(slots) = state.subs.get_mut(key) else {
        return false;
    };
    slots.retain(|s| s.id != id);
    if slots.is_empty() {
        state.subs.remove(key);
        return true;
    }
    false
}

impl Link {
    /// Signs `p` as a PUBLISH and sends it.
    pub async fn publish(&self, p: Publication) -> Result<(), LinkError> {
        let signed = SignedPublication::sign(&self.inner.key, &self.inner.publication_seq, p)?;
        self.publish_signed(&signed).await
    }

    /// Sends a publication signed once for several links, as it is.
    pub async fn publish_signed(&self, p: &SignedPublication) -> Result<(), LinkError> {
        self.inner.send_control(&p.frame).await
    }

    /// Subscribes to `topic` in `realm`: the first subscription to a realm
    /// and topic on the link sends SUBSCRIBE.
    pub async fn subscribe(
        &self,
        realm: &[u8; 32],
        topic: &str,
    ) -> Result<Subscription, LinkError> {
        let key = (*realm, topic.to_string());
        let (events_tx, events) = mpsc::channel(EVENT_BUFFER);
        let id = NEXT_SUBSCRIBER.fetch_add(1, Ordering::Relaxed);
        let first = add_subscriber(&self.inner, &key, id, events_tx)?;
        let subscription = Subscription {
            link: Arc::downgrade(&self.inner),
            key: key.clone(),
            id,
            events,
            unsubscribed: false,
        };
        let sent = if first {
            send_subscribe(&self.inner, realm, topic).await
        } else {
            Ok(())
        };
        if let Err(e) = sent {
            drop_subscriber(&self.inner, &key, id);
            let mut subscription = subscription;
            subscription.unsubscribed = true;
            return Err(e);
        }
        Ok(subscription)
    }
}

/// An EVENT's publication, once it verifies, delivered to every subscription
/// on its realm and topic, unless it was delivered before.
pub(super) fn evented(inner: &Arc<Inner>, v: &Value) {
    let now = now_ms();
    let Ok(publication) = frame::verify_publication(v, inner.profile, now) else {
        inner.count("event_unverified");
        return;
    };
    let delivered_via = frame::delivered_via(v).to_string();
    if !inner
        .dedup
        .first(publication.publication_hash, publication.expires_at, now)
    {
        inner.count("event_duplicate");
        return;
    }
    let event = Event {
        publisher: publication.publisher,
        realm: publication.realm,
        topic: publication.topic.clone(),
        seq: publication.seq,
        published_at: publication.published_at,
        seal_key_id: publication.payload.sealed().map(|s| s.key_id),
        payload: publication.payload,
        delivered_via,
        unopened: None,
    };
    let mut state = inner.lock();
    let Some(slots) = state.subs.get(&(publication.realm, publication.topic)) else {
        *state
            .unrouted
            .entry("event_unsubscribed".into())
            .or_default() += 1;
        return;
    };
    let overflowed = slots
        .iter()
        .filter(|s| s.events.try_send(event.clone()).is_err())
        .count();
    if overflowed > 0 {
        *state.unrouted.entry("event_overflow".into()).or_default() += overflowed as u64;
    }
}
