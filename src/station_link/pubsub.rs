//! PubSub, as macula 12's link does it. A PUBLISH carries a publication
//! signed with the link's identity key; SUBSCRIBE and UNSUBSCRIBE are control
//! frames naming the realm, the topic and this node, each answered by a
//! REGISTER_ACK (WIRE_1_0.md section 3.5, macula#12), and a subscription is
//! returned once the station has accepted its SUBSCRIBE; an EVENT carries a publication that is verified before it
//! is delivered, and delivered once however many copies arrive, until it
//! expires.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{mpsc, oneshot};

use crate::cbor::Value;
use crate::frame::{self, Payload, PublicationSpec};
use crate::node_key::NodeKey;

use super::{now_ms, Inner, Link, LinkError, REGISTER_ACK_TIMEOUT};

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

/// What a subscription waiting on a SUBSCRIBE is told: accepted, or why
/// not.
type AckWaiter = oneshot::Sender<Result<(), LinkError>>;

/// The SUBSCRIBEs of one realm and topic the station has not answered,
/// oldest first, each by the id of the subscription that sent it, with the
/// subscriptions waiting on it. The station answers the frames of one control
/// stream in the order they came, so the next ack of the realm and topic
/// answers the oldest.
pub(super) type AckQueue = VecDeque<(u64, Vec<AckWaiter>)>;

/// The station's answer to the oldest unanswered SUBSCRIBE of `key`, told to
/// every subscription waiting on it. A refusal ends every subscription to
/// `key` on the link, their events stopping and each one's `recv` giving
/// `None`, unless a later SUBSCRIBE of `key` is still unanswered: the
/// subscriptions then are that one's, and its own answer decides them. One
/// that answers nothing this link is waiting on is the station's to give:
/// an acceptance changes nothing, a refusal ends the subscriptions.
pub(super) fn subscribe_answered(
    inner: &Inner,
    key: &([u8; 32], String),
    answer: Result<(), LinkError>,
) {
    let mut state = inner.lock();
    let (waiters, later) = take_oldest(&mut state.sub_acks, key);
    if answer.is_err() && !later {
        state.subs.remove(key);
    }
    drop(state);
    for w in waiters {
        let _ = w.send(answer.clone());
    }
}

/// The unanswered SUBSCRIBEs of a link, by realm and topic.
pub(super) type SubAcks = HashMap<([u8; 32], String), AckQueue>;

/// Takes the oldest unanswered SUBSCRIBE of `key`: the subscriptions waiting
/// on it, and whether a later one is still unanswered.
fn take_oldest(acks: &mut SubAcks, key: &([u8; 32], String)) -> (Vec<AckWaiter>, bool) {
    let Some(queue) = acks.get_mut(key) else {
        return (Vec::new(), false);
    };
    let waiters = queue.pop_front().map(|(_, w)| w).unwrap_or_default();
    let later = !queue.is_empty();
    if !later {
        acks.remove(key);
    }
    (waiters, later)
}

/// Waits on the SUBSCRIBE of `key` subscription `id` sends when it is the
/// `first` on its realm and topic, else on the latest one unanswered: the
/// answer to wait for, `None` when none is unanswered, the station having
/// accepted the realm and topic already.
fn wait_on(
    acks: &mut SubAcks,
    key: &([u8; 32], String),
    id: u64,
    first: bool,
) -> Option<oneshot::Receiver<Result<(), LinkError>>> {
    let queue = acks.entry(key.clone()).or_default();
    if first {
        queue.push_back((id, Vec::new()));
    }
    let answer = queue.back_mut().map(|(_, waiters)| {
        let (tx, rx) = oneshot::channel();
        waiters.push(tx);
        rx
    });
    if queue.is_empty() {
        acks.remove(key);
    }
    answer
}

/// Takes the SUBSCRIBE of `key` subscription `id` sent, wherever it is in
/// the queue: the subscriptions waiting on it.
fn take_unsent(acks: &mut SubAcks, key: &([u8; 32], String), id: u64) -> Vec<AckWaiter> {
    let Some(queue) = acks.get_mut(key) else {
        return Vec::new();
    };
    let waiters = queue
        .iter()
        .position(|(sent_by, _)| *sent_by == id)
        .and_then(|at| queue.remove(at))
        .map(|(_, w)| w)
        .unwrap_or_default();
    if queue.is_empty() {
        acks.remove(key);
    }
    waiters
}

/// Tells every subscription still waiting on its SUBSCRIBE that the link
/// ended, with `err`.
pub(super) fn end_waits(waits: SubAcks, err: &LinkError) {
    for (_, waiters) in waits.into_values().flatten() {
        for w in waiters {
            let _ = w.send(Err(err.clone()));
        }
    }
}

/// The SUBSCRIBE subscription `id` sent did not go out, so nothing answers
/// it: it leaves the queue, and every subscription waiting on it is told
/// `err`.
fn subscribe_unsent(inner: &Inner, key: &([u8; 32], String), id: u64, err: &LinkError) {
    let waiters = take_unsent(&mut inner.lock().sub_acks, key, id);
    for w in waiters {
        let _ = w.send(Err(err.clone()));
    }
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

/// A subscriber added: whether it is the first on its realm and topic, so
/// it sends the SUBSCRIBE, and the station's answer to wait for, `None` when
/// the station already accepted the realm and topic on this link.
struct Added {
    first: bool,
    answer: Option<oneshot::Receiver<Result<(), LinkError>>>,
}

/// Adds a subscriber, waiting on the SUBSCRIBE it sends when it is the first
/// on its realm and topic, else on the latest one still unanswered, if any;
/// the link's end when it has ended. The wait is in place before the frame
/// is sent, so no answer arrives before it.
fn add_subscriber(
    inner: &Inner,
    key: &([u8; 32], String),
    id: u64,
    events: mpsc::Sender<Event>,
) -> Result<Added, LinkError> {
    let mut state = inner.lock();
    if let Some(e) = &state.ended {
        return Err(e.clone());
    }
    let slots = state.subs.entry(key.clone()).or_default();
    slots.push(SubscriberSlot { id, events });
    let first = slots.len() == 1;
    let answer = wait_on(&mut state.sub_acks, key, id, first);
    Ok(Added { first, answer })
}

/// The station's answer to the SUBSCRIBE a subscription waits on, within
/// [`REGISTER_ACK_TIMEOUT`].
async fn answered(
    inner: &Inner,
    answer: Option<oneshot::Receiver<Result<(), LinkError>>>,
) -> Result<(), LinkError> {
    let Some(answer) = answer else {
        return Ok(());
    };
    match within(answer, REGISTER_ACK_TIMEOUT).await {
        Heard::Answer(answer) => answer,
        Heard::Gone => Err(inner.lock().ended.clone().unwrap_or(LinkError::Closed)),
        Heard::Late => Err(LinkError::RegisterUnacknowledged(
            frame::RegisterKind::Subscribe,
        )),
    }
}

/// What a subscription waiting on its SUBSCRIBE heard.
#[derive(Debug, PartialEq)]
enum Heard {
    /// The station's answer, or the link's end.
    Answer(Result<(), LinkError>),
    /// Its wait dropped unanswered: the link went with it.
    Gone,
    /// Nothing within the time.
    Late,
}

/// The answer to `answer`, within `limit`.
async fn within(
    answer: oneshot::Receiver<Result<(), LinkError>>,
    limit: std::time::Duration,
) -> Heard {
    match tokio::time::timeout(limit, answer).await {
        Ok(Ok(answer)) => Heard::Answer(answer),
        Ok(Err(_)) => Heard::Gone,
        Err(_) => Heard::Late,
    }
}

/// Sends the SUBSCRIBE subscription `id` waits on, for `key`'s topic in its
/// realm. It is sent from a task of its own, so a caller that stops waiting
/// does not stop it half-sent: the queue of unanswered SUBSCRIBEs then still
/// matches what the station was sent. One that did not go out leaves the
/// queue.
async fn send_subscribe(
    inner: &Arc<Inner>,
    key: &([u8; 32], String),
    id: u64,
) -> Result<(), LinkError> {
    let inner = inner.clone();
    let key = key.clone();
    let sending = tokio::spawn(async move {
        let sent = match frame::subscribe_frame(key.1.as_bytes(), &key.0, &inner.self_id) {
            Ok(frame) => inner.send_control(&frame).await,
            Err(e) => Err(e.into()),
        };
        if let Err(e) = &sent {
            subscribe_unsent(&inner, &key, id, e);
        }
        sent
    });
    sending.await.unwrap_or(Err(LinkError::Closed))
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

    /// Subscribes to `topic` in `realm`, once the station has accepted it,
    /// so an event published after this returns is delivered: the first
    /// subscription to a realm and topic on the link sends SUBSCRIBE, and
    /// every subscription waits for the station's REGISTER_ACK of it, within
    /// [`REGISTER_ACK_TIMEOUT`]. A refusal is
    /// [`LinkError::RegisterRefused`], no answer in time
    /// [`LinkError::RegisterUnacknowledged`], and either way the subscription
    /// is withdrawn.
    pub async fn subscribe(
        &self,
        realm: &[u8; 32],
        topic: &str,
    ) -> Result<Subscription, LinkError> {
        let key = (*realm, topic.to_string());
        let (events_tx, events) = mpsc::channel(EVENT_BUFFER);
        let id = NEXT_SUBSCRIBER.fetch_add(1, Ordering::Relaxed);
        let added = add_subscriber(&self.inner, &key, id, events_tx)?;
        let subscription = Subscription {
            link: Arc::downgrade(&self.inner),
            key: key.clone(),
            id,
            events,
            unsubscribed: false,
        };
        let sent = if added.first {
            send_subscribe(&self.inner, &key, id).await
        } else {
            Ok(())
        };
        if let Err(e) = sent {
            drop_subscriber(&self.inner, &key, id);
            let mut subscription = subscription;
            subscription.unsubscribed = true;
            return Err(e);
        }
        // A subscription refused or not answered in time is withdrawn here,
        // in the caller's own order: its UNSUBSCRIBE, when it was the last on
        // its realm and topic, goes out before any SUBSCRIBE of a retry, which
        // a withdrawal left to Drop's task could overtake. A refused one sends
        // nothing: the refusal already ended the topic's subscriptions.
        if let Err(e) = answered(&self.inner, added.answer).await {
            let _ = subscription.unsubscribe().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ([u8; 32], String) {
        ([7; 32], "mcl-rust/tests/greeting_sent_v1".to_string())
    }

    fn told(rx: &mut oneshot::Receiver<Result<(), LinkError>>) -> Option<Result<(), LinkError>> {
        rx.try_recv().ok()
    }

    fn refused() -> Result<(), LinkError> {
        Err(LinkError::RegisterRefused {
            kind: frame::RegisterKind::Subscribe,
            reason: "not_authorized".into(),
        })
    }

    #[test]
    fn every_subscription_waiting_on_a_subscribe_hears_its_answer() {
        let mut acks = SubAcks::new();
        let mut first = wait_on(&mut acks, &key(), 1, true).unwrap();
        let mut second = wait_on(&mut acks, &key(), 2, false).unwrap();
        let (waiters, later) = take_oldest(&mut acks, &key());
        assert!(!later);
        for w in waiters {
            w.send(Ok(())).unwrap();
        }
        assert_eq!(told(&mut first), Some(Ok(())));
        assert_eq!(told(&mut second), Some(Ok(())));
        assert!(acks.is_empty(), "nothing is left unanswered");
        assert!(
            wait_on(&mut acks, &key(), 3, false).is_none(),
            "a subscription after the acceptance waits on nothing"
        );
        assert!(acks.is_empty());
    }

    #[test]
    fn acks_answer_the_subscribes_of_a_topic_oldest_first() {
        let mut acks = SubAcks::new();
        let mut old = wait_on(&mut acks, &key(), 1, true).unwrap();
        let mut new = wait_on(&mut acks, &key(), 2, true).unwrap();
        let (waiters, later) = take_oldest(&mut acks, &key());
        assert!(
            later,
            "a refusal of the old one leaves the new one's subscriptions"
        );
        for w in waiters {
            w.send(refused()).unwrap();
        }
        assert_eq!(told(&mut old), Some(refused()));
        assert_eq!(told(&mut new), None, "the new one is still unanswered");
        let (waiters, later) = take_oldest(&mut acks, &key());
        assert!(!later);
        for w in waiters {
            w.send(Ok(())).unwrap();
        }
        assert_eq!(told(&mut new), Some(Ok(())));
    }

    #[test]
    fn an_ack_nothing_waits_on_takes_nothing() {
        let mut acks = SubAcks::new();
        let (waiters, later) = take_oldest(&mut acks, &key());
        assert!(waiters.is_empty() && !later);
    }

    #[test]
    fn a_subscribe_that_did_not_go_out_leaves_the_queue_in_order() {
        let mut acks = SubAcks::new();
        let _old = wait_on(&mut acks, &key(), 1, true).unwrap();
        let mut joined = wait_on(&mut acks, &key(), 1, false).unwrap();
        let mut sent = wait_on(&mut acks, &key(), 2, true).unwrap();
        let unsent = take_unsent(&mut acks, &key(), 1);
        assert_eq!(
            unsent.len(),
            2,
            "its sender and the subscription that joined it"
        );
        for w in unsent {
            w.send(Err(LinkError::Closed)).unwrap();
        }
        assert_eq!(told(&mut joined), Some(Err(LinkError::Closed)));
        let (waiters, _) = take_oldest(&mut acks, &key());
        for w in waiters {
            w.send(Ok(())).unwrap();
        }
        assert_eq!(
            told(&mut sent),
            Some(Ok(())),
            "the next ack answers the one sent"
        );
    }

    #[test]
    fn a_link_that_ends_tells_every_waiting_subscription() {
        let mut acks = SubAcks::new();
        let mut a = wait_on(&mut acks, &key(), 1, true).unwrap();
        let mut b = wait_on(&mut acks, &key(), 2, true).unwrap();
        end_waits(acks, &LinkError::Closed);
        assert_eq!(told(&mut a), Some(Err(LinkError::Closed)));
        assert_eq!(told(&mut b), Some(Err(LinkError::Closed)));
    }

    #[tokio::test]
    async fn a_subscribe_not_answered_in_time_is_late() {
        let limit = std::time::Duration::from_millis(20);
        let (_tx, rx) = oneshot::channel();
        assert_eq!(within(rx, limit).await, Heard::Late);
        let (tx, rx) = oneshot::channel::<Result<(), LinkError>>();
        drop(tx);
        assert_eq!(within(rx, limit).await, Heard::Gone);
        let (tx, rx) = oneshot::channel();
        tx.send(Ok(())).unwrap();
        assert_eq!(within(rx, limit).await, Heard::Answer(Ok(())));
    }
}
