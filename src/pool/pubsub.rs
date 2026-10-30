//! PubSub through the pool: a subscription on every link the pool holds and
//! every link it dials later, each event delivered once whichever links hear
//! it, and a notice when no link carried it for a while (see
//! [`Delivery`]); a publication signed once and sent on the first
//! replication_factor links.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use tokio::sync::{mpsc, oneshot};

use crate::frame::Payload;
use crate::station_link::{self, now_ms, Event, Link, LinkError, Publication, SignedPublication};

use super::delivery::{Coverage, Delivery};
use super::{Pool, PoolError, PoolInner};

/// How many events a subscription holds that its reader has not taken; one
/// arriving at a full subscription is dropped and counted. A notice is never
/// dropped: at most one waits per time the subscription lost its links.
const SUBSCRIPTION_BUFFER: usize = 256;

static NEXT_SUBSCRIPTION: AtomicU64 = AtomicU64::new(1);

/// The node's subscription to a realm and topic, on every link the pool
/// holds and every link it dials later, until [`Subscription::unsubscribe`]
/// or the pool closes.
pub struct Subscription {
    inner: Arc<SubInner>,
    events: mpsc::UnboundedReceiver<Delivery>,
    unsubscribed: bool,
}

pub(super) struct SubInner {
    id: u64,
    pool: Weak<PoolInner>,
    realm: [u8; 32],
    topic: String,
    /// The sealed group's prefix this subscription opens under, `None` for a
    /// plain subscription, which delivers payloads as they arrive.
    group: Option<String>,
    held: Mutex<Held>,
    /// How many events wait for the reader, against [`SUBSCRIPTION_BUFFER`].
    queued: AtomicUsize,
    dropped: AtomicU64,
    refused: AtomicU64,
}

struct Held {
    /// `None` once the subscription ended.
    events: Option<mpsc::UnboundedSender<Delivery>>,
    /// The links that carry the subscription, and the notice owed when none
    /// does. Changed under this lock, with the notice sent under it, so the
    /// notices keep their place among the events.
    coverage: Coverage,
    /// Each link's forwarder, by link serial: told to stop, it unsubscribes
    /// on its link and says how that went.
    on_links: HashMap<u64, Forwarder>,
}

struct Forwarder {
    /// The link it forwards from: its end is the subscription's to count,
    /// whatever the forwarder is doing then (see [`Held::fold_ended`]).
    link: Link,
    stop: oneshot::Sender<()>,
    unsubscribed: oneshot::Receiver<Result<(), LinkError>>,
    /// Dropped with the forwarder, which ends the watch on its link's end.
    _watched: oneshot::Sender<()>,
}

impl Held {
    /// Counts every link that ended among those carrying the subscription,
    /// sending the [`Delivery::Interrupted`] owed unless the pool is
    /// `closing` or the subscription ended. Coverage follows the link, not
    /// its forwarder, which may still be opening an event the ended link
    /// heard: a link that ended no longer carries the subscription, so a
    /// link accepted after it must find it gone.
    fn fold_ended(&mut self, closing: bool) {
        let ended: Vec<(u64, u64, &'static str)> = self
            .on_links
            .values()
            .filter_map(|f| {
                let e = f.link.error()?;
                Some((f.link.serial(), f.link.last_heard_ms(), e.end_reason()))
            })
            .collect();
        let notices: Vec<Delivery> = ended
            .into_iter()
            .filter_map(|(serial, heard, reason)| self.coverage.ended(serial, heard, reason))
            .collect();
        let Some(events) = self.events.as_ref().filter(|_| !closing) else {
            return;
        };
        for notice in notices {
            let _ = events.send(notice);
        }
    }
}

impl Held {
    /// The subscription on the link `serial` ended, its end counted already
    /// when the link ended; `link_up` when the link went on, its station
    /// having ended the subscription there: the link no longer covers it.
    fn left(&mut self, serial: u64, link_up: bool) {
        self.on_links.remove(&serial);
        if link_up {
            self.coverage.left(serial);
        }
    }
}

impl Pool {
    /// Subscribes the node to `topic` in `realm` on every link, returning
    /// once one link's station has accepted it (macula#12), as macula's
    /// await_registration does: an event published after this returns is
    /// delivered. The other links go on subscribing. Every link failing is
    /// [`PoolError::NoLink`] with each one's error, a refusal being
    /// [`LinkError::RegisterRefused`]; with no link up it returns at once,
    /// and the links the pool dials later subscribe.
    pub async fn subscribe(
        &self,
        realm: &[u8; 32],
        topic: &str,
    ) -> Result<Subscription, PoolError> {
        self.subscribe_under(realm, topic, None).await
    }

    /// Subscribes the node to `topic` in `realm`, opening each event under
    /// `group` when there is one.
    pub(super) async fn subscribe_under(
        &self,
        realm: &[u8; 32],
        topic: &str,
        group: Option<String>,
    ) -> Result<Subscription, PoolError> {
        let (events_tx, events) = mpsc::unbounded_channel();
        let sub = Arc::new(SubInner {
            id: NEXT_SUBSCRIPTION.fetch_add(1, Ordering::Relaxed),
            pool: Arc::downgrade(&self.inner),
            realm: *realm,
            topic: topic.to_string(),
            group,
            refused: AtomicU64::new(0),
            held: Mutex::new(Held {
                events: Some(events_tx),
                coverage: Coverage::default(),
                on_links: HashMap::new(),
            }),
            queued: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        });
        register(&self.inner, &sub)?;
        let subscription = Subscription {
            inner: sub.clone(),
            events,
            unsubscribed: false,
        };
        let links = self.inner.links();
        if links.is_empty() {
            return Ok(subscription);
        }
        let (answers_tx, mut answers) = mpsc::channel(links.len());
        for link in links {
            tokio::spawn(attach_answering(sub.clone(), link, answers_tx.clone()));
        }
        drop(answers_tx);
        let mut errors = Vec::new();
        while let Some(answer) = answers.recv().await {
            match answer {
                Ok(()) => return Ok(subscription),
                Err(e) => errors.push(e),
            }
        }
        // Dropping the subscription ends it on every link.
        drop(subscription);
        Err(PoolError::NoLink(errors))
    }

    /// Signs `p` once and sends it on the first replication_factor links, in
    /// the pool's selection order, succeeding when one of them takes it.
    /// Every copy is the same publication, so a subscriber delivers it once.
    pub async fn publish(&self, p: Publication) -> Result<(), PoolError> {
        // A clear publish under a prefix whose sealed group this node holds is
        // refused rather than sent in the clear or silently sealed.
        let held = match p.payload {
            Payload::Clear(_) => self.inner.held_prefix(&p.realm, &p.topic),
            Payload::Sealed(_) => None,
        };
        if let Some(prefix) = held {
            return Err(PoolError::GroupHeld(prefix));
        }
        let signed =
            SignedPublication::sign(&self.inner.opts.identity, &self.inner.publication_seq, p)?;
        self.inner.send_signed(&signed).await
    }
}

impl Subscription {
    /// The next delivery: an event, once, whichever links heard it, or a
    /// notice that events may have been missed ([`Delivery`]); `None` once
    /// the subscription or the pool has ended.
    pub async fn recv(&mut self) -> Option<Delivery> {
        let delivery = self.events.recv().await?;
        if let Delivery::Event(_) = delivery {
            self.inner.queued.fetch_sub(1, Ordering::Relaxed);
        }
        Some(delivery)
    }

    /// How many events arrived while the subscription was full.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// How many events a required group this node holds refused because they
    /// arrived in the clear.
    pub fn refused(&self) -> u64 {
        self.inner.refused.load(Ordering::Relaxed)
    }

    /// Ends the subscription on every link.
    pub async fn unsubscribe(&mut self) -> Result<(), LinkError> {
        self.unsubscribed = true;
        if let Some(pool) = self.inner.pool.upgrade() {
            pool.lock().subs.remove(&self.inner.id);
        }
        self.inner.end().await
    }
}

impl Drop for Subscription {
    /// A subscription dropped without unsubscribing unsubscribes as it goes.
    fn drop(&mut self) {
        if self.unsubscribed {
            return;
        }
        if let Some(pool) = self.inner.pool.upgrade() {
            pool.lock().subs.remove(&self.inner.id);
        }
        let inner = self.inner.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let _ = inner.end().await;
        });
    }
}

/// Puts `sub` among the pool's subscriptions, so links it dials later get it,
/// unless the pool has closed.
fn register(pool: &PoolInner, sub: &Arc<SubInner>) -> Result<(), PoolError> {
    let mut state = pool.lock();
    if state.closed {
        return Err(PoolError::Closed);
    }
    state.subs.insert(sub.id, sub.clone());
    Ok(())
}

impl SubInner {
    /// Delivers one event: opened under the subscription's group when it has
    /// one, counted refused when the group refuses it, and counted dropped
    /// when the subscription is full.
    async fn deliver(self: &Arc<Self>, events: &mpsc::UnboundedSender<Delivery>, event: Event) {
        let Some(event) = self.delivered(event).await else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.queued.fetch_add(1, Ordering::Relaxed) >= SUBSCRIPTION_BUFFER {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if events.send(Delivery::Event(event)).is_err() {
            self.queued.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// The event as this subscription delivers it, or `None` when it is
    /// refused outright.
    ///
    /// Every subscription goes through the groups this node holds, not only a
    /// subscription under one: a prefix this node holds at `required` refuses
    /// a clear event on any subscription covering it, which is what stops a
    /// plain subscription from delivering a forged clear event under a group
    /// the node holds.
    async fn delivered(self: &Arc<Self>, event: Event) -> Option<Event> {
        let groups = self.pool.upgrade().and_then(|pool| pool.held_groups());
        match groups {
            Some(groups) => {
                super::group::open_delivered(&groups, self.group.as_deref(), event).await
            }
            None => Some(super::group::without_a_group(event)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Ends the subscription once: its events end, and every link
    /// unsubscribes.
    pub(super) async fn end(&self) -> Result<(), LinkError> {
        let Some(forwarders) = self.take_forwarders() else {
            return Ok(());
        };
        stop_forwarders(forwarders).await
    }

    /// Ends the subscription's events and takes every link's forwarder, or
    /// `None` when it had already ended.
    fn take_forwarders(&self) -> Option<HashMap<u64, Forwarder>> {
        let mut held = self.lock();
        held.events.take()?;
        Some(std::mem::take(&mut held.on_links))
    }

    /// Whether the subscription's pool is closing, when nothing is owed.
    fn pool_closing(&self) -> bool {
        self.pool.upgrade().is_none_or(|pool| pool.lock().closed)
    }

    /// Keeps `forwarder` as the one for its link, when the subscription still
    /// runs and that link has none yet; whether it did. The link covers the
    /// subscription from now: links that ended are counted first, and a
    /// [`Delivery::Gap`] owed goes out here, before the forwarder delivers
    /// anything this link heard.
    fn keep_forwarder(&self, forwarder: Forwarder) -> bool {
        let closing = self.pool_closing();
        let serial = forwarder.link.serial();
        let mut held = self.lock();
        let Some(events) = held.events.clone() else {
            return false;
        };
        if held.on_links.contains_key(&serial) {
            return false;
        }
        held.fold_ended(closing);
        held.on_links.insert(serial, forwarder);
        let now = u64::try_from(now_ms()).unwrap_or(0);
        if let Some(gap) = held.coverage.covers(serial, now) {
            let _ = events.send(gap);
        }
        true
    }

    /// Counts the links that ended, as soon as one does.
    fn links_ended(&self) {
        let closing = self.pool_closing();
        self.lock().fold_ended(closing);
    }

    /// The subscription on `link` ended: when the link did, it is counted
    /// (if its end was not already); when the link goes on, the station
    /// ended the subscription there and no link end is there to report.
    fn left_link(&self, link: &Link) {
        let closing = self.pool_closing();
        let mut held = self.lock();
        held.fold_ended(closing);
        held.left(link.serial(), link.error().is_none());
    }

    /// [`SubInner::attach`], for a task of its own.
    pub(super) async fn attach_owned(self: Arc<Self>, link: Link) -> Result<(), LinkError> {
        self.attach(&link).await
    }

    /// Subscribes on `link`, once, and forwards what it hears until the
    /// link's subscription ends: the link's error when its station refused
    /// the subscription or did not answer, and `Ok` when there was nothing to
    /// do, the subscription having ended or being on the link already.
    pub(super) async fn attach(self: &Arc<Self>, link: &Link) -> Result<(), LinkError> {
        let events = {
            let held = self.lock();
            match &held.events {
                Some(events) if !held.on_links.contains_key(&link.serial()) => events.clone(),
                _ => return Ok(()),
            }
        };
        let on_link = link.subscribe(&self.realm, &self.topic).await?;
        let (stop, stopped) = oneshot::channel();
        let (unsubscribed_tx, unsubscribed) = oneshot::channel();
        let (watched, unwatched) = oneshot::channel();
        let kept = self.keep_forwarder(Forwarder {
            link: link.clone(),
            stop,
            unsubscribed,
            _watched: watched,
        });
        if !kept {
            let _ = on_link.unsubscribe().await;
            return Ok(());
        }
        tokio::spawn(watch_link_end(
            Arc::downgrade(self),
            link.clone(),
            unwatched,
        ));
        tokio::spawn(forward(
            self.clone(),
            link.clone(),
            on_link,
            events,
            stopped,
            unsubscribed_tx,
        ));
        Ok(())
    }
}

/// Counts `link`'s end in `sub`'s coverage as soon as the link ends, while
/// `sub` still forwards from it (`unwatched` not yet dropped).
async fn watch_link_end(sub: Weak<SubInner>, link: Link, unwatched: oneshot::Receiver<()>) {
    tokio::select! {
        _ = link.done() => {}
        _ = unwatched => return,
    }
    if let Some(sub) = sub.upgrade() {
        sub.links_ended();
    }
}

/// Subscribes `sub` on `link`, sending how that went to `answers`.
async fn attach_answering(
    sub: Arc<SubInner>,
    link: Link,
    answers: mpsc::Sender<Result<(), LinkError>>,
) {
    let _ = answers.send(sub.attach(&link).await).await;
}

/// Tells each forwarder to stop and waits for its link to unsubscribe; the
/// last link that failed to is the error.
async fn stop_forwarders(forwarders: HashMap<u64, Forwarder>) -> Result<(), LinkError> {
    let mut result = Ok(());
    for (_, f) in forwarders {
        let _ = f.stop.send(());
        if let Ok(Err(e)) = f.unsubscribed.await {
            result = Err(e);
        }
    }
    result
}

async fn forward(
    sub: Arc<SubInner>,
    link: Link,
    mut on_link: station_link::Subscription,
    events: mpsc::UnboundedSender<Delivery>,
    mut stop: oneshot::Receiver<()>,
    unsubscribed: oneshot::Sender<Result<(), LinkError>>,
) {
    loop {
        tokio::select! {
            _ = &mut stop => {
                let _ = unsubscribed.send(on_link.unsubscribe().await);
                return;
            }
            event = on_link.recv() => match event {
                Some(event) => sub.deliver(&events, event).await,
                None => break,
            },
        }
    }
    // The link ended: a link dialed again gets the subscription back.
    sub.left_link(&link);
    let _ = unsubscribed.send(Ok(()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held_on(serials: &[u64]) -> Held {
        let mut held = Held {
            events: None,
            coverage: Coverage::default(),
            on_links: HashMap::new(),
        };
        for &serial in serials {
            assert_eq!(held.coverage.covers(serial, 0), None);
        }
        held
    }

    #[test]
    fn a_link_that_stays_up_no_longer_covers_once_the_subscription_left_it() {
        let mut held = held_on(&[1, 2]);
        held.left(1, true);
        // Link 1 does not carry it any more: link 2's end is the last.
        assert!(matches!(
            held.coverage.ended(2, 500, "closed_by_station"),
            Some(Delivery::Interrupted(_))
        ));
        assert_eq!(held.coverage.ended(1, 600, "closed_by_station"), None);
    }

    #[test]
    fn a_link_that_ended_is_not_left_twice() {
        let mut held = held_on(&[1, 2]);
        // Link 1's end was counted when it ended, or will be, by fold_ended.
        held.left(1, false);
        assert_eq!(held.coverage.ended(2, 500, "closed_by_station"), None);
    }
}
