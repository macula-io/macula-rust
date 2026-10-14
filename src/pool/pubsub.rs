//! PubSub through the pool: a subscription on every link the pool holds and
//! every link it dials later, each event delivered once whichever links hear
//! it; a publication signed once and sent on the first replication_factor
//! links.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use tokio::sync::{mpsc, oneshot};

use crate::frame::Payload;
use crate::station_link::{self, Event, Link, LinkError, Publication, SignedPublication};

use super::{Pool, PoolError, PoolInner};

/// How many events a subscription holds that its reader has not taken; one
/// arriving at a full subscription is dropped and counted.
const SUBSCRIPTION_BUFFER: usize = 256;

static NEXT_SUBSCRIPTION: AtomicU64 = AtomicU64::new(1);

/// The node's subscription to a realm and topic, on every link the pool
/// holds and every link it dials later, until [`Subscription::unsubscribe`]
/// or the pool closes.
pub struct Subscription {
    inner: Arc<SubInner>,
    events: mpsc::Receiver<Event>,
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
    dropped: AtomicU64,
    refused: AtomicU64,
}

struct Held {
    /// `None` once the subscription ended.
    events: Option<mpsc::Sender<Event>>,
    /// Each link's forwarder, by link serial: told to stop, it unsubscribes
    /// on its link and says how that went.
    on_links: HashMap<u64, Forwarder>,
}

struct Forwarder {
    stop: oneshot::Sender<()>,
    unsubscribed: oneshot::Receiver<Result<(), LinkError>>,
}

impl Pool {
    /// Subscribes the node to `topic` in `realm` on every link.
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
        let (events_tx, events) = mpsc::channel(SUBSCRIPTION_BUFFER);
        let sub = Arc::new(SubInner {
            id: NEXT_SUBSCRIPTION.fetch_add(1, Ordering::Relaxed),
            pool: Arc::downgrade(&self.inner),
            realm: *realm,
            topic: topic.to_string(),
            group,
            refused: AtomicU64::new(0),
            held: Mutex::new(Held {
                events: Some(events_tx),
                on_links: HashMap::new(),
            }),
            dropped: AtomicU64::new(0),
        });
        register(&self.inner, &sub)?;
        for link in self.inner.links() {
            sub.attach(&link).await;
        }
        Ok(Subscription {
            inner: sub,
            events,
            unsubscribed: false,
        })
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
    /// The next event, once, whichever links heard it; `None` once the
    /// subscription or the pool has ended.
    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
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
    async fn deliver(self: &Arc<Self>, events: &mpsc::Sender<Event>, event: Event) {
        let Some(event) = self.delivered(event).await else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if events.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The event as this subscription delivers it, or `None` when it is
    /// refused outright.
    async fn delivered(self: &Arc<Self>, event: Event) -> Option<Event> {
        let Some(prefix) = self.group.as_deref() else {
            return Some(event);
        };
        let groups = self.pool.upgrade().and_then(|pool| pool.held_groups());
        match groups {
            Some(groups) => super::group::open_delivered(&groups, Some(prefix), event).await,
            None => Some(super::group::unopened_no_group(event)),
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

    /// Keeps `forwarder` as the one for the link with `serial`, when the
    /// subscription still runs and that link has none yet; whether it did.
    fn keep_forwarder(&self, serial: u64, forwarder: Forwarder) -> bool {
        let mut held = self.lock();
        let wanted = held.events.is_some() && !held.on_links.contains_key(&serial);
        if wanted {
            held.on_links.insert(serial, forwarder);
        }
        wanted
    }

    /// Subscribes on `link`, once, and forwards what it hears until the
    /// link's subscription ends.
    pub(super) async fn attach(self: &Arc<Self>, link: &Link) {
        let events = {
            let held = self.lock();
            match &held.events {
                Some(events) if !held.on_links.contains_key(&link.serial()) => events.clone(),
                _ => return,
            }
        };
        let Ok(on_link) = link.subscribe(&self.realm, &self.topic).await else {
            return;
        };
        let (stop, stopped) = oneshot::channel();
        let (unsubscribed_tx, unsubscribed) = oneshot::channel();
        let kept = self.keep_forwarder(link.serial(), Forwarder { stop, unsubscribed });
        if !kept {
            let _ = on_link.unsubscribe().await;
            return;
        }
        tokio::spawn(forward(
            self.clone(),
            link.serial(),
            on_link,
            events,
            stopped,
            unsubscribed_tx,
        ));
    }
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
    serial: u64,
    mut on_link: station_link::Subscription,
    events: mpsc::Sender<Event>,
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
    sub.lock().on_links.remove(&serial);
    let _ = unsubscribed.send(Ok(()));
}
