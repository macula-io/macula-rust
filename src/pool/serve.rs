//! Serving through the pool: a procedure served on every link the pool
//! holds and every link it dials later, each advertising it naming its own
//! station, until stopped. An org procedure is served only in a realm the
//! pool pins a key for; one in the node's own namespace needs none.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use crate::frame::StreamMode;
use crate::station_link::{
    self, Confidentiality, Handler, Link, LinkError, StreamHandler, StreamOffer,
    DEFAULT_CALL_TIMEOUT,
};

use super::{Pool, PoolError, PoolInner};

static NEXT_SERVED: AtomicU64 = AtomicU64::new(1);

/// A procedure the node serves: its realm, which the pool must pin a key for
/// unless the procedure is in the node's own namespace, its name, and
/// exactly one of a unary handler and a stream offer, and how it takes its
/// requests: with [`super::Opts::kem_advertise`] its advertisement names the
/// node's KEM key unless `confidential` is off, and sealed requests are
/// answered sealed.
#[derive(Clone)]
pub struct Offer {
    pub realm: [u8; 32],
    pub procedure: String,
    pub handler: Option<Handler>,
    pub stream: Option<StreamOffer>,
    pub confidential: Confidentiality,
}

impl Offer {
    /// A unary procedure.
    pub fn unary(realm: [u8; 32], procedure: &str, handler: Handler) -> Offer {
        Offer {
            realm,
            procedure: procedure.to_string(),
            handler: Some(handler),
            stream: None,
            confidential: Confidentiality::Preferred,
        }
    }

    /// A streaming procedure of `mode`.
    pub fn stream(
        realm: [u8; 32],
        procedure: &str,
        mode: StreamMode,
        handler: StreamHandler,
    ) -> Offer {
        Offer {
            realm,
            procedure: procedure.to_string(),
            handler: None,
            stream: Some(StreamOffer { mode, handler }),
            confidential: Confidentiality::Preferred,
        }
    }
}

/// A procedure the node serves on every link the pool holds, and on every
/// link it dials later, until [`Served::stop`].
pub struct Served {
    inner: Arc<ServedInner>,
}

pub(super) struct ServedInner {
    id: u64,
    pool: Weak<PoolInner>,
    offer: station_link::Offer,
    held: Mutex<Held>,
}

struct Held {
    stopped: bool,
    on_links: HashMap<u64, station_link::Served>,
}

impl Pool {
    /// Serves `o` on every link that is up, and on every link that comes up
    /// after. It succeeds when one link serves it; each link advertises it
    /// naming its own station, and renews it and puts it in the DHT as
    /// [`Link::serve`] does.
    pub async fn serve(&self, o: Offer) -> Result<Served, PoolError> {
        let realm_key = self.inner.realm_key_for(&o.realm, &o.procedure)?;
        let kem_advertise = self.inner.opts.kem_advertise;
        if o.confidential == Confidentiality::Required && !kem_advertise {
            return Err(PoolError::Link(LinkError::KemAdvertiseDisabled));
        }
        // Kept across every link it is served on, so no link reopens the
        // keyless window.
        let keyed_since_ms = (kem_advertise && o.confidential != Confidentiality::Off)
            .then(|| crate::uuid_v7::now_ms() as i64);
        let served = Arc::new(ServedInner {
            id: NEXT_SERVED.fetch_add(1, Ordering::Relaxed),
            pool: Arc::downgrade(&self.inner),
            offer: station_link::Offer {
                realm: o.realm,
                procedure: o.procedure,
                handler: o.handler,
                stream: o.stream,
                realm_key,
                confidential: o.confidential,
                keyed_since_ms,
            },
            held: Mutex::new(Held {
                stopped: false,
                on_links: HashMap::new(),
            }),
        });
        let links = self.inner.links();
        if links.is_empty() {
            return Err(PoolError::NoLink(Vec::new()));
        }
        let mut errors = Vec::new();
        for link in &links {
            errors.extend(served.serve_on(link).await.err());
        }
        if errors.len() == links.len() {
            return Err(PoolError::NotServed(errors));
        }
        self.inner.hold_served(&served)?;
        for link in self.inner.links() {
            served.attach(link);
        }
        Ok(Served { inner: served })
    }
}

impl PoolInner {
    /// Keeps `served` among the procedures replayed on every new link;
    /// [`PoolError::Closed`] on a closed pool.
    fn hold_served(&self, served: &Arc<ServedInner>) -> Result<(), PoolError> {
        let mut state = self.lock();
        if state.closed {
            return Err(PoolError::Closed);
        }
        state.served.insert(served.id, served.clone());
        Ok(())
    }

    /// Gives a new link the node's subscriptions, then its served
    /// procedures, as macula's pool replays them on a respawned link.
    pub(super) async fn replay(&self, link: &Link) {
        let (subs, served) = {
            let state = self.lock();
            (
                state.subs.values().cloned().collect::<Vec<_>>(),
                state.served.values().cloned().collect::<Vec<_>>(),
            )
        };
        for sub in subs {
            sub.attach(link).await;
        }
        for s in served {
            s.attach(link.clone());
        }
    }
}

impl Served {
    /// Withdraws the procedure on every link.
    pub async fn stop(&self) -> Result<(), LinkError> {
        if let Some(pool) = self.inner.pool.upgrade() {
            pool.lock().served.remove(&self.inner.id);
        }
        let Some(on_links) = self.inner.mark_stopped() else {
            return Ok(());
        };
        let mut result = Ok(());
        for on_link in on_links.into_values() {
            // The last link's failure is the one returned.
            result = on_link.stop().await.and(result);
        }
        result
    }
}

impl ServedInner {
    fn lock(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Marks the offer stopped and hands back its serving on each link to
    /// withdraw; nothing when it was stopped already.
    fn mark_stopped(&self) -> Option<HashMap<u64, station_link::Served>> {
        let mut held = self.lock();
        if held.stopped {
            return None;
        }
        held.stopped = true;
        Some(std::mem::take(&mut held.on_links))
    }

    /// Whether `link` needs no serving of the offer: it is stopped, or
    /// already served there.
    fn needs_no_serving(&self, link: &Link) -> bool {
        let held = self.lock();
        held.stopped || held.on_links.contains_key(&link.serial())
    }

    /// Holds the offer's serving on `link` and watches it there, unless the
    /// offer was stopped meanwhile: then the serving is handed back to be
    /// withdrawn.
    fn hold_on_link(
        self: &Arc<Self>,
        link: &Link,
        on_link: station_link::Served,
    ) -> Option<station_link::Served> {
        let mut held = self.lock();
        if held.stopped {
            return Some(on_link);
        }
        held.on_links.insert(link.serial(), on_link.clone());
        drop(held);
        tokio::spawn(watch(self.clone(), link.clone(), on_link));
        None
    }

    fn respawn_delay(&self) -> Option<Duration> {
        self.pool.upgrade().map(|p| p.opts.respawn_delay)
    }

    /// Serves the offer on `link`, once, and watches it there.
    async fn serve_on(self: &Arc<Self>, link: &Link) -> Result<(), LinkError> {
        if self.needs_no_serving(link) {
            return Ok(());
        }
        let on_link = match link.serve(self.offer.clone()).await {
            Err(LinkError::AlreadyServed) => return Ok(()),
            other => other?,
        };
        let Some(stopped_meanwhile) = self.hold_on_link(link, on_link) else {
            return Ok(());
        };
        stopped_meanwhile.stop().await
    }

    /// Serves the offer on a link the pool dialed, trying again every
    /// respawn delay while the link lives and the offer is not served there.
    pub(super) fn attach(self: &Arc<Self>, link: Link) {
        tokio::spawn(serve_while_linked(self.clone(), link));
    }
}

/// Serves the offer on `link` until it is served there, trying again every
/// respawn delay while the link lives and the pool does.
async fn serve_while_linked(served: Arc<ServedInner>, link: Link) {
    loop {
        let outcome = tokio::time::timeout(DEFAULT_CALL_TIMEOUT, served.serve_on(&link)).await;
        if matches!(outcome, Ok(Ok(()))) {
            return;
        }
        let Some(delay) = served.respawn_delay() else {
            return;
        };
        tokio::select! {
            _ = link.done() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// Forgets a link's serving when it ends, and serves the offer there again
/// when it lapsed while the link lives.
async fn watch(served: Arc<ServedInner>, link: Link, on_link: station_link::Served) {
    let why = on_link.done().await;
    let stopped = {
        let mut held = served.lock();
        held.on_links.remove(&link.serial());
        held.stopped
    };
    if stopped || why == LinkError::Stopped || link.error().is_some() {
        return;
    }
    let Some(delay) = served.respawn_delay() else {
        return;
    };
    tokio::select! {
        _ = link.done() => {}
        _ = tokio::time::sleep(delay) => served.attach(link.clone()),
    }
}
