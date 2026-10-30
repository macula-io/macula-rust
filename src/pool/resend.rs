//! Publications a link sent and the station is not known to have read, sent
//! again once that link ends (macula-rust#57).
//!
//! QUIC delivers a control stream in order and retransmits what was lost,
//! but only while its connection lives. A link that ends (its idle timeout,
//! two missed liveness probes, an outage longer than either) takes with it
//! what it had not delivered, and the protocol acknowledges no PUBLISH, so
//! nothing would tell the publisher. Each link therefore holds what it sent
//! until the station answers a frame sent after it; the pool takes what is
//! still held when the link ends and sends it on a link that is up, or on
//! the next one up. A subscriber that did receive one delivers it once all
//! the same: it is the same signed publication, deduplicated by its hash.
//! One that cannot be sent again before subscribers would refuse it, or that
//! does not fit, is counted in [`Pool::unsent_publications`], never dropped
//! silently.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use super::{Pool, PoolInner};
use crate::station_link::{now_ms, Link, SignedPublication};

/// At most this many publications wait for a link to be up again.
const MAX_WAITING: usize = 4096;

/// The publications waiting for a link to be up again, oldest first.
pub(super) type Waiting = VecDeque<SignedPublication>;

impl Pool {
    /// How many publications this pool accepted and could not deliver: sent
    /// on a link that ended before the station was known to have read them,
    /// and then not sent again in time (no link came up before subscribers
    /// would refuse them, the pool closed, or too many were waiting).
    pub fn unsent_publications(&self) -> u64 {
        self.inner.unsent.load(Ordering::Relaxed)
    }
}

impl PoolInner {
    /// Sends again, on the links up now, what an ended link had not
    /// delivered; what none takes waits for the next link.
    pub(super) async fn send_again(&self, held: Vec<SignedPublication>) {
        for p in self.unexpired(held) {
            let sent = self.send_signed(&p).await.is_ok();
            self.wait_unless(sent, p);
        }
    }

    /// Gives a new link the publications waiting for one, oldest first.
    pub(super) async fn send_waiting(&self, link: &Link) {
        let waiting = std::mem::take(&mut self.lock().waiting);
        for p in self.unexpired(waiting.into()) {
            let sent = link.publish_signed(&p).await.is_ok();
            self.wait_unless(sent, p);
        }
    }

    /// Counts what still waits as unsent: the pool is closing.
    pub(super) fn give_up_waiting(&self) {
        let left = std::mem::take(&mut self.lock().waiting).len();
        self.unsent.fetch_add(left as u64, Ordering::Relaxed);
    }

    /// The publications subscribers would still accept, oldest first; the
    /// others are counted unsent.
    fn unexpired(&self, ps: Vec<SignedPublication>) -> Vec<SignedPublication> {
        let now = u64::try_from(now_ms()).unwrap_or(0);
        let (live, expired): (Vec<_>, Vec<_>) =
            ps.into_iter().partition(|p| now <= p.accepted_until());
        self.unsent
            .fetch_add(expired.len() as u64, Ordering::Relaxed);
        live
    }

    /// Keeps `p` for the next link unless it was `sent`.
    fn wait_unless(&self, sent: bool, p: SignedPublication) {
        if !sent {
            self.wait_for_link(p);
        }
    }

    /// Keeps `p` for the next link, or counts it unsent when the pool is
    /// closed or too many already wait.
    fn wait_for_link(&self, p: SignedPublication) {
        let mut state = self.lock();
        if state.closed || state.waiting.len() >= MAX_WAITING {
            drop(state);
            self.unsent.fetch_add(1, Ordering::Relaxed);
            return;
        }
        state.waiting.push_back(p);
    }
}
