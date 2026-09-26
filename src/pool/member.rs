//! One station the pool links to, a seed or a station dialed directly for a
//! call: it dials the station, and when the link ends dials it again after
//! the respawn delay, until it is retired.

use std::sync::{Arc, Weak};

use tokio::sync::watch;

use crate::station_link::{Config, Link, LinkError};
use crate::transport::Target;

use super::{LinkEvent, PoolInner};

pub(super) struct Member {
    pub(super) target: Target,
    pub(super) direct: bool,
    state: watch::Sender<Held>,
    retired: watch::Sender<bool>,
    stopped: watch::Sender<bool>,
}

/// What a member holds now: its link while one is up, the last error, and
/// how many dials have failed.
#[derive(Clone, Default)]
struct Held {
    link: Option<Link>,
    error: Option<LinkError>,
    failed_dials: u64,
}

impl PoolInner {
    pub(super) fn start_member(self: &Arc<Self>, target: Target, direct: bool) -> Arc<Member> {
        let m = Arc::new(Member {
            target,
            direct,
            state: watch::channel(Held::default()).0,
            retired: watch::channel(false).0,
            stopped: watch::channel(false).0,
        });
        self.lock().members.push(m.clone());
        tokio::spawn(supervise(Arc::downgrade(self), m.clone()));
        m
    }

    /// Retires a member the pool no longer keeps: its link closes, it is not
    /// dialed again, and it leaves the pool's members.
    pub(super) fn drop_member(&self, m: &Arc<Member>) {
        m.retire();
        self.lock().members.retain(|held| !Arc::ptr_eq(held, m));
    }
}

impl Member {
    pub(super) fn current(&self) -> Option<Link> {
        self.state.borrow().link.clone()
    }

    pub(super) fn last_error(&self) -> Option<LinkError> {
        self.state.borrow().error.clone()
    }

    pub(super) fn retire(&self) {
        let _ = self.retired.send_replace(true);
    }

    /// Waits until the member's link has closed after it was retired.
    pub(super) async fn stopped(&self) {
        let mut stopped = self.stopped.subscribe();
        let _ = stopped.wait_for(|s| *s).await;
    }

    /// The member's link once it is up, or `None` when `deadline` passes, the
    /// member is retired, or, with `fail_fast`, when its next dial fails.
    pub(super) async fn await_up(
        &self,
        deadline: tokio::time::Instant,
        fail_fast: bool,
    ) -> Option<Link> {
        let mut state = self.state.subscribe();
        let mut retired = self.retired.subscribe();
        let failures_at_start = state.borrow().failed_dials;
        loop {
            {
                let held = state.borrow_and_update();
                if let Some(link) = &held.link {
                    return Some(link.clone());
                }
                if fail_fast && held.failed_dials > failures_at_start {
                    return None;
                }
            }
            tokio::select! {
                changed = state.changed() => if changed.is_err() { return None },
                _ = retired.wait_for(|r| *r) => return None,
                _ = tokio::time::sleep_until(deadline) => return None,
            }
        }
    }
}

/// Dials the member's station, holds the link until it ends or the member is
/// retired, and dials again after the respawn delay.
async fn supervise(pool: Weak<PoolInner>, m: Arc<Member>) {
    let mut retired = m.retired.subscribe();
    loop {
        let Some(inner) = pool.upgrade() else { break };
        let respawn = inner.opts.respawn_delay;
        let mut cfg = Config::new(
            m.target.clone(),
            inner.opts.identity.clone(),
            inner.issuer.clone(),
        );
        cfg.publication_seq = Some(inner.publication_seq.clone());
        cfg.admission = Some(inner.admission.clone());
        cfg.dedup = Some(inner.dedup.clone());
        drop(inner);
        let dialed = tokio::select! {
            dialed = Link::dial(cfg) => dialed,
            _ = retired.wait_for(|r| *r) => break,
        };
        match dialed {
            Err(e) => {
                m.state.send_modify(|h| {
                    h.error = Some(e.clone());
                    h.failed_dials += 1;
                });
                event(&pool, &m, false, Some(e));
            }
            Ok(link) => {
                m.state.send_modify(|h| {
                    h.link = Some(link.clone());
                    h.error = None;
                });
                event(&pool, &m, true, None);
                if let Some(inner) = pool.upgrade() {
                    inner.replay(&link).await;
                }
                let retiring = tokio::select! {
                    _ = link.done() => false,
                    _ = retired.wait_for(|r| *r) => true,
                };
                if retiring {
                    let _ = link.close("client_stop").await;
                }
                let ended = link.error();
                m.state.send_modify(|h| {
                    h.link = None;
                    h.error = ended.clone();
                });
                event(&pool, &m, false, ended);
            }
        }
        if *retired.borrow() {
            break;
        }
        tokio::select! {
            _ = retired.wait_for(|r| *r) => break,
            _ = tokio::time::sleep(respawn) => {}
        }
    }
    let _ = m.stopped.send_replace(true);
}

fn event(pool: &Weak<PoolInner>, m: &Member, up: bool, error: Option<LinkError>) {
    if let Some(inner) = pool.upgrade() {
        inner.event(LinkEvent {
            station: m.target.expected_node_id,
            direct: m.direct,
            up,
            error,
        });
    }
}
