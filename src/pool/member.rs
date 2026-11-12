//! One station the pool links to, a seed or a station dialed directly for a
//! call: it dials the station, and when the link ends dials it again after
//! the respawn delay, until it is retired.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::watch;

use crate::station_link::{Config, Link, LinkError};
use crate::transport::Target;

use super::{LinkEvent, PoolInner, Tier};

pub(super) struct Member {
    pub(super) target: Target,
    pub(super) direct: bool,
    /// Which list the station was named in. It decides where the member's
    /// traffic goes, and whether it is redialed flat or on the backoff
    /// schedule: never which link exists.
    pub(super) tier: Tier,
    state: watch::Sender<Held>,
    retired: watch::Sender<bool>,
    stopped: watch::Sender<bool>,
}

/// What a member holds now: its link while one is up, the last error, and how
/// many dials have failed or died since its tier was last active.
#[derive(Clone, Default)]
struct Held {
    link: Option<Link>,
    error: Option<LinkError>,
    failed_dials: u64,
    attempts: u32,
}

impl PoolInner {
    pub(super) fn start_member(
        self: &Arc<Self>,
        target: Target,
        direct: bool,
        tier: Tier,
    ) -> Arc<Member> {
        let m = Arc::new(Member {
            target,
            direct,
            tier,
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

    /// How many dials have failed, or links died before proving themselves,
    /// since this member's tier was last active.
    fn attempts(&self) -> u32 {
        self.state.borrow().attempts
    }

    /// Clears the count: the member's tier just became the active one, so its
    /// next retry starts again from the floor.
    fn set_attempts(&self, attempts: u32) {
        self.state.send_modify(|h| h.attempts = attempts);
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
        let state = self.state.subscribe();
        let retired = self.retired.subscribe();
        let failures_at_start = state.borrow().failed_dials;
        await_up_on(state, retired, deadline, fail_fast, failures_at_start).await
    }
}

/// The waiting behind [`Member::await_up`], on the member's state and
/// retirement as subscribed when it began.
async fn await_up_on(
    mut state: watch::Receiver<Held>,
    mut retired: watch::Receiver<bool>,
    deadline: tokio::time::Instant,
    fail_fast: bool,
    failures_at_start: u64,
) -> Option<Link> {
    loop {
        if let Some(answer) = answer_now(&mut state, fail_fast, failures_at_start) {
            return answer;
        }
        tokio::select! {
            changed = state.changed() => if changed.is_err() { return None },
            _ = retired.wait_for(|r| *r) => return None,
            _ = tokio::time::sleep_until(deadline) => return None,
        }
    }
}

/// What a waiter for the link answers from the state seen now, marking it
/// seen: the link once it is up, `None` once a dial has failed since
/// `failures_at_start` while failing fast, or nothing yet.
fn answer_now(
    state: &mut watch::Receiver<Held>,
    fail_fast: bool,
    failures_at_start: u64,
) -> Option<Option<Link>> {
    let held = state.borrow_and_update();
    if let Some(link) = &held.link {
        return Some(Some(link.clone()));
    }
    if fail_fast && held.failed_dials > failures_at_start {
        return Some(None);
    }
    None
}

/// Dials the member's station, holds the link until it ends or the member is
/// retired, and dials again after the delay its tier earns: the flat respawn
/// delay while its tier is the active one, the backoff schedule while it is
/// not (macula-io/macula#201 §3).
async fn supervise(pool: Weak<PoolInner>, m: Arc<Member>) {
    let mut retired = m.retired.subscribe();
    loop {
        let Some(inner) = pool.upgrade() else { break };
        let cfg = link_config(&inner, &m);
        drop(inner);
        let dialed = tokio::select! {
            dialed = Link::dial(cfg) => dialed,
            _ = retired.wait_for(|r| *r) => break,
        };
        match dialed {
            Err(e) => dial_failed(&pool, &m, e),
            Ok(link) => hold(&pool, &m, &mut retired, link).await,
        }
        if *retired.borrow() {
            break;
        }
        let Some(inner) = pool.upgrade() else { break };
        if !wait_before_redial(&inner, &m, &mut retired).await {
            break;
        }
    }
    let _ = m.stopped.send_replace(true);
}

/// Waits out the member's redial delay, cutting it to the floor the moment the
/// member's own tier becomes the active one — so leaving the public tier is
/// immediate even for a seed that was waiting out a long backoff. Answers
/// false when the member was retired while it waited.
async fn wait_before_redial(
    inner: &Arc<PoolInner>,
    m: &Arc<Member>,
    retired: &mut watch::Receiver<bool>,
) -> bool {
    let floor = inner.opts.redial.base;
    let mut deadline = tokio::time::Instant::now() + redial_delay(inner, m);
    loop {
        tokio::select! {
            _ = retired.wait_for(|r| *r) => return false,
            _ = inner.tier_moved.notified() => {
                if m.tier == inner.active_tier() {
                    m.set_attempts(0);
                    deadline = deadline.min(tokio::time::Instant::now() + floor);
                }
            }
            _ = tokio::time::sleep_until(deadline) => return true,
        }
    }
}

/// How long the member waits before dialing again: the flat respawn delay
/// while its tier is the active one, and the backoff schedule while it is not.
fn redial_delay(inner: &PoolInner, m: &Member) -> Duration {
    match m.tier == inner.active_tier() {
        true => inner.opts.respawn_delay,
        false => inner.opts.redial.wait(m.attempts()),
    }
}

/// The link configuration a member dials its station with, from the pool's
/// identity, issuer, shared state and options.
fn link_config(inner: &PoolInner, m: &Member) -> Config {
    let mut cfg = Config::new(
        m.target.clone(),
        inner.opts.identity.clone(),
        inner.issuer.clone(),
    );
    cfg.publication_seq = Some(inner.publication_seq.clone());
    cfg.admission = Some(inner.admission.clone());
    cfg.dedup = Some(inner.dedup.clone());
    cfg.keyring = inner.keyring.clone();
    cfg.kem_advertise = inner.opts.kem_advertise;
    cfg
}

/// Records a failed dial: its error, one more failure, and the event. A failed
/// dial counts against the member's backoff: only a link that stays up for the
/// steady-up window clears the count.
fn dial_failed(pool: &Weak<PoolInner>, m: &Member, e: LinkError) {
    m.state.send_modify(|h| {
        h.error = Some(e.clone());
        h.failed_dials += 1;
        h.attempts = h.attempts.saturating_add(1);
    });
    event(pool, m, false, Some(e));
}

/// Holds a dialed link: marks it up, replays the pool onto it, waits until it
/// ends or the member is retired, closing it then, and marks it down with the
/// error it ended on.
async fn hold(pool: &Weak<PoolInner>, m: &Member, retired: &mut watch::Receiver<bool>, link: Link) {
    let up_since = tokio::time::Instant::now();
    m.state.send_modify(|h| {
        h.link = Some(link.clone());
        h.error = None;
    });
    event(pool, m, true, None);
    if let Some(inner) = pool.upgrade() {
        inner.tier_may_have_moved();
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
    let steady = pool
        .upgrade()
        .is_some_and(|inner| up_since.elapsed() >= inner.opts.redial.steady_up);
    m.state.send_modify(|h| {
        h.link = None;
        h.error = ended.clone();
        h.attempts = match steady {
            true => 0,
            false => h.attempts.saturating_add(1),
        };
    });
    event(pool, m, false, ended);
    if let Some(inner) = pool.upgrade() {
        inner.tier_may_have_moved();
        // What the link had not delivered goes out again on another (#57).
        inner.send_again(link.take_unconfirmed()).await;
    }
}

fn event(pool: &Weak<PoolInner>, m: &Member, up: bool, error: Option<LinkError>) {
    if let Some(inner) = pool.upgrade() {
        inner.event(LinkEvent {
            station: m.target.expected_node_id,
            tier: m.tier,
            direct: m.direct,
            up,
            error,
        });
    }
}
