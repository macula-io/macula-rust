//! The sessions this process has open, at most one per identity and
//! station, so direct dial can reuse one instead of dialing again.
//!
//! A station keeps one connection per identity: when a newer connection
//! under an identity completes its handshake, the station closes the older
//! one (`macula_station_listener.erl`, `replaced_by_newer_handshake`). Code
//! that needs a station under an identity this process already holds a
//! session to must therefore reuse that session, or it closes its own
//! session by dialing. Direct dial looks here before it dials.
//!
//! A session registers once its HELLO is accepted and unregisters when it
//! closes. The newest registration for a pair wins, matching the station,
//! and unregistering removes an entry only if it still holds that same
//! session, so closing an older session never drops a newer one. Entries
//! are weak: a session dropped without closing, or whose connection has
//! ended, is not found.
//!
//! A session direct dial dialed for its own requests carries [`Leases`]:
//! every request using it holds one, so it closes when the last request is
//! done, and it is not reused once it is closing. A session its owner opened
//! carries none, and direct dial never closes it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

/// Whether an open session's connection can still carry a request.
pub(crate) trait Live {
    fn is_live(&self) -> bool;
}

/// A session that may carry [`Leases`]: one direct dial dialed does, one its
/// owner opened doesn't.
pub(crate) trait Leased {
    fn leases(&self) -> Option<&Leases>;
}

/// The requests using a session direct dial dialed, counted so the session
/// closes when the last one is done and is not reused once it is closing.
/// The request that dialed the session holds the first lease.
pub(crate) struct Leases {
    count: Mutex<usize>,
}

impl Leases {
    pub(crate) fn new() -> Self {
        Self {
            count: Mutex::new(1),
        }
    }

    /// Takes one more lease, unless the last one was already released.
    pub(crate) fn try_lease(&self) -> bool {
        let mut count = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        if *count == 0 {
            return false;
        }
        *count += 1;
        true
    }

    /// Gives one lease back, and says whether it was the last, so the session
    /// is to be closed. A release after the last one does nothing.
    pub(crate) fn release(&self) -> bool {
        let mut count = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        if *count == 0 {
            return false;
        }
        *count -= 1;
        *count == 0
    }
}

/// An identity's node id and a station's node id.
type Pair = ([u8; 32], [u8; 32]);

pub(crate) struct OpenSessions<C> {
    open: Mutex<HashMap<Pair, Weak<C>>>,
}

impl<C> Default for OpenSessions<C> {
    fn default() -> Self {
        Self {
            open: Mutex::new(HashMap::new()),
        }
    }
}

impl<C: Live> OpenSessions<C> {
    pub(crate) fn register(&self, identity: [u8; 32], station: [u8; 32], session: &Arc<C>) {
        self.lock()
            .insert((identity, station), Arc::downgrade(session));
    }

    #[cfg(test)]
    pub(crate) fn unregister(&self, identity: [u8; 32], station: [u8; 32], session: &Arc<C>) {
        self.unregister_pointer(identity, station, Arc::as_ptr(session));
    }

    /// [`unregister`](Self::unregister), for a session only a weak reference
    /// is left to, such as one whose last handle is being dropped.
    pub(crate) fn unregister_weak(&self, identity: [u8; 32], station: [u8; 32], session: &Weak<C>) {
        self.unregister_pointer(identity, station, session.as_ptr());
    }

    fn unregister_pointer(&self, identity: [u8; 32], station: [u8; 32], session: *const C) {
        let mut open = self.lock();
        if open
            .get(&(identity, station))
            .is_some_and(|held| std::ptr::eq(held.as_ptr(), session))
        {
            open.remove(&(identity, station));
        }
    }

    pub(crate) fn find(&self, identity: [u8; 32], station: [u8; 32]) -> Option<Arc<C>> {
        let mut open = self.lock();
        let found = open
            .get(&(identity, station))
            .and_then(Weak::upgrade)
            .filter(|session| session.is_live());
        if found.is_none() {
            open.remove(&(identity, station));
        }
        found
    }

    // A panic elsewhere while the lock was held leaves the map itself intact.
    fn lock(&self) -> MutexGuard<'_, HashMap<Pair, Weak<C>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// This process's open sessions, which every
/// [`Session`](crate::connection::Session) registers with.
pub(crate) fn live() -> &'static OpenSessions<crate::connection::SessionInner> {
    static LIVE: OnceLock<OpenSessions<crate::connection::SessionInner>> = OnceLock::new();
    LIVE.get_or_init(OpenSessions::default)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct FakeSession {
        live: AtomicBool,
    }

    impl Live for FakeSession {
        fn is_live(&self) -> bool {
            self.live.load(Ordering::Relaxed)
        }
    }

    fn open_session() -> Arc<FakeSession> {
        Arc::new(FakeSession {
            live: AtomicBool::new(true),
        })
    }

    fn node_id() -> [u8; 32] {
        rand::random()
    }

    fn holds(found: Option<Arc<FakeSession>>, session: &Arc<FakeSession>) -> bool {
        found.is_some_and(|found| Arc::ptr_eq(&found, session))
    }

    #[test]
    fn a_session_is_found_by_its_identity_and_station() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let session = open_session();

        open.register(identity, station, &session);

        assert!(holds(open.find(identity, station), &session));
        assert!(open.find(node_id(), station).is_none());
        assert!(open.find(identity, node_id()).is_none());
    }

    #[test]
    fn the_newest_session_per_identity_and_station_wins() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let (older, newer) = (open_session(), open_session());

        open.register(identity, station, &older);
        open.register(identity, station, &newer);

        assert!(holds(open.find(identity, station), &newer));
    }

    #[test]
    fn closing_an_older_session_leaves_the_newer_one_registered() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let (older, newer) = (open_session(), open_session());
        open.register(identity, station, &older);
        open.register(identity, station, &newer);

        open.unregister(identity, station, &older);

        assert!(holds(open.find(identity, station), &newer));
    }

    #[test]
    fn a_closed_session_is_no_longer_found() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let session = open_session();
        open.register(identity, station, &session);

        open.unregister(identity, station, &session);

        assert!(open.find(identity, station).is_none());
    }

    #[test]
    fn a_dropped_session_is_no_longer_found() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let session = open_session();
        open.register(identity, station, &session);

        drop(session);

        assert!(open.find(identity, station).is_none());
    }

    #[test]
    fn a_session_whose_connection_ended_is_no_longer_found() {
        let (identity, station) = (node_id(), node_id());
        let open = OpenSessions::default();
        let session = open_session();
        open.register(identity, station, &session);

        session.live.store(false, Ordering::Relaxed);

        assert!(open.find(identity, station).is_none());
    }
}
