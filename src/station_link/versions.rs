//! Which handshake version a link dials each station with, and the handshake
//! counters, for this process (macula DESIGN_NEIGHBOUR_CHANNEL_BINDING
//! sections 3, 4 and 6), as macula's macula_peer_versions and macula-go's
//! stationlink keep them.
//!
//! A station never seen is dialled with version 5. One that refused a v5
//! CONNECT with `unsupported_version` is dialled with version 4 for the next
//! 10 minutes, then with 5 again. One that completed a v5 handshake in this
//! process is never dialled with version 4 again: a later
//! `unsupported_version` from it is refused as a downgrade
//! ([`LinkError::V5DowngradeRefused`]), which also refuses a station rolled
//! back below v5, until [`forget_v5_peer`] or a restart. There is no timer on
//! that memory, because a timer is also an attacker's wait.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use crate::handshake::{HandshakeError, VERSION, VERSION_5};

use super::{Inner, LinkError};

const V4_CACHE: Duration = Duration::from_secs(10 * 60);

/// The handshake counters [`handshake_counters`] reports, zero included.
const COUNTER_NAMES: &[&str] = &[
    "v4_connections",
    "v5_connections",
    "v4_fallbacks",
    "v5_downgrade_refused",
    "v4_hello_to_v5_connect",
    "session_proof_invalid",
    "session_proof_missing",
    "exporter_unavailable",
];

#[derive(Default)]
struct PeerVersions {
    seen_v5: HashSet<[u8; 32]>,
    v4_until: HashMap<[u8; 32], Instant>,
    /// This process's open v4 links, by station, by serial.
    v4_links: HashMap<[u8; 32], HashMap<u64, Weak<Inner>>>,
    counters: HashMap<&'static str, u64>,
}

static VERSIONS: LazyLock<Mutex<PeerVersions>> = LazyLock::new(Mutex::default);

fn versions() -> MutexGuard<'static, PeerVersions> {
    VERSIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The version to dial `node_id` with now.
pub(super) fn dial_version(node_id: &[u8; 32], now: Instant) -> i64 {
    let v = versions();
    match v.v4_until.get(node_id) {
        _ if v.seen_v5.contains(node_id) => VERSION_5,
        Some(until) if now < *until => VERSION,
        _ => VERSION_5,
    }
}

/// Records a v4 refusal of a v5 CONNECT from `node_id`: false for a node seen
/// on v5 (a refused downgrade), true for one that falls back to version 4 for
/// 10 minutes.
pub(super) fn unsupported_version(node_id: &[u8; 32], now: Instant) -> bool {
    let mut v = versions();
    if v.seen_v5.contains(node_id) {
        *v.counters.entry("v5_downgrade_refused").or_default() += 1;
        return false;
    }
    v.v4_until.insert(*node_id, now + V4_CACHE);
    *v.counters.entry("v4_fallbacks").or_default() += 1;
    true
}

/// Records `link`'s handshake with its station, in the link's version, so that
/// no ordering keeps a v4 link to a node this process has seen on v5
/// (macula#53). A v4 link to a node seen on v5 is
/// [`LinkError::V5DowngradeRefused`]; any other v4 link is registered, under
/// the same lock as the check, and a later v5 completion with that node ends
/// every registered one as a downgrade.
pub(super) fn completed(node_id: &[u8; 32], link: &Arc<Inner>) -> Result<(), LinkError> {
    let superseded = recorded(node_id, link.version, link.serial, Arc::downgrade(link))?;
    for old in superseded.iter().filter_map(Weak::upgrade) {
        old.end(LinkError::V5DowngradeRefused);
    }
    Ok(())
}

/// `completed` under the lock, for the link `serial` of `version`, held as
/// `link`: the v4 links a v5 completion supersedes, to be ended outside it.
fn recorded(
    node_id: &[u8; 32],
    version: i64,
    serial: u64,
    link: Weak<Inner>,
) -> Result<Vec<Weak<Inner>>, LinkError> {
    let mut v = versions();
    if version == VERSION_5 {
        v.seen_v5.insert(*node_id);
        v.v4_until.remove(node_id);
        *v.counters.entry("v5_connections").or_default() += 1;
        let superseded: Vec<Weak<Inner>> = v
            .v4_links
            .remove(node_id)
            .map(|links| links.into_values().collect())
            .unwrap_or_default();
        *v.counters.entry("v5_downgrade_refused").or_default() += superseded.len() as u64;
        return Ok(superseded);
    }
    if v.seen_v5.contains(node_id) {
        *v.counters.entry("v5_downgrade_refused").or_default() += 1;
        return Err(LinkError::V5DowngradeRefused);
    }
    v.v4_links.entry(*node_id).or_default().insert(serial, link);
    *v.counters.entry("v4_connections").or_default() += 1;
    Ok(Vec::new())
}

/// Forgets a v4 link that ended.
pub(super) fn v4_ended(node_id: &[u8; 32], serial: u64) {
    let mut v = versions();
    if let Some(links) = v.v4_links.get_mut(node_id) {
        links.remove(&serial);
        if links.is_empty() {
            v.v4_links.remove(node_id);
        }
    }
}

/// Counts a handshake refusal [`handshake_counters`] reports.
pub(super) fn count_refusal(e: &LinkError) {
    let name = match e {
        LinkError::Handshake(HandshakeError::V4HelloToV5Connect) => "v4_hello_to_v5_connect",
        LinkError::Handshake(HandshakeError::SessionProofInvalid) => "session_proof_invalid",
        LinkError::Handshake(HandshakeError::SessionProofMissing) => "session_proof_missing",
        LinkError::Handshake(HandshakeError::ExporterUnavailable) => "exporter_unavailable",
        _ => return,
    };
    *versions().counters.entry(name).or_default() += 1;
}

/// Forgets that this process completed a handshake v5 with the station
/// `node_id`, so a station deliberately rolled back below v5 is dialled again,
/// falling back to v4. An operator action for a deliberate rollback, never
/// automatic.
pub fn forget_v5_peer(node_id: &[u8; 32]) {
    versions().seen_v5.remove(node_id);
}

/// This process's handshake counters: links by version, v4 fallbacks, refused
/// downgrades, and HELLO refusals by reason. This crate logs nothing, so these
/// are where a repeated fallback or a refused downgrade shows.
pub fn handshake_counters() -> HashMap<&'static str, u64> {
    let v = versions();
    COUNTER_NAMES
        .iter()
        .map(|name| (*name, v.counters.get(name).copied().unwrap_or(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node id no other test uses: the memory is the process's.
    fn node(n: u8) -> [u8; 32] {
        let mut id = [0xA5; 32];
        id[0] = n;
        id
    }

    fn v4_links(node_id: &[u8; 32]) -> usize {
        versions().v4_links.get(node_id).map_or(0, HashMap::len)
    }

    #[test]
    fn a_station_never_seen_is_dialled_with_v5_and_one_that_refused_v5_with_v4_for_ten_minutes() {
        let (n, now) = (node(1), Instant::now());
        assert_eq!(dial_version(&n, now), VERSION_5);
        assert!(unsupported_version(&n, now), "a first refusal falls back");
        assert_eq!(dial_version(&n, now), VERSION);
        assert_eq!(
            dial_version(&n, now + V4_CACHE - Duration::from_secs(1)),
            VERSION
        );
        assert_eq!(dial_version(&n, now + V4_CACHE), VERSION_5, "then v5 again");
    }

    #[test]
    fn a_station_seen_on_v5_is_never_dialled_with_v4_until_forgotten() {
        let (n, now) = (node(2), Instant::now());
        recorded(&n, VERSION_5, 1, Weak::new()).unwrap();
        assert_eq!(dial_version(&n, now), VERSION_5);
        assert!(
            !unsupported_version(&n, now),
            "a v4 answer is a refused downgrade"
        );
        assert_eq!(
            dial_version(&n, now),
            VERSION_5,
            "no v4 cache for a downgrade"
        );
        assert!(
            matches!(
                recorded(&n, VERSION, 2, Weak::new()),
                Err(LinkError::V5DowngradeRefused)
            ),
            "a v4 completion after v5 is refused"
        );
        forget_v5_peer(&n);
        assert!(
            unsupported_version(&n, now),
            "forgotten: it falls back again"
        );
        assert_eq!(dial_version(&n, now), VERSION);
    }

    /// macula#53, the other ordering: a v4 link that completed first is ended
    /// when a v5 link to the same node completes.
    #[test]
    fn a_v5_completion_supersedes_every_open_v4_link_to_that_node() {
        let (n, other) = (node(3), node(4));
        assert!(recorded(&n, VERSION, 10, Weak::new()).unwrap().is_empty());
        assert!(recorded(&n, VERSION, 11, Weak::new()).unwrap().is_empty());
        assert!(recorded(&other, VERSION, 12, Weak::new())
            .unwrap()
            .is_empty());
        assert_eq!(v4_links(&n), 2);
        let superseded = recorded(&n, VERSION_5, 13, Weak::new()).unwrap();
        assert_eq!(superseded.len(), 2, "both v4 links to the node are ended");
        assert_eq!(v4_links(&n), 0);
        assert_eq!(v4_links(&other), 1, "another node's v4 link stays");
    }

    #[test]
    fn a_v4_link_that_ended_is_forgotten() {
        let n = node(5);
        recorded(&n, VERSION, 20, Weak::new()).unwrap();
        recorded(&n, VERSION, 21, Weak::new()).unwrap();
        v4_ended(&n, 20);
        assert_eq!(v4_links(&n), 1);
        v4_ended(&n, 21);
        assert!(!versions().v4_links.contains_key(&n));
        assert!(recorded(&n, VERSION_5, 22, Weak::new()).unwrap().is_empty());
    }

    #[test]
    fn the_counters_name_every_handshake_outcome() {
        let counters = handshake_counters();
        for name in COUNTER_NAMES {
            assert!(counters.contains_key(name), "{name}");
        }
        let before = handshake_counters()["session_proof_invalid"];
        count_refusal(&LinkError::Handshake(HandshakeError::SessionProofInvalid));
        count_refusal(&LinkError::Handshake(HandshakeError::ProofInvalid));
        assert!(handshake_counters()["session_proof_invalid"] > before);
    }
}
