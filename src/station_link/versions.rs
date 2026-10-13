//! The handshake version floor and counters of this process. The floor
//! (WIRE_1_0.md section 4.6) is the highest version this process completed a
//! handshake with, per station node_id; it is never completed below. An SDK
//! has no store of its own, so the floor holds for the run. The counters are
//! HELLO refusals by reason: this crate logs nothing, so these are where a
//! station that fails its session proof shows.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::handshake::HandshakeError;

use super::LinkError;

/// The handshake counters [`handshake_counters`] reports, zero included.
const COUNTER_NAMES: &[&str] = &[
    "session_proof_invalid",
    "session_proof_missing",
    "exporter_unavailable",
];

static COUNTERS: LazyLock<Mutex<HashMap<&'static str, u64>>> = LazyLock::new(Mutex::default);

static FLOORS: LazyLock<Mutex<HashMap<[u8; 32], i64>>> = LazyLock::new(Mutex::default);

fn floors() -> MutexGuard<'static, HashMap<[u8; 32], i64>> {
    FLOORS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The highest handshake version this process completed with `node_id`, 0
/// for none.
pub(super) fn floor(node_id: &[u8; 32]) -> i64 {
    floors().get(node_id).copied().unwrap_or(0)
}

/// Records a completed handshake with `node_id` in `version`: the floor is
/// raised, never lowered.
pub(super) fn completed(node_id: &[u8; 32], version: i64) {
    let mut f = floors();
    let held = f.entry(*node_id).or_insert(version);
    *held = (*held).max(version);
}

fn counters() -> MutexGuard<'static, HashMap<&'static str, u64>> {
    COUNTERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Counts a handshake refusal [`handshake_counters`] reports.
pub(super) fn count_refusal(e: &LinkError) {
    let name = match e {
        LinkError::Handshake(HandshakeError::SessionProofInvalid) => "session_proof_invalid",
        LinkError::Handshake(HandshakeError::SessionProofMissing) => "session_proof_missing",
        LinkError::Handshake(HandshakeError::ExporterUnavailable) => "exporter_unavailable",
        _ => return,
    };
    *counters().entry(name).or_default() += 1;
}

/// This process's handshake counters: HELLO refusals by reason.
pub fn handshake_counters() -> HashMap<&'static str, u64> {
    let c = counters();
    COUNTER_NAMES
        .iter()
        .map(|name| (*name, c.get(name).copied().unwrap_or(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_is_raised_by_a_completed_handshake_and_never_lowered() {
        let node = [0xF1; 32];
        assert_eq!(floor(&node), 0);
        completed(&node, 5);
        assert_eq!(floor(&node), 5);
        completed(&node, 4);
        assert_eq!(floor(&node), 5, "never lowered");
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
