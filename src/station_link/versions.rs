//! The handshake counters of this process: HELLO refusals by reason. This
//! crate logs nothing, so these are where a station that fails its session
//! proof shows.

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
