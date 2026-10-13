//! The wire 1.0 counters (WIRE_1_0.md section 8), one set per process: what a
//! receiver read past instead of refusing. This crate logs nothing, so these
//! are where a peer speaking a newer wire 1.x shows.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

/// A snapshot of the wire counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireCounts {
    /// `wire_unknown_frame_type`: frames of a type this node does not know,
    /// dropped with the link left up.
    pub unknown_frame_type: u64,
    /// `wire_ext_ignored`, by extension name: non-critical extensions this
    /// node does not know.
    pub ext_ignored: HashMap<String, u64>,
    /// `wire_ext_refused`, by extension name: unknown critical extensions
    /// that refused the frame or signed object carrying them.
    pub ext_refused: HashMap<String, u64>,
    /// `wire_enum_fallback`, by field name: per-hop enum values this node does
    /// not know, read as the field's fallback.
    pub enum_fallback: HashMap<String, u64>,
}

static COUNTS: LazyLock<Mutex<WireCounts>> = LazyLock::new(Mutex::default);

fn counts() -> MutexGuard<'static, WireCounts> {
    COUNTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// This process's wire counters.
pub fn wire_counters() -> WireCounts {
    counts().clone()
}

/// Counts one dropped frame of a type this node does not know.
pub(crate) fn count_unknown_frame_type() {
    counts().unknown_frame_type += 1;
}

/// How many extension names a counter keeps apart; any further name is
/// counted under [`OTHER`] (WIRE_1_0.md section 8).
pub const MAX_COUNTED_NAMES: usize = 64;

/// The label of the names past [`MAX_COUNTED_NAMES`].
pub const OTHER: &str = "other";

/// Counts one ignored extension under its name, which the envelope rule
/// already bounds to 64 bytes.
pub(crate) fn count_ext_ignored(name: &str) {
    count_named(&mut counts().ext_ignored, name);
}

/// Counts one unknown critical extension that refused what carried it.
pub(crate) fn count_ext_refused(name: &str) {
    count_named(&mut counts().ext_refused, name);
}

/// Counts `name` in `by_name`, or under [`OTHER`] once it holds
/// [`MAX_COUNTED_NAMES`] names, so a peer cannot grow it without bound.
fn count_named(by_name: &mut HashMap<String, u64>, name: &str) {
    let label = match by_name.contains_key(name) || by_name.len() < MAX_COUNTED_NAMES {
        true => name,
        false => OTHER,
    };
    *by_name.entry(label.to_owned()).or_default() += 1;
}

/// Counts one per-hop enum value read as its field's fallback.
pub(crate) fn count_enum_fallback(field: &str) {
    *counts().enum_fallback.entry(field.to_owned()).or_default() += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_keeps_64_names_apart_and_the_rest_under_other() {
        let mut by_name = HashMap::new();
        for n in 0..MAX_COUNTED_NAMES + 10 {
            count_named(&mut by_name, &format!("example.e{n}"));
        }
        count_named(&mut by_name, "example.e0");
        assert_eq!(by_name.len(), MAX_COUNTED_NAMES + 1);
        assert_eq!(by_name[OTHER], 10);
        assert_eq!(
            by_name["example.e0"], 2,
            "a name already kept is counted as itself"
        );
    }
}
