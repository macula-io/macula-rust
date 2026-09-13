//! Petnames: a deterministic, human-readable label for a mesh node id —
//! Docker's adjective_color_animal convention with a four-digit suffix
//! (e.g. "happy_green_rabbit_4831") — so a person skimming a roster,
//! transcript, or room listing can recognize and remember a specific
//! identity without reading 64 hex characters. A pure function of the
//! node id itself, not random per process: the same identity gets the
//! same petname across restarts, across every tool that shows it, and
//! on every other agent's own roster too (everyone hashes the same
//! public bytes). This is a companion label, never a replacement —
//! every surface that adds one keeps the real node_id right alongside
//! it, since only the real id is addressable.
//!
//! The suffix exists because the mesh is expected to host THOUSANDS of
//! agents: 40 x 40 x 40 word trios alone collide visibly under the
//! birthday problem at a few hundred identities, while the trio plus a
//! 4-digit hash group (640,000,000 combinations) stays effectively
//! collision-free at fleet scale while remaining scannable.
//!
//! The word lists and derivation are shared with macula-mcp's own
//! `src/petname.ts` (which this supersedes as the SDK-level home; the
//! desktop and every future consumer pull it from here): same sha256 of
//! the lowercased hex id, same 16-bit reads modulo the list lengths,
//! plus the suffix group.

use sha2::{Digest, Sha256};

const ADJECTIVES_A: [&str; 40] = [
    "bold", "bouncy", "brave", "breezy", "calm", "cheerful", "clever", "curious",
    "daring", "eager", "elegant", "fierce", "gentle", "graceful", "humble", "jolly",
    "jovial", "keen", "kind", "lively", "lucky", "mellow", "merry", "nimble",
    "noble", "plucky", "proud", "quiet", "quirky", "radiant", "silly", "sleepy",
    "spry", "sturdy", "tranquil", "upbeat", "vivid", "wise", "witty", "zealous",
];

const ADJECTIVES_B: [&str; 40] = [
    "amber", "azure", "bronze", "coral", "crimson", "cyan", "emerald", "golden",
    "green", "indigo", "ivory", "jade", "lavender", "lilac", "magenta", "maroon",
    "mauve", "navy", "olive", "orange", "peach", "pink", "plum", "purple",
    "red", "rust", "ruby", "sage", "salmon", "scarlet", "sienna", "silver",
    "slate", "tan", "teal", "turquoise", "violet", "yellow", "blue", "copper",
];

const NOUNS: [&str; 40] = [
    "antelope", "badger", "beetle", "bison", "cricket", "dolphin", "eagle", "elk",
    "falcon", "ferret", "flamingo", "fox", "gazelle", "gecko", "hare", "heron",
    "ibex", "iguana", "lynx", "marten", "mongoose", "moose", "narwhal", "orca",
    "otter", "owl", "panther", "pelican", "penguin", "rabbit", "raven", "salamander",
    "seal", "sparrow", "tiger", "toucan", "walrus", "weasel", "wolf", "wombat",
];

/// The stable "adjective_color_animal_0000" label for a node id, e.g.
/// "happy_green_rabbit_4831". Same input always produces the same
/// output — derived from a sha256 digest of the id (lowercased first,
/// so a node id that happens to arrive in mixed case still maps to the
/// same petname as its lowercase form), not from anything process-local
/// like a random seed or insertion order.
pub fn petname(node_id: &str) -> String {
    let digest = Sha256::digest(node_id.to_ascii_lowercase().as_bytes());
    let a = ADJECTIVES_A[u16::from_be_bytes([digest[0], digest[1]]) as usize % ADJECTIVES_A.len()];
    let b = ADJECTIVES_B[u16::from_be_bytes([digest[2], digest[3]]) as usize % ADJECTIVES_B.len()];
    let n = NOUNS[u16::from_be_bytes([digest[4], digest[5]]) as usize % NOUNS.len()];
    let suffix = u16::from_be_bytes([digest[6], digest[7]]) % 10_000;
    format!("{a}_{b}_{n}_{suffix:04}")
}

#[cfg(test)]
mod tests {
    use super::petname;

    #[test]
    fn petname_is_deterministic_and_shaped() {
        let id = "7374b0cfab4eea68e271c3815a0f78e21e913397f67345f337ddba7a3a88ab3a";
        let first = petname(id);
        assert_eq!(petname(id), first);
        let parts: Vec<&str> = first.split('_').collect();
        assert_eq!(parts.len(), 4, "adjective_color_animal_suffix");
        assert_eq!(parts[3].len(), 4, "zero-padded four-digit suffix");
        assert!(parts[3].chars().all(|c| c.is_ascii_digit()));
    }
}
