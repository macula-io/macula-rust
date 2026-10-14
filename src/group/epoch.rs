//! The group epoch: a key for a stretch of time, its times, and the epoch
//! math around them. The counterpart of macula's `macula_group_epoch`.

use std::fmt;

use macula_mldsa::Zeroizing;

/// How long an epoch publishes by default, in milliseconds.
pub const DEFAULT_ROTATE_AFTER_MS: i64 = 15 * 60_000;

/// The protocol's times, in milliseconds: an event lives at most 60 minutes of
/// ttl plus 5 of tolerance, so an epoch is still accepted that long past its
/// publishing, and a verifier allows 5 minutes of clock skew.
pub const EVENT_LIFE_MS: i64 = 65 * 60_000;
pub const TOLERANCE_MS: i64 = 5 * 60_000;

/// The bytes of an epoch id, and of an epoch key.
pub const ID_SIZE: usize = 8;
pub const KEY_SIZE: usize = 32;

/// A group key for a stretch of time: its random id, which names it on every
/// sealed event, its random key, independent of every other epoch's, and its
/// times in Unix milliseconds. An event is sealed under it from `issued_at`
/// until `publish_until`, and opened under it until `accept_until`.
///
/// The key is erased when the epoch is dropped and is never printed: the same
/// rule macula 14.10.0 holds, that no group's epoch key appears in a process
/// state or a crash report.
#[derive(Clone)]
pub struct Epoch {
    pub id: [u8; ID_SIZE],
    key: Zeroizing<[u8; KEY_SIZE]>,
    pub issued_at: i64,
    pub publish_until: i64,
    pub accept_until: i64,
}

impl Epoch {
    /// An epoch of these parts, as a distributor's reply carries them.
    pub fn new(
        id: [u8; ID_SIZE],
        key: [u8; KEY_SIZE],
        issued_at: i64,
        publish_until: i64,
        accept_until: i64,
    ) -> Self {
        Epoch {
            id,
            key: Zeroizing::new(key),
            issued_at,
            publish_until,
            accept_until,
        }
    }

    /// The epoch key. Never public: only sealing and opening reach it.
    pub(crate) fn key(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// How long this epoch publishes.
    pub fn rotation(&self) -> i64 {
        self.publish_until - self.issued_at
    }

    /// The epoch's ahead window, `[from, to)`: the last third of its
    /// publishing stretch, when a pull is also handed the next epoch and every
    /// holder re-pulls.
    pub fn ahead_window(&self) -> (i64, i64) {
        (
            self.publish_until - self.rotation() / 3,
            self.publish_until,
        )
    }

    /// The instant a holder re-pulls: `fraction` of the way through the ahead
    /// window, the caller drawing it uniformly.
    pub fn repull_at(&self, fraction: f64) -> i64 {
        let (from, to) = self.ahead_window();
        from + ((to - from) as f64 * fraction) as i64
    }

    /// Whether an event under this epoch is accepted at `now`: until its
    /// `accept_until`, with the 5-minute clock tolerance.
    pub fn acceptable(&self, now: i64) -> bool {
        now <= self.accept_until + TOLERANCE_MS
    }
}

impl PartialEq for Epoch {
    /// Equal when their ids and times are equal and their keys are equal in
    /// constant time: these are keys, and a comparison that stopped at the
    /// first differing byte would say where they differ.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.issued_at == other.issued_at
            && self.publish_until == other.publish_until
            && self.accept_until == other.accept_until
            && aws_lc_rs::constant_time::verify_slices_are_equal(&self.key[..], &other.key[..])
                .is_ok()
    }
}

impl Eq for Epoch {}

impl fmt::Debug for Epoch {
    /// Its id and times, never its key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch")
            .field("id", &hex(&self.id))
            .field("key", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("publish_until", &self.publish_until)
            .field("accept_until", &self.accept_until)
            .finish()
    }
}

/// The epoch a publisher seals under at `now`: the newest held epoch that has
/// been issued and has not stopped publishing.
pub fn for_publish(held: &[Epoch], now: i64) -> Option<&Epoch> {
    held.iter()
        .filter(|e| e.issued_at <= now && now < e.publish_until)
        .max_by_key(|e| e.issued_at)
}

/// Drops the held epochs no longer of use at `now`.
pub fn retain_live(held: &mut Vec<Epoch>, now: i64) {
    held.retain(|e| e.acceptable(now));
}

/// A group prefix's org, its second segment: `io.macula/acme/chat` is owned by
/// `acme`, and `_realm` there names a realm-wide group.
pub fn org_of(prefix: &str) -> Result<&str, NotAGroup> {
    let mut segments = prefix.split('/');
    let _realm = segments.next();
    let org = segments.next().ok_or(NotAGroup)?;
    if org.is_empty() || prefix.split('/').any(str::is_empty) {
        return Err(NotAGroup);
    }
    Ok(org)
}

/// Whether `topic` is under `prefix`: equal to it, or the prefix followed by
/// `/`, so `.../acme/chat` covers `.../acme/chat/room/said_v1` and not
/// `.../acme/chatter`.
pub fn under(topic: &str, prefix: &str) -> bool {
    topic == prefix
        || (topic.len() > prefix.len()
            && topic.starts_with(prefix)
            && topic.as_bytes()[prefix.len()] == b'/')
}

/// A prefix that cannot be a group: fewer than two segments, or an empty one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAGroup;

impl fmt::Display for NotAGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a group prefix (realm/org/..., no empty segment)")
    }
}

impl std::error::Error for NotAGroup {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> Epoch {
        Epoch::new([7; ID_SIZE], [9; KEY_SIZE], 1_000, 1_000 + DEFAULT_ROTATE_AFTER_MS, 1_000 + EVENT_LIFE_MS)
    }

    /// The ahead window is the last third of the publishing stretch, and a
    /// re-pull drawn at 0 or 1 lands on its ends.
    #[test]
    fn the_ahead_window_is_the_last_third() {
        let e = epoch();
        let (from, to) = e.ahead_window();
        assert_eq!(to, e.publish_until);
        assert_eq!(from, e.publish_until - DEFAULT_ROTATE_AFTER_MS / 3);
        assert_eq!(e.repull_at(0.0), from);
        assert_eq!(e.repull_at(1.0), to);
        assert!(e.repull_at(0.5) > from && e.repull_at(0.5) < to);
    }

    /// An epoch is accepted until its accept_until plus the clock tolerance,
    /// and no longer.
    #[test]
    fn an_epoch_is_acceptable_to_its_life_plus_the_tolerance() {
        let e = epoch();
        assert!(e.acceptable(e.accept_until));
        assert!(e.acceptable(e.accept_until + TOLERANCE_MS));
        assert!(!e.acceptable(e.accept_until + TOLERANCE_MS + 1));
    }

    /// Publishing picks the newest epoch that has been issued and has not
    /// stopped, and picks nothing outside that.
    #[test]
    fn publishing_picks_the_newest_live_epoch() {
        let older = Epoch::new([1; ID_SIZE], [1; KEY_SIZE], 0, 3_000, 3_000 + EVENT_LIFE_MS);
        let newer = Epoch::new([2; ID_SIZE], [2; KEY_SIZE], 2_000, 9_000, 9_000 + EVENT_LIFE_MS);
        let held = vec![older, newer];
        assert_eq!(for_publish(&held, 2_500).unwrap().id, [2; ID_SIZE]);
        assert_eq!(for_publish(&held, 1_500).unwrap().id, [1; ID_SIZE]);
        assert!(for_publish(&held, -1).is_none());
        assert!(for_publish(&held, 9_000).is_none());
    }

    /// A group prefix is realm and org, and a topic is under it by segment,
    /// never by a shared spelling.
    #[test]
    fn a_group_prefix_is_realm_and_org() {
        assert_eq!(org_of("io.macula/acme/chat"), Ok("acme"));
        assert_eq!(org_of("io.macula/_realm"), Ok("_realm"));
        assert_eq!(org_of("io.macula"), Err(NotAGroup));
        assert_eq!(org_of("io.macula//chat"), Err(NotAGroup));
        assert_eq!(org_of(""), Err(NotAGroup));

        assert!(under("io.macula/acme/chat", "io.macula/acme/chat"));
        assert!(under("io.macula/acme/chat/room/said_v1", "io.macula/acme/chat"));
        assert!(!under("io.macula/acme/chatter", "io.macula/acme/chat"));
        assert!(!under("io.macula/acme", "io.macula/acme/chat"));
    }

    /// An epoch's key never reaches a debug rendering, which is what a panic
    /// or a log line prints.
    #[test]
    fn an_epoch_never_prints_its_key() {
        let shown = format!("{:?}", epoch());
        assert!(shown.contains("<redacted>"), "{shown}");
        let key: String = [9u8; KEY_SIZE].iter().map(|x| format!("{x:02x}")).collect();
        assert!(!shown.contains(&key), "{shown}");
    }
}
