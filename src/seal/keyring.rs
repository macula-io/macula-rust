//! A provider's KEM keys (macula 13's E2E design, amendment A1): the key its
//! advertisements name, rotated every [`KEY_LIFETIME_MS`], and each replaced
//! key kept for [`RETIRED_KEY_KEPT_MS`], long enough that a request sealed to
//! it just before the rotation can still be admitted (the last
//! advertisement's 5 minutes, the clock tolerance's 5, the longest deadline's
//! 10, admission's 5 past it, and 5 of margin), then forgotten. Keys live in
//! memory only, never on disk: a restart loses them all, and a caller sealing
//! to an old one is refused sealed_refused, naming the new one. One node
//! identity, one keyring, as macula-go's seal.Keyring.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::profile::Profile;

use super::{hex, PrivateKey, SealError, KEY_ID_SIZE};

/// How long a key is the current one: 24 hours.
pub const KEY_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;
/// How long a replaced key still opens: 30 minutes.
pub const RETIRED_KEY_KEPT_MS: i64 = 30 * 60 * 1000;

/// The clock a keyring reads, in unix milliseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// One node identity's KEM keys. It is safe to share between links. Showing
/// it gives the current key id, never a key.
pub struct Keyring {
    profile: Profile,
    now: Clock,
    held: Mutex<Held>,
}

struct Held {
    current: Arc<PrivateKey>,
    current_id: [u8; KEY_ID_SIZE],
    since: i64,
    retired: Vec<Retired>,
}

struct Retired {
    key: Arc<PrivateKey>,
    id: [u8; KEY_ID_SIZE],
    until: i64,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = self.lock();
        write!(
            f,
            "Keyring({}, current key id {}, {} replaced kept)",
            self.profile.name(),
            hex(&held.current_id),
            held.retired.len()
        )
    }
}

impl Keyring {
    /// A keyring of `profile` with a fresh current key, reading the time
    /// from `now`.
    pub fn new(profile: Profile, now: Clock) -> Result<Keyring, SealError> {
        let key = PrivateKey::generate(profile)?;
        let since = now();
        Ok(Keyring {
            profile,
            now,
            held: Mutex::new(Held {
                current_id: key.public_key().key_id(),
                current: Arc::new(key),
                since,
                retired: Vec::new(),
            }),
        })
    }

    /// A keyring of `profile` on the system clock.
    pub fn system(profile: Profile) -> Result<Keyring, SealError> {
        Keyring::new(profile, Arc::new(unix_ms))
    }

    /// The profile of every key the keyring holds.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The key an advertisement names now, rotated first when it has lived
    /// [`KEY_LIFETIME_MS`]. Every advertisement reads it when it is signed,
    /// so a renewal names a rotated key.
    pub fn current(&self) -> Arc<PrivateKey> {
        let mut held = self.lock();
        self.rotate(&mut held, (self.now)());
        held.current.clone()
    }

    /// The id of the current key, which a sealed_refused names.
    pub fn current_id(&self) -> [u8; KEY_ID_SIZE] {
        let mut held = self.lock();
        self.rotate(&mut held, (self.now)());
        held.current_id
    }

    /// The key of `id`: the current key, or a replaced one still kept.
    pub fn find(&self, id: &[u8; KEY_ID_SIZE]) -> Option<Arc<PrivateKey>> {
        let mut held = self.lock();
        let now = (self.now)();
        self.rotate(&mut held, now);
        if &held.current_id == id {
            return Some(held.current.clone());
        }
        held.retired
            .iter()
            .find(|old| &old.id == id && now < old.until)
            .map(|old| old.key.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Replaces the current key once it has lived [`KEY_LIFETIME_MS`],
    /// keeping it for [`RETIRED_KEY_KEPT_MS`], and forgets the replaced keys
    /// past theirs.
    fn rotate(&self, held: &mut Held, now: i64) {
        held.retired.retain(|old| now < old.until);
        if now - held.since < KEY_LIFETIME_MS {
            return;
        }
        // The profile was checked when the keyring was made: a key that
        // cannot be generated now keeps the current one rather than hold
        // none.
        let Ok(next) = PrivateKey::generate(self.profile) else {
            return;
        };
        let next_id = next.public_key().key_id();
        let replaced = std::mem::replace(&mut held.current, Arc::new(next));
        held.retired.push(Retired {
            key: replaced,
            id: held.current_id,
            until: now + RETIRED_KEY_KEPT_MS,
        });
        held.current_id = next_id;
        held.since = now;
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;
    use crate::seal::carried_key_size;

    fn clock(at: &Arc<AtomicI64>) -> Clock {
        let at = at.clone();
        Arc::new(move || at.load(Ordering::SeqCst))
    }

    /// One current key, rotated every 24 hours, a replaced key still opening
    /// for 30 minutes and then gone.
    #[test]
    fn a_keyring_rotates_and_forgets() {
        let at = Arc::new(AtomicI64::new(1_790_000_000_000));
        let ring = Keyring::new(Profile::PqPure, clock(&at)).unwrap();
        let first = ring.current().public_key().key_id();
        assert_eq!(ring.current().public_key().key_id(), first);

        at.fetch_add(KEY_LIFETIME_MS - 1000, Ordering::SeqCst);
        assert_eq!(
            ring.current().public_key().key_id(),
            first,
            "a key rotated before its lifetime"
        );
        at.fetch_add(1000, Ordering::SeqCst);
        let second = ring.current().public_key().key_id();
        assert_ne!(second, first, "a key outlived its lifetime");
        assert_eq!(ring.current_id(), second);
        assert!(ring.find(&first).is_some(), "a replaced key stopped at once");

        at.fetch_add(RETIRED_KEY_KEPT_MS - 1000, Ordering::SeqCst);
        assert!(ring.find(&first).is_some(), "a replaced key went early");
        at.fetch_add(1000, Ordering::SeqCst);
        assert!(ring.find(&first).is_none(), "a replaced key outlived 30 minutes");
        assert_eq!(
            ring.find(&second).map(|k| k.public_key().key_id()),
            Some(second)
        );
        assert!(ring.find(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_keyring_is_of_its_profile_and_shows_no_key() {
        for profile in [Profile::PqPure, Profile::PqHybrid] {
            let ring = Keyring::system(profile).unwrap();
            assert_eq!(ring.profile(), profile);
            assert_eq!(
                ring.current().public_key().carried().len(),
                carried_key_size(profile)
            );
            let shown = format!("{ring:?}");
            assert!(shown.contains(&hex(&ring.current_id())), "{shown}");
            assert!(shown.len() < 200, "{shown}");
        }
    }
}
