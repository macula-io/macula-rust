//! A pool's two station tiers, and the schedule a link whose tier is not
//! active is redialed on (macula-io/macula#201).
//!
//! The tier a station is on is which list it was named in. Which of the two is
//! *active* is decided by the connections alone: the public tier the moment any
//! public link is up, the fallback tier only when none is. Every rule that uses
//! the pair lives in `pool.rs`, `member.rs` and `call.rs`; this module holds
//! only the two types and the arithmetic, so it can be read and tested on its
//! own.

use std::fmt;
use std::time::Duration;

/// Which list a station was named in: the seeds a pool is given are its public
/// tier, the stations in [`Opts::fallback_seeds`] its fallback tier. A station
/// dialed directly for a call is public — a station the node was handed a route
/// to is not a fallback.
///
/// *Originating* traffic (a publication, a station procedure, a content
/// announcement and a re-sent publication) goes to the active tier only.
/// *Standing* registrations (a subscription, a served procedure and every
/// replay) go to every link of both tiers, and it is that which lets two nodes
/// on different tiers still reach each other.
///
/// [`Opts::fallback_seeds`]: super::Opts::fallback_seeds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The tier of the pool's seeds, and of every station dialed directly.
    Public,
    /// The tier of the pool's fallback seeds, kept for when no public station
    /// is up.
    Fallback,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tier::Public => "public",
            Tier::Fallback => "fallback",
        })
    }
}

/// The floor of a redial wait: the first retry of a seed whose tier is down.
pub const DEFAULT_REDIAL_BASE: Duration = Duration::from_secs(5);
/// How much each further failed attempt multiplies the ceiling by.
pub const DEFAULT_REDIAL_FACTOR: u32 = 2;
/// The ceiling of a redial wait, before jitter.
pub const DEFAULT_REDIAL_CAP: Duration = Duration::from_secs(300);
/// How long a link must stay up before its seed's backoff resets.
pub const DEFAULT_REDIAL_STEADY_UP: Duration = Duration::from_secs(60);

/// How a link whose tier is **not** active is redialed, and how long a link
/// must stay up before its counter resets.
///
/// A link whose tier **is** active keeps the flat [`respawn_delay`]: a station
/// that drops while its tier is healthy is expected back at once.
///
/// [`respawn_delay`]: super::Opts::respawn_delay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redial {
    /// The floor: the first retry of an inactive-tier seed waits exactly this,
    /// and no later retry waits less.
    pub base: Duration,
    /// The growth per failed attempt.
    pub factor: u32,
    /// The ceiling on the computed delay, before jitter.
    pub cap: Duration,
    /// How long a link must stay up before its seed's counter resets. A link
    /// that connects and dies sooner keeps its accumulated backoff, so a
    /// connect-then-die loop escalates instead of retrying at the floor.
    pub steady_up: Duration,
}

impl Default for Redial {
    fn default() -> Redial {
        Redial {
            base: DEFAULT_REDIAL_BASE,
            factor: DEFAULT_REDIAL_FACTOR,
            cap: DEFAULT_REDIAL_CAP,
            steady_up: DEFAULT_REDIAL_STEADY_UP,
        }
    }
}

impl Redial {
    /// Refuses a schedule no wait can be made from, and fills in a zero bound
    /// with its default as the pool's other options do.
    pub(super) fn checked(mut self) -> Result<Redial, String> {
        let defaults = Redial::default();
        self.base = fill(self.base, defaults.base);
        self.factor = if self.factor == 0 {
            defaults.factor
        } else {
            self.factor
        };
        self.cap = fill(self.cap, defaults.cap);
        self.steady_up = fill(self.steady_up, defaults.steady_up);
        if self.factor < 2 {
            return Err(format!(
                "a redial factor of {}, which never backs off",
                self.factor
            ));
        }
        Ok(self)
    }

    /// How long to wait before the retry after `attempt` failed ones, `0` being
    /// the first: `base` plus a draw in `0..(min(cap, base × factor^attempt) −
    /// base)`. At attempt `0` the range is empty, so the first retry waits
    /// exactly the base, and no wait ever falls below it.
    pub(super) fn wait(&self, attempt: u32) -> Duration {
        let ceiling = self.cap.min(self.grown(attempt));
        if ceiling <= self.base {
            return self.base;
        }
        self.base + draw(ceiling - self.base)
    }

    /// The undrawn ceiling of the wait after `attempt` failures, never past the
    /// cap and never zero.
    ///
    /// Each step is clamped to the cap. [`Redial::checked`] keeps the factor at
    /// two or more, so a step that does not grow has passed the cap and every
    /// step after it would only pass it further: clamping is the same as
    /// stopping there.
    fn grown(&self, attempt: u32) -> Duration {
        (0..attempt).fold(self.base, |grown, _| {
            grown.saturating_mul(self.factor).min(self.cap)
        })
    }
}

/// A zero bound means the schedule's default, as a zero pool option does.
fn fill(value: Duration, default: Duration) -> Duration {
    if value.is_zero() {
        default
    } else {
        value
    }
}

/// A random duration in `0..bound`, and zero when the system's randomness
/// cannot be read (a draw of zero only ever waits the floor).
fn draw(bound: Duration) -> Duration {
    let Ok(nanos) = u64::try_from(bound.as_nanos()) else {
        return Duration::ZERO;
    };
    if nanos == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0_u8; 8];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    Duration::from_nanos(u64::from_le_bytes(bytes) % nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_retry_waits_exactly_the_base() {
        let redial = Redial::default();
        assert_eq!(redial.wait(0), redial.base);
    }

    /// Every wait is at or above the floor and at or below its drawn ceiling,
    /// for a run of attempts: the bound is asserted, not one sampled draw.
    #[test]
    fn no_wait_falls_below_the_base_or_past_its_ceiling() {
        let redial = Redial {
            base: Duration::from_millis(10),
            factor: 2,
            cap: Duration::from_millis(200),
            steady_up: Duration::from_millis(50),
        };
        for attempt in 0..12 {
            assert_bounded_draws(&redial, attempt);
        }
    }

    /// Fifty draws at one attempt are each inside the bounds that attempt
    /// admits.
    fn assert_bounded_draws(redial: &Redial, attempt: u32) {
        let ceiling = redial.cap.min(redial.grown(attempt));
        for _ in 0..50 {
            let wait = redial.wait(attempt);
            assert!(
                wait >= redial.base,
                "attempt {attempt}: {wait:?} is below the floor {:?}",
                redial.base
            );
            assert!(
                wait <= ceiling,
                "attempt {attempt}: {wait:?} is past the ceiling {ceiling:?}"
            );
        }
    }

    #[test]
    fn the_ceiling_grows_by_the_factor_and_stops_at_the_cap() {
        let redial = Redial {
            base: Duration::from_millis(100),
            factor: 3,
            cap: Duration::from_millis(1000),
            steady_up: Duration::from_millis(50),
        };
        assert_eq!(redial.grown(0), Duration::from_millis(100));
        assert_eq!(redial.grown(1), Duration::from_millis(300));
        assert_eq!(redial.grown(2), Duration::from_millis(900));
        assert_eq!(redial.grown(3), redial.cap, "past the cap it stays there");
        assert_eq!(redial.grown(40), redial.cap, "and never overflows");
    }

    #[test]
    fn a_base_above_the_cap_waits_the_base() {
        let redial = Redial {
            base: Duration::from_millis(500),
            factor: 2,
            cap: Duration::from_millis(100),
            steady_up: Duration::from_millis(50),
        };
        assert_eq!(redial.wait(0), redial.base);
        assert_eq!(redial.wait(3), redial.base);
    }

    #[test]
    fn a_schedule_no_wait_can_be_made_from_is_refused() {
        let flat = Redial {
            factor: 1,
            ..Redial::default()
        };
        let refused = flat.checked().expect_err("a factor of 1 never grows");
        assert!(refused.contains("factor"), "{refused}");
    }

    #[test]
    fn a_zero_bound_takes_its_default() {
        let filled = Redial {
            base: Duration::ZERO,
            factor: 0,
            cap: Duration::ZERO,
            steady_up: Duration::ZERO,
        }
        .checked()
        .expect("every zero bound takes its default");
        assert_eq!(filled, Redial::default());
    }
}
