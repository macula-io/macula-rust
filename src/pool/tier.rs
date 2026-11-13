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
    /// Where a wait's jitter lands. [`Jitter::Random`] outside a test.
    #[doc(hidden)]
    pub jitter: Jitter,
}

impl Default for Redial {
    fn default() -> Redial {
        Redial {
            base: DEFAULT_REDIAL_BASE,
            factor: DEFAULT_REDIAL_FACTOR,
            cap: DEFAULT_REDIAL_CAP,
            steady_up: DEFAULT_REDIAL_STEADY_UP,
            jitter: Jitter::Random,
        }
    }
}

impl Redial {
    /// Fills a zero bound in with its default, as the pool's other options do.
    ///
    /// macula's own refusal set (macula-go `pool/redial.go`, the Go step of
    /// macula#201) takes out a non-positive base, cap or steady-up and a
    /// factor below 1, after filling the zeros the same way. In this crate a
    /// `Duration` cannot be negative and a zero is filled here, so of that set
    /// only the factor is left for the fill to answer: a factor of zero
    /// becomes the default, and one is the smallest a caller may choose —
    /// a schedule that never grows, which `wait` answers with the floor at
    /// every attempt. Nothing else can be refused, so nothing is.
    pub(super) fn filled(mut self) -> Redial {
        let defaults = Redial::default();
        self.base = fill(self.base, defaults.base);
        self.factor = if self.factor == 0 {
            defaults.factor
        } else {
            self.factor
        };
        self.cap = fill(self.cap, defaults.cap);
        self.steady_up = fill(self.steady_up, defaults.steady_up);
        self
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
        self.base + draw(ceiling - self.base, self.jitter)
    }

    /// The undrawn ceiling of the wait after `attempt` failures, never past the
    /// cap and never zero.
    ///
    /// Each step is clamped to the cap: for a factor of two or more a step
    /// that does not grow has passed the cap and every step after it would
    /// only pass it further, and for a factor of one every step is the base.
    /// Clamping is the same as stopping in both.
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

/// Where a wait's jitter lands in the range above the floor.
///
/// [`Jitter::Random`] is the only one a caller should use. The others exist so
/// that a test can place the draw at either end of that range instead of
/// waiting for one, which is what macula-go's `randBelow` is a variable for
/// (`pool/redial.go`, macula#201's Go step).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Jitter {
    /// A draw from the system's randomness: what every pool uses.
    #[default]
    Random,
    /// The bottom of the range, so the wait is exactly the floor.
    Floor,
    /// The top of the range, a nanosecond under the ceiling.
    Ceiling,
}

/// The draw a wait spreads over its range above the floor.
fn draw(bound: Duration, jitter: Jitter) -> Duration {
    match jitter {
        Jitter::Floor => Duration::ZERO,
        Jitter::Ceiling => bound.saturating_sub(Duration::from_nanos(1)),
        Jitter::Random => random_draw(bound),
    }
}

/// A random duration in `0..bound`, and zero when the system's randomness
/// cannot be read (a draw of zero only ever waits the floor).
fn random_draw(bound: Duration) -> Duration {
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
            ..Redial::default()
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
            ..Redial::default()
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
            ..Redial::default()
        };
        assert_eq!(redial.wait(0), redial.base);
        assert_eq!(redial.wait(3), redial.base);
    }

    /// A factor of one is the smallest macula's own refusal set allows
    /// (macula-go `pool/redial.go` refuses below one, not at one): a schedule
    /// that never grows, and every wait is exactly the floor.
    #[test]
    fn a_factor_of_one_never_grows_and_waits_the_floor() {
        let flat = Redial {
            factor: 1,
            ..Redial::default()
        }
        .filled();
        assert_eq!(flat.factor, 1, "the fill leaves a one alone");
        assert_eq!(flat.grown(0), flat.base);
        assert_eq!(flat.grown(9), flat.base);
        assert_eq!(flat.wait(0), flat.base);
        assert_eq!(flat.wait(9), flat.base);
    }

    #[test]
    fn a_zero_bound_takes_its_default() {
        let filled = Redial {
            base: Duration::ZERO,
            factor: 0,
            cap: Duration::ZERO,
            steady_up: Duration::ZERO,
            ..Redial::default()
        }
        .filled();
        assert_eq!(filled, Redial::default());
    }

    /// The two pinned draws a test uses instead of waiting for a random one:
    /// the floor exactly, and a nanosecond under the ceiling.
    #[test]
    fn the_draw_can_be_pinned_to_either_end_of_its_range() {
        let base = Duration::from_millis(100);
        let cap = Duration::from_millis(800);
        let floor = Redial {
            base,
            factor: 2,
            cap,
            jitter: Jitter::Floor,
            ..Redial::default()
        };
        let ceiling = Redial {
            jitter: Jitter::Ceiling,
            ..floor
        };
        assert_eq!(floor.wait(2), base, "the floor draw waits the floor");
        assert_eq!(
            ceiling.wait(2),
            Duration::from_millis(400) - Duration::from_nanos(1),
            "the ceiling draw waits a nanosecond under min(cap, base x factor^2)"
        );
        assert_eq!(
            ceiling.wait(9),
            cap - Duration::from_nanos(1),
            "and a nanosecond under the cap once the growth passes it"
        );
    }
}
