//! What a subscription delivers: its events, and a notice when it may have
//! missed some (macula-station#129, phase 1).
//!
//! A subscription runs on every link the pool holds. A link *covers* it from
//! the moment its station accepted the SUBSCRIBE until the link ends, and
//! whatever the station wrote to a link that ended is gone with it. While
//! another link still covers the subscription nothing is missed: that link
//! carried every event. When the last covering link ends, the subscription
//! is told so, once, with [`Delivery::Interrupted`]; when a station accepts
//! it again, once more with [`Delivery::Gap`], before any event that link
//! hears. An outage a link survives raises nothing: QUIC retransmits and
//! nothing is lost.

use std::collections::HashSet;

use crate::station_link::Event;

/// One item a subscription delivers, in the order it delivers them.
#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    /// An event the subscription heard, once, whichever links heard it.
    Event(Event),
    /// No link carries the subscription any more: events published from
    /// `from_ms` on may be missed until a [`Delivery::Gap`] follows.
    Interrupted(Interruption),
    /// A link carries the subscription again: events published between
    /// `from_ms` and `to_ms` may have been missed, so resync it.
    Gap(Gap),
}

/// The last link carrying a subscription ended.
///
/// `from_ms` is when that link (or, of several that ended, the latest) last
/// heard from its station, on this node's clock; `reason` is why it ended, as
/// [`LinkError::end_reason`](crate::station_link::LinkError::end_reason)
/// names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interruption {
    pub from_ms: u64,
    pub reason: String,
}

/// A subscription that was interrupted is carried again.
///
/// `from_ms` and `reason` are its [`Interruption`]'s; `to_ms` is when a
/// station accepted it again, on this node's clock. The times are hints: an
/// event's `published_at` is its publisher's clock, so answer a gap by
/// resyncing the subscription, never by dropping events whose
/// `published_at` falls outside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub from_ms: u64,
    pub to_ms: u64,
    pub reason: String,
}

/// The links that cover a subscription, by serial, and the notice it is owed
/// as that set empties and fills again.
#[derive(Debug, Default)]
pub(super) struct Coverage {
    links: HashSet<u64>,
    /// The latest time a link that ended last heard from its station, since
    /// the set last filled again.
    heard: u64,
    interrupted: Option<Interruption>,
}

impl Coverage {
    /// The link `serial` covers the subscription from `now_ms`: the
    /// [`Delivery::Gap`] owed when that fills a set a link's end emptied.
    pub(super) fn covers(&mut self, serial: u64, now_ms: u64) -> Option<Delivery> {
        self.links.insert(serial);
        let interruption = self.interrupted.take()?;
        self.heard = 0;
        Some(Delivery::Gap(Gap {
            from_ms: interruption.from_ms,
            to_ms: now_ms,
            reason: interruption.reason,
        }))
    }

    /// The link `serial` ended, having last heard from its station at
    /// `heard_ms`, for `reason`: the [`Delivery::Interrupted`] owed when that
    /// empties the set. A link that did not cover the subscription changes
    /// nothing.
    pub(super) fn ended(&mut self, serial: u64, heard_ms: u64, reason: &str) -> Option<Delivery> {
        if !self.links.remove(&serial) {
            return None;
        }
        self.heard = self.heard.max(heard_ms);
        if !self.links.is_empty() {
            return None;
        }
        let interruption = Interruption {
            from_ms: self.heard,
            reason: reason.to_string(),
        };
        self.interrupted = Some(interruption.clone());
        Some(Delivery::Interrupted(interruption))
    }

    /// The subscription ended on the link `serial` while the link went on:
    /// the link no longer covers it, and no link end is there to report.
    pub(super) fn left(&mut self, serial: u64) {
        self.links.remove(&serial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interrupted(d: Option<Delivery>) -> Interruption {
        match d {
            Some(Delivery::Interrupted(i)) => i,
            other => panic!("not an Interrupted: {other:?}"),
        }
    }

    fn gap(d: Option<Delivery>) -> Gap {
        match d {
            Some(Delivery::Gap(g)) => g,
            other => panic!("not a Gap: {other:?}"),
        }
    }

    #[test]
    fn the_first_cover_owes_nothing() {
        let mut c = Coverage::default();
        assert_eq!(c.covers(1, 100), None);
        assert_eq!(c.covers(2, 200), None);
    }

    #[test]
    fn the_last_link_ending_owes_one_interrupted_then_one_gap() {
        let mut c = Coverage::default();
        c.covers(1, 100);
        let i = interrupted(c.ended(1, 500, "liveness_lost"));
        assert_eq!((i.from_ms, i.reason.as_str()), (500, "liveness_lost"));
        let g = gap(c.covers(2, 900));
        assert_eq!(
            (g.from_ms, g.to_ms, g.reason.as_str()),
            (500, 900, "liveness_lost")
        );
        assert_eq!(c.covers(3, 950), None, "a second link back adds nothing");
    }

    #[test]
    fn a_link_ending_while_another_covers_owes_nothing() {
        let mut c = Coverage::default();
        c.covers(1, 100);
        c.covers(2, 100);
        assert_eq!(c.ended(1, 500, "liveness_lost"), None);
        assert_eq!(c.covers(3, 600), None);
    }

    #[test]
    fn links_ending_together_report_the_latest_heard_and_the_last_reason() {
        let mut c = Coverage::default();
        c.covers(1, 100);
        c.covers(2, 100);
        assert_eq!(c.ended(1, 500, "liveness_lost"), None);
        let i = interrupted(c.ended(2, 400, "closed_by_station"));
        assert_eq!((i.from_ms, i.reason.as_str()), (500, "closed_by_station"));
    }

    #[test]
    fn the_latest_heard_resets_once_the_set_fills_again() {
        let mut c = Coverage::default();
        c.covers(1, 100);
        c.ended(1, 900, "liveness_lost");
        c.covers(2, 1000);
        let i = interrupted(c.ended(2, 300, "goodbye"));
        assert_eq!(i.from_ms, 300);
    }

    #[test]
    fn a_link_that_never_covered_changes_nothing() {
        let mut c = Coverage::default();
        assert_eq!(c.ended(1, 500, "liveness_lost"), None);
        c.covers(2, 100);
        assert_eq!(c.ended(1, 500, "liveness_lost"), None);
        assert!(c.ended(2, 600, "closed").is_some());
    }

    #[test]
    fn a_subscription_that_left_its_link_is_not_a_link_end() {
        let mut c = Coverage::default();
        c.covers(1, 100);
        c.left(1);
        assert_eq!(c.ended(1, 500, "liveness_lost"), None);
        assert_eq!(c.covers(2, 600), None);
    }
}
