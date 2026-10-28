//! Sealed groups (macula 13.2,
//! `docs/design/DESIGN_E2E_SEALED_PUBSUB.md`): a group is a topic prefix whose
//! events are sealed under the group's current epoch key, which the org's
//! distributor hands out over a sealed call, `<org>/group_keys_v1`, to members
//! holding the org's grant. This is the Rust counterpart of macula's
//! `macula_group_epoch`, `macula_group_event`, `macula_group_keyring` and
//! `macula_group_keys`: epochs and their times, sealing and opening an event,
//! the pull's payloads, the keyring a node holds its groups' epochs in, and the
//! distributor that serves them. Epoch keys are held in memory only, erased as
//! soon as no event under them can be accepted any more — on the distributor's
//! own clock, not at the group's next pull — and never printed.
//!
//! [`Keyring`] is the member side, behind [`Pool::join_group`], and
//! [`Distributor`] is the other half, served through [`Pool::serve`] with
//! [`Distributor::offer`].
//!
//! [`Pool::join_group`]: crate::pool::Pool::join_group
//! [`Pool::serve`]: crate::pool::Pool::serve

use std::error::Error;
use std::fmt;

mod distributor;
mod epoch;
mod event;
mod keyring;
mod wire;

pub use distributor::{
    chain_bound, Caps, Distributor, DistributorOptions, Membership, MembershipCheck,
    MembershipFuture, Misconfigured, RemovedCheck, DEFAULT_MEMBERSHIP_TIMEOUT, GROUP_KEYS_CAN,
    MAX_LOOKUPS, MAX_LOOKUPS_PER_CALLER, MAX_ROTATE_AFTER_MS,
};
pub use epoch::{
    for_publish, org_of, retain_live, under, Epoch, NoRandomness, NotAGroup,
    DEFAULT_ROTATE_AFTER_MS, EVENT_LIFE_MS, ID_SIZE, KEY_SIZE, TOLERANCE_MS,
};
pub use event::{open_event, seal_event, Fields};
pub use keyring::{JoinOptions, Keyring, Options, Pull, PullError, Puller};
#[cfg(test)]
pub(crate) use wire::reply_value;
pub use wire::{by_id_request, current_request, parse_reply, procedure, Policy, Reply};

/// The sealed group a publish or a subscribe is under: its prefix, which the
/// topic must be under and whose second segment is its org; the org's grant,
/// a UCAN carrying `can` `group_keys`, presented on every key pull; and the
/// distributor's node id when it must be that node.
#[derive(Debug, Clone, Default)]
pub struct Group {
    pub prefix: String,
    pub ucan: Vec<u8>,
    pub distributor: Option<[u8; 32]>,
}

impl Group {
    /// The join this group is made with.
    pub fn join_options(&self) -> JoinOptions {
        JoinOptions {
            ucan: self.ucan.clone(),
            distributor: self.distributor,
        }
    }

    /// Checks the group against its topic before anything is sent: a prefix
    /// that is not a group's, or a topic not under it, is refused here rather
    /// than sealed under the wrong group.
    pub fn covering(&self, topic: &str) -> Result<(), GroupError> {
        org_of(&self.prefix)?;
        if !under(topic, &self.prefix) {
            return Err(GroupError::TopicNotUnder {
                topic: topic.to_string(),
                prefix: self.prefix.clone(),
            });
        }
        Ok(())
    }
}

/// Why a group's key could not be had, or an event could not be opened: the
/// closed set every SDK names (DESIGN_E2E_SEALED_PUBSUB.md section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The distributor's membership says this node is not in the group, or
    /// the app has removed it.
    NotAMember,
    /// The distributor could not read this node's membership.
    MembershipUnknown,
    /// The distributor does not know the epoch asked for.
    UnknownEpoch,
    /// The epoch exists but is past the last moment an event under it is
    /// accepted.
    EpochExpired,
    /// No trusted distributor answers for the group, or its reply is not the
    /// protocol's.
    NoDistributor,
    /// The group is not one this node holds.
    NoGroup,
    /// A sealed event does not open under the epoch it names: another epoch's
    /// key, a routing field other than the one it was sealed with, or a
    /// changed byte.
    TagInvalid,
}

impl Reason {
    /// The reason as the design names it.
    pub fn name(self) -> &'static str {
        match self {
            Reason::NotAMember => "not_a_member",
            Reason::MembershipUnknown => "membership_unknown",
            Reason::UnknownEpoch => "unknown_epoch",
            Reason::EpochExpired => "epoch_expired",
            Reason::NoDistributor => "no_distributor",
            Reason::NoGroup => "no_group",
            Reason::TagInvalid => "tag_invalid",
        }
    }

    /// The reason a distributor's refusal names, when it names one it
    /// details: a provider error of code `handler_error` carries one of the
    /// design's reasons as its detail.
    pub fn from_refusal(detail: &str) -> Option<Reason> {
        match detail {
            "not_a_member" => Some(Reason::NotAMember),
            "membership_unknown" => Some(Reason::MembershipUnknown),
            "unknown_epoch" => Some(Reason::UnknownEpoch),
            "epoch_expired" => Some(Reason::EpochExpired),
            // A prefix another org owns is the distributor's to refuse, and to
            // a member it is no distributor of its group.
            "unknown_group" => Some(Reason::NoDistributor),
            _ => None,
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What went wrong with a group's key or an event: one of the design's
/// reasons, or one of the local conditions that is not a distributor's
/// refusal.
#[derive(Debug)]
pub enum GroupError {
    /// The prefix cannot be a group.
    NotAGroup,
    /// A publish, an open or a policy read under a group this keyring does
    /// not hold.
    NotJoined,
    /// The distributor's reply is not `group_keys_v1`'s. Nothing of it is
    /// held.
    MalformedReply,
    /// An event could not be sealed: a payload the wire cannot carry, or a
    /// primitive that failed. Nothing was published.
    NotSealed(Cause),
    /// A topic that is not under the group's prefix, or a prefix that is not
    /// a group's.
    TopicNotUnder { topic: String, prefix: String },
    /// The pool could not carry it: no link to publish on, a closed pool, or
    /// a subscription the station refused.
    Pool(Cause),
    /// A refusal or a failure by its reason, with whatever caused it.
    Refused {
        reason: Reason,
        cause: Option<Cause>,
    },
}

/// What caused a group error, when something did.
pub type Cause = Box<dyn Error + Send + Sync + 'static>;

impl GroupError {
    /// A refusal by its reason, with nothing under it.
    pub(crate) fn of(reason: Reason) -> Self {
        GroupError::Refused {
            reason,
            cause: None,
        }
    }

    /// A refusal by its reason, caused by `cause`.
    pub(crate) fn caused_by(reason: Reason, cause: impl Error + Send + Sync + 'static) -> Self {
        GroupError::Refused {
            reason,
            cause: Some(Box::new(cause)),
        }
    }

    /// The reason, when this is one of the design's.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            GroupError::Refused { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// Whether this is a refusal of `reason`.
    pub fn is(&self, reason: Reason) -> bool {
        self.reason() == Some(reason)
    }
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupError::NotAGroup => write!(f, "group: not a group prefix"),
            GroupError::NotJoined => f.write_str("group: the group is not joined"),
            GroupError::MalformedReply => {
                f.write_str("group: the distributor's reply is not group_keys_v1's")
            }
            GroupError::NotSealed(cause) => write!(f, "group: the event was not sealed: {cause}"),
            GroupError::TopicNotUnder { topic, prefix } => {
                write!(f, "group: the topic {topic:?} is not under {prefix:?}")
            }
            GroupError::Pool(cause) => write!(f, "group: {cause}"),
            GroupError::Refused { reason, cause } => match cause {
                Some(cause) => write!(f, "group: {reason}: {cause}"),
                None => write!(f, "group: {reason}"),
            },
        }
    }
}

impl Error for GroupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            GroupError::NotSealed(cause) | GroupError::Pool(cause) => Some(cause.as_ref()),
            GroupError::Refused {
                cause: Some(cause), ..
            } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

impl From<NotAGroup> for GroupError {
    fn from(_: NotAGroup) -> Self {
        GroupError::NotAGroup
    }
}

#[cfg(test)]
mod vectors;

#[cfg(test)]
mod tests {
    use super::*;

    /// The closed set is exactly the design's names, and the distributor's
    /// five refusal details map onto it.
    #[test]
    fn the_reasons_are_the_design_s_closed_set() {
        let all = [
            Reason::NotAMember,
            Reason::MembershipUnknown,
            Reason::UnknownEpoch,
            Reason::EpochExpired,
            Reason::NoDistributor,
            Reason::NoGroup,
            Reason::TagInvalid,
        ];
        let names: Vec<&str> = all.iter().map(|r| r.name()).collect();
        assert_eq!(
            names,
            [
                "not_a_member",
                "membership_unknown",
                "unknown_epoch",
                "epoch_expired",
                "no_distributor",
                "no_group",
                "tag_invalid"
            ]
        );
        for refusal in [
            "not_a_member",
            "membership_unknown",
            "unknown_epoch",
            "epoch_expired",
        ] {
            assert_eq!(
                Reason::from_refusal(refusal).map(Reason::name),
                Some(refusal)
            );
        }
        assert_eq!(
            Reason::from_refusal("unknown_group"),
            Some(Reason::NoDistributor)
        );
        assert_eq!(Reason::from_refusal("something_else"), None);
    }

    /// A refusal reads as its reason, and carries what caused it.
    #[test]
    fn a_refusal_reads_as_its_reason() {
        let plain = GroupError::of(Reason::NotAMember);
        assert!(plain.is(Reason::NotAMember));
        assert!(!plain.is(Reason::UnknownEpoch));
        assert_eq!(plain.to_string(), "group: not_a_member");

        let caused = GroupError::caused_by(Reason::NoDistributor, NotAGroup);
        assert_eq!(
            caused.to_string(),
            "group: no_distributor: not a group prefix (realm/org/..., no empty segment)"
        );
        assert!(caused.source().is_some(), "the cause is reachable");

        assert_eq!(GroupError::NotJoined.reason(), None);
    }
}
