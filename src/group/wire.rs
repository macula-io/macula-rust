//! The distributor's protocol, `group_keys_v1`: the CALL payloads a member
//! pulls with, and the RESULT a distributor answers with. Both are pinned
//! byte for byte by macula's `e2e_seal_v1_group_keys.json`, so they are built
//! and read here exactly as macula's `macula_group_keyring` does.

use crate::cbor::Value;

use super::{Epoch, GroupError, EVENT_LIFE_MS, ID_SIZE, KEY_SIZE};

/// A group's policy as its distributor answers it: required refuses clear
/// events under the prefix, preferred seals and accepts clear ones, off
/// accepts clear events too. Once a node has seen preferred or required for a
/// prefix it never accepts off for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Required,
    Preferred,
    Off,
}

impl Policy {
    /// The policy as the wire names it.
    pub fn name(self) -> &'static str {
        match self {
            Policy::Required => "required",
            Policy::Preferred => "preferred",
            Policy::Off => "off",
        }
    }

    /// The policy a distributor's reply names, `None` for a name that is not
    /// one of the three.
    pub fn parse(name: &str) -> Option<Policy> {
        match name {
            "required" => Some(Policy::Required),
            "preferred" => Some(Policy::Preferred),
            "off" => Some(Policy::Off),
            _ => None,
        }
    }

    /// The policy to hold after a reply answered `self`, given the `held` one:
    /// monotonic, so off never lowers a preferred or a required already seen.
    pub fn following(self, held: Option<Policy>) -> Policy {
        match (self, held) {
            (Policy::Off, Some(seen)) if seen != Policy::Off => seen,
            _ => self,
        }
    }
}

/// The distributor's procedure for an org's groups.
pub fn procedure(org: &str) -> String {
    format!("{org}/group_keys_v1")
}

/// The pull of a group's current epoch: the CALL payload
/// `{prefix, epoch: "current"}`.
pub fn current_request(prefix: &str) -> Value {
    request(prefix, Value::text("current"))
}

/// The pull of a group's epoch by id: the CALL payload
/// `{prefix, epoch: <8 bytes>}`.
pub fn by_id_request(prefix: &str, id: &[u8; ID_SIZE]) -> Value {
    request(prefix, Value::Bytes(id.to_vec()))
}

fn request(prefix: &str, epoch: Value) -> Value {
    Value::Map(vec![
        (Value::text("prefix"), Value::text(prefix)),
        (Value::text("epoch"), epoch),
    ])
}

/// A distributor's answer to a pull: the policy and the epochs it handed out,
/// the asked one and the next inside the ahead window.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub prefix: String,
    pub policy: Policy,
    pub epochs: Vec<Epoch>,
}

/// Reads a distributor's RESULT for a pull of `prefix`, as macula's
/// `macula_group_keyring` reads one. A reply that is not the protocol's, in
/// any part, is refused whole: nothing of it is held.
pub fn parse_reply(prefix: &str, v: &Value) -> Result<Reply, GroupError> {
    match text(v, "prefix") {
        Some(echoed) if echoed == prefix => {}
        _ => return Err(GroupError::MalformedReply),
    }
    let policy = text(v, "policy")
        .and_then(|p| Policy::parse(&p))
        .ok_or(GroupError::MalformedReply)?;
    let list = v.get("epochs").ok_or(GroupError::MalformedReply)?;
    let Value::List(items) = list else {
        return Err(GroupError::MalformedReply);
    };
    if items.is_empty() {
        return Err(GroupError::MalformedReply);
    }
    let mut epochs = Vec::with_capacity(items.len());
    for item in items {
        epochs.push(epoch_of(item).ok_or(GroupError::MalformedReply)?);
    }
    Ok(Reply {
        prefix: prefix.to_string(),
        policy,
        epochs,
    })
}

/// The RESULT payload for `r`, as a distributor answers it and as the vectors
/// pin it. Only a distributor builds one, and this crate serves none: it is
/// here for the vectors and the tests that hold this crate to them, which is
/// why it is not public.
#[cfg(test)]
pub(crate) fn reply_value(r: &Reply) -> Value {
    let epochs = r
        .epochs
        .iter()
        .map(|e| {
            Value::Map(vec![
                (Value::text("id"), Value::Bytes(e.id.to_vec())),
                (Value::text("key"), Value::Bytes(e.key().to_vec())),
                (
                    Value::text("issued_at"),
                    Value::Int(i128::from(e.issued_at)),
                ),
                (
                    Value::text("publish_until"),
                    Value::Int(i128::from(e.publish_until)),
                ),
                (
                    Value::text("accept_until"),
                    Value::Int(i128::from(e.accept_until)),
                ),
            ])
        })
        .collect();
    Value::Map(vec![
        (Value::text("prefix"), Value::text(r.prefix.clone())),
        (Value::text("policy"), Value::text(r.policy.name())),
        (Value::text("epochs"), Value::List(epochs)),
    ])
}

/// Reads one epoch: an 8-byte id, a 32-byte key, and times where it is issued
/// before it stops publishing and is accepted exactly the life of an event
/// past that.
fn epoch_of(v: &Value) -> Option<Epoch> {
    let id = fixed::<ID_SIZE>(v, "id")?;
    let key = fixed::<KEY_SIZE>(v, "key")?;
    let issued_at = integer(v, "issued_at")?;
    let publish_until = integer(v, "publish_until")?;
    let accept_until = integer(v, "accept_until")?;
    if issued_at >= publish_until || accept_until != publish_until + EVENT_LIFE_MS {
        return None;
    }
    Some(Epoch::new(id, key, issued_at, publish_until, accept_until))
}

/// Wipes every byte string a reply carries: an epoch key travels as one, and
/// the value the reply arrived in outlives the epochs read out of it.
pub(crate) fn zeroize_reply(v: &mut Value) {
    match v {
        Value::Bytes(bytes) => bytes.fill(0),
        Value::List(items) => items.iter_mut().for_each(zeroize_reply),
        Value::Map(pairs) => pairs.iter_mut().for_each(|(key, value)| {
            zeroize_reply(key);
            zeroize_reply(value);
        }),
        _ => {}
    }
}

fn text(v: &Value, name: &str) -> Option<String> {
    match v.get(name) {
        Some(Value::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

/// An integer of the protocol's: present, and never negative.
fn integer(v: &Value, name: &str) -> Option<i64> {
    match v.get(name) {
        Some(Value::Int(n)) if *n >= 0 && *n <= i128::from(i64::MAX) => Some(*n as i64),
        _ => None,
    }
}

/// A byte string of exactly `N` bytes, which is how an epoch's id and key are
/// carried.
fn fixed<const N: usize>(v: &Value, name: &str) -> Option<[u8; N]> {
    match v.get(name) {
        Some(Value::Bytes(b)) if b.len() == N => b.as_slice().try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "io.macula/acme/chat";

    /// An epoch of the protocol's: it is issued, publishes for a rotation,
    /// and is accepted exactly the life of an event past that.
    fn epoch(id: u8) -> Epoch {
        let issued_at = 1_000;
        let publish_until = issued_at + 15 * 60_000;
        Epoch::new(
            [id; ID_SIZE],
            [id.wrapping_add(1); KEY_SIZE],
            issued_at,
            publish_until,
            publish_until + EVENT_LIFE_MS,
        )
    }

    fn a_reply() -> Reply {
        Reply {
            prefix: PREFIX.into(),
            policy: Policy::Required,
            epochs: vec![epoch(1), epoch(2)],
        }
    }

    /// A reply's pairs, to be bent out of shape one field at a time.
    fn pairs_of(v: &Value) -> Vec<(Value, Value)> {
        match v {
            Value::Map(pairs) => pairs.clone(),
            _ => unreachable!("a reply is a map"),
        }
    }

    /// Sets `field` on a reply's pairs, replacing it where it is there.
    fn set(pairs: &mut Vec<(Value, Value)>, field: &str, value: Value) {
        pairs.retain(|(key, _)| key != &Value::text(field));
        pairs.push((Value::text(field), value));
    }

    fn is_malformed(reply: &Value) -> bool {
        matches!(parse_reply(PREFIX, reply), Err(GroupError::MalformedReply))
    }

    /// A reply of the protocol's reads back, and re-encodes to the same
    /// bytes: the round trip the vectors assert.
    #[test]
    fn a_reply_reads_and_re_encodes_as_it_arrived() {
        let reply = a_reply();
        let encoded = crate::cbor::encode(&reply_value(&reply)).unwrap();
        let decoded = crate::cbor::decode(&encoded).unwrap();
        assert_eq!(parse_reply(PREFIX, &decoded).ok(), Some(reply));
        let parsed = parse_reply(PREFIX, &decoded).unwrap();
        assert_eq!(crate::cbor::encode(&reply_value(&parsed)).unwrap(), encoded);
    }

    /// A reply that is not the protocol's is refused whole: another prefix
    /// echoed, a policy that is not one of the three, and epochs that are not
    /// a non-empty list.
    #[test]
    fn a_reply_off_the_protocol_is_refused_whole() {
        let base = reply_value(&a_reply());
        assert!(parse_reply(PREFIX, &base).is_ok());
        let bent: [(&str, Value); 5] = [
            ("prefix", Value::text("io.macula/other/chat")),
            ("policy", Value::text("sometimes")),
            ("policy", Value::Int(1)),
            ("epochs", Value::List(Vec::new())),
            ("epochs", Value::text("none")),
        ];
        for (field, value) in bent {
            let mut pairs = pairs_of(&base);
            set(&mut pairs, field, value.clone());
            assert!(
                is_malformed(&Value::Map(pairs)),
                "a reply whose {field} is {value:?}"
            );
        }
    }

    /// An epoch that is not the protocol's refuses the whole reply: a short
    /// id or key, a negative time, and times that contradict one another.
    #[test]
    fn an_epoch_off_the_protocol_refuses_the_whole_reply() {
        let base = reply_value(&a_reply());
        let epochs = pairs_of(&base)
            .into_iter()
            .find(|(key, _)| key == &Value::text("epochs"))
            .map(|(_, value)| value)
            .expect("a reply carries epochs");
        let Value::List(one) = epochs else {
            unreachable!("epochs is a list")
        };
        let an_epoch = one[0].clone();
        let bent: [(&str, Value); 6] = [
            ("id", Value::Bytes(vec![1; ID_SIZE - 1])),
            ("key", Value::Bytes(vec![1; KEY_SIZE - 1])),
            ("issued_at", Value::Int(-1)),
            ("issued_at", Value::text("soon")),
            ("publish_until", Value::Int(999)),
            ("accept_until", Value::Int(0)),
        ];
        for (field, value) in bent {
            let mut epoch_pairs = pairs_of(&an_epoch);
            set(&mut epoch_pairs, field, value.clone());
            let mut pairs = pairs_of(&base);
            set(
                &mut pairs,
                "epochs",
                Value::List(vec![Value::Map(epoch_pairs)]),
            );
            assert!(
                is_malformed(&Value::Map(pairs)),
                "a reply whose epoch's {field} is {value:?}"
            );
        }
    }

    /// The policy never falls back to off once a preferred or a required has
    /// been seen for a prefix.
    #[test]
    fn the_policy_is_monotonic() {
        assert_eq!(Policy::Required.following(None), Policy::Required);
        assert_eq!(Policy::Off.following(None), Policy::Off);
        assert_eq!(
            Policy::Off.following(Some(Policy::Preferred)),
            Policy::Preferred
        );
        assert_eq!(
            Policy::Off.following(Some(Policy::Required)),
            Policy::Required
        );
        assert_eq!(Policy::Off.following(Some(Policy::Off)), Policy::Off);
        assert_eq!(
            Policy::Preferred.following(Some(Policy::Required)),
            Policy::Preferred,
            "a preferred after a required is the distributor's answer"
        );
    }
}
