//! Admission of the CALLs a provider node receives, as
//! macula_request_admission judges them: a request runs once, whichever of
//! the node's links it arrives on. Its deadline must lie between the
//! provider's clock minus 5 minutes and plus 10 minutes, and (caller,
//! request_id) must be new; the entry is kept until the deadline plus 5
//! minutes. A copy with the same request hash gets the stored reply, or
//! request_copy while the first still runs; one with another hash is refused.
//! The entries are bounded, and a full bound refuses rather than evicts, in
//! this order: each caller holds at most `caller_quota` entries, each share
//! (one link's place: the station it dialed) at most `share`, and the
//! admission at most `cap`; stored replies take at most `reply_bytes` per
//! caller and `reply_bytes_total` in all. A reply past either is not kept, and
//! a copy of its request is refused reply_not_kept.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::frame::VerifiedRequest;

use super::LinkError;

const DEADLINE_PAST_TOLERANCE_MS: i64 = 5 * 60_000;
const DEADLINE_AHEAD_MAX_MS: i64 = 10 * 60_000;
const KEPT_PAST_DEADLINE_MS: i64 = 5 * 60_000;

/// An admission's bounds. The last four bound the streaming sessions a node
/// serves, as macula_stream_sessions does: sessions at once per caller and in
/// all, and the bytes their inboxes hold per caller and in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    pub caller_quota: usize,
    pub share: usize,
    pub cap: usize,
    pub reply_bytes: usize,
    pub reply_bytes_total: usize,
    pub sessions_per_caller: usize,
    pub sessions: usize,
    pub inbox_bytes_per_caller: usize,
    pub inbox_bytes: usize,
}

impl Default for AdmissionLimits {
    /// macula's defaults, with `cap` one share's worth: the bound of an
    /// admission a single link holds. A pool sets `cap` to `share` times the
    /// most links it holds.
    fn default() -> Self {
        AdmissionLimits {
            caller_quota: 256,
            share: 1024,
            cap: 1024,
            reply_bytes: 256 * 1024,
            reply_bytes_total: 16 * 1024 * 1024,
            sessions_per_caller: 16,
            sessions: 1000,
            inbox_bytes_per_caller: 16 * 1024 * 1024,
            inbox_bytes: 256 * 1024 * 1024,
        }
    }
}

impl AdmissionLimits {
    /// Whether macula would start with these limits: every bound positive,
    /// and each per-caller bound within its total.
    pub fn validate(&self) -> Result<(), LinkError> {
        let l = self;
        let valid = l.caller_quota > 0
            && l.share > 0
            && l.cap > 0
            && l.reply_bytes > 0
            && l.reply_bytes_total > 0
            && l.caller_quota <= l.share
            && l.reply_bytes <= l.reply_bytes_total
            && l.sessions_per_caller > 0
            && l.sessions >= l.sessions_per_caller
            && l.inbox_bytes_per_caller > 0
            && l.inbox_bytes >= l.inbox_bytes_per_caller;
        if valid {
            Ok(())
        } else {
            Err(LinkError::InvalidConfig(
                "admission limits must be positive, each per-caller bound within its total".into(),
            ))
        }
    }
}

/// The admission's judgement of a request: refused with a code, a copy with
/// its stored reply (`None` while the first still runs), or new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    Refused(&'static str),
    Copy(Option<Vec<u8>>),
    New,
}

struct Entry {
    hash: [u8; 48],
    expires_at: i64,
    share: String,
    answered: bool,
    /// `None` when answered but not kept.
    reply: Option<Vec<u8>>,
}

impl Entry {
    /// Judges a copy of the request this entry admitted, by its request hash:
    /// another hash is refused, an answer not kept is refused, and otherwise
    /// the copy gets the stored reply, `None` while the first still runs.
    fn judge_copy(&self, request_hash: &[u8; 48]) -> Verdict {
        if self.hash != *request_hash {
            return Verdict::Refused("request_id_reused");
        }
        if self.answered && self.reply.is_none() {
            return Verdict::Refused("reply_not_kept");
        }
        Verdict::Copy(self.reply.clone())
    }
}

#[derive(Default)]
struct Held {
    entries: HashMap<([u8; 32], [u8; 16]), Entry>,
    callers: HashMap<[u8; 32], usize>,
    shares: HashMap<String, usize>,
    reply_bytes: HashMap<[u8; 32], usize>,
    reply_total: usize,
    sessions: HashMap<[u8; 32], usize>,
    sessions_total: usize,
    inbox: HashMap<[u8; 32], usize>,
    inbox_total: usize,
}

/// One provider node's request admission, shared by all its links.
pub struct Admission {
    limits: AdmissionLimits,
    held: Mutex<Held>,
}

impl Admission {
    /// An empty admission with `limits`, which must validate: a link given
    /// limits that do not is refused at dial.
    pub fn new(limits: AdmissionLimits) -> Admission {
        Admission {
            limits,
            held: Mutex::new(Held::default()),
        }
    }

    /// The admission's bounds.
    pub fn limits(&self) -> AdmissionLimits {
        self.limits
    }

    fn lock(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Judges `request` arriving on `share` at `now_ms`, sweeping the entries
    /// that expired first.
    pub(super) fn admit(&self, request: &VerifiedRequest, share: &str, now_ms: i64) -> Verdict {
        let deadline = request.deadline as i64;
        if deadline < now_ms - DEADLINE_PAST_TOLERANCE_MS {
            return Verdict::Refused("expired");
        }
        if deadline > now_ms + DEADLINE_AHEAD_MAX_MS {
            return Verdict::Refused("not_yet_valid");
        }
        let mut held = self.lock();
        held.sweep(now_ms);
        let key = (request.caller, request.request_id);
        if let Some(entry) = held.entries.get(&key) {
            return entry.judge_copy(&request.request_hash);
        }
        if held.callers.get(&request.caller).copied().unwrap_or(0) >= self.limits.caller_quota {
            return Verdict::Refused("caller_quota");
        }
        if held.shares.get(share).copied().unwrap_or(0) >= self.limits.share {
            return Verdict::Refused("share_full");
        }
        if held.entries.len() >= self.limits.cap {
            return Verdict::Refused("admission_full");
        }
        held.entries.insert(
            key,
            Entry {
                hash: request.request_hash,
                expires_at: deadline + KEPT_PAST_DEADLINE_MS,
                share: share.to_string(),
                answered: false,
                reply: None,
            },
        );
        *held.callers.entry(request.caller).or_default() += 1;
        *held.shares.entry(share.to_string()).or_default() += 1;
        Verdict::New
    }

    /// Keeps the encoded reply of an admitted request for its copies, when
    /// the byte bounds leave room for it.
    pub(super) fn store(&self, request: &VerifiedRequest, reply: Vec<u8>) {
        let mut held = self.lock();
        let held = &mut *held;
        let Some(entry) = held.entries.get_mut(&(request.caller, request.request_id)) else {
            return;
        };
        if entry.answered || entry.hash != request.request_hash {
            return;
        }
        entry.answered = true;
        let caller_bytes = held.reply_bytes.get(&request.caller).copied().unwrap_or(0);
        if caller_bytes + reply.len() > self.limits.reply_bytes
            || held.reply_total + reply.len() > self.limits.reply_bytes_total
        {
            return;
        }
        *held.reply_bytes.entry(request.caller).or_default() += reply.len();
        held.reply_total += reply.len();
        entry.reply = Some(reply);
    }

    /// Takes a streaming session's place for `caller`, or `None` when the
    /// per-caller or node bound is full. Dropping the place gives it back.
    pub(super) fn open_session(self: &Arc<Self>, caller: [u8; 32]) -> Option<SessionPlace> {
        let mut held = self.lock();
        if held.sessions.get(&caller).copied().unwrap_or(0) >= self.limits.sessions_per_caller
            || held.sessions_total >= self.limits.sessions
        {
            return None;
        }
        *held.sessions.entry(caller).or_default() += 1;
        held.sessions_total += 1;
        Some(SessionPlace {
            admission: self.clone(),
            caller,
        })
    }

    /// Counts `n` more bytes that `caller`'s served streams hold unread,
    /// refusing a charge past either bound.
    pub(super) fn charge_inbox(&self, caller: [u8; 32], n: usize) -> bool {
        let mut held = self.lock();
        if held.inbox.get(&caller).copied().unwrap_or(0) + n > self.limits.inbox_bytes_per_caller
            || held.inbox_total + n > self.limits.inbox_bytes
        {
            return false;
        }
        *held.inbox.entry(caller).or_default() += n;
        held.inbox_total += n;
        true
    }

    /// Gives back `n` bytes `caller`'s served streams no longer hold.
    pub(super) fn release_inbox(&self, caller: [u8; 32], n: usize) {
        let mut held = self.lock();
        decrement(&mut held.inbox, caller, n);
        held.inbox_total = held.inbox_total.saturating_sub(n);
    }
}

/// A streaming session's place in the admission, given back when dropped.
pub(super) struct SessionPlace {
    admission: Arc<Admission>,
    caller: [u8; 32],
}

impl Drop for SessionPlace {
    fn drop(&mut self) {
        let mut held = self.admission.lock();
        decrement(&mut held.sessions, self.caller, 1);
        held.sessions_total = held.sessions_total.saturating_sub(1);
    }
}

impl Held {
    /// Removes the entries whose deadline plus 5 minutes passed before
    /// `now_ms`.
    fn sweep(&mut self, now_ms: i64) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at < now_ms)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            self.remove_entry(key);
        }
    }

    /// Removes one entry, giving back its caller's and share's places and
    /// the bytes of its stored reply.
    fn remove_entry(&mut self, key: ([u8; 32], [u8; 16])) {
        let Some(entry) = self.entries.remove(&key) else {
            return;
        };
        decrement(&mut self.callers, key.0, 1);
        decrement(&mut self.shares, entry.share, 1);
        if let Some(reply) = entry.reply {
            decrement(&mut self.reply_bytes, key.0, reply.len());
            self.reply_total = self.reply_total.saturating_sub(reply.len());
        }
    }
}

/// Takes `n` from `m[k]`, dropping the key at zero.
fn decrement<K: Eq + Hash>(m: &mut HashMap<K, usize>, k: K, n: usize) {
    if let Some(v) = m.get_mut(&k) {
        *v = v.saturating_sub(n);
        if *v == 0 {
            m.remove(&k);
        }
    }
}
