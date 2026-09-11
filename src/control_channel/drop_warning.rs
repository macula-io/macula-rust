//! The warnings a session logs when it drops an inbound frame or refuses a
//! stream, bounded per kind: the first drop in an interval is logged at once,
//! and the rest in that interval are counted into one closing line when it
//! ends, so a flood of bad frames can't flood the log. The kinds, reasons and
//! fields are the same in every Macula stack.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::cbor::Value;
use crate::frame;

/// The interval a session starts with.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// How many bytes of a procedure a warning line carries.
const PROCEDURE_LIMIT: usize = 256;

/// What was dropped or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    RefusedStreamOpen,
    DroppedCall,
    DroppedReply,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::RefusedStreamOpen => "refused_stream_open",
            Kind::DroppedCall => "dropped_call",
            Kind::DroppedReply => "dropped_reply",
        }
    }
}

/// Why it was dropped or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A well-formed signature that doesn't verify against the caller the
    /// frame names.
    InvalidSignature,
    /// A signature that's missing or isn't 64 bytes, or a caller that isn't a
    /// 32-byte key.
    Unsigned,
    /// A frame that doesn't parse.
    Malformed,
    /// A dedicated stream whose first frame is of another type.
    NotAStreamOpen,
    /// A RESULT or ERROR for no pending call.
    UnknownCallId,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Reason::InvalidSignature => "invalid_signature",
            Reason::Unsigned => "unsigned",
            Reason::Malformed => "malformed",
            Reason::NotAStreamOpen => "not_a_stream_open",
            Reason::UnknownCallId => "unknown_call_id",
        }
    }
}

/// What a warning line names besides its kind and reason.
#[derive(Debug)]
pub(crate) enum Subject {
    Procedure(String),
    CallId([u8; 16]),
    Nothing,
}

impl Subject {
    fn field(&self) -> String {
        match self {
            Subject::Procedure(procedure) => {
                format!(" procedure={}", printable(truncated(procedure)))
            }
            Subject::CallId(call_id) => format!(" call_id={}", super::hex(&call_id[..4])),
            Subject::Nothing => String::new(),
        }
    }
}

/// The caller `frame` names, when the frame is signed by it: the check macula
/// runs on an inbound CALL or STREAM_OPEN before anything else looks at it.
pub(crate) fn signed_caller(frame: &Value) -> Result<[u8; 32], Reason> {
    let caller = match frame.get("caller") {
        Some(Value::Bytes(bytes)) => {
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Reason::Unsigned)?
        }
        _ => return Err(Reason::Unsigned),
    };
    match frame::verify(frame, &caller) {
        Ok(()) => Ok(caller),
        Err(frame::VerifyError::MissingSignature | frame::VerifyError::BadSignature) => {
            Err(Reason::Unsigned)
        }
        Err(frame::VerifyError::SignatureInvalid) => Err(Reason::InvalidSignature),
    }
}

/// The procedure `frame` names, as a warning line carries it.
pub(crate) fn procedure_of(frame: &Value) -> Subject {
    match frame.get("procedure") {
        Some(Value::Bytes(bytes)) => {
            Subject::Procedure(String::from_utf8_lossy(bytes).into_owned())
        }
        Some(Value::Text(text)) => Subject::Procedure(text.clone()),
        _ => Subject::Nothing,
    }
}

/// A session's drop warnings, one limiter per kind.
pub(crate) struct DropWarnings {
    station: [u8; 32],
    interval: Mutex<Duration>,
    refused_stream_open: Limiter,
    dropped_call: Limiter,
    dropped_reply: Limiter,
}

#[derive(Default)]
struct Limiter(Arc<Mutex<Window>>);

#[derive(Default)]
struct Window {
    /// An interval is running: its first drop was logged at once.
    open: bool,
    /// The drops after that first one, and the latest one's reason and
    /// subject field.
    later: u64,
    latest: Option<(Reason, String)>,
}

impl DropWarnings {
    pub(crate) fn new(station: [u8; 32]) -> Self {
        Self {
            station,
            interval: Mutex::new(DEFAULT_INTERVAL),
            refused_stream_open: Limiter::default(),
            dropped_call: Limiter::default(),
            dropped_reply: Limiter::default(),
        }
    }

    pub(crate) fn interval(&self) -> Duration {
        *lock(&self.interval)
    }

    pub(crate) fn set_interval(&self, interval: Duration) {
        *lock(&self.interval) = interval;
    }

    /// Records one drop of `kind`. The first in an interval is logged at once;
    /// later ones are counted and reported in one line when the interval ends,
    /// and not at all when none came.
    pub(crate) fn record(&self, kind: Kind, reason: Reason, subject: Subject) {
        let limiter = match kind {
            Kind::RefusedStreamOpen => &self.refused_stream_open,
            Kind::DroppedCall => &self.dropped_call,
            Kind::DroppedReply => &self.dropped_reply,
        };
        let field = subject.field();
        {
            let mut window = lock(&limiter.0);
            if window.open {
                window.later += 1;
                window.latest = Some((reason, field));
                return;
            }
            window.open = true;
        }
        log_line(self.station, kind, 1, reason, &field);
        let (window, interval, station) = (limiter.0.clone(), self.interval(), self.station);
        let close = async move {
            tokio::time::sleep(interval).await;
            let (later, latest) = {
                let mut window = lock(&window);
                window.open = false;
                (std::mem::take(&mut window.later), window.latest.take())
            };
            if let Some((reason, field)) = latest.filter(|_| later > 0) {
                log_line(station, kind, later, reason, &field);
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(close);
            }
            // With no runtime to end the interval, every drop gets its own line.
            Err(_) => lock(&limiter.0).open = false,
        }
    }
}

fn log_line(station: [u8; 32], kind: Kind, count: u64, reason: Reason, field: &str) {
    log::warn!(
        "macula: kind={} count={count} reason={}{field} (station {})",
        kind.name(),
        reason.name(),
        super::hex(&station)
    );
}

/// `procedure` cut to [`PROCEDURE_LIMIT`] bytes, on a character boundary.
fn truncated(procedure: &str) -> &str {
    let mut end = procedure.len().min(PROCEDURE_LIMIT);
    while !procedure.is_char_boundary(end) {
        end -= 1;
    }
    &procedure[..end]
}

/// `text` with its control characters escaped, `\n`, `\r` and `\t` by name
/// and any other as `\u{..}`, so a warning line never breaks.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

// A panic elsewhere while a lock was held leaves the counts usable.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    //! The shared drop warning tests. The names match the Go, .NET and
    //! Erlang tests.
    use super::*;
    use crate::control_channel::fake_station::{capture_logs, logged_about};

    const SHORT: Duration = Duration::from_millis(100);

    fn warnings() -> DropWarnings {
        let warnings = DropWarnings::new(rand::random());
        warnings.set_interval(SHORT);
        warnings
    }

    #[tokio::test]
    async fn a_drop_burst_logs_one_immediate_line_and_one_closing_line_with_the_rest() {
        capture_logs();
        let warnings = warnings();

        for n in 0..5 {
            warnings.record(
                Kind::RefusedStreamOpen,
                Reason::InvalidSignature,
                Subject::Procedure(format!("app/stream_{n}")),
            );
        }
        let immediate = logged_about(&warnings.station);
        tokio::time::sleep(SHORT * 3).await;
        let lines = logged_about(&warnings.station);

        assert_eq!(immediate.len(), 1, "{immediate:?}");
        assert!(
            immediate[0].1.contains(
                "kind=refused_stream_open count=1 reason=invalid_signature procedure=app/stream_0"
            ),
            "{immediate:?}"
        );
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[1].1.contains(
                "kind=refused_stream_open count=4 reason=invalid_signature procedure=app/stream_4"
            ),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_single_drop_logs_only_the_immediate_line() {
        capture_logs();
        let warnings = warnings();

        warnings.record(
            Kind::DroppedReply,
            Reason::UnknownCallId,
            Subject::CallId([0xab; 16]),
        );
        tokio::time::sleep(SHORT * 3).await;
        let lines = logged_about(&warnings.station);

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0]
                .1
                .contains("kind=dropped_reply count=1 reason=unknown_call_id call_id=abababab"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_procedure_with_a_newline_stays_on_one_log_line() {
        capture_logs();
        let warnings = warnings();

        warnings.record(
            Kind::DroppedCall,
            Reason::InvalidSignature,
            Subject::Procedure("app/a\nkind=forged\u{1b}".to_string()),
        );
        let lines = logged_about(&warnings.station);

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(!lines[0].1.contains('\n'), "{lines:?}");
        assert!(
            lines[0].1.contains("procedure=app/a\\nkind=forged\\u{1b}"),
            "{lines:?}"
        );
    }

    #[test]
    fn a_procedure_is_cut_on_a_character_boundary() {
        let procedure = format!("{}é", "a".repeat(PROCEDURE_LIMIT - 1));

        assert_eq!(truncated(&procedure), "a".repeat(PROCEDURE_LIMIT - 1));
    }
}
