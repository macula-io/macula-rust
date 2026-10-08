//! A caller's seal report (macula's DESIGN_E2E_SEAL_REPORT): whether the
//! exchange that produced a result was sealed, and to which key. It states
//! that sealing ran on that exchange, nothing more: not that the provider
//! keeps the payload secret, not that the key is uncompromised.

use std::fmt;

use crate::seal::KEY_ID_SIZE;

use super::Stream;

/// A caller's seal report on one exchange, with the three fields every SDK
/// names alike (macula's `sealed`, `provider`, `seal_key_id`). `sealed` is 1
/// when the request that produced the result was sealed and its answer opened
/// under the same key, whose id `seal_key_id` names, and 0, with no key id,
/// for a clear exchange. `provider` is the node the request was addressed
/// to: for a sealed result also the one whose answer opened, for a clear one
/// the target and no claim about who answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub sealed: u8,
    pub provider: [u8; 32],
    pub seal_key_id: Option<[u8; KEY_ID_SIZE]>,
}

impl Report {
    /// The report on an exchange with `provider`: sealed to `key_id`, or
    /// clear when it is `None`.
    pub(crate) fn of(provider: [u8; 32], key_id: Option<[u8; KEY_ID_SIZE]>) -> Report {
        Report {
            sealed: u8::from(key_id.is_some()),
            provider,
            seal_key_id: key_id,
        }
    }
}

/// Why a stream has no seal report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// The provider has sent no data or reply opened under the stream's key
    /// (on a clear stream, no data, reply or end), or the stream ended
    /// first, an error included.
    NotSettled,
    /// A served stream: the report is the caller's evidence, and the
    /// provider side has none.
    NotACaller,
}

impl ReportError {
    /// The error as macula and libmacula name it.
    pub fn name(self) -> &'static str {
        match self {
            ReportError::NotSettled => "not_settled",
            ReportError::NotACaller => "not_a_caller",
        }
    }
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for ReportError {}

impl Stream {
    /// This caller stream's seal report. It settles on the provider's first
    /// STREAM_DATA or STREAM_REPLY opened under the stream's key; on a clear
    /// stream, on its first STREAM_DATA, STREAM_REPLY or STREAM_END. A sealed
    /// stream's STREAM_END travels clear and settles nothing, and no error
    /// settles a stream. Before it settles, and on a stream that ended
    /// first, it is [`ReportError::NotSettled`]; on a served stream,
    /// [`ReportError::NotACaller`]. A stream that settled and then ended, an
    /// error included, keeps its report. A stream resealed after its
    /// provider's key rotated reports the key it reopened under.
    pub fn report(&self) -> Result<Report, ReportError> {
        let inner = self.current();
        if !inner.caller {
            return Err(ReportError::NotACaller);
        }
        if !inner.side().settled {
            return Err(ReportError::NotSettled);
        }
        let key_id = inner.sealing.as_ref().map(|s| s.key_id());
        Ok(Report::of(inner.open.target, key_id))
    }
}
