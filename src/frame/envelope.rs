//! Wire 1.0's frame envelope (WIRE_1_0.md section 3, macula#99): every frame,
//! of every type, carries version 5 and a frame_type of 1 to 64 bytes, and its
//! other envelope keys only where it has a value for them. Additions arrive in
//! `ext`, never as new core fields; an unknown frame type is read past.

use crate::cbor::Value;

use super::wire_counters::{count_ext_ignored, count_ext_refused, count_unknown_frame_type};
use super::{protocol_uint, FrameError, PROTOCOL_VERSION};

/// The bounds of a frame_type, an extension name and an `ext` map.
pub const MAX_FRAME_TYPE_BYTES: usize = 64;
pub const MAX_EXTENSION_NAME_BYTES: usize = 64;
pub const MAX_EXTENSIONS: usize = 16;

/// The QUIC application code a dedicated stream is aborted with when its
/// frame is of a type the receiver does not know (WIRE_1_0.md section 3.3),
/// distinct from 3, "did not decode".
pub const QUIC_CODE_UNKNOWN_FRAME_TYPE: u32 = 5;

/// The extensions this crate acts on. Wire 1.0 defines none; each arrives
/// with the capability bit that announces it.
const KNOWN_EXTENSIONS: &[&str] = &[];

/// A received frame as wire 1.0 reads it: its type, and the frame without
/// `ext`, so the type's own table never sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub frame_type: String,
    pub frame: Value,
}

/// Reads a received frame's envelope: a map with text keys, version 5, a
/// frame_type of 1 to 64 bytes, each shared envelope key of its type, and an
/// `ext` map of 1 to 16 well-formed extensions, acted on. The dropped
/// `capabilities` header is malformed. An unknown critical extension is
/// [`FrameError::ExtensionUnsupported`]; an unknown non-critical one is
/// counted and read past. An optional key is absent or of its type, never
/// null. Keys beyond the envelope are the frame type's own, for its table to
/// judge.
pub fn read_envelope(v: &Value) -> Result<Envelope, FrameError> {
    let Value::Map(pairs) = v else {
        return Err(FrameError::Malformed);
    };
    let mut frame_type = None;
    let mut has_version = false;
    let mut kept = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let Value::Text(name) = key else {
            return Err(FrameError::Malformed);
        };
        match name.as_str() {
            "version" if *value == Value::Int(i128::from(PROTOCOL_VERSION)) => has_version = true,
            "frame_type" => match value {
                Value::Text(t) if !t.is_empty() && t.len() <= MAX_FRAME_TYPE_BYTES => {
                    frame_type = Some(t.clone())
                }
                _ => return Err(FrameError::Malformed),
            },
            "ext" => {
                act_on_ext(value)?;
                continue;
            }
            "version" | "capabilities" => return Err(FrameError::Malformed),
            other if !shared_key_accepts(other, value) => return Err(FrameError::Malformed),
            _ => {}
        }
        kept.push((key.clone(), value.clone()));
    }
    match (has_version, frame_type) {
        (true, Some(frame_type)) => Ok(Envelope {
            frame_type,
            frame: Value::Map(kept),
        }),
        _ => Err(FrameError::Malformed),
    }
}

/// The frame type of a frame that reads as an envelope but is of a type
/// outside `known`: counted, never acted on, never forwarded. `None` for a
/// known type.
pub fn unknown_frame_type(envelope: &Envelope, known: &[&str]) -> Option<String> {
    if known.contains(&envelope.frame_type.as_str()) {
        return None;
    }
    count_unknown_frame_type();
    Some(envelope.frame_type.clone())
}

/// Whether a shared envelope key's value is of its type; a key that is not
/// one of them is the frame type's own.
fn shared_key_accepts(name: &str, v: &Value) -> bool {
    match name {
        "frame_id" => matches!(v, Value::Bytes(b) if b.len() == 16),
        "sent_at_ms" => protocol_uint(v).is_some(),
        "realm" => matches!(v, Value::Bytes(b) if b.len() == 32),
        "call_id" => matches!(v, Value::Bytes(b) if b.len() == 16),
        "source_route" => matches!(v, Value::Bytes(_)),
        _ => true,
    }
}

/// Judges an `ext` map's shape alone (WIRE_1_0.md section 3.2): 1 to 16
/// entries, each a name of 1 to 64 bytes of `[a-z0-9_.]` mapped to exactly
/// `{critical: 0 | 1, value}`, else [`FrameError::Malformed`]. It acts on
/// nothing, as a custodian storing a record that carries `ext` does not.
pub fn check_ext(v: &Value) -> Result<(), FrameError> {
    ext_entries(v).map(|_| ())
}

/// Acts on a well-formed `ext` map as a receiver that knows no extension: an
/// unknown critical one is [`FrameError::ExtensionUnsupported`], each such
/// name counted as `wire_ext_refused`; only when none is, each unknown
/// non-critical one is counted under its name as `wire_ext_ignored`.
pub fn act_on_ext(v: &Value) -> Result<(), FrameError> {
    let entries = ext_entries(v)?;
    let refused: Vec<&String> = entries
        .iter()
        .filter(|(name, critical)| *critical && !KNOWN_EXTENSIONS.contains(&name.as_str()))
        .map(|(name, _)| name)
        .collect();
    if let Some(first) = refused.first() {
        refused.iter().for_each(|name| count_ext_refused(name));
        return Err(FrameError::ExtensionUnsupported((*first).clone()));
    }
    for (name, _) in entries
        .iter()
        .filter(|(name, _)| !KNOWN_EXTENSIONS.contains(&name.as_str()))
    {
        count_ext_ignored(name);
    }
    Ok(())
}

/// A well-formed `ext` map's entries, name and whether it is critical.
fn ext_entries(v: &Value) -> Result<Vec<(String, bool)>, FrameError> {
    let Value::Map(pairs) = v else {
        return Err(FrameError::Malformed);
    };
    if pairs.is_empty() || pairs.len() > MAX_EXTENSIONS {
        return Err(FrameError::Malformed);
    }
    pairs
        .iter()
        .map(|(key, entry)| match (key, extension_critical(entry)) {
            (Value::Text(name), Some(critical)) if extension_name(name) => {
                Ok((name.clone(), critical))
            }
            _ => Err(FrameError::Malformed),
        })
        .collect()
}

/// An extension entry's `critical`, when it is exactly `{critical: 0 | 1,
/// value}`.
fn extension_critical(entry: &Value) -> Option<bool> {
    let Value::Map(fields) = entry else {
        return None;
    };
    let named = |n: &str| fields.iter().filter(|(k, _)| *k == Value::text(n)).count() == 1;
    if fields.len() != 2 || !named("critical") || !named("value") {
        return None;
    }
    match entry.get("critical") {
        Some(Value::Int(0)) => Some(false),
        Some(Value::Int(1)) => Some(true),
        _ => None,
    }
}

fn extension_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_EXTENSION_NAME_BYTES
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.')
}
