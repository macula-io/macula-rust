//! The checks a sender runs so that nothing the decoding rule refuses on
//! arrival leaves this node, as macula_frame's check_payload/1 and
//! check_frame/1: a map key that is not text or an integer, two keys of one
//! map that encode alike, an integer outside -2^63 to 2^63-1, a float that is
//! NaN or infinite, too deep a nesting, and too many items. Text is valid
//! UTF-8 by construction here.

use crate::cbor::{self, Value, MAX_ELEMENTS, MAX_NESTING_DEPTH};

use super::{FrameError, MAX_FRAME_BYTES};

/// How many lists and maps a payload may nest, the outermost counted: a
/// payload travels inside a frame's map, which takes one level.
pub const MAX_PAYLOAD_NESTING: usize = MAX_NESTING_DEPTH - 1;

/// How many of the decoding rule's items a payload leaves for the frame
/// around it.
pub const FRAME_RESERVED_ELEMENTS: usize = 64;

/// How many CBOR items a payload may hold, itself included.
pub const MAX_PAYLOAD_ELEMENTS: usize = MAX_ELEMENTS - FRAME_RESERVED_ELEMENTS;

/// Whether `payload` is admissible as a frame payload. It also refuses a
/// payload whose own encoding is over the frame cap.
pub fn check_payload(payload: &Value) -> Result<(), FrameError> {
    let mut check = RuleCheck {
        subject: "payload",
        max_items: MAX_PAYLOAD_ELEMENTS,
        max_nesting: MAX_PAYLOAD_NESTING,
        items: 0,
    };
    check
        .value(payload, &mut Vec::new())
        .map_err(FrameError::Payload)?;
    let encoded = cbor::encode(payload).map_err(|e| FrameError::Payload(e.to_string()))?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Payload(format!(
            "the payload encodes to {} bytes, over the {MAX_FRAME_BYTES}-byte frame cap",
            encoded.len()
        )));
    }
    Ok(())
}

/// Whether the whole `frame` is one the decoding rule accepts where it
/// arrives, the check macula runs on every frame before it is sent.
pub fn check_frame(frame: &Value) -> Result<(), FrameError> {
    let mut check = RuleCheck {
        subject: "frame",
        max_items: MAX_ELEMENTS,
        max_nesting: MAX_NESTING_DEPTH,
        items: 0,
    };
    check
        .value(frame, &mut Vec::new())
        .map_err(FrameError::BreaksDecodingRule)
}

/// A walk of a payload or a whole frame, its subject, under the decoding
/// rule's limits for it, counting its items.
struct RuleCheck {
    subject: &'static str,
    max_items: usize,
    max_nesting: usize,
    items: usize,
}

impl RuleCheck {
    fn value(&mut self, v: &Value, path: &mut Vec<String>) -> Result<(), String> {
        self.items += 1;
        if self.items > self.max_items {
            return Err(format!(
                "the {} holds more than {} items, at {}",
                self.subject,
                self.max_items,
                self.at(path)
            ));
        }
        match v {
            Value::Float(f) if !f.is_finite() => {
                Err(format!("a float that is not finite at {}", self.at(path)))
            }
            Value::Int(n) if i64::try_from(*n).is_err() => Err(format!(
                "an integer outside -2^63 to 2^63-1 at {}",
                self.at(path)
            )),
            Value::List(items) => {
                self.nesting(path)?;
                for (i, item) in items.iter().enumerate() {
                    path.push(i.to_string());
                    self.value(item, path)?;
                    path.pop();
                }
                Ok(())
            }
            Value::Map(pairs) => {
                self.nesting(path)?;
                let mut seen = std::collections::HashSet::with_capacity(pairs.len());
                for (key, value) in pairs {
                    if !matches!(key, Value::Text(_) | Value::Int(_)) {
                        return Err(format!(
                            "a map key that is not text or an integer at {}",
                            self.at(path)
                        ));
                    }
                    self.value(key, path)?;
                    let encoded = cbor::encode(key).map_err(|e| e.to_string())?;
                    if !seen.insert(encoded) {
                        return Err(format!(
                            "two keys of the map at {} encode alike",
                            self.at(path)
                        ));
                    }
                    path.push(match key {
                        Value::Text(t) => t.clone(),
                        other => format!("{other:?}"),
                    });
                    self.value(value, path)?;
                    path.pop();
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Refuses a list or map at `path` that would nest more than the limit.
    fn nesting(&self, path: &[String]) -> Result<(), String> {
        if path.len() >= self.max_nesting {
            return Err(format!(
                "lists and maps at {} nest more than {} levels",
                self.at(path),
                self.max_nesting
            ));
        }
        Ok(())
    }

    fn at(&self, path: &[String]) -> String {
        if path.is_empty() {
            format!("the {} root", self.subject)
        } else {
            path.join(".")
        }
    }
}
