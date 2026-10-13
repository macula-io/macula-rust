//! The liveness probe (macula 13.2, DESIGN_NEIGHBOUR_CHANNEL_BINDING section
//! 3): liveness_ping, answered with liveness_pong and the same nonce by the
//! peer's connection itself, unsigned and never handed on. The session proofs
//! authenticate the neighbour once, so after HELLO no frame carries a
//! neighbour signature, and QUIC's AEAD authenticates every frame.

use crate::cbor::Value;

use super::{base, entry};

/// The bytes of a liveness frame's nonce.
pub const LIVENESS_NONCE_SIZE: usize = 16;

/// macula 13.2's liveness_ping with a 16-byte nonce.
pub fn liveness_ping_frame(nonce: &[u8; LIVENESS_NONCE_SIZE]) -> Value {
    liveness_frame("liveness_ping", nonce)
}

/// macula 13.2's liveness_pong, answering the liveness_ping of the same
/// nonce.
pub fn liveness_pong_frame(nonce: &[u8; LIVENESS_NONCE_SIZE]) -> Value {
    liveness_frame("liveness_pong", nonce)
}

fn liveness_frame(frame_type: &str, nonce: &[u8; LIVENESS_NONCE_SIZE]) -> Value {
    let mut fields = base(frame_type);
    fields.push(entry("nonce", Value::Bytes(nonce.to_vec())));
    Value::Map(fields)
}

/// Whether a liveness frame is the peer's probe or its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Ping,
    Pong,
}

/// A liveness frame's kind and nonce, or `None` for any other frame, or one
/// whose nonce is not 16 bytes.
pub fn liveness_nonce(frame: &Value) -> Option<(Liveness, [u8; LIVENESS_NONCE_SIZE])> {
    let kind = match frame.get("frame_type") {
        Some(Value::Text(t)) if t == "liveness_ping" => Liveness::Ping,
        Some(Value::Text(t)) if t == "liveness_pong" => Liveness::Pong,
        _ => return None,
    };
    match frame.get("nonce") {
        Some(Value::Bytes(nonce)) => Some((kind, nonce.as_slice().try_into().ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::goodbye_frame;

    /// Encodes `frame` and decodes it back, which must give a whole frame.
    fn round_trip(frame: &Value, name: &str) -> Value {
        let wire = crate::frame::encode(frame).unwrap();
        let crate::frame::Decoded::Complete { frame: decoded, .. } =
            crate::frame::decode(&wire).unwrap()
        else {
            panic!("{name}: not whole");
        };
        decoded
    }

    #[test]
    fn liveness_frames_carry_their_nonce() {
        let nonce = [1; 16];
        for (kind, frame, name) in [
            (Liveness::Ping, liveness_ping_frame(&nonce), "liveness_ping"),
            (Liveness::Pong, liveness_pong_frame(&nonce), "liveness_pong"),
        ] {
            assert_eq!(liveness_nonce(&frame), Some((kind, nonce)), "{name}");
            let decoded = round_trip(&frame, name);
            assert_eq!(liveness_nonce(&decoded), Some((kind, nonce)), "{name}");
        }
        let mut short = base("liveness_ping");
        short.push(entry("nonce", Value::Bytes(vec![1, 2])));
        assert_eq!(liveness_nonce(&Value::Map(short)), None);
        assert_eq!(liveness_nonce(&goodbye_frame("bye", None).unwrap()), None);
    }
}
