//! Handshake v5 (macula 13.2, DESIGN_NEIGHBOUR_CHANNEL_BINDING section 3): the
//! session proofs authenticate the neighbour once, so after HELLO no frame
//! carries a neighbour signature, and QUIC's AEAD authenticates every frame.
//! The liveness probe is liveness_ping, answered with liveness_pong and the
//! same nonce by the peer's connection itself: unsigned, never handed on, and
//! on a v5 connection only.

use crate::cbor::Value;

use super::neighbour::control_header;
use super::{base, entry, FrameError};

/// The bytes of a liveness frame's nonce.
pub const LIVENESS_NONCE_SIZE: usize = 16;

/// A received frame on a v5 connection: one that carries a neighbour
/// signature is [`FrameError::Malformed`], and any other comes back as it is.
pub fn verify_session_frame(frame: &Value) -> Result<Value, FrameError> {
    let Value::Map(pairs) = frame else {
        return Err(FrameError::Malformed);
    };
    match control_header(pairs) {
        (_, _, true) => Err(FrameError::Malformed),
        _ => Ok(frame.clone()),
    }
}

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
    let Value::Map(pairs) = frame else {
        return None;
    };
    let kind = match control_header(pairs).0.as_str() {
        "liveness_ping" => Liveness::Ping,
        "liveness_pong" => Liveness::Pong,
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
    use crate::frame::{goodbye_frame, neighbour_signed};
    use crate::profile::Profile;

    #[test]
    fn a_v5_connection_reads_frames_without_a_neighbour_signature_and_refuses_one_that_has_it() {
        let ping = liveness_ping_frame(&[7; 16]);
        assert_eq!(verify_session_frame(&ping).unwrap(), ping);
        let Value::Map(mut goodbye) = goodbye_frame("bye", None).unwrap() else {
            panic!("a goodbye is a map");
        };
        goodbye.push(entry("neighbour", Value::Map(Vec::new())));
        assert_eq!(
            verify_session_frame(&Value::Map(goodbye)),
            Err(FrameError::Malformed)
        );
    }

    #[test]
    fn liveness_frames_carry_their_nonce_and_are_never_neighbour_signed() {
        let nonce = [1; 16];
        for (kind, frame, name) in [
            (Liveness::Ping, liveness_ping_frame(&nonce), "liveness_ping"),
            (Liveness::Pong, liveness_pong_frame(&nonce), "liveness_pong"),
        ] {
            assert_eq!(liveness_nonce(&frame), Some((kind, nonce)), "{name}");
            assert!(!neighbour_signed(Profile::PqHybrid, name), "{name}");
            let wire = crate::frame::encode(&frame).unwrap();
            let crate::frame::Decoded::Complete { frame: decoded, .. } =
                crate::frame::decode(&wire).unwrap()
            else {
                panic!("{name}: not whole");
            };
            assert_eq!(liveness_nonce(&decoded), Some((kind, nonce)), "{name}");
        }
        let mut short = base("liveness_ping");
        short.push(entry("nonce", Value::Bytes(vec![1, 2])));
        assert_eq!(liveness_nonce(&Value::Map(short)), None);
        assert_eq!(liveness_nonce(&goodbye_frame("bye", None).unwrap()), None);
    }
}
