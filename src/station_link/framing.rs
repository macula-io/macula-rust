//! A control stream's or a session stream's frames: `<Len:32/big, CBOR>`,
//! with the caps macula 12 holds them to. A length header over the cap is
//! refused as soon as it arrives, before its body is read.

use super::LinkError;

/// A handshake frame (OPENER, CHALLENGE, CONNECT, HELLO) is at most 64 KiB.
pub(super) const HANDSHAKE_FRAME_BYTES: usize = 64 * 1024;

/// Every frame after HELLO is at most 16 MiB minus one byte.
pub(super) const MAX_FRAME_BYTES: usize = crate::frame::MAX_FRAME_BYTES;

/// The next frame's CBOR bytes, refusing a length header over `max`.
pub(super) async fn read_frame(
    recv: &mut quinn::RecvStream,
    max: usize,
) -> Result<Vec<u8>, LinkError> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| LinkError::Io(e.to_string()))?;
    let length = u32::from_be_bytes(header) as usize;
    length_within(length, max)?;
    let mut payload = vec![0u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| LinkError::Io(e.to_string()))?;
    Ok(payload)
}

/// Refuses a length header over `max`, read from the four header bytes alone.
pub(super) fn length_within(length: usize, max: usize) -> Result<(), LinkError> {
    if length > max {
        return Err(LinkError::FrameTooLarge(length));
    }
    Ok(())
}

/// A stream's sending side, writing one frame at a time.
pub(super) struct FrameWriter {
    send: tokio::sync::Mutex<quinn::SendStream>,
}

impl FrameWriter {
    pub(super) fn new(send: quinn::SendStream) -> FrameWriter {
        FrameWriter {
            send: tokio::sync::Mutex::new(send),
        }
    }

    /// Sends `payload` as one frame, refusing one over `max`.
    pub(super) async fn write(&self, payload: &[u8], max: usize) -> Result<(), LinkError> {
        if payload.len() > max {
            return Err(LinkError::FrameTooLarge(payload.len()));
        }
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        self.send
            .lock()
            .await
            .write_all(&framed)
            .await
            .map_err(|e| LinkError::Io(e.to_string()))
    }

    /// Finishes the sending side gracefully, after what was written.
    pub(super) async fn finish(&self) {
        let _ = self.send.lock().await.finish();
    }

    /// Resets the sending side, dropping what it still holds.
    pub(super) async fn reset(&self) {
        self.reset_with(0).await;
    }

    /// Resets the sending side with the QUIC application code `code`.
    pub(super) async fn reset_with(&self, code: u32) {
        let _ = self.send.lock().await.reset(code.into());
    }
}
