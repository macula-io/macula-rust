//! UUID v7s, the frame ids and record versions macula 12 carries: 48 bits of
//! Unix milliseconds, the version and variant bits, and 74 random bits.

/// Now, in Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A new UUID v7.
pub(crate) fn new() -> [u8; 16] {
    let mut id = [0u8; 16];
    // An id is an identifier, not a secret: one without randomness is still
    // ordered and unique by its time, so a failure to draw is not an error.
    let _ = aws_lc_rs::rand::fill(&mut id[6..]);
    id[..6].copy_from_slice(&now_ms().to_be_bytes()[2..]);
    id[6] = (id[6] & 0x0f) | 0x70;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}
