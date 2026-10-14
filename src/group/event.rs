//! Sealing and opening a group's events: one publisher's subkey of the
//! group's epoch key, a fresh nonce, and the event AAD the publication's
//! routing fields are bound to. The counterpart of macula's
//! `macula_group_event`.

use crate::cbor::{self, Value};
use crate::frame::{Sealed, SEALED_SCHEME};
use crate::seal;

use super::{Epoch, GroupError, Reason};

/// What an event's seal is bound to: the publication's routing fields, which
/// the event AAD covers. The epoch is not among them: the derived key binds
/// the group, and the sealed map's key id names the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    pub realm: [u8; 32],
    pub topic: String,
    pub publisher: [u8; 32],
    pub seq: u64,
    pub published_at: u64,
}

impl Fields {
    fn aad(&self) -> Vec<u8> {
        seal::event_aad(
            &self.realm,
            &self.topic,
            &self.publisher,
            self.seq,
            self.published_at,
        )
    }
}

/// Seals `payload` for a publication with `f` under `epoch`, as macula's
/// `macula_group_event:seal/3` does: under the publisher's own subkey of the
/// epoch key, `k_pub`, with a fresh 96-bit random nonce, bound by the event
/// AAD to `f`. The plaintext is the payload's deterministic CBOR. What comes
/// back rides in the PUBLISH in place of the payload.
pub fn seal_event(epoch: &Epoch, f: &Fields, payload: &Value) -> Result<Sealed, GroupError> {
    crate::frame::check_payload(payload).map_err(|e| GroupError::NotSealed(Box::new(e)))?;
    let nonce = seal::random_nonce().map_err(|e| GroupError::NotSealed(Box::new(e)))?;
    let plain = cbor::encode(payload).map_err(|e| GroupError::NotSealed(Box::new(e)))?;
    let key = seal::event_key(epoch.key(), &f.publisher);
    let ct = seal::seal(&key, &nonce, &f.aad(), &plain);
    Ok(Sealed {
        scheme: SEALED_SCHEME,
        key_id: epoch.id,
        kem_ct: None,
        nonce: Some(nonce.to_vec()),
        ct,
    })
}

/// Opens a sealed event with `f` under `epoch`, as macula's
/// `macula_group_event:open/2` does, and answers its payload in the shape a
/// clear payload arrives in. Anything that does not open, whatever it is, is
/// refused `tag_invalid`: another epoch's key, a routing field other than the
/// one it was sealed with, or a changed byte.
pub fn open_event(epoch: &Epoch, f: &Fields, sealed: &Sealed) -> Result<Value, GroupError> {
    let tag_invalid = || GroupError::of(Reason::TagInvalid);
    if !sealed.known_scheme() {
        return Err(tag_invalid());
    }
    let nonce: [u8; seal::NONCE_SIZE] = sealed
        .nonce
        .as_ref()
        .filter(|n| n.len() == seal::NONCE_SIZE)
        .and_then(|n| n.as_slice().try_into().ok())
        .ok_or_else(tag_invalid)?;
    let key = seal::event_key(epoch.key(), &f.publisher);
    let plain = seal::open(&key, &nonce, &f.aad(), &sealed.ct).map_err(|_| tag_invalid())?;
    cbor::decode(&plain).map_err(|_| tag_invalid())
}
