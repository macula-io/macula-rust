//! End-to-end payload sealing, scheme 1 (macula 13, E2E design and amendment
//! A1): what a node needs to seal a payload so that the stations relaying it
//! cannot read it, the counterpart of macula's macula_seal and macula-go's
//! seal. The byte-exact construction is macula's test/vectors/E2E_SEAL_V1.md,
//! and tests/vectors/seal/e2e_seal_v1.json holds its vectors.
//!
//! The key agreement is ML-KEM-1024 in pq_pure, and ML-KEM-1024 with an
//! ephemeral P-384 ECDH in pq_hybrid, combined with HKDF-SHA-384 over both
//! secrets, both ciphertexts and the recipient's key. Payloads are sealed
//! with AES-256-GCM. A key travels as carried, ML-KEM-1024's encapsulation
//! key followed in pq_hybrid by a P-384 point, and is named by its id, the
//! first 8 bytes of its SHA-384. Everything here is a pure function over
//! aws-lc-rs; the frames that carry a sealed payload are built elsewhere.

use std::fmt;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::agreement::{self, ParsedPublicKey, UnparsedPublicKey, ECDH_P384};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::profile::Profile;

mod keyring;
pub use keyring::{Clock, Keyring, KEY_LIFETIME_MS, RETIRED_KEY_KEPT_MS};

/// The sealed map's scheme number this module implements.
pub const SCHEME: i64 = 1;

/// The bytes of a key id.
pub const KEY_ID_SIZE: usize = 8;
/// The SHA-384 of a recipient's key as carried.
pub const KEY_HASH_SIZE: usize = 48;
/// An ML-KEM-1024 ciphertext.
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1568;
/// An ML-KEM-1024 expanded decapsulation key.
pub const MLKEM_DK_SIZE: usize = 3168;
/// An AES-256-GCM nonce.
pub const NONCE_SIZE: usize = 12;
/// The AES-256-GCM tag appended to every ciphertext.
pub const TAG_SIZE: usize = 16;

const MLKEM_EK_BYTES: usize = 1568;
const P384_POINT_BYTES: usize = 97;
const P384_SCALAR_BYTES: usize = 48;

/// The frame types that name their key and AAD, as the wire's text.
pub const FRAME_CALL: &str = "call";
pub const FRAME_STREAM_OPEN: &str = "stream_open";
pub const FRAME_RESULT: &str = "result";
pub const FRAME_ERROR: &str = "error";

const LABEL_PURE: &str = "MACULA-E2E-PURE-V1";
const LABEL_HYBRID: &str = "MACULA-E2E-HYBRID-V1";
const LABEL_CALL: &str = "MACULA-E2E-CALL-V1";
const LABEL_STREAM: &str = "MACULA-E2E-STREAM-V1";
const LABEL_AAD: &str = "MACULA-E2E-AAD-V1";
const LABEL_STREAM_AAD: &str = "MACULA-E2E-STREAM-AAD-V1";

/// An opened ERROR's code and detail are bounded as a clear ERROR's are, as
/// macula_frame's error_read/1 bounds them.
pub const MAX_ERROR_CODE_BYTES: usize = 64;
pub const MAX_ERROR_DETAIL_BYTES: usize = 256;

/// Why a seal operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// A sealed payload, kem_ct or point that does not open: the wrong
    /// length, a point off the curve, a zero ECDH output, or a ciphertext
    /// whose key, nonce, AAD or a single bit differs. macula's
    /// `sealed_refused`.
    Refused,
    /// A recipient key that cannot be built, and why.
    Key(String),
    /// An opened ERROR plaintext that is not cbor([code, detail]) with both
    /// text within their bounds.
    NotAnErrorPlain,
    /// Randomness or a primitive that failed.
    Unavailable,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Refused => f.write_str("sealed_refused"),
            SealError::Key(why) => write!(f, "not a recipient key: {why}"),
            SealError::NotAnErrorPlain => {
                f.write_str("an ERROR's plaintext is not cbor([code, detail])")
            }
            SealError::Unavailable => f.write_str("a seal primitive is unavailable"),
        }
    }
}

impl std::error::Error for SealError {}

/// The size of a KEM key as carried under `profile`.
pub fn carried_key_size(profile: Profile) -> usize {
    match profile {
        Profile::PqPure => MLKEM_EK_BYTES,
        Profile::PqHybrid => MLKEM_EK_BYTES + P384_POINT_BYTES,
    }
}

/// Whether `len` is a carried KEM key's size under some profile, as
/// macula_record's kem_key_sizes/0: an advertisement's key is checked by size
/// alone, whatever the reader's profile.
pub fn is_carried_key_size(len: usize) -> bool {
    [Profile::PqPure, Profile::PqHybrid]
        .into_iter()
        .any(|p| carried_key_size(p) == len)
}

/// The SHA-384 of a key as carried, which the combiner binds.
pub fn key_hash(carried: &[u8]) -> [u8; KEY_HASH_SIZE] {
    Sha384::digest(carried).into()
}

/// A carried key's id: the first 8 bytes of its SHA-384.
pub fn key_id(carried: &[u8]) -> [u8; KEY_ID_SIZE] {
    let mut id = [0; KEY_ID_SIZE];
    id.copy_from_slice(&key_hash(carried)[..KEY_ID_SIZE]);
    id
}

/// A recipient's KEM key as carried in a profile: what a caller seals to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    profile: Profile,
    carried: Vec<u8>,
}

impl PublicKey {
    /// The key as it is carried and hashed.
    pub fn carried(&self) -> &[u8] {
        &self.carried
    }

    /// The profile the key is of.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The key's id.
    pub fn key_id(&self) -> [u8; KEY_ID_SIZE] {
        key_id(&self.carried)
    }

    fn mlkem(&self) -> &[u8] {
        &self.carried[..MLKEM_EK_BYTES]
    }

    fn p384(&self) -> Option<&[u8]> {
        (self.profile == Profile::PqHybrid).then(|| &self.carried[MLKEM_EK_BYTES..])
    }
}

/// The recipient key a key as carried holds in `profile`: an advertisement's
/// kem_key, which a caller seals to. A key of another size than the
/// profile's, an ML-KEM key aws-lc refuses, or a P-384 point that is not an
/// uncompressed point on the curve is [`SealError::Key`].
pub fn parse_public_key(profile: Profile, carried: &[u8]) -> Result<PublicKey, SealError> {
    if carried.len() != carried_key_size(profile) {
        return Err(SealError::Key(format!(
            "a {} key as carried is {} bytes, not {}",
            profile.name(),
            carried_key_size(profile),
            carried.len()
        )));
    }
    EncapsulationKey::new(&ML_KEM_1024, &carried[..MLKEM_EK_BYTES])
        .map_err(|e| SealError::Key(format!("ML-KEM-1024: {e}")))?;
    if profile == Profile::PqHybrid && !p384_point(&carried[MLKEM_EK_BYTES..]) {
        return Err(SealError::Key("not an uncompressed point on P-384".into()));
    }
    Ok(PublicKey {
        profile,
        carried: carried.to_vec(),
    })
}

/// Whether `point` is an uncompressed point on P-384.
fn p384_point(point: &[u8]) -> bool {
    point.len() == P384_POINT_BYTES
        && point[0] == 0x04
        && ParsedPublicKey::try_from(&UnparsedPublicKey::new(&ECDH_P384, point)).is_ok()
}

/// A recipient's KEM key pair: the ML-KEM-1024 decapsulation key and, in
/// pq_hybrid, a P-384 scalar, with the key as carried that others seal to.
pub struct PrivateKey {
    public: PublicKey,
    mlkem: DecapsulationKey,
    p384: Option<agreement::PrivateKey>,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seal::PrivateKey({}, key id {})",
            self.public.profile.name(),
            hex(&self.public.key_id())
        )
    }
}

impl PrivateKey {
    /// A fresh recipient key in `profile`.
    pub fn generate(profile: Profile) -> Result<PrivateKey, SealError> {
        let mlkem = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| SealError::Unavailable)?;
        let ek = mlkem
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(|_| SealError::Unavailable)?;
        let mut carried = ek.as_ref().to_vec();
        let p384 = match profile {
            Profile::PqPure => None,
            Profile::PqHybrid => {
                let key = agreement::PrivateKey::generate(&ECDH_P384)
                    .map_err(|_| SealError::Unavailable)?;
                let point = key
                    .compute_public_key()
                    .map_err(|_| SealError::Unavailable)?;
                carried.extend_from_slice(point.as_ref());
                Some(key)
            }
        };
        Ok(PrivateKey {
            public: PublicKey { profile, carried },
            mlkem,
            p384,
        })
    }

    /// A recipient key from its parts: the expanded ML-KEM-1024
    /// decapsulation key (3168 bytes), the key as carried that it answers to,
    /// and in pq_hybrid only its 48-byte P-384 scalar.
    pub fn from_parts(
        profile: Profile,
        mlkem_dk: &[u8],
        carried: &[u8],
        p384_scalar: Option<&[u8]>,
    ) -> Result<PrivateKey, SealError> {
        let public = parse_public_key(profile, carried)?;
        if mlkem_dk.len() != MLKEM_DK_SIZE {
            return Err(SealError::Key(format!(
                "an ML-KEM-1024 decapsulation key is {MLKEM_DK_SIZE} bytes, not {}",
                mlkem_dk.len()
            )));
        }
        let mlkem = DecapsulationKey::new(&ML_KEM_1024, mlkem_dk)
            .map_err(|e| SealError::Key(format!("ML-KEM-1024: {e}")))?;
        let p384 = match (profile, p384_scalar) {
            (Profile::PqPure, None) => None,
            (Profile::PqHybrid, Some(scalar)) if scalar.len() == P384_SCALAR_BYTES => Some(
                agreement::PrivateKey::from_private_key(&ECDH_P384, scalar)
                    .map_err(|e| SealError::Key(format!("P-384: {e}")))?,
            ),
            (profile, scalar) => {
                return Err(SealError::Key(format!(
                    "a {} key with {} bytes of P-384 scalar",
                    profile.name(),
                    scalar.map_or(0, <[u8]>::len)
                )))
            }
        };
        if let (Some(key), Some(point)) = (&p384, public.p384()) {
            let derived = key
                .compute_public_key()
                .map_err(|_| SealError::Unavailable)?;
            if derived.as_ref() != point {
                return Err(SealError::Key(
                    "the P-384 scalar is not the carried point's".into(),
                ));
            }
        }
        Ok(PrivateKey {
            public,
            mlkem,
            p384,
        })
    }

    /// The recipient key others seal to.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The expanded ML-KEM-1024 decapsulation key, for a keyring that keeps
    /// this key.
    pub fn mlkem_dk(&self) -> Result<Vec<u8>, SealError> {
        self.mlkem
            .key_bytes()
            .map(|b| b.as_ref().to_vec())
            .map_err(|_| SealError::Unavailable)
    }
}

/// A fresh shared secret to `recipient`, and the kem_ct that carries it:
/// ML-KEM-1024's ciphertext, followed by the ephemeral P-384 point in
/// pq_hybrid.
pub fn sender_secret(recipient: &PublicKey) -> Result<([u8; KEY_HASH_SIZE], Vec<u8>), SealError> {
    let ek = EncapsulationKey::new(&ML_KEM_1024, recipient.mlkem())
        .map_err(|_| SealError::Unavailable)?;
    let (mlkem_ct, ss_mlkem) = ek.encapsulate().map_err(|_| SealError::Unavailable)?;
    let mlkem_ct = mlkem_ct.as_ref().to_vec();
    let ss_mlkem = ss_mlkem.as_ref().to_vec();
    let key_hash = key_hash(recipient.carried());
    let Some(point) = recipient.p384() else {
        return Ok((
            combine(LABEL_PURE, &pure_ikm(&ss_mlkem, &mlkem_ct, &key_hash)),
            mlkem_ct,
        ));
    };
    let ephemeral =
        agreement::PrivateKey::generate(&ECDH_P384).map_err(|_| SealError::Unavailable)?;
    let eph_pub = ephemeral
        .compute_public_key()
        .map_err(|_| SealError::Unavailable)?
        .as_ref()
        .to_vec();
    let ss_ecdh = ecdh_secret(&ephemeral, point)?;
    let ss = combine(
        LABEL_HYBRID,
        &hybrid_ikm(&ss_mlkem, &ss_ecdh, &mlkem_ct, &eph_pub, &key_hash),
    );
    Ok((ss, [mlkem_ct, eph_pub].concat()))
}

/// The shared secret a kem_ct carries, recovered with the recipient's own
/// key. A kem_ct of the wrong length for the key's profile, an ephemeral
/// point that is not an uncompressed point on P-384, or a zero ECDH output
/// is [`SealError::Refused`].
pub fn recipient_secret(
    recipient: &PrivateKey,
    kem_ct: &[u8],
) -> Result<[u8; KEY_HASH_SIZE], SealError> {
    let key_hash = key_hash(recipient.public.carried());
    let decapsulated = |ct: &[u8]| {
        recipient
            .mlkem
            .decapsulate(Ciphertext::from(ct))
            .map(|ss| ss.as_ref().to_vec())
            .map_err(|_| SealError::Refused)
    };
    let Some(p384) = &recipient.p384 else {
        if kem_ct.len() != MLKEM_CIPHERTEXT_SIZE {
            return Err(SealError::Refused);
        }
        let ss_mlkem = decapsulated(kem_ct)?;
        return Ok(combine(LABEL_PURE, &pure_ikm(&ss_mlkem, kem_ct, &key_hash)));
    };
    if kem_ct.len() != MLKEM_CIPHERTEXT_SIZE + P384_POINT_BYTES {
        return Err(SealError::Refused);
    }
    let (mlkem_ct, eph_pub) = kem_ct.split_at(MLKEM_CIPHERTEXT_SIZE);
    let ss_ecdh = ecdh_secret(p384, eph_pub)?;
    let ss_mlkem = decapsulated(mlkem_ct)?;
    Ok(combine(
        LABEL_HYBRID,
        &hybrid_ikm(&ss_mlkem, &ss_ecdh, mlkem_ct, eph_pub, &key_hash),
    ))
}

/// The 48-byte x coordinate of `private` times the peer's point. Only an
/// uncompressed point on the curve is taken, and a zero output is refused
/// with an explicit check, as the spec requires: P-384 has points with
/// x = 0, and the primitives under every stack return them without an error.
fn ecdh_secret(private: &agreement::PrivateKey, peer_point: &[u8]) -> Result<Vec<u8>, SealError> {
    if !p384_point(peer_point) {
        return Err(SealError::Refused);
    }
    let secret = agreement::agree(
        private,
        UnparsedPublicKey::new(&ECDH_P384, peer_point),
        SealError::Refused,
        |secret| Ok(secret.to_vec()),
    )?;
    let zero = verify_slices_are_equal(&secret, &[0; P384_SCALAR_BYTES]).is_ok();
    if secret.len() != P384_SCALAR_BYTES || zero {
        return Err(SealError::Refused);
    }
    Ok(secret)
}

fn pure_ikm(ss_mlkem: &[u8], mlkem_ct: &[u8], key_hash: &[u8]) -> Vec<u8> {
    encode(vec![bytes(ss_mlkem), bytes(mlkem_ct), bytes(key_hash)])
}

fn hybrid_ikm(
    ss_mlkem: &[u8],
    ss_ecdh: &[u8],
    mlkem_ct: &[u8],
    eph_pub: &[u8],
    key_hash: &[u8],
) -> Vec<u8> {
    encode(vec![
        bytes(ss_mlkem),
        bytes(ss_ecdh),
        bytes(mlkem_ct),
        bytes(eph_pub),
        bytes(key_hash),
    ])
}

/// HKDF-Extract with the profile's label as the salt.
fn combine(label: &str, ikm: &[u8]) -> [u8; KEY_HASH_SIZE] {
    extract(label.as_bytes(), ikm)
}

/// The request_id, caller and target one call's or stream's keys are bound
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parties {
    pub request_id: [u8; 16],
    pub caller: [u8; 32],
    pub target: [u8; 32],
}

/// The request and reply keys of one CALL or STREAM_OPEN. `frame_type` is
/// [`FRAME_CALL`] or [`FRAME_STREAM_OPEN`].
pub fn call_keys(
    secret: &[u8; KEY_HASH_SIZE],
    frame_type: &str,
    p: &Parties,
) -> ([u8; 32], [u8; 32]) {
    halves(expand(
        secret,
        &encode(vec![
            Value::text(LABEL_CALL),
            Value::text(frame_type),
            bytes(&p.request_id),
            bytes(&p.caller),
            bytes(&p.target),
        ]),
    ))
}

/// The caller-to-provider and provider-to-caller keys of one stream.
pub fn stream_keys(secret: &[u8; KEY_HASH_SIZE], p: &Parties) -> ([u8; 32], [u8; 32]) {
    halves(expand(
        secret,
        &encode(vec![
            Value::text(LABEL_STREAM),
            bytes(&p.request_id),
            bytes(&p.caller),
            bytes(&p.target),
        ]),
    ))
}

fn halves(okm: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0; 32];
    let mut b = [0; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

/// What a request's sealed payload is bound to: its routing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub frame_type: String,
    pub realm: [u8; 32],
    pub procedure: String,
    pub caller: [u8; 32],
    pub target: [u8; 32],
    pub request_id: [u8; 16],
    pub deadline: u64,
}

impl Request {
    fn fields(&self, frame_type: &str) -> Vec<Value> {
        vec![
            Value::text(LABEL_AAD),
            Value::text(frame_type),
            bytes(&self.realm),
            Value::text(self.procedure.clone()),
            bytes(&self.caller),
            bytes(&self.target),
            bytes(&self.request_id),
            Value::Int(i128::from(self.deadline)),
        ]
    }
}

/// A CALL's or STREAM_OPEN's AAD. Its nonce is 12 zero bytes: k_req seals
/// exactly one payload.
pub fn request_aad(r: &Request) -> Vec<u8> {
    encode(r.fields(&r.frame_type))
}

/// A RESULT's or ERROR's AAD: its request's routing fields under the reply's
/// frame type, the request hash the reply carries and the provider that
/// responded.
pub fn reply_aad(
    r: &Request,
    reply_frame_type: &str,
    request_hash: &[u8; 48],
    responded_by: &[u8; 32],
) -> Vec<u8> {
    let mut fields = r.fields(reply_frame_type);
    fields.push(bytes(request_hash));
    fields.push(bytes(responded_by));
    encode(fields)
}

/// Which way a stream frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Caller frames seal under k_c2p, with their seq as the nonce.
    CallerToProvider = 0,
    /// Provider frames seal under k_p2c, with a random nonce carried.
    ProviderToCaller = 1,
}

/// A stream frame's AAD.
pub fn stream_aad(frame_type: &str, request_id: &[u8; 16], seq: u64, d: Direction) -> Vec<u8> {
    encode(vec![
        Value::text(LABEL_STREAM_AAD),
        Value::text(frame_type),
        bytes(request_id),
        Value::Int(i128::from(seq)),
        Value::Int(d as i128),
    ])
}

/// A caller stream frame's nonce: its seq as a 96-bit big-endian integer.
pub fn stream_nonce(seq: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0; NONCE_SIZE];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// A fresh nonce, for a reply, a provider stream frame or an event, which
/// carry theirs.
pub fn random_nonce() -> Result<[u8; NONCE_SIZE], SealError> {
    let mut nonce = [0; NONCE_SIZE];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| SealError::Unavailable)?;
    Ok(nonce)
}

/// AES-256-GCM: the ciphertext with its 16-byte tag appended.
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte AES-256 key"));
    let mut out = plain.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut out,
    )
    .expect("AES-256-GCM seals any payload under 2^36 bytes");
    out
}

/// The plaintext of a sealed payload, or [`SealError::Refused`] when the
/// key, the nonce, the AAD or a single bit of it differ.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, SealError> {
    if sealed.len() < TAG_SIZE {
        return Err(SealError::Refused);
    }
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte AES-256 key"));
    let mut buf = sealed.to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| SealError::Refused)?;
    Ok(plain.to_vec())
}

/// A sealed ERROR's plaintext: cbor([code, detail]), both text, detail the
/// empty text when there is none. A sealed ERROR carries no code or detail
/// of its own; both travel sealed.
pub fn error_plain(code: &str, detail: &str) -> Vec<u8> {
    encode(vec![Value::text(code), Value::text(detail)])
}

/// A sealed ERROR's opened plaintext as its code and detail. An empty detail
/// is none.
pub fn open_error_plain(plain: &[u8]) -> Result<(String, Option<String>), SealError> {
    match cbor::decode(plain) {
        Ok(Value::List(items)) => match items.as_slice() {
            [Value::Text(code), Value::Text(detail)]
                if code.len() <= MAX_ERROR_CODE_BYTES && detail.len() <= MAX_ERROR_DETAIL_BYTES =>
            {
                Ok((code.clone(), (!detail.is_empty()).then(|| detail.clone())))
            }
            _ => Err(SealError::NotAnErrorPlain),
        },
        _ => Err(SealError::NotAnErrorPlain),
    }
}

// HKDF-SHA-384 (RFC 5869), from HMAC-SHA-384: the PRK itself is a value the
// vectors pin (`ss`), so it is computed as bytes.

fn extract(salt: &[u8], ikm: &[u8]) -> [u8; KEY_HASH_SIZE] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA384, salt), ikm);
    let mut prk = [0; KEY_HASH_SIZE];
    prk.copy_from_slice(tag.as_ref());
    prk
}

/// HKDF-Expand to 64 bytes: two HMAC-SHA-384 blocks, of which the second is
/// cut to 16.
fn expand(prk: &[u8; KEY_HASH_SIZE], info: &[u8]) -> [u8; 64] {
    let key = hmac::Key::new(hmac::HMAC_SHA384, prk);
    let mut okm = [0; 64];
    let mut previous: Vec<u8> = Vec::new();
    for (counter, chunk) in (1u8..).zip(okm.chunks_mut(KEY_HASH_SIZE)) {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&previous);
        ctx.update(info);
        ctx.update(&[counter]);
        previous = ctx.sign().as_ref().to_vec();
        chunk.copy_from_slice(&previous[..chunk.len()]);
    }
    okm
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// The CBOR array of the items in the crate's encoding, which for arrays of
/// byte strings, text and unsigned integers is RFC 8949's core
/// deterministic one.
fn encode(items: Vec<Value>) -> Vec<u8> {
    cbor::encode(&Value::List(items)).expect("seal arrays hold no integer outside u64")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod vectors;
