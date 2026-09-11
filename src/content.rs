//! Content sharing (§12 of `plans/PLAN_WIRE_PROTOCOL.md`): put/get by
//! content-address, over a dedicated QUIC stream — ordinary CALL/RESULT
//! (§6.4) against four well-known `_content.*` procedures, ported from
//! `macula_content_transfer.erl`. Not a separate wire protocol: nothing
//! here is new frame types, just calls a normal [`crate::connection::Session`]
//! could already make, sent on a stream opened via
//! [`Session::open_dedicated_stream`](crate::connection::Session::open_dedicated_stream)
//! instead of the control stream.
//!
//! **Deliberate v1 simplification (documented per spec §12.2):** chunked
//! transfers here run strictly sequentially, one `_content.put_block` /
//! `_content.get_block` in flight at a time on the single dedicated
//! stream this module opens — not the reference's parallel multi-lane
//! algorithm (round-robin chunks across up to 4 concurrent streams).
//! Multi-lane parallelism is a throughput optimization, not a
//! correctness requirement: every `_content.*` call, the MCID scheme,
//! and the manifest wire format are identical either way, so this v1
//! client interoperates fully with a station built to serve a
//! parallel-lane peer, and lanes can be added later purely as a
//! performance improvement with no wire change.
//!
//! Sequential retrieval has one incidental upside over the reference:
//! chunks arrive and get appended in index order for free, so there's no
//! need for the reference's "accumulate into a map keyed by index, then
//! reassemble" step.

use std::time::Duration;

use crate::bolt4;
use crate::cbor::Value;
use crate::connection::{FrameStream, Session, StreamCallError};
use crate::identity::KeyPair;
use crate::manifest::{self, Manifest, Mcid};

/// Reserved realm sentinel for all `_content.*` calls — 32 zero bytes,
/// distinct from any real realm (`plans/PLAN_WIRE_PROTOCOL.md` §12.1).
pub const CONTENT_REALM: [u8; 32] = [0u8; 32];

const PUT_BLOCK_PROC: &str = "_content.put_block";
const GET_BLOCK_PROC: &str = "_content.get_block";
const PUT_MANIFEST_PROC: &str = "_content.put_manifest";
const GET_MANIFEST_PROC: &str = "_content.get_manifest";

/// Matches `CONTENT_BLOCK_TIMEOUT_MS` in `macula_content_transfer.erl`.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(15);
/// Matches `CONTENT_MANIFEST_TIMEOUT_MS`.
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Matches §12.2's retry policy: up to 3 attempts total, 200ms backoff
/// between them, only for a BOLT#4 code flagged retryable (§9).
const MAX_ATTEMPTS: u32 = 3;
const RETRY_BACKOFF: Duration = Duration::from_millis(200);

#[derive(Debug)]
pub enum PutError {
    /// Opening the dedicated stream itself failed (e.g. the connection
    /// is already dead) — never got as far as making a call.
    OpenStream(quinn::ConnectionError),
    Call(StreamCallError),
    /// The station rejected the call with a BOLT#4 ERROR.
    Remote {
        code: u8,
        name: String,
        detail: Option<String>,
    },
    /// A RESULT arrived but its payload wasn't one of the shapes this
    /// procedure is documented to return.
    UnexpectedReply(Value),
    /// The station recomputed the block's hash and it didn't match the
    /// MCID the caller sent — the block was not stored.
    HashMismatch,
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::OpenStream(e) => write!(f, "opening a dedicated stream: {e}"),
            PutError::Call(e) => write!(f, "{e}"),
            PutError::Remote { code, name, detail } => {
                write!(f, "station returned error {code} ({name}): {detail:?}")
            }
            PutError::UnexpectedReply(v) => write!(f, "unexpected reply shape: {v:?}"),
            PutError::HashMismatch => write!(f, "station reported hash_mismatch"),
        }
    }
}

impl std::error::Error for PutError {}

#[derive(Debug)]
pub enum GetError {
    /// Opening the dedicated stream itself failed (e.g. the connection
    /// is already dead) — never got as far as making a call.
    OpenStream(quinn::ConnectionError),
    Call(StreamCallError),
    Remote {
        code: u8,
        name: String,
        detail: Option<String>,
    },
    UnexpectedReply(Value),
    NotFound,
    ManifestDecode(manifest::FromWireError),
    /// A fetched block or reassembled blob didn't hash to the MCID it
    /// was fetched under — see the module-level note in §12.1: a
    /// station may only be relaying content it doesn't itself store, so
    /// its answer is never trusted without this client-side check.
    HashMismatch,
    Verify(manifest::VerifyError),
}

impl std::fmt::Display for GetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetError::OpenStream(e) => write!(f, "opening a dedicated stream: {e}"),
            GetError::Call(e) => write!(f, "{e}"),
            GetError::Remote { code, name, detail } => {
                write!(f, "station returned error {code} ({name}): {detail:?}")
            }
            GetError::UnexpectedReply(v) => write!(f, "unexpected reply shape: {v:?}"),
            GetError::NotFound => write!(f, "station reported not_found"),
            GetError::ManifestDecode(e) => write!(f, "decoding the fetched manifest: {e}"),
            GetError::HashMismatch => write!(f, "fetched content does not hash to its MCID"),
            GetError::Verify(e) => write!(f, "reassembled content failed verification: {e}"),
        }
    }
}

impl std::error::Error for GetError {}

/// Store `data`, returning the MCID it's now addressable by.
///
/// `name` is attached to the manifest when `data` is large enough to be
/// chunked; a single block (`data.len() <= manifest::DEFAULT_CHUNK_SIZE`)
/// is addressed purely by content hash and carries no name at all,
/// matching `macula_content_transfer:put_single_block/3` — `name` is
/// silently unused on that path, not an oversight.
pub async fn put(
    session: &Session,
    data: &[u8],
    name: impl Into<String>,
    identity: &KeyPair,
) -> Result<Mcid, PutError> {
    let stream = session
        .open_dedicated_stream()
        .await
        .map_err(PutError::OpenStream)?;
    put_on(stream, data, name, identity).await
}

/// [`put`], over a dedicated stream already open to the station.
pub(crate) async fn put_on(
    mut stream: FrameStream,
    data: &[u8],
    name: impl Into<String>,
    identity: &KeyPair,
) -> Result<Mcid, PutError> {
    if data.len() <= manifest::DEFAULT_CHUNK_SIZE {
        let mcid = manifest::block_mcid(data);
        put_block(&mut stream, &mcid, data, identity).await?;
        return Ok(mcid);
    }

    let opts = manifest::CreateOptions {
        name: name.into(),
        ..manifest::CreateOptions::default()
    };
    let (manifest, chunks) = manifest::create(data, &opts);
    for (index, chunk) in chunks.iter().enumerate() {
        let chunk_mcid = manifest::chunk_mcid(&manifest, index)
            .expect("index is in range: it came from iterating manifest.create's own chunks");
        put_block(&mut stream, &chunk_mcid, chunk, identity).await?;
    }
    put_manifest(&mut stream, &manifest, identity).await?;
    Ok(manifest.mcid)
}

/// Fetch and verify the content addressed by `mcid`.
pub async fn get(
    session: &Session,
    mcid: Mcid,
    identity: &KeyPair,
) -> Result<Vec<u8>, GetError> {
    let stream = session
        .open_dedicated_stream()
        .await
        .map_err(GetError::OpenStream)?;
    get_on(stream, mcid, identity).await
}

/// [`get`], over a dedicated stream already open to the station.
pub(crate) async fn get_on(
    mut stream: FrameStream,
    mcid: Mcid,
    identity: &KeyPair,
) -> Result<Vec<u8>, GetError> {
    if !manifest::mcid_is_chunked(&mcid) {
        let data = get_block(&mut stream, &mcid, identity).await?;
        if manifest::block_mcid(&data) != mcid {
            return Err(GetError::HashMismatch);
        }
        return Ok(data);
    }

    let manifest = get_manifest(&mut stream, &mcid, identity).await?;
    // Deliberately NOT `Vec::with_capacity(manifest.size as usize)`:
    // `manifest.size` is a bare claim from whichever peer served this
    // manifest, unverified until every chunk is in hand and
    // `manifest::verify` runs below — a single small malicious manifest
    // could otherwise claim an enormous size and trigger an immediate,
    // unbounded allocation attempt before a single byte of real content
    // has been fetched. Growing the buffer as genuinely-received,
    // individually-hash-verified chunks arrive bounds memory use to
    // what has actually, legitimately come off the wire.
    let mut data = Vec::new();
    for index in 0..manifest.chunk_count {
        let chunk_mcid = manifest::chunk_mcid(&manifest, index)
            .expect("index < manifest.chunk_count, so manifest.chunks[index] exists");
        let chunk = get_block(&mut stream, &chunk_mcid, identity).await?;
        if manifest::block_mcid(&chunk) != chunk_mcid {
            return Err(GetError::HashMismatch);
        }
        data.extend_from_slice(&chunk);
    }
    manifest::verify(&manifest, &data).map_err(GetError::Verify)?;
    Ok(data)
}

async fn put_block(
    stream: &mut FrameStream,
    mcid: &Mcid,
    bytes: &[u8],
    identity: &KeyPair,
) -> Result<(), PutError> {
    let payload = Value::Map(vec![
        (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
        (Value::text("payload"), Value::Bytes(bytes.to_vec())),
    ]);
    let response = call_with_retry(stream, PUT_BLOCK_PROC, payload, BLOCK_TIMEOUT, identity)
        .await
        .map_err(PutError::Call)?;
    match response {
        crate::frame::CallResponse::Result { payload, .. } => match payload {
            Value::Text(t) if t == "ok" => Ok(()),
            Value::Text(t) if t == "hash_mismatch" => Err(PutError::HashMismatch),
            other => Err(PutError::UnexpectedReply(other)),
        },
        crate::frame::CallResponse::Error {
            code, name, detail, ..
        } => Err(PutError::Remote { code, name, detail }),
    }
}

async fn put_manifest(
    stream: &mut FrameStream,
    manifest: &Manifest,
    identity: &KeyPair,
) -> Result<(), PutError> {
    let payload = Value::Map(vec![(Value::text("manifest"), manifest::to_wire(manifest))]);
    let response = call_with_retry(
        stream,
        PUT_MANIFEST_PROC,
        payload,
        MANIFEST_TIMEOUT,
        identity,
    )
    .await
    .map_err(PutError::Call)?;
    match response {
        crate::frame::CallResponse::Result { payload, .. } => match payload {
            Value::Text(t) if t == "ok" => Ok(()),
            other => Err(PutError::UnexpectedReply(other)),
        },
        crate::frame::CallResponse::Error {
            code, name, detail, ..
        } => Err(PutError::Remote { code, name, detail }),
    }
}

async fn get_block(
    stream: &mut FrameStream,
    mcid: &Mcid,
    identity: &KeyPair,
) -> Result<Vec<u8>, GetError> {
    let payload = Value::Map(vec![(Value::text("mcid"), Value::Bytes(mcid.to_vec()))]);
    let response = call_with_retry(stream, GET_BLOCK_PROC, payload, BLOCK_TIMEOUT, identity)
        .await
        .map_err(GetError::Call)?;
    match response {
        crate::frame::CallResponse::Result { payload, .. } => match payload {
            Value::Bytes(b) => Ok(b),
            Value::Text(t) if t == "not_found" => Err(GetError::NotFound),
            other => Err(GetError::UnexpectedReply(other)),
        },
        crate::frame::CallResponse::Error {
            code, name, detail, ..
        } => Err(GetError::Remote { code, name, detail }),
    }
}

async fn get_manifest(
    stream: &mut FrameStream,
    mcid: &Mcid,
    identity: &KeyPair,
) -> Result<Manifest, GetError> {
    let payload = Value::Map(vec![(Value::text("mcid"), Value::Bytes(mcid.to_vec()))]);
    let response = call_with_retry(
        stream,
        GET_MANIFEST_PROC,
        payload,
        MANIFEST_TIMEOUT,
        identity,
    )
    .await
    .map_err(GetError::Call)?;
    match response {
        crate::frame::CallResponse::Result { payload, .. } => match payload {
            Value::Map(_) => manifest::from_wire(&payload).map_err(GetError::ManifestDecode),
            Value::Text(t) if t == "not_found" => Err(GetError::NotFound),
            other => Err(GetError::UnexpectedReply(other)),
        },
        crate::frame::CallResponse::Error {
            code, name, detail, ..
        } => Err(GetError::Remote { code, name, detail }),
    }
}

/// Send one `_content.*` CALL, retrying per §12.2's policy: up to
/// [`MAX_ATTEMPTS`] total, [`RETRY_BACKOFF`] between them, only when the
/// prior attempt's ERROR carries a BOLT#4 code flagged
/// [retryable](bolt4::Code::is_retryable). A non-retryable ERROR, or a
/// RESULT (whatever its payload turns out to mean to the caller), both
/// return on the first attempt.
async fn call_with_retry(
    stream: &mut FrameStream,
    procedure: &str,
    payload: Value,
    timeout: Duration,
    identity: &KeyPair,
) -> Result<crate::frame::CallResponse, StreamCallError> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let deadline_ms = (now_ms() + timeout.as_millis() as u64) as i128;
        let outcome = stream
            .call(
                procedure,
                CONTENT_REALM,
                payload.clone(),
                deadline_ms,
                identity,
                timeout,
            )
            .await;

        let should_retry = attempt < MAX_ATTEMPTS
            && matches!(
                &outcome,
                Ok(crate::frame::CallResponse::Error { code, .. })
                    if bolt4::Code::from_u8(*code).is_some_and(bolt4::Code::is_retryable)
            );
        if !should_retry {
            return outcome;
        }
        tokio::time::sleep(RETRY_BACKOFF).await;
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_data_addresses_as_a_single_block() {
        let data = vec![7u8; 100];
        assert!(data.len() <= manifest::DEFAULT_CHUNK_SIZE);
        let mcid = manifest::block_mcid(&data);
        assert!(!manifest::mcid_is_chunked(&mcid));
    }

    #[test]
    fn large_data_would_address_as_a_manifest() {
        let data = vec![7u8; manifest::DEFAULT_CHUNK_SIZE + 1];
        let opts = manifest::CreateOptions::default();
        let (manifest, chunks) = manifest::create(&data, &opts);
        assert!(chunks.len() > 1);
        assert!(manifest::mcid_is_chunked(&manifest.mcid));
    }

    #[test]
    fn call_with_retry_backoff_matches_the_spec() {
        assert_eq!(MAX_ATTEMPTS, 3);
        assert_eq!(RETRY_BACKOFF, Duration::from_millis(200));
    }
}
