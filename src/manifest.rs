//! Content manifests as macula 12's macula_manifest builds them, byte for
//! byte: fixed-size chunks (256 KiB by default), SHA-384 hashes, a 50-byte
//! content id `<<2, Codec, SHA-384>>` (tag 2 names SHA-384, D24; codec 0x55 a
//! raw block, 0x56 a manifest), and a Merkle fold that pairs an odd last hash
//! with itself.
//!
//! A manifest's name has two encodings that must not be confused: its
//! content id hashes the name as CBOR text, while the wire form a manifest
//! travels in carries it as a byte string.

use std::fmt;

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};

/// 256 KiB, macula_manifest's default chunk size.
pub const DEFAULT_CHUNK_SIZE: u64 = 262_144;

/// A SHA-384 digest's length.
pub const HASH_SIZE: usize = 48;

/// A content id: `<<Tag:8, Codec:8, Hash:48/binary>>`.
pub type Mcid = [u8; 50];

/// A SHA-384 digest.
pub type Hash = [u8; HASH_SIZE];

/// The one hash algorithm a manifest names.
pub const SHA384: &str = "sha384";

const VERSION: u32 = 1;
const TAG_SHA384: u8 = 2;
const CODEC_RAW: u8 = 0x55;
const CODEC_MANIFEST: u8 = 0x56;

/// One chunk of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkInfo {
    pub index: u64,
    pub offset: u64,
    pub size: u64,
    pub hash: Hash,
}

/// A chunked content's manifest. `name` is bytes, as the wire carries it, and
/// `hash_algorithm` the wire's own text: a manifest read from a peer may name
/// anything, and [`verify_mcid`] refuses what is not a UTF-8 name and sha384.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub mcid: Mcid,
    pub version: u32,
    pub name: Vec<u8>,
    pub size: u64,
    /// Unix seconds.
    pub created: u64,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub hash_algorithm: String,
    pub root_hash: Hash,
    pub chunks: Vec<ChunkInfo>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// A chunk size of zero.
    ChunkSizeZero,
    /// Content that does not match the manifest, and how.
    ContentMismatch(String),
    /// A manifest that does not describe the content id it was asked for by.
    McidMismatch,
    /// A manifest whose chunks do not describe its content whole, and where.
    NotWhole(String),
    /// A manifest whose chunk hashes do not make its root hash.
    ChunkHashes,
    /// A wire form that is not a manifest, and why.
    Malformed(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::ChunkSizeZero => f.write_str("a chunk size of zero"),
            ManifestError::ContentMismatch(why) => {
                write!(f, "the content does not match the manifest: {why}")
            }
            ManifestError::McidMismatch => {
                f.write_str("the manifest does not describe the content id")
            }
            ManifestError::NotWhole(why) => write!(
                f,
                "the manifest's chunks do not describe its content whole: {why}"
            ),
            ManifestError::ChunkHashes => {
                f.write_str("the manifest's chunk hashes do not make its root hash")
            }
            ManifestError::Malformed(why) => write!(f, "not a manifest: {why}"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn sha384(data: &[u8]) -> Hash {
    Sha384::digest(data).into()
}

fn make_mcid(codec: u8, hash: &Hash) -> Mcid {
    let mut out = [0u8; 50];
    out[0] = TAG_SHA384;
    out[1] = codec;
    out[2..].copy_from_slice(hash);
    out
}

/// Splits `data` into chunks of `chunk_size` bytes and builds its manifest,
/// created now; returns it with the chunks in order.
pub fn create(
    data: &[u8],
    name: &str,
    chunk_size: u64,
) -> Result<(Manifest, Vec<Vec<u8>>), ManifestError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    create_at(data, name, chunk_size, now)
}

/// [`create`] with the manifest's creation time given, in unix seconds.
pub fn create_at(
    data: &[u8],
    name: &str,
    chunk_size: u64,
    created: u64,
) -> Result<(Manifest, Vec<Vec<u8>>), ManifestError> {
    if chunk_size == 0 {
        return Err(ManifestError::ChunkSizeZero);
    }
    let chunks: Vec<Vec<u8>> = data
        .chunks(chunk_size as usize)
        .map(<[u8]>::to_vec)
        .collect();
    let infos = chunk_infos(&chunks);
    let root_hash = root_hash_for(&infos);
    let mut m = Manifest {
        mcid: [0; 50],
        version: VERSION,
        name: name.as_bytes().to_vec(),
        size: data.len() as u64,
        created,
        chunk_size,
        chunk_count: infos.len() as u64,
        hash_algorithm: SHA384.into(),
        root_hash,
        chunks: infos,
    };
    m.mcid = mcid_for(&m);
    Ok((m, chunks))
}

/// The content id chunk `index` is stored and fetched under: the block id of
/// its bytes, which a sharer derives from the manifest alone.
pub fn chunk_mcid(m: &Manifest, index: usize) -> Option<Mcid> {
    m.chunks.get(index).map(|c| make_mcid(CODEC_RAW, &c.hash))
}

/// The content id of a single block: `<<2, 0x55, SHA-384(data)>>`.
pub fn block_mcid(data: &[u8]) -> Mcid {
    make_mcid(CODEC_RAW, &sha384(data))
}

/// Whether a content id names a manifest (chunked content) rather than a
/// single block, read from its codec byte.
pub fn mcid_is_chunked(mcid: &Mcid) -> bool {
    mcid[1] == CODEC_MANIFEST
}

/// The content id the manifest's canonical fields describe: its name, size,
/// chunk size and count, hash algorithm and root hash. Its creation time and
/// chunk list are not part of it.
pub fn mcid_for(m: &Manifest) -> Mcid {
    let canonical = Value::Map(vec![
        (
            Value::text("name"),
            Value::text(String::from_utf8_lossy(&m.name)),
        ),
        (Value::text("size"), Value::Int(i128::from(m.size))),
        (
            Value::text("chunk_size"),
            Value::Int(i128::from(m.chunk_size)),
        ),
        (
            Value::text("chunk_count"),
            Value::Int(i128::from(m.chunk_count)),
        ),
        (
            Value::text("hash_algorithm"),
            Value::text(m.hash_algorithm.clone()),
        ),
        (Value::text("root_hash"), Value::Bytes(m.root_hash.to_vec())),
    ]);
    let encoded = cbor::encode(&canonical).expect("a manifest's canonical fields always encode");
    make_mcid(CODEC_MANIFEST, &sha384(&encoded))
}

/// Whether `m` describes `mcid`, as macula_manifest's verify_mcid/2 checks:
/// a UTF-8 name, sha384, and the content id its canonical fields recompute
/// to. The manifest's own `mcid` field is not consulted.
pub fn verify_mcid(m: &Manifest, mcid: &Mcid) -> Result<(), ManifestError> {
    if std::str::from_utf8(&m.name).is_err() || m.hash_algorithm != SHA384 || mcid_for(m) != *mcid {
        return Err(ManifestError::McidMismatch);
    }
    Ok(())
}

/// Checks reassembled `data` against `m`: its size, then a root hash over
/// `data` cut the same way.
pub fn verify(m: &Manifest, data: &[u8]) -> Result<(), ManifestError> {
    if m.chunk_size == 0 {
        return Err(ManifestError::ChunkSizeZero);
    }
    if data.len() as u64 != m.size {
        return Err(ManifestError::ContentMismatch(format!(
            "{} bytes, the manifest's {}",
            data.len(),
            m.size
        )));
    }
    let chunks: Vec<Vec<u8>> = data
        .chunks(m.chunk_size as usize)
        .map(<[u8]>::to_vec)
        .collect();
    if root_hash_for(&chunk_infos(&chunks)) != m.root_hash {
        return Err(ManifestError::ContentMismatch("another root hash".into()));
    }
    Ok(())
}

/// Checks that `m`'s chunks describe its content whole, cut as [`create`]
/// cuts it: a positive chunk size, ceil(size / chunk size) chunks, which is
/// its chunk count, chunk i at offset i × chunk size and chunk size long but
/// for the last, which holds what is left, between 1 and chunk size bytes.
pub fn check_whole(m: &Manifest) -> Result<(), ManifestError> {
    let wanted = if m.chunk_size == 0 {
        None
    } else {
        Some(m.size.div_ceil(m.chunk_size))
    };
    if wanted != Some(m.chunk_count) || m.chunk_count != m.chunks.len() as u64 {
        return Err(ManifestError::NotWhole(format!(
            "chunk size {}, size {}, {} chunks counted, {} listed",
            m.chunk_size,
            m.size,
            m.chunk_count,
            m.chunks.len()
        )));
    }
    for (i, c) in m.chunks.iter().enumerate() {
        let offset = i as u64 * m.chunk_size;
        let size = m.chunk_size.min(m.size - offset);
        if c.index != i as u64 || c.offset != offset || c.size != size {
            return Err(ManifestError::NotWhole(format!("chunk {i}")));
        }
    }
    Ok(())
}

/// Checks that `m`'s chunk hashes make its root hash. The root hash is part
/// of the content id and the chunk hashes are not, so after [`verify_mcid`]
/// this is what ties each chunk, fetched by its hash, to the content id.
pub fn check_chunk_hashes(m: &Manifest) -> Result<(), ManifestError> {
    if root_hash_for(&m.chunks) != m.root_hash {
        return Err(ManifestError::ChunkHashes);
    }
    Ok(())
}

fn chunk_infos(chunks: &[Vec<u8>]) -> Vec<ChunkInfo> {
    let mut offset = 0u64;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let info = ChunkInfo {
                index: i as u64,
                offset,
                size: chunk.len() as u64,
                hash: sha384(chunk),
            };
            offset += chunk.len() as u64;
            info
        })
        .collect()
}

/// The Merkle root: pairs from the front, hash(left || right), an odd last
/// hash paired with itself, until one is left; SHA-384 of nothing for no
/// chunks.
fn root_hash_for(infos: &[ChunkInfo]) -> Hash {
    let mut level: Vec<Hash> = infos.iter().map(|c| c.hash).collect();
    if level.is_empty() {
        return sha384(&[]);
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                sha384(&[pair[0].as_slice(), right.as_slice()].concat())
            })
            .collect();
    }
    level[0]
}

/// The manifest as it travels: the name as a byte string.
pub fn to_wire(m: &Manifest) -> Value {
    let chunks = m
        .chunks
        .iter()
        .map(|c| {
            Value::Map(vec![
                (Value::text("index"), Value::Int(i128::from(c.index))),
                (Value::text("offset"), Value::Int(i128::from(c.offset))),
                (Value::text("size"), Value::Int(i128::from(c.size))),
                (Value::text("hash"), Value::Bytes(c.hash.to_vec())),
            ])
        })
        .collect();
    Value::Map(vec![
        (Value::text("mcid"), Value::Bytes(m.mcid.to_vec())),
        (Value::text("version"), Value::Int(i128::from(m.version))),
        (Value::text("name"), Value::Bytes(m.name.clone())),
        (Value::text("size"), Value::Int(i128::from(m.size))),
        (Value::text("created"), Value::Int(i128::from(m.created))),
        (
            Value::text("chunk_size"),
            Value::Int(i128::from(m.chunk_size)),
        ),
        (
            Value::text("chunk_count"),
            Value::Int(i128::from(m.chunk_count)),
        ),
        (
            Value::text("hash_algorithm"),
            Value::text(m.hash_algorithm.clone()),
        ),
        (Value::text("root_hash"), Value::Bytes(m.root_hash.to_vec())),
        (Value::text("chunks"), Value::List(chunks)),
    ])
}

/// A manifest read from its wire form, as macula_manifest's from_wire/1
/// reads it. One that names another hash algorithm than sha384 (as text or
/// bytes), whose chunks do not describe its content whole, or holding a
/// number outside its field, is refused. Nothing is allocated from the size
/// or count it claims: only the chunks it lists are read.
pub fn from_wire(v: &Value) -> Result<Manifest, ManifestError> {
    let chunks = match v.get("chunks") {
        Some(Value::List(items)) => items
            .iter()
            .map(chunk_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(malformed("chunks")),
    };
    let m = Manifest {
        mcid: bytes_exact(v, "mcid")?,
        version: u32::try_from(uint(v, "version")?).map_err(|_| malformed("version"))?,
        name: match v.get("name") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(malformed("name")),
        },
        size: uint(v, "size")?,
        created: uint(v, "created")?,
        chunk_size: uint(v, "chunk_size")?,
        chunk_count: uint(v, "chunk_count")?,
        hash_algorithm: match v.get("hash_algorithm") {
            Some(Value::Text(t)) if t == SHA384 => SHA384.into(),
            Some(Value::Bytes(b)) if b == SHA384.as_bytes() => SHA384.into(),
            _ => return Err(malformed("hash_algorithm")),
        },
        root_hash: bytes_exact(v, "root_hash")?,
        chunks,
    };
    check_whole(&m)?;
    Ok(m)
}

fn chunk_from_wire(v: &Value) -> Result<ChunkInfo, ManifestError> {
    Ok(ChunkInfo {
        index: uint(v, "index")?,
        offset: uint(v, "offset")?,
        size: uint(v, "size")?,
        hash: bytes_exact(v, "hash")?,
    })
}

fn malformed(field: &str) -> ManifestError {
    ManifestError::Malformed(format!("field {field:?} is missing or of the wrong type"))
}

/// A field that is an integer between 0 and 2^63 - 1.
fn uint(v: &Value, field: &str) -> Result<u64, ManifestError> {
    match v.get(field) {
        Some(Value::Int(n)) if (0..=i128::from(i64::MAX)).contains(n) => Ok(*n as u64),
        _ => Err(malformed(field)),
    }
}

fn bytes_exact<const N: usize>(v: &Value, field: &str) -> Result<[u8; N], ManifestError> {
    match v.get(field) {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| malformed(field)),
        _ => Err(malformed(field)),
    }
}
