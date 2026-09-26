//! Content manifests as macula 12's macula_manifest builds them, byte for
//! byte (tests/vectors/manifest/erlang_manifests.json holds manifests macula
//! built): fixed-size chunks, SHA-384, a 50-byte content id, a Merkle fold
//! that pairs an odd last hash with itself, and the wire form a manifest
//! travels in. Ported from macula-go v0.12.0's manifest tests.

use macula_rust::cbor::{self, Value};
use macula_rust::manifest::{
    block_mcid, check_chunk_hashes, check_whole, chunk_mcid, create_at, from_wire, mcid_for,
    mcid_is_chunked, to_wire, verify, verify_mcid, ChunkInfo, Manifest, ManifestError,
    DEFAULT_CHUNK_SIZE,
};
use sha2::{Digest, Sha384};

const EMPTY_ROOT_HASH: &str =
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

fn sha384(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

fn made(data: &[u8], name: &str, chunk_size: u64) -> (Manifest, Vec<Vec<u8>>) {
    create_at(data, name, chunk_size, 1000).unwrap()
}

fn three_chunks() -> Manifest {
    made(
        &vec![1; 2 * DEFAULT_CHUNK_SIZE as usize + 3],
        "unnamed",
        DEFAULT_CHUNK_SIZE,
    )
    .0
}

fn edited(m: &Manifest, change: impl FnOnce(&mut Manifest)) -> Manifest {
    let mut c = m.clone();
    change(&mut c);
    c
}

fn with_own_mcid(mut m: Manifest) -> Manifest {
    m.mcid = mcid_for(&m);
    m
}

fn set_field(v: &Value, field: &str, value: Option<Value>) -> Value {
    let Value::Map(entries) = v else {
        panic!("a map")
    };
    let mut out: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| *k != Value::text(field))
        .cloned()
        .collect();
    if let Some(value) = value {
        out.push((Value::text(field), value));
    }
    Value::Map(out)
}

fn set_chunk_field(v: &Value, i: usize, field: &str, value: Value) -> Value {
    let Some(Value::List(chunks)) = v.get("chunks") else {
        panic!("chunks")
    };
    let mut changed = chunks.clone();
    changed[i] = set_field(&changed[i], field, Some(value));
    set_field(v, "chunks", Some(Value::List(changed)))
}

#[test]
fn a_single_block_s_mcid_is_the_block_s_sha384() {
    let data = b"small blob, single block";
    let got = block_mcid(data);
    let mut want = vec![2, 0x55];
    want.extend(sha384(data));
    assert_eq!(got.to_vec(), want);
    assert!(!mcid_is_chunked(&got));
}

#[test]
fn chunks_are_cut_at_the_chunk_size_with_no_empty_trailing_chunk() {
    let (m, chunks) = made(&[0x42; 20], "x", 10);
    assert_eq!((chunks.len(), m.chunk_count), (2, 2));
    assert!(chunks.iter().all(|c| c.len() == 10));
    let (m, chunks) = made(&[7; 25], "x", 10);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[2].len(), 5);
    assert_eq!(m.size, 25);
    assert!(
        create_at(b"x", "x", 0, 1000).is_err(),
        "a chunk size of zero"
    );
}

#[test]
fn a_manifest_s_mcid_is_chunked_and_a_block_s_is_not() {
    let (m, _) = made(&[1; 100], "x", 10);
    assert!(mcid_is_chunked(&m.mcid));
    assert!(!mcid_is_chunked(&block_mcid(&[1; 100])));
}

#[test]
fn a_chunk_s_mcid_is_the_block_mcid_of_the_chunk() {
    let (m, chunks) = made(&[9; 25], "x", 10);
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk_mcid(&m, i), Some(block_mcid(chunk)));
    }
    assert_eq!(chunk_mcid(&m, chunks.len()), None);
}

#[test]
fn an_odd_last_hash_is_paired_with_itself() {
    let (m, _) = made(&[3; 25], "x", 10);
    let fold = |l: &[u8; 48], r: &[u8; 48]| sha384(&[l.as_slice(), r.as_slice()].concat());
    let (h0, h1, h2) = (m.chunks[0].hash, m.chunks[1].hash, m.chunks[2].hash);
    assert_eq!(m.root_hash, fold(&fold(&h0, &h1), &fold(&h2, &h2)));
}

#[test]
fn verify_accepts_the_content_and_refuses_tampering() {
    let data = vec![5u8; 1000];
    let (m, _) = made(&data, "x", 300);
    verify(&m, &data).unwrap();
    let mut tampered = data.clone();
    tampered[500] ^= 0xFF;
    assert!(verify(&m, &tampered).is_err());
    assert!(verify(&m, &data[..999]).is_err());
    let zero = edited(&m, |c| c.chunk_size = 0);
    assert!(verify(&zero, &data).is_err(), "a chunk size of zero");
}

#[test]
fn the_wire_form_round_trips_with_the_name_as_bytes() {
    let data: Vec<u8> = [0x11, 0x22].repeat(500);
    let (m, _) = create_at(&data, "my-file.bin", 300, 1_700_000_000).unwrap();
    let wire = to_wire(&m);
    assert_eq!(
        wire.get("name"),
        Some(&Value::Bytes(b"my-file.bin".to_vec()))
    );
    assert_eq!(from_wire(&wire).unwrap(), m);
}

#[test]
fn verify_mcid_checks_the_fields_macula_checks() {
    let m = three_chunks();
    let not_utf8 = with_own_mcid(edited(&m, |c| c.name = vec![0xff, 0xfe]));
    let unknown = with_own_mcid(edited(&m, |c| c.hash_algorithm = "sha256".into()));
    let cases: Vec<(&str, Manifest, [u8; 50], bool)> = vec![
        ("as created", m.clone(), m.mcid, true),
        (
            "another created time, version, own mcid and chunk list",
            edited(&m, |c| {
                c.created += 1;
                c.version = 9;
                c.mcid = [0; 50];
                c.chunks.clear();
            }),
            m.mcid,
            true,
        ),
        (
            "another name",
            edited(&m, |c| c.name = b"other".to_vec()),
            m.mcid,
            false,
        ),
        ("another size", edited(&m, |c| c.size += 1), m.mcid, false),
        (
            "another chunk count",
            edited(&m, |c| c.chunk_count += 1),
            m.mcid,
            false,
        ),
        (
            "another root hash",
            edited(&m, |c| c.root_hash[0] ^= 1),
            m.mcid,
            false,
        ),
        (
            "a name that isn't UTF-8",
            not_utf8.clone(),
            not_utf8.mcid,
            false,
        ),
        (
            "another hash algorithm",
            unknown.clone(),
            unknown.mcid,
            false,
        ),
    ];
    for (name, manifest, mcid, ok) in cases {
        let got = verify_mcid(&manifest, &mcid);
        assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
        if !ok {
            assert_eq!(got, Err(ManifestError::McidMismatch), "{name}");
        }
    }
}

#[test]
fn check_whole_refuses_chunks_that_do_not_describe_the_content_whole() {
    let m = three_chunks();
    let (empty, _) = made(&[], "unnamed", DEFAULT_CHUNK_SIZE);
    let cases: Vec<(&str, Manifest, bool)> = vec![
        ("as created", m.clone(), true),
        ("empty content, as created", empty, true),
        (
            "a chunk cut short before the last, with the count still right",
            edited(&m, |c| {
                c.chunks[0].size -= 1;
                c.chunks[1].offset -= 1;
                c.chunks[2].offset -= 1;
                c.chunks[2].size += 1;
            }),
            false,
        ),
        (
            "a chunk counted that isn't listed",
            edited(&m, |c| c.chunk_count += 1),
            false,
        ),
        (
            "chunks out of index order",
            edited(&m, |c| {
                c.chunks[0].index = 1;
                c.chunks[1].index = 0;
            }),
            false,
        ),
        (
            "a gap between chunks",
            edited(&m, |c| c.chunks[1].offset += 1),
            false,
        ),
        (
            "an empty chunk",
            edited(&m, |c| c.chunks[2].size = 0),
            false,
        ),
        (
            "a chunk larger than the chunk size",
            edited(&m, |c| c.chunks[2].size = c.chunk_size + 1),
            false,
        ),
        (
            "a size the chunks don't add up to",
            edited(&m, |c| c.size += 1),
            false,
        ),
        (
            "a chunk size of zero",
            edited(&m, |c| c.chunk_size = 0),
            false,
        ),
    ];
    for (name, manifest, whole) in cases {
        let got = check_whole(&manifest);
        assert_eq!(got.is_ok(), whole, "{name}: {got:?}");
        if !whole {
            assert!(
                matches!(got, Err(ManifestError::NotWhole(_))),
                "{name}: {got:?}"
            );
        }
    }
}

#[test]
fn chunk_hashes_must_make_the_root_hash() {
    let m = three_chunks();
    check_chunk_hashes(&m).unwrap();
    let swapped = edited(&m, |c| c.chunks.swap(0, 2));
    assert_eq!(
        check_chunk_hashes(&swapped),
        Err(ManifestError::ChunkHashes)
    );
}

#[test]
fn empty_content_has_one_whole_form() {
    let (empty, _) = made(&[], "unnamed", DEFAULT_CHUNK_SIZE);
    let back = from_wire(&to_wire(&empty)).unwrap();
    assert_eq!((back.size, back.chunk_count, back.chunks.len()), (0, 0, 0));
    assert!(back.chunk_size > 0);
    assert_eq!(hex::encode(back.root_hash), EMPTY_ROOT_HASH);
    verify_mcid(&back, &empty.mcid).unwrap();
    verify(&back, &[]).unwrap();
    let one_empty_chunk = edited(&empty, |c| {
        c.chunk_count = 1;
        c.chunks = vec![ChunkInfo {
            index: 0,
            offset: 0,
            size: 0,
            hash: c.root_hash,
        }];
    });
    assert!(matches!(
        from_wire(&to_wire(&one_empty_chunk)),
        Err(ManifestError::NotWhole(_))
    ));
}

#[test]
fn only_sha384_is_read_as_the_hash_algorithm() {
    let (m, _) = made(b"some content", "unnamed", DEFAULT_CHUNK_SIZE);
    let wire = to_wire(&m);
    let cases: Vec<(&str, Option<Value>, bool)> = vec![
        ("missing", None, false),
        ("sha384 as text", Some(Value::text("sha384")), true),
        (
            "sha384 as bytes",
            Some(Value::Bytes(b"sha384".to_vec())),
            true,
        ),
        ("blake3 as text", Some(Value::text("blake3")), false),
        ("sha256 as text", Some(Value::text("sha256")), false),
        (
            "sha256 as bytes",
            Some(Value::Bytes(b"sha256".to_vec())),
            false,
        ),
        ("an unknown name", Some(Value::text("md5")), false),
    ];
    for (name, value, ok) in cases {
        let got = from_wire(&set_field(&wire, "hash_algorithm", value));
        assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
        if let Ok(read) = got {
            assert_eq!(read.hash_algorithm, "sha384");
        }
    }
}

#[test]
fn a_number_too_large_for_its_field_is_refused() {
    let m = three_chunks();
    let wire = to_wire(&m);
    from_wire(&wire).unwrap();
    let past32 = |n: u64| Value::Int(i128::from(n) + (1 << 32));
    let last = m.chunks.last().unwrap().clone();
    let i = last.index as usize;
    let cases = [
        (
            "version",
            set_field(&wire, "version", Some(past32(u64::from(m.version)))),
        ),
        (
            "a chunk index",
            set_chunk_field(&wire, i, "index", past32(last.index)),
        ),
        (
            "a chunk offset",
            set_chunk_field(&wire, i, "offset", past32(last.offset)),
        ),
        (
            "a chunk size",
            set_chunk_field(&wire, i, "size", past32(last.size)),
        ),
        (
            "chunk_size",
            set_field(&wire, "chunk_size", Some(past32(m.chunk_size))),
        ),
        (
            "chunk_count",
            set_field(&wire, "chunk_count", Some(past32(m.chunk_count))),
        ),
    ];
    for (name, v) in cases {
        assert!(from_wire(&v).is_err(), "{name} plus 2^32 was accepted");
    }
    let negative = set_field(&wire, "size", Some(Value::Int(-1)));
    assert!(from_wire(&negative).is_err(), "a negative size");
    // created is read by nothing that checks it, so its own range is its only
    // guard.
    for created in [Value::Int(-1), Value::Int(i128::from(i64::MAX) + 1)] {
        let v = set_field(&wire, "created", Some(created.clone()));
        assert!(from_wire(&v).is_err(), "created {created:?}");
    }
}

#[test]
fn manifests_match_macula_s_byte_for_byte() {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/manifest/erlang_manifests.json"
    ))
    .unwrap();
    let fixture: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let text = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let pattern = |n: usize| (0..n).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    let manifests = fixture["manifests"].as_array().unwrap();
    assert_eq!(manifests.len(), 5);
    for want in manifests {
        let name = String::from_utf8(hex::decode(text(&want["name"])).unwrap()).unwrap();
        let size = want["size"].as_u64().unwrap() as usize;
        let chunk_size = want["chunk_size"].as_u64().unwrap();
        let (m, chunks) = create_at(&pattern(size), &name, chunk_size, 1_789_000_000).unwrap();
        assert_eq!(hex::encode(m.mcid), text(&want["mcid_hex"]), "{name}: mcid");
        assert_eq!(
            hex::encode(m.root_hash),
            text(&want["root_hex"]),
            "{name}: root"
        );
        let hashes = want["chunk_hashes"].as_array().unwrap();
        let mcids = want["chunk_mcids"].as_array().unwrap();
        assert_eq!(
            (chunks.len(), m.chunks.len()),
            (hashes.len(), hashes.len()),
            "{name}"
        );
        for (i, c) in m.chunks.iter().enumerate() {
            assert_eq!(
                hex::encode(c.hash),
                text(&hashes[i]),
                "{name}: chunk {i} hash"
            );
            assert_eq!(
                hex::encode(chunk_mcid(&m, i).unwrap()),
                text(&mcids[i]),
                "{name}: chunk {i} mcid"
            );
        }
        let wire = hex::decode(text(&want["wire_hex"])).unwrap();
        assert_eq!(
            hex::encode(cbor::encode(&to_wire(&m)).unwrap()),
            hex::encode(&wire),
            "{name}: wire"
        );
        let read = from_wire(&cbor::decode(&wire).unwrap()).unwrap();
        verify_mcid(&read, &read.mcid).unwrap();
        assert_eq!(read.mcid, m.mcid, "{name}: read back");
    }
    let block = block_mcid(&hex::decode(text(&fixture["block"]["data_hex"])).unwrap());
    assert_eq!(hex::encode(block), text(&fixture["block"]["mcid_hex"]));
}
