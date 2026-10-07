//! Node-served content through the pool (D27): a node keeps what it shares,
//! serves it on its own `~<node_id>/content_v1` server stream and announces it
//! in the DHT; a fetcher finds the announcements, dials each sharer's station
//! and checks everything it receives against the content id it asked for. No
//! realm key is needed on either side. Ported from macula-go v0.12.0's
//! content tests.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::lab::{Lab, LabStation};
use macula_rust::cbor::Value;
use macula_rust::frame::StreamMode;
use macula_rust::manifest::{
    self, block_mcid, chunk_mcid, mcid_is_chunked, Mcid, DEFAULT_CHUNK_SIZE,
};
use macula_rust::node_key::{NodeKey, PUZZLE_DIFFICULTY};
use macula_rust::pool::{
    content_procedure_bound, ContentOptions, Offer, Opts, Pool, PoolError, CONTENT_PROCEDURE,
};
use macula_rust::profile::Profile;
use macula_rust::record::{self, new_content_announcement, ContentAnnouncementOptions};
use macula_rust::station_link::stream_handler;

const REALM: [u8; 32] = [0x0c; 32];

fn key() -> Arc<NodeKey> {
    Arc::new(NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).unwrap())
}

/// A pool as `key` on one station, trusting no realm.
async fn connect(key: &Arc<NodeKey>, s: &LabStation) -> Pool {
    let mut opts = Opts::new(key.clone());
    opts.respawn_delay = Duration::from_millis(100);
    opts.connect_timeout = Duration::from_secs(15);
    Pool::connect(vec![s.seed()], opts).await.unwrap()
}

/// A sharer on one station and a fetcher on another, the two sharing a DHT.
async fn content_pools(lab: &Lab, name: &str) -> (Pool, Pool, LabStation, LabStation) {
    let sharing = lab.station(&format!("{name} sharing"));
    let fetching = lab.station(&format!("{name} fetching"));
    lab.share(&[&sharing, &fetching]);
    let sharer = connect(&key(), &sharing).await;
    let fetcher = connect(&key(), &fetching).await;
    (sharer, fetcher, sharing, fetching)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn block_body(mcid: &[u8], bytes: &[u8]) -> Value {
    Value::Map(vec![
        (Value::text("kind"), Value::text("block")),
        (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
        (Value::text("bytes"), Value::Bytes(bytes.to_vec())),
    ])
}

fn manifest_body(mcid: &Mcid, m: &manifest::Manifest) -> Value {
    Value::Map(vec![
        (Value::text("kind"), Value::text("manifest")),
        (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
        (Value::text("manifest"), manifest::to_wire(m)),
    ])
}

/// Announces `mcid` as shared by `key`'s node on `procedure`, served through
/// `station`.
async fn announce(pool: &Pool, key: &NodeKey, mcid: &Mcid, station: &LabStation, procedure: &str) {
    let unsigned = new_content_announcement(
        &key.node_id().unwrap(),
        mcid,
        &ContentAnnouncementOptions {
            realm_id: REALM,
            serving_station: station.node_id,
            procedure: procedure.to_string(),
            ..ContentAnnouncementOptions::default()
        },
    )
    .unwrap();
    let wire = record::encode(&record::sign(&unsigned, key).unwrap()).unwrap();
    pool.put_record(&wire).await.unwrap();
}

/// A node on `station` that serves, on its own content procedure, whatever
/// `answer` gives for a fetch's want and content id, and announces `mcid` as
/// shared there. Returns its pool, kept alive by the caller.
async fn liar_for(
    station: &LabStation,
    mcid: &Mcid,
    answer: impl Fn(String, Vec<u8>) -> Value + Send + Sync + 'static,
) -> Pool {
    let k = key();
    let liar = connect(&k, station).await;
    let own = record::own_procedure(&liar.node_id(), CONTENT_PROCEDURE);
    let answer = Arc::new(answer);
    liar.serve(Offer::stream(
        REALM,
        &own,
        StreamMode::ServerStream,
        stream_handler(move |s| {
            let answer = answer.clone();
            async move {
                let payload = s.request().payload.clone();
                let want = match payload.get("want") {
                    Some(Value::Text(t)) => t.clone(),
                    _ => String::new(),
                };
                let asked = match payload.get("mcid") {
                    Some(Value::Bytes(b)) => b.clone(),
                    _ => Vec::new(),
                };
                s.send_value(answer(want, asked))
                    .await
                    .map_err(|e| e.to_string())?;
                s.close().await.map_err(|e| e.to_string())
            }
        }),
    ))
    .await
    .unwrap();
    announce(&liar, &k, mcid, station, &own).await;
    liar
}

/// A liar's answer with another content's manifest `m` under `mcid`, then
/// that content's chunks.
fn another_content_answer(
    mcid: &Mcid,
    m: &manifest::Manifest,
    chunks: &[Vec<u8>],
    want: &str,
    asked: &[u8],
) -> Value {
    if want == "root" {
        return manifest_body(mcid, m);
    }
    block_body(asked, &chunk_of(m, chunks, asked))
}

/// A liar's answer with the right manifest `m`, then its chunks with their
/// first byte changed, each one asked for counted.
fn altered_chunk_answer(
    m: &manifest::Manifest,
    chunks: &[Vec<u8>],
    counter: &AtomicUsize,
    want: &str,
    asked: &[u8],
) -> Value {
    if want == "root" {
        return manifest_body(&m.mcid, m);
    }
    counter.fetch_add(1, Ordering::SeqCst);
    let mut b = chunk_of(m, chunks, asked);
    b[0] ^= 0xff;
    block_body(asked, &b)
}

fn chunk_of(m: &manifest::Manifest, chunks: &[Vec<u8>], asked: &[u8]) -> Vec<u8> {
    (0..chunks.len())
        .find(|i| chunk_mcid(m, *i).is_some_and(|c| c.as_slice() == asked))
        .map(|i| chunks[i].clone())
        .unwrap_or_default()
}

async fn within(limit: Duration, what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("not within {limit:?}: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn content_is_fetched_from_the_node_that_shares_it() {
    let lab = Lab::start(Profile::PqPure);
    let (sharer, fetcher, sharing, _) = content_pools(&lab, "content").await;
    for (name, data) in [
        ("a raw block", pattern(10_000)),
        ("a chunked blob", pattern(600_000)),
    ] {
        let mcid = sharer
            .share_content(&REALM, &data, "blob.bin")
            .await
            .unwrap();
        assert_eq!(
            mcid_is_chunked(&mcid),
            data.len() as u64 > DEFAULT_CHUNK_SIZE,
            "{name}: chunked"
        );
        let got = fetcher
            .get_content(&REALM, &mcid, ContentOptions::default())
            .await
            .unwrap();
        assert!(got == data, "{name}: {} bytes back", got.len());
        assert!(
            lab.connected(&sharing, &fetcher.node_id()),
            "{name}: the fetcher dialed the sharer's station"
        );
        sharer.unshare_content(&REALM, &mcid).await.unwrap();
        let after = fetcher
            .get_content(&REALM, &mcid, ContentOptions::default())
            .await;
        assert!(
            matches!(after, Err(PoolError::NotShared)),
            "{name}: after unsharing {after:?}"
        );
    }
    let never = fetcher
        .get_content(
            &[0x0d; 32],
            &block_mcid(b"never shared"),
            ContentOptions::default(),
        )
        .await;
    assert!(matches!(never, Err(PoolError::NotShared)), "{never:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_refuses_content_over_its_bounds() {
    let lab = Lab::start(Profile::PqPure);
    let (sharer, fetcher, _, _) = content_pools(&lab, "bounds").await;
    let mcid = sharer
        .share_content(&REALM, &pattern(600_000), "big.bin")
        .await
        .unwrap();
    let bytes = ContentOptions {
        max_bytes: 500_000,
        ..ContentOptions::default()
    };
    let refused = fetcher.get_content(&REALM, &mcid, bytes).await;
    assert!(
        matches!(&refused, Err(PoolError::ContentUnavailable(tried)) if matches!(tried[0].1, PoolError::ContentTooLarge(_))),
        "{refused:?}"
    );
    let chunks = ContentOptions {
        max_chunks: 2,
        ..ContentOptions::default()
    };
    let refused = fetcher.get_content(&REALM, &mcid, chunks).await;
    assert!(
        matches!(&refused, Err(PoolError::ContentUnavailable(tried)) if matches!(tried[0].1, PoolError::ContentTooLarge(_))),
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_a_sharer_says_is_trusted() {
    let lab = Lab::start(Profile::PqPure);
    let (_, fetcher, sharing, _) = content_pools(&lab, "liar").await;
    let asked = b"the content asked for";
    let mcid = block_mcid(asked);
    let wanted = mcid;
    let liar_key = key();
    let liar = connect(&liar_key, &sharing).await;
    let own = record::own_procedure(&liar.node_id(), CONTENT_PROCEDURE);
    liar.serve(Offer::stream(
        REALM,
        &own,
        StreamMode::ServerStream,
        stream_handler(move |s| async move {
            s.send_value(block_body(&wanted, b"something else"))
                .await
                .map_err(|e| e.to_string())?;
            s.close().await.map_err(|e| e.to_string())
        }),
    ))
    .await
    .unwrap();
    // An announcement pointing at another node's procedure is never tried.
    announce(
        &liar,
        &liar_key,
        &mcid,
        &sharing,
        &record::own_procedure(&fetcher.node_id(), CONTENT_PROCEDURE),
    )
    .await;
    let got = fetcher
        .get_content(&REALM, &mcid, ContentOptions::default())
        .await;
    assert!(matches!(got, Err(PoolError::NotShared)), "{got:?}");
    // A sharer answering with other bytes is refused.
    announce(&liar, &liar_key, &mcid, &sharing, &own).await;
    let got = fetcher
        .get_content(&REALM, &mcid, ContentOptions::default())
        .await;
    assert!(
        matches!(&got, Err(PoolError::ContentUnavailable(tried)) if matches!(tried[0].1, PoolError::ContentMismatch(_))),
        "{got:?}"
    );
}

#[test]
fn a_content_procedure_is_bound_to_its_announcer() {
    let mut node = [0u8; 32];
    node[0] = 0xab;
    let hex_node = format!("ab{}", "00".repeat(31));
    let cases = [
        (format!("~{hex_node}/content_v1"), true),
        (format!("acme/content_v1_{hex_node}"), true),
        (format!("~{}/content_v1", hex_node.to_uppercase()), false),
        (format!("~{hex_node}/content_v2"), false),
        (format!("acme/content_v1_{}", "cd".repeat(32)), false),
        (format!("/content_v1_{hex_node}"), false),
        (format!("_/content_v1_{hex_node}"), false),
        (format!("~x/content_v1_{hex_node}"), false),
        (format!("acme/sub/content_v1_{hex_node}"), false),
    ];
    for (procedure, want) in cases {
        assert_eq!(
            content_procedure_bound(&procedure, &node),
            want,
            "{procedure}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_announcement_names_where_the_content_is_served_and_streams_are_released() {
    let lab = Lab::start(Profile::PqPure);
    let (sharer, fetcher, sharing, fetching) = content_pools(&lab, "announce").await;
    let mcid = sharer
        .share_content(&REALM, &pattern(300_000), "two.bin")
        .await
        .unwrap();
    let (found, _) = fetcher
        .find_records(&record::content_key(&mcid).unwrap())
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    let a = record::read_content_announcement(found[0].record()).unwrap();
    assert_eq!(a.announcer_node, sharer.node_id());
    assert_eq!(a.realm_id, REALM);
    assert_eq!(a.serving_station, sharing.node_id);
    assert_eq!(
        a.procedure,
        record::own_procedure(&sharer.node_id(), CONTENT_PROCEDURE)
    );
    assert_eq!(a.chunk_count, Some(2));
    let one_at_a_time = ContentOptions {
        parallel: 1,
        ..ContentOptions::default()
    };
    fetcher
        .get_content(&REALM, &mcid, one_at_a_time)
        .await
        .unwrap();
    within(
        Duration::from_secs(2),
        "every content stream released",
        || lab.relayed(&sharing) == 0 && lab.relayed(&fetching) == 0,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_manifest_and_its_chunks_are_checked_against_their_content_ids() {
    let lab = Lab::start(Profile::PqPure);
    let (_, fetcher, sharing, _) = content_pools(&lab, "manifests").await;
    let (real, real_chunks) =
        manifest::create(&pattern(600_000), "real.bin", DEFAULT_CHUNK_SIZE).unwrap();
    let (other, other_chunks) = manifest::create(
        &pattern(700_000)[100_000..],
        "other.bin",
        DEFAULT_CHUNK_SIZE,
    )
    .unwrap();

    // Another content's manifest for this content id.
    let (real_mcid, other_m) = (real.mcid, other.clone());
    let _first = liar_for(&sharing, &real.mcid, move |want, asked| {
        another_content_answer(&real_mcid, &other_m, &other_chunks, &want, &asked)
    })
    .await;
    let got = fetcher
        .get_content(&REALM, &real.mcid, ContentOptions::default())
        .await;
    assert!(
        matches!(&got, Err(PoolError::ContentUnavailable(tried)) if matches!(&tried[0].1, PoolError::ContentMismatch(why) if why.contains("manifest"))),
        "{got:?}"
    );

    // The right manifest, then chunks that are not theirs: the first one ends
    // the fetch, before another is asked for.
    let asked_count = Arc::new(AtomicUsize::new(0));
    let (counter, real_m) = (asked_count.clone(), real.clone());
    let _second = liar_for(&sharing, &real.mcid, move |want, asked| {
        altered_chunk_answer(&real_m, &real_chunks, &counter, &want, &asked)
    })
    .await;
    let one_at_a_time = ContentOptions {
        parallel: 1,
        ..ContentOptions::default()
    };
    let got = fetcher.get_content(&REALM, &real.mcid, one_at_a_time).await;
    let chunk_mismatch = |tried: &Vec<(_, PoolError)>| {
        tried
            .iter()
            .any(|(_, e)| matches!(e, PoolError::ContentMismatch(why) if why.contains("chunk")))
    };
    assert!(
        matches!(&got, Err(PoolError::ContentUnavailable(tried)) if chunk_mismatch(tried)),
        "{got:?}"
    );
    assert_eq!(
        asked_count.load(Ordering::SeqCst),
        1,
        "chunks asked for after the first did not match"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn content_is_fetched_only_in_the_realm_it_is_shared_in() {
    let lab = Lab::start(Profile::PqPure);
    let (sharer, fetcher, _, _) = content_pools(&lab, "realms").await;
    let mcid = sharer
        .share_content(&REALM, &pattern(1_000), "r.bin")
        .await
        .unwrap();
    let got = fetcher
        .get_content(&[0x0d; 32], &mcid, ContentOptions::default())
        .await;
    assert!(matches!(got, Err(PoolError::NotShared)), "{got:?}");
}
