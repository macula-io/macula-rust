//! Node-served content, as macula 12 has it (D27). A station keeps no
//! content: the node that shares content keeps it, serves it on a
//! server_stream procedure of its own, `~<node_id>/content_v1`, and announces
//! it in the DHT under the content id's key, naming the realm, the station it
//! is reachable through and that procedure. A fetcher finds the
//! announcements, dials each sharer's station from the station's own endpoint
//! record, and asks for the root and then each chunk, one stream each;
//! everything it receives is checked against the content id it asked for, so
//! it trusts no realm key and no sharer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::cbor::Value;
use crate::frame::StreamMode;
use crate::manifest::{self, block_mcid, chunk_mcid, Manifest, Mcid, DEFAULT_CHUNK_SIZE};
use crate::record::{
    self, new_content_announcement, ContentAnnouncementOptions, Reason, Record, RecordType,
    TombstoneOptions,
};
use crate::station_link::{
    self, stream_handler, Link, LinkError, Stream, StreamEvent, DEFAULT_CALL_TIMEOUT,
};

use super::{shuffle, Offer, Pool, PoolError, PoolInner, Served};

/// The content procedure's name in a sharer's own namespace.
pub const CONTENT_PROCEDURE: &str = "content_v1";

/// How long an announcement is signed for; it is renewed at half that.
const ANNOUNCEMENT_TTL: Duration = Duration::from_secs(60 * 60);

/// One DATA body holds at most one chunk.
const MAX_BLOCK_BYTES: u64 = DEFAULT_CHUNK_SIZE;

/// A fetch's bounds, macula_content_fetch's defaults: 256 MiB, 16,384
/// chunks, 4 chunk streams at a time, 15 seconds per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentOptions {
    pub max_bytes: u64,
    pub max_chunks: u64,
    pub parallel: usize,
    pub chunk_timeout: Duration,
}

impl Default for ContentOptions {
    fn default() -> Self {
        ContentOptions {
            max_bytes: 256 << 20,
            max_chunks: 16_384,
            parallel: 4,
            chunk_timeout: Duration::from_secs(15),
        }
    }
}

/// What a pool shares: per realm, the content it keeps (roots and chunks, by
/// content id), the served content procedure, and each root's latest signed
/// announcement.
#[derive(Default)]
pub(super) struct Sharer {
    realms: Mutex<HashMap<[u8; 32], SharedRealm>>,
    /// Serves one realm's content procedure at a time.
    serving: tokio::sync::Mutex<()>,
}

struct SharedRealm {
    _served: Served,
    roots: HashMap<Mcid, Root>,
    chunks: HashMap<Mcid, Vec<u8>>,
    announcements: HashMap<Mcid, Announced>,
}

#[derive(Clone)]
enum Root {
    Block(Vec<u8>),
    Chunked(Arc<Manifest>),
}

struct Announced {
    latest: Arc<Mutex<Record>>,
    stop: watch::Sender<bool>,
}

impl Sharer {
    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], SharedRealm>> {
        self.realms.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Whether `procedure` is `node`'s content procedure: `~<node>/content_v1`,
/// or `<org>/content_v1_<node>` under an org that is not empty, `_`, nor a
/// `~` namespace, each node as 64 lowercase hex, so an announcement cannot
/// point a fetch at another node's procedure.
pub fn content_procedure_bound(procedure: &str, node: &[u8; 32]) -> bool {
    let node_hex: String = node.iter().map(|b| format!("{b:02x}")).collect();
    if procedure == record::own_procedure(node, CONTENT_PROCEDURE) {
        return true;
    }
    match procedure.split_once('/') {
        Some((org, name)) => {
            !org.is_empty()
                && org != "_"
                && !org.starts_with(record::OWN_NAMESPACE_PREFIX)
                && name == format!("{CONTENT_PROCEDURE}_{node_hex}")
        }
        None => false,
    }
}

impl Pool {
    /// Keeps `data`, serves it on this node's content procedure in `realm`
    /// and announces it, renewing the announcement until unshared or the
    /// pool is dropped. Data of at most one chunk is one raw block; larger
    /// data is a manifest over 256 KiB chunks, named `name`. Returns the
    /// content id.
    pub async fn share_content(
        &self,
        realm: &[u8; 32],
        data: &[u8],
        name: &str,
    ) -> Result<Mcid, PoolError> {
        let inner = &self.inner;
        let (mcid, root, chunks) = if data.len() as u64 <= MAX_BLOCK_BYTES {
            (block_mcid(data), Root::Block(data.to_vec()), HashMap::new())
        } else {
            let (m, parts) = manifest::create(data, name, DEFAULT_CHUNK_SIZE)
                .map_err(|e| PoolError::ContentMismatch(e.to_string()))?;
            let chunks: HashMap<Mcid, Vec<u8>> = parts
                .into_iter()
                .enumerate()
                .filter_map(|(i, part)| chunk_mcid(&m, i).map(|c| (c, part)))
                .collect();
            (m.mcid, Root::Chunked(Arc::new(m)), chunks)
        };
        inner.shared_realm(realm).await?;
        let already = {
            let mut realms = inner.content.lock();
            let shared = realms.get_mut(realm).ok_or(PoolError::Closed)?;
            shared.roots.insert(mcid, root.clone());
            shared.chunks.extend(chunks);
            shared.announcements.contains_key(&mcid)
        };
        if already {
            return Ok(mcid);
        }
        let latest = match inner.announce_content(realm, &mcid, &root).await {
            Ok(latest) => latest,
            Err(e) => {
                inner.forget_shared(realm, &mcid);
                return Err(e);
            }
        };
        let latest = Arc::new(Mutex::new(latest));
        let (stop, stopped) = watch::channel(false);
        if let Some(shared) = inner.content.lock().get_mut(realm) {
            shared.announcements.insert(
                mcid,
                Announced {
                    latest: latest.clone(),
                    stop,
                },
            );
        }
        tokio::spawn(renew_announcement(
            Arc::downgrade(inner),
            *realm,
            mcid,
            root,
            latest,
            stopped,
        ));
        Ok(mcid)
    }

    /// Stops sharing `mcid` in `realm`: it is no longer served, and its
    /// announcement is withdrawn with a tombstone this node signs. Content
    /// not shared is nothing to do.
    pub async fn unshare_content(&self, realm: &[u8; 32], mcid: &Mcid) -> Result<(), PoolError> {
        let Some(announced) = self.inner.forget_shared(realm, mcid) else {
            return Ok(());
        };
        announced.stop.send_replace(true);
        let latest = announced
            .latest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let tombstone =
            record::new_tombstone(&latest, Reason::Shutdown, &TombstoneOptions::default())
                .map_err(LinkError::from)?;
        let signed =
            record::sign(&tombstone, &self.inner.opts.identity).map_err(LinkError::from)?;
        let wire = record::encode(&signed).map_err(LinkError::from)?;
        self.put_record(&wire).await
    }

    /// Fetches the content `mcid` names in `realm` from a node that shares
    /// it, as macula_content_fetch does: the announcements under the content
    /// id's key that name it, `realm`, a serving station and a content
    /// procedure bound to their announcer; the sharers tried one at a time in
    /// a random order; a block that must hash to `mcid`, or a manifest that
    /// must match `mcid` before its sizes are read and fit `opts` before any
    /// chunk is asked for, each chunk on its own stream, `opts.parallel` at a
    /// time, checked against its own content id, and the whole against the
    /// manifest. No realm key is needed. Content nobody announces is
    /// [`PoolError::NotShared`]; when every sharer fails,
    /// [`PoolError::ContentUnavailable`] names each failure.
    pub async fn get_content(
        &self,
        realm: &[u8; 32],
        mcid: &Mcid,
        opts: ContentOptions,
    ) -> Result<Vec<u8>, PoolError> {
        let sharers = self.inner.content_sharers(realm, mcid).await?;
        if sharers.is_empty() {
            return Err(PoolError::NotShared);
        }
        let mut tried = Vec::new();
        for sharer in sharers {
            match self.inner.fetch_from(realm, &sharer, mcid, &opts).await {
                Ok(data) => return Ok(data),
                Err(e) => tried.push((sharer.node, e)),
            }
        }
        Err(PoolError::ContentUnavailable(tried))
    }
}

/// An announcing node, where it is served, and on what.
#[derive(Debug, Clone)]
struct Sharing {
    node: [u8; 32],
    station: [u8; 32],
    procedure: String,
}

impl PoolInner {
    /// `realm`'s share, serving the content procedure on first use.
    async fn shared_realm(self: &Arc<Self>, realm: &[u8; 32]) -> Result<(), PoolError> {
        let _serving = self.content.serving.lock().await;
        if self.content.lock().contains_key(realm) {
            return Ok(());
        }
        let pool = Arc::downgrade(self);
        let r = *realm;
        let answer = stream_handler(move |s| answer_fetch_while_pooled(pool.clone(), r, s));
        let procedure = record::own_procedure(&self.self_id, CONTENT_PROCEDURE);
        let served = Pool {
            inner: self.clone(),
        }
        .serve(Offer::stream(
            *realm,
            &procedure,
            StreamMode::ServerStream,
            answer,
        ))
        .await?;
        self.content.lock().insert(
            *realm,
            SharedRealm {
                _served: served,
                roots: HashMap::new(),
                chunks: HashMap::new(),
                announcements: HashMap::new(),
            },
        );
        Ok(())
    }

    /// Answers one fetch, as macula_content_serve does: one DATA body, then
    /// the end, or not_shared or malformed.
    async fn answer_fetch(&self, realm: &[u8; 32], s: &Stream) -> Result<(), LinkError> {
        let args = &s.request().payload;
        let mcid: Option<Mcid> = match wire_bytes(args, "mcid") {
            Some(b) if b.len() == 50 && b[0] == 2 => b.as_slice().try_into().ok(),
            _ => None,
        };
        let want = wire_text(args, "want");
        let (Some(mcid), Some(want @ ("root" | "block"))) = (mcid, want.as_deref()) else {
            return s
                .abort(
                    "malformed",
                    "a fetch names one content id and wants root or block",
                )
                .await;
        };
        let body = self
            .content
            .lock()
            .get(realm)
            .and_then(|shared| shared.body(want, &mcid));
        match body {
            None => {
                s.abort("not_shared", "this node does not share that content")
                    .await
            }
            Some(body) => {
                s.send_value(body).await?;
                s.close().await
            }
        }
    }

    /// Drops `mcid`'s root, its chunks and its announcement from `realm`, and
    /// returns the announcement, if there was one.
    fn forget_shared(&self, realm: &[u8; 32], mcid: &Mcid) -> Option<Announced> {
        let mut realms = self.content.lock();
        let shared = realms.get_mut(realm)?;
        if let Some(Root::Chunked(m)) = shared.roots.remove(mcid) {
            forget_chunks(&mut shared.chunks, &m);
        }
        shared.announcements.remove(mcid)
    }

    /// Signs an announcement of `mcid` in `realm`, naming a station this
    /// node is linked to and its content procedure, and puts it in the DHT.
    async fn announce_content(
        self: &Arc<Self>,
        realm: &[u8; 32],
        mcid: &Mcid,
        root: &Root,
    ) -> Result<Record, PoolError> {
        let station = self
            .links()
            .first()
            .map(Link::station_node_id)
            .ok_or(PoolError::NoLink(Vec::new()))?;
        let mut opts = ContentAnnouncementOptions {
            realm_id: *realm,
            serving_station: station,
            procedure: record::own_procedure(&self.self_id, CONTENT_PROCEDURE),
            ttl_ms: ANNOUNCEMENT_TTL.as_millis() as u64,
            ..ContentAnnouncementOptions::default()
        };
        match root {
            Root::Chunked(m) => {
                opts.name = String::from_utf8_lossy(&m.name).into_owned();
                opts.size = Some(m.size);
                opts.chunk_count = Some(m.chunk_count);
            }
            Root::Block(b) => opts.size = Some(b.len() as u64),
        }
        let unsigned =
            new_content_announcement(&self.self_id, mcid, &opts).map_err(LinkError::from)?;
        let signed = record::sign(&unsigned, &self.opts.identity).map_err(LinkError::from)?;
        let wire = record::encode(&signed).map_err(LinkError::from)?;
        Pool {
            inner: self.clone(),
        }
        .put_record(&wire)
        .await?;
        Ok(signed)
    }

    /// Every node whose verified announcement of `mcid` in `realm` names a
    /// serving station and a content procedure bound to it, shuffled.
    async fn content_sharers(
        &self,
        realm: &[u8; 32],
        mcid: &Mcid,
    ) -> Result<Vec<Sharing>, PoolError> {
        let key = record::content_key(mcid).map_err(LinkError::from)?;
        let found = match self
            .first_answer(|l| async move { l.find_records(&key).await })
            .await
        {
            Ok((found, _)) => found,
            Err(PoolError::Link(LinkError::RecordNotFound)) => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut out: Vec<Sharing> = found
            .iter()
            .filter(|v| v.record().record_type == RecordType::CONTENT_ANNOUNCEMENT)
            .filter_map(|v| record::read_content_announcement(v.record()).ok())
            .filter(|a| {
                a.mcid.as_slice() == mcid.as_slice()
                    && a.realm_id == *realm
                    && a.serving_station != [0; 32]
                    && content_procedure_bound(&a.procedure, &a.announcer_node)
            })
            .map(|a| Sharing {
                node: a.announcer_node,
                station: a.serving_station,
                procedure: a.procedure,
            })
            .collect();
        shuffle(&mut out);
        Ok(out)
    }

    /// Fetches `mcid` from one sharer.
    async fn fetch_from(
        self: &Arc<Self>,
        realm: &[u8; 32],
        s: &Sharing,
        mcid: &Mcid,
        opts: &ContentOptions,
    ) -> Result<Vec<u8>, PoolError> {
        let link = self
            .link_to(&s.station, Instant::now() + DEFAULT_CALL_TIMEOUT)
            .await?;
        let (kind, body) = fetch_one(&link, realm, s, mcid, "root", opts.chunk_timeout).await?;
        if kind == "block" {
            return verified_block(&body, mcid)
                .ok_or_else(|| PoolError::ContentMismatch("the block".into()));
        }
        let m = manifest::from_wire(body.get("manifest").unwrap_or(&Value::Null))
            .map_err(|e| PoolError::ContentReply(format!("the manifest: {e}")))?;
        manifest::verify_mcid(&m, mcid)
            .map_err(|e| PoolError::ContentMismatch(format!("the manifest: {e}")))?;
        if m.size > opts.max_bytes || m.chunk_count > opts.max_chunks {
            return Err(PoolError::ContentTooLarge(format!(
                "{} bytes in {} chunks",
                m.size, m.chunk_count
            )));
        }
        manifest::check_whole(&m)
            .map_err(|e| PoolError::ContentMismatch(format!("the manifest: {e}")))?;
        fetch_chunks(link, *realm, s.clone(), Arc::new(m), opts).await
    }
}

impl SharedRealm {
    /// What a fetch of `want` for `mcid` is answered with; a raw root is not
    /// served as a chunk.
    fn body(&self, want: &str, mcid: &Mcid) -> Option<Value> {
        let block = |b: &[u8]| {
            Value::Map(vec![
                (Value::text("kind"), Value::text("block")),
                (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
                (Value::text("bytes"), Value::Bytes(b.to_vec())),
            ])
        };
        if want == "block" {
            return self.chunks.get(mcid).map(|b| block(b));
        }
        match self.roots.get(mcid)? {
            Root::Block(b) => Some(block(b)),
            Root::Chunked(m) => Some(Value::Map(vec![
                (Value::text("kind"), Value::text("manifest")),
                (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
                (Value::text("manifest"), manifest::to_wire(m)),
            ])),
        }
    }
}

/// Answers one fetch of `realm`'s content while the pool lives, and refuses
/// it as not shared once the pool is gone.
async fn answer_fetch_while_pooled(
    pool: Weak<PoolInner>,
    realm: [u8; 32],
    s: Stream,
) -> Result<(), String> {
    match pool.upgrade() {
        Some(inner) => inner.answer_fetch(&realm, &s).await,
        None => {
            s.abort("not_shared", "the node no longer shares content")
                .await
        }
    }
    .map_err(|e| e.to_string())
}

/// Drops every chunk of `m` from a realm's shared chunks.
fn forget_chunks(chunks: &mut HashMap<Mcid, Vec<u8>>, m: &Manifest) {
    for i in 0..m.chunks.len() {
        if let Some(c) = chunk_mcid(m, i) {
            chunks.remove(&c);
        }
    }
}

/// A block body's bytes, when they are the block `mcid` names.
fn verified_block(body: &Value, mcid: &Mcid) -> Option<Vec<u8>> {
    let bytes = wire_bytes(body, "bytes").unwrap_or_default();
    (block_mcid(&bytes) == *mcid).then_some(bytes)
}

/// Signs `mcid`'s announcement again at half its lifetime, naming the
/// station the pool is linked to then, until it is unshared or the pool is
/// dropped; a failed renewal is tried again at the next half.
async fn renew_announcement(
    pool: Weak<PoolInner>,
    realm: [u8; 32],
    mcid: Mcid,
    root: Root,
    latest: Arc<Mutex<Record>>,
    mut stopped: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stopped.wait_for(|s| *s) => return,
            _ = tokio::time::sleep(ANNOUNCEMENT_TTL / 2) => {}
        }
        let Some(inner) = pool.upgrade() else { return };
        if inner.lock().closed {
            return;
        }
        let renewed = tokio::time::timeout(
            DEFAULT_CALL_TIMEOUT,
            inner.announce_content(&realm, &mcid, &root),
        )
        .await;
        if let Ok(Ok(record)) = renewed {
            *latest.lock().unwrap_or_else(|p| p.into_inner()) = record;
        }
    }
}

/// Fetches every chunk of `m`, `opts.parallel` at a time, each checked
/// against its own content id, then the whole against `m`. The first failure
/// ends the fetch: no chunk is asked for after it.
async fn fetch_chunks(
    link: Link,
    realm: [u8; 32],
    s: Sharing,
    m: Arc<Manifest>,
    opts: &ContentOptions,
) -> Result<Vec<u8>, PoolError> {
    let count = m.chunks.len();
    let parts: Arc<Mutex<Vec<Option<Vec<u8>>>>> = Arc::new(Mutex::new(vec![None; count]));
    let next = Arc::new(AtomicUsize::new(0));
    let (failed_tx, failed) = watch::channel::<Option<PoolError>>(None);
    let failed_tx = Arc::new(failed_tx);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..opts.parallel.max(1).min(count) {
        workers.spawn(fetch_chunks_in_turn(ChunkWorker {
            link: link.clone(),
            realm,
            s: s.clone(),
            m: m.clone(),
            parts: parts.clone(),
            next: next.clone(),
            failed_tx: failed_tx.clone(),
            timeout: opts.chunk_timeout,
        }));
    }
    while workers.join_next().await.is_some() {}
    if let Some(e) = failed.borrow().clone() {
        return Err(e);
    }
    let parts = std::mem::take(&mut *parts.lock().unwrap_or_else(|p| p.into_inner()));
    let mut whole = Vec::with_capacity(m.size as usize);
    for part in parts {
        whole.extend(part.ok_or_else(|| PoolError::ContentReply("a chunk never arrived".into()))?);
    }
    manifest::verify(&m, &whole)
        .map_err(|e| PoolError::ContentMismatch(format!("the whole: {e}")))?;
    Ok(whole)
}

/// One of a fetch's chunk workers: the link, realm and sharer it asks, the
/// manifest it fetches by, what it shares with the other workers (the parts
/// fetched, the next chunk to ask for and the first failure), and each
/// chunk's timeout.
struct ChunkWorker {
    link: Link,
    realm: [u8; 32],
    s: Sharing,
    m: Arc<Manifest>,
    parts: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    next: Arc<AtomicUsize>,
    failed_tx: Arc<watch::Sender<Option<PoolError>>>,
    timeout: Duration,
}

/// Fetches the next chunk no worker has asked for, checked against its own
/// content id, until none is left or a fetch has failed; a failure is kept
/// when it is the first.
async fn fetch_chunks_in_turn(w: ChunkWorker) {
    loop {
        if w.failed_tx.borrow().is_some() {
            return;
        }
        let i = w.next.fetch_add(1, Ordering::SeqCst);
        let Some(want) = chunk_mcid(&w.m, i) else {
            return;
        };
        let fetched = fetch_one(&w.link, &w.realm, &w.s, &want, "block", w.timeout).await;
        let outcome = fetched.and_then(|(_, body)| {
            verified_block(&body, &want)
                .ok_or_else(|| PoolError::ContentMismatch(format!("chunk {i}")))
        });
        let bytes = match outcome {
            Ok(bytes) => bytes,
            Err(e) => return keep_first_failure(&w.failed_tx, e),
        };
        w.parts.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(bytes);
    }
}

/// Keeps `e` as the fetch's failure, unless one was kept before it.
fn keep_first_failure(failed_tx: &watch::Sender<Option<PoolError>>, e: PoolError) {
    failed_tx.send_if_modified(|f| {
        let first = f.is_none();
        if first {
            *f = Some(e);
        }
        first
    });
}

/// Asks a sharer for `want` of `mcid` on a stream of its own and reads its
/// one DATA body; the stream is released on every path.
async fn fetch_one(
    link: &Link,
    realm: &[u8; 32],
    s: &Sharing,
    mcid: &Mcid,
    want: &str,
    timeout: Duration,
) -> Result<(String, Value), PoolError> {
    let asked = async {
        let stream = link
            .open_stream(station_link::StreamCall {
                realm: *realm,
                procedure: s.procedure.clone(),
                target: s.node,
                mode: StreamMode::ServerStream,
                payload: Value::Map(vec![
                    (Value::text("mcid"), Value::Bytes(mcid.to_vec())),
                    (Value::text("want"), Value::text(want)),
                ]),
                deadline: timeout,
                // A content fetch is clear, as macula opens it confidential
                // => off: a content announcement names no key, and the
                // content is checked against its id.
                seal: Some(station_link::Seal::Clear),
                ..station_link::StreamCall::default()
            })
            .await?;
        let event = stream.recv().await;
        let _ = stream.close().await;
        read_body(event, mcid, want)
    };
    tokio::time::timeout(timeout, asked)
        .await
        .unwrap_or(Err(PoolError::Link(LinkError::CallTimeout)))
}

fn read_body(
    event: Result<StreamEvent, LinkError>,
    mcid: &Mcid,
    want: &str,
) -> Result<(String, Value), PoolError> {
    let body = match event {
        Err(LinkError::Stream { code, .. }) if code == "not_shared" => {
            return Err(PoolError::NotShared)
        }
        Err(LinkError::EndOfStream) => {
            return Err(PoolError::ContentReply(
                "the stream ended with no body".into(),
            ))
        }
        Err(e) => return Err(e.into()),
        Ok(StreamEvent::Data { body, .. }) => body,
        Ok(_) => return Err(PoolError::ContentReply("a frame that is not DATA".into())),
    };
    let kind = wire_text(&body, "kind").unwrap_or_default();
    if wire_bytes(&body, "mcid").as_deref() != Some(mcid.as_slice()) {
        return Err(PoolError::ContentReply(
            "a body for another content id".into(),
        ));
    }
    let bytes = wire_bytes(&body, "bytes");
    match (kind.as_str(), bytes) {
        ("block", Some(b)) if b.len() as u64 > MAX_BLOCK_BYTES => Err(PoolError::ContentTooLarge(
            format!("a block of {} bytes", b.len()),
        )),
        ("block", Some(_)) => Ok((kind, body)),
        ("manifest", _) if want == "root" => Ok((kind, body)),
        _ => Err(PoolError::ContentReply(format!("kind {kind:?}"))),
    }
}

/// Field `name` of `v` as text, however it arrives.
fn wire_text(v: &Value, name: &str) -> Option<String> {
    match v.get(name) {
        Some(Value::Text(t)) => Some(t.clone()),
        Some(Value::Bytes(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

/// Field `name` of `v` as bytes.
fn wire_bytes(v: &Value, name: &str) -> Option<Vec<u8>> {
    match v.get(name) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}
