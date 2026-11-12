//! Publications a link sent and the station is not known to have read, sent
//! again once that link ends (macula-rust#57).
//!
//! QUIC delivers a control stream in order and retransmits what was lost,
//! but only while its connection lives. A link that ends (its idle timeout,
//! two missed liveness probes, an outage longer than either) takes with it
//! what it had not delivered, and the protocol acknowledges no PUBLISH, so
//! nothing would tell the publisher. Each link therefore holds what it sent
//! until the station answers a frame sent after it; the pool takes what is
//! still held when the link ends and sends it on a link that is up, or on
//! the next one up. A subscriber that did receive one delivers it once all
//! the same: it is the same signed publication, deduplicated by its hash.
//! One that cannot be sent again before subscribers would refuse it, or that
//! does not fit, is counted in [`Pool::unsent_publications`], never dropped
//! silently.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use super::{Pool, PoolInner};
use crate::station_link::{now_ms, SignedPublication};

/// At most this many publications wait for a link to be up again.
const MAX_WAITING: usize = 4096;

/// The publications waiting for a link to be up again, oldest first.
pub(super) type Waiting = VecDeque<SignedPublication>;

impl Pool {
    /// How many publications this pool accepted and could not deliver: sent
    /// on a link that ended before the station was known to have read them,
    /// and then not sent again in time (no link came up before subscribers
    /// would refuse them, the pool closed, or too many were waiting).
    pub fn unsent_publications(&self) -> u64 {
        self.inner.unsent.load(Ordering::Relaxed)
    }
}

impl PoolInner {
    /// Sends again, on the links up now, what an ended link had not
    /// delivered; what none takes waits for the next link.
    pub(super) async fn send_again(&self, held: Vec<SignedPublication>) {
        for p in self.unexpired(held) {
            let sent = self.send_signed(&p).await.is_ok();
            self.wait_unless(sent, p);
        }
    }

    /// Gives the publications waiting for a link the ones the active tier can
    /// carry now, oldest first.
    ///
    /// It runs inside a link's replay, whichever link came up, so it selects
    /// where an originating publish would: the active tier, never the
    /// returning link's own (macula-io/macula#201 §2). A fallback link that
    /// comes up while the public tier is up therefore carries none of them,
    /// and a publication re-sent this way goes to as many stations as a fresh
    /// publish would, up to `replication_factor`.
    pub(super) async fn send_waiting(&self) {
        let waiting = std::mem::take(&mut self.lock().waiting);
        for p in self.unexpired(waiting.into()) {
            let sent = self.send_signed(&p).await.is_ok();
            self.wait_unless(sent, p);
        }
    }

    /// Counts what still waits as unsent: the pool is closing.
    pub(super) fn give_up_waiting(&self) {
        let left = std::mem::take(&mut self.lock().waiting).len();
        self.unsent.fetch_add(left as u64, Ordering::Relaxed);
    }

    /// The publications subscribers would still accept, oldest first; the
    /// others are counted unsent.
    fn unexpired(&self, ps: Vec<SignedPublication>) -> Vec<SignedPublication> {
        let now = u64::try_from(now_ms()).unwrap_or(0);
        let (live, expired): (Vec<_>, Vec<_>) =
            ps.into_iter().partition(|p| now <= p.accepted_until());
        self.unsent
            .fetch_add(expired.len() as u64, Ordering::Relaxed);
        live
    }

    /// Keeps `p` for the next link unless it was `sent`.
    fn wait_unless(&self, sent: bool, p: SignedPublication) {
        if !sent {
            self.wait_for_link(p);
        }
    }

    /// Keeps `p` for the next link, or counts it unsent when the pool is
    /// closed or too many already wait.
    fn wait_for_link(&self, p: SignedPublication) {
        let mut state = self.lock();
        if state.closed || state.waiting.len() >= MAX_WAITING {
            drop(state);
            self.unsent.fetch_add(1, Ordering::Relaxed);
            return;
        }
        state.waiting.push_back(p);
    }
}

#[cfg(test)]
mod tests {
    //! The flush selects where an originating publish would
    //! (macula-io/macula#201 §2). Its waiting set is not reachable from an
    //! integration test — a publication only waits when no link of the active
    //! tier could take it, which is a window of a failed write — so the flush
    //! is driven from here, with both tiers up, where the rule it applies is
    //! observable: the active tier's station carries the publication and the
    //! fallback's does not.

    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::cbor::Value;
    use crate::frame::Payload;
    use crate::node_key::{NodeKey, PUZZLE_DIFFICULTY};
    use crate::pool::{Delivery, Opts, Pool, Seed, Subscription, Tier};
    use crate::profile::Profile;
    use crate::station_link::{Publication, SignedPublication};

    const TOPIC: &str = "mcl-craft/wire/edit_made_v1";
    const REALM: [u8; 32] = [7; 32];

    /// The test station the integration tests dial, in its lab mode: a few
    /// commands and their one-line answers are all this file needs.
    struct Lab {
        child: Child,
        io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
    }

    /// A station the lab started.
    struct Station {
        node_id: [u8; 32],
        host: String,
        port: u16,
    }

    impl Lab {
        fn start() -> Lab {
            let binary =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/teststation");
            assert!(
                binary.exists(),
                "{} is missing: run scripts/build-teststation.sh first",
                binary.display()
            );
            let mut child = Command::new(binary)
                .args([Profile::PqPure.name(), "lab"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("the teststation starts");
            let stdin = child.stdin.take().expect("its stdin");
            let stdout = BufReader::new(child.stdout.take().expect("its stdout"));
            Lab {
                child,
                io: Mutex::new((stdin, stdout)),
            }
        }

        fn station(&self, name: &str) -> Station {
            let reply = self.ask(&format!("start {name}"));
            let f: Vec<&str> = reply.split_whitespace().collect();
            assert_eq!(f.first(), Some(&"station"), "{reply}");
            Station {
                node_id: hex32(f[4]),
                host: f[2].to_string(),
                port: f[3].parse().expect("a port"),
            }
        }

        fn ask(&self, command: &str) -> String {
            let mut io = self.io.lock().unwrap_or_else(|p| p.into_inner());
            writeln!(io.0, "{command}").expect("a command to the teststation");
            io.0.flush().expect("flushed");
            let mut line = String::new();
            io.1.read_line(&mut line).expect("an answer");
            line.trim_end().to_string()
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn hex32(text: &str) -> [u8; 32] {
        let raw = hex::decode(text).expect("hex");
        raw.try_into().expect("32 bytes")
    }

    impl Station {
        fn seed(&self) -> Seed {
            Seed {
                host: self.host.clone(),
                port: self.port,
                node_id: self.node_id,
            }
        }
    }

    fn opts() -> Opts {
        let identity = Arc::new(
            NodeKey::generate_identity(Profile::PqPure, PUZZLE_DIFFICULTY).expect("a key"),
        );
        let mut opts = Opts::new(identity);
        opts.realm_trust = HashMap::new();
        opts.respawn_delay = Duration::from_millis(100);
        opts.connect_timeout = Duration::from_secs(15);
        opts
    }

    /// A pool linked to `seed` only, subscribed to TOPIC.
    async fn subscribed(seed: Seed) -> (Pool, Subscription) {
        let pool = Pool::connect(vec![seed], opts()).await.expect("connected");
        let sub = pool.subscribe(&REALM, TOPIC).await.expect("subscribed");
        (pool, sub)
    }

    /// How many times `sub` hears `text` before `limit` passes.
    async fn heard(sub: &mut Subscription, text: &str, limit: Duration) -> usize {
        let until = tokio::time::Instant::now() + limit;
        let mut n = 0;
        while let Ok(Some(delivery)) = tokio::time::timeout_at(until, sub.recv()).await {
            n += usize::from(hears(&delivery, text));
        }
        n
    }

    /// Whether a delivery is the `text` publication, rather than an
    /// interruption or a gap.
    fn hears(delivery: &Delivery, text: &str) -> bool {
        match delivery {
            Delivery::Event(event) => event.payload == Payload::Clear(Value::text(text)),
            Delivery::Interrupted(_) | Delivery::Gap(_) => false,
        }
    }

    async fn all_up(p: &Pool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !every_link_up(p) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(every_link_up(p), "not both links up: {:?}", p.status());
    }

    /// Whether every link the pool holds is up.
    fn every_link_up(p: &Pool) -> bool {
        p.status().iter().all(|l| l.up)
    }

    fn signed(pool: &Pool, text: &str) -> SignedPublication {
        SignedPublication::sign(
            &pool.inner.opts.identity,
            &pool.inner.publication_seq,
            Publication {
                realm: REALM,
                topic: TOPIC.to_string(),
                payload: Payload::Clear(Value::text(text)),
                ttl_ms: None,
            },
        )
        .expect("a signed publication")
    }

    /// A waiting publication is flushed to the active tier, whatever link
    /// came up: with the public tier up it goes to the public station and the
    /// fallback station carries nothing. A flush that wrote on the returning
    /// link instead would put it on the fallback.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_flush_goes_where_an_originating_publish_would() {
        let lab = Lab::start();
        let public = lab.station("flush public");
        let fallback = lab.station("flush fallback");
        let (_public_pool, mut public_sub) = subscribed(public.seed()).await;
        let (_fallback_pool, mut fallback_sub) = subscribed(fallback.seed()).await;

        let mut tiered = opts();
        tiered.fallback_seeds = vec![fallback.seed()];
        let pool = Pool::connect(vec![public.seed()], tiered)
            .await
            .expect("connected to both tiers");
        all_up(&pool).await;
        assert_eq!(pool.active_tier(), Tier::Public);

        // The waiting set a replay would flush: a publication no link of the
        // active tier could carry when it was handed over.
        pool.inner
            .wait_unless(false, signed(&pool, "waits for a link"));
        pool.inner.send_waiting().await;

        assert_eq!(
            heard(&mut public_sub, "waits for a link", Duration::from_secs(5)).await,
            1,
            "the active tier's station carries it"
        );
        assert_eq!(
            heard(
                &mut fallback_sub,
                "waits for a link",
                Duration::from_millis(500)
            )
            .await,
            0,
            "the fallback station carries nothing while the public tier is up"
        );
    }
}
