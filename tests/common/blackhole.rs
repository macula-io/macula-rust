//! A node's path to its station that can lose every packet and still be a
//! path: the node talks to a relay that forwards datagrams both ways, and
//! while it is closed nothing crosses but nothing is refused either
//! (macula-rust#57, after macula-craft-collab's tests/common/blackhole.rs).
//!
//! Unlike [`super::lab::Lab::drop_node`], which closes the node's connection
//! at the station, a closed relay loses the packets: what the node writes
//! meanwhile leaves the node and never arrives, and the link ends only when
//! QUIC's idle timeout or the liveness probe gives up on it.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// How long a socket read waits before checking whether it should stop.
const POLL: Duration = Duration::from_millis(50);

/// What both directions of a relay share.
#[derive(Default)]
struct Shared {
    dropping: AtomicBool,
    stop: AtomicBool,
    /// Datagrams the node sent while the relay was dropping them.
    lost_to_station: AtomicU64,
    /// The node's address, learnt from what it sends: one node per relay.
    node: Mutex<Option<SocketAddr>>,
}

/// A UDP relay in front of a station, closable on demand.
pub struct BlackHole {
    addr: SocketAddr,
    shared: Arc<Shared>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl BlackHole {
    /// A relay that forwards to `station` and listens for the node.
    pub fn in_front_of(station: SocketAddr) -> BlackHole {
        let front = Arc::new(bind_loopback());
        let up = Arc::new(bind_loopback());
        let addr = front.local_addr().expect("the relay's front socket");
        let shared = Arc::new(Shared::default());
        let threads = vec![
            spawn(&shared, &front, &up, Some(station)),
            spawn(&shared, &up, &front, None),
        ];
        BlackHole {
            addr,
            shared,
            threads,
        }
    }

    /// Where the node dials, naming the station's node_id.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// From now on, every datagram in either direction is dropped.
    pub fn close(&self) {
        self.shared.dropping.store(true, Ordering::Relaxed);
    }

    /// From now on, datagrams cross again.
    pub fn open(&self) {
        self.shared.dropping.store(false, Ordering::Relaxed);
    }

    /// Datagrams the node sent while the relay was dropping them: proof that
    /// what it wrote left it.
    pub fn lost_to_station(&self) -> u64 {
        self.shared.lost_to_station.load(Ordering::Relaxed)
    }
}

impl Drop for BlackHole {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Forwards what `from` reads out of `to`: to `station` when it is the
/// node's side, else back to the node.
fn spawn(
    shared: &Arc<Shared>,
    from: &Arc<UdpSocket>,
    to: &Arc<UdpSocket>,
    station: Option<SocketAddr>,
) -> thread::JoinHandle<()> {
    let (shared, from, to) = (Arc::clone(shared), Arc::clone(from), Arc::clone(to));
    thread::spawn(move || {
        while !shared.stop.load(Ordering::Relaxed) {
            forward_one(&shared, &from, &to, station);
        }
    })
}

/// Forwards one datagram, if one arrives within [`POLL`].
fn forward_one(shared: &Shared, from: &UdpSocket, to: &UdpSocket, station: Option<SocketAddr>) {
    let mut buffer = vec![0_u8; 65_536];
    let Ok((len, sender)) = from.recv_from(&mut buffer) else {
        return;
    };
    if station.is_some() {
        *shared.node.lock().expect("the node address") = Some(sender);
    }
    let dropping = shared.dropping.load(Ordering::Relaxed);
    if dropping && station.is_some() {
        shared.lost_to_station.fetch_add(1, Ordering::Relaxed);
    }
    let dest = station.or(*shared.node.lock().expect("the node address"));
    if let (false, Some(dest)) = (dropping, dest) {
        let _ = to.send_to(&buffer[..len], dest);
    }
}

/// A loopback UDP socket whose reads time out, so its thread can be stopped.
fn bind_loopback() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback UDP socket");
    socket.set_read_timeout(Some(POLL)).expect("a read timeout");
    socket
}
