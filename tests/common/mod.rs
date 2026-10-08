//! In-process macula 12 stations for a test file: macula-go's teststation,
//! built to target/teststation by scripts/build-teststation.sh (or named by
//! MACULA_TESTSTATION), driven over its stdin. [`TestStations`] is two
//! stations sharing a DHT and a test realm with one org; [`lab::Lab`] starts
//! and shapes stations and realms one by one.

#![allow(dead_code)]

pub mod lab;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;

use macula_rust::profile::Profile;
use macula_rust::transport::Target;

/// One station: where it listens and the node_id it proves.
#[derive(Debug, Clone)]
pub struct TestStation {
    pub host: String,
    pub port: u16,
    pub node_id: [u8; 32],
}

/// The running stations, their realm and org, the helper's stdin, and the
/// test's [`Deadline`].
pub struct TestStations {
    pub profile: Profile,
    pub stations: Vec<TestStation>,
    pub realm_id: [u8; 32],
    pub realm_key: Vec<u8>,
    pub org: String,
    child: Child,
    io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
    _deadline: Deadline,
}

impl TestStations {
    /// Starts the stations in `profile`. A missing helper fails the test,
    /// naming how to build it: a test that cannot reach its stations proves
    /// nothing, so it is never skipped.
    pub fn start(profile: Profile) -> TestStations {
        let (child, stdin, mut stdout) = spawn(&[profile.name()]);
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .expect("the teststation prints its stations");
        let info: serde_json::Value =
            serde_json::from_str(&line).expect("the teststation's JSON line");
        let id = |v: &serde_json::Value| -> [u8; 32] {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let stations = info["stations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| TestStation {
                host: s["host"].as_str().unwrap().to_string(),
                port: s["port"].as_u64().unwrap() as u16,
                node_id: id(&s["node_id"]),
            })
            .collect();
        TestStations {
            profile,
            stations,
            realm_id: id(&info["realm_id"]),
            realm_key: hex::decode(info["realm_key"].as_str().unwrap()).unwrap(),
            org: info["org"].as_str().unwrap().to_string(),
            child,
            io: Mutex::new((stdin, stdout)),
            _deadline: Deadline::arm(),
        }
    }

    /// Station `i` as a dial target, pinned by its node_id.
    pub fn target(&self, i: usize) -> Target {
        let s = &self.stations[i];
        Target {
            host: s.host.clone(),
            port: s.port,
            profile: self.profile,
            expected_node_id: s.node_id,
        }
    }

    /// The org delegates its procedures to `node_id`.
    pub fn admit(&self, node_id: &[u8; 32]) {
        let reply = self.ask(&format!("admit {}", hex::encode(node_id)));
        assert!(reply.starts_with("admitted"), "{reply}");
    }

    /// How many streams the stations relay now.
    pub fn relayed(&self) -> u64 {
        let reply = self.ask("relayed");
        reply
            .split_whitespace()
            .nth(1)
            .and_then(|n| n.parse().ok())
            .expect("relayed <n>")
    }

    fn ask(&self, command: &str) -> String {
        ask(&self.io, command)
    }
}

/// Starts the teststation with `args`. A missing helper fails the test,
/// naming how to build it: a test that cannot reach its stations proves
/// nothing, so it is never skipped.
fn spawn(args: &[&str]) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    // target/ of the workspace: this crate's own, or, for the FFI crate, its
    // parent's.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let binary = std::env::var("MACULA_TESTSTATION").unwrap_or_else(|_| {
        [manifest, manifest.parent().unwrap_or(manifest)]
            .iter()
            .map(|dir| dir.join("target/teststation"))
            .find(|path| path.exists())
            .unwrap_or_else(|| manifest.join("target/teststation"))
            .to_string_lossy()
            .into_owned()
    });
    assert!(
        std::path::Path::new(&binary).exists(),
        "{binary} is missing: run scripts/build-teststation.sh first"
    );
    let mut child = Command::new(&binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the teststation starts");
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdin, stdout)
}

/// One command to the teststation and its one-line answer.
fn ask(io: &Mutex<(ChildStdin, BufReader<ChildStdout>)>, command: &str) -> String {
    let mut io = io.lock().unwrap();
    writeln!(io.0, "{command}").unwrap();
    io.0.flush().unwrap();
    let mut line = String::new();
    io.1.read_line(&mut line).unwrap();
    line.trim_end().to_string()
}

impl Drop for TestStations {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The longest a test may hold its stations, unless
/// MACULA_TEST_DEADLINE_SECS names another. A thread watches it, not an
/// async timeout: a test also blocks on the teststation's stdout, which no
/// async timeout can interrupt.
pub const TEST_DEADLINE: Duration = Duration::from_secs(300);

fn test_deadline() -> Duration {
    std::env::var("MACULA_TEST_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(TEST_DEADLINE, Duration::from_secs)
}

/// Ends the test binary, naming the test, when the test that armed it still
/// holds its stations past its limit, so one stuck test fails its
/// binary instead of holding the gate without bound (#17). Dropped with the
/// stations, it is disarmed.
pub struct Deadline {
    _disarm: Sender<()>,
}

impl Deadline {
    /// Armed for the current test, named by its thread as libtest names it.
    pub fn arm() -> Deadline {
        let test = std::thread::current()
            .name()
            .unwrap_or("a test")
            .to_string();
        let limit = test_deadline();
        let (disarm, armed) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            if armed.recv_timeout(limit) == Err(RecvTimeoutError::Timeout) {
                // Past libtest's capture, which inherits into this thread and
                // would be lost with the process.
                let _ = writeln!(
                    std::io::stderr(),
                    "{test} did not finish within {limit:?}: ending its test binary"
                );
                std::process::exit(101);
            }
        });
        Deadline { _disarm: disarm }
    }
}
