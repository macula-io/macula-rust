//! In-process macula 12 stations for a test file: macula-go's teststation,
//! built to target/teststation by scripts/build-teststation.sh (or named by
//! MACULA_TESTSTATION), driven over its stdin. [`TestStations`] is two
//! stations sharing a DHT and a test realm with one org; [`lab::Lab`] starts
//! and shapes stations and realms one by one.

#![allow(dead_code)]

pub mod lab;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use macula_rust::profile::Profile;
use macula_rust::transport::Target;

/// One station: where it listens and the node_id it proves.
#[derive(Debug, Clone)]
pub struct TestStation {
    pub host: String,
    pub port: u16,
    pub node_id: [u8; 32],
}

/// The running stations, their realm and org, and the helper's stdin.
pub struct TestStations {
    pub profile: Profile,
    pub stations: Vec<TestStation>,
    pub realm_id: [u8; 32],
    pub realm_key: Vec<u8>,
    pub org: String,
    child: Child,
    io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
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
    let binary = std::env::var("MACULA_TESTSTATION")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/target/teststation").to_string());
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
