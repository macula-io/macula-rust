//! The teststation's lab mode: stations and realms started one by one, and
//! the station-side facts a test asserts on (who is connected, what is
//! advertised or subscribed, how many streams are relayed).

use std::io::BufReader;
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::Mutex;

use macula_rust::pool::Seed;
use macula_rust::profile::Profile;

use super::{ask, spawn, Deadline};

/// A station the lab started: its index, where it listens, the node_id it
/// proves.
#[derive(Debug, Clone)]
pub struct LabStation {
    pub index: usize,
    pub host: String,
    pub port: u16,
    pub node_id: [u8; 32],
}

impl LabStation {
    /// The station as a pool seed, pinned by its node_id.
    pub fn seed(&self) -> Seed {
        Seed {
            host: self.host.clone(),
            port: self.port,
            node_id: self.node_id,
        }
    }
}

/// A test realm with one org: its index, id and realm key as carried.
#[derive(Debug, Clone)]
pub struct LabRealm {
    pub index: usize,
    pub id: [u8; 32],
    pub key: Vec<u8>,
}

/// A teststation in lab mode, killed when dropped, and the test's
/// [`Deadline`].
pub struct Lab {
    pub profile: Profile,
    child: Child,
    io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
    _deadline: Deadline,
}

impl Lab {
    /// A lab in `profile`, with no station yet.
    pub fn start(profile: Profile) -> Lab {
        let (child, stdin, stdout) = spawn(&[profile.name(), "lab"]);
        Lab {
            profile,
            child,
            io: Mutex::new((stdin, stdout)),
            _deadline: Deadline::arm(),
        }
    }

    /// A new station named `name`, its own endpoint record in its DHT.
    pub fn station(&self, name: &str) -> LabStation {
        let reply = self.expect(&format!("start {name}"), "station");
        let f: Vec<&str> = reply.split_whitespace().collect();
        LabStation {
            index: f[1].parse().unwrap(),
            host: f[2].to_string(),
            port: f[3].parse().unwrap(),
            node_id: id32(f[4]),
        }
    }

    /// Stops a station: its listener and every connection close.
    pub fn stop(&self, s: &LabStation) {
        self.expect(&format!("stop {}", s.index), "stopped");
    }

    /// Closes `node`'s connection at the station, as a restart would.
    pub fn drop_node(&self, s: &LabStation, node: &[u8; 32]) {
        self.expect(
            &format!("drop {} {}", s.index, hex::encode(node)),
            "dropped",
        );
    }

    pub fn connected(&self, s: &LabStation, node: &[u8; 32]) -> bool {
        self.yes(&format!("connected {} {}", s.index, hex::encode(node)))
    }

    pub fn advertised(&self, s: &LabStation, realm: &[u8; 32], procedure: &str) -> bool {
        self.yes(&format!(
            "advertised {} {} {procedure}",
            s.index,
            hex::encode(realm)
        ))
    }

    pub fn subscribed(
        &self,
        s: &LabStation,
        node: &[u8; 32],
        realm: &[u8; 32],
        topic: &str,
    ) -> bool {
        self.yes(&format!(
            "subscribed {} {} {} {topic}",
            s.index,
            hex::encode(node),
            hex::encode(realm)
        ))
    }

    /// The stations hold one record store, as a replicating DHT would.
    pub fn share(&self, stations: &[&LabStation]) {
        let indexes: Vec<String> = stations.iter().map(|s| s.index.to_string()).collect();
        self.expect(&format!("share {}", indexes.join(" ")), "shared");
    }

    /// Stores a verified record's wire bytes at the station.
    pub fn put(&self, s: &LabStation, wire: &[u8]) {
        self.expect(&format!("put {} {}", s.index, hex::encode(wire)), "put");
    }

    /// Stores `wire` under `key` whatever it is, as a lying station would.
    pub fn forge(&self, s: &LabStation, key: &[u8; 32], wire: &[u8]) {
        self.expect(
            &format!(
                "forge {} {} {}",
                s.index,
                hex::encode(key),
                hex::encode(wire)
            ),
            "forged",
        );
    }

    /// How many streams the station relays now.
    pub fn relayed(&self, s: &LabStation) -> u64 {
        let reply = self.expect(&format!("relayed {}", s.index), "relayed");
        reply.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    /// A realm named `name` with the org `org`.
    pub fn realm(&self, name: &str, org: &str) -> LabRealm {
        assert!(
            !name.contains(char::is_whitespace) && !org.contains(char::is_whitespace),
            "a realm name or org with whitespace would split the lab's command: {name:?} {org:?}"
        );
        self.realm_line(&format!("realm {name} {org}"))
    }

    /// A realm with `r`'s id and org and another realm key.
    pub fn impostor(&self, r: &LabRealm) -> LabRealm {
        self.realm_line(&format!("impostor {}", r.index))
    }

    /// Puts `r`'s org directory, and its org's delegation to each of
    /// `advertisers`, in the station's DHT.
    pub fn admit(&self, r: &LabRealm, s: &LabStation, advertisers: &[[u8; 32]]) {
        let nodes: Vec<String> = advertisers.iter().map(hex::encode).collect();
        self.expect(
            &format!("admit {} {} {}", r.index, s.index, nodes.join(" ")),
            "admitted",
        );
    }

    fn realm_line(&self, command: &str) -> LabRealm {
        let reply = self.expect(command, "realm");
        let f: Vec<&str> = reply.split_whitespace().collect();
        LabRealm {
            index: f[1].parse().unwrap(),
            id: id32(f[2]),
            key: hex::decode(f[3]).unwrap(),
        }
    }

    fn yes(&self, command: &str) -> bool {
        match ask(&self.io, command).as_str() {
            "yes" => true,
            "no" => false,
            other => panic!("{command}: {other}"),
        }
    }

    fn expect(&self, command: &str, answer: &str) -> String {
        let reply = ask(&self.io, command);
        assert!(reply.starts_with(answer), "{command}: {reply}");
        reply
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn id32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}
