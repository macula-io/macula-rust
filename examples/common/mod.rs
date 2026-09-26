//! What every example joins the mesh with, from the environment:
//!
//! - `MACULA_SEED`: the station, host:port (`[v6]:port` for IPv6)
//! - `MACULA_STATION_ID`: its node_id, 64 hex: the station must prove it
//! - `MACULA_REALM`: the realm id, 64 hex
//! - `MACULA_REALM_KEY`: the realm's key as carried, hex (the realm publishes it)
//! - `MACULA_KEY`: this node's key file, created on first use (`node.key`)
//! - `MACULA_PROFILE`: `pq_hybrid` (the fleet's, the default) or `pq_pure`

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use macula_rust::node_key::NodeKey;
use macula_rust::pool::{Opts, Pool, Seed};
use macula_rust::profile::Profile;

pub fn env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("set {name} (see the top of examples/common/mod.rs)");
            std::process::exit(2);
        }
    }
}

pub fn hex32(name: &str) -> [u8; 32] {
    let bytes = hex_decode(&env(name));
    bytes.try_into().unwrap_or_else(|_| {
        eprintln!("{name} must be 64 hex characters");
        std::process::exit(2);
    })
}

pub fn realm() -> [u8; 32] {
    hex32("MACULA_REALM")
}

/// A pool on the seed, as the key in `key_file` (or `MACULA_KEY`, or
/// `node.key`), made on first use, trusting the realm.
pub async fn connect(key_file: Option<&str>) -> Pool {
    let seed = env("MACULA_SEED");
    let Some((host, port)) = seed.rsplit_once(':') else {
        eprintln!("MACULA_SEED must be host:port");
        std::process::exit(2);
    };
    let profile = std::env::var("MACULA_PROFILE")
        .ok()
        .and_then(|p| Profile::parse(&p).ok())
        .unwrap_or(Profile::PqHybrid);
    let key_file = key_file
        .map(str::to_string)
        .or_else(|| std::env::var("MACULA_KEY").ok())
        .unwrap_or_else(|| "node.key".into());
    let key = NodeKey::load_or_create(Path::new(&key_file), profile).expect("the node's key");
    let mut opts = Opts::new(Arc::new(key));
    opts.realm_trust = HashMap::from([(realm(), hex_decode(&env("MACULA_REALM_KEY")))]);
    Pool::connect(
        vec![Seed {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port: port.parse().expect("MACULA_SEED's port"),
            node_id: hex32("MACULA_STATION_ID"),
        }],
        opts,
    )
    .await
    .expect("a link to the seed")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| {
            eprintln!("not hex: {text}");
            std::process::exit(2);
        })
}
