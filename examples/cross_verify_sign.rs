//! This crate's half of scripts/cross-verify-macula.sh: a pq_hybrid key made
//! for the run and never saved signs a message; the message, the public key
//! as carried and the signature go to the directory named on the command line
//! for macula to verify.

use macula_rust::node_key::{verify, NodeKey, Purpose};
use macula_rust::profile::Profile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: cross_verify_sign <dir>")?,
    );
    let key = NodeKey::generate(Purpose::Identity, Profile::PqHybrid)?;
    let message = b"signed by macula-rust";
    let signature = key.sign(message)?;
    if !verify(message, &signature, &key.public_key(), Profile::PqHybrid) {
        return Err("macula-rust does not verify its own composite".into());
    }
    std::fs::write(dir.join("m.bin"), message)?;
    std::fs::write(dir.join("pk.bin"), key.public_key())?;
    std::fs::write(dir.join("s.bin"), &signature)?;
    println!(
        "rust_signed: {}-byte composite by macula-rust written",
        signature.len()
    );
    Ok(())
}
