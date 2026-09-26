//! Connects to a macula 12 station and calls mcl-echo/echo, which runs on
//! another station: the pool finds its trusted advertisement in the DHT and
//! dials the station it serves from.
//!
//! Run: `cargo run --example quickstart`, with the environment
//! examples/common/mod.rs reads.

mod common;

use macula_rust::cbor::Value;
use macula_rust::pool::Call;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = common::connect(None).await;
    println!("node {}", common::hex(&pool.node_id()));
    for provider in pool.providers(&common::realm(), "mcl-echo/echo").await? {
        println!(
            "provider {} at station {}",
            common::hex(&provider.node),
            common::hex(&provider.station)
        );
    }
    let answered = pool
        .call(Call {
            realm: common::realm(),
            procedure: "mcl-echo/echo".into(),
            payload: Value::text("hello"),
            ..Call::default()
        })
        .await?;
    println!("mcl-echo/echo answered {answered:?}");
    pool.close().await;
    Ok(())
}
