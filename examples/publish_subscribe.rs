//! Subscribes to a topic and publishes to it. A topic names a kind of fact,
//! with a business verb, and ids go in the payload. There is no boolean on
//! the wire: write 1 or 0.
//!
//! Run: `cargo run --example publish_subscribe`, with the environment
//! examples/common/mod.rs reads.

mod common;

use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::station_link::Publication;

const TOPIC: &str = "acme/demo/greeting_sent_v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = common::connect(None).await;
    let mut sub = pool.subscribe(&common::realm(), TOPIC).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.publish(Publication {
        realm: common::realm(),
        topic: TOPIC.into(),
        payload: Value::Map(vec![
            (Value::text("text"), Value::text("hi")),
            (Value::text("urgent"), Value::Int(0)),
        ]),
        ttl_ms: None,
    })
    .await?;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(2), sub.recv()).await {
        println!(
            "{} published {:?}",
            common::hex(&event.publisher),
            event.payload
        );
    }
    sub.unsubscribe().await?;
    pool.close().await;
    Ok(())
}
