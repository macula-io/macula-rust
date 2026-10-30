//! Subscribes to a topic and publishes to it. A topic names a kind of fact,
//! with a business verb, and ids go in the payload. There is no boolean on
//! the wire: write 1 or 0.
//!
//! Run: `cargo run --example publish_subscribe`, with the environment
//! examples/common/mod.rs reads.

mod common;

use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::frame::Payload;
use macula_rust::pool::Delivery;
use macula_rust::station_link::Publication;

const TOPIC: &str = "acme/demo/greeting_sent_v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = common::connect(None).await;
    // subscribe returns once the station has acknowledged the subscription,
    // so this node hears its own publication with no wait in between.
    let mut sub = pool.subscribe(&common::realm(), TOPIC).await?;
    pool.publish(Publication {
        realm: common::realm(),
        topic: TOPIC.into(),
        payload: Payload::Clear(Value::Map(vec![
            (Value::text("text"), Value::text("hi")),
            (Value::text("urgent"), Value::Int(0)),
        ])),
        ttl_ms: None,
    })
    .await?;
    while let Ok(Some(delivery)) = tokio::time::timeout(Duration::from_secs(2), sub.recv()).await {
        match delivery {
            Delivery::Event(event) => println!(
                "{} published {:?}",
                common::hex(&event.publisher),
                event.payload
            ),
            // No link carried the subscription for a while: resync what it
            // follows, as events in between may be missed.
            Delivery::Interrupted(i) => println!("interrupted ({}) since {}", i.reason, i.from_ms),
            Delivery::Gap(g) => println!("may have missed {}..{}: resync", g.from_ms, g.to_ms),
        }
    }
    sub.unsubscribe().await?;
    pool.close().await;
    Ok(())
}
