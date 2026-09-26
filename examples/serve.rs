//! Serves a procedure in this node's own namespace, `~<node_id>/ring`, which
//! needs no org and no realm key: the node's signature authorizes it. A
//! second node, with a key of its own, calls it by direct dial.
//!
//! Run: `cargo run --example serve`, with the environment
//! examples/common/mod.rs reads. The caller's key is `caller.key`.

mod common;

use macula_rust::cbor::Value;
use macula_rust::pool::{Call, Offer};
use macula_rust::record;
use macula_rust::station_link::handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = common::connect(None).await;
    let ring = record::own_procedure(&provider.node_id(), "ring");
    let served = provider
        .serve(Offer::unary(
            common::realm(),
            &ring,
            handler(|request| async move {
                Ok(Value::Map(vec![(
                    Value::text("answered"),
                    Value::Bytes(request.caller.to_vec()),
                )]))
            }),
        ))
        .await?;
    println!("serving {ring}");

    let caller = common::connect(Some("caller.key")).await;
    let answered = caller
        .call(Call {
            realm: common::realm(),
            procedure: ring,
            payload: Value::Null,
            ..Call::default()
        })
        .await?;
    println!("{answered:?}");

    served.stop().await?;
    caller.close().await;
    provider.close().await;
    Ok(())
}
