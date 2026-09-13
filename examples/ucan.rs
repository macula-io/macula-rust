//! UCAN-gated serving: mint a token, gate a served procedure on it, show
//! both the rejected-without-token and accepted-with-token paths. Dials
//! the real fleet, so this isn't run by CI — see README.md's "Known
//! limitations" section for the investigation this example closes out
//! (kept compiling by `cargo build --examples` in CI, run manually with
//! `cargo run --example ucan`).
//!
//! Keeps the provider `Session` alive for a moment after
//! `serve_one_call_gated` returns before letting it drop — dropping its
//! last handle closes the QUIC connection at once, which can discard the
//! just-sent reply before it reaches the peer (the same race documented
//! on [`macula_rust::connection::Session::close`]). See this file's own
//! git history / README for the investigation that found this.
use std::sync::Arc;
use std::time::Duration;

use macula_rust::{
    cbor::Value, connection, connection::CallHandler, identity::KeyPair, transport::Trust, ucan,
};

const HOST: &str = "station-de-frankfurt.macula.io";
const PORT: u16 = 4433;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider_id = KeyPair::generate_with_default_puzzle();
    let caller_id = KeyPair::generate_with_default_puzzle();
    let authority = KeyPair::generate_with_default_puzzle();

    let provider = connection::connect(HOST, PORT, Trust::WebPki, &provider_id).await?;
    let caller = connection::connect(HOST, PORT, Trust::WebPki, &caller_id).await?;

    let realm = [0u8; 32];
    let procedure = "macula_rust.examples.ucan_gated";
    let advertise_spec =
        macula_rust::frame::AdvertiseSpec::new(realm, procedure, provider_id.node_id());
    provider.advertise(&advertise_spec, &provider_id).await?;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Only callers holding a token issued by `authority` may invoke this
    // procedure. A real deployment would use a stable, pre-shared
    // authority identity, not one minted fresh per run.
    let issuer_pub = authority.node_id();
    let handler: CallHandler = Arc::new(|payload: Value| {
        Box::pin(async move { Ok(Value::Text(format!("granted: {payload:?}"))) })
    });

    // serve_one_call_gated answers exactly ONE inbound call, then
    // returns -- this example makes two calls (rejected, then granted),
    // so the provider loops twice, once per expected call.
    let serve_task = tokio::spawn(async move {
        for _ in 0..2 {
            let handler = handler.clone();
            provider
                .serve_one_call_gated(
                    move |_realm, proc| {
                        if proc == procedure {
                            Some(handler.clone())
                        } else {
                            None
                        }
                    },
                    move |_, _| ucan::Policy::required(issuer_pub),
                    &provider_id,
                    Duration::from_secs(15),
                )
                .await?;
        }
        // Keep the session alive briefly after the last reply -- see
        // this file's module doc for why this matters.
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok::<(), connection::ServeCallError>(())
    });

    // First call: no token at all -- refused before the handler ever runs.
    let rejected = caller
        .call(
            procedure,
            realm,
            Value::Null,
            0,
            &caller_id,
            Duration::from_secs(5),
        )
        .await;
    println!("call without a token: {rejected:?}");

    // Second call: a real token minted by the required authority. It names
    // this caller as its audience (the caller's node id as lowercase hex),
    // the only caller a gated provider accepts it from.
    let token = ucan::create(
        "did:key:example-issuer",
        &hex::encode(caller_id.node_id()),
        vec![],
        &authority,
        ucan::CreateOpts::default(),
    )?;
    let granted = caller
        .call_with_ucan(
            procedure,
            realm,
            Value::Text("hello".into()),
            0,
            &caller_id,
            Duration::from_secs(5),
            token,
        )
        .await;
    println!("call with a valid token: {granted:?}");

    serve_task.await??;
    Ok(())
}
