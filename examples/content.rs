//! Shares content from one node and fetches it from another by its content
//! id. The sharer keeps the content and serves it from its own namespace;
//! the fetcher checks everything it receives against the content id, so
//! neither needs a realm key.
//!
//! Run: `cargo run --example content`, with the environment
//! examples/common/mod.rs reads. The fetcher's key is `fetcher.key`.

mod common;

use macula_rust::pool::ContentOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sharer = common::connect(None).await;
    let data: Vec<u8> = (0..600_000usize).map(|i| (i % 251) as u8).collect();
    let mcid = sharer
        .share_content(&common::realm(), &data, "example.bin")
        .await?;
    println!("shared {} bytes as {}", data.len(), common::hex(&mcid));

    let fetcher = common::connect(Some("fetcher.key")).await;
    let got = fetcher
        .get_content(&common::realm(), &mcid, ContentOptions::default())
        .await?;
    println!("fetched {} bytes, the same: {}", got.len(), got == data);

    sharer.unshare_content(&common::realm(), &mcid).await?;
    fetcher.close().await;
    sharer.close().await;
    Ok(())
}
