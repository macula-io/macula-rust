//! Node-served content (D27): a node shares content it keeps, served from
//! its own `~<node_id>/content_v1` and announced in the DHT; another node
//! fetches it by its 50-byte content id, checking everything it receives
//! against that id. No realm key is needed on either side.

use macula_rust::manifest::Mcid;
use macula_rust::pool::ContentOptions;

use crate::pool::FfiPool;
use crate::{millis, to_32, FfiError};

/// A fetch's bounds. Zero is macula's default: 256 MiB, 16,384 chunks, 4
/// chunk streams at a time, 15 seconds per stream.
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FfiContentOptions {
    #[uniffi(default = 0)]
    pub max_bytes: u64,
    #[uniffi(default = 0)]
    pub max_chunks: u64,
    #[uniffi(default = 0)]
    pub parallel: u32,
    #[uniffi(default = 0)]
    pub chunk_timeout_ms: u64,
}

impl From<FfiContentOptions> for ContentOptions {
    fn from(o: FfiContentOptions) -> Self {
        let d = ContentOptions::default();
        let or = |v: u64, fallback: u64| if v == 0 { fallback } else { v };
        ContentOptions {
            max_bytes: or(o.max_bytes, d.max_bytes),
            max_chunks: or(o.max_chunks, d.max_chunks),
            parallel: or(u64::from(o.parallel), d.parallel as u64) as usize,
            chunk_timeout: if o.chunk_timeout_ms == 0 {
                d.chunk_timeout
            } else {
                millis(o.chunk_timeout_ms)
            },
        }
    }
}

/// A content id: 50 bytes.
fn to_mcid(bytes: Vec<u8>) -> Result<Mcid, FfiError> {
    let actual = bytes.len() as u32;
    bytes.try_into().map_err(|_| FfiError::WrongByteLength {
        expected: 50,
        actual,
    })
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiPool {
    /// Keeps `data`, serves it and announces it in `realm`, until
    /// [`unshare_content`](Self::unshare_content). Returns its 50-byte
    /// content id: a raw block's for up to 256 KiB, a manifest's, named
    /// `name`, above that.
    pub async fn share_content(
        &self,
        realm: Vec<u8>,
        data: Vec<u8>,
        name: String,
    ) -> Result<Vec<u8>, FfiError> {
        Ok(self
            .0
            .share_content(&to_32(realm)?, &data, &name)
            .await?
            .to_vec())
    }

    /// Stops sharing `mcid` in `realm` and withdraws its announcement.
    pub async fn unshare_content(&self, realm: Vec<u8>, mcid: Vec<u8>) -> Result<(), FfiError> {
        Ok(self
            .0
            .unshare_content(&to_32(realm)?, &to_mcid(mcid)?)
            .await?)
    }

    /// Fetches the content `mcid` names in `realm` from a node that shares
    /// it, checked against `mcid` throughout. [`FfiError::NotShared`] when
    /// nobody announces it; [`FfiError::ContentUnavailable`] when every
    /// sharer failed, naming why.
    pub async fn get_content(
        &self,
        realm: Vec<u8>,
        mcid: Vec<u8>,
        options: FfiContentOptions,
    ) -> Result<Vec<u8>, FfiError> {
        let mcid = to_mcid(mcid)?;
        Ok(self
            .0
            .get_content(&to_32(realm)?, &mcid, options.into())
            .await?)
    }
}
