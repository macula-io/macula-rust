//! A node's pool of station links: one link per pinned seed, redialed when it
//! drops; calls to a provider at its own station, trusted only under the
//! realm keys the pool pins; and DHT records.

use std::collections::HashMap;
use std::sync::Arc;

use macula_rust::pool::{Call, Confidentiality, Opts, Pool, Report, Seed};
use macula_rust::record::{self, RecordType, Verified};

use crate::node_key::FfiNodeKey;
use crate::ucan::FfiUcan;
use crate::{millis, to_32, FfiError, FfiValue};

/// A station to link to: where it is dialed and the node_id it must prove.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiSeed {
    pub host: String,
    pub port: u16,
    pub node_id: Vec<u8>,
}

/// A realm's key as carried, the key its members pin.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiRealmKey {
    pub realm: Vec<u8>,
    pub key: Vec<u8>,
}

/// A pool's options. Zero for a number is macula's default.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Default)]
pub struct FfiPoolOptions {
    /// The realms whose org procedures the pool trusts and serves.
    #[uniffi(default = [])]
    pub realm_trust: Vec<FfiRealmKey>,
    #[uniffi(default = 0)]
    pub connect_timeout_ms: u64,
    #[uniffi(default = 0)]
    pub respawn_delay_ms: u64,
    #[uniffi(default = 0)]
    pub replication_factor: u32,
    #[uniffi(default = 0)]
    pub max_seeds: u32,
    #[uniffi(default = 0)]
    pub max_direct_links: u32,
    /// Try the links in a fresh random order each time, not seed order.
    #[uniffi(default = false)]
    pub random_link_order: bool,
    /// Give the node a KEM keyring and name its key in the advertisements
    /// of procedures served confidentially, so callers seal to it. Switch
    /// it on only once every station runs macula 12.11 or later and every
    /// caller runs 13.
    #[uniffi(default = false)]
    pub kem_advertise: bool,
}

/// How a served procedure takes its requests, and how a call or an open is
/// kept (macula 13, end-to-end payload sealing). Serving: `Preferred` names
/// the node's KEM key when the pool's `kem_advertise` is on and still takes
/// clear requests for a while; `Required` takes sealed ones only and needs
/// `kem_advertise`; `Off` names no key. Calling: `Preferred` seals to a
/// provider that names a key and calls one that names none in the clear;
/// `Required` calls only providers that name one; `Off` is refused.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiConfidentiality {
    Preferred,
    Required,
    Off,
}

impl From<FfiConfidentiality> for Confidentiality {
    fn from(c: FfiConfidentiality) -> Self {
        match c {
            FfiConfidentiality::Preferred => Confidentiality::Preferred,
            FfiConfidentiality::Required => Confidentiality::Required,
            FfiConfidentiality::Off => Confidentiality::Off,
        }
    }
}

/// One of the pool's links.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiLinkStatus {
    pub station: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub direct: bool,
    pub up: bool,
}

/// A caller's seal report on one exchange (macula's DESIGN_E2E_SEAL_REPORT):
/// `sealed` 1 when the request that produced the result was sealed and its
/// answer opened under the same key, whose 8-byte id `seal_key_id` names; 0,
/// with no key id, for a clear exchange. `provider` is the node the request
/// was addressed to. It states that sealing ran on this exchange, nothing
/// more.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiSealReport {
    pub sealed: u8,
    pub provider: Vec<u8>,
    pub seal_key_id: Option<Vec<u8>>,
}

impl From<Report> for FfiSealReport {
    fn from(r: Report) -> Self {
        FfiSealReport {
            sealed: r.sealed,
            provider: r.provider.to_vec(),
            seal_key_id: r.seal_key_id.map(|id| id.to_vec()),
        }
    }
}

/// A call's result and its seal report.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiCallReport {
    pub result: FfiValue,
    pub report: FfiSealReport,
}

/// A node serving a procedure, and the station it serves from.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiProvider {
    pub node: Vec<u8>,
    pub station: Vec<u8>,
}

/// A DHT record that verified: its type, its signer's key id, its times,
/// its payload, and its wire bytes.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiRecord {
    pub record_type: u8,
    pub signer: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub payload: FfiValue,
    pub wire: Vec<u8>,
}

impl TryFrom<Verified> for FfiRecord {
    type Error = FfiError;

    fn try_from(v: Verified) -> Result<Self, FfiError> {
        let r = v.into_record();
        let wire = record::encode(&r).map_err(|e| FfiError::Other {
            message: e.to_string(),
        })?;
        Ok(FfiRecord {
            record_type: r.record_type.0,
            signer: r
                .signed
                .as_ref()
                .map(|s| s.key_id.to_vec())
                .unwrap_or_default(),
            created_at: r.created_at,
            expires_at: r.expires_at,
            payload: r.payload.try_into()?,
            wire,
        })
    }
}

/// `name` in the own namespace of `node`, `~<node_id hex>/name`: a procedure
/// its node serves with no realm key, authorized by its signature alone.
#[uniffi::export]
pub fn own_procedure(node: Vec<u8>, name: String) -> Result<String, FfiError> {
    Ok(record::own_procedure(&to_32(node)?, &name))
}

/// A node's station links.
#[derive(uniffi::Object)]
pub struct FfiPool(pub(crate) Pool);

#[uniffi::export(async_runtime = "tokio")]
impl FfiPool {
    /// Links to every seed as `key`, and returns once one link is up.
    #[uniffi::constructor]
    pub async fn connect(
        key: Arc<FfiNodeKey>,
        seeds: Vec<FfiSeed>,
        options: FfiPoolOptions,
    ) -> Result<Arc<Self>, FfiError> {
        let mut opts = Opts::new(key.0.clone());
        let mut trust = HashMap::new();
        for r in options.realm_trust {
            trust.insert(to_32(r.realm)?, r.key);
        }
        opts.realm_trust = trust;
        opts.connect_timeout = millis(options.connect_timeout_ms);
        opts.respawn_delay = millis(options.respawn_delay_ms);
        opts.replication_factor = options.replication_factor as usize;
        opts.max_seeds = options.max_seeds as usize;
        opts.max_direct_links = options.max_direct_links as usize;
        opts.kem_advertise = options.kem_advertise;
        if options.random_link_order {
            opts.link_selection = macula_rust::pool::LinkSelection::Random;
        }
        let seeds = seeds
            .into_iter()
            .map(|s| {
                Ok(Seed {
                    host: s.host,
                    port: s.port,
                    node_id: to_32(s.node_id)?,
                })
            })
            .collect::<Result<Vec<_>, FfiError>>()?;
        Ok(Arc::new(FfiPool(Pool::connect(seeds, opts).await?)))
    }

    /// The node_id the pool links as.
    pub fn node_id(&self) -> Vec<u8> {
        self.0.node_id().to_vec()
    }

    /// Every link the pool holds, seeds first.
    pub fn status(&self) -> Vec<FfiLinkStatus> {
        self.0
            .status()
            .into_iter()
            .map(|l| FfiLinkStatus {
                station: l.station.to_vec(),
                host: l.host,
                port: l.port,
                direct: l.direct,
                up: l.up,
            })
            .collect()
    }

    /// Ends every link with a GOODBYE, and every subscription.
    pub async fn close(&self) {
        self.0.close().await;
    }

    /// Calls `procedure` in `realm` at a provider that serves it (`provider`,
    /// or any trusted one when `None`), waiting up to `timeout_ms` (0 for
    /// macula's 5 seconds), presenting `ucan` to a gated procedure. A
    /// provider's ERROR is [`FfiError::Provider`]: unauthorized for a token a
    /// gated procedure does not accept.
    #[allow(clippy::too_many_arguments)]
    pub async fn call(
        &self,
        realm: Vec<u8>,
        procedure: String,
        payload: FfiValue,
        provider: Option<Vec<u8>>,
        timeout_ms: u64,
        confidential: FfiConfidentiality,
        ucan: Option<FfiUcan>,
    ) -> Result<FfiValue, FfiError> {
        let (token, proofs) = presented(ucan);
        let answered = self
            .0
            .call(Call {
                realm: to_32(realm)?,
                procedure,
                provider: provider.map(to_32).transpose()?.unwrap_or([0; 32]),
                payload: payload.into(),
                timeout: millis(timeout_ms),
                confidential: confidential.into(),
                token,
                proofs,
            })
            .await?;
        answered.try_into()
    }

    /// [`FfiPool::call`], returning with its result the call's seal report.
    /// An error comes with no report.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_report(
        &self,
        realm: Vec<u8>,
        procedure: String,
        payload: FfiValue,
        provider: Option<Vec<u8>>,
        timeout_ms: u64,
        confidential: FfiConfidentiality,
        ucan: Option<FfiUcan>,
    ) -> Result<FfiCallReport, FfiError> {
        let (token, proofs) = presented(ucan);
        let (result, report) = self
            .0
            .call_report(Call {
                realm: to_32(realm)?,
                procedure,
                provider: provider.map(to_32).transpose()?.unwrap_or([0; 32]),
                payload: payload.into(),
                timeout: millis(timeout_ms),
                confidential: confidential.into(),
                token,
                proofs,
            })
            .await?;
        Ok(FfiCallReport {
            result: result.try_into()?,
            report: report.into(),
        })
    }

    /// Every provider of `procedure` in `realm` the pinned realm key
    /// authorizes, freshest first.
    pub async fn providers(
        &self,
        realm: Vec<u8>,
        procedure: String,
    ) -> Result<Vec<FfiProvider>, FfiError> {
        let found = self.0.providers(&to_32(realm)?, &procedure).await?;
        Ok(found
            .into_iter()
            .map(|p| FfiProvider {
                node: p.node.to_vec(),
                station: p.station.to_vec(),
            })
            .collect())
    }

    /// The record under `key`, verified.
    pub async fn find_record(&self, key: Vec<u8>) -> Result<FfiRecord, FfiError> {
        self.0.find_record(&to_32(key)?).await?.try_into()
    }

    /// The records under `key` that verify.
    pub async fn find_records(&self, key: Vec<u8>) -> Result<Vec<FfiRecord>, FfiError> {
        let (found, _) = self.0.find_records(&to_32(key)?).await?;
        found.into_iter().map(FfiRecord::try_from).collect()
    }

    /// The records of `record_type` the station holds that verify.
    pub async fn find_records_by_type(&self, record_type: u8) -> Result<Vec<FfiRecord>, FfiError> {
        let (found, _) = self.0.find_records_by_type(RecordType(record_type)).await?;
        found.into_iter().map(FfiRecord::try_from).collect()
    }

    /// Puts a signed record, as its wire bytes, in the DHT.
    pub async fn put_record(&self, wire: Vec<u8>) -> Result<(), FfiError> {
        Ok(self.0.put_record(&wire).await?)
    }
}

/// A presented UCAN as a request carries it: the token, `None` for none,
/// and its chain's proofs.
pub(crate) fn presented(ucan: Option<FfiUcan>) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
    ucan.map_or((None, Vec::new()), |u| (Some(u.token), u.proofs))
}
