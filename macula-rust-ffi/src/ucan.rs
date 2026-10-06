//! UCAN across the FFI: a node mints a token for another node's node_id, a
//! caller presents one with its delegation chain's proofs on a call or an
//! open, and a provider gates a procedure on a policy. The rules are
//! [`macula_rust::ucan`]'s, which are macula's.

use macula_rust::ucan::{self, Capability, CreateError, Options, Policy};

use crate::node_key::FfiNodeKey;
use crate::{to_32, FfiError};

/// A UCAN a call or an open presents, and the tokens of the delegation
/// chain it rests on, as they travel.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiUcan {
    pub token: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
}

/// What a gated procedure requires of a request's UCAN: a chain rooted at
/// the identity key of `issuer` (a node_id), or at the realm key of `key_id`
/// granting a capability with `can`.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiPolicy {
    UcanRequired { issuer: Vec<u8> },
    RealmMemberRequired { key_id: Vec<u8>, can: String },
}

impl TryFrom<FfiPolicy> for Policy {
    type Error = FfiError;

    fn try_from(p: FfiPolicy) -> Result<Self, FfiError> {
        Ok(match p {
            FfiPolicy::UcanRequired { issuer } => Policy::UcanRequired {
                issuer: to_32(issuer)?,
            },
            FfiPolicy::RealmMemberRequired { key_id, can } => Policy::RealmMemberRequired {
                key_id: to_32(key_id)?,
                can,
            },
        })
    }
}

/// One grant: a `with` (an MRI: `mri:realm:<realm>`, `mri:org:<realm>/<org>`
/// or `mri:proc:<realm>/<procedure>`) and a `can`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiCapability {
    pub with: String,
    pub can: String,
}

/// A token's claims beyond its issuer, audience and capabilities: `exp` in
/// unix seconds, at most ten years ahead; `nbf` before `exp`; a nonce; facts
/// as a JSON object's text; and the proof id of the parent it rests on.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiUcanOptions {
    pub exp: i64,
    pub nbf: Option<i64>,
    pub nnc: Option<String>,
    pub fct_json: Option<String>,
    pub parent: Option<String>,
}

impl From<CreateError> for FfiError {
    fn from(e: CreateError) -> Self {
        match e {
            CreateError::Sign(k) => FfiError::Key {
                message: k.to_string(),
            },
            other => FfiError::InvalidArgument {
                message: other.to_string(),
            },
        }
    }
}

#[uniffi::export]
impl FfiNodeKey {
    /// A UCAN from this identity key for the node `audience` (a node_id),
    /// granting `capabilities` as `options` say. A window macula would never
    /// accept, such as an `exp` in milliseconds, is refused naming its
    /// values.
    pub fn mint_ucan(
        &self,
        audience: Vec<u8>,
        capabilities: Vec<FfiCapability>,
        options: FfiUcanOptions,
    ) -> Result<Vec<u8>, FfiError> {
        let fct = options
            .fct_json
            .map(|text| match serde_json::from_str(&text) {
                Ok(serde_json::Value::Object(map)) => Ok(map),
                _ => Err(FfiError::InvalidArgument {
                    message: "fct_json is not a JSON object".into(),
                }),
            })
            .transpose()?;
        let caps: Vec<Capability> = capabilities
            .into_iter()
            .map(|c| Capability {
                with: c.with,
                can: c.can,
            })
            .collect();
        let o = Options {
            exp: options.exp,
            nbf: options.nbf,
            nnc: options.nnc,
            fct,
            prf: options.parent.map(|id| vec![id]),
        };
        Ok(ucan::create(&self.0, &to_32(audience)?, &caps, &o)?)
    }
}

/// The proof id a child token's parent is named by: the lowercase hex of the
/// SHA-384 of the parent token's bytes.
#[uniffi::export]
pub fn ucan_proof_id(token: Vec<u8>) -> String {
    ucan::proof_id(&token)
}
