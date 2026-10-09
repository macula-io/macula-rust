//! macula 12's UCAN, macula's `macula_ucan` in Rust: tokens signed in the
//! node's crypto profile (D7), and a provider's authorization of one.
//! macula's `test/vectors/UCAN_V1.md` is the contract, and
//! `tests/vectors/ucan` holds its vectors; every verdict here is macula's,
//! reached in the same order.
//!
//! A token is a JWT, header.payload.signature, each part base64url without
//! padding. The header names the profile's algorithm: ML-DSA-87 in pq_pure,
//! ML-DSA-87-PS384 (the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512) in
//! pq_hybrid. The signature is the issuer's node key's over the header and
//! payload as sent. The payload's `iss` is a did:key for the issuer's key as
//! carried; `aud` is the lowercase hex node_id of the node that presents the
//! token, which must be the request's verified caller; `cap` lists
//! `{with, can}`; `exp` is in seconds, at most [`MAX_LIFETIME`] past now.
//!
//! A token may rest on a parent: its `prf` names the parent by [`proof_id`],
//! and the parents travel beside it in the request's caller-signed proofs.
//! The chain is walked to its root, which must be the issuer the policy
//! names; each link's own signature and validity window hold, each parent's
//! `aud` is the node_id of its child's issuer, `can` is equal at every step,
//! and a child's capability is covered by one of its parent's ([`covers`]).
//! Every proof that travelled must be used.

mod capability;
mod chain;
mod did_key;
mod first_wins;
mod token;

use std::collections::HashMap;
use std::fmt;

use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};

use crate::node_key::{KeyError, NodeKey, Purpose};
use crate::profile::Profile;

pub use capability::covers;
pub use did_key::{carried_key, did_key, MAX_DID_KEY_ENCODED};

/// The furthest past now, in seconds, that a token's `exp` may lie: ten
/// years of 365.25 days, as `macula_ucan:max_lifetime/0`. UCAN_V1 has no
/// revocation, so `exp` is the only bound on a token's life. An `exp` in
/// milliseconds lies far beyond it, so a token minted with one is refused,
/// by [`create`] and by [`authorize`], rather than valid for tens of
/// thousands of years.
pub const MAX_LIFETIME: i64 = 315_576_000;

/// Why a token does not authorize: one of `macula_ucan`'s refusals, by the
/// same name ([`Refusal::name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    Malformed,
    WrongAlgorithm,
    SignatureInvalid,
    NotTheIssuer,
    NotTheAudience,
    Expired,
    ExpBeyondMaxLifetime,
    NotYetValid,
    MissingCapability,
    MissingProof,
    UnreferencedProof,
    NotTheDelegate,
    ChainNotLinear,
    GrantsMoreThanProof,
    CanChanged,
    WrongRealm,
    RealmNameNotCanonical,
    ProcedureWithoutOrg,
}

impl Refusal {
    /// The refusal's name in macula: `not_the_audience`, say.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::WrongAlgorithm => "wrong_algorithm",
            Refusal::SignatureInvalid => "signature_invalid",
            Refusal::NotTheIssuer => "not_the_issuer",
            Refusal::NotTheAudience => "not_the_audience",
            Refusal::Expired => "expired",
            Refusal::ExpBeyondMaxLifetime => "exp_beyond_max_lifetime",
            Refusal::NotYetValid => "not_yet_valid",
            Refusal::MissingCapability => "missing_capability",
            Refusal::MissingProof => "missing_proof",
            Refusal::UnreferencedProof => "unreferenced_proof",
            Refusal::NotTheDelegate => "not_the_delegate",
            Refusal::ChainNotLinear => "chain_not_linear",
            Refusal::GrantsMoreThanProof => "grants_more_than_proof",
            Refusal::CanChanged => "can_changed",
            Refusal::WrongRealm => "wrong_realm",
            Refusal::RealmNameNotCanonical => "realm_name_not_canonical",
            Refusal::ProcedureWithoutOrg => "procedure_without_org",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ucan: {}", self.name())
    }
}

impl std::error::Error for Refusal {}

/// What a gated procedure requires of a request's token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// A token whose chain is rooted at the identity key of this node_id.
    UcanRequired { issuer: [u8; 32] },
    /// A token whose chain is rooted at the realm key of this key id,
    /// granting a capability with this `can`.
    RealmMemberRequired { key_id: [u8; 32], can: String },
}

impl Policy {
    /// Whether a procedure may be served under the policy, as macula's
    /// advertise checks it: a realm member policy names a `can`.
    pub fn valid(&self) -> bool {
        match self {
            Policy::UcanRequired { .. } => true,
            Policy::RealmMemberRequired { can, .. } => !can.is_empty(),
        }
    }
}

/// The request a token is presented with: its realm id and procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub realm: [u8; 32],
    pub procedure: String,
}

/// What a token is authorized against: the request's verified caller, the
/// provider's profile, the time in seconds, the request (`None` to check the
/// token alone, as a gate with no request in front of it), and the proofs
/// that travelled with it, keyed by [`proof_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub caller: [u8; 32],
    pub profile: Profile,
    pub now: i64,
    pub request: Option<Request>,
    pub proofs: HashMap<String, Vec<u8>>,
}

impl Context {
    /// The proofs as a request carries them, keyed by [`proof_id`].
    pub fn keyed_proofs(proofs: &[Vec<u8>]) -> HashMap<String, Vec<u8>> {
        proofs.iter().map(|p| (proof_id(p), p.clone())).collect()
    }
}

/// One grant: a `with` (an MRI) and a `can`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub with: String,
    pub can: String,
}

/// A token's claims beyond `iss`, `aud` and `cap`: `exp` (seconds) is
/// required, the rest optional. `prf` names the token's parent by
/// [`proof_id`]; at most one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Options {
    pub exp: i64,
    pub nbf: Option<i64>,
    pub nnc: Option<String>,
    pub fct: Option<Map<String, Value>>,
    pub prf: Option<Vec<String>>,
}

/// Why [`create`] mints no token, naming the values it compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateError {
    /// A token is signed by an identity key, and this key is not one.
    NotAnIdentityKey(Purpose),
    /// `exp` lies more than [`MAX_LIFETIME`] past `now`: at most `max`.
    ExpBeyondMaxLifetime { exp: i64, now: i64, max: i64 },
    /// `nbf` is not before `exp`, so the token would never be valid.
    WindowNeverOpens { nbf: i64, exp: i64 },
    /// The issuer's key could not sign.
    Sign(KeyError),
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateError::NotAnIdentityKey(purpose) => {
                write!(
                    f,
                    "ucan: a token is signed by an identity key, not a {purpose} key"
                )
            }
            CreateError::ExpBeyondMaxLifetime { exp, now, max } => write!(
                f,
                "ucan: exp_beyond_max_lifetime: exp {exp}, now {now}, at most {max} \
                 (milliseconds, where seconds are meant?)"
            ),
            CreateError::WindowNeverOpens { nbf, exp } => write!(
                f,
                "ucan: nbf is not before exp, so the token is never valid: nbf {nbf}, exp {exp}"
            ),
            CreateError::Sign(e) => write!(f, "ucan: {e}"),
        }
    }
}

impl std::error::Error for CreateError {}

const TYP: &str = "JWT";
const UCV: &str = "0.10.0";

/// A JWT part's base64url: no padding, as macula writes it.
const BASE64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The `alg` a token names in `profile`.
fn algorithm(profile: Profile) -> &'static str {
    match profile {
        Profile::PqPure => "ML-DSA-87",
        Profile::PqHybrid => "ML-DSA-87-PS384",
    }
}

/// A token from `issuer`'s identity key, for the audience's node_id,
/// granting `caps` until `o.exp`. An `exp` more than [`MAX_LIFETIME`] past
/// now, or an `nbf` not before `exp`, is refused, naming the values.
pub fn create(
    issuer: &NodeKey,
    audience: &[u8; 32],
    caps: &[Capability],
    o: &Options,
) -> Result<Vec<u8>, CreateError> {
    if issuer.purpose() != Purpose::Identity {
        return Err(CreateError::NotAnIdentityKey(issuer.purpose()));
    }
    window_opens(o, now_seconds())?;
    let caps: Vec<Value> = caps
        .iter()
        .map(|c| serde_json::json!({"with": c.with, "can": c.can}))
        .collect();
    let mut claims = Map::new();
    claims.insert(
        "iss".into(),
        Value::String(did_key(&issuer.public_key(), issuer.profile())),
    );
    claims.insert("aud".into(), Value::String(hex(audience)));
    claims.insert("cap".into(), Value::Array(caps));
    claims.insert("exp".into(), Value::from(o.exp));
    if let Some(nbf) = o.nbf {
        claims.insert("nbf".into(), Value::from(nbf));
    }
    if let Some(nnc) = o.nnc.as_ref().filter(|n| !n.is_empty()) {
        claims.insert("nnc".into(), Value::String(nnc.clone()));
    }
    if let Some(fct) = &o.fct {
        claims.insert("fct".into(), Value::Object(fct.clone()));
    }
    if let Some(prf) = &o.prf {
        claims.insert(
            "prf".into(),
            Value::Array(prf.iter().cloned().map(Value::String).collect()),
        );
    }
    let header = serde_json::json!({"alg": algorithm(issuer.profile()), "typ": TYP, "ucv": UCV});
    let input = format!(
        "{}.{}",
        BASE64URL.encode(header.to_string()),
        BASE64URL.encode(Value::Object(claims).to_string())
    );
    let signature = issuer.sign(input.as_bytes()).map_err(CreateError::Sign)?;
    Ok(format!("{input}.{}", BASE64URL.encode(signature)).into_bytes())
}

/// Whether `o`'s validity window is one [`create`] mints at `now`: an `exp`
/// at most [`MAX_LIFETIME`] past now, and an `nbf`, if any, before `exp`.
fn window_opens(o: &Options, now: i64) -> Result<(), CreateError> {
    let max = now.saturating_add(MAX_LIFETIME);
    if o.exp > max {
        return Err(CreateError::ExpBeyondMaxLifetime {
            exp: o.exp,
            now,
            max,
        });
    }
    match o.nbf {
        Some(nbf) if nbf >= o.exp => Err(CreateError::WindowNeverOpens { nbf, exp: o.exp }),
        _ => Ok(()),
    }
}

/// The id a child's `prf` names a parent token by: the lowercase hex of the
/// SHA-384 of the token's bytes as they travel.
pub fn proof_id(token: &[u8]) -> String {
    hex(&Sha384::digest(token))
}

/// Whether `token` authorizes `ctx`'s caller under `p`: the token's claims
/// when it does, or the first refusal, in `macula_ucan`'s order.
pub fn authorize(token: &[u8], p: &Policy, ctx: &Context) -> Result<Map<String, Value>, Refusal> {
    let mut leaf = token::Checked::parsed(token)?;
    leaf.algorithm_is(ctx.profile)?;
    leaf.signed_by_iss(ctx.profile)?;
    leaf.audience_is(&ctx.caller)?;
    leaf.valid_at(ctx.now)?;
    let granted = capability::grants(p, ctx.request.as_ref(), &leaf.claims)?;
    chain::chained(p, ctx, &leaf, granted)?;
    Ok(leaf.claims)
}

/// The time in unix seconds.
pub(crate) fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_beyond_the_max_lifetime_or_never_open_is_not_minted() {
        let now = 1_790_000_000;
        let at = |exp, nbf| Options {
            exp,
            nbf,
            ..Options::default()
        };
        assert_eq!(window_opens(&at(now + MAX_LIFETIME, None), now), Ok(()));
        assert_eq!(
            window_opens(&at(now + MAX_LIFETIME + 1, None), now),
            Err(CreateError::ExpBeyondMaxLifetime {
                exp: now + MAX_LIFETIME + 1,
                now,
                max: now + MAX_LIFETIME
            })
        );
        assert_eq!(window_opens(&at(now + 10, Some(now + 9)), now), Ok(()));
        assert_eq!(
            window_opens(&at(now + 10, Some(now + 10)), now),
            Err(CreateError::WindowNeverOpens {
                nbf: now + 10,
                exp: now + 10
            })
        );
    }

    #[test]
    fn the_max_lifetime_is_ten_years_of_365_25_days() {
        assert_eq!(MAX_LIFETIME, 10 * 36525 * 24 * 3600 / 100);
    }
}
