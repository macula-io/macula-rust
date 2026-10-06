//! A token's delegation chain, walked a link at a time from the leaf: the
//! shape of `prf`, the parent among the proofs, the parent as a token, its
//! audience the child's issuer, and the narrowing; then the root against the
//! policy, and last, a proof no link used.

use std::collections::HashMap;

use serde_json::Value;

use super::capability::narrowed;
use super::token::Checked;
use super::{hex, Context, Policy, Refusal};
use crate::node_key::{key_id_of, node_id_of};
use crate::profile::Profile;

/// Walks the leaf's chain to its root, which must be the issuer `p` names,
/// with `granted` the capabilities the leaf hands on; every proof that
/// travelled must be used.
pub(super) fn chained(
    p: &Policy,
    ctx: &Context,
    leaf: &Checked,
    granted: Vec<Value>,
) -> Result<(), Refusal> {
    let mut proofs = ctx.proofs.clone();
    let root = walk(ctx, leaf, granted, &mut proofs)?;
    issued_by(p, root_key(leaf, root.as_ref()), ctx.profile)?;
    match proofs.is_empty() {
        true => Ok(()),
        false => Err(Refusal::UnreferencedProof),
    }
}

fn root_key<'a>(leaf: &'a Checked, root: Option<&'a Checked>) -> &'a [u8] {
    root.unwrap_or(leaf).issuer_key.as_slice()
}

/// Checks each link from `child` up, taking each proof it uses out of
/// `proofs`; the root's token, or `None` when `child` is the root.
fn walk(
    ctx: &Context,
    child: &Checked,
    granted: Vec<Value>,
    proofs: &mut HashMap<String, Vec<u8>>,
) -> Result<Option<Checked>, Refusal> {
    let mut child_key = child.issuer_key.clone();
    let mut prf = child.claims.get("prf").cloned();
    let mut granted = granted;
    let mut root = None;
    while let Some(id) = parent_id(prf.as_ref())? {
        let proof = proofs.remove(&id).ok_or(Refusal::MissingProof)?;
        let parent = chain_link(&proof, ctx)?;
        delegates_to(&parent, &child_key, ctx.profile)?;
        let caps = parent
            .claims
            .get("cap")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        granted = narrowed(caps, &granted)?;
        child_key = parent.issuer_key.clone();
        prf = parent.claims.get("prf").cloned();
        root = Some(parent);
    }
    Ok(root)
}

/// The proof id `prf` names: none when absent or empty, malformed when not a
/// list, and chain_not_linear for more than one id or one that is no text.
fn parent_id(prf: Option<&Value>) -> Result<Option<String>, Refusal> {
    let Some(prf) = prf else {
        return Ok(None);
    };
    match prf.as_array().map(Vec::as_slice) {
        None => Err(Refusal::Malformed),
        Some([]) => Ok(None),
        Some([Value::String(id)]) => Ok(Some(id.clone())),
        Some(_) => Err(Refusal::ChainNotLinear),
    }
}

/// A parent checked as a token: parts, algorithm, signature and validity
/// window. Its audience and capability are checked against its child.
fn chain_link(token: &[u8], ctx: &Context) -> Result<Checked, Refusal> {
    let mut parent = Checked::parsed(token)?;
    parent.algorithm_is(ctx.profile)?;
    parent.signed_by_iss(ctx.profile)?;
    parent.valid_at(ctx.now)?;
    Ok(parent)
}

/// The parent's `aud` is the node_id of its child's issuer key.
fn delegates_to(parent: &Checked, child_key: &[u8], profile: Profile) -> Result<(), Refusal> {
    match parent.aud() == Some(hex(&node_id_of(child_key, profile)).as_str()) {
        true => Ok(()),
        false => Err(Refusal::NotTheDelegate),
    }
}

/// The chain's root is signed by the issuer the policy names.
fn issued_by(p: &Policy, root_key: &[u8], profile: Profile) -> Result<(), Refusal> {
    let issued = match p {
        Policy::UcanRequired { issuer } => node_id_of(root_key, profile) == *issuer,
        Policy::RealmMemberRequired { key_id, .. } => key_id_of(root_key, profile) == *key_id,
    };
    match issued {
        true => Ok(()),
        false => Err(Refusal::NotTheIssuer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_names_at_most_one_parent_by_text() {
        let id = |v: Value| parent_id(Some(&v));
        assert_eq!(parent_id(None), Ok(None));
        assert_eq!(id(serde_json::json!([])), Ok(None));
        assert_eq!(id(serde_json::json!(["a"])), Ok(Some("a".into())));
        assert_eq!(
            id(serde_json::json!(["a", "b"])),
            Err(Refusal::ChainNotLinear)
        );
        assert_eq!(id(serde_json::json!([1])), Err(Refusal::ChainNotLinear));
        assert_eq!(id(serde_json::json!("a")), Err(Refusal::Malformed));
    }
}
