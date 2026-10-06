//! Capabilities: a `with` is an MRI, `mri:realm:<realm>`,
//! `mri:org:<realm>/<org>` or `mri:proc:<realm>/<procedure>`, and D7's
//! narrowing says which grant covers which. A request's realm id is SHA-256
//! over a grant's realm name, so a grant is checked against it with nothing
//! looked up.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{Policy, Refusal, Request};
use crate::record::procedure_org;

/// A `with` parsed: a realm, an org of that realm, or one procedure of that
/// realm.
#[derive(Debug, PartialEq, Eq)]
enum Grant<'a> {
    Realm(&'a str),
    Org(&'a str, &'a str),
    Proc(&'a str, &'a str),
}

impl<'a> Grant<'a> {
    fn realm(&self) -> &'a str {
        match self {
            Grant::Realm(realm) | Grant::Org(realm, _) | Grant::Proc(realm, _) => realm,
        }
    }
}

/// A `with` parsed into its grant, or why it is not one.
fn grant(with: &str) -> Result<Grant<'_>, Refusal> {
    let canonical = |realm| match canonical_realm_name(realm) {
        true => Ok(()),
        false => Err(Refusal::RealmNameNotCanonical),
    };
    if let Some(realm) = with.strip_prefix("mri:realm:") {
        canonical(realm)?;
        return Ok(Grant::Realm(realm));
    }
    if let Some(rest) = with.strip_prefix("mri:org:") {
        let (realm, org) = rest.split_once('/').ok_or(Refusal::Malformed)?;
        if org.is_empty() {
            return Err(Refusal::Malformed);
        }
        canonical(realm)?;
        return Ok(Grant::Org(realm, org));
    }
    if let Some(rest) = with.strip_prefix("mri:proc:") {
        let (realm, procedure) = rest.split_once('/').ok_or(Refusal::Malformed)?;
        canonical(realm)?;
        org_of(procedure)?;
        return Ok(Grant::Proc(realm, procedure));
    }
    Err(Refusal::Malformed)
}

/// A procedure's org, or procedure_without_org.
fn org_of(procedure: &str) -> Result<&str, Refusal> {
    match procedure_org(procedure) {
        Ok(Some(org)) => Ok(org),
        _ => Err(Refusal::ProcedureWithoutOrg),
    }
}

/// Whether a grant covers another grant or a request, by D7's narrowing: a
/// realm grant covers its realm, an org grant covers that org and its
/// procedures, a procedure grant only itself. False for a `with` that is not
/// one of the three MRIs, whose realm name is not canonical, or whose
/// procedure has no org.
pub fn covers(parent: &str, child: &str) -> bool {
    let (Ok(p), Ok(c)) = (grant(parent), grant(child)) else {
        return false;
    };
    match (p, c) {
        (Grant::Realm(realm), c) => c.realm() == realm,
        (Grant::Org(realm, org), Grant::Org(c_realm, c_org)) => c_realm == realm && c_org == org,
        (Grant::Org(realm, org), Grant::Proc(c_realm, procedure)) => {
            c_realm == realm && org_of(procedure) == Ok(org)
        }
        (Grant::Proc(realm, procedure), Grant::Proc(c_realm, c_procedure)) => {
            c_realm == realm && c_procedure == procedure
        }
        _ => false,
    }
}

/// At least one segment, segments joined by single dots, each of a-z, 0-9,
/// hyphen or underscore. Case is never folded.
fn canonical_realm_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

fn realm_id(realm: &str) -> [u8; 32] {
    Sha256::digest(realm.as_bytes()).into()
}

/// A capability entry's `with` when it is text, and its `can`, when it has
/// both.
fn with_and_can(entry: &Value) -> Option<(&str, &Value)> {
    let cap = entry.as_object()?;
    Some((cap.get("with")?.as_str()?, cap.get("can")?))
}

/// What the leaf hands up the chain: the capability the request needs, one
/// the token grants whose `can` is the policy's where it names one and whose
/// `with` covers the request's realm and procedure. With no request,
/// ucan_required hands on every capability, and realm_member_required the
/// first with its `can`.
pub(super) fn grants(
    p: &Policy,
    request: Option<&Request>,
    claims: &Map<String, Value>,
) -> Result<Vec<Value>, Refusal> {
    let caps = claims
        .get("cap")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if let Some(r) = request {
        return requested(p, r, caps);
    }
    match p {
        Policy::UcanRequired { .. } => Ok(caps.to_vec()),
        Policy::RealmMemberRequired { can, .. } => caps
            .iter()
            .find(|entry| {
                entry.as_object().and_then(|c| c.get("can")) == Some(&Value::String(can.clone()))
            })
            .map(|cap| vec![cap.clone()])
            .ok_or_else(|| why_not_granted(caps, None)),
    }
}

fn requested(p: &Policy, r: &Request, caps: &[Value]) -> Result<Vec<Value>, Refusal> {
    org_of(&r.procedure)?;
    let answers = |entry: &Value| {
        let Some((with, can)) = with_and_can(entry) else {
            return false;
        };
        let can_matches = match p {
            Policy::RealmMemberRequired { can: wanted, .. } => {
                can == &Value::String(wanted.clone())
            }
            Policy::UcanRequired { .. } => true,
        };
        let Ok(g) = grant(with) else {
            return false;
        };
        can_matches
            && realm_id(g.realm()) == r.realm
            && covers(with, &format!("mri:proc:{}/{}", g.realm(), r.procedure))
    };
    caps.iter()
        .find(|entry| answers(entry))
        .map(|cap| vec![cap.clone()])
        .ok_or_else(|| why_not_granted(caps, Some(&r.realm)))
}

/// Why no capability answered: the first text `with` decides (a grant not
/// well formed, or one in another realm, says so), and otherwise the
/// capability is missing. `realm` is `None` when there is no request.
fn why_not_granted(caps: &[Value], realm: Option<&[u8; 32]>) -> Refusal {
    let first = caps
        .iter()
        .find_map(|entry| entry.as_object()?.get("with")?.as_str());
    let Some(with) = first else {
        return Refusal::MissingCapability;
    };
    match (grant(with), realm) {
        (Err(Refusal::Malformed), _) => Refusal::MissingCapability,
        (Err(refusal), _) => refusal,
        (Ok(_), None) => Refusal::MissingCapability,
        (Ok(g), Some(realm)) if realm_id(g.realm()) == *realm => Refusal::MissingCapability,
        (Ok(_), Some(_)) => Refusal::WrongRealm,
    }
}

/// A parent carries up, for each capability its child hands on, the first
/// of its own that covers it with the same `can`; why not, otherwise, for
/// the first that fails in the child's order.
pub(super) fn narrowed(parent_caps: &[Value], children: &[Value]) -> Result<Vec<Value>, Refusal> {
    children
        .iter()
        .map(|child| covering(parent_caps, child))
        .collect()
}

fn covering(caps: &[Value], child: &Value) -> Result<Value, Refusal> {
    let child_cap = child.as_object().ok_or(Refusal::Malformed)?;
    let (Some(child_with), Some(child_can)) = (child_cap.get("with"), child_cap.get("can")) else {
        return Err(Refusal::Malformed);
    };
    let found = caps
        .iter()
        .find(|entry| match (with_and_can(entry), child_with.as_str()) {
            (Some((with, can)), Some(child_with)) => can == child_can && covers(with, child_with),
            _ => false,
        });
    found
        .cloned()
        .ok_or_else(|| why_not_narrowed(caps, child_with))
}

/// A parent that granted the same authority under another `can` changed it;
/// one of another realm is wrong_realm; otherwise it granted less than its
/// child hands on. The first of its capabilities decides.
fn why_not_narrowed(caps: &[Value], child_with: &Value) -> Refusal {
    let Some((with, _)) = caps.first().and_then(with_and_can) else {
        return Refusal::GrantsMoreThanProof;
    };
    match child_with.as_str() {
        Some(child) if same_realm(with, child) && covers(with, child) => Refusal::CanChanged,
        Some(child) if same_realm(with, child) => Refusal::GrantsMoreThanProof,
        _ => Refusal::WrongRealm,
    }
}

fn same_realm(with: &str, other: &str) -> bool {
    matches!((grant(with), grant(other)), (Ok(a), Ok(b)) if a.realm() == b.realm())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_realm_name_is_dotted_lowercase_segments() {
        for good in ["io.macula", "a", "a-b_c.0"] {
            assert!(canonical_realm_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "io..macula",
            "io.macula.",
            "IO.macula",
            "io macula",
            "é",
        ] {
            assert!(!canonical_realm_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_with_is_one_of_three_mris() {
        assert_eq!(grant("mri:realm:io.macula"), Ok(Grant::Realm("io.macula")));
        assert_eq!(
            grant("mri:org:io.macula/acme"),
            Ok(Grant::Org("io.macula", "acme"))
        );
        assert_eq!(
            grant("mri:proc:io.macula/acme/count_v1"),
            Ok(Grant::Proc("io.macula", "acme/count_v1"))
        );
        assert_eq!(grant("mri:org:io.macula/"), Err(Refusal::Malformed));
        assert_eq!(grant("mri:org:io.macula"), Err(Refusal::Malformed));
        assert_eq!(grant("mri:realm:IO"), Err(Refusal::RealmNameNotCanonical));
        assert_eq!(
            grant("mri:proc:io.macula/count"),
            Err(Refusal::ProcedureWithoutOrg)
        );
        assert_eq!(grant("https://x"), Err(Refusal::Malformed));
    }
}
