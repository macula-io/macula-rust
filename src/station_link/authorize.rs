//! A gated procedure's judgment of a verified request, as macula's link's
//! authorize_policy answers it.

use crate::frame::VerifiedRequest;
use crate::profile::Profile;
use crate::ucan::{self, Context, Policy, Refusal, Request};

/// The codes a gated procedure refuses a CALL or a STREAM_OPEN with.
const CODE_UNAUTHORIZED: &str = "unauthorized";
const CODE_MALFORMED_FRAME: &str = "malformed_frame";

/// The code to refuse `request` with under `policy`, or `None` to serve it.
/// An open procedure serves any caller. A gated one serves a request whose
/// token [`ucan::authorize`] accepts for the request's verified caller, now,
/// and the request's realm and procedure, its proofs keyed by proof id; a
/// request with no token is unauthorized. A proof no token in the chain
/// names is what the caller sent being wrong, not the authority it claims,
/// so malformed_frame, and every other refusal is unauthorized.
pub(super) fn authorize(
    profile: Profile,
    policy: Option<&Policy>,
    request: &VerifiedRequest,
) -> Option<&'static str> {
    let policy = policy?;
    let Some(token) = &request.token else {
        return Some(CODE_UNAUTHORIZED);
    };
    let ctx = Context {
        caller: request.caller,
        profile,
        now: ucan::now_seconds(),
        request: Some(Request {
            realm: request.realm,
            procedure: request.procedure.clone(),
        }),
        proofs: Context::keyed_proofs(request.proofs.as_deref().unwrap_or(&[])),
    };
    match ucan::authorize(token, policy, &ctx) {
        Ok(_) => None,
        Err(Refusal::UnreferencedProof) => Some(CODE_MALFORMED_FRAME),
        Err(_) => Some(CODE_UNAUTHORIZED),
    }
}
