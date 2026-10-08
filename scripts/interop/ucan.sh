#!/usr/bin/env bash
# UCANs macula-rust mints, authorized by macula's macula_ucan: the reverse of
# the vectors, which macula mints and tests/ucan.rs checks. tests/interop_ucan.rs
# writes the cases (a token, its proofs, the policy's issuer, the context and
# the verdict macula must reach), then erlang_ucan.escript authorizes each and
# exits non-zero on any verdict that differs. Runs where podman is, cargo and
# the Erlang side in the pinned CI image.
#
#   MACULA_BUILD=<a compiled macula checkout, 13.6 or later> scripts/interop/ucan.sh
#
# erlang_ucan.escript is macula-go's (scripts/interop at c635e30), unchanged.
# CGROUP_PARENT puts the containers in a CI host's cgroup slice.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp:20260923-1347@sha256:b2260d084a3d3c5e0b74932c4ee052a0cadfddddb6587d5d2214873e6bb06330}"
: "${MACULA_BUILD:?a compiled macula checkout, 13.6 or later}"
slice=${CGROUP_PARENT:+--cgroup-parent=$CGROUP_PARENT}
cases="target/interop-ucan/rust_ucans.json"

mkdir -p "$root/target/interop-cargo" "$root/target/interop-ucan"
podman run --rm --init $slice \
  -e MACULA_RUST_UCAN_CASES="/w/$cases" \
  -e CARGO_HOME=/w/target/interop-cargo -e CARGO_TARGET_DIR=/w/target/interop \
  -v "$root:/w:Z" -w /w "$image" \
  cargo test --locked --test interop_ucan -- --ignored --exact tokens_for_macula_to_authorize
podman run --rm $slice \
  -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" -v "$root/$(dirname "$cases"):/cases:ro" \
  "$image" escript /interop/erlang_ucan.escript /macula/_build/default/lib/macula "/cases/$(basename "$cases")"
echo "== every UCAN macula-rust minted reached macula's verdict"
