#!/usr/bin/env bash
# Sealed calls and streams between macula-rust and macula 17.2.0, end to end,
# both ways, through the lab station (tests/teststation). First an Erlang
# provider with kem_advertise on serves ~<node>/vault and ~<node>/watch,
# confidential => required, and tests/interop_sealed.rs calls and streams to
# them sealed. Then tests/interop_sealed.rs serves the same two, required, from
# a Rust pool with kem_advertise on, and erlang_sealed.escript calls them as
# macula does, sealed, and once in the clear, which must be refused
# sealed_required. A required provider refuses every clear request, so an
# answer proves the seal.
#
# Release A0 (DESIGN_E2E_SEALED_BY_DEFAULT.md section 8.1) is the third case:
# an Erlang provider built to name the key it holds in its signed refusal
# (erlang_sealed.escript's serve_a0, macula 17.2.0's refusal_names_key), and a
# Rust caller that only ever learns that key there. tests/interop_sealed_a0.rs
# sends four clear requests -- a call, a server stream open, a client stream
# that wrote first, and a bidi stream the provider answers only after the
# caller's first chunk -- and each has to come back sealed to the provider's
# own key (macula-rust#49, macula-rust#42).
#
# Runs where podman is, the Erlang side and cargo in the pinned CI image.
#
#   MACULA_BUILD=<a compiled macula 17.2.0 checkout> scripts/interop/sealed.sh [pq_hybrid|pq_pure]
#
# erlang_sealed.escript is macula-go's (scripts/interop at 4c357ca), unchanged
# but for its header; MACULA_SEALED_PEER=rust names the texts it expects from a
# Rust provider. The Rust caller always checks its seal reports
# (DESIGN_E2E_SEAL_REPORT): the call's and the stream's, sealed 1, addressed to
# the Erlang provider, naming one key. MACULA_SEAL_REPORT=1 has the Erlang
# caller check its own reports of the Rust provider the same way, and
# MACULA_OFF_REFUSED=1 has it require a direct dial with confidential => off
# refused.
# Needs target/teststation (scripts/build-teststation.sh). CGROUP_PARENT puts
# the containers in a CI host's cgroup slice.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp:20260923-1347@sha256:b2260d084a3d3c5e0b74932c4ee052a0cadfddddb6587d5d2214873e6bb06330}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula checkout at v17.2.0}"
slice=${CGROUP_PARENT:+--cgroup-parent=$CGROUP_PARENT}
work="$(mktemp -d)"
erl_name="macula-rust-sealed-$$"
rust_name="macula-rust-sealed-provider-$$"
cleanup() {
  podman rm -f "$erl_name" "$rust_name" > /dev/null 2>&1 || true
  exec 3>&- || true
  rm -rf "$work"
}
trap cleanup EXIT

mkfifo "$work/stations.in"
"$root/target/teststation" "$profile" < "$work/stations.in" > "$work/stations.out" &
exec 3> "$work/stations.in"

# first_line FILE PATTERN waits up to 180 s for a line of FILE matching PATTERN.
first_line() {
  for _ in $(seq 1 900); do
    line="$(grep -m1 -E "$2" "$1" 2> /dev/null || true)"
    [ -n "$line" ] && { echo "$line"; return 0; }
    sleep 0.2
  done
  echo "sealed.sh: no line matching $2 in $1" >&2
  cat "$1" >&2 || true
  return 1
}
info="$(first_line "$work/stations.out" '^\{')"
read -r host port station realm < <(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); s=d["stations"][0]; print(s["host"], s["port"], s["node_id"], d["realm_id"])' "$info")

# erl ARGS runs erlang_sealed.escript in the CI image against MACULA_BUILD.
erl() {
  podman run --rm --name "$erl_name" --network host $slice \
    -e MACULA_OFF_REFUSED="${MACULA_OFF_REFUSED:-}" -e MACULA_SEALED_PEER=rust \
    -e MACULA_SEAL_REPORT="${MACULA_SEAL_REPORT:-}" \
    -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
    "$image" escript /interop/erlang_sealed.escript /macula/_build/default/lib/macula \
    "$host" "$port" "$station" "$realm" "$profile" "$@"
}

# stop_erl stops the Erlang serve this script started, so the next case dials
# a station with nobody serving the previous provider's procedures.
stop_erl() {
  podman rm -f "$erl_name" > /dev/null 2>&1 || true
}

# rust_test FILE NAME runs one ignored test of FILE in the CI image, with the
# interop variables every test here reads; EXTRA_ENV is passed through as-is.
rust_test() {
  local file="$1" name="$2" extra="${3:-}"
  mkdir -p "$root/target/interop-cargo"
  # shellcheck disable=SC2086 # EXTRA_ENV is a list of -e flags, by design.
  podman run --rm --init --network host $slice \
    -e MACULA_RUST_SEALED_SEED="$host:$port" -e MACULA_RUST_SEALED_STATION_ID="$station" \
    -e MACULA_RUST_SEALED_REALM="$realm" -e MACULA_RUST_SEALED_PROFILE="$profile" \
    $extra \
    -e CARGO_HOME=/w/target/interop-cargo -e CARGO_TARGET_DIR=/w/target/interop \
    -v "$root:/w:Z" -w /w "$image" \
    cargo test --locked --test "$file" -- --ignored --nocapture --exact "$name"
}

echo "== $profile: an Erlang provider, a Rust caller"
erl serve 180 > "$work/erlang.out" 2>&1 &
first_line "$work/erlang.out" '^serving' > /dev/null
provider="$(first_line "$work/erlang.out" '^node ' | awk '{print $2}')"
rust_test interop_sealed a_sealed_call_and_stream_reach_a_required_macula_provider \
  "-e MACULA_RUST_SEALED_PROVIDER=$provider"
stop_erl

# Release A0 (DESIGN_E2E_SEALED_BY_DEFAULT.md section 8.1): a provider built to
# name its key in a refusal, and a caller that only ever learns it there. This
# is macula-rust#49, and the only cross-SDK case that checks a Rust caller
# recovers from macula's own refusal rather than from an in-process peer.
echo "== $profile: an Erlang provider naming its key (release A0), a Rust caller"
erl serve_a0 180 > "$work/erlang-a0.out" 2>&1 &
first_line "$work/erlang-a0.out" '^serving' > /dev/null
provider="$(first_line "$work/erlang-a0.out" '^node ' | awk '{print $2}')"
carried="$(first_line "$work/erlang-a0.out" '^kem ' | awk '{print $2}')"
rust_test interop_sealed_a0 a_clear_request_reaches_a_keyed_macula_provider_sealed \
  "-e MACULA_RUST_SEALED_PROVIDER=$provider -e MACULA_RUST_SEALED_KEM=$carried"
stop_erl

echo "== $profile: a Rust provider, an Erlang caller"
mkdir -p "$root/target/interop-cargo"
podman run --rm --init --name "$rust_name" --network host $slice \
  -e MACULA_RUST_SEALED_SEED="$host:$port" -e MACULA_RUST_SEALED_STATION_ID="$station" \
  -e MACULA_RUST_SEALED_REALM="$realm" -e MACULA_RUST_SEALED_PROFILE="$profile" \
  -e MACULA_RUST_SEALED_HOLD=240 \
  -e CARGO_HOME=/w/target/interop-cargo -e CARGO_TARGET_DIR=/w/target/interop \
  -v "$root:/w:Z" -w /w "$image" \
  cargo test --locked --test interop_sealed -- --ignored --nocapture --exact \
  a_required_rust_provider_serves_a_macula_caller_sealed > "$work/rust.out" 2>&1 &
first_line "$work/rust.out" '^serving' > /dev/null
provider="$(first_line "$work/rust.out" '^node ' | awk '{print $2}')"
erl call "$provider"
echo "== $profile: both ways sealed"
