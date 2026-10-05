#!/usr/bin/env bash
# Sealed calls and streams from macula-rust to a macula 13 provider, end to
# end, through the lab station (tests/teststation): an Erlang provider with
# kem_advertise on serves ~<node>/vault and ~<node>/watch, confidential =>
# required, and tests/interop_sealed.rs calls and streams to them sealed.
# A required provider refuses every clear request, so an answer proves the
# seal. Runs where podman is, the Erlang side and cargo in the pinned CI image.
#
#   MACULA_BUILD=<a compiled macula 13.x checkout> scripts/interop/sealed.sh [pq_hybrid|pq_pure]
#
# erlang_sealed.escript is macula-go's (scripts/interop at 0cb83e8), unchanged.
# Needs target/teststation (scripts/build-teststation.sh). CGROUP_PARENT puts
# the containers in a CI host's cgroup slice.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp:20260923-1347@sha256:b2260d084a3d3c5e0b74932c4ee052a0cadfddddb6587d5d2214873e6bb06330}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula checkout at v13.x}"
slice=${CGROUP_PARENT:+--cgroup-parent=$CGROUP_PARENT}
work="$(mktemp -d)"
erl_name="macula-rust-sealed-$$"
cleanup() {
  podman rm -f "$erl_name" > /dev/null 2>&1 || true
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

echo "== $profile: an Erlang provider, a Rust caller"
podman run --rm --name "$erl_name" --network host $slice \
  -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
  "$image" escript /interop/erlang_sealed.escript /macula/_build/default/lib/macula \
  "$host" "$port" "$station" "$realm" "$profile" serve 180 > "$work/erlang.out" 2>&1 &
first_line "$work/erlang.out" '^serving' > /dev/null
provider="$(first_line "$work/erlang.out" '^node ' | awk '{print $2}')"
mkdir -p "$root/target/interop-cargo"
podman run --rm --init --network host $slice \
  -e MACULA_RUST_SEALED_SEED="$host:$port" -e MACULA_RUST_SEALED_STATION_ID="$station" \
  -e MACULA_RUST_SEALED_REALM="$realm" -e MACULA_RUST_SEALED_PROFILE="$profile" \
  -e MACULA_RUST_SEALED_PROVIDER="$provider" \
  -e CARGO_HOME=/w/target/interop-cargo -e CARGO_TARGET_DIR=/w/target/interop \
  -v "$root:/w:Z" -w /w "$image" \
  cargo test --locked --test interop_sealed -- --ignored --nocapture
echo "== $profile: sealed to a macula 13 provider"
