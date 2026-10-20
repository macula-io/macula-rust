#!/usr/bin/env bash
# Sealed groups across macula (13.2 on, wire 1.0) and macula-rust, both ways,
# through the lab station (tests/teststation) and macula's own distributor
# (macula_group_keys, DESIGN_E2E_SEALED_PUBSUB.md): the org's distributor runs
# in Erlang; an Erlang member and the Rust member here each subscribe under
# the group, pulling its epoch from that distributor over a sealed call with
# the org's grant, and each publishes sealed under it; each must open the
# other's event. Then a node the distributor's removed set names must be
# refused not_a_member at this crate's public subscribe. The Erlang side and
# cargo run in macula's pinned CI image.
#
#   MACULA_BUILD=<macula 15.0.0-rc.1 or later, compiled> scripts/interop/groups.sh [pq_hybrid|pq_pure]
#
# MACULA_BUILD may be a rebar3 project that depends on macula from hex, as for
# sealed.sh. Needs target/teststation (scripts/build-teststation.sh).
# CGROUP_PARENT puts the containers in a CI host's cgroup slice.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
: "${MACULA_BUILD:?a compiled macula at 15.0.0-rc.1 or later (wire 1.0)}"
slice=${CGROUP_PARENT:+--cgroup-parent=$CGROUP_PARENT}
work="$(mktemp -d)"
shared="$work/shared"
mkdir -p "$shared" "$root/target/interop-cargo"
chmod 777 "$shared"
names=("macula-rust-groups-dist-$$" "macula-rust-groups-member-$$" "macula-rust-groups-rust-$$" "macula-rust-groups-stranger-$$")
cleanup() {
  for n in "${names[@]}"; do podman rm -f "$n" > /dev/null 2>&1 || true; done
  exec 3>&- || true
  rm -rf "$work"
}
trap cleanup EXIT

mkfifo "$work/stations.in"
"$root/target/teststation" "$profile" < "$work/stations.in" > "$work/stations.out" &
exec 3> "$work/stations.in"

# nth_line FILE PATTERN N waits up to 180 s for the Nth line of FILE matching PATTERN.
nth_line() {
  for _ in $(seq 1 900); do
    line="$(grep -E "$2" "$1" 2> /dev/null | sed -n "$3p" || true)"
    [ -n "$line" ] && { echo "$line"; return 0; }
    sleep 0.2
  done
  echo "groups.sh: no line $3 matching $2 in $1" >&2
  cat "$1" >&2 || true
  return 1
}
info="$(nth_line "$work/stations.out" '^\{' 1)"
read -r host port station realm realm_key org org_key_id < <(python3 -c '
import json,sys; d=json.loads(sys.argv[1]); s=d["stations"][0]
print(s["host"], s["port"], s["node_id"], d["realm_id"], d["realm_key"], d["org"], d["org_key_id"])' "$info")
realm_name="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["realm_name"])' "$info")"
prefix="$realm_name/$org/chat"
topic="$prefix/said_v1"
grants=0

# grant NODE asks the test station for the org's grant to NODE and writes it where NODE waits for it.
grant() {
  echo "grant $1" >&3
  grants=$((grants + 1))
  # Written aside and moved into place: the node reads the file the moment it exists.
  nth_line "$work/stations.out" '^grant ' "$grants" | cut -d' ' -f2 > "$work/grant.tmp"
  mv "$work/grant.tmp" "$shared/grant.$1"
}
erl() {
  local name="$1"; shift
  podman run --rm --name "$name" --network host $slice -e MACULA_GROUPS_PEER=rust \
    -v "$MACULA_BUILD:/macula:ro" -v "$root/scripts/interop:/interop:ro" \
    -v "$shared:/work" "$image" escript /interop/erlang_groups.escript /macula/_build/default/lib/macula \
    "$host" "$port" "$station" "$realm" "$realm_key" "$profile" /work "$@"
}
# rustpeer CONTAINER TEST runs one of tests/interop_groups.rs's ignored tests on the station.
rustpeer() {
  podman run --rm --init --name "$1" --network host $slice \
    -e MACULA_RUST_GROUPS_SEED="$host:$port" -e MACULA_RUST_GROUPS_STATION_ID="$station" \
    -e MACULA_RUST_GROUPS_REALM="$realm" -e MACULA_RUST_GROUPS_REALM_KEY="$realm_key" \
    -e MACULA_RUST_GROUPS_PROFILE="$profile" -e MACULA_RUST_GROUPS_WORK=/work \
    -e MACULA_RUST_GROUPS_PREFIX="$prefix" -e MACULA_RUST_GROUPS_TOPIC="$topic" \
    -e CARGO_HOME=/w/target/interop-cargo -e CARGO_TARGET_DIR=/w/target/interop \
    -v "$root:/w:Z" -v "$shared:/work" -w /w "$image" \
    cargo test --locked --test interop_groups -- --ignored --nocapture --exact "$2"
}

echo "== $profile: the org's distributor in Erlang"
erl "${names[0]}" distribute "$org" "$org_key_id" 300 > "$work/dist.out" 2>&1 &
distributor="$(nth_line "$work/dist.out" '^node ' 1 | awk '{print $2}')"
echo "admit $distributor" >&3
nth_line "$work/stations.out" '^admitted ' 1 > /dev/null
touch "$shared/admitted.$distributor"
nth_line "$work/dist.out" '^serving' 1 > /dev/null

echo "== $profile: an Erlang member and a Rust member, each opening the other's sealed event"
erl "${names[1]}" member "$prefix" "$topic" > "$work/erlang.out" 2>&1 &
erl_pid=$!
rustpeer "${names[2]}" a_rust_member_and_macula_open_each_others_events_under_one_epoch > "$work/rust.out" 2>&1 &
rust_pid=$!
grant "$(nth_line "$work/erlang.out" '^node ' 1 | awk '{print $2}')"
grant "$(nth_line "$work/rust.out" '^node ' 1 | awk '{print $2}')"
status=0
wait "$rust_pid" || status=1
wait "$erl_pid" || status=1
cat "$work/erlang.out" "$work/rust.out"
[ "$status" = 0 ] || { echo "groups.sh: a member failed"; cat "$work/dist.out"; exit 1; }

echo "== $profile: a Rust node the distributor removed"
rustpeer "${names[3]}" a_removed_node_is_refused_at_the_public_subscribe > "$work/stranger.out" 2>&1 &
stranger_pid=$!
stranger="$(nth_line "$work/stranger.out" '^node ' 1 | awk '{print $2}')"
echo "$stranger" >> "$shared/removed"
grant "$stranger"
wait "$stranger_pid" || { cat "$work/stranger.out"; exit 1; }
cat "$work/stranger.out"
echo "== $profile: sealed groups both ways"
