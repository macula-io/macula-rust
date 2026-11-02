#!/usr/bin/env bash
# The Swift that uniffi generates from macula-rust-ffi must type-check, not only
# generate (macula-io/macula-rust#61): an iOS app finds a refused binding at its
# first build; this finds it here. Runs where swiftc is, a macOS runner in CI.
#
# Usage: scripts/typecheck_swift_bindings.sh <generated swift dir>
set -eu

bindings=${1:?usage: typecheck_swift_bindings.sh <generated swift dir>}

modulemap=$(find "$bindings" -name '*.modulemap' | head -1)
sources=$(find "$bindings" -name '*.swift')
[ -n "$modulemap" ] || { echo "no .modulemap under $bindings" >&2; exit 1; }
[ -n "$sources" ] || { echo "no .swift files under $bindings" >&2; exit 1; }

# shellcheck disable=SC2086 # one argument per generated file
swiftc -typecheck -module-name MaculaSdk \
    -Xcc -fmodule-map-file="$modulemap" -I "$bindings" $sources
echo "generated Swift type-checks with $(swiftc --version 2>&1 | head -1)"
