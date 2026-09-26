#!/usr/bin/env bash
# Builds the in-process macula 12 test stations the integration tests dial
# (tests/teststation, macula-go's teststation) to target/teststation. cargo
# test does not build it: run this first, as CI does.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ASDF_GOLANG_VERSION="${ASDF_GOLANG_VERSION:-1.27.0}"
mkdir -p "$ROOT/target"
cd "$ROOT/tests/teststation"
go build -trimpath -o "$ROOT/target/teststation" .
echo "built $ROOT/target/teststation"
