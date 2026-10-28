#!/usr/bin/env bash
# The version a job builds with is the version rust-toolchain.toml names, and CI
# says so out loud: a float on `stable` silently changes the compiler, the linter
# and the formatter from one morning to the next (macula-io/macula-rust#54).
#
# Run from the checkout root, after `rustup show`, in every job that compiles.
set -eu

root=$(cd -P -- "$(dirname -- "$0")/.." && pwd)
pinned=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$root/rust-toolchain.toml" | head -1)
[ -n "$pinned" ] || { echo "rust-toolchain.toml names no channel" >&2; exit 1; }

reported=$(rustc --version)
version=${reported#rustc }
version=${version%% *}

if [ "$version" != "$pinned" ]; then
    echo "rustc is $version, rust-toolchain.toml pins $pinned" >&2
    exit 1
fi
echo "rustc $version, as pinned in rust-toolchain.toml"
