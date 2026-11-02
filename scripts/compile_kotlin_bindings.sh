#!/usr/bin/env bash
# The Kotlin that uniffi generates from macula-rust-ffi must COMPILE, not only
# generate (macula-io/macula-rust#61). Generation succeeds on an API a Kotlin
# compiler then refuses: a `close` that becomes `suspend fun close()` collides
# with AutoCloseable.close(), and an error field called `message` collides with
# Throwable.message. An app finds that out at its first build; this finds it here.
#
# Usage: scripts/compile_kotlin_bindings.sh <generated kotlin dir> [tool cache dir]
# Needs java and curl. The compiler and the two jars the bindings import are
# pinned by version and sha256 (checked against the upstream checksums).
set -eu

bindings=${1:?usage: compile_kotlin_bindings.sh <generated kotlin dir> [tool cache dir]}
cache=${2:-${RUNNER_TEMP:-/tmp}/kotlin-bindings-tools}

kotlin_version=2.2.21
kotlin_url=https://github.com/JetBrains/kotlin/releases/download/v$kotlin_version/kotlin-compiler-$kotlin_version.zip
kotlin_sha256=a623871f1cd9c938946948b70ef9170879f0758043885bbd30c32f024e511714

jna_url=https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar
jna_sha256=b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0

coroutines_url=https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.10.2/kotlinx-coroutines-core-jvm-1.10.2.jar
coroutines_sha256=5ca175b38df331fd64155b35cd8cae1251fa9ee369709b36d42e0a288ccce3fd

fetch() {
    [ -f "$2" ] || curl -fsSL -o "$2" "$1"
    echo "$3  $2" | sha256sum -c --quiet -
}

mkdir -p "$cache"
fetch "$kotlin_url" "$cache/kotlin-compiler.zip" "$kotlin_sha256"
fetch "$jna_url" "$cache/jna.jar" "$jna_sha256"
fetch "$coroutines_url" "$cache/coroutines.jar" "$coroutines_sha256"
[ -x "$cache/kotlinc/bin/kotlinc" ] || unzip -q -o "$cache/kotlin-compiler.zip" -d "$cache"

sources=$(find "$bindings" -name '*.kt')
[ -n "$sources" ] || { echo "no .kt files under $bindings" >&2; exit 1; }

# shellcheck disable=SC2086 # one argument per generated file
"$cache/kotlinc/bin/kotlinc" \
    -cp "$cache/jna.jar:$cache/coroutines.jar" \
    -d "$cache/out" $sources
echo "generated Kotlin compiles with kotlinc $kotlin_version"
