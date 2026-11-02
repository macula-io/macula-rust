#!/usr/bin/env bash
# An Android app keeps its node key in the Android Keystore through
# macula-rust-ffi (macula-io/macula-rust#63). This proves it on a running
# emulator or device:
#   1. libmacula_rust_ffi.so itself exports the initializeNdkContext JNI hook,
#      so the app initialises the ndk-context the SDK reads;
#   2. a key saved through the FFI loads back as the same node, a missing one
#      is KeystoreNotFound, and a save writes no file but the store's own.
#
# Usage: scripts/android_keystore_proof.sh <abi> [gradle command]
#   abi: the device's ABI (x86_64 on an emulator, arm64-v8a on most phones)
# Needs ANDROID_NDK_HOME, cargo-ndk, the Rust target for <abi>, a JDK 21,
# Gradle, and one device on adb.
set -euo pipefail

abi=${1:?usage: android_keystore_proof.sh <abi> [gradle command]}
gradle=${2:-gradle}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="$root/macula-rust-ffi/tests/android"
jni_dir="$project/keystore/src/main/jniLibs/$abi"
kotlin_dir="$project/keystore/src/main/kotlin"
hook=Java_io_crates_keyring_Keyring_00024Companion_initializeNdkContext

rm -rf "$jni_dir" "$kotlin_dir/io/macula/sdk"
mkdir -p "$jni_dir"
(cd "$root" && cargo ndk --platform 26 -t "$abi" --output-dir "$project/keystore/src/main/jniLibs" \
    build -p macula-rust-ffi --release --locked)

# Only the SDK's own library ships: cargo-ndk also copies
# android-native-keyring-store's separate cdylib, whose ndk-context is not
# the one the SDK reads. The test must pass without it.
find "$jni_dir" -name '*.so' ! -name 'libmacula_rust_ffi.so' -delete

# Not `find -type f`: the NDK may ship llvm-nm as a symlink.
nm=$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -name llvm-nm | head -1)
if [ ! -x "$nm" ]; then
    echo "no llvm-nm under $ANDROID_NDK_HOME/toolchains/llvm/prebuilt" >&2
    exit 1
fi
if ! "$nm" -D --defined-only "$jni_dir/libmacula_rust_ffi.so" | grep -q " $hook\$"; then
    echo "libmacula_rust_ffi.so does not export $hook" >&2
    echo "llvm-nm: $nm; library: $(wc -c <"$jni_dir/libmacula_rust_ffi.so") bytes" >&2
    echo "Java_ symbols defined: $("$nm" -D --defined-only "$jni_dir/libmacula_rust_ffi.so" | grep -c Java_ || true)" >&2
    "$nm" -D "$jni_dir/libmacula_rust_ffi.so" | grep -i keyring | head -5 >&2 || true
    exit 1
fi
echo "libmacula_rust_ffi.so exports $hook"

(cd "$root" && cargo run -p macula-rust-ffi --release --locked --bin uniffi-bindgen -- generate \
    --library "$jni_dir/libmacula_rust_ffi.so" \
    --language kotlin --out-dir "$kotlin_dir" --no-format)

(cd "$project" && "$gradle" --no-daemon connectedDebugAndroidTest)
