#!/usr/bin/env bash
# Builds the native SDK library for the host and generates the Swift, Kotlin
# and Python bindings into sdk/native/dist.
#
# For devices, build the same crate for the target triples and package:
#   iOS:     cargo build --release -p mobile-ffi --target aarch64-apple-ios   (+ xcodebuild -create-xcframework)
#   Android: cargo ndk -t arm64-v8a build --release -p mobile-ffi            (+ AAR with the generated Kotlin)
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -p mobile-ffi
LIB=target/release/libzenollull.so
[ -f "$LIB" ] || LIB=target/release/libzenollull.dylib
OUT=sdk/native/dist
rm -rf "$OUT"
for lang in python kotlin swift; do
  ./target/release/uniffi-bindgen generate --library "$LIB" --language "$lang" --out-dir "$OUT/$lang"
done
cp "$LIB" "$OUT/python/"
find "$OUT" -type f | sort
