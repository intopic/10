#!/usr/bin/env bash
# Builds ZenoLlullFFI.xcframework (device + simulator) and the Swift
# bindings of the native SDK into sdk/ios/dist. Requires macOS with Xcode and
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=sdk/ios/dist
rm -rf "$OUT"
mkdir -p "$OUT/headers" "$OUT/swift"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo build --release -p mobile-ffi --target "$target"
done
# One fat library for the simulator (Apple Silicon and Intel hosts).
lipo -create \
  target/aarch64-apple-ios-sim/release/libzenollull.a \
  target/x86_64-apple-ios/release/libzenollull.a \
  -output "$OUT/libzenollull-sim.a"

# The bindings are generated from a host build of the same crate.
cargo build --release -p mobile-ffi
./target/release/uniffi-bindgen generate --library target/release/libzenollull.dylib \
  --language swift --out-dir "$OUT/swift"
mv "$OUT/swift/zenollullFFI.h" "$OUT/headers/"
mv "$OUT/swift/zenollullFFI.modulemap" "$OUT/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libzenollull.a -headers "$OUT/headers" \
  -library "$OUT/libzenollull-sim.a" -headers "$OUT/headers" \
  -output "$OUT/ZenoLlullFFI.xcframework"
rm "$OUT/libzenollull-sim.a"

# The generated Swift must compile against the framework's module.
xcrun --sdk iphonesimulator swiftc -typecheck \
  -target arm64-apple-ios15.0-simulator \
  -I "$OUT/ZenoLlullFFI.xcframework/ios-arm64_x86_64-simulator/Headers" \
  "$OUT/swift/zenollull.swift"
find "$OUT" -maxdepth 3 | sort
