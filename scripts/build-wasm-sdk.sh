#!/usr/bin/env bash
# Builds the @zenollull/wasm-sdk NPM package (Node.js and browser targets).
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli 0.2.130.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --target wasm32-unknown-unknown -p sdk-bindings
WASM=target/wasm32-unknown-unknown/release/sdk_bindings.wasm
OUT=sdk/wasm/dist
rm -rf "$OUT"
wasm-bindgen --target nodejs --out-dir "$OUT/node" "$WASM"
wasm-bindgen --target web --out-dir "$OUT/web" "$WASM"
ls -l "$OUT/node" "$OUT/web"
