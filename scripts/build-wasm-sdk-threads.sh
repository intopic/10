#!/usr/bin/env bash
# Builds the multi-threaded browser variant of @zenollull/wasm-sdk into
# sdk/wasm/dist/web-threads. It runs the prover on a pool of Web Workers and
# therefore needs a cross-origin-isolated page (COOP: same-origin,
# COEP: require-corp) so that SharedArrayBuffer is available.
#
# Requires: nightly Rust with rust-src and the wasm32-unknown-unknown target,
# wasm-bindgen-cli 0.2.130.
set -euo pipefail
cd "$(dirname "$0")/.."

# Shared, imported linear memory (capped at 1 GiB) and the TLS exports that
# wasm-bindgen needs to start a module instance in every worker.
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory
  -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=1073741824
  -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size
  -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base' \
  cargo +nightly build --release --target wasm32-unknown-unknown \
  -Z build-std=panic_abort,std -p sdk-bindings --features wasm-threads \
  --target-dir target/wasm-mt
OUT=sdk/wasm/dist/web-threads
rm -rf "$OUT"
wasm-bindgen --target web --out-dir "$OUT" \
  target/wasm-mt/wasm32-unknown-unknown/release/sdk_bindings.wasm
ls -l "$OUT"
