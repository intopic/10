#!/usr/bin/env bash
# Runs the Cloud Prover container and drives one pay-per-proof flow through
# its HTTP API with a freshly issued license key.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -p zeno-license
eval "$(./target/release/zeno-license keygen)"
export ZENO_LICENSE_PRIVATE_KEY
TOKEN="$(./target/release/zeno-license issue --customer smoke --plan pay-per-proof --days 1 2>/dev/null)"

CID="$(docker run -d -p 127.0.0.1:18080:8080 \
  -e ZENO_LICENSE_PUBLIC_KEY="$ZENO_LICENSE_PUBLIC_KEY" \
  -e ZENO_USAGE_LOG=/data/usage.jsonl zenollull-cloud-prover)"
trap 'docker rm -f "$CID" >/dev/null' EXIT

URL=http://127.0.0.1:18080
for _ in $(seq 1 50); do
  curl -sf "$URL/healthz" >/dev/null && break
  sleep 0.2
done
curl -sf "$URL/healthz" >/dev/null

FIX=crates/sdk-bindings/fixtures
AUTH="Authorization: Bearer $TOKEN"
test "$(curl -s -o /dev/null -w '%{http_code}' "$URL/v1/usage")" = 401

SID="$(curl -sf -H "$AUTH" --data-binary "@$FIX/step.r1cs" "$URL/v1/sessions?z0=3" \
  | sed -E 's/.*"session_id":"([0-9a-f]+)".*/\1/')"
for i in 0 1 2; do
  curl -sf -H "$AUTH" --data-binary "@$FIX/step$i.wtns" "$URL/v1/fold-step?session=$SID"
  echo
done
PROOF="$(mktemp)"
curl -sf -H "$AUTH" -X POST "$URL/v1/finalize-snark?session=$SID" -o "$PROOF" \
  -w 'finalize-snark: HTTP %{http_code}, %{size_download} bytes, %{time_total}s\n'
test "$(stat -c %s "$PROOF")" -lt 16384
# The proof stays available for a repeated request, unbilled.
AGAIN="$(mktemp)"
curl -sf -H "$AUTH" -X POST "$URL/v1/finalize-snark?session=$SID" -o "$AGAIN"
cmp "$PROOF" "$AGAIN"
curl -sf "$URL/metrics" | grep -E '^zeno_(sessions|proofs_retained) '

USAGE="$(curl -sf -H "$AUTH" "$URL/v1/usage")"
echo "$USAGE"
echo "$USAGE" | grep -q '"fold_steps":3'
echo "$USAGE" | grep -q '"proofs":1'
test "$(docker exec "$CID" sh -c 'wc -l < /data/usage.jsonl')" = 5
echo OK
