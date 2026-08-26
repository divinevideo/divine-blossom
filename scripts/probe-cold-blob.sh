#!/bin/bash
# ABOUTME: Measures verified-cold bare-blob fills without printing or persisting the object hash.
# ABOUTME: Uses targeted surrogate purges only and emits bounded probe IDs for collapse verification.

set -euo pipefail

DOMAIN="${DOMAIN:-media.divine.video}"
ANONYMOUS_BLOB_HASH="${ANONYMOUS_BLOB_HASH:-}"
CREDENTIALED_BLOB_HASH="${CREDENTIALED_BLOB_HASH:-}"
CONCURRENT_BLOB_HASH="${CONCURRENT_BLOB_HASH:-}"
OUTER_SERVICE_ID="${OUTER_SERVICE_ID:-ML7R82HKfmTaqTpHExIDVN}"
COMPUTE_SERVICE_ID="${COMPUTE_SERVICE_ID:-pOvEEWykEbpnylqst1KTrR}"
EXPECTED_POP_REGEX="${EXPECTED_POP_REGEX:-[A-Z]{3}}"
CONCURRENCY="${CONCURRENCY:-8}"
RANGE="${RANGE:-bytes=0-1023}"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

for command in curl fastly nak; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

for hash_name in ANONYMOUS_BLOB_HASH CREDENTIALED_BLOB_HASH CONCURRENT_BLOB_HASH; do
  hash=${!hash_name}
  [[ "$hash" =~ ^[0-9a-fA-F]{64}$ ]] || \
    fail "set $hash_name to a fresh non-user synthetic object"
done
[[ "$ANONYMOUS_BLOB_HASH" != "$CREDENTIALED_BLOB_HASH" && \
   "$ANONYMOUS_BLOB_HASH" != "$CONCURRENT_BLOB_HASH" && \
   "$CREDENTIALED_BLOB_HASH" != "$CONCURRENT_BLOB_HASH" ]] || \
  fail "the anonymous, credentialed, and concurrent cases require distinct fresh objects"
[[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]] || fail "CONCURRENCY must be a positive integer"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
RUN_ID="coldfill-$(date -u +%Y%mt%dt%H%M%Sz)-$$"

purge_fixture() {
  local hash="$1"
  # Purge both services: the outer VCL and Compute internal cache are distinct.
  fastly purge --key "${hash,,}" --service-id "$OUTER_SERVICE_ID" >/dev/null
  fastly purge --key "${hash,,}" --service-id "$COMPUTE_SERVICE_ID" >/dev/null
  sleep 3
}

header_value() {
  local name="$1" file="$2"
  python3 - "$name" "$file" <<'PY'
import sys
name = sys.argv[1].lower() + ":"
with open(sys.argv[2], encoding="utf-8", errors="replace") as source:
    values = [line.split(":", 1)[1].strip() for line in source if line.lower().startswith(name)]
print(values[-1] if values else "-")
PY
}

fetch_one() {
  local mode="$1" hash="$2" probe_id="$3" headers="$4" metrics="$5"
  local url="https://${DOMAIN}/${hash}"
  local args=(-sS -D "$headers" -o /dev/null -H "Range: $RANGE"
    -H "X-Divine-Diagnostic-Probe: $probe_id"
    -w '%{http_code} %{time_starttransfer} %{time_total}\n' "$url")
  if [ "$mode" = credentialed ]; then
    nak curl "${args[@]}" >"$metrics"
  else
    curl "${args[@]}" >"$metrics"
  fi
}

report_one() {
  local label="$1" headers="$2" metrics="$3"
  local status ttfb total served cache age internal
  read -r status ttfb total <"$metrics"
  [[ "$status" = 200 || "$status" = 206 ]] || fail "$label returned HTTP $status"
  served=$(header_value x-served-by "$headers")
  cache=$(header_value x-cache "$headers")
  age=$(header_value age "$headers")
  internal=$(header_value x-divine-storage-cache "$headers")
  [[ "$served" =~ $EXPECTED_POP_REGEX ]] || \
    fail "$label served-by '$served' does not match EXPECTED_POP_REGEX"
  echo "$label status=$status ttfb_s=$ttfb total_s=$total x_cache=$cache age=$age storage_cache=$internal served_by=$served"
}

echo "run_id=$RUN_ID domain=$DOMAIN concurrency=$CONCURRENCY"
echo "The object identifier is intentionally omitted from output."

purge_fixture "$ANONYMOUS_BLOB_HASH"
fetch_one anonymous "$ANONYMOUS_BLOB_HASH" "$RUN_ID-anon" "$TMP/anon.headers" "$TMP/anon.metrics"
report_one anonymous "$TMP/anon.headers" "$TMP/anon.metrics"

purge_fixture "$CREDENTIALED_BLOB_HASH"
fetch_one credentialed "$CREDENTIALED_BLOB_HASH" "$RUN_ID-credentialed" "$TMP/credentialed.headers" "$TMP/credentialed.metrics"
report_one credentialed "$TMP/credentialed.headers" "$TMP/credentialed.metrics"

purge_fixture "$CONCURRENT_BLOB_HASH"
prefix="$RUN_ID-concurrent-"
pids=()
for ((index = 1; index <= CONCURRENCY; index++)); do
  fetch_one anonymous "$CONCURRENT_BLOB_HASH" "$prefix$index" "$TMP/concurrent-$index.headers" \
    "$TMP/concurrent-$index.metrics" &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "$pid" || fail "a concurrent request failed"
done
for ((index = 1; index <= CONCURRENCY; index++)); do
  report_one "concurrent_$index" "$TMP/concurrent-$index.headers" \
    "$TMP/concurrent-$index.metrics"
done

echo
echo "collapse_prefix=$prefix"
echo "After diagnostics have arrived, run from an authorized operator session:"
echo "  REQUEST_PREFIX=$prefix scripts/tail-edge-errors.sh 500"
echo "One cold_fill/slow_cold_fill record establishes one GCS fill; more than one establishes duplicate fills."
