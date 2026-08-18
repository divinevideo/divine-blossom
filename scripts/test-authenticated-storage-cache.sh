#!/bin/sh
# ABOUTME: Verifies age-gated media authorizes before using the internal storage cache.
# ABOUTME: Uses ephemeral NIP-98 signers; no user private key or reusable token is required.

set -eu

DOMAIN="${DOMAIN:-media.divine.video}"
AGE_RESTRICTED_HASH="${AGE_RESTRICTED_HASH:-}"
COMPUTE_SERVICE_ID="${COMPUTE_SERVICE_ID:-pOvEEWykEbpnylqst1KTrR}"

if ! command -v nak >/dev/null 2>&1; then
  echo "FAIL: nak is required (https://github.com/fiatjaf/nak)" >&2
  exit 2
fi

if ! command -v fastly >/dev/null 2>&1; then
  echo "FAIL: fastly CLI is required to purge the fixture for the cold-path check" >&2
  exit 2
fi

if ! printf '%s' "$AGE_RESTRICTED_HASH" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "FAIL: set AGE_RESTRICTED_HASH to a maintained 64-hex age-gated fixture" >&2
  exit 2
fi

URL="https://${DOMAIN}/${AGE_RESTRICTED_HASH}"
FIRST_HEADERS=$(mktemp)
SECOND_HEADERS=$(mktemp)
COLD_RANGE_HEADERS=$(mktemp)
WARM_RANGE_HEADERS=$(mktemp)
trap 'rm -f "$FIRST_HEADERS" "$SECOND_HEADERS" "$COLD_RANGE_HEADERS" "$WARM_RANGE_HEADERS"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

ANON_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$URL")
[ "$ANON_CODE" = "401" ] || fail "anonymous request returned $ANON_CODE, expected 401"

FORGED_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Authorization: Nostr c21va2U=' "$URL")
[ "$FORGED_CODE" = "401" ] || fail "forged NIP-98 request returned $FORGED_CODE, expected 401"

# Evict any prior copy so the range request below is a genuinely cold miss.
# The content hash is the surrogate key for both the outer and internal caches.
LOWER_HASH=$(printf '%s' "$AGE_RESTRICTED_HASH" | tr 'A-F' 'a-f')
fastly purge --key "$LOWER_HASH" --service-id "$COMPUTE_SERVICE_ID" >/dev/null || \
  fail "fastly purge --key failed for the fixture"
sleep 2

COLD_RANGE_CODE=$(nak curl -sS -D "$COLD_RANGE_HEADERS" -o /dev/null -w '%{http_code}' \
  -H 'Range: bytes=0-1023' "$URL")
[ "$COLD_RANGE_CODE" = "206" ] || \
  fail "cold authorized range request returned $COLD_RANGE_CODE, expected 206"
grep -qi '^content-range: bytes 0-1023/' "$COLD_RANGE_HEADERS" || \
  fail "cold range response is missing the requested Content-Range"
grep -qi '^x-divine-storage-cache:[[:space:]]*MISS[[:space:]]*$' "$COLD_RANGE_HEADERS" || \
  fail "cold range request did not MISS the internal cache after purge (re-run if purge propagation raced)"

# A different range must now be synthesized from the full object the cold
# ranged miss stored. Pre-fix, a cold 206 was uncacheable, so this repeat
# would keep missing.
WARM_RANGE_HIT=false
ATTEMPT=0
while [ "$ATTEMPT" -lt 5 ]; do
  ATTEMPT=$((ATTEMPT + 1))
  WARM_RANGE_CODE=$(nak curl -sS -D "$WARM_RANGE_HEADERS" -o /dev/null -w '%{http_code}' \
    -H 'Range: bytes=1024-2047' "$URL")
  [ "$WARM_RANGE_CODE" = "206" ] || \
    fail "warm authorized range attempt $ATTEMPT returned $WARM_RANGE_CODE, expected 206"
  grep -qi '^content-range: bytes 1024-2047/' "$WARM_RANGE_HEADERS" || \
    fail "warm range response is missing the requested Content-Range"
  if grep -qi '^x-divine-storage-cache:[[:space:]]*HIT[[:space:]]*$' "$WARM_RANGE_HEADERS"; then
    WARM_RANGE_HIT=true
    break
  fi
  sleep 1
done
[ "$WARM_RANGE_HIT" = "true" ] || \
  fail "cold ranged miss did not populate the internal cache (no warm range HIT in 5 attempts)"

FIRST_CODE=$(nak curl -sS -D "$FIRST_HEADERS" -o /dev/null -w '%{http_code}' "$URL")
[ "$FIRST_CODE" = "200" ] || fail "valid NIP-98 request returned $FIRST_CODE, expected 200"

grep -qi '^cache-control:.*\(private\|no-store\)' "$FIRST_HEADERS" || \
  fail "authorized response is missing private/no-store browser policy"

CACHE_HIT=false
ATTEMPT=0
while [ "$ATTEMPT" -lt 5 ]; do
  ATTEMPT=$((ATTEMPT + 1))
  REPEAT_CODE=$(nak curl -sS -D "$SECOND_HEADERS" -o /dev/null -w '%{http_code}' "$URL")
  [ "$REPEAT_CODE" = "200" ] || \
    fail "authorized repeat $ATTEMPT returned $REPEAT_CODE, expected 200"
  if grep -qi '^x-divine-storage-cache:[[:space:]]*HIT[[:space:]]*$' "$SECOND_HEADERS"; then
    CACHE_HIT=true
    break
  fi
  sleep 1
done
[ "$CACHE_HIT" = "true" ] || \
  fail "internal storage cache did not produce a HIT within 5 authorized repeats"

ANON_AFTER_WARM_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$URL")
[ "$ANON_AFTER_WARM_CODE" = "401" ] || \
  fail "anonymous request returned $ANON_AFTER_WARM_CODE after cache warm, expected 401"

FORGED_AFTER_WARM_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Authorization: Nostr c21va2U=' "$URL")
[ "$FORGED_AFTER_WARM_CODE" = "401" ] || \
  fail "forged NIP-98 request returned $FORGED_AFTER_WARM_CODE after cache warm, expected 401"

echo "PASS: NIP-98 is checked before an authorized internal storage-cache HIT"
echo "PASS: a cold authorized range request populated the internal cache"
