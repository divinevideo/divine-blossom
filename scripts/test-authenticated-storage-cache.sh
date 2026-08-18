#!/bin/sh
# ABOUTME: Verifies age-gated media authorizes before using the internal storage cache.
# ABOUTME: Uses ephemeral NIP-98 signers; no user private key or reusable token is required.

set -eu

DOMAIN="${DOMAIN:-media.divine.video}"
AGE_RESTRICTED_HASH="${AGE_RESTRICTED_HASH:-}"

if ! command -v nak >/dev/null 2>&1; then
  echo "FAIL: nak is required (https://github.com/fiatjaf/nak)" >&2
  exit 2
fi

if ! printf '%s' "$AGE_RESTRICTED_HASH" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "FAIL: set AGE_RESTRICTED_HASH to a maintained 64-hex age-gated fixture" >&2
  exit 2
fi

URL="https://${DOMAIN}/${AGE_RESTRICTED_HASH}"
FIRST_HEADERS=$(mktemp)
SECOND_HEADERS=$(mktemp)
trap 'rm -f "$FIRST_HEADERS" "$SECOND_HEADERS"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

ANON_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$URL")
[ "$ANON_CODE" = "401" ] || fail "anonymous request returned $ANON_CODE, expected 401"

FORGED_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Authorization: Nostr c21va2U=' "$URL")
[ "$FORGED_CODE" = "401" ] || fail "forged NIP-98 request returned $FORGED_CODE, expected 401"

FIRST_CODE=$(nak curl -sS -D "$FIRST_HEADERS" -o /dev/null -w '%{http_code}' "$URL")
[ "$FIRST_CODE" = "200" ] || fail "valid NIP-98 request returned $FIRST_CODE, expected 200"

grep -qi '^cache-control:.*\(private\|no-store\)' "$FIRST_HEADERS" || \
  fail "authorized response is missing private/no-store browser policy"

SECOND_CODE=$(nak curl -sS -D "$SECOND_HEADERS" -o /dev/null -w '%{http_code}' "$URL")
[ "$SECOND_CODE" = "200" ] || fail "second valid NIP-98 request returned $SECOND_CODE, expected 200"

grep -qi '^x-divine-storage-cache:.*HIT' "$SECOND_HEADERS" || \
  fail "second authorized request was not served from the internal storage cache"

ANON_AFTER_WARM_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$URL")
[ "$ANON_AFTER_WARM_CODE" = "401" ] || \
  fail "anonymous request returned $ANON_AFTER_WARM_CODE after cache warm, expected 401"

echo "PASS: NIP-98 is checked before an authorized internal storage-cache HIT"
