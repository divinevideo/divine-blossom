#!/bin/bash
# ABOUTME: Integration test for admin content bypass endpoint
# ABOUTME: Tests GET /admin/api/blob/{hash}/content auth, routing, and moderation bypass
#
# Requires: fastly compute serve running on $BASE_URL (default http://127.0.0.1:7676)
# KV store must have test blobs (kv-store-data.json) and secrets (secrets-store-data.json)

set -e

BASE_URL="${BASE_URL:-http://127.0.0.1:7676}"
ADMIN_TOKEN="${ADMIN_TOKEN:-test-admin-token-local}"

# Test hashes matching kv-store-data.json fixtures
BANNED_HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ACTIVE_HASH="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MISSING_HASH="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

PASS=0
FAIL=0

assert_http_code() {
    local description="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $description (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected HTTP $expected, got HTTP $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_body_contains() {
    local description="$1"
    local expected="$2"
    local body="$3"

    if echo "$body" | grep -q "$expected"; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected body to contain '$expected', got: $body)"
        FAIL=$((FAIL + 1))
    fi
}

echo "Admin Content Bypass Endpoint Tests"
echo "===================================="
echo "Base URL: $BASE_URL"
echo ""

# ------------------------------------------------------------------
echo "1. Auth enforcement"
# ------------------------------------------------------------------

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/admin/api/blob/$BANNED_HASH/content")
assert_http_code "No auth returns 401" "401" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer wrong-token" \
    "$BASE_URL/admin/api/blob/$BANNED_HASH/content")
assert_http_code "Wrong token returns 401" "401" "$CODE"

# ------------------------------------------------------------------
echo ""
echo "2. Moderation bypass (banned blob)"
# ------------------------------------------------------------------

# Public endpoint blocks banned content at moderation check
BODY=$(curl -s "$BASE_URL/$BANNED_HASH")
assert_body_contains "Public endpoint blocks banned blob at moderation" \
    '"error":"Blob not found"' "$BODY"

# Admin bypass gets past moderation (fails at GCS download, not moderation)
BODY=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/admin/api/blob/$BANNED_HASH/content")
assert_body_contains "Admin bypass passes moderation, fails at storage" \
    '"error":"Blob not found in any storage"' "$BODY"

# ------------------------------------------------------------------
echo ""
echo "3. Active blob (both endpoints reach storage)"
# ------------------------------------------------------------------

BODY=$(curl -s "$BASE_URL/$ACTIVE_HASH")
assert_body_contains "Public endpoint for active blob reaches storage" \
    '"error":"Blob not found in any storage"' "$BODY"

BODY=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/admin/api/blob/$ACTIVE_HASH/content")
assert_body_contains "Admin bypass for active blob reaches storage" \
    '"error":"Blob not found in any storage"' "$BODY"

# ------------------------------------------------------------------
echo ""
echo "4. Nonexistent blob"
# ------------------------------------------------------------------

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/admin/api/blob/$MISSING_HASH/content")
assert_http_code "Nonexistent blob returns 404" "404" "$CODE"

BODY=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/admin/api/blob/$MISSING_HASH/content")
assert_body_contains "Nonexistent blob error from metadata lookup" \
    '"error":"Blob not found"' "$BODY"

# ------------------------------------------------------------------
echo ""
echo "5. Routing: metadata endpoint unaffected"
# ------------------------------------------------------------------

BODY=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/admin/api/blob/$BANNED_HASH")
assert_body_contains "Metadata endpoint returns JSON with sha256" \
    '"sha256":"aaaa' "$BODY"
assert_body_contains "Metadata endpoint shows banned status" \
    '"status":"banned"' "$BODY"

# ------------------------------------------------------------------
echo ""
echo "===================================="
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
