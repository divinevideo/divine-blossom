#!/bin/bash
# ABOUTME: Smoke test for VCL caching layer on media.divine.video
# ABOUTME: Tests all critical paths after domain switch

DOMAIN="${1:-media.divine.video}"
HASH="832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1"
PASS=0
FAIL=0

check() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name (expected '$expected')"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== Smoke Test: https://$DOMAIN ==="
echo ""

# 1. Content GET (cache miss, then hit)
echo "[1] Content GET (cache MISS then HIT)"
R1=$(curl -s -D /tmp/smoke_h1 -o /dev/null -w "%{http_code}" "https://$DOMAIN/$HASH" 2>&1)
H1=$(cat /tmp/smoke_h1)
check "200 OK" "200" "$R1"
check "Content-Type video" "video/mp4" "$H1"
check "Cache-Control immutable" "immutable" "$H1"
if echo "$H1" | grep -qi "access-control-allow-origin"; then
  echo "  PASS: CORS headers"; PASS=$((PASS + 1))
else
  echo "  FAIL: CORS headers missing"; FAIL=$((FAIL + 1))
fi
echo ""

sleep 2
R2=$(curl -s -D /tmp/smoke_h2 -o /dev/null -w "%{http_code} %{time_total}" "https://$DOMAIN/$HASH" 2>&1)
H2=$(cat /tmp/smoke_h2)
check "Cache HIT on 2nd request" "HIT" "$H2"
TOTAL_TIME=$(echo "$R2" | awk '{print $2}')
echo "  INFO: Response time: ${TOTAL_TIME}s"
echo ""

# 2. Range request
echo "[2] Range request"
R3=$(curl -s -D /tmp/smoke_h3 -o /dev/null -w "%{http_code}" -H "Range: bytes=0-1023" "https://$DOMAIN/$HASH" 2>&1)
H3=$(cat /tmp/smoke_h3)
check "206 Partial Content" "206" "$R3"
if echo "$H3" | grep -qi "content-range"; then
  echo "  PASS: Content-Range present"; PASS=$((PASS + 1))
else
  echo "  FAIL: Content-Range missing"; FAIL=$((FAIL + 1))
fi
echo ""

# 3. HLS manifest
echo "[3] HLS manifest"
R4=$(curl -s -D /tmp/smoke_h4 -o /dev/null -w "%{http_code}" "https://$DOMAIN/$HASH.hls" 2>&1)
H4=$(cat /tmp/smoke_h4)
check "HLS 200 OK" "200" "$R4"
check "HLS Content-Type" "mpegurl" "$H4"
echo ""

# 4. Upload endpoint (should pass through, require auth)
echo "[4] Upload pass-through"
R5=$(curl -s -X PUT "https://$DOMAIN/upload" -H "Content-Type: video/mp4" -d 'test' 2>&1)
check "Upload requires auth" "Authorization" "$R5"
echo ""

# 5. POST webhook (should pass through, require secret)
echo "[5] Webhook pass-through"
R6=$(curl -s -X POST "https://$DOMAIN/admin/moderate" -H "Content-Type: application/json" -d '{"sha256":"test"}' 2>&1)
check "Webhook requires secret" "secret" "$R6"
echo ""

# 6. CORS preflight
echo "[6] CORS preflight"
R7=$(curl -s -D /tmp/smoke_h7 -o /dev/null -w "%{http_code}" -X OPTIONS "https://$DOMAIN/upload" 2>&1)
H7=$(cat /tmp/smoke_h7)
check "OPTIONS 204" "204" "$R7"
check "CORS Allow-Methods" "PUT" "$H7"
echo ""

# 7. Version endpoint (non-cached pass-through)
echo "[7] Version endpoint"
R8=$(curl -s "https://$DOMAIN/version" 2>&1)
check "Version responds" "v1" "$R8"
echo ""

# 8. 404 for non-existent hash
echo "[8] Non-existent content"
R9=$(curl -s -D /tmp/smoke_h9 -o /dev/null -w "%{http_code}" "https://$DOMAIN/0000000000000000000000000000000000000000000000000000000000000000" 2>&1)
check "404 for missing" "404" "$R9"
echo ""

# 9. No Surrogate-Key leaking to client
echo "[9] No internal header leakage"
H10=$(curl -sI "https://$DOMAIN/$HASH" 2>&1)
if echo "$H10" | grep -qi "Surrogate-Key:"; then
  echo "  FAIL: Surrogate-Key leaked to client"
  FAIL=$((FAIL + 1))
else
  echo "  PASS: No Surrogate-Key leaked"
  PASS=$((PASS + 1))
fi
echo ""

# 10. Stats summary
echo "[10] Cache stats (VCL service)"
echo "  Run: fastly stats --service-id ML7R82HKfmTaqTpHExIDVN"
echo "  Watch: hit_ratio, errors, status_2xx, status_5xx"
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "SOME TESTS FAILED - investigate before proceeding"
  exit 1
else
  echo "ALL TESTS PASSED"
  exit 0
fi

# Cleanup
rm -f /tmp/smoke_h1 /tmp/smoke_h2 /tmp/smoke_h3 /tmp/smoke_h4 /tmp/smoke_h7 /tmp/smoke_h9
