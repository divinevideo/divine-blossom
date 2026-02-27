#!/bin/bash
# ABOUTME: Monitor VCL cache hit ratio and error rates after domain switch
# ABOUTME: Run periodically to verify caching is working

VCL_SERVICE="ML7R82HKfmTaqTpHExIDVN"
COMPUTE_SERVICE="pOvEEWykEbpnylqst1KTrR"

echo "=== VCL Cache Layer Stats ==="
echo ""
echo "Real-time stats (last minute):"
fastly stats --service-id "$VCL_SERVICE" 2>/dev/null | head -20

echo ""
echo "---"
echo ""
echo "Key metrics to watch:"
echo "  hit_ratio    - should be 85-95% (was 0.82%)"
echo "  miss_ratio   - should be 5-15%"
echo "  errors       - should be near 0"
echo "  status_5xx   - should be near 0"
echo "  status_2xx   - should be majority of requests"
echo ""
echo "If hit_ratio is low:"
echo "  1. Check if content is being served with no-store headers"
echo "  2. Check if Vary headers are too broad"
echo "  3. Check if shielding is enabled (reduces inter-POP misses)"
echo ""
echo "Quick checks:"
echo "  curl -sI https://media.divine.video/{hash} | grep X-Cache"
echo "  HIT = served from VCL cache, MISS = went to Compute origin"
echo ""
echo "=== Compute Origin Stats (should show FEWER requests now) ==="
fastly stats --service-id "$COMPUTE_SERVICE" 2>/dev/null | head -10
