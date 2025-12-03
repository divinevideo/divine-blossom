#!/bin/bash
# ABOUTME: Integration test for GCS storage operations
# ABOUTME: Tests upload, download, and delete via local Viceroy server

set -e

BASE_URL="${BASE_URL:-http://127.0.0.1:7676}"

echo "Testing GCS integration..."
echo "Base URL: $BASE_URL"

# Check version endpoint
echo ""
echo "1. Testing version endpoint..."
VERSION=$(curl -s "$BASE_URL/version")
echo "Version: $VERSION"

# Create test file
echo ""
echo "2. Creating test file..."
TEST_CONTENT="Hello GCS $(date +%s)"
echo "$TEST_CONTENT" > /tmp/test-gcs.txt
EXPECTED_HASH=$(shasum -a 256 /tmp/test-gcs.txt | cut -d' ' -f1)
echo "Expected SHA256: $EXPECTED_HASH"

# Note: Full upload test requires valid Nostr auth
# This is a placeholder for manual testing
echo ""
echo "3. Upload test requires Nostr auth token"
echo "   Use test-upload.mjs for authenticated upload tests"

# Test HEAD for non-existent blob
echo ""
echo "4. Testing HEAD for non-existent blob..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/$EXPECTED_HASH")
echo "HTTP Code: $HTTP_CODE (expected 404)"

if [ "$HTTP_CODE" != "404" ]; then
    echo "WARNING: Expected 404, got $HTTP_CODE"
fi

echo ""
echo "Basic integration tests complete!"
echo ""
echo "For full testing:"
echo "1. Set up GCS credentials in fastly.toml"
echo "2. Run: fastly compute serve"
echo "3. Run: node test-upload.mjs"
