#!/bin/bash
# ABOUTME: Runs the fastly-blossom edge crate unit tests on wasm32-wasip1 under Viceroy
# ABOUTME: Asserts the tests actually executed, so a silent regression to zero tests fails CI
#
# Plain `cargo test` builds the edge crate for the host target, where the Fastly
# host functions cannot link. Viceroy provides those host functions, so the tests
# run when cargo is told to execute the wasm test binaries through it.
#
# Usage:
#   ./scripts/run-edge-tests.sh              # uses `viceroy` from PATH
#   VICEROY=~/.config/fastly/viceroy ./scripts/run-edge-tests.sh
#
# Extra arguments are passed through to cargo test, e.g.:
#   ./scripts/run-edge-tests.sh generation

set -euo pipefail

VICEROY="${VICEROY:-viceroy}"

# The crate has exactly two unit-test binaries: the lib target (src/lib.rs) and
# the bin target (src/main.rs). `--lib --bins` selects both and excludes doc
# tests, which cargo reports as a third zero-count result and which would
# otherwise blur the executed-test accounting below.
EXPECTED_TEST_BINARIES=2

command -v "$VICEROY" >/dev/null 2>&1 || {
  echo "error: viceroy not found (looked for '$VICEROY')" >&2
  echo "install it from https://github.com/fastly/Viceroy/releases or set VICEROY=<path>" >&2
  exit 1
}

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

CARGO_TARGET_WASM32_WASIP1_RUNNER="$VICEROY run -C fastly.toml --" \
  cargo test --locked --target wasm32-wasip1 --lib --bins "$@" 2>&1 | tee "$log"

# A step that exits zero while running nothing is the exact failure this guard
# exists to catch: cargo reports success for "0 passed; 0 failed" just as it does
# for a real run. Count what actually executed and refuse to pass on an empty run.
read -r results passed ignored <<<"$(awk '
  /^test result:/ { results++ }
  /^test result: ok\./ { passed += $4; ignored += $8 }
  END { print results + 0, passed + 0, ignored + 0 }
' "$log")"

# `ignored` is reported but not gated on: #[ignore] is sometimes legitimate, and
# failing on it would be over-strict. Printing it keeps a silent coverage drop
# visible in the CI log instead of invisible behind a healthy `passed` count.
echo
echo "edge crate tests executed under Viceroy: ${passed} passed, ${ignored} ignored across ${results} test binaries"

if [ "$results" -ne "$EXPECTED_TEST_BINARIES" ]; then
  echo "error: expected $EXPECTED_TEST_BINARIES test binaries, saw $results" >&2
  echo "the lib or bin test target stopped being built or run; fix it or update EXPECTED_TEST_BINARIES" >&2
  exit 1
fi

if [ "$passed" -eq 0 ]; then
  echo "error: no edge tests executed" >&2
  exit 1
fi

# These exercise actual asynchronous host I/O against a delayed loopback backend.
VICEROY="$VICEROY" python3 scripts/run-probe-deadline-tests.py

# Exercise translated VTT routing against synthetic storage and worker backends.
VICEROY="$VICEROY" python3 scripts/run-subtitle-translation-tests.py

# Verify private origin selection, signed requests, and bounded migration fallback.
VICEROY="$VICEROY" python3 scripts/run-media-origin-tests.py
VICEROY="$VICEROY" python3 scripts/run-hls-alias-tests.py

# Canary policy/readiness runs before every uncached pinned-version read.
VICEROY="$VICEROY" python3 scripts/run-b2-canary-tests.py

# Default-off production CDN routing admits only final verified B2 originals.
VICEROY="$VICEROY" python3 scripts/run-b2-cdn-tests.py

# Private control objects participate in the same bounded all-version erasure.
VICEROY="$VICEROY" python3 scripts/run-private-family-erasure-tests.py

# Durable eviction retries and physical erasure completion use real loopback KV.
VICEROY="$VICEROY" python3 scripts/run-b2-cdn-purge-outbox-tests.py
VICEROY="$VICEROY" python3 scripts/run-parent-gate-tests.py
VICEROY="$VICEROY" python3 scripts/run-b2-cdn-phase-tests.py
for contract in \
  quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries \
  moderation_cdn_purge_failure_is_durable_and_same_status_retry_purges \
  soft_delete_cdn_failure_cannot_be_acknowledged_before_eviction \
  restore_cdn_failure_keeps_durable_retry_after_status_commits \
  bulk_approve_skip_purge_reports_durable_pending_hashes \
  cdn_purge_drain_requires_admin_and_rejects_oversized_batches \
  cdn_drain_service_token_is_not_an_admin_credential \
  creator_physical_delete_waits_for_final_purge_without_replaying_absent_bytes \
  creator_physical_delete_retains_audio_discovery_until_both_final_receipts \
  creator_physical_delete_unreadable_phase_fails_before_policy_mutation; do
  TEST_CDN_CONTRACT="$contract" VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
done
TEST_CDN_ADMISSION=false VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
for contract in \
  restore_without_cdn_keeps_existing_non_deleted_rejection \
  pending_cdn_intent_cannot_clear_when_purge_configuration_disappears; do
  TEST_CDN_ABSENT=1 TEST_CDN_CONTRACT="$contract" VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
done

TEST_CDN_MISSING_STORE=1 TEST_CDN_CONTRACT=unavailable_config_store_cannot_disable_durable_eviction VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
# Both retained hosts must use the same modern outer-service URL endpoint.
(
  export TEST_CDN_PURGE_HOSTS=media-b2-cdn.divine.video,media-b2.divine.video
  TEST_CDN_URL_OK=1 TEST_CDN_CONTRACT=service_scoped_url_and_bulk_key_acknowledgements_complete_final_purge VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
  TEST_CDN_URL404=1 TEST_CDN_CONTRACT=url_404_keeps_committed_final_purge_pending_without_ack VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
  TEST_CDN_KEY404=1 TEST_CDN_CONTRACT=missing_hash_key_purge_acknowledgement_is_not_success VICEROY="$VICEROY" python3 scripts/run-b2-cdn-invalidation-tests.py
)

# Streaming fills must outlive guest exit and remain safe under 1KiB fragmentation.
VICEROY="$VICEROY" python3 scripts/run-b2-native-stream-tests.py
VICEROY="$VICEROY" python3 scripts/run-b2-segmented-policy-races.py

# Named media holds preserve base policy and enforce every derived route.
VICEROY="$VICEROY" python3 scripts/run-quarantine-tests.py

# A slow public origin read must not refill the CDN after a concurrent hold.
VICEROY="$VICEROY" python3 scripts/run-quarantine-race-tests.py

# Opt-in delivery correlation uses request-local observations and never cache metadata.
VICEROY="$VICEROY" python3 scripts/run-playback-telemetry-tests.py
VICEROY="$VICEROY" python3 scripts/run-playback-origin-telemetry-tests.py
VICEROY="$VICEROY" python3 scripts/run-playback-cache-telemetry-tests.py

# Canonical direct uploads can reuse the provider-aware service for small images.
VICEROY="$VICEROY" python3 scripts/run-upload-routing-tests.py

# Canonical B2 misses queue the verified mirror after GCS fallback, never on outage.
VICEROY="$VICEROY" python3 scripts/run-b2-canonical-demand-tests.py

# Trusted archive imports register without media readback and share erasure exclusion.
VICEROY="$VICEROY" python3 scripts/run-archive-import-tests.py
