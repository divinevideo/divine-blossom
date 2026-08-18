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
