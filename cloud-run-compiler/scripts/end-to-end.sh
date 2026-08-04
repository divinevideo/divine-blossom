#!/bin/bash
# ABOUTME: Runs the live end-to-end compilation test in a production-like container
# ABOUTME: Needs Docker plus outbound access to relay.divine.video and media.divine.video

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="${COMPILER_TEST_IMAGE:-divine-compiler-test:local}"

docker build -f "${SERVICE_DIR}/Dockerfile.test" -t "${IMAGE}" "${SERVICE_DIR}"

docker run --rm \
  ${DIVINE_E2E_COORDINATES:+-e DIVINE_E2E_COORDINATES="${DIVINE_E2E_COORDINATES}"} \
  "${IMAGE}" \
  cargo test --locked --test end_to_end -- --ignored --nocapture
