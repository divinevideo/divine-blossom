#!/bin/bash
# ABOUTME: Prepare only the transcoder and shared core sources for Cloud Build.
# ABOUTME: Keeps credentials, local targets, and unrelated checkout files out of the upload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_CONTEXT="${1:?Usage: prepare-build-context.sh <empty-directory>}"
mkdir "${BUILD_CONTEXT}/blossom-core"
cp "${SCRIPT_DIR}/Cargo.toml" "${SCRIPT_DIR}/Cargo.lock" \
  "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}/.dockerignore" "${BUILD_CONTEXT}/"
cp -R "${SCRIPT_DIR}/src" "${BUILD_CONTEXT}/src"
cp "${REPO_ROOT}/blossom-core/Cargo.toml" "${BUILD_CONTEXT}/blossom-core/"
cp -R "${REPO_ROOT}/blossom-core/src" "${BUILD_CONTEXT}/blossom-core/src"
