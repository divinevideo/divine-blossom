#!/usr/bin/env bash
# ABOUTME: One-time cleanup for erased media that edge POPs stored without a Surrogate-Key
# ABOUTME: Purges and probes each hash's enumerable public URL forms by URL
#
# Usage:
#   envchain fastly-global scripts/purge-erased-edge-copies.sh --hash-file <path> [--domain <host>] [--dry-run] [--probe-only]
#
# Reads one 64-hex content hash per line from --hash-file. Blank lines and
# lines starting with # are ignored. Never pass hashes on the command line,
# commit the file, or paste its contents into an issue; see
# docs/runbooks/erased-media-edge-cleanup.md.
#
# For each hash every enumerable public form below is purged by URL. A URL purge
# reaches every POP, including copies that were stored without a Surrogate-Key
# before the guarded vcl/deliver.vcl was activated (#279). A purge by key
# cannot reach those copies, which is why this script exists.
#
# After purging, every form is fetched once and must return 404. Those probes
# see only the POP that answers this machine; copies held by other POPs are not
# observable from here.
set -euo pipefail

DOMAIN="media.divine.video"
HASH_FILE=""
DRY_RUN=0
PROBE_ONLY=0
URL_SUFFIXES=(
  ""
  ".mp4"
  ".jpg"
  "/720p"
  "/480p"
  "/720p.mp4"
  "/480p.mp4"
  ".hls"
  "/hls/master.m3u8"
  "/hls/stream_720p.m3u8"
  "/hls/stream_480p.m3u8"
  "/hls/stream_720p.ts"
  "/hls/stream_480p.ts"
  "/hls/stream_720p.mp4"
  "/hls/stream_480p.mp4"
  ".vtt"
  "/vtt"
  ".audio.m4a"
)

usage() {
  cat <<'USAGE'
Usage: envchain fastly-global scripts/purge-erased-edge-copies.sh --hash-file <path> [--domain <host>] [--dry-run] [--probe-only]

Reads one 64-hex content hash per line from --hash-file (blank lines and
# comments ignored). Never pass hashes on the command line. For each hash the
enumerable public URL forms are purged by URL, then each form is fetched once
and must return 404. The probes see one POP only.
See docs/runbooks/erased-media-edge-cleanup.md.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --hash-file)
      [ $# -ge 2 ] || { echo "error: --hash-file needs a path" >&2; exit 2; }
      HASH_FILE="$2"
      shift 2
      ;;
    --domain)
      [ $# -ge 2 ] || { echo "error: --domain needs a host" >&2; exit 2; }
      DOMAIN="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --probe-only)
      PROBE_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$HASH_FILE" ]; then
  echo "error: --hash-file is required" >&2
  usage >&2
  exit 2
fi
if [ ! -r "$HASH_FILE" ]; then
  echo "error: cannot read hash file" >&2
  exit 2
fi
if [ "$DRY_RUN" -eq 1 ] && [ "$PROBE_ONLY" -eq 1 ]; then
  echo "error: --dry-run and --probe-only cannot be combined" >&2
  exit 2
fi

HASHES=()
line_no=0
while IFS= read -r raw || [ -n "$raw" ]; do
  line_no=$((line_no + 1))
  line="${raw//[[:space:]]/}"
  case "$line" in
    ""|"#"*) continue ;;
  esac
  if ! [[ "$line" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: line $line_no is not a 64-hex content hash" >&2
    exit 2
  fi
  HASHES+=("$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')")
done < "$HASH_FILE"

if [ "${#HASHES[@]}" -eq 0 ]; then
  echo "error: hash file holds no hashes" >&2
  exit 2
fi

PURGE_FAIL=0
PROBE_FAIL=0
HEADERS_TMP=$(mktemp "${TMPDIR:-/tmp}/purge-erased-edge-copies.XXXXXX")
trap 'rm -f "$HEADERS_TMP"' EXIT

echo "hashes=${#HASHES[@]} domain=${DOMAIN} dry_run=${DRY_RUN} probe_only=${PROBE_ONLY}"

index=0
for hash in "${HASHES[@]}"; do
  index=$((index + 1))
  label="${index}/${#HASHES[@]}"

  if [ "$PROBE_ONLY" -eq 0 ]; then
    for suffix in "${URL_SUFFIXES[@]}"; do
      url="https://${DOMAIN}/${hash}${suffix}"
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "[$label] would purge url form '${suffix:-bare}'"
        continue
      fi
      if fastly purge --url "$url" >/dev/null; then
        echo "[$label] purged url form '${suffix:-bare}'"
      else
        echo "[$label] PURGE FAIL url form '${suffix:-bare}'"
        PURGE_FAIL=$((PURGE_FAIL + 1))
      fi
    done
  fi

  for suffix in "${URL_SUFFIXES[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "[$label] would probe url form '${suffix:-bare}' and require 404"
      continue
    fi

    : > "$HEADERS_TMP"
    status=$(curl --max-time 20 -sS -o /dev/null -D "$HEADERS_TMP" -w '%{http_code}' \
      "https://${DOMAIN}/${hash}${suffix}" || true)
    [ -n "$status" ] || status="000"
    served_by=$(grep -i '^x-served-by:' "$HEADERS_TMP" | tr -d '\r' | cut -d' ' -f2- || true)
    if [ "$status" = "404" ]; then
      echo "[$label] probe 404 url form '${suffix:-bare}' served_by='${served_by}'"
    else
      echo "[$label] PROBE FAIL url form '${suffix:-bare}' status=${status} served_by='${served_by}'"
      PROBE_FAIL=$((PROBE_FAIL + 1))
    fi
  done
done

echo "purge_failures=${PURGE_FAIL} probe_failures=${PROBE_FAIL}"
echo "note: the probe observed one POP; other POPs' copies are not visible from here"
if [ "$PURGE_FAIL" -gt 0 ] || [ "$PROBE_FAIL" -gt 0 ]; then
  exit 1
fi
