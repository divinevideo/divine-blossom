#!/usr/bin/env bash
# ABOUTME: One-time cleanup for erased media that edge POPs stored without a Surrogate-Key
# ABOUTME: Purges an exact private address list with rate-limited PURGE requests
#
# Usage:
#   envchain fastly-global scripts/purge-erased-edge-copies.sh --address-file <path> [--domain <host>] [--dry-run]
#
# Reads one exact URL path per line from --address-file. Blank lines and lines
# starting with # are ignored. Never pass addresses on the command line, commit
# the file, or paste its contents into an issue; see
# docs/runbooks/erased-media-edge-cleanup.md.
set -euo pipefail

DOMAIN="media.divine.video"
ADDRESS_FILE=""
DRY_RUN=0
REQUEST_DELAY="0.084"

usage() {
  cat <<'USAGE'
Usage: envchain fastly-global scripts/purge-erased-edge-copies.sh --address-file <path> [--domain <host>] [--dry-run]

Reads one exact URL path per line from --address-file (blank lines and comments
ignored). Paths may have one leading slash and must begin with a 64-hex content
hash. Never pass addresses on the command line. Each address is purged with the
PURGE method at no more than 12 requests per second.
See docs/runbooks/erased-media-edge-cleanup.md.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --address-file)
      [ $# -ge 2 ] || { echo "error: --address-file needs a path" >&2; exit 2; }
      ADDRESS_FILE="$2"
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

if [ -z "$ADDRESS_FILE" ]; then
  echo "error: --address-file is required" >&2
  usage >&2
  exit 2
fi
if [ ! -r "$ADDRESS_FILE" ]; then
  echo "error: cannot read address file" >&2
  exit 2
fi
if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ ]]; then
  echo "error: --domain must be a host name with an optional port" >&2
  exit 2
fi

ADDRESSES=()
line_no=0
while IFS= read -r raw || [ -n "$raw" ]; do
  line_no=$((line_no + 1))
  address="${raw#/}"
  case "$address" in
    ""|"#"*) continue ;;
  esac
  if ! [[ "$address" =~ ^[0-9a-f]{64}($|[./]) ]] \
    || [[ "$address" =~ [[:space:]] ]] \
    || [[ "$address" =~ (^|/)\.{1,2}(/|$) ]] \
    || [[ "$address" == *"%"* ]] \
    || [[ "$address" == *"?"* ]] \
    || [[ "$address" == *"#"* ]]; then
    echo "error: line $line_no is not a safe erased-media address" >&2
    exit 2
  fi
  ADDRESSES+=("$address")
done < "$ADDRESS_FILE"

if [ "${#ADDRESSES[@]}" -eq 0 ]; then
  echo "error: address file holds no addresses" >&2
  exit 2
fi
if [ "$DRY_RUN" -eq 0 ] && [ -z "${FASTLY_API_TOKEN:-}" ]; then
  echo "error: FASTLY_API_TOKEN is required (run through envchain fastly-global)" >&2
  exit 2
fi
if [ "$DRY_RUN" -eq 0 ] && ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required to validate purge receipts" >&2
  exit 2
fi

umask 077
BODY_TMP=$(mktemp "${TMPDIR:-/tmp}/purge-erased-edge-copies.XXXXXX")
CURL_CONFIG_TMP=$(mktemp "${TMPDIR:-/tmp}/purge-erased-edge-curl.XXXXXX")
trap 'rm -f "$BODY_TMP" "$CURL_CONFIG_TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$DRY_RUN" -eq 0 ]; then
  printf 'header = "Fastly-Key: %s"\n' "$FASTLY_API_TOKEN" > "$CURL_CONFIG_TMP"
fi

echo "addresses=${#ADDRESSES[@]} domain=${DOMAIN} dry_run=${DRY_RUN} rate_limit=12/s"

index=0
for address in "${ADDRESSES[@]}"; do
  index=$((index + 1))
  label="${index}/${#ADDRESSES[@]}"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[$label] would purge address"
    continue
  fi

  : > "$BODY_TMP"
  if ! status=$(curl --config "$CURL_CONFIG_TMP" --globoff --max-time 20 \
    --silent --show-error --output "$BODY_TMP" \
    --write-out '%{http_code}' --request PURGE \
    "https://${DOMAIN}/${address}"); then
    echo "[$label] PURGE FAIL request error" >&2
    exit 1
  fi
  if [ "$status" != "200" ] || ! jq -e '.status == "ok"' "$BODY_TMP" >/dev/null; then
    echo "[$label] PURGE FAIL unexpected response status=${status}" >&2
    exit 1
  fi
  purge_id=$(jq -r '.id // empty' "$BODY_TMP")
  if [ -z "$purge_id" ]; then
    echo "[$label] PURGE FAIL response omitted purge id" >&2
    exit 1
  fi

  echo "[$label] purged_at=$(date -u +%Y-%m-%dT%H:%M:%SZ) purge_id=${purge_id}"
  sleep "$REQUEST_DELAY"
done

echo "purged=${#ADDRESSES[@]} failures=0"
