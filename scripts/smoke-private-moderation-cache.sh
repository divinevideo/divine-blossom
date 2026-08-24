#!/bin/sh
# ABOUTME: Post-deploy smoke coverage for private moderation-status cache behavior.
# ABOUTME: Requires dedicated synthetic fixtures and externally injected credentials.

set -eu
set +x

DOMAIN="${DOMAIN:-media.divine.video}"
umask 077
SMOKE_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/divine-blossom-private-smoke.XXXXXX")
HEADERS_FILE="$SMOKE_TMP_DIR/headers"
ADMIN_CURL_CONFIG="$SMOKE_TMP_DIR/admin-curl.conf"
trap 'rm -rf "$SMOKE_TMP_DIR"' EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

require_value() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || fail "$1 is required"
}

require_hash() {
  eval "value=\${$1:-}"
  printf '%s' "$value" | grep -Eq '^[0-9a-fA-F]{64}$' || \
    fail "$1 must be a 64-hex synthetic fixture hash"
}

require_command curl
require_command nak
require_value OWNER_NSEC
require_value ADMIN_TOKEN
require_hash RESTRICTED_HASH
require_hash AGE_RESTRICTED_HASH
require_hash BANNED_HASH
require_hash DELETED_HASH

seen_hashes=""
for fixture_hash in \
  "$RESTRICTED_HASH" "$AGE_RESTRICTED_HASH" "$BANNED_HASH" "$DELETED_HASH"; do
  case " $seen_hashes " in
    *" $fixture_hash "*)
      fail "each moderation status requires a distinct synthetic fixture hash"
      ;;
  esac
  seen_hashes="$seen_hashes $fixture_hash"
done

# Keep the bearer credential out of curl's argv and remove the file on every exit.
printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_TOKEN" >"$ADMIN_CURL_CONFIG"

header_has() {
  name="$1"
  pattern="$2"
  grep -Eiq "^${name}:[[:space:]]*.*${pattern}" "$HEADERS_FILE"
}

request() {
  auth="$1"
  method="$2"
  url="$3"

  : >"$HEADERS_FILE"
  case "$auth" in
    anonymous)
      curl -sS -X "$method" -D "$HEADERS_FILE" -o /dev/null \
        -w '%{http_code}' --max-time 30 "$url"
      ;;
    owner)
      # nak signs a fresh NIP-98 event for the exact method and URL.
      NOSTR_SECRET_KEY="$OWNER_NSEC" nak curl -sS -X "$method" -D "$HEADERS_FILE" \
        -o /dev/null -w '%{http_code}' --max-time 30 "$url"
      ;;
    admin)
      curl -sS -X "$method" --config "$ADMIN_CURL_CONFIG" -D "$HEADERS_FILE" \
        -o /dev/null -w '%{http_code}' --max-time 30 "$url"
      ;;
    *) fail "unknown auth mode: $auth" ;;
  esac
}

assert_code() {
  label="$1"
  expected="$2"
  actual="$3"
  [ "$actual" = "$expected" ] || \
    fail "$label returned $actual, expected $expected"
}

assert_private() {
  label="$1"
  header_has cache-control 'private([,[:space:]]|$)' || \
    fail "$label is missing Cache-Control: private"
  header_has cache-control 'no-store([,[:space:]]|$)' || \
    fail "$label is missing Cache-Control: no-store"
  header_has surrogate-control 'no-store([,[:space:]]|$)' || \
    fail "$label is missing Surrogate-Control: no-store"
  if header_has x-cache 'HIT'; then
    fail "$label was stored in the shared edge cache"
  fi
}

assert_hidden_cache_policy() {
  label="$1"
  header_has cache-control 'no-store([,[:space:]]|$)' || \
    fail "$label is missing browser no-store"
  header_has surrogate-control 'max-age=60([^0-9]|$)' || \
    fail "$label is missing the bounded 60-second edge policy"
}

assert_age_gate_cache_policy() {
  label="$1"
  if header_has cache-control 'public' || header_has surrogate-control 'max-age'; then
    fail "$label advertised a public cache policy"
  fi
  if header_has x-cache 'HIT'; then
    fail "$label was stored in the shared edge cache"
  fi
}

route_paths() {
  hash="$1"
  printf '%s\n' \
    "/$hash" \
    "/$hash.jpg" \
    "/$hash.audio.m4a" \
    "/$hash.hls"
}

check_anonymous_fixture() {
  status="$1"
  hash="$2"
  expected="$3"

  route_paths "$hash" | while IFS= read -r path; do
    for method in GET HEAD; do
      for attempt in 1 2; do
        label="anonymous $method $status $path attempt $attempt"
        code=$(request anonymous "$method" "https://$DOMAIN$path")
        assert_code "$label" "$expected" "$code"
        if [ "$expected" = "404" ]; then
          assert_hidden_cache_policy "$label"
        else
          assert_age_gate_cache_policy "$label"
        fi
        printf 'PASS: %s\n' "$label"
      done
    done
  done
}

check_owner_fixture() {
  status="$1"
  hash="$2"
  expected="$3"

  route_paths "$hash" | while IFS= read -r path; do
    for attempt in 1 2; do
      label="owner GET $status $path attempt $attempt"
      code=$(request owner GET "https://$DOMAIN$path")
      assert_code "$label" "$expected" "$code"
      if [ "$expected" = "200" ]; then
        assert_private "$label"
      else
        assert_hidden_cache_policy "$label"
      fi
      printf 'PASS: %s\n' "$label"
    done
  done
}

check_admin_fixture() {
  status="$1"
  hash="$2"

  route_paths "$hash" | while IFS= read -r path; do
    for attempt in 1 2; do
      label="admin GET $status $path attempt $attempt"
      code=$(request admin GET "https://$DOMAIN$path")
      assert_code "$label" 200 "$code"
      assert_private "$label"
      if [ "$path" = "/$hash" ]; then
        header_has x-moderation-status "${status}[[:space:]]*$" || \
          fail "$label did not identify the expected synthetic fixture status"
      fi
      printf 'PASS: %s\n' "$label"
    done
  done
}

printf '=== Private moderation cache smoke: https://%s ===\n' "$DOMAIN"

check_anonymous_fixture Restricted "$RESTRICTED_HASH" 404
check_anonymous_fixture AgeRestricted "$AGE_RESTRICTED_HASH" 401
check_anonymous_fixture Banned "$BANNED_HASH" 404
check_anonymous_fixture Deleted "$DELETED_HASH" 404

# Restricted content serves only to its owner; age-restricted content serves to
# any authenticated viewer. Both successful response classes must remain private.
check_owner_fixture Restricted "$RESTRICTED_HASH" 200
check_owner_fixture AgeRestricted "$AGE_RESTRICTED_HASH" 200
check_owner_fixture Banned "$BANNED_HASH" 404
check_owner_fixture Deleted "$DELETED_HASH" 404

# Standard GET handlers accept the admin bearer bypass. HEAD handlers do not
# receive auth context, so their anonymous behavior above is the supported check.
check_admin_fixture Restricted "$RESTRICTED_HASH"
check_admin_fixture AgeRestricted "$AGE_RESTRICTED_HASH"
check_admin_fixture Banned "$BANNED_HASH"
check_admin_fixture Deleted "$DELETED_HASH"

printf 'PASS: all private moderation-status routes preserved access and cache policy\n'
