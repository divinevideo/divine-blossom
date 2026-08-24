#!/bin/sh
# ABOUTME: Post-deploy smoke coverage for private moderation-status cache behavior.
# ABOUTME: Requires dedicated synthetic fixtures and externally injected credentials.

set -eu
set +x

DOMAIN="${DOMAIN:-media.divine.video}"
RUN_ID="$(date +%s)-$$"
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
  header_name="$1"
  header_pattern="$2"
  grep -Eiq "^${header_name}:[[:space:]]*.*${header_pattern}" "$HEADERS_FILE"
}

header_equals() {
  exact_header_name="$1"
  exact_header_value="$2"
  grep -Eiq "^${exact_header_name}:[[:space:]]*${exact_header_value}[[:space:]]*$" "$HEADERS_FILE"
}

request() {
  request_auth="$1"
  request_method="$2"
  request_url="$3"

  : >"$HEADERS_FILE"
  case "$request_auth" in
    anonymous)
      if [ "$request_method" = "HEAD" ]; then
        curl -sS -I -D "$HEADERS_FILE" -o /dev/null \
          -w '%{http_code}' --max-time 30 "$request_url"
      else
        curl -sS -D "$HEADERS_FILE" -o /dev/null \
          -w '%{http_code}' --max-time 30 "$request_url"
      fi
      ;;
    owner)
      # nak signs a fresh NIP-98 event for the exact method and URL.
      NOSTR_SECRET_KEY="$OWNER_NSEC" nak curl -sS -D "$HEADERS_FILE" \
        -o /dev/null -w '%{http_code}' --max-time 30 "$request_url"
      ;;
    admin)
      curl -sS --config "$ADMIN_CURL_CONFIG" -D "$HEADERS_FILE" \
        -o /dev/null -w '%{http_code}' --max-time 30 "$request_url"
      ;;
    *) fail "unknown auth mode: $request_auth" ;;
  esac
}

assert_code() {
  assert_label="$1"
  assert_expected="$2"
  assert_actual="$3"
  [ "$assert_actual" = "$assert_expected" ] || \
    fail "$assert_label returned $assert_actual, expected $assert_expected"
}

assert_private() {
  private_label="$1"
  header_has cache-control 'private([,[:space:]]|$)' || \
    fail "$private_label is missing Cache-Control: private"
  header_has cache-control 'no-store([,[:space:]]|$)' || \
    fail "$private_label is missing Cache-Control: no-store"
  if header_has x-cache 'HIT'; then
    fail "$private_label was stored in the shared edge cache"
  fi
}

assert_hidden_cache_policy() {
  hidden_label="$1"
  header_has cache-control 'no-store([,[:space:]]|$)' || \
    fail "$hidden_label is missing browser no-store"
}

assert_age_gate_cache_policy() {
  age_label="$1"
  if header_has cache-control 'public'; then
    fail "$age_label advertised a public cache policy"
  fi
  if header_has x-cache 'HIT'; then
    fail "$age_label was stored in the shared edge cache"
  fi
}

route_paths() {
  route_hash="$1"
  printf '%s\n' \
    "/$route_hash" \
    "/$route_hash.jpg" \
    "/$route_hash.audio.m4a" \
    "/$route_hash.hls"
}

check_anonymous_fixture() {
  anon_status="$1"
  anon_hash="$2"
  anon_expected="$3"

  route_paths "$anon_hash" | while IFS= read -r anon_path; do
    for anon_method in GET HEAD; do
      for anon_attempt in 1 2; do
        anon_label="anonymous $anon_method $anon_status $anon_path attempt $anon_attempt"
        anon_code=$(request anonymous "$anon_method" "https://$DOMAIN$anon_path")
        assert_code "$anon_label" "$anon_expected" "$anon_code"
        if [ "$anon_expected" = "404" ]; then
          assert_hidden_cache_policy "$anon_label"
        else
          assert_age_gate_cache_policy "$anon_label"
        fi
        printf 'PASS: %s\n' "$anon_label"
      done
    done
  done
}

check_owner_fixture() {
  owner_status="$1"
  owner_hash="$2"
  owner_expected="$3"

  route_paths "$owner_hash" | while IFS= read -r owner_path; do
    owner_url="https://$DOMAIN$owner_path?private-smoke=$RUN_ID-owner"
    for owner_attempt in 1 2; do
      owner_label="owner GET $owner_status $owner_path attempt $owner_attempt"
      owner_code=$(request owner GET "$owner_url")
      assert_code "$owner_label" "$owner_expected" "$owner_code"
      if [ "$owner_expected" = "200" ]; then
        assert_private "$owner_label"
      else
        assert_hidden_cache_policy "$owner_label"
      fi
      printf 'PASS: %s\n' "$owner_label"
    done
    check_anonymous_after_credential owner "$owner_status" "$owner_path" "$owner_url"
  done
}

check_admin_fixture() {
  admin_status="$1"
  admin_hash="$2"

  route_paths "$admin_hash" | while IFS= read -r admin_path; do
    admin_url="https://$DOMAIN$admin_path?private-smoke=$RUN_ID-admin"
    for admin_attempt in 1 2; do
      admin_label="admin GET $admin_status $admin_path attempt $admin_attempt"
      admin_code=$(request admin GET "$admin_url")
      assert_code "$admin_label" 200 "$admin_code"
      assert_private "$admin_label"
      if [ "$admin_path" = "/$admin_hash" ]; then
        header_equals x-moderation-status "$admin_status" || \
          fail "$admin_label did not identify the expected synthetic fixture status"
      fi
      printf 'PASS: %s\n' "$admin_label"
    done
    check_anonymous_after_credential admin "$admin_status" "$admin_path" "$admin_url"
  done
}

check_anonymous_after_credential() {
  post_credential="$1"
  post_status="$2"
  post_path="$3"
  post_url="$4"

  case "$post_status" in
    AgeRestricted) post_expected=401 ;;
    *) post_expected=404 ;;
  esac

  post_label="anonymous after $post_credential GET $post_status $post_path"
  post_code=$(request anonymous GET "$post_url")
  assert_code "$post_label" "$post_expected" "$post_code"
  if [ "$post_expected" = "404" ]; then
    assert_hidden_cache_policy "$post_label"
  else
    assert_age_gate_cache_policy "$post_label"
  fi
  printf 'PASS: %s\n' "$post_label"

  bare_label="anonymous bare URL after $post_credential GET $post_status $post_path"
  bare_code=$(request anonymous GET "https://$DOMAIN$post_path")
  assert_code "$bare_label" "$post_expected" "$bare_code"
  if [ "$post_expected" = "404" ]; then
    assert_hidden_cache_policy "$bare_label"
  else
    assert_age_gate_cache_policy "$bare_label"
  fi
  printf 'PASS: %s\n' "$bare_label"
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
