# ABOUTME: VCL log snippet for CDN video view counting
# ABOUTME: Logs delivered video bytes to Google Cloud Pub/Sub for view count aggregation
#
# Production does NOT apply this file as a snippet. It runs the equivalent as a
# Google Cloud Pub/Sub logging endpoint format plus a response condition named
# `cdn-view-log-condition`, both set in the Fastly dashboard — see
# docs/runbooks/cdn-view-counting.md. This file is the authoritative source for
# the regex literals and the snippet form to fall back to if the endpoint is
# ever moved back into an explicit `vcl_log` snippet.
#
# Fastly log endpoint setup:
#   Type: Google Cloud Pub/Sub
#   Name: cdn-view-logs
#   Project: rich-compiler-479518-d2
#   Topic: cdn-view-logs
#   Service account JSON: (from Fastly dashboard)
#
# Only logs:
#   - GET requests (not HEAD, OPTIONS, etc.)
#   - Video byte responses (Content-Type: video/*)
#   - Canonical and derivative video paths for the same SHA256
#   - Any successful response that delivered video bytes
#
# Every logged row = one view. No dedup, no rate limiting.
# No client IP stored — only POP for geographic distribution.
#
# The path pattern accepts uppercase hex because the service does: routing
# validates with is_ascii_hexdigit and then normalises with to_lowercase
# (blossom-core/src/types.rs). std.tolower on the logged sha256 and path keeps
# the emitted rows joinable with the lowercase hashes stored everywhere else.
#
# The query strip uses "[\s\S]*", not ".*", because "." does not cross a
# newline. `path` is interpolated into the JSON row below without escaping, so a
# strip that stops at a newline could leave raw bytes from the query string in a
# JSON string and break the row. The character class consumes to the true end.
#
# Escaping: VCL string literals do not process backslash escapes (Fastly uses
# percent escapes, e.g. "%22"). A backslash reaches the regex engine verbatim,
# so regex escapes are written with a SINGLE backslash. Doubling them would
# produce "\\?" — an optional literal backslash, which matches the empty string
# and silently disables the alternation.
#
# This file is the authoritative source for the three regex literals below.
# scripts/tests/test_cdn_view_vcl.py parses them out of this file, exercises
# them against real request paths, and asserts the copies in
# docs/runbooks/cdn-view-counting.md have not drifted.

if (req.method == "GET"
    && req.url ~ "^/[0-9a-fA-F]{64}($|\?|\.(mp4|m4v|webm|mov|mkv|ogv|avi)(\?|$)|/(720p|480p)(\.mp4)?(\?|$)|/hls/stream_(720p|480p)\.(ts|mp4)(\?|$))"
    && resp.http.Content-Type ~ "^video/"
    && resp.status >= 200
    && resp.status < 300
    && resp.body_bytes_written > 0) {
  log {"syslog "} req.service_id {" cdn-view-logs :: "}
    {"{"}
      {""v":2,"}
      {""ts":"} time.start.sec {","}
      {""sha256":""} std.tolower(regsub(req.url, "^/([0-9a-fA-F]{64}).*", "\1")) {"","}
      {""path":""} std.tolower(regsub(req.url, "\?[\s\S]*$", "")) {"","}
      {""status":"} resp.status {","}
      {""bytes":"} resp.body_bytes_written {","}
      {""pop":""} server.datacenter {"","}
      {""cache":""} fastly_info.state {""}
    {"}"};
}
