# ABOUTME: VCL log snippet for CDN video view counting
# ABOUTME: Logs delivered video bytes to Google Cloud Pub/Sub for view count aggregation
#
# Applied via Fastly dashboard as a VCL snippet in vcl_log subroutine.
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
    && req.url ~ "^/[0-9a-fA-F]{64}($|\?|\.mp4(\?|$)|/(720p|480p)(\.mp4)?(\?|$)|/hls/stream_(720p|480p)\.(ts|mp4)(\?|$))"
    && resp.http.Content-Type ~ "^video/"
    && resp.status >= 200
    && resp.status < 300
    && resp.body_bytes_written > 0) {
  log {"syslog "} req.service_id {" cdn-view-logs :: "}
    {"{"}
      {""v":2,"}
      {""ts":"} time.start.sec {","}
      {""sha256":""} regsub(req.url, "^/([0-9a-fA-F]{64}).*", "\1") {"","}
      {""path":""} regsub(req.url, "\?.*$", "") {"","}
      {""status":"} resp.status {","}
      {""bytes":"} resp.body_bytes_written {","}
      {""pop":""} server.datacenter {"","}
      {""cache":""} fastly_info.state {""}
    {"}"};
}
