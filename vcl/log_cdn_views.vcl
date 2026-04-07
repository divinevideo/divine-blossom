# ABOUTME: VCL log snippet for CDN video view counting
# ABOUTME: Logs full video downloads to Google Cloud Pub/Sub for view count aggregation
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
#   - Bare SHA256 paths (not thumbnails, HLS segments, VTT, etc.)
#   - HTTP 200 responses (not 206 range requests, 404s, etc.)
#
# Every logged row = one view. No dedup, no rate limiting.
# No client IP stored — only POP for geographic distribution.

if (req.method == "GET"
    && req.url ~ "^/[0-9a-fA-F]{64}$"
    && resp.status == 200) {
  log {"syslog "} req.service_id {" cdn-view-logs :: "}
    {"{"}
      {""ts":"} time.start.sec {","}
      {""sha256":""} regsub(req.url, "^/", "") {"","}
      {""bytes":"} resp.body_bytes_written {","}
      {""pop":""} server.datacenter {""}
    {"}"};
}
