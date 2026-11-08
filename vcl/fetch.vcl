# ABOUTME: VCL fetch snippet for Divine Blossom VCL caching layer
# ABOUTME: Enforces long edge caching while preserving explicit browser cache policy

declare local var.backend_hop STRING;
declare local var.b2_segment_start INTEGER;
declare local var.b2_segment_end INTEGER;
declare local var.b2_segment_total INTEGER;
declare local var.b2_segment_length INTEGER;

# Strip any anti-caching headers leaked from GCS through Compute
unset beresp.http.Pragma;

# A syntactically valid origin 5xx does not enter vcl_error. These records are
# the ones Fastly status_503 counts while error_sub_time stays 0 (see #271).
# Do not return(error) here: that would replace the origin body.
if (beresp.status >= 500 && beresp.status < 600) {
  if (req.backend.is_origin) {
    set var.backend_hop = "origin";
  } else {
    set var.backend_hop = "shield";
  }
  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.vcl_5xx.v1","}
      {""phase":"fetch","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(substr(regsuball(req.http.X-Divine-Edge-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 64)) {"","}
      {""service_id":""} json.escape(req.service_id) {"","}
      {""method":""} json.escape(req.method) {"","}
      {""url":""} json.escape(utf8.substr(req.url, 0, 256)) {"","}
      {""status":"} beresp.status {","}
      {""error_reason":""} json.escape(beresp.response) {"","}
      {""pop":""} json.escape(server.datacenter) {"","}
      {""backend":""} json.escape(req.backend.name) {"","}
      {""backend_hop":""} json.escape(var.backend_hop) {"","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""ff_visits":"} fastly.ff.visits_this_service {","}
      {""restart_count":"} req.restarts {","}
      {""elapsed_ms":"} time.elapsed.msec
    {"}"};
}

# B2 original admission is default-deny on both declared delivery names.
# The marker is issued by Compute only at its final guarded response boundary.
# Preserve it and the bare-hash key through shield delivery for edge admission.
if (req.http.Host ~ "(?i)^media-b2(-cdn)?[.]divine[.]video(:[0-9]+)?$") {
  set beresp.grace = 0s;
  set beresp.stale_while_revalidate = 0s;
  set beresp.stale_if_error = 0s;
  if (req.http.Host !~ "^media-b2(-cdn)?[.]divine[.]video$" ||
      req.url !~ "^/[0-9a-f]{64}$" ||
      (req.method != "GET" && req.method != "HEAD") ||
      req.http.Authorization || req.http.Cookie ||
      beresp.http.Surrogate-Control != "max-age=31536000, stale-while-revalidate=0, stale-if-error=0" ||
      beresp.http.Surrogate-Key != regsub(req.url, "^/", "") ||
      beresp.http.X-Sha256 != regsub(req.url, "^/", "") ||
      beresp.http.Set-Cookie) {
    set beresp.ttl = 0s;
    return(pass);
  }
  if (segmented_caching.is_inner_req) {
    # Only Compute's final guarded response can issue this version-bound marker.
    # Native segmented caching requires length framing, never chunked encoding.
    if (!req.enable_segmented_caching || beresp.status != 206 ||
        beresp.http.X-Divine-B2-CDN-Admission != "original-segment-v1" ||
        beresp.http.X-Divine-Source != "b2" ||
        beresp.http.Content-Length !~ "^[0-9]+\z" ||
        beresp.http.Content-Range !~ "^bytes [0-9]+-[0-9]+/[0-9]+\z" ||
        beresp.http.X-Content-Length !~ "^[0-9]+\z" ||
        beresp.http.ETag !~ "^\"b2-[0-9a-f]{64}\"\z" ||
        beresp.http.Transfer-Encoding ||
        (beresp.http.Content-Encoding && beresp.http.Content-Encoding != "identity")) {
      set beresp.ttl = 0s;
      return(pass);
    }
    set var.b2_segment_start = std.atoi(regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\1"));
    set var.b2_segment_end = std.atoi(regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\2"));
    set var.b2_segment_total = std.atoi(regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\3"));
    set var.b2_segment_length = std.atoi(beresp.http.Content-Length);
    # Round-trip every integer so overflow/fallback parsing cannot admit bytes.
    if (std.itoa(var.b2_segment_start) != regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\1") ||
        std.itoa(var.b2_segment_end) != regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\2") ||
        std.itoa(var.b2_segment_total) != regsub(beresp.http.Content-Range, "^bytes ([0-9]+)-([0-9]+)/([0-9]+)\z", "\3") ||
        std.itoa(var.b2_segment_length) != beresp.http.Content-Length ||
        std.itoa(var.b2_segment_total) != beresp.http.X-Content-Length ||
        var.b2_segment_start < 0 || var.b2_segment_end < var.b2_segment_start ||
        var.b2_segment_total <= var.b2_segment_end || var.b2_segment_length <= 0 ||
        var.b2_segment_end - var.b2_segment_start + 1 != var.b2_segment_length) {
      set beresp.ttl = 0s;
      return(pass);
    }
  } else if (beresp.status != 200 ||
      beresp.http.X-Divine-B2-CDN-Admission != "original-v1" ||
      beresp.http.Content-Range) {
    # Preserve ordinary admission during the coordinated Compute/VCL rollout.
    set beresp.ttl = 0s;
    return(pass);
  }
  set beresp.ttl = 365d;
  set beresp.do_stream = true;
  set beresp.http.Cache-Control = "private, no-store";
  return(deliver);
}

# Origin owns the edge-cache decision through Surrogate-Control. Compute marks
# restricted and admin content `no-store` there, and that must win over the long
# TTL set below -- otherwise a credentialed fetch of restricted content would be
# stored at the edge for a year. Cache-Control is deliberately not consulted:
# 404 responses use browser `no-store` together with an edge `max-age=60` policy.
# This check must stay ahead of the 200/206 branch, which sets a 365-day TTL.
#
# This is the origin-policy enforcement layer that keeps explicitly non-public
# responses out of the shared edge cache, so it must stay first and stay broad.
if (beresp.http.Surrogate-Control ~ "(?i)(private|no-store)") {
  set beresp.ttl = 0s;
  set beresp.grace = 0s;
  return(pass);
}

if (beresp.status == 200 || beresp.status == 206) {
  # Successful content responses: keep a long, purgeable edge TTL.
  set beresp.ttl = 365d;
  set beresp.grace = 24h;
  set beresp.stale_while_revalidate = 24h;

  # Deliver bytes to the client as they arrive from origin instead of buffering
  # the whole object first. This is the required counterpart to the vcl_miss
  # snippet that strips the client Range header: that strip makes every cache
  # fill fetch the FULL object, so without streaming a client asking for the
  # first 1KB of a cold video waits for the entire object to land.
  #
  # Measured on 2026-08-11 before this line existed:
  #   cold range request, Range stripped, buffered : 3.1-4.0s to first byte
  #   cold range request, Range forwarded (control): 1.34s
  #   warm range request (cache hit)               : 0.09s
  #
  # Streaming keeps the whole object cached -- the byte-offload gain is
  # unaffected -- while removing the buffer wait. Caveats: a mid-stream origin
  # failure cannot be cleanly retried, and a range starting mid-object still
  # waits for the stream to reach that offset. Players request bytes=0- first,
  # which is the case this helps most.
  set beresp.do_stream = true;

  # No Cache-Control fallback here on purpose. Compute owns browser policy, so a
  # missing header must not be rewritten as public and immutable for a year.
  # Browser caches cannot be purged after such a response is delivered.
  #
  # This removal affects browser policy only. The successful-response branch
  # above still assigns an edge TTL when Surrogate-Control is absent.
  # TODO(#223): make an unclassified edge response fail closed as well.

} else if (beresp.status == 202) {
  # 202 Accepted = transcoding/transcription in progress
  # Compute already sets no-store headers, but enforce uncacheability as defense-in-depth
  set beresp.ttl = 0s;
  set beresp.grace = 0s;
  return(pass);

} else if (beresp.status == 404) {
  # Cache 404s briefly (moderation blocks, missing content)
  # Surrogate-Key on the response enables instant purge when content is unblocked
  set beresp.ttl = 60s;
  set beresp.grace = 0s;

} else {
  # Other errors (4xx, 5xx): don't cache
  set beresp.ttl = 0s;
  set beresp.grace = 0s;
  return(pass);
}
