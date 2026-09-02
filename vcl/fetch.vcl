# ABOUTME: VCL fetch snippet for Divine Blossom VCL caching layer
# ABOUTME: Enforces long edge caching while preserving explicit browser cache policy

# Strip any anti-caching headers leaked from GCS through Compute
unset beresp.http.Pragma;

# A syntactically valid origin 5xx does not enter vcl_error. These records are
# the ones Fastly status_503 counts while error_sub_time stays 0 (see #271).
# Do not return(error) here: that would replace the origin body.
if (beresp.status >= 500 && beresp.status < 600) {
  if (req.backend.is_origin) {
    set req.http.X-Divine-Backend-Hop = "origin";
  } else {
    set req.http.X-Divine-Backend-Hop = "shield";
  }
  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.vcl_5xx.v1","}
      {""phase":"fetch","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(substr(regsuball(req.http.X-Divine-Edge-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 64)) {"","}
      {""service_id":""} json.escape(req.service_id) {"","}
      {""method":""} json.escape(req.method) {"","}
      {""url":""} json.escape(substr(req.url, 0, 256)) {"","}
      {""status":"} beresp.status {","}
      {""reason":""} json.escape(beresp.response) {"","}
      {""pop":""} json.escape(server.datacenter) {"","}
      {""backend":""} json.escape(req.backend.name) {"","}
      {""backend_hop":""} json.escape(req.http.X-Divine-Backend-Hop) {"","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""ff_visits":"} fastly.ff.visits_this_service {","}
      {""restart_count":"} req.restarts {","}
      {""elapsed_ms":"} time.elapsed.msec
    {"}"};
  unset req.http.X-Divine-Backend-Hop;
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
