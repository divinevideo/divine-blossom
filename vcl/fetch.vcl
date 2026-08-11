# ABOUTME: VCL fetch snippet for Divine Blossom VCL caching layer
# ABOUTME: Enforces long edge caching while preserving explicit browser cache policy

# Strip any anti-caching headers leaked from GCS through Compute
unset beresp.http.Pragma;

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

  # Compute owns browser policy: blobs are immutable, but repairable derivatives
  # have a shorter browser TTL. Retain the immutable default for legacy responses
  # that do not provide an explicit policy.
  if (!beresp.http.Cache-Control) {
    set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
  }

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
