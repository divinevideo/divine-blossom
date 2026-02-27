# ABOUTME: VCL fetch snippet for Divine Blossom VCL caching layer
# ABOUTME: Overrides backend cache headers from Compute/GCS to enforce aggressive caching

# Strip any anti-caching headers leaked from GCS through Compute
unset beresp.http.Pragma;

if (beresp.status == 200 || beresp.status == 206) {
  # Successful content responses: cache aggressively (1 year)
  # Content is SHA256-addressed and immutable
  set beresp.ttl = 365d;
  set beresp.grace = 24h;
  set beresp.stale_while_revalidate = 24h;

  # Override any anti-caching headers from GCS (no-cache, no-store, private)
  set beresp.http.Cache-Control = "public, max-age=31536000, immutable";

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
