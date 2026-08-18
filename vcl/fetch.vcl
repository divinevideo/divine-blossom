# ABOUTME: VCL fetch snippet for Divine Blossom VCL caching layer
# ABOUTME: Enforces long edge caching while preserving explicit browser cache policy

# Strip any anti-caching headers leaked from GCS through Compute
unset beresp.http.Pragma;

# Origin owns the decision about what must not be cached. Compute marks
# restricted and admin content `private, no-store` (src/main.rs, via
# requires_private_cache), and that must win over the long TTL set below --
# otherwise a credentialed fetch of restricted content would be stored at the
# edge for a year. This check must come first: the 200/206 branch sets a 365-day
# TTL unconditionally and would otherwise cache it regardless of this header.
#
# This is the only thing keeping non-public responses out of the shared edge
# cache, so it must stay first and must stay broad.
if (beresp.http.Cache-Control ~ "(?i)(private|no-store)") {
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

  # No Cache-Control fallback here on purpose. This block used to stamp
  # `public, max-age=31536000, immutable` onto any response that arrived without
  # a policy, which meant a response the origin had not classified was published
  # to browsers as immutable for a year -- uninvalidatable, since browser caches
  # cannot be purged. Compute sets an explicit policy on every response it means
  # to be cacheable, so a missing header signals an origin that did not decide,
  # and the edge must not decide on its behalf.
  #
  # Removed on Fastly's review (Kay Sawada, 2026-08-18, service version 16).

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
