# ABOUTME: VCL recv snippet for Divine Blossom VCL caching layer
# ABOUTME: Routes cacheable GET/HEAD requests through cache, passes everything else to Compute

# Pass original host to Compute so it can generate correct URLs
set req.http.X-Original-Host = req.http.Host;

# Keep one correlation ID across the outer VCL and chained Compute services.
if (std.strlen(req.http.X-Request-Id) == 0) {
  set req.http.X-Request-Id = uuid.version4();
}
# Preserve the outer service's sanitized value for cross-service correlation.
# The 64-character cap must match blossom-core request_diagnostics
# MAX_REQUEST_ID_LEN so both services truncate caller IDs identically.
set req.http.X-Divine-Edge-Request-Id = substr(regsuball(req.http.X-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 64);
if (std.strlen(req.http.X-Divine-Edge-Request-Id) == 0) {
  set req.http.X-Divine-Edge-Request-Id = uuid.version4();
  set req.http.X-Request-Id = req.http.X-Divine-Edge-Request-Id;
}

# Force all traffic to the Compute backend
set req.backend = F_compute_origin;

# Only cache GET and HEAD requests
if (req.method != "GET" && req.method != "HEAD") {
  return(pass);
}

# Never trust a client-supplied value for the cache-key bit; it is derived below.
unset req.http.X-Auth-Present;

# Cache hash-based content paths: /{64-char-hex}[.ext], /{hash}.hls, /{hash}/hls/*, /{hash}.vtt, /{hash}/{quality}
# Match paths starting with / followed by 64 hex chars.
#
# These are cacheable whether or not the caller sent credentials. The bytes for a
# given hash do not vary by WHICH user asks -- only by whether credentials were
# present at all, since restricted content is served to a credentialed caller and
# refused to an anonymous one. So the auth-presence bit goes into the cache key
# (see the vcl_hash snippet) and both variants can go hot.
#
# This snippet used to pass every credentialed request. Clients send Authorization
# on every media request, so that took 48% of requests and 64% of delivered bytes
# out of cache entirely (measured on the outer service, 2026-08-17) for content
# that is SHA-256 addressed and immutable.
#
# Restricted content is kept out of the anonymous cache by two independent layers:
# this key split, and the private/no-store check in the vcl_fetch snippet. Neither
# is sufficient alone and both must hold.
if (req.url ~ "^/[0-9a-fA-F]{64}") {
  if (req.http.Authorization) {
    set req.http.X-Auth-Present = "1";
  } else {
    set req.http.X-Auth-Present = "0";
  }
  return(lookup);
}

# Everything else (uploads, admin, API, list, etc.) passes to Compute.
# Credentialed non-media responses are per-user and must never be cached.
return(pass);
