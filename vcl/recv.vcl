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

# Don't cache requests with Authorization header (restricted content needs auth check)
if (req.http.Authorization) {
  return(pass);
}

# Cache hash-based content paths: /{64-char-hex}[.ext], /{hash}.hls,
# /{hash}/hls/*, /{hash}.vtt, /{hash}/{quality}. Everything else (uploads,
# admin, API, list, etc.) passes to Compute.
if (req.url !~ "^/[0-9a-fA-F]{64}") {
  return(pass);
}

# Deliberately fall through for cacheable hash paths. Fastly's generated
# vcl_recv code selects the configured shield after this snippet, then performs
# the default lookup. Returning lookup here would bypass that shield selection.
