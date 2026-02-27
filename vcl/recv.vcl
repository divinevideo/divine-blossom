# ABOUTME: VCL recv snippet for Divine Blossom VCL caching layer
# ABOUTME: Routes cacheable GET/HEAD requests through cache, passes everything else to Compute

# Pass original host to Compute so it can generate correct URLs
set req.http.X-Original-Host = req.http.Host;

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

# Cache hash-based content paths: /{64-char-hex}[.ext], /{hash}.hls, /{hash}/hls/*, /{hash}.vtt, /{hash}/{quality}
# Match paths starting with / followed by 64 hex chars
if (req.url ~ "^/[0-9a-fA-F]{64}") {
  return(lookup);
}

# Everything else (uploads, admin, API, list, etc.) passes to Compute
return(pass);
