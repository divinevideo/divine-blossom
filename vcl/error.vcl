# ABOUTME: VCL error snippet for Divine Blossom VCL caching layer
# ABOUTME: Generates synthetic error responses when Compute backend is unreachable

if (obj.status == 503) {
  set obj.http.Content-Type = "application/json";
  set obj.http.Access-Control-Allow-Methods = "GET, HEAD, PUT, POST, DELETE, OPTIONS";
  set obj.http.Access-Control-Allow-Headers = "Authorization, Content-Type, Range, X-Requested-With, X-Sha256";
  set obj.http.Access-Control-Max-Age = "86400";
  if ((req.method == "GET" || req.method == "HEAD" || req.method == "OPTIONS") &&
      req.url ~ "^/[0-9a-fA-F]{64}($|[./])") {
    set obj.http.Access-Control-Allow-Origin = "*";
  } else if (req.http.Origin == "https://app.divine.video" ||
      req.http.Origin ~ "^https://[^.]+\\.openvine-app\\.pages\\.dev$") {
    set obj.http.Access-Control-Allow-Origin = req.http.Origin;
    set obj.http.Vary = "Origin";
  }
  synthetic {"{"error":"Service temporarily unavailable","status":503}"};
  return(deliver);
}
