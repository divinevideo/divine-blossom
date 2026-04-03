# ABOUTME: VCL error snippet for Divine Blossom VCL caching layer
# ABOUTME: Generates synthetic error responses when Compute backend is unreachable

if (obj.status == 503) {
  set obj.http.Content-Type = "application/json";
  set obj.http.Access-Control-Allow-Methods = "GET, HEAD, PUT, POST, DELETE, OPTIONS";
  set obj.http.Access-Control-Allow-Headers = "Authorization, Content-Type, Range, X-Requested-With, X-Sha256";
  set obj.http.Access-Control-Max-Age = "86400";
  set obj.http.Access-Control-Allow-Origin = "*";
  synthetic {"{"error":"Service temporarily unavailable","status":503}"};
  return(deliver);
}
