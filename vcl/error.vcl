# ABOUTME: VCL error snippet for Divine Blossom VCL caching layer
# ABOUTME: Generates synthetic error responses when Compute backend is unreachable

# Log every Fastly-generated 5xx so the record set matches the runbook's
# outer-5xx triage language. The client-facing synthetic JSON response below stays
# scoped to 503; other 5xx statuses keep Fastly's default error delivery.
if (obj.status >= 500 && obj.status < 600) {
  # Closed route class matching blossom-core request_diagnostics::route_category.
  # url is path plus query, capped and JSON-escaped. Do not log Authorization.
  set req.http.X-Divine-Route-Class = "other";
  if (req.url.path == "/") {
    set req.http.X-Divine-Route-Class = "landing";
  } else if (req.url.path == "/version") {
    set req.http.X-Divine-Route-Class = "version";
  } else if (req.url.path ~ "\.hls$") {
    set req.http.X-Divine-Route-Class = "hls_master";
  } else if (req.url.path ~ "/hls/") {
    set req.http.X-Divine-Route-Class = "hls_content";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}/[Vv][Tt][Tt]$") {
    set req.http.X-Divine-Route-Class = "transcript";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}\.[Vv][Tt][Tt]$") {
    set req.http.X-Divine-Route-Class = "transcript";
  } else if (req.url.path ~ "^/v1/subtitles/") {
    set req.http.X-Divine-Route-Class = "subtitle_api";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}/provenance$") {
    set req.http.X-Divine-Route-Class = "provenance";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}\.audio\.m4a$") {
    set req.http.X-Divine-Route-Class = "audio";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}/(720p|480p)(\.mp4)?$") {
    set req.http.X-Divine-Route-Class = "quality_variant";
  } else if (req.url.path ~ "^/[0-9a-fA-F]{64}(\.[A-Za-z0-9]+)?$") {
    set req.http.X-Divine-Route-Class = "blob";
  } else if (req.url.path == "/upload" || req.url.path ~ "^/upload/") {
    set req.http.X-Divine-Route-Class = "upload";
  } else if (req.url.path == "/transcribe") {
    set req.http.X-Divine-Route-Class = "transcribe";
  } else if (req.url.path == "/vanish") {
    set req.http.X-Divine-Route-Class = "vanish";
  } else if (req.url.path == "/report") {
    set req.http.X-Divine-Route-Class = "report";
  } else if (req.url.path == "/mirror") {
    set req.http.X-Divine-Route-Class = "mirror";
  } else if (req.url.path ~ "^/list/") {
    set req.http.X-Divine-Route-Class = "list";
  } else if (req.url.path == "/admin" || req.url.path ~ "^/admin/") {
    set req.http.X-Divine-Route-Class = "admin";
  }

  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.vcl_error.v1","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(substr(regsuball(req.http.X-Divine-Edge-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 64)) {"","}
      {""service_id":""} json.escape(req.service_id) {"","}
      {""method":""} json.escape(req.method) {"","}
      {""route":""} json.escape(req.http.X-Divine-Route-Class) {"","}
      {""url":""} json.escape(substr(req.url, 0, 256)) {"","}
      {""status":"} obj.status {","}
      {""error_reason":""} json.escape(obj.response) {"","}
      {""pop":""} json.escape(server.datacenter) {"","}
      {""backend":""} json.escape(req.backend.name) {"","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""restart_count":"} req.restarts {","}
      {""elapsed_ms":"} time.elapsed.msec
    {"}"};
  unset req.http.X-Divine-Route-Class;
}

if (obj.status == 503) {
  set obj.http.Content-Type = "application/json";
  set obj.http.Access-Control-Allow-Origin = "*";
  synthetic {"{"error":"Service temporarily unavailable","status":503}"};
  return(deliver);
}
