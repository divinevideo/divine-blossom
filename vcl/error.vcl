# ABOUTME: VCL error snippet for Divine Blossom VCL caching layer
# ABOUTME: Generates synthetic error responses when Compute backend is unreachable

if (obj.status == 503) {
  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.vcl_error.v1","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(substr(regsuball(req.http.X-Divine-Edge-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 16)) {"","}
      {""service_id":""} json.escape(req.service_id) {"","}
      {""status":"} obj.status {","}
      {""error_reason":""} json.escape(obj.response) {"","}
      {""pop":""} json.escape(server.datacenter) {"","}
      {""backend":""} json.escape(req.backend.name) {"","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""restart_count":"} req.restarts {","}
      {""elapsed_ms":"} time.elapsed.msec
    {"}"};

  set obj.http.Content-Type = "application/json";
  set obj.http.Access-Control-Allow-Origin = "*";
  synthetic {"{"error":"Service temporarily unavailable","status":503}"};
  return(deliver);
}
