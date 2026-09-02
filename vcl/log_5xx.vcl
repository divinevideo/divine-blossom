# ABOUTME: VCL log snippet for Divine Blossom VCL caching layer
# ABOUTME: Records client-facing 5xx that never entered vcl_error
#
# Applied as a Fastly vcl_log snippet. Keep automatic log placement disabled
# for vcl-error-diagnostics; this file emits only selected failures.
#
# vcl_error already logs Fastly-generated 5xx. Skip only states that mean
# vcl_error ran (bare ERROR plus CLUSTER/WAIT/REFRESH suffixes). Do not use an
# unanchored ERROR match: ERROR-LOSTHDR, ERROR-DISCONNECT, and BG-ERROR-* never
# entered vcl_error and are part of the #271 population.
#
# Shield hops run the full VCL flow. Log only the client-facing edge hop
# (fastly.ff.visits_this_service == 0) so counts line up with status_503.
#
# A mid-stream failure after vcl_deliver has started still cannot change the
# status already sent; those stay 200 and will not appear here.

if (fastly.ff.visits_this_service == 0
    && resp.status >= 500
    && resp.status < 600
    && fastly_info.state !~ "^ERROR(-(CLUSTER|WAIT|REFRESH))*$") {
  if (req.backend.is_origin) {
    set req.http.X-Divine-Backend-Hop = "origin";
  } else {
    set req.http.X-Divine-Backend-Hop = "shield";
  }
  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.vcl_5xx.v1","}
      {""phase":"log","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(substr(regsuball(req.http.X-Divine-Edge-Request-Id, "[^A-Za-z0-9_-]", ""), 0, 64)) {"","}
      {""service_id":""} json.escape(req.service_id) {"","}
      {""method":""} json.escape(req.method) {"","}
      {""url":""} json.escape(substr(req.url, 0, 256)) {"","}
      {""status":"} resp.status {","}
      {""reason":""} json.escape(resp.response) {"","}
      {""pop":""} json.escape(server.datacenter) {"","}
      {""backend":""} json.escape(req.backend.name) {"","}
      {""backend_hop":""} json.escape(req.http.X-Divine-Backend-Hop) {"","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""ff_visits":"} fastly.ff.visits_this_service {","}
      {""restart_count":"} req.restarts {","}
      {""elapsed_ms":"} time.elapsed.msec {","}
      {""body_bytes_written":"} resp.body_bytes_written
    {"}"};
  unset req.http.X-Divine-Backend-Hop;
}
