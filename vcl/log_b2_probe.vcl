# ABOUTME: Opt-in synthetic B2 outer delivery evidence, never a view/QoE record.
# ABOUTME: Final cache state is authoritative; cached response headers are not.
# Existing endpoint must have placement=none. No URL, hash, load ID or identity.
# A probe is a public opt-in marker, not authentication or a sampling guarantee.

declare local var.backend_fetch STRING;

if (fastly.ff.visits_this_service == 0
    && req.http.Host ~ "^media-b2(-cdn)?[.]divine[.]video$"
    && (req.method == "GET" || req.method == "HEAD")
    && !req.http.Authorization && !req.http.Cookie
    && req.url ~ "^/[0-9a-f]{64}([.]mp4)?([?].*)?$"
    && req.http.X-Divine-B2-Probe ~ "^b2outer-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    && req.http.X-Divine-Edge-Request-Id ~ "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$") {
  # Boolean for this outer request's backend path, NOT a Compute/provider count.
  # MISS/PASS may target a shield. WAIT/REFRESH/STALE/SYNTH/errors/restarts
  # remain unknown. A req header mutated in miss/pass cannot carry this fact
  # back from a clustered fetch node to the delivery node.
  set var.backend_fetch = "null";
  if (req.restarts == 0) {
    if (fastly_info.state ~ "^HIT(-CLUSTER)?$") {
      set var.backend_fetch = "0";
    } else if (fastly_info.state ~ "^(MISS|PASS)(-CLUSTER)?$") {
      set var.backend_fetch = "1";
    }
  }
  log {"syslog "} req.service_id {" vcl-error-diagnostics :: "}
    {"{"}
      {""schema":"divine.blossom.b2_outer_probe.v1","}
      {""phase":"log","}
      {""timestamp":"} time.start.sec {","}
      {""request_id":""} json.escape(req.http.X-Divine-Edge-Request-Id) {"","}
      {""probe_id":""} json.escape(req.http.X-Divine-B2-Probe) {"","}
      {""method":""} json.escape(req.method) {"","}
      {""status":"} resp.status {","}
      {""cache_state":""} json.escape(fastly_info.state) {"","}
      {""backend_fetch":"} var.backend_fetch {","}
      {""restart_count":"} req.restarts {","}
      {""ff_visits":"} fastly.ff.visits_this_service {","}
      {""elapsed_ms":"} time.elapsed.msec {","}
      {""body_bytes_written":"} resp.body_bytes_written
    {"}"};
}
