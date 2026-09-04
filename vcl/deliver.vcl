# ABOUTME: VCL deliver snippet for Divine Blossom VCL caching layer
# ABOUTME: Strips internal headers and adds cache debug info before sending to client

# Strip internal headers that should not reach clients.
#
# Surrogate-Key and Surrogate-Control are stripped only on client-facing
# delivery. The compute_origin backend shields through one POP, and this
# snippet also runs there when an edge POP fetches through it. Stripping on
# that hop stores the edge copy without its key, so a purge by key evicts the
# shield's copy and leaves every edge copy serving until its TTL expires (#279).
# fastly.ff.visits_this_service is 0 on the client-facing hop and at least 1
# on the shield hop. Fastly also removes Surrogate-Key from client responses on its
# own unless the request carries Fastly-Debug.
if (fastly.ff.visits_this_service == 0) {
  unset resp.http.Surrogate-Key;
  unset resp.http.Surrogate-Control;
}
unset resp.http.X-Divine-Edge-Request-Id;
unset resp.http.X-Divine-Internal-Diagnostic-Authorization-Present;
unset resp.http.X-Divine-Internal-Diagnostic-Source;
unset resp.http.X-Divine-Internal-Diagnostic-Storage-Cache;
unset resp.http.X-Divine-Internal-Diagnostic-FOS-Outcome;
unset resp.http.X-Divine-Internal-Diagnostic-FOS-Lookup-Ms;
unset resp.http.X-Divine-Internal-Diagnostic-GCS-Fetch-Ms;
unset resp.http.X-Divine-Internal-Diagnostic-Buffer-Ms;
unset resp.http.X-Divine-Internal-Diagnostic-Write-Back-Ms;
unset resp.http.X-Divine-Internal-Diagnostic-Probe-Id;

# Probe metadata must also cross the shield hop. Compare and strip it only on
# client-facing delivery so shielding does not erase the evidence before the
# edge POP can classify the response.
if (fastly.ff.visits_this_service == 0) {
  unset resp.http.X-Divine-Diagnostic-Role;
  unset resp.http.X-Divine-Diagnostic-Source;
  unset resp.http.X-Divine-Diagnostic-FOS-Outcome;
  unset resp.http.X-Divine-Diagnostic-Buffer;
  unset resp.http.X-Divine-Diagnostic-Write-Back;

  if (req.http.X-Divine-Diagnostic-Probe ~ "^coldfill-[a-z0-9-]{1,55}$" && resp.http.X-Divine-Probe-Id) {
    if (req.http.X-Divine-Diagnostic-Probe == resp.http.X-Divine-Probe-Id) {
      set resp.http.X-Divine-Diagnostic-Role = "leader";
    } else {
      set resp.http.X-Divine-Diagnostic-Role = "follower";
    }
    if (resp.http.X-Divine-Probe-Source ~ "^(gcs|fos|fallback)$") {
      set resp.http.X-Divine-Diagnostic-Source = resp.http.X-Divine-Probe-Source;
    }
    if (resp.http.X-Divine-Probe-FOS-Outcome ~ "^(hit|miss|disabled)$") {
      set resp.http.X-Divine-Diagnostic-FOS-Outcome = resp.http.X-Divine-Probe-FOS-Outcome;
    }
    if (resp.http.X-Divine-Probe-Buffer ~ "^(present|absent)$") {
      set resp.http.X-Divine-Diagnostic-Buffer = resp.http.X-Divine-Probe-Buffer;
    }
    if (resp.http.X-Divine-Probe-Write-Back ~ "^(present|absent)$") {
      set resp.http.X-Divine-Diagnostic-Write-Back = resp.http.X-Divine-Probe-Write-Back;
    }
  }
  unset resp.http.X-Divine-Probe-Id;
  unset resp.http.X-Divine-Probe-Source;
  unset resp.http.X-Divine-Probe-FOS-Outcome;
  unset resp.http.X-Divine-Probe-Buffer;
  unset resp.http.X-Divine-Probe-Write-Back;
}

# Strip GCS/S3 backend headers that leak through Compute
unset resp.http.x-guploader-uploadid;
unset resp.http.x-goog-generation;
unset resp.http.x-goog-metageneration;
unset resp.http.x-goog-stored-content-encoding;
unset resp.http.x-goog-stored-content-length;
unset resp.http.x-goog-hash;
unset resp.http.x-goog-storage-class;
unset resp.http.x-amz-meta-owner;
unset resp.http.x-amz-checksum-crc32c;
unset resp.http.expires;

# Add cache debug header
if (obj.hits > 0) {
  set resp.http.X-Cache = "HIT";
  set resp.http.X-Cache-Hits = obj.hits;
} else {
  set resp.http.X-Cache = "MISS";
}

# Ensure CORS headers are present (Compute sets them, but belt-and-suspenders)
if (!resp.http.Access-Control-Allow-Origin) {
  set resp.http.Access-Control-Allow-Origin = "*";
}
