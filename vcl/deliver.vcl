# ABOUTME: VCL deliver snippet for Divine Blossom VCL caching layer
# ABOUTME: Strips internal headers and adds cache debug info before sending to client

# Strip internal headers that should not reach clients
unset resp.http.Surrogate-Key;
unset resp.http.Surrogate-Control;

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
