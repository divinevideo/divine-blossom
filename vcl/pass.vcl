# ABOUTME: VCL pass snippet for Divine Blossom VCL caching layer
# ABOUTME: Gives upload requests the origin's real time budget instead of the delivery timeout
#
# Applied via the Fastly API/CLI as a VCL snippet in the vcl_pass subroutine.
#
# The compute_origin backend sets first_byte_timeout to 15s, which is the right
# budget for media delivery: a viewer is better served by a fast failure and a
# player retry than by a connection held open. It is the wrong budget for
# uploads. Compute proxies these to cloud_run_upload, whose own backend
# definition allows 120s, so the 15s cap on the outer service silently overrode
# an allowance the inner service had already been given.
#
# Measured against production on 2026-08-18, 15 sequential 1 MB uploads:
#   first request (Cloud Run cold start) : 503 at 15.61s -- the 15s ceiling
#   warm uploads                         : p50 9.18s, p90 12.38s, max 12.92s
#
# So a warm upload already runs within 2.6s of the ceiling at p90, and any
# request that lands on a cold instance exceeds it outright. Under load, where
# scale-up mints new instances, ordinary variance turns into user-visible 503s.
#
# This raises the ceiling for the upload routes only -- PUT /upload,
# POST /upload/init, POST /upload/{id}/complete, and PUT /mirror -- matching
# what cloud_run_upload already permits. Delivery keeps the 15s budget.
#
# Raising the timeout treats the symptom. The cause is Cloud Run cold starts,
# fixed by giving the upload service a non-zero min-instances so no request pays
# container startup.
# TODO(#227): set min-instances on the upload service and re-measure; this
# snippet should then only be covering ordinary variance, not cold starts.

if (req.url ~ "^/(upload|mirror)(/|$)") {
  set bereq.first_byte_timeout = 120s;
}
