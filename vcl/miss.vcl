# ABOUTME: VCL miss snippet for Divine Blossom VCL caching layer
# ABOUTME: Fetches full objects on cache fill so Fastly can synthesize 206s from cache
#
# Applied via the Fastly API/CLI as a VCL snippet in the vcl_miss subroutine.
#
# Without this, a player's Range header is forwarded to the Compute origin and on
# to GCS, the origin returns 206 Partial Content, and Fastly stores nothing --
# every seek and every replay is a fresh origin fetch. That is the difference
# between a 77.2% request hit ratio and ~25% byte offload (294.5 GB/day
# delivered vs 218.8 GB/day fetched from origin).
#
# vcl_miss only runs for requests that recv sent to lookup, i.e. GET/HEAD on
# /{64-hex}... without an Authorization header. Restricted and authenticated
# traffic takes the pass path and never reaches here.
#
# Safe to strip unconditionally: the largest object in a 1/256 sample of the
# bucket is 27.9 MB (p50 0.17 MB, p99 3.4 MB), so a full fetch on a one-byte
# probe is cheap and bounded.
#
# Expected behavior change: the FIRST client to request a cold object with a
# Range header receives a full 200 rather than a 206. Players handle this
# correctly. Subsequent range requests are synthesized from cache as 206s.

unset bereq.http.Range;

