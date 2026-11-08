# ABOUTME: VCL miss snippet for Divine Blossom VCL caching layer
# ABOUTME: Preserves native B2 segments and fills complete canonical objects
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
# Canonical fills keep their existing full-object behavior. B2 native segmented
# fills carry the range selected by Fastly; stripping it would defeat native
# segmentation and could turn a bounded range into a large full-object fetch.
# The provider integration tests must verify actual cold and warm client ranges.

# Keep native segmented inner ranges intact. Canonical/non-segmented fills
# retain the existing full-object behavior.
if (req.http.Host !~ "^media-b2(-cdn)?[.]divine[.]video$") {
  unset bereq.http.Range;
}


# A B2 HEAD miss uses a body-bearing GET fill, never a headers-only entry.
# Fastly selects native segments and suppresses the client body on HEAD.
if (req.http.Host ~ "^media-b2(-cdn)?[.]divine[.]video$") {
  set bereq.method = "GET";
}
