# ABOUTME: VCL hash snippet for Divine Blossom VCL caching layer
# ABOUTME: Adds an auth-presence bit to the cache key so credentialed and anonymous responses never share an entry
#
# Applied via the Fastly API/CLI as a VCL snippet in the vcl_hash subroutine.
#
# Media responses do not vary by WHICH user is authenticated -- the bytes for a
# given hash are the same for every caller. They vary only by whether the request
# carried credentials at all, because restricted content is served to a
# credentialed caller and refused to an anonymous one.
#
# So the cache key carries one bit, not the credential. Two entries per object at
# most, both of which can go hot. Varying on the Authorization VALUE instead
# would produce one cache entry per user and defeat caching entirely.
#
# This is the load-bearing safety property for caching credentialed media: an
# anonymous request cannot be served an object that a credentialed request
# populated, even if the origin failed to mark that object private. The
# private/no-store check in vcl_fetch is the second, independent layer.
#
# X-Auth-Present is set in the vcl_recv snippet and is always "0" or "1" for
# requests that reach lookup, so the key can never be poisoned by a
# client-supplied value.

set req.hash += req.http.X-Auth-Present;
