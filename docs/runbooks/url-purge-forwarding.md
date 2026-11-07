# URL purge forwarding

Fastly's [standard VCL boilerplate](https://www.fastly.com/documentation/guides/full-site-delivery/fastly-vcl/about-fastly-vcl/)
exempts its internal `FASTLYPURGE` method from the non-GET/HEAD pass guard.
The recv snippet follows that path through the existing host/path checks and
original-key normalization. It falls through for generated shield/cache routing;
there is no early `return(lookup)`.

Before forwarding, the snippet unconditionally sets
`Fastly-Purge-Requires-Auth` to `1` for that method, overriding any caller value.
Fastly performs provider-managed purge-token validation as described in its
[URL purge guide](https://www.fastly.com/documentation/guides/full-site-delivery/purging/purging-a-url/).
The method or a caller-supplied header does not grant purge authority. Existing
Authorization, cookie and host/path restrictions are preserved; other methods
continue to pass to Compute.

The Python checks evaluate source predicates and the shared normalization regex,
including caller header0, method selection and bare/MP4/query aliases. They are
source-contract checks, not runtime VCL execution or proof of authentication,
shield forwarding or eviction. Source changes neither activate VCL nor reopen
admission. Separate private operator guards may still reject maintenance purges;
their immutable plans and expiry windows are outside this tracked source.

After reviewed release, the provider owner must verify authenticated URL purges
reach the same cache key at edge and shield, cause the expected controlled refill,
and reject unauthenticated purges. Cache maintenance must remain possible after
read admission closes. API acceptance alone is not end-to-end eviction or
in-flight-fill privacy proof; no such live test is performed by this change.
