# Verified B2 segment admission contract

`blossom_core::b2_cdn::SegmentedOriginal` defines the verification contract for
an original before the guarded delivery path admits it. Compute applies this
contract after native version verification and final policy checks. The outer
VCL enables native segmented caching on the anonymous B2 original route and
admits verified inner 206 responses separately from `original-v1`. The ordinary
20 MiB limit remains unchanged. These source changes do not activate a live
service or change runtime configuration.

The identity consists of the content hash, the verified destination version,
and the complete object size. A strong entity tag hashes a versioned canonical
tuple of those values. It exposes neither the destination version identifier
nor any owner identity. A changed version, hash, or size changes the tag.

Only a matching strong `If-Range` tag preserves a valid single range. Weak,
date, unknown, and mismatching validators select a full response. HEAD does not
select a range. Malformed and multiple ranges retain the existing full-read
selection policy.

Admission requires B2 provenance, the exact strong tag, explicit decimal
Content-Length, identity encoding, and no cookies or Transfer-Encoding. A full
200 must have the complete length, no Content-Range, and no selected range. A
206 must match the selected interval, complete object total, and exact interval
length. Error responses and GCS fallback cannot be admitted.

These are metadata checks after native version verification and the existing
fresh policy guards. They do not authenticate a caller, verify body bytes, or
establish quiescence. Duplicate/conflicting wire headers must be rejected by the
transport boundary before constructing the response view.

## Integration and remaining runtime acceptance

The CDN handler mints a private admission hint only after native B2 version and
framing verification. Final policy checks consume and remove it before delivery.
Verified native inner 206 responses receive `original-segment-v1`; ordinary
full responses retain their existing admission rules. The outer VCL preserves
native range requests, normalized object keys, generated shield selection,
browser no-store and authenticated maintenance purges. GCS fallback retains its
GCS label and cannot receive either B2 admission marker.

Loopback Compute tests cover 8/16/32 MiB bodies, conditional ranges, framing
rejection and delayed policy changes across real HTTP streams. Those tests do
not execute Fastly native caching, compile provider VCL, or prove live eviction.

The live matrix must verify complete bytes at 8, 16 and 32 MiB, disjoint and
conditional ranges, version changes, all-range purge, and denial of future
requests after pre-header and mid-body delayed fills. A successful ordinary
chunked-response fixture does not establish segmented-cache acceptance.

Fastly's [segmented caching guide](https://www.fastly.com/documentation/guides/full-site-delivery/caching/segmented-caching/)
requires Content-Length on origin range responses, rejects chunked origin
framing for this feature, and requires authenticated URL purges. It enables the
feature before lookup, without knowing object size. No size configuration knob
is introduced by this contract.
