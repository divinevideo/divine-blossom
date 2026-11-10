# Verified B2 segment admission contract

`blossom_core::b2_cdn::SegmentedOriginal` defines the verification contract for
an original before a future segmented delivery path admits it. It does not
enable Fastly segmented caching, change `original-v1`, remove the ordinary
20 MiB limit, or change any runtime configuration.

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

## Remaining integration and runtime acceptance

Wire the contract into the guarded Compute delivery path and native Fastly
segmented caching together. Preserve authenticated URL purges for every segment,
neutral object keys, shield selection, browser no-store, explicit GCS fallback
labels, and final policy rechecks. Do not treat the contract tests as provider
VCL execution or evidence that the live feature is enabled.

The live matrix must verify complete bytes at 8, 16 and 32 MiB, disjoint and
conditional ranges, version changes, all-range purge, and denial of future
requests after pre-header and mid-body delayed fills. A successful ordinary
chunked-response fixture does not establish segmented-cache acceptance.

Fastly's [segmented caching guide](https://www.fastly.com/documentation/guides/full-site-delivery/caching/segmented-caching/)
requires Content-Length on origin range responses, rejects chunked origin
framing for this feature, and requires authenticated URL purges. It enables the
feature before lookup, without knowing object size. No size configuration knob
is introduced by this contract.
