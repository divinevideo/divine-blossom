# ABOUTME: Verified capability and limit notes for CDN and object storage vendors relevant to media delivery.
# ABOUTME: Vendor facts and their technical implications for this codebase; no traffic figures or commercial analysis.

# CDN and Object Storage Vendor Notes

**Verified:** 2026-08-06 against vendor primary sources (linked at the end).

Reference notes gathered while evaluating delivery-origin options for `media.divine.video`. This
file records **vendor-published facts and their technical consequences for this repo**. Traffic
figures, cost modelling, and commercial analysis live outside this repository.

Claims are tagged **[V]** verified from a vendor primary source, **[I]** inferred, **[U]** unknown
without a vendor answer. Re-verify before relying on any of it — vendor pricing and limits change.

---

## Fastly

### Delivery pricing [V]

| Item | Rate |
|---|---|
| Bandwidth, North America / Europe | $0.12/GB (100 GB–10 TB), $0.08/GB (next 10 TB), "contact us" beyond |
| Bandwidth, Asia / Australia / Mexico / South America | $0.19 → $0.12/GB |
| Bandwidth, Africa / India / South Korea | $0.28 → $0.24/GB |
| Requests | $0.010 / 10k; $0.0095 / 10k beyond 100M/mo; first 1M free |
| Compute requests | $0.50 → $0.20 per 1M; 10M free |
| Compute vCPU-ms | $0.05 → $0.02 per 1M; 100M free |

The published curve ends around 20 TB/month and hands off to negotiation.

### Billing mechanics [V]

From Fastly's delivery billing documentation:

> "egress traffic from our POPs, including traffic served to end users and, if shielding is
> enabled, traffic served from the shield POP to other POPs"

> "we charge for bandwidth and requests for content delivered to clients from the CDN and for
> bandwidth for traffic sent from the CDN to our customers' origins"

Consequences:
- **Shield→edge inter-POP transfer is billable.** Not conditional.
- Fastly bills the CDN→origin direction (the request leg). The origin→CDN response is Fastly
  ingress and is not billed by Fastly — but it is billed by the origin provider.
- Total billed Fastly bandwidth with shielding on ≈ `delivered + (1 − byte_offload) × delivered`.
  **Enabling shielding while byte offload is low multiplies the bandwidth bill.** Raise offload
  first.

### Object Storage [V]

| Property | Value |
|---|---|
| Storage | $0.020/GB-mo (<50 TB), $0.018 (50–500 TB), $0.017 (>500 TB) |
| Class A ops (writes) | $0.0025 per 1,000 |
| Class B ops (reads) | $0.0004 per 1,000 |
| Free tier | 5 GB, 1k Class A, 10k Class B per month |
| Regions | 9, all single-region: `us-west-1`, `us-central-1`, `us-east-1`, `uk-east-1`, `eu-west-1`, `eu-central`, `eu-south-1`, `jp-central-1`, `au-east-1` |
| Max object | 5 TB |
| Max single upload | 5 GB |
| Multipart | 5 MB min part, 10,000 parts max |
| Object key | 1,024 bytes |
| **Object metadata** | **1,000 bytes** |
| Upload timeout | 120 s, else `408` |
| Buckets | 100 per region |
| **Public S3 endpoint** | **~150 Mbps and 100 req/s per bucket** |

Complete supported operation set:
`CreateBucket`, `DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `ListBuckets`, `PutObject`,
`CopyObject`, `DeleteObject`, `DeleteObjects`, `ListObjectsV1`, `ListObjectsV2`,
`CreateMultipartUpload`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`,
`ListParts`, `UploadPart`, `UploadPartCopy`, `GetObject`, `HeadObject`.

**Not available** (absent from that list): versioning, lifecycle rules, object lock / retention,
bucket policies, ACLs, server-side-encryption configuration, tagging, inventory, batch operations,
replication, event notifications.

Also documented as unsupported: virtual-hosted-style addressing (path-style only, which breaks the
default in several AWS SDKs), chunked uploads, and public/unauthenticated access. Bucket names may
not begin with `fst` or `fastly`.

**No published durability figure and no Object Storage availability SLA found.** Fastly publishes a
Network Services availability SLA (1%–50% credits) but it does not enumerate Object Storage, and it
pays nothing to unpaid or month-to-month accounts.

### "Zero egress" — exact scope [V]

Fastly's launch post (2024-12-12):

> "we're talking zero-egress access to Object Storage from both our Compute and Content Delivery services"

Scoped to *access from* Compute and Deliver. It makes no claim about what those services then
charge. **Not covered:** CDN→viewer bandwidth, shield→edge bandwidth, storage at rest, Class A/B
operations, Compute execution. Reads from Object Storage are still billed as Class B operations —
"zero egress" is not zero cost.

### Streaming classification [V]

From Fastly's Packaged Offering Entitlements:

> "Network Services packages are intended for web pages (including HTML) and web APIs, and are
> not intended for streaming services."

> "No more than 10% of traffic may originate in the African, Indian, or South Korean billing regions."

From Fastly's Streaming Delivery product documentation:

> "must be configured in a separate Fastly account, for exclusive use with streaming media content,
> in order to use separate billing plans and invoices"

> covers "audio and video segments, and associated content intended to enable or to be consumed
> with them, such as manifests and files used for captions or subtitles"

> "all of the features available to full site delivery services are available to streaming delivery services"

**Streaming Delivery is the same platform with separate billing, not a separate platform.**
Shielding is documented as not enabled by default there.

**[I] This service serves `.m3u8` manifests (`application/vnd.apple.mpegurl`), `.ts` segments
(`video/mp2t`), progressive MP4, and WebVTT captions** — matching Fastly's enumerated definition of
streaming content. **[U] Whether Compute is available on a Streaming Delivery account is not
documented and is a blocking question**, since access control, moderation, and Blossom protocol
handling all run in Compute.

### On-Demand Migration [V]

Pull-through migration: on a miss, Fastly reads the `fastly-object-storage-source-url` header,
fetches from that URL, serves it, and asynchronously copies it into the bucket. **Objects larger
than 250 MB are served but never copied.** The source must return `200` or `206`.

**[I] Takedown hazard:** deleting an object from the bucket while its source URL still resolves
means the next request silently repopulates it. Any deletion path must disable or re-point the
source URL before deleting the replica.

### Service chaining [V]

Maximum 20 hops and 6 unique services per chain. Cross-account chaining is technically possible.
**[U]** Billing across a chain is undocumented — Fastly states only that services are "billed based
on Fastly egress" and that chaining strategies "may result in different billing implications."

---

## Cloudflare R2 [V]

| Property | Value |
|---|---|
| Standard storage | $0.015/GB-mo |
| Infrequent Access | $0.010/GB-mo + $0.01/GB retrieval, 30-day minimum |
| Class A | $4.50 / million |
| Class B | $0.36 / million |
| **Egress** | **$0 via Workers API, S3 API, or r2.dev — i.e. $0 to any consumer, not only Cloudflare** |
| Durability | designed for 99.999999999% (11 nines) |
| Availability SLA | 99.9% |
| Max object | 5 TiB; single-part 5 GiB; 10,000 parts |
| Object metadata | 8,192 bytes |
| Buckets per account | 1,000,000 |

Cloudflare removed ToS §2.8 in 2023 and moved the restriction into its Service-Specific Terms,
which reserve the right to limit CDN use "to serve video or a disproportionate percentage of
pictures, audio files, or other large files" **without** the relevant paid services — with video
hosted on R2, Stream, or Images explicitly permitted, and an Enterprise carve-out.

---

## Backblaze B2 [V]

| Property | Value |
|---|---|
| Storage | $6.95/TB-mo = $0.00695/GB-mo |
| Free egress | 3× average monthly storage, then $0.01/GB |
| Class A/B/C API calls | free |
| Partner-CDN egress | claimed "unlimited free egress when downloading to or through partner CDNs … including Fastly, Cloudflare, bunny.net, CacheFly" |

**[U]** The partner-CDN mechanism is not documented in detail: whether it applies to an edge-compute
S3 fetch as opposed to a direct CDN pull-zone origin fetch, whether enrolment is required, and
whether volume caps apply. Confirm in writing before relying on it.

---

## bunny.net [V]

| Network | Rate |
|---|---|
| Volume (10 PoPs) | $0.005/GB first 500 TB; $0.004 500 TB–1 PB; $0.002 1–2 PB; **2 PB+ contact sales** |
| Standard (119 PoPs) | $0.010/GB EU+NA; $0.030 Asia/Oceania; $0.045 South America; $0.060 MEA |
| Requests | **$0** |

Volume network PoPs: Frankfurt, Paris, Chicago, Dallas, Los Angeles, Miami, São Paulo, Hong Kong,
Singapore, Tokyo. **No Australia, India, Middle East, Africa, UK, or Korea PoP** — those regions are
served cross-region on the Volume tier, or via the 119-PoP Standard network at higher rates.

Network is stated at 119 PoPs and 250+ Tbps. A contractual 99.99% SLA was introduced in January
2026; the ToS separately states "at least a 99.995% monthly uptime" alongside "we make no warranty
or assurance that the service will run uninterrupted," and reserves the right to change prices "at
bunny.net's sole discretion."

### Edge Scripting [V]

bunny has a real edge compute platform, not just header rewriting. Deno/V8 runtime, native
TypeScript, and **Middleware Apps** that "inject custom logic directly into the existing CDN
processing pipeline", modifying both origin requests and responses. External `fetch` is supported.

| Item | Rate |
|---|---|
| Requests | $0.20 per million |
| CPU time | $0.02 per 1,000 seconds |

Note this **reintroduces a per-request fee** that plain pull-zone delivery does not have.

**[V] No persistent KV store yet.** A "globally distributed database" and a storage library are on
the published roadmap, not shipped. Middleware Apps are documented as supporting request/response
modification today, with "caching, revalidation, and other core CDN behaviors" planned.

**[I] Implication for this codebase.** The blocker is state, not compute. A moderation gate needs a
fast local lookup keyed on content hash; without KV every check becomes an external fetch on the
request path. Fastly Compute has Config Store, KV Store, and Secret Store today. Separately, the
existing logic is Rust compiled to Wasm, so moving it would be a TypeScript rewrite rather than a
port.

None of this blocks a second-CDN delivery design, because the access decision is made once when the
URL is issued rather than per-request at the edge.

---

## Google Cloud Storage

Egress, Premium tier **[V, corroborated across independent sources]**: $0.12/GB first 1 TB,
$0.11/GB 1–10 TB, $0.08/GB above 10 TB. The published curve ends at 10 TB.

Storage and operations **[I, medium confidence — Google's pricing page did not render for automated
fetch; verify in console]**: Standard regional ≈ $0.020/GB-mo; Class A ≈ $0.005/1,000; Class B ≈
$0.0004/1,000.

---

## Implications for this codebase

**1. A Fastly Object Storage bucket cannot serve a second CDN. [V→I]**
The ~150 Mbps / 100 req/s public-endpoint cap applies to everything except Fastly's own network
(*"Data accessed from within Fastly's network is not subject to these limits"*). Choosing it as the
delivery replica forecloses multi-CDN delivery, external reconciliation at throughput, and any
second delivery endpoint. R2 and B2 have no equivalent restriction.

**2. Legal hold cannot live on Fastly Object Storage. [V]**
No object lock, versioning, or retention policies. Hold semantics belong on the authoritative store
(GCS bucket lock). Treat delivery replicas as disposable and unprivileged — which also means their
durability guarantees matter less than an authoritative store's.

**3. Object metadata is capped at 1,000 bytes on Fastly Object Storage. [V]**
A SHA-256 hex digest is 64 bytes, so content addressing fits comfortably. C2PA manifest references,
moderation verdicts, provenance, or rendition maps carried in object metadata will not.

**4. Reconcile on a stored content hash, not on ETag. [I]**
Multipart-upload ETags are not content hashes and differ between providers. Since blob keys here are
the SHA-256 itself, originals can be verified by set-difference on key listings alone; derivative
paths (`{hash}/hls/…`, `{hash}.vtt`) are not self-verifying and need a stored checksum.

**5. Blossom does not require single-origin delivery. [V]**
BUD-02 defines the blob descriptor `url` as "A publicly accessible URL to the BUD-01 `GET /<sha256>`
endpoint with a file extension" — no same-host requirement. All outbound URLs already funnel through
`to_descriptor(&base_url)` in `blossom-core/src/types.rs`, so the delivery host is a one-function
change. **[I]** The real constraint is the installed base: published kind-10063 server lists name
`media.divine.video`, so that host must keep answering both reads and writes indefinitely.

**6. There is no streaming miss configured. [V]**
No `beresp.do_stream` in `vcl/`, and nothing streaming response bodies in `src/`. Every cache miss
buffers the complete object before the client receives a byte. Fastly's streaming guidance
recommends enabling `do_stream` for video and audio objects specifically. This interacts with any
change that strips `Range` on cache fill: the origin fetch becomes the whole object, so without
streaming miss the client waits for all of it.

**7. Fastly's streaming guidance conflicts with a uniform long edge TTL. [V→I]**
Fastly recommends shorter edge TTLs for segments (under 3600 s, to keep them served from memory)
with longer TTLs on the shield. `vcl/fetch.vcl` sets a uniform 365-day TTL. Defensible for immutable
content-addressed blobs, but it is the opposite of the vendor guidance and worth measuring rather
than assuming.

---

## Open technical questions for vendors

- Fastly: is Compute available on a Streaming Delivery account?
- Fastly: can a streaming account serve Blossom `/upload`, `/list`, and `/mirror` on the same
  hostname as media, or must those split off?
- Fastly: if Object Storage buckets are in one account and Compute in another, does zero-egress
  treatment still apply?
- Fastly: can the ~150 Mbps / 100 req/s per-bucket public endpoint limit be raised, and to what
  ceiling?
- Fastly: contractual durability target and availability SLA for Object Storage.
- Fastly: is the 1,000-byte object metadata limit raisable?
- Fastly: does On-Demand Migration have any mechanism preventing a deleted object being repopulated
  from a still-live source URL?
- Backblaze: does partner-CDN free egress apply to an edge-compute S3 fetch, or only a direct pull
  zone?
- bunny: can a pull zone originate from R2 or B2 with private-bucket authentication?
- bunny: purge API latency and rate limits.

---

## Sources

Fastly: [pricing](https://www.fastly.com/pricing/) ·
[delivery bill](https://docs.fastly.com/products/how-we-calculate-your-delivery-bill) ·
[Object Storage product](https://docs.fastly.com/products/object-storage) ·
[working with Object Storage](https://www.fastly.com/documentation/guides/platform/object-storage/working-with-object-storage/) ·
[about Object Storage](https://www.fastly.com/documentation/guides/platform/object-storage/about-object-storage/) ·
[on-demand migration](https://www.fastly.com/documentation/guides/platform/object-storage/on-demand-migration-for-object-storage/) ·
[zero-egress blog](https://www.fastly.com/blog/build-store-scale-fastly-object-storage-with-zero-egress-costs-here) ·
[package entitlements](https://www.fastly.com/package-entitlements) ·
[Streaming Delivery](https://docs.fastly.com/products/fastlys-streaming-delivery) ·
[Network Services SLA](https://docs.fastly.com/products/network-services-service-availability-sla) ·
[streaming config guidelines](https://www.fastly.com/documentation/guides/full-site-delivery/video/streaming-configuration-guidelines/) ·
[service chaining](https://www.fastly.com/documentation/guides/getting-started/services/service-chaining/)

Cloudflare: [R2 pricing](https://developers.cloudflare.com/r2/pricing/) ·
[R2 limits](https://developers.cloudflare.com/r2/platform/limits/) ·
[R2 durability](https://developers.cloudflare.com/r2/reference/durability/) ·
[service-specific terms](https://www.cloudflare.com/service-specific-terms-application-services/) ·
[goodbye §2.8](https://blog.cloudflare.com/updated-tos)

Backblaze: [B2 pricing](https://www.backblaze.com/cloud-storage/pricing) ·
[CDN partners](https://www.backblaze.com/cloud-storage/solutions/cdn)

Other: [bunny.net pricing](https://bunny.net/pricing/) ·
[bunny.net network](https://bunny.net/network/) ·
[GCS pricing](https://cloud.google.com/storage/pricing) ·
[Blossom BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md)
