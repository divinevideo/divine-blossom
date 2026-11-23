# Blossom on Bunny: runtime feasibility spike

An isolated TypeScript/Deno implementation of the first Blossom read/write slice. This is a
feasibility experiment for replacing the Fastly edge service, including its request-time logic and
metadata store. It is **not a production replacement**, a complete Blossom implementation, or
authorization to change canonical DNS. There is no Fastly proxy or fallback hidden in this handler.

## Run the proof

Requires Deno 2.9 or later for the local SQLite test harness. The edge modules themselves use Web
APIs and the Bunny SDK; `node:sqlite` is test-only.

```sh
cd experiments/bunny-blossom
deno task verify
deno bundle --platform=deno bunny.ts -o /tmp/bunny-blossom-spike-bundle.js
deno bundle --platform=deno probe_bunny.ts -o /tmp/bunny-blossom-conformance-probe.js
python3 inventory.py
```

These commands do not start a browser or a local dashboard. Dependency versions and their integrity
hashes are pinned in `deno.json` and `deno.lock`.

## Implemented slice

| Capability                     | Evidence and limit                                                                                                                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT /upload`                  | BIP-340 Nostr signature and content hash checked before storage; 4 MiB default fixture limit; Pending metadata; owner reference recorded. No transcoder dispatch.                   |
| `GET` / `HEAD` originals       | Direct private S3 object request, original extension aliases, public Pending/Active reads. Fresh metadata read before and after origin headers.                                     |
| Fixed progressive/HLS children | Native allowlisted routing and the same parent policy on each request. Fixtures can be seeded by an operator; no rendition publisher or source-generation proof yet.                |
| Authenticated media            | Hash-scoped Blossom `get` events and exact URL/method/time-scoped NIP-98. No client credential is forwarded to B2.                                                                  |
| `GET /list/<pubkey>`           | Signed owner-scoped query; bounded to 100. SQL adapter refuses overflow instead of pretending it paginates.                                                                         |
| `DELETE /<hash>`               | Removes only the signer's reference. Last-reference removal writes a tombstone and durable cleanup-pending marker. Returns **202**, never physical-erasure completion.              |
| SQL metadata                   | Atomic primary-key insert/update revision CAS, parameterized owner query, strict row decoding. Tested against real local SQLite.                                                    |
| B2 transport                   | AWS SigV4, fixed provider host and isolated fixture prefix, no redirects or mutation retries, Range forwarding, response-header allowlist. Tested with captured transport requests. |
| Runtime                        | Native Bunny SDK entry point and bundled Deno build. Both the ephemeral probe and separate-request hosted SQL/B2 fixture flow passed on the real Bunny runtime. See limits below.   |

The upload exclusion gate survives lost storage acknowledgements. A policy change during upload or
while waiting for origin headers prevents publication or delivery. No elapsed-time lease clears an
uncertain operation.

The spike requires an expiration on Blossom authorization; production viewer auth also supports some
legacy events without one. It does not claim full authorization or moderation parity. `Restricted`
and `ageRestricted` here are fixture-level controls, not replacements for every production policy
state.

## Isolated configuration

`bunny.ts` consumes secrets at runtime, never from source files:

| Name                                 | Purpose                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| `SPIKE_PUBLIC_ORIGIN`                | Exact HTTPS test origin, including its host. Do not bind `media.divine.video`.             |
| `SPIKE_SQL_PRIMARY_URL`              | Explicit primary libSQL/HTTPS endpoint for a dedicated fixture database.                   |
| `SPIKE_SQL_TOKEN`                    | Token limited to that database. Apply `schema.sql` separately.                             |
| `SPIKE_B2_REGION`, `SPIKE_B2_BUCKET` | Private test storage location.                                                             |
| `SPIKE_B2_PREFIX`                    | Required shape `blossom-runtime-spike/<UUID>/`; production delivery prefixes are rejected. |
| `SPIKE_B2_KEY_ID`, `SPIKE_B2_KEY`    | Dedicated credentials restricted to that exact fixture prefix.                             |
| `SPIKE_ENABLE_FIXTURE_WRITES`        | Defaults off; set `true` only for synthetic fixtures.                                      |

Bunny Database is currently in public preview. The SQL adapter is also usable with another
compatible primary, but that compatibility is not a durability, consistency or failover guarantee.
Primary-only routing, concurrent updates, backup/restore and outage behavior must be proven on the
selected hosted store. The local SQLite proof does not establish regional replication behavior.

The provider currently documents a possible loss of acknowledged writes during primary failover, up
to 10 seconds or 4096 WAL frames. That is a material durability trade-off for policy and deletion
records, separate from temporary unavailability. The synthetic hosted proof does not test failover
or establish an acceptable production recovery point.

## Full rewrite parity inventory

`routes.json` records the canonical Rust route matchers from the source checkout. Each starts with
parity **not established**. This inventory is deliberately separate from the implemented-slice
table: accepting a similar path is not proof of matching production behavior. Regenerate when
comparing a newer baseline.

The following remain before a canonical cutover:

- Full policy schema: tombstones, quarantine, uploader/reference vanish gates, legal holds, appeals
  and every authenticated viewer rule.
- Multipart and resumable uploads, existing upload/transcoder callbacks, original/derived source
  versions, dedupe and all producer-gate consumers.
- Streaming upload bodies and production media sizes. The spike buffers at most its fixture limit;
  it is not a production upload architecture.
- An indexed owner/reference schema and cursor pagination. The fixture SQL JSON owner scan must not
  become the production listing implementation.
- All-version erasure worker, durable retries, checked CDN purges, late-fill withdrawal and
  independent confirmation of physical absence.
- CDN caching. **Every response is currently private/no-store.** Before enabling caching, prove
  authorization on hits and revocation of every child. The spike does not protect against a policy
  change after streaming response headers.
- Well-known/root responses, descriptors and every media alias, captions, images, audio, subtitle
  jobs, reports, mirrors, archive imports and provenance.
- Admin authentication/UI, moderation hooks, backfills, operational rate limits, production
  telemetry, secret rotation and disaster recovery.
- Metadata export/migration, reference reconciliation and a rollback path that prevents divergence
  between the old and new policy authorities.
- Representative media sizes and HLS playback on Bunny, concurrent hosted policy mutations, region
  failure and representative load/cost measurements. The small hosted original fixture establishes
  basic integration only.

Unimplemented routes return 501. Existing upload and transcoder services need not be rewritten
merely to replace the Fastly edge, but their metadata, signing and callback contracts still need
migration and parity tests.

## Cost experiment

Compare total backend cost per delivered GB and per completed clip at the same workload, including
Edge Script invocations/CPU, SQL rows read/written, storage, origin reads, purge traffic and
request/error amplification. Measure p50/p95/p99 for public reads, signed reads and mutations, plus
failure and retry rates. Do not compare only CDN rates or substitute wall time for billable CPU
time.

Do not publish account usage exports, negotiated prices, real object hashes or credentials in this
public repository. No savings measurement is claimed by the local checks. Use paid list prices for
the database model even while preview usage is free, and verify both providers' actual billing units
and commitments.

## Primary references

- [Bunny standalone scripts](https://bunny.net/docs/scripting/standalone/overview)
- [Before-cache execution](https://bunny.net/docs/scripting/before-cache)
- [Bunny SQL quickstart](https://bunny.net/docs/database/quickstart)
- [Database preview status](https://bunny.net/docs/database)
- [Database durability](https://bunny.net/docs/database/durability-and-consistency)
- [Database replication](https://bunny.net/docs/database/replication)
- [Database published prices](https://bunny.net/database/)
- [Bunny Edge Scripting pricing](https://bunny.net/edge-scripting/)
- Production parity baseline: `src/main.rs`, `src/viewer_auth.rs`, `src/delete_policy.rs`,
  `src/storage.rs`, `src/metadata.rs`.

## Live runtime proof

The separate `probe_bunny.ts` entry point exposes only GET/HEAD `/health`. Each call allocates new
in-memory fixtures and executes a signed upload, GET, HEAD, owner list, reference deletion and
denied post-delete read through the same native handler. It has no provider secrets or external data
access, and there is no persistent public upload endpoint. It is a runtime compatibility probe, not
a deployed persistent Blossom service.

Observed on Bunny on 2026-11-23: all six expected statuses passed on the first request and three
subsequent probes. These samples are not a latency benchmark or a billing measurement. The provider
also changed the requested client cache header to `no-cache`; final header and cache behavior still
require explicit zone configuration and live verification before any real content.

A separate deployment of the reviewed `bunny.ts` bundle also passed a synthetic persistent flow on
2026-11-23: signed upload (200), original GET (200, exact bytes), HEAD (200), Range (206, exact two
bytes), owner list (200), reference deletion (202) and subsequent denied GET (404). The tombstone
and cleanup-pending marker were independently read back from hosted SQL. B2 credentials were limited
to a fresh fixture prefix, and the handler admitted only one configured digest and an operator-owned
signer. No production metadata or media was imported.

The first Range probe returned a full 200 response. Direct B2 through the same adapter returned 206;
enabling `EnableCacheSlice` on the isolated linked pull zone made the public request return 206 with
the expected content range and bytes. This configuration is part of the hosted proof, not an
application-code fix. The proof does not establish multi-region freshness, failover durability,
production caching, physical erasure or load capacity.

## Fixture and delivery boundaries

For a persistent fixture deployment, enabling writes also requires `SPIKE_FIXTURE_SHA256` and
`SPIKE_FIXTURE_OWNERS` (one to four comma-separated full public keys). Only those signers may mutate
that one fixture hash. This restriction is checked before metadata or storage mutations. Use a newly
created, operator-owned test identity, never a real account.

The inventory includes three dispatches before the 64 tuple matchers: the B2 delivery host route,
canary host route, and canonical playback-selection prefix. These are separate migration surfaces,
not implemented parity.

The isolated probe now checks descriptor fields, returned bytes, the owner listing, cleanup state
and denied-read body as well as HTTP statuses. Its in-memory state is discarded after every probe
call.

The experiment-specific workflow does not deploy. Merging any change in this repository still
invokes normal mainline CI, including its existing Fastly publish policy. This spike does not change
that policy and must not be described as a merge with no possible production deployment activity.
