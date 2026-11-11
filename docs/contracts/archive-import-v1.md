# Trusted archive import v1

Private control plane at `/internal/archive/v1/{operation}`. It accepts no media
bytes and performs no provider verification downloads. A dedicated
`archive_import_token` is required; admin and moderation credentials do not authorize
this interface. `archive_import_enabled=true` enables admissions. Existing
registration, reconciliation and settlement remain available when admissions pause.

`admit`, `admit-copy`, `check`, `register`, `reconcile`, and `settle` accept:

```json
{"version":1,"items":[{"sha256":"<64 lowercase hex>","owner":"<64 lowercase hex>","attempt":"<32 lowercase hex>","source":"<immutable source identity>","provenance":"<approved archive manifest identity>","size":99,"content_type":"video/mp4"}]}
```

Maximum 16 items and 64 KiB per request. Results preserve input order and identify the
hash and owner; each contains `ok` and `result`, or `error` (`policy_denied`, `invalid`,
`retry`). Retrying one item does not replay successful items. The importer is trusted
to bind approved archive identity to its existing creator account; this is not a public
Blossom upload or a creator signature.

Admission returns a generation string for the shared `b2-sync:v1:<hash>` no-TTL gate.
`register` adds that `generation`, destination `bucket`, and immutable `file_id` to the
original item. It stores metadata, references, provenance and the registration receipt
before releasing the gate. `reconcile` returns any existing admission and owner receipt.
`check` validates the generation and current removal policy before a storage write.
`admit-copy` obtains exclusion for compatibility writes even when the owner is already
registered. `settle` releases only the matching attempt; the durable CloudSQL authority
must establish that all physical effects have finished or were explicitly rejected.
Never use settlement to time out an uncertain write.

Registration preserves moderation status and existing ownership. New records start
pending. An `archive_storage` receipt makes bare original GET and Range use B2 even
when legacy global reads still prefer GCS. Normal visibility checks run first.
The public hash URL and Blossom descriptor format are unchanged.

`process-thumbnail`, `process-transcode`, `process-transcript`, `process-moderation`,
and `process-index` use the same item envelope. Submit processing one item per request;
these run in the separate durable followup fleet, after canonical GCS compatibility.
They check provider/service responses instead of silently discarding dispatch failures.

`aggregate` accepts a distinct body containing `version`, `previous`, `next`, `count`,
`bytes`, and `mime_counts`. A CloudSQL-journaled batch contains up to 1,000 newly created
originals. A single conditional global stats update records both the delta and the
monotonic batch cursor; replaying an acknowledged batch does not count it twice. This
work runs separately from registration. Drain the aggregate queue before a full admin
statistics rebuild. Existing status-change counters remain eventually consistent.

Owner unlink removes archive receipts and provenance and writes a permanent,
non-identifying owner/hash removal fence. Full metadata erasure removes the private
archive record. Neither ordinary retries nor enabling the feature can override erasure.

Run `scripts/run-archive-import-tests.py` with Viceroy for real synthetic KV, ownership,
replay, authorization, aggregate idempotency, erasure and signed Range tests. Registration
must generate no media reads; the fixture permits exactly one explicit Range request.

Archive ownership mutations check permanent owner/hash and account-erasure fences inside
the generation-conditional update. Starting account erasure retires archive authority
and advances the creator list generation before enumeration. Empty creator lists and
blob-reference arrays remain as generation fences, containing no ownership associations;
expiring/deleting those keys would allow a delayed add-only request to recreate them.
This retirement applies to archive import authority; ordinary signed uploads retain their
existing account policy.
