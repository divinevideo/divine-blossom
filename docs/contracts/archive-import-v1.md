# Trusted archive import v1

Private control plane at `/internal/archive/v1/{operation}`. It accepts no media
bytes and performs no provider verification downloads. A dedicated
`archive_import_token` is required; admin and moderation credentials do not authorize
this interface. `archive_import_enabled=true` enables admissions. Existing
registration, reconciliation and settlement remain available when admissions pause.

`admit`, `admit-copy`, `check`, `register`, `reconcile`, `settle`, and
`settle-copy` accept:

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

For `settle-copy`, add the `generation` returned by `admit-copy` to the original
admitted item. Every item field must match the admission, or the exact item retained
by an earlier copy settlement. The generation must be a canonical, nonzero decimal
`u64` string. Before retiring the attempt, the operation requires either its exact
copying gate or the released gate for that same attempt and admission generation.

A successful item returns this object in `items[n].result`:

```json
{
  "settled": true,
  "copy_settlement": {
    "version": 1,
    "sha256": "<64 lowercase hex>",
    "owner": "<64 lowercase hex>",
    "attempt": "<32 lowercase hex>",
    "state": "released",
    "admission_generation": "<admitted generation>",
    "released_from_generation": "<same admitted generation>",
    "parent_generation": "<observed released-gate generation>"
  }
}
```

Retirement atomically retains the admitted item and clears the active admission.
The operation conditionally releases the owning gate, rechecks current policy, and
returns proof only after observing that exact released gate. `owner` comes from the
retained item. Both `admission_generation` and `released_from_generation` equal the
supplied generation; `parent_generation` identifies the observed released gate.
All three are canonical, nonzero decimal `u64` strings used as equality fences.

Retry the identical item after a lost response; the retained binding is reused,
and proof still requires the exact released gate and current policy. A missing
gate, a different attempt or admission generation, or an erasing parent cannot
produce this proof. Retired copy attempts cannot be readmitted with `admit-copy`.
Legacy `settle` returns only `{"settled":true}`; that acknowledgment
is not a copy-release proof, and a historical settlement without a retained copy
item cannot be upgraded to one by replaying `settle-copy`.

See the [archive handler and synthetic contract](../../src/archive_import.rs) and
[parent-gate helpers](../../src/parent_gate.rs) for the implementation.

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

Erased blob metadata is stored as JSON `null`, which public lookup treats as absent.
Archive admission records are cleared of identity and provenance while their KV
generation remains. These empty records prevent a request prepared before erasure
from succeeding as an add-only insertion after erasure. Admission and metadata
mutations check owner policy and the writer generation inside every CAS retry.
