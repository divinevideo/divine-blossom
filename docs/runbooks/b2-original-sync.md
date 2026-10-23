# Approved original-video B2 mirror

This worker prepares private, verified originals for the internal playback
canary. GCS stays authoritative for uploads and default playback. Running the
worker does not activate a hostname or a mobile flag. No scheduler or deployment
is installed by this change.

## Preconditions

- Verify the source bucket against the existing upload configuration. Explicitly
  choose a separate private B2 destination; public delivery buckets are ineligible.
- Map that exact B2 bucket name **and** ID to the endpoint's delivery configuration
  and the existing all-version erasure configuration. The worker requires both
  mappings on its command line and rejects differences.
- Deploy and verify the shared `b2-sync:v1:{hash}` erasure gate before starting
  any mirror worker. Existing all-version deletion must hold the permanent
  `erasing` gate before deleting. A deployment without that gate is ineligible.
- Use GCS application default credentials with object-read/list permission only.
  Inject `B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY`, and `FASTLY_API_TOKEN`
  through the approved credential runner. Do not paste values into commands,
  shell history, logs, or the repository. B2 needs read/write files, `listBuckets`,
  and `readBucketRetentions`; the worker does not need deletion permission.
  Fastly needs reads of authoritative policy and writes of mirror state in the
  configured metadata store. Its implementation permits writes only to
  `b2-ready:*` and owned `b2-sync:v1:*` copy gates; the token may have broader
  provider permissions, so use an approved restricted operator environment.
- The native B2 preflight verifies exact name/ID, `allPrivate`, visible retention
  configuration, Object Lock disabled, and no default retention. Missing visibility
  fails closed. Every upload must return a nonempty immutable version ID.
- Use Python 3.11 or later, durable local state, one worker invocation per state
  directory, and a monitored periodic runner. The state directory contains media
  bytes and must be private. Its directory and files use owner-only permissions
  when created by the CLI. Do not share or commit it.

## Install and run a bounded pass

Create an isolated virtual environment and install the operator dependencies:

```sh
python3 -m venv .venv-b2-sync
.venv-b2-sync/bin/python -m pip install -r scripts/requirements-b2-sync.txt
```

The following names are operator-supplied variables, not committed account or
bucket assignments. Run only after verifying all preconditions:

```sh
.venv-b2-sync/bin/python scripts/sync_b2_originals.py \
  --source-bucket "$MIRROR_SOURCE_BUCKET" \
  --destination-bucket "$MIRROR_DESTINATION_BUCKET" \
  --destination-bucket-id "$MIRROR_DESTINATION_BUCKET_ID" \
  --erasure-bucket "$MIRROR_ERASURE_BUCKET" \
  --erasure-bucket-id "$MIRROR_ERASURE_BUCKET_ID" \
  --kv-store-id "$MIRROR_KV_STORE_ID" \
  --state-dir "$MIRROR_STATE_DIRECTORY" \
  --max-objects 10 --max-bytes 268435456 \
  --max-object-bytes 67108864 --max-spool-bytes 268435456
```

Each invocation lists at most one page of source names, then checks at most
`max-objects` known originals, oldest checked first. Only lowercase 64-character
SHA-256 object keys are candidates. Derivatives and aliases are skipped. Repeated
bounded invocations continue the persisted listing cursor and restart a full
scan at its end, discovering new uploads and repairing missed earlier uploads.
Keep the same SQLite database and spool directory across invocations. The
database is bound to the exact source/destination/store mapping and rejects reuse
for a different mapping. Run under a timer or job runner at an operator-chosen
interval; there is no automatic production schedule in this repository.

Known objects remain in the local schedule after disappearing from source
listings, so repeated passes remove readiness for missing originals and revoked
policy. Newly approved objects are reconsidered on later passes. The time to
complete a scan/reconciliation grows with the inventory, page size, scheduling
frequency, and backlog; monitor those rather than assuming a fixed deletion SLA.
Keep and back up the state database: rebuilding it from GCS alone cannot discover
an old readiness key whose source has already disappeared. Playback still checks
current policy independently of this reconciliation schedule.

`max-bytes` bounds reserved media traffic for source download, destination upload,
and independent destination verification in a pass. Failed operations consume
their reservation. Control requests and protocol overhead are excluded. All
provider retries for media transfer are disabled, and each bounded original uses
one S3 PUT with no multipart background workers. Source downloads resume at the
last fsynced chunk using generation preconditions; a changed generation discards
the partial file. Upload plus verification requires a reservation of twice the
object size, or the object waits for a later pass. The canary ceiling is 64 MiB
per original with at most 1 MiB read chunks. Spool bytes are separately bounded.

Output is aggregate JSON counts, including `errors`, `locked`, `pending`, and
`transfer_bytes_reserved`. An error count exits nonzero for operator alerting.
Provider exceptions are intentionally suppressed because they can contain signed
URLs, account identifiers, or credentials. `locked` requires investigation of the
shared gate; repeated retries will never steal an existing gate.

## Policy and readiness contract

All policy comes from uncached Fastly metadata, never from GCS object metadata.
An original needs `blob:{hash}` with matching hash/size, `status: active`, a video
MIME type, a valid owner, no `tombstone:{hash}`, and no
`vanish_in_progress:v1:{uploader}` for the owner or any known uploader in
`refs:{hash}`. Missing/malformed policy or a lookup failure cannot grant access.

The worker checks policy before download, after obtaining the copy gate,
immediately before readiness, and after publication. It verifies the complete
source SHA-256 and that the live source generation did not change. It then reads
the complete destination using the returned immutable B2 version ID and verifies
SHA-256, range length, total size, and version. Only then does it publish
`b2-ready:{hash}` in the same Fastly metadata store:

```json
{
  "version": 1,
  "sha256": "<full original SHA-256>",
  "source_bucket": "<configured GCS bucket>",
  "source_generation": "<pinned GCS generation>",
  "bucket": "<configured private B2 bucket>",
  "key": "<full original SHA-256>",
  "size": 12345,
  "destination_version_id": "<verified immutable B2 version>",
  "verified_sha256": "<full original SHA-256>",
  "verified_at": 0
}
```

`verified_at` is Unix seconds. This record does not override moderation or
deletion. The canary endpoint independently checks current policy and pins every
GET/HEAD to `destination_version_id`. Missing readiness denies delivery. The
worker deletes readiness on revoked policy or disappearance, never GCS objects
or B2 versions. The existing scoped all-version erasure path owns B2 removal.

## Shared copy/erasure gate and recovery

Before PUT, the worker uses atomic add-only insertion for
`b2-sync:v1:{hash}` with `{"state":"copying","attempt_id":"<random UUID>"}`.
It rechecks policy after the claim. Erasure uses the same key, add-only, with
`{"state":"erasing"}` and keeps it permanently. Whichever claims first excludes
the other. A `copying` gate makes erasure retry rather than report completion;
an `erasing` gate prevents all later copies, including a worker whose earlier
policy reads raced with deletion. This prevents physical resurrection after an
all-version erase, beyond the endpoint's independent delivery gate.

The copying gate has **no TTL**. A successful, definitively completed PUT can
release its owned gate after verification/publication or a definitive failure
later in the process. A crash or uncertain PUT response keeps the gate closed
indefinitely. No scheduled task or retry is allowed to expire or steal it.

For a stuck gate, stop and drain every writer for that destination and hash,
including any worker that could still resume. Confirm that no in-flight PUT can
commit later; a process timeout alone is not evidence of the remote outcome.
Inspect the scoped B2 version inventory and current authoritative deletion state
through the approved operator workflow. If deletion is pending, preserve the gate
until the writer is conclusively drained, transition it to permanent `erasing`
using a conditional generation-matched update, and rerun the existing all-version
erasure to verified completion. If the object remains approved, conclusively
resolve the upload outcome and version inventory before a conditional owned-gate
release and a fresh bounded pass. Do not blindly delete a gate, clear the whole
namespace, change it using an unconditional write, or restart copying during this
recovery. Automated recovery is deliberately absent because the worker cannot
prove that another process or a timed-out remote PUT has drained.

## Local validation

```sh
.venv-b2-sync/bin/python -m unittest scripts.tests.test_sync_b2_originals -v
```

The suite uses synthetic bytes, metadata, and identifiers. It covers durable
resume, changed source generation, transfer/spool bounds, corrupt copies,
revocation and vanish races, permanent erasure gates, uncertain upload outcomes,
native private-bucket preflight, and real GCS/S3 SDK traffic against a local HTTP
server. It does not perform cloud mutations or establish production readiness.

References: [GCS generation-pinned downloads](https://docs.cloud.google.com/python/docs/reference/storage/latest/google.cloud.storage.blob.Blob),
[version-pinned S3 reads](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_object.html),
[B2 bucket privacy and retention metadata](https://www.backblaze.com/apidocs/b2-list-buckets),
and [Fastly atomic add-only operations](https://www.fastly.com/blog/beyond-crud-advanced-features-of-fastlys-kv-store).
