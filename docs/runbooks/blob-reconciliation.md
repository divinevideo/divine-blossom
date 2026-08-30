# Blob Reconciliation

Use `scripts/cleanup_orphan_kv.py` to classify event-referenced blobs without printing their hashes. Catalogue scans are read-only. Repair is limited to a private, curated hash file and soft-deletes metadata only when storage bytes are missing and the normal direct delivery path also returns 404.

Install the operator dependencies before running the tool:

```bash
python3 -m pip install requests google-cloud-storage
```

## Required Configuration

Read-only scans require:

- `FASTLY_API_TOKEN`: read access to the Fastly KV store.
- `KV_STORE_ID`: the Fastly KV store containing `blob:*` metadata.
- `GCS_BUCKET`: the exact GCS bucket to inspect. The script validates that the bucket exists before scanning.
- Google application-default credentials with `storage.buckets.get` and permission to read object metadata from that bucket.

Repair also requires:

- `FASTLY_ADMIN_TOKEN`: bearer token accepted by the Blossom admin delete endpoint.
- `BLOSSOM_ADMIN_ENDPOINT`: the trusted Blossom service origin that owns `/admin/api/delete`. Do not point this at the public media hostname.
- `--public-endpoint`: the normal anonymous direct-blob delivery endpoint.

Do not print these values or store them in shell history. Use the repository's approved credential manager and pass secrets through the environment.

## Private Hash Files

Create the candidate file outside the repository, with one complete SHA-256 hash per line. Blank lines and lines beginning with `#` are ignored. Restrict access before adding identifiers:

```bash
umask 077
touch /secure/path/blob-candidates.txt
chmod 600 /secure/path/blob-candidates.txt
```

Do not pass hashes on the command line, commit the file, attach it to a ticket, or paste it into logs. Remove it according to the operator host's secure-data policy after the incident record no longer needs it.

## Read-Only Measurement

Scan the catalogue, optionally by prefix or count:

```bash
python3 scripts/cleanup_orphan_kv.py --all --public-endpoint https://media.example
python3 scripts/cleanup_orphan_kv.py --all --hex-prefix 0a --limit 1000
```

Progress is written to stderr as aggregate `scanned=N` counters. The final JSON contains counts and recommended actions only.

A catalogue scan makes several service requests per blob. Start with `--hex-prefix` and `--limit`, which are pushed into Fastly pagination, then expand deliberately. Schedule a full `--all --public-endpoint` run as an operational workload rather than an interactive sample.

## Two-Run Repair Protocol

1. Curate a private hash file from authorized incident evidence.
2. Run the file read-only with the public endpoint and record only its aggregate `missing_bytes` count.
3. Investigate every other class. Do not broaden the file to make the count match an expectation.
4. Wait at least 61 seconds after the read-only public probes so the edge's known 60-second negative-cache TTL has expired.
5. Run the same file again with repair enabled, the prior count, and a hard cap no lower than that count.

```bash
python3 scripts/cleanup_orphan_kv.py \
  --hash-file /secure/path/blob-candidates.txt \
  --public-endpoint https://media.example

python3 scripts/cleanup_orphan_kv.py \
  --hash-file /secure/path/blob-candidates.txt \
  --public-endpoint https://media.example \
  --repair-missing-bytes \
  --confirm-missing-count COUNT_FROM_FIRST_RUN \
  --max-repairs APPROVED_CAP
```

The second run reclassifies the complete file before the first mutation. It writes nothing if the live candidate count changed or exceeds the cap. Immediately before each soft delete, it also re-reads the blob owner and that owner's blob list. A hash still in the owner list may be retry state for an interrupted account vanish, so the tool excludes it rather than clearing the marker. A failed marker probe also prevents repair. Whole-catalogue repair is rejected.
Public probes stream and close the response without retaining the body, but the opaque query marker deliberately forces a cold cache fill. Because the deployed delivery cache key includes the query string, each probe can fetch the full object from origin and leave a separate edge entry for its cache lifetime. Treat this as an operational workload and do not use it casually at catalogue scale; the 61-second wait remains required for negative-cache expiry.

## Classification Meanings

| Class | Meaning | Operator action |
| --- | --- | --- |
| `available` | Metadata, configured storage, and any requested public probe agree. | None. |
| `missing_bytes` | Active metadata, missing configured storage object, and direct public delivery returned 404. | Eligible for the guarded two-run repair protocol. |
| `unverified_missing_bytes` | Active metadata and missing configured storage object, but no public endpoint was probed. | Re-run with the correct public endpoint. Never repair from this class. |
| `alias_only_derived_audio` | Reverse references identify derived audio intentionally hidden at the direct hash path. | None. It is explicitly ineligible for missing-byte repair. |
| `storage_path_divergence` | Configured storage is missing while public delivery still serves bytes. | Investigate replicas, cache, and bucket targeting. |
| `missing_metadata` | Storage bytes exist without blob metadata. | Restore only from a verified metadata backup. |
| `stale_event_reference` | Neither metadata nor configured storage exists. | Repair at the event source where possible. |
| `moderation_hidden`, `age_restricted`, `deleted` | The public response matches intentional access state. | None. |
| `delivery_path_failure` | The public response conflicts with metadata state. | Investigate routing and access enforcement. |
| `inconsistent_metadata` | Metadata exists but its schema, identity, or status is invalid. | Quarantine and restore only from verified evidence. |
| `probe_error` | Fastly, GCS, reverse-reference, or public probing failed. | Fix the probe failure and rerun. |

## Failure And Recovery

- Exit `0`: the read-only scan completed, or every approved repair completed.
- Exit `2`: configuration, input, dependency, bucket validation, or CLI validation failed. No repair scan started.
- Exit `3`: repair was skipped, excluded an outstanding vanish retry, partially failed, or did not complete. Some earlier candidates may already have been soft-deleted.

On exit `3`, retain the private file and inspect the aggregate `repairs` counters. `excluded_vanish_retry` means the hash remained discoverable by account vanish and must not be repaired here. `failed_vanish_retry_probe` means the safety check could not read current metadata or owner-list state. Correct any service or authorization failure, then start again with a new read-only count-confirmation run. Repeating the repair command without a fresh first run is not recovery. Soft deletion is idempotent only through the admin API's current contract; verify the live aggregate result rather than assuming a retry completed previous work.
