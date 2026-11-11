# MP4 backfill

`POST /backfill-fmp4` fills missing progressive MP4 variants from existing HLS
segments. Ordinary requests need only `{"hash":"<sha256>"}`. Existing variants
in the selected primary store are skipped individually; both present returns
`{"status":"already_exists","hash":"<sha256>"}` without downloading or writing.

To regenerate existing variants, send `force:true` and the existing
`x-divine-repair-secret` credential. Forced requests return 401 for missing or
wrong credentials, or 503 when repair is not configured. No additional caller
secret is introduced. Successful processing returns `status:ok`; unavailable
sibling TS variants are skipped, but every downloaded variant must produce a
verified MP4 or the request returns 500. A partial failure may leave successful
MP4 writes in place. Concurrent calls are not serialized by this endpoint.

## Operator configuration

The script intentionally forces regeneration, preserving its repair purpose.
Use an isolated Python environment with `scripts/requirements-b2-sync.txt`
installed, and supply an existing credential file through
`TRANSCODE_REPAIR_SECRET_FILE`. Do not pass the credential value as an argument.
The file must contain one nonempty header-safe token. The script does not fetch
or copy deployment secrets.

B2 discovery is the default and requires `B2_MEDIA_BUCKET`, `B2_REGION`,
`B2_APPLICATION_KEY_ID`, and `B2_APPLICATION_KEY` in the approved operator
environment. It lists current objects, not retained versions. GCS discovery uses
application-default credentials and `GCS_BUCKET` (default `divine-blossom-media`),
without changing the active gcloud configuration. `--source both` requires access
to both stores and deduplicates their results. Either TS variant identifies a
candidate; originals without HLS are not candidates.

```sh
./scripts/backfill-fmp4.sh --dry-run
./scripts/backfill-fmp4.sh --source both --dry-run
./scripts/backfill-fmp4.sh --source b2 --concurrency 5
```

`TRANSCODER_URL` or `--transcoder-url` selects the approved worker base URL or
its `/backfill-fmp4` endpoint; the default remains the existing transcoder.
Production worker URLs require HTTPS. Redirects are rejected, and forced
requests are never automatically retried because a lost response may follow a
successful write.

The script keeps `backfill-fmp4-done.txt` and `backfill-fmp4-failed.txt` in
`scripts/`, or under `--state-dir`. Existing done entries remain trusted and are
skipped; historical entries are not revalidated. Failed entries remain eligible
on a later run. Only HTTP 200 with a matching hash and recognized success status
is recorded as done. Any discovery or processing failure makes the run exit
nonzero; discovery errors do not discard pending worker results. Dry-run lists
eligible hashes, skips done entries, and does not read the repair credential,
submit requests, or modify state files.

## Tagged revision validation (operator step)

This change does not deploy. For later validation, follow the deployment runbook
to create a tagged no-traffic revision, preserving all existing environment and
secret bindings. Use designated test media only.

1. Record the selected primary MP4 version IDs and backup generations.
2. Call without `force` when both MP4s exist. Expect `already_exists` and unchanged
   primary versions and backup generations.
3. On a test fixture with one missing MP4, call without `force`; verify only the
   missing output is published, with its required backup.
4. Confirm forced requests without the credential return 401 (503 if repair is
   unconfigured), then call with the existing repair credential and `force:true`.
   Expect `ok`, new MP4 versions, and verified required backups.
5. Exercise one failed remux or backup publication; expect 500 and no done entry
   from the operator script. Do not automatically replay forced requests after
   ambiguous transport failures.

Retain scrubbed validation evidence privately. Do not put credentials, real-user
identifiers, or raw provider responses in PRs or committed files.
