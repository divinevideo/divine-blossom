# Transcript storage and regeneration

Transcript completion requires the selected media-provider output. In
`b2_primary`, completion also requires the verified GCS backup. A transcript
found only in GCS is historical input for translation; it is not proof that
B2 output exists. A missing selected transcript enters normal regeneration.

Cache validation and required-backup repair hold the existing transcript lock.
Repair creates an absent GCS backup with `ifGenerationMatch=0`, or replaces only
the observed generation. A conflicting writer causes failure without replacing
that writer's generation. Lock-acquisition and provider/verification failures send a failed status
webhook, including the adapter's sanitized cause. Default GCS metadata lookup
errors retain the existing fall-through to locked processing.

## Authorized regeneration

The public subtitle-jobs `force` flag is a job-cache choice, not worker repair
authority. Do not forward it as trusted worker authority. Forced `/transcribe`
requests use the existing `TRANSCODE_REPAIR_SECRET` authorizer and
`x-divine-repair-secret` header, shared with derivative repair. Missing worker
configuration returns 503; an invalid credential returns 401 before work.
No credential, binding, IAM change, or runtime configuration is created here.
An operator must verify an approved existing repair-secret binding before using
forced regeneration. Source support alone does not make runtime repair ready.

The existing repair tools support an explicit authenticated-worker mode. Read
the existing credential from an access-controlled file; pass its path, never its
value. Use the approved worker URL and an explicitly owned hash, for example:

```sh
python3 cloud-run-transcoder/repair_recent_bad_vtts.py \
  --repair-hash "$MEDIA_SHA256" \
  --transcoder-url "$TRANSCODER_URL" \
  --repair-secret-file "$TRANSCODE_REPAIR_SECRET_FILE" \
  --timeout 300
```

Both Python scanning tools accept `--transcoder-url` and `--repair-secret-file`.
The shell tool accepts `TRANSCODER_URL` and `TRANSCODE_REPAIR_SECRET_FILE` with
`--transcript-only`. In that mode it skips `--delete-vtt-first`: regeneration
writes through the selected adapter, requiring both copies in `b2_primary`.
Legacy public-job mode remains available for existing GCS workflows but does
not bypass a selected-provider cache. Deleting only a GCS VTT cannot force
regeneration of a surviving B2 transcript.

The existing `--dry-run` flag also applies to `--repair-hash`: it reads no repair
credential and makes no worker request. An explicitly empty single-hash target
or authenticated configuration is rejected; it cannot select a batch scan or
legacy job path. Authenticated execution performs one
request, refuses redirects, and reports
success only for a matching hash and completed worker response. It does not
retry a failed or uncertain request. A timed-out caller does not cancel forced
work: the worker retains its lock and task through storage and release. Inspect
worker status before another attempt; do not delete a lock based on caller
absence or elapsed time.

## Rollout and erasure

Before enabling additional B2 transcript writes, enable and verify the existing
B2 erasure path: edge B2 artifact cleanup is gated by `b2_replica_enabled`.
Validate owned-fixture deletion across the relevant versions. That flag alone
is not proof of shared exclusion between all writers and erasure; the existing
writer/erasure coordination limitation remains explicit. Retain GCS compatibility
and the current public URLs. Translation output, job state and operational locks
remain in GCS.

Related work: [bounded derivative/transcript failures](https://github.com/divinevideo/divine-blossom/issues/70)
and [B2 replica erasure](https://github.com/divinevideo/divine-blossom/issues/249).
