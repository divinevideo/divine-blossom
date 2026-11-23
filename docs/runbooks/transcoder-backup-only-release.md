# Disable media backups on the serving transcoder release

This release backports the optional GCS backup setting from #391 to the
previously serving transcoder source. It does not include the newer HLS claim,
queue admission or media stream-copy changes. The release branch is based on
the serving commit, not a rollback of main.

Keep `MEDIA_STORAGE_PROVIDER=b2_primary` and set
`MEDIA_GCS_BACKUP_ENABLED=false`. Unset or `true` preserves required GCS backups;
other values fail startup. Plain `b2` and `gcs` modes are unchanged.

B2 output writes still require version-pinned metadata and byte verification.
Disabling backups skips GCS replication and backup repair for adapter-managed
HLS, progressive MP4, audio and transcript output. HLS reuse still requires
all five required B2 artifacts, including both variant playlists and TS files;
progressive MP4 remains best effort. Missing originals and backfill inputs may
still be read from legacy GCS with pinned verification. B2 errors do not trigger
fallback. This setting neither deletes existing GCS copies nor disables direct
GCS control, translation or other service writes.

## Release checks

Run the transcoder tests with `--locked -- --include-ignored` and Clippy. Before
promotion, exercise the exact built image against isolated synthetic inputs in
real B2/GCS: verify every output and original, decode HLS and both MP4 variants,
check that no GCS derivative replicas were created, and test GCS-only source
fallback and duplicate replay. Compare matched jobs with the serving image.
Synthetic serial measurements do not establish fleet capacity or billed savings.

Follow [deployment configuration preservation](deployment.md#check-live-configuration-before-running-a-deploy-script).
Compare both the service template and currently serving revision, including all
environment and secret-binding names, without printing credential values.
Stage the pinned image with `--no-traffic` and
`--update-env-vars=MEDIA_GCS_BACKUP_ENABLED=false`; preserve all other settings.
Verify the resulting revision before moving traffic. Record the previous
revision and traffic tags for rollback. Inspect fresh completion/error logs and
output storage after promotion. Legacy tagged revisions must be accounted for
separately; stable traffic alone does not change their settings.

Rollback traffic to the recorded previous revision if verification fails.
Re-enabling backups on this image requires `MEDIA_GCS_BACKUP_ENABLED=true` in a
new revision; it does not immediately backfill historical output.
