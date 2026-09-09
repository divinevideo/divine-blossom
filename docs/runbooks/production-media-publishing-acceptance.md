# Production media publishing acceptance

This manually invoked smoke check exercises the deployed client-visible path:
upload a stable synthetic fixture, wait for progressive MP4 and HLS readiness,
publish a kind-34236 event, and read that exact event from both the relay and
canonical REST API. It is not a pull-request CI job. Its deadlines are liveness
guards, not service-level objectives; timing objectives are owned by #284.

## Safety prerequisite

Do not run the publishing stages until the dedicated synthetic pubkey is
excluded from production feeds and discovery. A kind-34236 event is immutable
once distributed, even though repeated runs replace the same addressable
coordinate in Divine's read model.

The harness refuses to start unless the operator sets
`DIVINE_ACCEPTANCE_FEED_EXCLUSION_CONFIRMED=1`. That variable is an execution
interlock, not proof of exclusion. Confirm the actual production exclusion with
the feed owner first and record that decision privately; do not commit the
synthetic pubkey.

## Requirements and invocation

Install the official [fiatjaf/nak](https://github.com/fiatjaf/nak) binary. The
harness rejects unrelated executables named `nak`. Supply the dedicated
synthetic identity outside the repository:

```bash
export DIVINE_ACCEPTANCE_NSEC='<dedicated synthetic nsec>'
export DIVINE_ACCEPTANCE_FEED_EXCLUSION_CONFIRMED=1

python3 scripts/production_media_publish_acceptance.py --json
```

The secret key is passed to `nak` through `NOSTR_SECRET_KEY`; it is never added
to a command line or result payload. Keep it out of shell history, logs, and
committed configuration.

The default fixture is `scripts/tests/fixtures/readiness_ok.mp4`, shared with
the readiness assertion. The script computes its SHA-256 locally, validates the
upload descriptor's hash, size, and MIME type, and uses the returned thumbnail
and dimensions in a Format 1 `imeta` tag.

Every run uses the fixed `d` tag `divine-production-media-acceptance` and a
fresh nonce. The coordinate remains stable while the signed event ID is new.
Relay and REST checks require that exact new ID, so an older value at the same
coordinate cannot make a run pass.

Run the command twice. Both results must report the same `media_hash` and
`coordinate`, different `event_id` values, and successful `upload`,
`readiness`, `publish`, `relay_read`, and `rest_read` stages. Store raw output
only in the authorized operational record; put only scrubbed timings in public
issues or pull requests.

## Result contract

Exit `0` means every stage passed. Exit `1` means a stage failed or its bounded
poll expired. With `--json`, stdout is one object containing the verdict,
stable media hash and coordinate, exact newly published event ID, and scrubbed
elapsed seconds for each completed stage. Failures contain only a verdict and
scrubbed reason; raw authorization material and command stderr are excluded.
