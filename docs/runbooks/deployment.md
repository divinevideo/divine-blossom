# Deployment

Some of this repository deploys itself and some of it does not. After tests pass,
merging to `main` publishes the Fastly edge service to production within minutes,
with no human step. Most Cloud Run services do not ship that way — each one is a
script someone runs by hand.

That asymmetry is the thing to plan around. Any change that spans the edge and a
Cloud Run service goes out in two stages, the edge first, and there is a window
where new edge code is talking to an old backend.

## What ships automatically

`.github/workflows/ci.yml` runs on every push to `main`. After the `test` job
passes, it deploys, in parallel:

- the edge service to Fastly (`fastly compute publish`), followed by a CDN purge
- `process-blob` to Cloud Run
- the container image to GHCR

## What ships by hand

These services are not deployed by CI. Each is a script you run yourself.

| Service | Script |
| --- | --- |
| `divine-transcoder` | `cloud-run-transcoder/deploy.sh` |
| upload service | `cloud-run-upload/deploy.sh` |
| Parakeet ASR | `cloud-run-asr-parakeet/deploy.sh` |

`process-blob` also has `scripts/deploy-cloud-function.sh` for manual deploys.
It targets the same Cloud Run service that CI deploys on merge, so treat the CI
job and the manual script as competing deploy paths for one service, not two
separate services.

## The edge Cloud Run backends are not in the production project

The edge hardcodes its backends to project number `149672065768`:

```rust
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";
const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
```

That is the proof-of-concept project `rich-compiler-479518-d2`, not
`dv-platform-prod`. See issue #32, which is open and tracks moving them.

Most deploy scripts default `PROJECT_ID` to whatever your active `gcloud`
configuration points at. `scripts/deploy-cloud-function.sh` is the exception: it
requires `GCP_PROJECT_ID` and exits if it is unset. If your context is
`dv-platform-prod` — the normal case — running a script that reads the active
context without an explicit project may build and deploy into the wrong project.
The edge keeps calling the old service, and nothing changes except a stray
service in production. The transcoder script is especially easy to mis-run this
way because it derives its runtime service account from the target project.

Always pass the project explicitly, using the variable the script reads:

```bash
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-transcoder/deploy.sh
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-upload/deploy.sh
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-asr-parakeet/deploy.sh
GCP_PROJECT_ID=rich-compiler-479518-d2 ./scripts/deploy-cloud-function.sh
```

## Check live configuration before running a deploy script

Only `cloud-run-transcoder/deploy.sh` currently uses `--update-env-vars` and
`--update-secrets`, so unnamed keys are preserved for transcoder deploys. Keys it
*does* name are overwritten with the script's defaults, which may not match what
is running. Compare against the revision serving traffic, not the service's
`spec.template`, and read names rather than values:

```bash
REVISION="$(gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
traffic=json.load(sys.stdin).get('status',{}).get('traffic',[])
serving=[t for t in traffic if t.get('percent')]
print(max(serving,key=lambda t:t['percent']).get('revisionName','') if serving else '')
")"

gcloud run revisions describe "$REVISION" \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
c=json.load(sys.stdin)['spec']['containers'][0]
print('image:', c['image'])
print('env:', sorted(e['name'] for e in c.get('env',[]) if 'value' in e))
print('secrets:', sorted(e['name'] for e in c.get('env',[]) if 'valueFrom' in e))
"
```

Do not assume that safety applies to the other deploy paths yet:

- `cloud-run-upload/deploy.sh` still uses `--set-env-vars` and `--set-secrets`.
- `cloud-run-asr-parakeet/deploy.sh` still uses `--set-env-vars`.
- `scripts/deploy-cloud-function.sh` still uses `--set-env-vars`.
- `.github/workflows/ci.yml` still deploys `process-blob` with
  `--set-env-vars`, so every merge to `main` can replace live `process-blob`
  environment variables with the smaller CI set.

Never add new `--set-env-vars` or `--set-secrets` usage unless the command owns
the complete live configuration. Both replace the entire configuration and
silently drop live settings the deploy path does not name. PR #153 fixed this
for the transcoder script only; the other deploy paths still need the same
treatment; see issue #171.

## Exported shell variables override script defaults

The deploy scripts resolve every setting as `VAR="${VAR:-production-default}"`,
so an exported shell variable silently wins over the production default. On
2026-08-07 a shell with `GCS_BUCKET=divine-blossom-media-staging` exported
pointed the production transcoder at the staging bucket, where its service
account has no read access; every transcode failed with 403 for four and a
half hours.

Do not export deploy-time variables (`GCS_BUCKET`, `PROJECT_ID`, and friends)
from a shell profile. Set them inline on the one command that needs them.

After #195 merges, the transcoder and upload deploy scripts will run
`scripts/require-env-match.sh` after resolving their variables and before
building anything. It compares a named subset of fully resolved values against
the revision currently serving traffic and aborts the deploy when they differ;
re-run with `CONFIRM_ENV_CHANGES=1` when the change is intended. The check is a
backstop, not a substitute for passing `PROJECT_ID` explicitly: it uses the
resolved project to find the live service, and it skips when the service or
serving revision cannot be read. The comparison has to use resolved values: a
check that parses the default out of the script text cannot catch this failure
mode, because the whole failure is the default not applying.

## Staged rollout when the edge and a backend change together

The edge is already live by the time you start deploying the backend, so the
compatibility question is always "what does new edge do when the old backend
answers?" Where the edge has a receiver-side switch, set it before merging, not
after.

The derivative status generation guard is one such switch. See
[derivative-status-queue.md](../derivative-status-queue.md) for its rollout,
including the `REQUIRE_DERIVATIVE_STATUS_GENERATION` config-store key that must
be `false` while the transcoder is still an image that does not send
`generation`.

## Verifying a transcoder deploy landed

The transcoder does not report its version anywhere the edge can see. Confirm
from the Cloud Run side that the image tag on the revision serving traffic
matches the commit you deployed:

```bash
REVISION="$(gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
traffic=json.load(sys.stdin).get('status',{}).get('traffic',[])
serving=[t for t in traffic if t.get('percent')]
print(max(serving,key=lambda t:t['percent']).get('revisionName','') if serving else '')
")"

printf 'serving revision: %s\n' "$REVISION"
gcloud run revisions describe "$REVISION" \
  --project rich-compiler-479518-d2 --region us-central1 \
  --format='value(spec.containers[0].image)'
```

## A traffic rollback pins the service

`gcloud run services update-traffic --to-revisions=<revision>=100` rolls back
by pointing traffic at an explicit revision, and in doing so stops the service
from migrating to the latest revision. A later `gcloud run deploy` then creates
the new revision at 0% traffic while reporting success — the rollback target
keeps serving.

After any rollback, restore migration to latest explicitly:

```bash
gcloud run services update-traffic divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --to-latest
```

Until that runs, check where traffic actually is after every deploy:

```bash
gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 \
  --format='json(status.traffic)'
```

The same pinning is why the pre-deploy environment check compares against the
serving revision rather than the service's `spec.template`: after a rollback,
the spec still describes the newest rolled-back revision.
