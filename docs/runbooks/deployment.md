# Deployment

Some of this repository deploys itself and some of it does not. Merging to `main`
publishes the Fastly edge service to production within minutes, with no human
step. The Cloud Run services do not ship that way — each one is a script someone
runs by hand.

That asymmetry is the thing to plan around. Any change that spans the edge and a
Cloud Run service goes out in two stages, the edge first, and there is a window
where new edge code is talking to an old backend.

## What ships automatically

`.github/workflows/ci.yml` runs on every push to `main` and deploys, in parallel:

- the edge service to Fastly (`fastly compute publish`), followed by a CDN purge
- `process-blob` to Cloud Run
- the container image to GHCR

## What ships by hand

Nothing below is in CI. Each is a script you run yourself.

| Service | Script |
| --- | --- |
| `divine-transcoder` | `cloud-run-transcoder/deploy.sh` |
| upload service | `cloud-run-upload/deploy.sh` |
| Parakeet ASR | `cloud-run-asr-parakeet/deploy.sh` |
| cloud function | `scripts/deploy-cloud-function.sh` |

## The Cloud Run services are not in the production project

The edge hardcodes its backends to project number `149672065768`:

```rust
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";
const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
```

That is the proof-of-concept project `rich-compiler-479518-d2`, not
`dv-platform-prod`. See issue #32, which is open and tracks moving them.

Every deploy script defaults `PROJECT_ID` to whatever your active `gcloud`
configuration points at. If your context is `dv-platform-prod` — the normal case
— running a script without an explicit project builds and deploys into the wrong
project. The deploy appears to succeed, the edge keeps calling the old service,
and nothing changes except a stray service in production.

Always pass the project explicitly:

```bash
PROJECT_ID=rich-compiler-479518-d2 ./cloud-run-transcoder/deploy.sh
```

## Check live configuration before running a deploy script

The scripts use `--update-env-vars` and `--update-secrets`, so keys they do not
name are preserved. Keys they *do* name are overwritten with the script's
defaults, which may not match what is running. Compare before you deploy, and
read names rather than values:

```bash
gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 --format=json \
  | python3 -c "
import json,sys
c=json.load(sys.stdin)['spec']['template']['spec']['containers'][0]
print('image:', c['image'])
print('env:', sorted(e['name'] for e in c.get('env',[]) if 'value' in e))
print('secrets:', sorted(e['name'] for e in c.get('env',[]) if 'valueFrom' in e))
"
```

Never use `--set-env-vars` or `--set-secrets` in these scripts. Both replace the
entire configuration and silently drop live settings the script does not know
about. That bug was fixed in #153; do not reintroduce it.

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
from the Cloud Run side that the image tag matches the commit you deployed:

```bash
gcloud run services describe divine-transcoder \
  --project rich-compiler-479518-d2 --region us-central1 \
  --format='value(spec.template.spec.containers[0].image)'
```
