# Deployment

Some of this repository deploys itself and some of it does not. After tests pass,
merging to `main` publishes the Fastly edge service to production within minutes,
with no human step. Most Cloud Run services do not ship that way — each one is a
script someone runs by hand.

The VCL caching layer is also manual. Files under `vcl/` are source copies of
snippets for the outer Fastly VCL service; the Compute publish job does not
activate them. Apply and validate those snippets in a cloned VCL service version,
then activate that version separately. The VCL changes themselves have no
production effect until that activation happens. CI still republishes and purges
the Compute service after any merge to `main`, including a VCL-only merge.

That asymmetry is the thing to plan around. Any change that spans the edge and a
Cloud Run service goes out in two stages, the edge first, and there is a window
where new edge code is talking to an old backend.

## What ships automatically

`.github/workflows/ci.yml` runs on every push to `main`. After the `test` job
passes, it deploys, in parallel:

- the edge service to Fastly (`fastly compute publish`), followed by a CDN purge
- `process-blob` to Cloud Run
- the container image to GHCR

The Fastly publish and purge target the Compute service. They do not deploy or
purge the outer VCL caching service. See [Fastly 5xx
diagnostics](fastly-5xx.md) for the separate logging endpoint and VCL activation
work required by the diagnostic sources in this repository.

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

`cloud-run-transcoder/deploy.sh` and the CI `process-blob` job use
`--update-env-vars`; the transcoder script also uses `--update-secrets`. Unnamed
keys are therefore preserved for those deploys. Keys they *do* name are
overwritten with the deploy path's values, which may not match what is running.

`gcloud run deploy` creates or updates the *service*, and `--update-env-vars`
merges its pairs onto the service's `spec.template`. The template is therefore
the baseline the next deploy merges onto, and it is what this check has to read.
Read names rather than values:

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

The template is not necessarily what production is running: after a traffic
rollback the two diverge. See [A traffic rollback pins the
service](#a-traffic-rollback-pins-the-service) for that case, and read the
serving revision when the question is what production is answering with rather
than what the next deploy will merge onto.

Current configuration-preservation status by deploy path:

- `cloud-run-upload/deploy.sh` still uses `--set-env-vars` and `--set-secrets`.
- `cloud-run-asr-parakeet/deploy.sh` still uses `--set-env-vars`.
- `scripts/deploy-cloud-function.sh` still uses `--set-env-vars`.
- `.github/workflows/ci.yml` deploys `process-blob` with `--update-env-vars`,
  preserving keys that the workflow does not manage.

Never add new `--set-env-vars` or `--set-secrets` usage unless the command owns
the complete live configuration. Both replace the entire configuration and
silently drop live settings the deploy path does not name. PR #153 fixed the
transcoder script; the remaining manual deploy paths still need the same
treatment; see issue #171.

The CI `process-blob` job also sets the service's runtime identity explicitly:
it deploys with `--service-account="$GCP_RUNTIME_SERVICE_ACCOUNT"`, read from
the `GCP_RUNTIME_SERVICE_ACCOUNT` repository secret, and the step fails before
`gcloud` runs when that secret is unset. The deploy job cannot succeed until
the secret is created and the paired IaC change (divine-iac-coreconfig#1767)
is applied.

## Exported shell variables override script defaults

The three hand-run Cloud Run deploy scripts resolve most settings as
`VAR="${VAR:-production-default}"`, so an exported shell variable silently wins
over the production default. `scripts/deploy-cloud-function.sh` resolves its
project differently — it requires `GCP_PROJECT_ID` and exits if it is unset — but
it is not exempt from the trap: its bucket and region come from exported
`GCS_BUCKET_NAME` and `GCS_REGION`. A different variable name is not immunity,
it is the same trap wearing a different name, and it lands on the one service
with two competing deploy paths.

On 2026-08-07 a shell with `GCS_BUCKET=divine-blossom-media-staging` exported
pointed the production transcoder at the staging bucket, where its service
account has no read access; every transcode failed with 403 for four and a
half hours.

Do not export deploy-time variables (`GCS_BUCKET`, `PROJECT_ID`, and friends)
from a shell profile. Set them inline on the one command that needs them.

Nothing in this repository checks a deploy's resolved variables against what is
running, so there is no automated backstop for this trap today. The
configuration check above will not catch it either: that check deliberately
reads names and not values, so a `GCS_BUCKET` aimed at the staging bucket looks
identical to one aimed at production.

What does catch it is checking your own shell before you deploy. Read the
variable names straight out of the scripts so the list cannot drift, and test
whether each one is exported without printing any value. Run this from the
repository root:

```bash
for script in cloud-run-transcoder/deploy.sh cloud-run-upload/deploy.sh \
              cloud-run-asr-parakeet/deploy.sh scripts/deploy-cloud-function.sh; do
  for v in $(sed -n 's/^[A-Z_][A-Z0-9_]*="\{0,1\}\${\([A-Z_][A-Z0-9_]*\):-.*/\1/p' "$script"); do
    printenv "$v" >/dev/null && echo "$v is exported — $script would use your value"
  done
done
```

That captures the name on the *right* of the `:-`, which is the name `printenv`
is being asked about. It matters: `scripts/deploy-cloud-function.sh` assigns
`BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"`, where the two sides differ, so
a pattern keyed to the left-hand name would miss exactly the variable that can
misdirect `process-blob`.

`GCS_BUCKET` is not the only variable that can bite this way. The transcoder
script alone resolves 27 settings from the environment, and several have names
generic enough to be sitting exported in a working shell for unrelated reasons —
an exported `MAX_INSTANCES` or `CONCURRENCY` silently reshapes production
capacity exactly the way the exported `GCS_BUCKET` silently redirected storage.
Deriving the list is what keeps this check honest as the scripts grow.

Whoever adds an automated guard: it has to compare *fully resolved* values, and
it has to run after the script resolves its variables and before it builds
anything. A check that parses the *defaults* out of the script text cannot catch
this failure mode, because the whole failure is the default not applying.
(Reading variable *names* out of the script, as the shell check above does, is a
different and safe operation: what it looks for lives in the operator's
environment, not in the script's text.)

Such a guard's comparison baseline is the revision currently serving traffic, not
`spec.template` — the question it asks is "am I about to change what production
is running?", which is the serving revision's question, not the merge baseline's.

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

if [ -z "$REVISION" ]; then
  echo 'no revision is serving traffic'
else
  printf 'serving revision: %s\n' "$REVISION"
  gcloud run revisions describe "$REVISION" \
    --project rich-compiler-479518-d2 --region us-central1 \
    --format='value(spec.containers[0].image)'
fi
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

This pinning is also why the two checks above read different places. After a
rollback, the service's `spec.template` describes the newest revision *created*,
which is not the one serving traffic. The pre-deploy configuration check reads
`spec.template`, because that is the baseline the next deploy merges onto. The
deploy-landed check reads the serving revision, because that is what production
is answering with. Do not substitute one for the other — during a pinned window
they give different answers, and each is the wrong answer to the other's
question.
