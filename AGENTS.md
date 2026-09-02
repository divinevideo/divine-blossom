# Repository Guidelines

## Divine Context And Brain

Before broad product, architecture, protocol, cross-repo, service-boundary, or pull-request authoring, review, or modification work, read the shared Divine context primer.

Resolve the context directory and clone it there if it is missing:

```bash
CONTEXT_DIR="${DIVINE_CONTEXT_ROOT:-../divine-context}"
[ -e "$CONTEXT_DIR/.git" ] || gh repo clone divinevideo/divine-context "$CONTEXT_DIR"
```

Use that value as `<context-dir>` below.

The `divine-context` repo is private, so cloning requires GitHub access. If clone, network, or auth fails, continue from the local repo docs and avoid cross-repo assumptions.

Before updating an existing context checkout, verify it is clean and on its default branch. If it is clean and on the default branch, update it with `git -C <context-dir> pull --ff-only`. If it is dirty, on another branch, cannot fast-forward, or network/auth fails, leave it untouched and say the context may be stale.

Read `<context-dir>/AGENT_CONTEXT.md` and follow its instructions. If unavailable, continue from the local repo docs and avoid cross-repo assumptions.

Before working on a pull request, follow `<context-dir>/PR_REVIEW.md` and use `<context-dir>/PR_REVIEW_TEAMS.md` to request the normal team and check takeover authority. Ordinary review remains open to any eligible Divine human. Before modifying a pull-request branch, enforce the mapping and every takeover gate; if the mapping cannot be read, feedback-only review may continue but automated takeover must stop. Request and verify required human review automatically when tooling permits. If the runbook is unavailable, leave the pull request open and report the blocker.

If a Divine Brain search or ask tool is available, you may use it for company memory. Treat it as optional and credentialed: tool names vary by client, and work must continue when Brain is unavailable. When Brain results influence work, cite the returned document ids. Never commit Brain credentials or expose Brain-derived sensitive content in public PRs, issues, branch names, commit messages, code comments, logs, screenshots, release notes, or externally shared agent transcripts.

## Project Structure & Module Organization
- Fastly Compute edge service code lives under `src/`.
- Cloud Run services live under `cloud-run-upload/` and `cloud-run-transcoder/`.
- Blob processing and moderation webhook code lives under `cloud-functions/process-blob/`.
- Operational docs and rollout notes live in `README.md`, `OAUTH_SETUP.md`, and `docs/`.
- Deployment and environment config lives in `fastly.toml*`, `Dockerfile.local`, and service-specific config files. Verify current config before changing domains, buckets, or service bindings.

## Build, Test, and Validation Commands
- `./scripts/run-edge-tests.sh`: run the Fastly edge crate tests under Viceroy.
- `cargo check --tests --locked`: compile-check the Fastly edge crate tests.
- `cargo test --manifest-path cloud-run-upload/Cargo.toml --locked`: upload service tests.
- `cargo clippy --locked --all-targets --all-features`: lint gate used in CI.
- Use the relevant service-local test or validation command when touching `cloud-run-transcoder/` or `cloud-functions/process-blob/`.
- For deploy work, prefer local verification before any publish or deploy step.

## Coding Style & Naming Conventions
- Keep edge, upload, transcoder, and process-blob changes scoped. Do not mix unrelated services or deployment refactors in one PR.
- Follow the existing Rust, Python, and Fastly/GCP patterns already established in the repo.
- Verify domains, bucket names, and service identifiers against config files before introducing or changing URLs. Do not hardcode environment-specific values in application code.

## Security & Operational Notes
- Never commit secrets, API tokens, private keys, service credentials, or screenshots/logs containing sensitive values.
- Public issues, PRs, branch names, screenshots, and descriptions must not mention corporate partners, customers, brands, campaign names, or other sensitive external identities unless a maintainer explicitly approves it. Use generic descriptors instead.
- Before modifying or running `gcloud run deploy`, compare live environment-variable and secret-binding names with the command without reading values. `--set-env-vars` and `--set-secrets` replace all existing entries and may be used only when the script owns the complete configuration; otherwise use `--update-env-vars` and `--update-secrets`.
- Respect the existing deployment rule: use `fastly compute publish` for Fastly deploys, not separate build and deploy commands.

## Fastly Compute Deployment Rules

**ALWAYS use `fastly compute publish` instead of `fastly compute build` + `fastly compute deploy`.** The `publish` command does build+deploy in a single atomic operation.

### Deployment Workflow
```bash
fastly compute publish --comment "description"
```

### Key Lessons
- `fastly compute publish --comment "description"` is the correct way to deploy.
- Do NOT use `fastly compute deploy` separately.
- Local testing with `fastly compute serve` works correctly for verification.
- Do not purge the whole cache after routine deploys. Blob responses are content-addressed and carry their hash as a surrogate key; use `fastly purge --key <hash> --service-id pOvEEWykEbpnylqst1KTrR` when one object must be invalidated.
- A rare global purge must be an explicit manual CI run on `main` with the `purge_cache` input enabled.
- **Propagation can be SLOW** — Compute package propagation to all POPs can take several minutes after a publish. The version may show as "active" in the API while edge POPs still serve old code. Be patient.
- Remember it takes a few minutes for Fastly deploys to roll out; relax and let it happen.

## Pull Request Guardrails
- PR titles must use Conventional Commit format: `type(scope): summary` or `type: summary`.
- Set the correct PR title when opening the PR. Do not rely on fixing it later.
- If a PR title is edited after opening, verify that the semantic PR title check reruns successfully.
- Keep PRs tightly scoped. Do not include unrelated formatting churn, dependency noise, or drive-by refactors.
- Temporary or transitional code must include `TODO(#issue):` with a tracking issue.
- UI, API, or externally visible behavior changes should include screenshots, sample payloads, or an explicit note that there is no visual change.
- PR descriptions must include a summary, motivation, linked issue, and manual validation plan.
- Before requesting review, run the relevant checks for the files you changed, or note what you could not run.

## Topic files

- Before Fastly 5xx diagnosis, Pub/Sub diagnostics, or logging-endpoint work, read `docs/runbooks/fastly-5xx.md`.
- Before a Compute publish, outer VCL activate, or cache purge, read `docs/runbooks/rollback.md`.
- Before creating or inspecting a Fastly Google Pub/Sub logging endpoint, read `docs/runbooks/edge-upload-observability.md`. Do not run `fastly logging googlepubsub list --json` or `describe`.
- Before `gcloud run deploy`, read `docs/runbooks/deployment.md`.
