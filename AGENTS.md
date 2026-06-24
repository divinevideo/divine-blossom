# Repository Guidelines

## Project Structure & Module Organization
- Fastly Compute edge service code lives under `src/`.
- Cloud Run services live under `cloud-run-upload/` and `cloud-run-transcoder/`.
- Blob processing and moderation webhook code lives under `cloud-functions/process-blob/`.
- Operational docs and rollout notes live in `README.md`, `OAUTH_SETUP.md`, and `docs/`.
- Deployment and environment config lives in `fastly.toml*`, `Dockerfile.local`, and service-specific config files. Verify current config before changing domains, buckets, or service bindings.

## Build, Test, and Validation Commands
- `cargo check --tests --locked`: check the Fastly edge crate.
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
- Respect the existing deployment rule: use `fastly compute publish` for Fastly deploys, not separate build and deploy commands.

## Fastly Compute Deployment Rules

**ALWAYS use `fastly compute publish` instead of `fastly compute build` + `fastly compute deploy`.** The `publish` command does build+deploy in a single atomic operation.

### Deployment Workflow
```bash
fastly compute publish --comment "description" && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

### Key Lessons
- `fastly compute publish --comment "description"` is the correct way to deploy.
- Do NOT use `fastly compute deploy` separately.
- Local testing with `fastly compute serve` works correctly for verification.
- **CRITICAL: Always purge after deploy!** Run `fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR` after publishing.
- **Propagation can be SLOW** — even after purge, Compute package propagation to all POPs can take several minutes. The version may show as "active" in the API but edge POPs may still serve old code. Be patient.
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
