# Compilation Service Managed Deployment Implementation Plan

> **For agentic workers:** Execute this plan with the test-driven-development
> and verification-before-completion skills. Do not deploy production resources
> while implementing the plan.

**Goal:** Make `divine-iac-coreconfig` the authoritative owner of the private
production compiler service and its internal edge, with image promotion from
`divine-blossom-stt`.

**Architecture:** A production Terragrunt stack instantiates a reusable
OpenTofu module for Cloud Run v2 GPU, IAM, Firestore indexes, secret containers,
Cloudflare DNS, and Cloudflare Access. Application CI builds immutable artifacts
and opens an image-promotion PR in coreconfig. Wrangler deploys the Worker code;
it does not own DNS or Access.

**Design:** `docs/superpowers/specs/2026-07-26-compilation-deployment-design.md`

---

## Task 1: Add a failing infrastructure contract test

**Repository:** `divine-iac-coreconfig`

**Files:**

- Create: `tests/compiler_service_infrastructure_test.py`

1. Write a standard-library `unittest` contract that requires:
   - Exactly `main.tf`, `variables.tf`, `outputs.tf`, and `versions.tf` in the
     compiler module.
   - A production-only Terragrunt stack.
   - Cloud Run v2 with one NVIDIA L4, 8 CPU, 32 GiB, private ingress/IAM,
     minimum one and maximum two instances, and digest-pinned image input.
   - Runtime and edge service accounts with least-privilege IAM.
   - Secret containers without secret payload resources.
   - Both required Firestore composite indexes.
   - Cloudflare proxied DNS and a staff-domain Access policy.
2. Run the test and confirm it fails because the module does not exist.
3. Commit the red test with the implementation or retain the red result in the
   verification notes.

## Task 2: Implement the compiler OpenTofu module

**Repository:** `divine-iac-coreconfig`

**Files:**

- Create: `infrastructure/modules/compiler-service/main.tf`
- Create: `infrastructure/modules/compiler-service/variables.tf`
- Create: `infrastructure/modules/compiler-service/outputs.tf`
- Create: `infrastructure/modules/compiler-service/versions.tf`

1. Enable Cloud Run, Firestore, Secret Manager, IAM Credentials, and required
   supporting APIs.
2. Create separate runtime and edge service accounts.
3. Create secret containers for the output Nostr signing key and edge
   credential without creating secret versions.
4. Grant the runtime account Firestore access and accessor permission only on
   the output-key secret.
5. Create a Cloud Run v2 service with the approved GPU, sizing, scaling,
   execution, and environment configuration.
6. Grant `roles/run.invoker` only to the edge service account.
7. Create the two Firestore composite indexes.
8. Read the existing Cloudflare token from Secret Manager, locate the production
   zone, create proxied compiler DNS, and create the Access application/policy.
9. Output only non-sensitive operational identifiers.
10. Run the contract test until green.

## Task 3: Instantiate production

**Repository:** `divine-iac-coreconfig`

**Files:**

- Create:
  `infrastructure/environments/production/compiler-service/terragrunt.hcl`
- Modify: `.github/workflows/terragrunt-infra-workflow.yaml`

1. Instantiate only in production using `dv-platform-prod`, `us-central1`, and
   `compiler.divine.video`.
2. Use the production Artifact Registry and a placeholder bootstrap image that
   must be replaced by a digest before apply.
3. Add `compiler-service` to the infrastructure workflow's changed-module
   detection.
4. Run formatting, the contract test, and Terragrunt validation without apply.

## Task 4: Add compiler image promotion

**Repository:** `divine-iac-coreconfig`

**Files:**

- Modify: `.github/workflows/image-deploy.yaml`
- Modify: `tests/compiler_service_infrastructure_test.py`

1. Extend the existing dispatch allowlist with application
   `divine-compiler`, image `divine-compiler`, and production-only targeting.
2. Require a valid `sha256:<64 hex>` digest for this application.
3. Update only the compiler production Terragrunt image reference.
4. Stage the HCL file in the generated deployment PR.
5. Keep production review and semantic-PR guardrails intact.
6. Extend and pass the contract test for this dispatch path.

## Task 5: Replace imperative application deployment

**Repository:** `divine-blossom-stt`

**Files:**

- Create: `.github/workflows/compiler-release.yml`
- Delete: `cloud-run-compiler/deploy.sh`
- Modify: `compiler-web/wrangler.jsonc`
- Modify: compiler deployment documentation as required

1. Add compiler Rust tests, clippy, web tests, and web build to the release
   workflow.
2. Authenticate to GCP with the repository's production Workload Identity
   Federation configuration.
3. Build and push `cloud-run-compiler` to production Artifact Registry with a
   source-SHA tag.
4. Capture the immutable image digest and dispatch the existing coreconfig
   `image-deploy` event using the established GitHub App credentials.
5. Deploy the Worker bundle with Wrangler using repository-managed secrets and
   variables after checks pass.
6. Remove the imperative Cloud Run deployment script so it cannot drift from
   coreconfig.
7. Validate the workflow syntax and all application test suites.

## Task 6: Documentation and full verification

**Repositories:** both

1. Document first-time secret population and required GitHub variables by name,
   never by value.
2. Document deploy and rollback through image-promotion PRs.
3. Run:
   - `python3 -m unittest tests/compiler_service_infrastructure_test.py`
   - `tofu fmt -recursive infrastructure/`
   - `terragrunt init` and `terragrunt validate` for the production compiler
     stack.
   - Compiler Rust tests and clippy.
   - Compiler web tests and production build.
   - YAML/JSON syntax checks for changed workflow and Wrangler files.
4. Inspect diffs for secret material and unrelated changes.
5. Commit and push the scoped coreconfig and application branches.

