# Compilation Service Deployment: Design Spec

**Status:** Approved
**Date:** 2026-07-26
**Site:** `https://compiler.divine.video`
**Application repository:** `divinevideo/divine-blossom-stt`
**Infrastructure repository:** `divinevideo/divine-iac-coreconfig`

## Goal

Deploy the internal compilation editor and its GPU renderer through Divine's
canonical management systems. Infrastructure must be declarative, reviewable,
and owned by `divine-iac-coreconfig`; application artifacts remain owned by
their source repository.

## Ownership

### `divine-iac-coreconfig`

OpenTofu and Terragrunt own:

- The production Cloud Run v2 service and NVIDIA L4 allocation.
- Runtime and edge service accounts, IAM, and private invocation.
- Firestore indexes used by compilation jobs.
- Secret Manager containers and least-privilege secret access.
- The `compiler.divine.video` Cloudflare DNS record.
- The Cloudflare Access application and staff-only policy.
- The production image digest selected for Cloud Run.

Infrastructure changes are applied with `tofu` through the existing Terragrunt
workflow. The module is production-only until a real non-production compiler
environment is requested.

### `divine-blossom-stt`

The application repository owns:

- `cloud-run-compiler/` source and container image.
- `compiler-web/` source and Cloudflare Worker bundle.
- Tests and build workflows for both artifacts.
- A release dispatch that proposes a pinned compiler image digest in
  `divine-iac-coreconfig`.

The application workflow may publish artifacts, but it does not imperatively
create or mutate Cloud Run, IAM, Firestore, DNS, or Access resources.

### `divine-upload-server`

`upload.divine.video` is provided by the GKE-hosted
`divinevideo/divine-upload-server`, not the historical `cloud-run-upload/`
directory in this repository.

Its current resumable completion path stores the finalized object without
starting thumbnail, HLS, or transcription derivatives. Compiler outputs use
that existing path. No upload-server change is required for the compiler
deployment.

## Runtime Architecture

```text
staff browser
    |
    v
Cloudflare Access
    |
    v
compiler-web Worker and static assets
    |
    | Google-signed identity token
    v
private Cloud Run v2 compiler
    |
    +--> Firestore
    +--> Divine relays and media
    +--> upload.divine.video resumable API
```

Cloudflare Access authenticates staff. The Worker is the only Cloud Run
invoker and forwards the Access identity after authenticating to Google.
Cloud Run remains unreachable to unauthenticated browsers.

## Cloud Run Configuration

The production service uses:

- Region `us-central1`.
- 8 vCPU and 32 GiB memory.
- One NVIDIA L4 GPU per instance.
- Generation 2 execution environment.
- CPU available outside request handling so the asynchronous job worker runs.
- Minimum one and maximum two instances initially.
- Private invocation with an explicit edge service-account invoker.
- A container image pinned by immutable digest, never `latest`.

The runtime service account receives only the Firestore and Secret Manager
permissions needed by the compiler.

## Secrets

OpenTofu creates secret containers and IAM bindings, not secret payloads.
Operators populate the compiler output signing key and the edge credential
through the established secret-management procedure. Secret values are never
committed, printed, decoded, or exposed as outputs.

The edge credential remains a Cloudflare Worker secret. The service-account
public identity and Cloud Run audience are normal Worker variables.

## Cloudflare Boundary

OpenTofu owns the proxied DNS record and Cloudflare Access policy. The Worker
script and static asset bundle are application artifacts deployed by the
application repository with Wrangler.

This preserves a clean boundary: coreconfig declares the hostname and who may
reach it; the application repository supplies the code served there.

## Deployment Flow

1. Application CI tests the Rust service and web application.
2. CI builds and pushes the compiler image to production Artifact Registry.
3. CI resolves the pushed image digest.
4. CI dispatches a compiler image promotion to `divine-iac-coreconfig`.
5. Coreconfig opens a conventional-commit PR updating the production digest.
6. Review and merge run the Terragrunt infrastructure workflow.
7. The web artifact is deployed with Wrangler after application checks pass.

The old `cloud-run-compiler/deploy.sh` is not an authoritative deployment path
and is removed once the managed flow is present.

## Rollback

Cloud Run rollback is a coreconfig PR restoring the previous image digest.
Worker rollback uses the previous Wrangler deployment version. Neither rollback
changes list events or compilation output blobs.

## Out of Scope

- A public compiler.
- A staging hostname created only for symmetry.
- Moving compilation onto GKE GPU nodes.
- Publishing compilations as Divine posts.
- Direct publication to external social platforms.
