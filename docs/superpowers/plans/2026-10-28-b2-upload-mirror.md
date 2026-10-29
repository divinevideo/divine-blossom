# B2 upload mirror implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this authorized continuation. Steps use checkbox syntax for tracking.

**Goal:** Durably queue new canonical GCS uploads for verified B2 copying while independently discovering and backfilling historical originals.

**Architecture:** GCS OBJECT_FINALIZE -> dedicated Pub/Sub subscription -> persistent worker queue -> existing approved-video copy path. A bounded fair scheduler shares each pass with historical discovery/reconciliation. GCS stays authoritative.

**Tech Stack:** Python/SQLite, Google Pub/Sub REST with existing google-auth dependency, OpenTofu, suspended GKE CronJob.

**Spec:** docs/superpowers/specs/2026-10-28-b2-upload-mirror-design.md

## Global constraints

No upload response changes, default GCS selection changes, new provider dependencies, secret output, automatic schedule activation, weakened moderation, or automatic erasure-gate recovery. No existing bucket notifications or IAM bindings may be replaced.

## Review focus

- An event acknowledged before SQLite commit must never lose an upload.
- Duplicate/out-of-order events and pending moderation must survive restart.
- New uploads must not starve historical reconciliation, or vice versa.
- Queue tokens/ack IDs and media identifiers must not leak through reports/errors.
- IAM and notification configuration must be additive and restricted to the named resources.

## Task 1: Durable upload queue and fair worker scheduling

- [ ] Add failing tests in scripts/tests/test_sync_b2_originals.py for durable ingest/ack, duplicate generations, restart, deferred moderation, poison messages, byte bounds and fairness.
- [ ] Add a Pub/Sub adapter with fixed HTTPS origin and bounded pull/ack; reuse existing google-auth rather than adding dependencies.
- [ ] Extend State and Worker.cycle with durable queued candidates, deferred retries and separate discovery limits. Preserve existing CLI behavior without a subscription.
- [ ] Add optional --notification-subscription and --discovery-limit arguments, input bounds, aggregate counters, and document both new uploads and historical catchup.
- [ ] Run isolated SDK-backed worker tests and script checks; commit the implementation.

## Task 2: Additive event infrastructure and runner configuration

- [ ] In an isolated divine-iac-coreconfig worktree add a standalone module and mocked tests for a dedicated topic/subscription, exact subscriber/publisher IAM and source OBJECT_FINALIZE notification.
- [ ] Extend the suspended renderer with optional subscription/discovery settings, preserving default schedule/budgets. Include aggregate queue counters in run.py.
- [ ] Add renderer/run-wrapper contracts; run unit tests, OpenTofu tests/validation and relevant CI.
- [ ] Pin the worker source to the reviewed Blossom implementation when packaging it; document dependency/activation order.

## Task 3: Review and delivery

- [ ] Commit/push both branches, open linked focused PRs, request Platform once per PR.
- [ ] Obtain fresh complete-diff adversarial review; resolve findings, publish review conclusions and inspect required checks.
- [ ] Hand back concrete code/CI status and remaining live gates. No production copy schedule enabled by merge alone.
