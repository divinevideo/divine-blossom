# Fastly 5xx Diagnostics

Use this runbook to correlate failures across the outer VCL caching service and
the inner Compute service. Service chaining can make one request appear in both
services, so compare each service over the same UTC window rather than adding
their 5xx counts together.

Failed uploads additionally carry per-upload records on the separate
`edge_upload_logs` sink; see the [edge upload observability
runbook](edge-upload-observability.md). Both records share one correlation
value, keyed `request_id` here and `req_id` there, and label a given
`BlossomError` with the same `kind()` vocabulary.

## Repository State

The repository contains, but does not activate or configure:

- `vcl/recv.vcl`, which preserves a non-empty caller `X-Request-Id`, creates a
  UUID when it is absent or sanitizes to empty, and forwards the header to
  Compute.
- `vcl/error.vcl`, an `vcl_error` snippet that writes every Fastly-generated
  5xx (`obj.status` 500–599) to the endpoint named `vcl-error-diagnostics`.
  The client-facing synthetic JSON response remains 503-only; other 5xx
  statuses keep Fastly's default error delivery.
- Error-only Compute request logging to the endpoint named
  `compute-diagnostics` with the sanitized request ID, method, normalized route,
  final status, available error category, and duration. Routine successful and
  client-error responses are not persisted. Rust panics are moved (not copied)
  to `compute-diagnostics` via `fastly::log::set_panic_endpoint`: once that
  endpoint exists on the service, panic text is written there and no longer
  appears on stderr / `log-tail`. While the endpoint is absent, the call fails
  open and panics keep their default stderr output. A panic record carries only
  the panic message — no request ID or schema — so correlate it with outer VCL
  records by UTC timestamp and POP, not by request ID.

Neither endpoint is created by repository code. Compute logging fails open when
`compute-diagnostics` is unavailable. The outer VCL source is not deployed by
the Compute publish workflow and has no effect until an operator activates it.

## Log Schemas

`divine.blossom.vcl_error.v1` records the request start timestamp, sanitized
request ID, service ID, status, original `obj.response`, POP, selected backend,
cache state, restart count, and elapsed milliseconds for every Fastly-generated
5xx that reaches `vcl_error`. It does not record a URL, query string, client
address, authorization, cookies, or body.

The outer service copies the selected caller/generated ID to the private
`X-Divine-Edge-Request-Id` request header before chaining so a later Compute
sanitization cannot change the VCL-side correlation value. Both services cap
the sanitized ID at 64 characters, so common caller IDs — UUIDs, W3C trace
ids, `traceparent` values — are preserved verbatim across both services;
longer caller values are preserved as their sanitized 64-character prefix, so
caller-side correlation for those is prefix-match only. `vcl/deliver.vcl`
removes that private header from client responses.
When a caller supplies only characters outside the allowed request-ID charset,
the outer service generates a fallback UUID and writes it to both
`X-Request-Id` and `X-Divine-Edge-Request-Id`.

`divine.blossom.compute_request.v1` records the sanitized request ID, method,
normalized route category, final status, available backend/error category, and
Compute duration in milliseconds for every final 5xx response. This includes
storage, metadata, and internal failures without making persistent ingestion
scale with successful request volume. A route category never contains a path
parameter or query string.

This change deliberately removes the old unconditional `[BLOSSOM ROUTE]`
stderr line, which logged every request's method, full path, and host to the
ephemeral Compute log. Route visibility now exists only as the route category
in persisted 5xx records; routine traffic writes no per-request route log.
Operators who relied on `[BLOSSOM ROUTE]` in `log-tail` for live debugging no
longer have it at any status.

Do not point either schema at `cdn-view-logs`; that stream has a separate
view-counting contract.

## Later Fastly Configuration

An operator must complete all of the following before persistent diagnostics can
work:

1. Create restricted real-time logging endpoints named exactly
   `vcl-error-diagnostics` on the outer service and `compute-diagnostics` on the
   Compute service. Set retention and access ownership in the destination.
2. Add `vcl/recv.vcl` as a `recv` snippet, `vcl/error.vcl` as an `error`
   snippet, and `vcl/deliver.vcl` as a `deliver` snippet on a cloned
   outer-service version. Each file is the body Fastly inserts into the
   corresponding subroutine. Keep automatic log placement disabled for
   `vcl-error-diagnostics`; the error snippet emits only the selected failures.
3. Compile the cloned version, confirm the generated VCL contains all three
   snippets once in their named subroutines, and review the diff before
   activation.
4. Activate the separately validated outer VCL version first, then publish the
   Compute package through the repository deployment path. After activation,
   set the GitHub Actions repository variable
   `FASTLY_OUTER_DIAGNOSTICS_ACTIVE=true`; it is absent/off by default and gates
   both automatic and manually requested Compute publishes. A missing or false
   value makes the deploy job fail visibly without publishing. If the merge
   happened while the gate was off, run the `CI` workflow with
   `publish_compute` enabled after setting the variable. This order is
   required because Compute may emit internal response metadata that the deliver
   snippet strips; publishing Compute first can expose those headers until the
   outer version is active.
5. Validate each failure stage separately with approved, controlled requests.
   Confirm a Compute 5xx preserves its supplied request ID (verbatim for
   IDs up to 64 characters after sanitization; longer IDs keep a 64-character
   prefix). Confirm an all-filtered request ID generates one shared fallback ID
   in both `X-Request-Id` and `X-Divine-Edge-Request-Id`. Confirm an outer
   backend failure preserves its supplied request ID and `obj.response` without
   producing a matching Compute record. Confirm the existing 503 status, JSON
   body, content type, and CORS header remain unchanged.
6. Create separate outer `status_5xx_rate` and inner
   `compute_resp_status_5xx_rate` alerts with minimum request thresholds. Add a
   low-volume absolute 5xx alert only if sustained small failures require it.
   Choose thresholds from approved operational requirements rather than this
   repository; no alert or threshold is configured by these sources.

Do not create service versions or inject failures merely to validate a source
change locally. Exact VCL compilation, endpoint delivery, retention/access, and
cross-service production correlation remain operator validation.

## Triage

- An outer VCL 5xx with no matching Compute record means one of two things:
  the request failed before Compute completed, **or** Compute terminated
  without returning — a Rust panic (plain panic message on
  `compute-diagnostics`, matched by timestamp/POP rather than request ID), a
  guest trap or OOM, or a wall-clock timeout (which may leave no Compute
  record at all). Do not treat a missing Compute record as proof the request
  never reached Compute.
- A matching Compute 5xx identifies an application or origin-side failure; use
  its normalized error category without assuming the VCL record is a second
  independent request.
- POP-local VCL failures without matching Compute failures are evidence to
  include in a Fastly support case together with UTC windows, service IDs,
  `obj.response`, cache state, and request IDs.

Never add stale serving, blind retries, health checks, failover, shielding, or
routing changes as an unreviewed diagnostic response.
