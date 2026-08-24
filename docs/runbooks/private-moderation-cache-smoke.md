# Private moderation cache smoke

Run `scripts/smoke-private-moderation-cache.sh` after an edge deploy to verify
that deployed routing, authorization, and cache headers preserve private and
hidden moderation behavior.

The probe covers four dedicated synthetic video fixtures in `Restricted`,
`AgeRestricted`, `Banned`, and `Deleted` state. For each status it checks the
blob, thumbnail, extracted audio, and HLS master routes. Anonymous checks use
both `GET` and `HEAD`; credentialed checks use `GET`, because the current `HEAD`
handlers intentionally have no request or admin auth context.

## Required inputs

Inject these values from an operator-controlled credential manager or a CI
environment with equivalent protected secret bindings:

| Variable | Purpose |
| --- | --- |
| `OWNER_NSEC` | Signing key for the dedicated synthetic fixture owner |
| `ADMIN_TOKEN` | Admin bearer token used to verify moderation bypass responses |
| `RESTRICTED_HASH` | Synthetic fixture currently classified `Restricted` |
| `AGE_RESTRICTED_HASH` | Synthetic fixture currently classified `AgeRestricted` |
| `BANNED_HASH` | Synthetic fixture currently classified `Banned` |
| `DELETED_HASH` | Synthetic fixture currently soft-deleted as `Deleted` |
| `DOMAIN` | Optional target host; defaults to `media.divine.video` |

The script requires `curl` and the Nostr army knife from
`github.com/fiatjaf/nak`. Another utility with the same `nak` executable name
does not satisfy the prerequisite; the script verifies the CLI identity before
handling credentials.

Do not put these values in this repository, command history, CI logs, issue or
pull-request prose, or shared fixture documentation. The script turns off shell
tracing before handling them; the calling shell or CI wrapper must also avoid
printing injected values.
It writes the admin header only to a mode-600 temporary curl config and removes
the file on exit. `nak` receives the owner key through its documented
`NOSTR_SECRET_KEY` environment input, not a command-line argument, and uses it
only to sign fresh, URL-bound NIP-98 requests.

For a local operator run, use the team's approved credential manager to inject
the variables directly into the process without sourcing a plaintext file. The
exact command depends on that manager; verify all six required variable names
are bound before starting the script.

The probe does not deploy, change moderation status, purge caches, or rotate
credentials. It is not strictly read-only: derivative GET handlers may repair
metadata or source-reference records, clear a stale audio mapping, synchronously
extract missing audio, or trigger missing thumbnail/HLS generation. Provision
and verify every derivative before the run to avoid intentionally exercising
those repair paths, but treat the probe as capable of production writes.

## Synthetic fixture provisioning

Provision fixtures through the normal upload and moderation paths in a
controlled maintenance session. This setup changes live state and is separate
from the smoke command:

1. Generate four distinct, small, unmistakably synthetic videos. Each needs a
   thumbnail, completed HLS master, and extracted audio. Do not derive them from
   creator media; content-addressed copies of identical bytes are one fixture,
   not four.
2. Upload all four using one dedicated test-owner key. Ensure the synthetic
   events permit audio reuse so `/<hash>.audio.m4a` is a supported route.
3. Wait until thumbnail, HLS, and audio requests all return `200` while the
   fixtures are active.
4. Classify the copies as `Restricted`, `AgeRestricted`, `Banned`, and soft
   `Deleted`. Soft deletion is required so the admin bypass can still read the
   preserved bytes and derivatives.
5. Store the four hashes with the credential namespace, outside the repository.
   Although hashes are not credentials, keeping the complete fixture manifest
   together prevents accidental substitution of real creator media.
6. Run the smoke and confirm the admin base-blob response reports each expected
   `X-Moderation-Status`. This detects stale or misclassified fixtures.

Never use a real creator identifier, key, or blob as a fixture. Never change a
fixture's status merely to make a failing smoke pass; investigate the deployed
behavior first.

## Rotation

Rotate the dedicated owner key and admin token under the normal operational
credential process. Re-provision all four fixtures when rotating the owner key,
when any derivative is missing, or when fixture bytes are removed. Update the
external namespace atomically, run the smoke against the new set, then retire
the old fixtures and credentials. No rotation value or fixture hash belongs in
git history.

## Expected behavior

| Status | Anonymous GET/HEAD | Owner GET | Admin GET |
| --- | --- | --- | --- |
| `Restricted` | `404`; browser `no-store` | `200`; `private, no-store` | `200`; `private, no-store` |
| `AgeRestricted` | `401`; never a shared-cache hit | `200`; `private, no-store` | `200`; `private, no-store` |
| `Banned` | `404`; browser `no-store` | `404` | `200`; `private, no-store` |
| `Deleted` | `404`; browser `no-store` | `404` | `200`; `private, no-store` |

Before this matrix, the probe uses the existing fixtures as credential positive
controls. An owner request must pass the `AgeRestricted` fixture to prove NIP-98
authentication and the `Restricted` fixture to prove ownership. An admin request
must bypass the `Banned` fixture. These failures are reported as credential
problems instead of moderation regressions.

The audio route also depends on the fixture's audio-reuse permission and on a
successful Funnelcake lookup. An unexpected `403` is reported as fixture drift;
an unexpected `503` is reported as a dependency outage. Neither is reported as
an access-matrix regression.

The same expectation is applied twice to blob, thumbnail, audio, and HLS master
routes so a response accidentally stored on the first request is detected on
the second. Each owner/admin check uses a run-specific query string, then makes
an anonymous request to both the exact same URL and the bare route URL. These
checks detect credentialed bytes leaking through either the full query-bearing
cache key or a query-normalized cache key. A successful credentialed response
must not report a shared `X-Cache: HIT`. Authorization currently makes the outer
VCL pass the request, so the post-credential anonymous checks are the primary
shared-cache leak coverage; the credentialed `X-Cache` assertion is defense in
depth.

The public VCL service intentionally strips `Surrogate-Control` before delivery,
so the smoke does not require that origin-only header. The repository contract
test for `vcl/fetch.vcl` verifies the 60-second edge TTL for hidden `404`
responses; the live probe verifies the client-visible browser `no-store` policy
and repeated access behavior.

## Automation boundary

Do not add this probe to an ordinary pull-request job: forks and untrusted code
must never receive its credentials. Automation is appropriate only in a
protected post-deploy environment that binds all six inputs above, suppresses
secret-bearing command traces, and runs the smoke after deployment propagation.
Missing bindings must fail closed rather than falling back to a public or
real-user fixture. Because derivative repair paths can write production state,
the protected runner must also be authorized for operational probes against
these dedicated fixtures.
