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

Do not put these values in this repository, command history, CI logs, issue or
pull-request prose, or shared fixture documentation. The script turns off shell
tracing before handling them; the calling shell or CI wrapper must also avoid
printing injected values.
It writes the admin header only to a mode-600 temporary curl config and removes
the file on exit. `nak` receives the owner key through its documented
`NOSTR_SECRET_KEY` environment input, not a command-line argument, and uses it
only to sign fresh, URL-bound NIP-98 requests.

For a local operator run, the preferred pattern is a credential namespace that
injects the variables without sourcing a file:

```bash
credchain divine-blossom-smoke scripts/smoke-private-moderation-cache.sh
```

The probe performs read-only HTTP requests. It does not deploy, change fixture
state, purge caches, or rotate credentials.

## Synthetic fixture provisioning

Provision fixtures through the normal upload and moderation paths in a
controlled maintenance session. This setup changes live state and is separate
from the read-only smoke command:

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
| `Restricted` | `404`; browser `no-store`, edge `max-age=60` | `200`; `private, no-store` | `200`; `private, no-store` |
| `AgeRestricted` | `401`; never a shared-cache hit | `200`; `private, no-store` | `200`; `private, no-store` |
| `Banned` | `404`; browser `no-store`, edge `max-age=60` | `404` | `200`; `private, no-store` |
| `Deleted` | `404`; browser `no-store`, edge `max-age=60` | `404` | `200`; `private, no-store` |

The same expectation is applied twice to blob, thumbnail, audio, and HLS master
routes so a response accidentally stored on the first request is detected on
the second. A successful credentialed response must also carry
`Surrogate-Control: no-store` and must not report a shared `X-Cache: HIT`.

## Automation boundary

Do not add this probe to an ordinary pull-request job: forks and untrusted code
must never receive its credentials. Automation is appropriate only in a
protected post-deploy environment that binds all six inputs above, suppresses
secret-bearing command traces, and runs the read-only smoke after deployment
propagation. Missing bindings must fail closed rather than falling back to a
public or real-user fixture.
