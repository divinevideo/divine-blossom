# On-demand subtitle translation

Translation is a derived track requested with `GET /{hash}.vtt?lang=es` or
`GET /{hash}/VTT?lang=es`. The original URL without `lang` remains available.
`HEAD` reports the original transcript's existence/status and ignores `lang`.

## Product decision: option (b)

Translation is default-on once enabled, initiated by a viewer's language request.
Before public enablement, disclose that transcript text is processed by Google
Cloud Translation and display machine-translation attribution in the client.
There is no automatic translation fan-out. Creator opt-out is follow-up product
work, to be delivered before broad rollout; this backend PR does not implement
an account preference or claim to enforce one.

The backend sends cue text and the target language to the provider. It does not
send the creator's pubkey, the video's hash, or the original media to the
translation API. Translations may contain mistakes and are not statements
signed or approved by the creator.

Suggested disclosure for the privacy owner's review and publication:

> When a viewer requests subtitles in another language, Divine sends the
> video's transcript text to Google Cloud Translation to generate a machine
> translation. Divine stores the translated subtitles to serve later viewers.
> Machine translations may contain errors; the original subtitles remain
> available.

Publishing that disclosure belongs to the canonical privacy policy in
`divine-web/src/pages/PrivacyPage.tsx`. This document is rollout guidance, not a
replacement for the published policy. Client work is tracked in
[divine-mobile#9937](https://github.com/divinevideo/divine-mobile/pull/9937),
with implementation tracking in
[divine-mobile#9938](https://github.com/divinevideo/divine-mobile/issues/9938).

## Client contract

A translated `200` response includes:

```http
Content-Type: text/vtt; charset=utf-8
Content-Language: pt-BR
X-Divine-Machine-Translated: true
```

The last two headers are exposed through CORS. Its WebVTT body starts with:

```vtt
WEBVTT

NOTE
Machine-translated by Google Cloud Translation
Target-Language: pt-BR

1
00:00:00.000 --> 00:00:01.000
Texto traduzido
```

Clients must show “Machine-translated” alongside translated subtitles and offer
the original track. A `NOTE` block by itself is not visible in standard subtitle
renderers. The current API does not report a detected source language; clients
may use the video's source-language metadata when available.

While the source is missing, the request follows normal transcription processing,
cooldown, repair, and terminal-failure behavior. Translation begins only after
the source exists. Translation pending returns `202` and `Retry-After: 15`.
A recorded translation failure returns `503`, `status: translation_unavailable`,
a safe `error_code`, and `terminal`. Retryable failures also include
`Retry-After`; clients should offer the original rather than poll indefinitely.
Malformed language values fall back to the original. Unsupported languages
rejected by the provider produce a terminal failure for that source version.

## Storage and concurrency

The edge reads the current source without either the Simple Cache or backend
cache. Translated objects live at:

```text
{hash}/vtt/translations/{sha256-of-main-vtt}/{canonical-language}.vtt
```

The source digest covers the exact bytes, including timings. A source repair
selects a new object and cache key without enumerating old languages. The worker
verifies that digest before billing. Existing legacy `{hash}/vtt/{lang}.vtt`
objects are not reused. Translation responses do not change source transcript
status. Normal source-completion callbacks still purge the public hash's CDN
cache; out-of-band repairs must use the existing repair/purge procedure to
refresh already-cached public responses.

The edge sends `202` before waiting for the worker response, retaining the
pending request until delivery completes. Worker delivery failures are logged
and cause a short POP-local `503` cooldown on subsequent polls.

An adjacent `.vtt.json` object records a distributed claim or failure. GCS
generation preconditions allow one worker per source/language, across instances.
A claim expires after 120 seconds; active work is bounded to 100 seconds.
Transient failures cool down before another claim. Empty sources and provider
request rejections are terminal for that source/language. Old revisions and job
objects remain under the blob prefix and are removed by existing blob cleanup.

Both services use the same language canonicalizer. Chinese script aliases map
to `zh-CN` or `zh-TW`; `pt-BR` and `pt-PT` remain distinct. Other accepted locale
hints normalize to the primary language. This is not a promise of support for
every BCP-47 tag or regional dialect.

## Rollout and rollback

1. Publish the privacy disclosure and verify the client displays attribution
   and can return to the original. Keep creator opt-out tracked before broad
   rollout.
2. Enable the Cloud Translation API and grant the transcoder runtime service
   account `roles/cloudtranslate.user`. `GOOGLE_TRANSLATE_LOCATION` defaults to
   `global` and can select another supported location.
3. Deploy the transcoder using `cloud-run-transcoder/deploy.sh`. Its staged build
   context includes the shared core crate and excludes local credentials and
   build outputs. Follow `docs/runbooks/deployment.md`; inspect live binding
   names before changing them, without reading secret values.
4. Configure `TRANSLATE_SHARED_SECRET` on the transcoder and the matching
   `translate_shared_secret` in Fastly's `blossom_secrets` store. Use a dedicated
   translation secret. Until configured, the worker fails closed; do not enable
   the edge secret until the disclosure/client prerequisites are satisfied.
5. Verify the authenticated worker contract with a synthetic source, then verify
   both public URL forms: pending, translated, failed, and repaired source.
   Confirm only one provider request runs for simultaneous misses.

No deploy, API enablement, permission grant, or secret provisioning is performed
by this PR. The deployment script preserves bindings it does not own, including
the optional translation secret. To stop new translation dispatch, remove the
edge translation secret; the original transcript remains available. Existing
translated tracks remain readable. To withdraw those tracks too, roll back the
edge package following `docs/runbooks/rollback.md` and purge affected URLs.

## Validation

```sh
cargo test -p blossom-core --locked
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked
./scripts/run-edge-tests.sh
cargo check --tests --locked
cargo clippy --locked --all-targets --all-features
```

The edge script includes real loopback storage/worker I/O tests under Viceroy.
Worker tests use a local GCS protocol double; no test bills the provider or uses
live media, credentials, or creator identifiers.
