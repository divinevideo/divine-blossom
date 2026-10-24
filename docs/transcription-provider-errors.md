# Transcription provider failure codes

Provider failure codes describe the final failed attempt, independently of
whether the bounded retry budget was exhausted:

| Code | Meaning |
| --- | --- |
| `provider_rate_limited` | An explicit HTTP 429 response was received. |
| `provider_timeout` | The HTTP client reported a timeout, with no explicit 429. |
| `provider_transport_failed` | The HTTP client reported another request, connection, or response-body transport failure, with no explicit 429. |
| `provider_failed` | Other failures, including other HTTP errors, invalid responses, local setup errors, and unavailable credentials. |

Previously, every exhausted retryable failure used `provider_rate_limited`,
including timeouts and transient HTTP 5xx responses. Consumers must accept the
new timeout and transport codes and must not infer quota exhaustion from retry
exhaustion. Body text is not used to infer these classifications. An explicit
429 takes precedence even if reading its response body subsequently fails.

OpenAI-compatible, Gemini, Google STT V2, and Parakeet calls share the request-error
classifier. The by-hash transcript path supplies the same selected code to its
Sentry failure tag, persisted cooldown lock, and failed-status webhook. The edge
accepts the webhook code as a string and persists it in transcript metadata.
The raw-audio editor endpoint still returns its existing HTTP error envelope;
it does not emit the by-hash cooldown or webhook metadata.

Retry eligibility, attempt and elapsed-time bounds, fallback selection, cooldown
duration, webhook fields, and `terminal=false` semantics are unchanged. In
particular, non-timeout transport failures do not gain retries. Credential
lookup exhaustion remains retryable but no longer impersonates a provider
timeout. Only the failure-code values and diagnostic timeout flag change.

There is no visual change and no provider configuration or quota change.
