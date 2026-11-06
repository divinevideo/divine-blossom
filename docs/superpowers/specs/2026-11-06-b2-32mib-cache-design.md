# Bounded cache fills through 32 MiB

The user requires ordinary playback caching through 32 MiB (33,554,432 bytes),
including the 8 MiB normal-video case. Controlled reads on Compute 404 established
that 8 MiB GCS and B2 fills returned correct bytes but bypassed during buffering
at 26/29 ms CPU. An 8 KiB B2 fill and subsequent hit succeeded at 4/5 ms.

## Approach

Use one fallibly allocated, initialized buffer of expected size plus one byte.
Read directly into it in windows up to 256 KiB; every short read is followed by
the existing CPU and absolute-deadline checks. This removes the 16 KiB staging
copy and allows fewer host calls without assuming that larger requests are
always returned in full. On budget expiry, truncate to bytes actually read and
replay that prefix followed by the untouched origin stream.

After complete length verification, insert and stream back through Core Cache.
Only use the returned stream after successful writer finish, avoiding a second
whole-object guest-to-host delivery copy. Retain the verified buffer until that
point so insertion errors preserve the successful origin response.

Do not advertise cache length before finishing insertion. HIT admission still
requires a known, exact length, so concurrent readers cannot select an incomplete
insert. Use a new v2 namespace to exclude older in-flight insertions that did
advertise length. Both namespaces retain the bare media-hash surrogate key.

An alternative streaming/background fill needs a separate complete-publication
protocol and client-delivery lifecycle changes. It is deferred unless measured
32 MiB fills cannot fit the current resource budgets. Increasing CPU or I/O
budgets is not part of this change. Slow fills still fall back within the
existing bounded wait; receiving the entire 32 MiB is never required to resume
ordinary streaming after that wait expires.

## Limits and observations

- Keep the 25 ms admission guard, 3 s buffer budget, overall I/O deadline,
  50 ms cache coordination wait, TTL, no-stale behavior and policy checks.
- Raise only cache eligibility to 32 MiB; larger bodies use ordinary streaming.
- One guest body buffer is about 32 MiB plus one byte. Host cache/delivery
  storage is separate and its actual footprint is not established by SDK code.
- Record actual buffer reads/bytes and committed WASM linear memory per request,
  never in cached metadata. Linear memory is not live heap or host memory.
- Writer completion and response construction also consume CPU after the
  admission guard; live acceptance must measure the final request CPU.
- Preserve version pinning, authoritative origin trust, full-length checks,
  outward no-store, current policy/erasure checks and physical cleanup.

## Acceptance

Local contracts cover 8/16/32 MiB full checksum fills, warm HEAD/ranges, the
32 MiB boundary, short/truncated/oversized bodies, timeout prefix replay and
incomplete insertion visibility. After reviewed merge and automatic deployment,
one bounded owned fixture at each size must demonstrate actual MISS/HIT,
checksum, range/HEAD/416, CPU/read-count/linear-memory measurements and signed
erasure. CPU fallback is recorded as a failed caching acceptance at these sizes,
not counted as success merely because playback remained available. The Popular
cohort runs only after acceptance and while no scheduled worker competes.
