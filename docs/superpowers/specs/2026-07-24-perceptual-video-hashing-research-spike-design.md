# Perceptual Video Hashing Research Spike Design

**Date:** 2026-07-24
**Status:** Approved

## Decision summary

Run an offline, reproducible benchmark of two open-source perceptual video
hashing systems:

- **vPDQ** as the primary candidate;
- **TMK+PDQF** as the fixed-length baseline.

The spike determines whether either system can reliably recognize
near-duplicate and transformed Divine-style short videos. It does not add
hashing to the upload path, integrate a sensitive hash corpus, take moderation
action, or change user-visible behavior.

The expected outcome is a measured recommendation among vPDQ, TMK+PDQF, or no
adoption. The benchmark must not presume that deploying perceptual hashing is
the correct conclusion.

## Problem

Divine identifies exact media bytes with SHA-256, but an exact digest changes
after a harmless re-encode, resize, crop, overlay, or remux. That makes it
unsuitable for recognizing a previously reviewed video when the bytes have
changed.

Perceptual hashing may provide a reusable moderation-memory signal for:

1. routing likely reuploads of known harmful material to review;
2. avoiding repeated expensive analysis of equivalent media;
3. later supporting repost or attribution workflows.

Safety is the first use case. A perceptual match would be a review signal, not
an enforcement verdict. False positives must not automatically quarantine,
delete, downrank, or label content.

The repository does not currently implement perceptual video matching. The
upload service computes a cryptographic SHA-256 while streaming media, and the
asynchronous transcode and blob-processing services perform separate
derivative and provenance work. The existing video branch in
`cloud-functions/process-blob/main.py` does not yet extract a thumbnail. A
sibling moderation project pins a Python PDQ package but does not call it.
These facts make a self-contained experiment safer than inserting unmeasured
native hashing code into an operational service.

## Why these two candidates

The public [ThreatExchange repository](https://github.com/facebook/ThreatExchange)
defines:

- **vPDQ**, which applies PDQ across sampled video frames and supports matching
  overlapping clips by comparing sets of deduplicated frame hashes;
- **TMK+PDQF**, which produces a compact fixed-length signature optimized for
  near-identical full videos.

Frame-sampled PDQ is not a third candidate: it is the basic mechanism of vPDQ.
Comparing a hand-rolled frame sampler would duplicate vPDQ while losing its
published matching behavior.

The public
[PHVSpec benchmark](https://www.technologycoalition.org/knowledge-hub/phvspec-a-benchmark-based-analysis-of-perceptual-hash-systems-for-videos)
found that vPDQ had substantially higher recall than TMK+PDQF at each
algorithm's highest-F1 operating point, while both allowed local processing.
That external result is useful for candidate selection, but it cannot answer
how the algorithms behave on Divine's short loops and expected
transformations. The spike therefore tests both on a Divine-shaped corpus.

Proprietary systems and sensitive external hash-sharing networks are excluded.
They introduce access, policy, legal, and interoperability questions that are
not needed to establish whether the underlying technique is useful.

## Goals

- Measure recognition quality across transformations common to short-form
  video.
- Measure false matches against a distinct nonmatching corpus.
- Measure hash time, query time, failures, and fingerprint size.
- Select thresholds on a development split and evaluate them once on an
  isolated test split.
- Produce a deterministic, inspectable benchmark that another engineer can
  run from a local manifest.
- Keep all source media, source URLs, per-video fingerprints, and credentials
  out of git.
- Produce a recommendation with explicit uncertainty and failure modes.

## Non-goals

- Production service or schema changes.
- Upload, Fastly, GCS, Eventarc, Cloud Run, Osprey, or moderation-queue
  integration.
- Automatic moderation, blocking, labeling, deduplication, or attribution.
- Obtaining or testing a sensitive external reference corpus.
- Detecting previously unseen harmful content.
- Identifying authorship, ownership, intent, or whether media is AI-generated.
- Choosing a long-term cross-repository service boundary.
- Benchmarking every commercial perceptual hashing product.

## Repository boundary

The later implementation plan should create one isolated experiment under:

```text
experiments/perceptual-video-hashing/
  Dockerfile
  README.md
  requirements.lock
  src/
  tests/
  fixtures/
  config/
```

`fixtures/` contains only scripts or specifications for generating tiny
synthetic videos. It contains no user media.

The experiment consumes a caller-provided local manifest and writes generated
artifacts below a gitignored run directory. It does not import production
service modules or require production credentials. This boundary makes it
clear that benchmark code is not an approved production dependency.

## Reproducible toolchain

The container pins the public ThreatExchange source to commit:

```text
baefb4ed67b6cdc1d4c82dbaef858d50866ac424
```

It builds the official vPDQ and TMK+PDQF implementations with pinned system
packages and FFmpeg. The runner records:

- ThreatExchange commit;
- base container image digest and exact installed package versions;
- container image digest;
- FFmpeg version;
- host OS, architecture, and CPU model;
- benchmark configuration digest;
- input manifest digest;
- deterministic random seed;
- command and start time.

The build also emits an SBOM and SHA-256 checksums for the FFmpeg, vPDQ, and
TMK+PDQF binaries used in the run. Dependency installation uses a dated or
content-addressed package snapshot so rebuilding does not silently select new
native libraries.

The experiment must not depend on the unused `pdqhash` Python package already
pinned elsewhere in the Divine organization. Native dependencies stay inside
the benchmark container.

The build uses release optimization and runs upstream sample or regression
vectors for both algorithms. Because TMK output can vary with FFmpeg behavior,
an upstream-compatibility failure blocks real-media evaluation.

## Operator interface

The repository exposes one entry point, `./benchmark`, from the experiment
directory:

```text
./benchmark build
./benchmark preflight --manifest <file> --input-root <dir> --runs-root <dir>
./benchmark smoke --runs-root <dir>
./benchmark pilot --manifest <file> --input-root <dir> --runs-root <dir>
./benchmark accept-pilot --runs-root <dir> --run <run-id>
./benchmark tune --runs-root <dir> --run <run-id>
./benchmark test --runs-root <dir> --run <run-id> \
  --freeze <frozen-operating-points.json>
./benchmark report --runs-root <dir> --run <run-id>
./benchmark accept --runs-root <dir> --run <run-id> --conclusion <value>
./benchmark cleanup --runs-root <dir> --run <run-id>
./benchmark full --manifest <file> --input-root <dir> --runs-root <dir> \
  [--run <run-id>]
```

`full` is the one-command computational path and invokes the same visible
phases in order, prints its allocated run ID, and passes the same explicit
runs root and run ID to every internal phase. A real-media run pauses for
pilot acceptance before full-corpus work and ends pending final human
acceptance; it never cleans restricted evidence before acceptance. Follow-up
commands never discover runs through global state. Each phase is independently
rerunnable when its recorded inputs and digests match. Help text documents
required mounts and emits the exact container command rather than relying on
shell aliases or operator memory.

`preflight` is read-only. It validates the manifest and runtime isolation,
probes inputs inside the sandbox, calculates the expected source/variant/query
counts, and estimates CPU, wall time, memory, and disk. It refuses to start if
free disk is less than the estimate plus 25% headroom.

The commands use these exit statuses:

- `0`: requested phase completed and, for `full`, a valid decision report was
  produced;
- `2`: usage, manifest, attestation, path, duplicate, or preflight failure
  before benchmark work;
- `3`: build, isolation, upstream compatibility, or synthetic smoke failure;
- `4`: diagnostic partial run; per-item failures exceeded a gate or prevented
  a valid decision.

An exit-4 run still produces a clearly headed `NO DECISION — PARTIAL RUN`
diagnostic report. It cannot emit a recommendation. Undecodable individual
files and bounded transform/hash failures are recorded and allow remaining
items to run; schema, containment, attestation, isolation, freeze-digest, or
ground-truth errors abort immediately. Expected, attempted, succeeded, and
failed counts appear for every phase and transformation.

### Manifest contract

The manifest is strict UTF-8 JSON with `schema_version: 1`; unknown keys are
rejected. Its top-level fields are:

- `schema_version`, exactly `1`;
- `corpus_id`, an opaque identifier;
- `attestation`, with literal booleans `authorized_for_local_research`,
  `non_sensitive`, and `perceptually_distinct_distractors`, all true, plus
  opaque aliases for the corpus approver, benchmark operator, safety reviewer,
  and decision owner, and literal confirmation that the corpus approver and
  decision owner are human;
- `items`, a nonempty array.

Each item contains:

- `id`, unique and matching `^[a-z0-9][a-z0-9_-]{2,63}$`;
- `path`, a unique normalized relative path below the input root, with no
  absolute prefix, `..`, empty component, or symlink;
- `role`, either `source` or `distractor`;
- `corpus`, one of `divine_public`, `archive_public`, or
  `synthetic_generated`;
- `use_basis`, one of `owned_or_licensed`, `public_local_research`, or
  `archive_local_research`;
- `visual_classes`, a unique array drawn from the checked-in technical image
  characteristic enum;
- `duplicate_group`, either null or an opaque group identifier used to keep
  known equivalents together.

A minimal valid shape is:

```json
{
  "schema_version": 1,
  "corpus_id": "study_01",
  "attestation": {
    "authorized_for_local_research": true,
    "non_sensitive": true,
    "perceptually_distinct_distractors": true,
    "corpus_approver_human": true,
    "decision_owner_human": true,
    "corpus_approver_role": "corpus-approver",
    "benchmark_operator_role": "benchmark-operator",
    "safety_reviewer_role": "safety-reviewer",
    "decision_owner_role": "decision-owner"
  },
  "items": [
    {
      "id": "src_001",
      "path": "sources/src_001.mp4",
      "role": "source",
      "corpus": "divine_public",
      "use_basis": "public_local_research",
      "visual_classes": ["live_action", "camera_motion"],
      "duplicate_group": null
    }
  ]
}
```

Free-form descriptions and source locators are intentionally absent. Preflight
computes SHA-256 rather than trusting an operator-supplied digest and rejects
duplicate IDs, paths, or unexplained exact digests.

## Dataset

### Real samples

Use 100 non-sensitive source videos:

- 50 current, publicly available Divine videos;
- 50 publicly available archived Vine videos.

Selection should cover the formats and visual character of six-second social
video without attempting demographic, behavioral, or moderation profiling.
The corpus should include animation, live action, text-heavy clips, low-light
clips, static scenes, camera motion, and fast cuts.

Before selection, the benchmark configuration sets a minimum of ten sources
for each listed visual class; one source may satisfy several classes. The
sanitized report publishes achieved class counts so accidental corpus skew is
visible. These are technical image characteristics, not labels about creators
or people depicted.

The benchmark runner never downloads production media. An authorized operator
places files in a local input directory and creates a manifest containing
opaque sample IDs, relative file paths, corpus class, and declared license or
public-use basis. No account ID, pubkey, event ID, caption, username, source
URL, moderation label, or human name is permitted in the manifest.

Before a run, the operator attests separately that every selected file is both
authorized for local research use and non-sensitive. Public reachability alone
does not satisfy this check, because accidentally exposed or subsequently
privatized media may still be reachable.

Add at least 400 distinct nonmatching distractor videos. Distractors must not
be transformations or known reposts of any source video. A preflight exact
SHA-256 check rejects duplicate bytes; manual or provenance-based selection is
still required because exact hashes cannot prove perceptual distinctness.

### Synthetic samples

Tests generate small videos from FFmpeg test sources, moving shapes, and
generated tones. Synthetic fixtures verify the harness without exposing real
media and are not included in reported real-corpus quality metrics.

### Split isolation

Assign source videos deterministically to:

- 60% training/exploration;
- 20% threshold-development;
- 20% held-out test.

All transformations of a source inherit that source's split. No source,
transformation, extracted frame, or fingerprint may cross splits. The
training split validates the harness and explores ranges. The development
split selects one operating point per algorithm. The test split is evaluated
once for the final report.

Distractors use a separate deterministic negative split: 100 for threshold
development and at least 300 held out for the final test. Training explores
negative pairs between distinct training references. If a source is found to
duplicate another source, both are removed or assigned to the same split
before any metrics are calculated.

## Transformation matrix

For every source, generate deterministic variants that exercise:

1. container remux with no intended visual change;
2. H.264 re-encode at two quality levels;
3. downscale to 480p and 240p;
4. frame-rate conversion;
5. a fixed text or watermark overlay;
6. letterboxing or black padding;
7. 5% and 10% spatial crops followed by resize;
8. horizontal reflection;
9. 0.9x and 1.1x speed changes;
10. a middle subsequence;
11. a loop or simple concatenated remix.

FFmpeg commands, fonts, overlay contents, codecs, seeds, and output metadata
are fixed in configuration. Each generated variant records its parent,
transformation class, exact parameters, and SHA-256.

The subsequence and remix classes are especially important because vPDQ can
recognize overlapping clips from its unordered set of unique sampled-frame
hashes, while TMK+PDQF is optimized for a near-identical full video. vPDQ does
not perform temporal alignment and ignores frame order and timestamps during
comparison; remix or reordering results must not be described as sequence
recognition. Results for these classes must not be mixed into a single average
that hides the architectural difference.

## Ownership, staging, and budget

Four recorded roles bound the work:

- the **corpus approver** attests authorization and non-sensitivity;
- the **benchmark operator** executes the documented commands;
- the **safety reviewer** reviews omissions, false matches, limitations, and
  report sanitization;
- the **decision owner** accepts the final go/no-go conclusion.

The corpus approver and decision owner must be human and distinct. Provenance
records role aliases, not personal identifiers.

Execution proceeds through stop/go stages:

1. native release build, upstream compatibility vectors, and synthetic smoke;
2. a five-source-per-corpus pilot plus 20 distractors exercising every
   transformation;
3. full corpus generation and development tuning;
4. frozen held-out test and aggregate report.

Stage 1 stops if either candidate cannot build, parse its upstream vectors, or
distinguish the synthetic exact/re-encode positive from the unrelated
negative. Stage 2 stops if either candidate is nonfunctional on supported
media, if sandbox limits are repeatedly exhausted, if projected full-run
resources exceed the budget, or if transformation failure makes the corpus
unrepresentative. A stopped stage produces a diagnostic no-decision report
before any larger collection or transformation begins.

The spike is capped at five engineering days, 200 CPU-hours, 250 GiB of
ephemeral benchmark storage, and seven calendar days from first real-media
run to cleanup. Exceeding a cap stops the experiment and requires a new scope
decision; it does not justify turning the harness into a production service.

## Benchmark flow

```text
validate manifest and privacy fields
  -> probe/decode every input
  -> assign source-level splits
  -> generate deterministic variants
  -> hash references with vPDQ and TMK+PDQF
  -> query positive variants and negative distractors
  -> sweep thresholds on training/development only
  -> freeze one operating point per algorithm
  -> evaluate held-out test once
  -> write raw machine results and a sanitized aggregate report
```

Hash generation and matching run locally with outbound network access
disabled after the container image has been built. The runner must fail closed
if the manifest contains disallowed identifying fields or paths outside the
declared input root.

### Untrusted-media execution boundary

All real media is treated as hostile parser input. The documented run command
starts the benchmark container with:

- a non-root numeric UID and GID;
- a read-only root filesystem;
- the caller-owned input directory mounted read-only;
- one separately mounted benchmark-owned writable run directory;
- every Linux capability dropped and `no-new-privileges` enabled;
- bounded CPU, memory, process count, output size, and wall-clock time;
- no outbound or inbound network;
- no host, home directory, SSH agent, cloud configuration, credential, or
  container-engine socket mounts;
- an explicit minimal environment allowlist rather than inherited host
  variables.

The runner accepts only regular files and rejects every symlink, device,
socket, FIFO, and hard-linked file with an unexpected link count. It resolves
and validates canonical containment at manifest load and immediately before
each subprocess opens a path. Subprocesses receive argument arrays directly;
the runner never invokes a shell or interpolates paths into command strings.

FFmpeg and FFprobe run with standard input disabled, protocol access restricted
to the minimum local `file`/`pipe` set needed by the checked-in transforms,
playlist indirection disabled, and an explicit allowlist of supported local
container demuxers. Inputs requiring another protocol, indirection mechanism,
or demuxer fail as unsupported. Generated output paths are created by the
runner under the owned run directory and cannot be chosen by manifest fields.

### Retrieval protocol and ground truth

Each split is evaluated as an independent reference collection:

- its canonical source videos form the reference index;
- every generated variant is a positive query whose only expected reference
  is its parent source;
- every distractor is a negative query with no expected reference.

Before benchmarking, reviewers remove or group sources that are genuinely
similar to more than one reference. The manifest records this decision without
identifying the source.

For every query/reference pair that crosses the algorithm's threshold, the
harness records an opaque query ID, opaque reference ID, raw score, threshold,
and outcome. A returned parent pair is a true positive; a returned wrong
reference is a false positive; and a parent not returned is a false negative.
All non-returned negative pairs form the true-negative denominator. A query
may produce both a true positive and false positives, so top-one accuracy
cannot substitute for pair-level precision and false-positive rate.

The report also includes operational query-level counts:

- positive queries with the correct parent anywhere in the returned set;
- positive queries with at least one wrong reference;
- distractor queries with any returned reference;
- queries returning more than one reference.

This protocol prevents a permissive matcher from appearing successful merely
because the correct parent was one of many results. It also makes the reference
collection size explicit; results cannot be extrapolated to Divine scale
without a later larger shadow evaluation.

Quality evaluation scores every query against every canonical reference in its
split. It uses no approximate index, candidate pruning, nearest-neighbor
library, or early-exit retrieval layer. Optional indexed experiments may be
reported separately for performance exploration, but they cannot contribute
to quality gates or replace exhaustive results.

Expected variant count, successfully generated count, and failed count are
reported for each transform. Generation or decode failures remain in the
denominator for completion-rate metrics and cannot be silently excluded from
quality conclusions.

## Threshold selection

The exact supported threshold controls must be taken from the pinned official
implementations rather than recreated in the harness.

For vPDQ, the canonical source is always the comparison/reference and its
variant or a distractor is always the query. The sweep controls its asymmetric
parameters independently:

- PDQ Hamming-distance threshold `D`: 16, 24, 31, and 40;
- minimum frame-quality filter `F`: 0, 25, 50, and 75;
- comparison/reference matched-frame percentage `Pc`: 0%, 25%, 50%, 80%,
  and 100%;
- query matched-frame percentage `Pq`: 0%, 25%, 50%, 80%, and 100%, including
  the official example's 0% case.

For TMK+PDQF, explore:

- TMK+PDQF level-one and level-two similarity thresholds around 0.70, 0.80,
  0.90, and 0.95.

These are sweep bounds, not endorsed production defaults. Unsupported or
semantically invalid combinations are removed and documented after inspecting
the pinned CLI behavior. Frame-sampling cadence and all remaining tool options
are fixed before development evaluation and recorded in the freeze artifact.

Choose each standalone operating point with this lexicographic rule:

1. held-development precision at least 99%;
2. highest recall among points satisfying that precision floor;
3. lower compute cost when quality is statistically indistinguishable.

If no point reaches 99% development precision, select the highest-precision
point for diagnosis and mark the candidate as failing the quality gate. Do not
adjust thresholds after seeing test results.

The selected algorithm, all thresholds, orientation, sample cadence, tool
version, development-result digest, and configuration digest are written to a
content-addressed `frozen-operating-points.json`. The held-out command requires
that artifact, verifies every digest, and has no tuning code path.

## Metrics

Report confusion counts and the following metrics for every algorithm,
threshold, split, and transformation class:

- precision;
- recall;
- F1;
- false-positive rate;
- false negatives;
- hash-generation wall time and CPU time per second of source video;
- query wall time per reference/query comparison or indexed query;
- fingerprint and index bytes per second and per six-second video;
- decode/hash/query failure count and failure reason.

The final test report includes deterministic bootstrap 95% confidence
intervals. Positive variants are clustered and resampled at the parent-source
level; negative distractors are clustered by query ID. Source-level resampling
prevents many variants of one clip from creating false statistical confidence.
The quality gate's precision statistic is exhaustive candidate-pair precision;
correct-parent recall and the fraction of negative queries returning any match
are separately named operational statistics.

Overall aggregates are shown only alongside transformation-level results. The
report calls out the worst-performing transform and never ranks candidates
solely by average F1.

## Spike completion and decision criteria

The research spike is complete when:

- one documented command builds the pinned container and runs the benchmark
  from a validated manifest;
- all available source variants and distractors are processed, with every
  omission explained;
- synthetic integration tests demonstrate an exact/re-encoded positive and an
  unrelated negative for both candidates;
- no source bytes, source URLs, identifying metadata, cryptographic digests,
  or perceptual fingerprints are committed;
- a machine-readable result and sanitized aggregate report reproduce the
  recommendation.

A candidate earns a recommendation for a later, separately designed pilot
only if its held-out operating point:

- has at least 99% exhaustive candidate-pair precision;
- returns no match for any of the at least 300 held-out distractor queries and
  reports the exact one-sided 95% upper confidence bound on the true
  query-level false-match rate;
- has at least 90% recall for remux, re-encode, downscale, and watermark
  classes;
- reports crop, padding, speed, subsequence, and remix performance separately;
- processes at least 99% of supported inputs without a crash;
- hashes at no more than 0.1 CPU-seconds per second of input on the recorded
  reference machine;
- averages no more than 10 KiB of fingerprint data per six-second video.

The performance and storage bounds are feasibility screens, not production
SLOs. The corpus is too small to prove production safety. Passing means only
that a larger shadow-mode pilot is worth designing.

Zero observed distractor matches is a screening gate, not a claim that the
false-match rate is zero. With this corpus size, its confidence bound remains
far too weak to authorize production enforcement.

The report applies this cross-candidate rule:

1. if neither candidate passes every gate, recommend no adoption;
2. if exactly one passes, recommend that candidate;
3. if both pass, compare their correct-parent recall with a paired
   source-level bootstrap;
4. prefer a candidate for quality only when its recall advantage is at least
   five percentage points, the 95% interval for that difference excludes
   zero, and it does not materially regress another required transformation;
5. when quality is statistically indistinguishable, choose lower measured
   hash CPU, then lower fingerprint bytes; if both are within 10%, prefer
   TMK+PDQF's simpler fixed-length storage/query model.

The spike evaluates standalone candidates only. A hybrid would require its own
ordering, joint threshold tuning, cost model, and held-out freeze, so it is
deferred rather than invented after test results.

The report must therefore choose exactly one conclusion:

1. recommend vPDQ for a later shadow pilot;
2. recommend TMK+PDQF for a later shadow pilot;
3. recommend no adoption.

`report.md` begins with the selected conclusion and a pass/fail table for every
decision criterion. Transformation-level quality follows, then
failures/omissions, uncertainty, reproducibility provenance, and limitations.
It also projects shadow-pilot hashing CPU, storage, and review-queue volume as
ranges at 10,000, 100,000, and 1,000,000 daily uploads using the measured
rates and the false-match confidence bound. These projections are planning
inputs, not production forecasts.

## Output and retention

Each local run writes:

```text
runs/<run-id>/
  provenance.json
  normalized-manifest.json
  frozen-operating-points.json
  raw-results.jsonl
  metrics.json
  report.md
  failures.jsonl
  pilot-acceptance.json
  decision-acceptance.json
```

The entire `runs/` tree, local inputs, generated variants, and fingerprints
are gitignored. A sanitized `report.md` may be copied into documentation only
after checking that it contains aggregate metrics, opaque IDs where examples
are essential, and no recoverable fingerprints or source paths.

The benchmark never deletes caller-owned input originals. Each run directory
contains an ownership marker created before any outputs; cleanup refuses a
directory without that marker, revalidates its canonical location below the
configured runs root, and deletes only benchmark-owned copies, variants,
fingerprints, raw pair results, and temporary files for that exact run ID.

The runner invokes scoped cleanup on success and on handled failure. Data kept
temporarily for diagnosis has a maximum seven-day retention period, and the
README provides a command that identifies and removes expired owned runs.
Aggregate-only reporting is the default. Including even an opaque per-video
example requires an explicit manual sanitization review.

## Privacy, security, and product safeguards

- Inputs are public and non-sensitive; known harmful material is not required.
- All hashing and matching happens locally.
- No third-party API receives video, frames, fingerprints, or queries.
- The run environment has no production credentials.
- The container receives only an explicit environment allowlist and cannot see
  host credential directories or agents.
- Input paths are contained below one declared root and opened without
  following symlinks outside that root.
- Output identifiers are opaque and unlinkable to Divine accounts or Nostr
  identities.
- Per-video fingerprints are treated as derived sensitive data even when the
  source is public.
- Fingerprints and media never appear in logs, test snapshots, exceptions, or
  committed fixtures.
- A match is explicitly documented as evidence of visual similarity, not
  identity, authorship, policy violation, intent, or legal status.
- Nothing in the spike can call moderation or deletion endpoints.

## Test strategy

Implementation follows TDD. Unit tests are written and observed failing before
their production code for:

- manifest schema and rejection of identifying/disallowed fields;
- path containment and symlink escape;
- deterministic source-level split isolation;
- transformation command construction and provenance;
- official tool-output parsing and failure classification;
- threshold sweep generation and frozen operating-point selection;
- confusion matrices and zero-denominator handling;
- source-level bootstrap confidence intervals;
- sanitization of reports and logs.

Container integration tests use generated synthetic videos to verify:

- both official tools build from the pinned source;
- exact and re-encoded positives match at a documented smoke threshold;
- an unrelated synthetic video does not match;
- malformed and undecodable files produce bounded structured failures;
- repeated runs with the same seed produce identical assignments and metrics.

The applicable coverage threshold is read from
`.coverage-thresholds.json` when implementation begins. The benchmark runner
must meet the repository gate; native third-party code is excluded from Divine
coverage calculations.

## Risks and mitigations

### Benign data is only a proxy

A non-sensitive corpus avoids handling harmful material but cannot establish
performance on every adversarial or policy-relevant video. The final report
must state this limitation, and any later safety pilot requires a separately
approved, access-controlled evaluation.

### Small-corpus false confidence

Four hundred distractors cannot demonstrate a production-scale false-positive
rate. The 99% precision floor is a screening point estimate, not proof of
production safety; confidence intervals are source-grouped, and passing does
not authorize enforcement.

### Benchmark leakage

Selecting thresholds after examining test results would inflate performance.
The split is source-isolated, operating points are frozen before the test
evaluation, and the test command records that freeze.

### Native dependency and supply-chain cost

Both candidates require FFmpeg and native code. Pinning an exact public commit
and container packages makes the experiment reproducible. Any production use
would require a separate dependency, license, vulnerability, and maintenance
review.

### Metric masking

Short clips can make an aggregate look healthy while failing on padding,
cropping, or partial reuse. Per-transformation results and worst-class
reporting are mandatory.

### Misuse as a verdict

Perceptual similarity can be mistaken for policy certainty. The spike has no
enforcement path, and any later system must route matches to human review with
auditable corpus provenance and thresholds.

## Expected outcome

Based on public benchmark evidence and six-second-video needs, vPDQ is the
leading candidate because it has stronger published recognition performance
and can match overlapping clips. TMK+PDQF remains a useful baseline because
its fixed-length signature has a predictable and readily indexable storage
model for full-video near duplicates.

That expectation is a hypothesis. The benchmark is successful if it produces
credible evidence against it as readily as evidence for it.

## Design review

The mandatory design-review gate approved this design after review by:

- Product Management;
- Architecture;
- Operator Experience;
- Security and Privacy;
- CTO/Executive.

Review changes corrected vPDQ's unordered frame-set semantics, made quality
evaluation exhaustive, defined its asymmetric controls and orientation,
removed an unevaluated hybrid conclusion, hardened untrusted-media execution,
added staged ownership and resource caps, specified the complete operator and
manifest contract, and made false-positive and cross-candidate decisions
explicit.
