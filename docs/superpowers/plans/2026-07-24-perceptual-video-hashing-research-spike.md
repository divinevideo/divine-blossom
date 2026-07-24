# Perceptual Video Hashing Research Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the approved offline, sandboxed, reproducible vPDQ versus
TMK+PDQF benchmark and verify it with synthetic media without changing any
production service.

**Architecture:** A standard-library Python package owns strict manifest
validation, deterministic transforms and splits, native-tool adapters,
threshold selection, metrics, reporting, and bounded run storage. A single
`./benchmark` launcher builds or invokes a digest-pinned container containing
the official ThreatExchange revision and FFmpeg. Quality evaluation is
exhaustive; development thresholds are frozen into a content-addressed
artifact before the held-out test phase.

**Tech Stack:** Python 3.12 standard library, `unittest`, coverage.py 7.15.2,
FFmpeg/FFprobe, Docker, CMake/C++14, official ThreatExchange vPDQ and
TMK+PDQF at `baefb4ed67b6cdc1d4c82dbaef858d50866ac424`.

**Status:** Approved by feasibility, completeness, and scope/alignment review.

---

## Scope and file map

Create only the isolated experiment and documentation:

- `experiments/perceptual-video-hashing/benchmark` — operator entry point.
- `experiments/perceptual-video-hashing/Dockerfile` — pinned native toolchain.
- `experiments/perceptual-video-hashing/requirements.lock` — test dependency.
- `experiments/perceptual-video-hashing/README.md` — safe operating runbook.
- `experiments/perceptual-video-hashing/config/defaults.json` — transforms,
  split ratios, threshold grids, and budgets.
- `experiments/perceptual-video-hashing/src/phash_benchmark/model.py` —
  immutable domain records and exit codes.
- `experiments/perceptual-video-hashing/src/phash_benchmark/manifest.py` —
  strict schema, attestation, file and path validation.
- `experiments/perceptual-video-hashing/src/phash_benchmark/splits.py` —
  deterministic group-preserving assignment.
- `experiments/perceptual-video-hashing/src/phash_benchmark/media.py` —
  hostile-input probing, normalization, and resource limits.
- `experiments/perceptual-video-hashing/src/phash_benchmark/transforms.py` —
  shell-free FFmpeg argument construction.
- `experiments/perceptual-video-hashing/src/phash_benchmark/adapters.py` —
  bounded subprocess execution and official-tool parsers.
- `experiments/perceptual-video-hashing/src/phash_benchmark/metrics.py` —
  exhaustive outcomes, operating-point selection, intervals, freeze digest.
- `experiments/perceptual-video-hashing/src/phash_benchmark/store.py` —
  run ownership, atomic artifacts, safe cleanup.
- `experiments/perceptual-video-hashing/src/phash_benchmark/provenance.py` —
  non-identifying build and run provenance.
- `experiments/perceptual-video-hashing/src/phash_benchmark/report.py` —
  aggregate-only Markdown and JSON reports.
- `experiments/perceptual-video-hashing/src/phash_benchmark/pipeline.py` —
  preflight, smoke, pilot, tune, test, report phases.
- `experiments/perceptual-video-hashing/src/phash_benchmark/cli.py` — command
  parsing and stable exit statuses.
- `experiments/perceptual-video-hashing/tests/` — mirrored unit tests.
- `experiments/perceptual-video-hashing/container/` — direct package lock and
  deterministic SPDX generator.
- `experiments/perceptual-video-hashing/fixtures/` — generated-media script
  and safe example manifest only.
- `.gitignore` — ignore experiment inputs, runs, generated media, hashes, and
  coverage output.

Do not modify edge, upload, transcoder, process-blob, moderation, deployment,
or schema code.

### Task 1: Scaffold the package and strict domain model

**Files:**

- Create: `experiments/perceptual-video-hashing/requirements.lock`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/__init__.py`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/model.py`
- Create: `experiments/perceptual-video-hashing/tests/__init__.py`
- Create: `experiments/perceptual-video-hashing/tests/test_model.py`

- [ ] **Step 1: Write the failing model tests**

Define tests for exact enum values, immutable dataclasses, and stable exit
codes:

```python
from dataclasses import FrozenInstanceError
import unittest

from phash_benchmark.model import (
    Corpus,
    ExitCode,
    Item,
    Role,
    Split,
    UseBasis,
)


class ModelTest(unittest.TestCase):
    def test_protocol_values_are_stable(self):
        self.assertEqual(Role.SOURCE.value, "source")
        self.assertEqual(Role.DISTRACTOR.value, "distractor")
        self.assertEqual(Split.TRAIN.value, "train")
        self.assertEqual(Split.DEVELOPMENT.value, "development")
        self.assertEqual(Split.TEST.value, "test")
        self.assertEqual(Corpus.DIVINE_PUBLIC.value, "divine_public")
        self.assertEqual(UseBasis.OWNED_OR_LICENSED.value, "owned_or_licensed")
        self.assertEqual(ExitCode.OK, 0)
        self.assertEqual(ExitCode.PREFLIGHT, 2)
        self.assertEqual(ExitCode.INFRASTRUCTURE, 3)
        self.assertEqual(ExitCode.PARTIAL, 4)

    def test_items_are_immutable(self):
        item = Item(
            item_id="src_001",
            relative_path="sources/src_001.mp4",
            role=Role.SOURCE,
            corpus=Corpus.DIVINE_PUBLIC,
            use_basis=UseBasis.PUBLIC_LOCAL_RESEARCH,
            visual_classes=("live_action",),
            duplicate_group=None,
        )
        with self.assertRaises(FrozenInstanceError):
            item.item_id = "changed"
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
cd experiments/perceptual-video-hashing
PYTHONPATH=src python3 -m unittest tests.test_model -v
```

Expected: `ModuleNotFoundError: No module named 'phash_benchmark'`.

- [ ] **Step 3: Implement the exact model**

Use `StrEnum`, `IntEnum`, and frozen dataclasses. Define:

```python
class ExitCode(IntEnum):
    OK = 0
    PREFLIGHT = 2
    INFRASTRUCTURE = 3
    PARTIAL = 4


class Role(StrEnum):
    SOURCE = "source"
    DISTRACTOR = "distractor"


class Split(StrEnum):
    TRAIN = "train"
    DEVELOPMENT = "development"
    TEST = "test"


class Corpus(StrEnum):
    DIVINE_PUBLIC = "divine_public"
    ARCHIVE_PUBLIC = "archive_public"
    SYNTHETIC_GENERATED = "synthetic_generated"


class UseBasis(StrEnum):
    OWNED_OR_LICENSED = "owned_or_licensed"
    PUBLIC_LOCAL_RESEARCH = "public_local_research"
    ARCHIVE_LOCAL_RESEARCH = "archive_local_research"


@dataclass(frozen=True, slots=True)
class Item:
    item_id: str
    relative_path: str
    role: Role
    corpus: Corpus
    use_basis: UseBasis
    visual_classes: tuple[str, ...]
    duplicate_group: str | None
```

Define these additional frozen, slotted records with the exact fields shown:

```python
@dataclass(frozen=True, slots=True)
class RunRoles:
    corpus_approver: str
    benchmark_operator: str
    safety_reviewer: str
    decision_owner: str

@dataclass(frozen=True, slots=True)
class Manifest:
    schema_version: int
    corpus_id: str
    roles: RunRoles
    items: tuple[Item, ...]
    digests: Mapping[str, str]
    authorized_for_local_research: bool
    non_sensitive: bool
    perceptually_distinct_distractors_attested: bool
    corpus_approver_human_attested: bool
    decision_owner_human_attested: bool

@dataclass(frozen=True, slots=True)
class CommandResult:
    executable: str
    returncode: int
    stdout: str
    stderr: str
    wall_seconds: float
    child_cpu_seconds: float
    timed_out: bool
    output_limited: bool
    file_size_limited: bool

@dataclass(frozen=True, slots=True)
class Limits:
    wall_seconds: float
    child_cpu_seconds: float
    address_space_bytes: int
    process_count: int
    output_bytes: int
    output_file_bytes: int

@dataclass(frozen=True, slots=True)
class MediaProbe:
    item_id: str
    demuxer: str
    duration_seconds: float
    width: int
    height: int
    frame_rate: str
    file_bytes: int

@dataclass(frozen=True, slots=True)
class PairScore:
    algorithm: str
    split: Split
    query_id: str
    reference_id: str
    parent_reference_id: str | None
    transform_class: str
    distance: int | None
    quality: int | None
    query_percent: float | None
    reference_percent: float | None
    level_one: float | None
    level_two: float | None
    query_wall_seconds: float
    query_cpu_seconds: float

@dataclass(frozen=True, slots=True)
class HashMeasurement:
    algorithm: str
    item_id: str
    split: Split
    transform_class: str
    input_seconds: float
    wall_seconds: float
    child_cpu_seconds: float
    fingerprint_bytes: int

@dataclass(frozen=True, slots=True)
class OperatingPoint:
    algorithm: str
    distance: int | None
    quality: int | None
    reference_percent: float | None
    query_percent: float | None
    level_one: float | None
    level_two: float | None

@dataclass(frozen=True, slots=True)
class ConfusionCounts:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int

@dataclass(frozen=True, slots=True)
class Failure:
    phase: str
    opaque_item_id: str | None
    reason: str
    limit_name: str | None

@dataclass(frozen=True, slots=True)
class BudgetState:
    started_at_utc: str
    cumulative_cpu_seconds: float
    generated_bytes: int
    engineering_time_budget_confirmed: bool

@dataclass(frozen=True, slots=True)
class RunPaths:
    runs_root: Path
    run_id: str
    run_dir: Path
    marker: Path
    provenance: Path
    normalized_manifest: Path
    frozen_operating_points: Path
    raw_results: Path
    metrics: Path
    failures: Path
    report: Path
    pilot_acceptance: Path
    decision_acceptance: Path
    media_dir: Path
    hashes_dir: Path

@dataclass(frozen=True, slots=True)
class PreflightPlan:
    run_id: str
    source_count: int
    distractor_count: int
    expected_variant_count: int
    estimated_cpu_seconds: float
    estimated_wall_seconds: float
    estimated_peak_memory_bytes: int
    estimated_disk_bytes: int
    free_disk_bytes: int

@dataclass(frozen=True, slots=True)
class PhaseResult:
    phase: str
    expected: int
    attempted: int
    succeeded: int
    failed: int
    exit_code: ExitCode

@dataclass(frozen=True, slots=True)
class Context:
    manifest: Manifest
    paths: RunPaths
    seed: str
    config_digest: str
    image_digest: str
    budget: BudgetState

@dataclass(frozen=True, slots=True)
class Summary:
    conclusion: str
    gate_results: Mapping[str, bool]
    evaluations: tuple["Evaluation", ...]
    failures: tuple[Failure, ...]
    provenance: Mapping[str, object]
    projections: Mapping[str, Mapping[str, float]]
```

`Evaluation` and `Observation` are defined in Task 6 beside the computations
that construct them. Export `__version__ = "0.1.0"` from `__init__.py`. Pin
`coverage==7.15.2` in `requirements.lock`; there are no runtime Python
dependencies.

- [ ] **Step 4: Run the model test and verify GREEN**

Run the Step 2 command. Expected: two tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): define benchmark domain model"
```

### Task 2: Validate manifests and hostile input paths

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/manifest.py`
- Create: `experiments/perceptual-video-hashing/tests/test_manifest.py`
- Create: `experiments/perceptual-video-hashing/fixtures/example-manifest.json`

- [ ] **Step 1: Write failing validation tests**

Test:

- the exact v1 example loads;
- unknown top-level and item keys fail;
- all five attestation booleans must be literal `true`, including
  `perceptually_distinct_distractors`, `corpus_approver_human`, and
  `decision_owner_human`;
- attestation records opaque `corpus_approver_role`,
  `benchmark_operator_role`, `safety_reviewer_role`, and
  `decision_owner_role` aliases;
- every role alias is nonempty, matches the opaque ID grammar, and the corpus
  approver differs from the decision owner;
- IDs, paths, paths after canonical resolution, enums, class allowlist,
  duplicate IDs/paths/digests, symlinks, directories, FIFOs, and multi-link
  files fail;
- absolute paths, `..`, empty components, and NUL fail;
- SHA-256 is computed by preflight and never accepted from JSON;
- error messages contain opaque item IDs but not source paths.

The main positive test must call:

```python
manifest = load_manifest(manifest_path, input_root)
self.assertEqual(manifest.schema_version, 1)
self.assertEqual(manifest.items[0].item_id, "src_001")
self.assertEqual(
    manifest.digests["src_001"],
    hashlib.sha256(b"video").hexdigest(),
)
self.assertEqual(manifest.roles.corpus_approver, "corpus-approver")
self.assertNotEqual(
    manifest.roles.corpus_approver,
    manifest.roles.decision_owner,
)
```

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_manifest -v
```

Expected: import failure for `phash_benchmark.manifest`.

- [ ] **Step 3: Implement strict validation**

Implement:

```python
def load_manifest(path: Path, input_root: Path) -> Manifest
def validate_relative_path(value: object) -> PurePosixPath
def open_validated_regular_file(root: Path, relative: PurePosixPath) -> BinaryIO
def sha256_stream(stream: BinaryIO) -> str
```

Use strict key equality, `json.loads`, `lstat`, `O_NOFOLLOW` where available,
`fstat`, `stat.S_ISREG`, `st_nlink == 1`, and a post-open canonical containment
check. Reject duplicate byte digests unless every duplicate has the same
non-null `duplicate_group`. Never interpolate a path into an exception.

The visual class enum is:

```python
VISUAL_CLASSES = frozenset({
    "animation", "live_action", "text_heavy", "low_light",
    "static_scene", "camera_motion", "fast_cuts",
})
```

The accepted attestation shape is exactly:

```json
{
  "authorized_for_local_research": true,
  "non_sensitive": true,
  "perceptually_distinct_distractors": true,
  "corpus_approver_human": true,
  "decision_owner_human": true,
  "corpus_approver_role": "corpus-approver",
  "benchmark_operator_role": "benchmark-operator",
  "safety_reviewer_role": "safety-reviewer",
  "decision_owner_role": "decision-owner"
}
```

The example manifest contains one generated source and one generated
distractor with opaque names, both attestations, and all four role aliases.
`Manifest` includes a frozen `RunRoles` value; the provenance writer records
all four aliases and never records personal identifiers.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all manifest tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): validate benchmark manifests"
```

### Task 3: Implement deterministic split isolation

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/splits.py`
- Create: `experiments/perceptual-video-hashing/tests/test_splits.py`

- [ ] **Step 1: Write failing split tests**

Test deterministic output, different seeds, source 60/20/20 assignment,
distractor 100-development/remainder-test assignment, duplicate groups staying
together, every transform inheriting its parent's split, and pair construction
rejecting any query/reference whose splits differ.

Use 100 opaque source IDs and 400 distractors, and assert exact counts:

```python
self.assertEqual(Counter(source_splits.values()), {
    Split.TRAIN: 60,
    Split.DEVELOPMENT: 20,
    Split.TEST: 20,
})
self.assertEqual(Counter(distractor_splits.values()), {
    Split.DEVELOPMENT: 100,
    Split.TEST: 300,
})
```

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_splits -v
```

Expected: import failure for `phash_benchmark.splits`.

- [ ] **Step 3: Implement stable ranking**

Implement:

```python
def stable_rank(seed: str, group_key: str) -> bytes:
    return hashlib.sha256(f"{seed}\0{group_key}".encode()).digest()

def assign_splits(
    items: Sequence[Item],
    seed: str,
) -> dict[str, Split]:
    ...
```

Group sources by `duplicate_group or item_id`, sort groups by `stable_rank`,
and allocate counts with largest-remainder apportionment so 100 sources produce
60/20/20. Allocate distractors by stable rank with the first 100 development
and the rest test. Reject fewer than 400 distractors for a full run in
preflight, not in this pure function.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all split tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): isolate benchmark splits"
```

### Task 4: Probe hostile media and enforce supported local demuxers

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/media.py`
- Create: `experiments/perceptual-video-hashing/tests/test_media.py`

- [ ] **Step 1: Write failing probe and limit tests**

Test:

- only `.mp4`, `.m4v`, `.mov`, `.webm`, and `.mkv` inputs reach FFprobe;
- extensions map before parsing to explicit demuxers:
  `.mp4/.m4v/.mov -> mov` and `.webm/.mkv -> matroska`;
- explicit demuxer mapping accepts only `mov,mp4,m4a,3gp,3g2,mj2` as `mov`
  and `matroska,webm` as `matroska`;
- playlists, manifests, image sequences, concat files, and playlist/concat
  content renamed with an allowed extension fail under the forced demuxer;
  URLs, attached paths, unknown formats, multiple video streams,
  zero/negative/over-budget duration, invalid dimensions, and non-finite
  values fail;
- FFprobe arguments include `-nostdin`, `-v error`,
  `-protocol_whitelist file,pipe`, JSON output, and the revalidated path;
- canonical containment, regular-file status, link count, inode, and device
  are revalidated immediately before every FFprobe, FFmpeg, vPDQ, or TMK
  subprocess;
- child CPU, wall time, stdout/stderr, process count, and generated-file size
  limits produce structured opaque failures;
- normalization writes deterministic MP4 beneath the owned run and only that
  generated media, never the caller file, reaches vPDQ or TMK;
- native input paths use only generated opaque `[a-z0-9_-]` components, making
  TMK's pinned internal `/bin/sh`/`popen()` invocation non-injectable;
- malformed/undecodable files do not leak paths.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_media -v
```

Expected: import failure for `phash_benchmark.media`.

- [ ] **Step 3: Implement the fail-closed media boundary**

Implement:

```python
SUPPORTED_EXTENSIONS = frozenset({".mp4", ".m4v", ".mov", ".webm", ".mkv"})
DEMUXER_BY_EXTENSION = {
    ".mp4": "mov",
    ".m4v": "mov",
    ".mov": "mov",
    ".webm": "matroska",
    ".mkv": "matroska",
}
SUPPORTED_DEMUXERS = {
    "mov,mp4,m4a,3gp,3g2,mj2": "mov",
    "matroska,webm": "matroska",
}

def ffprobe_argv(path: Path, explicit_demuxer: str) -> tuple[str, ...]
def parse_probe(item_id: str, stdout: str, file_bytes: int) -> MediaProbe
def probe_media(item: Item, input_root: Path, limits: Limits) -> MediaProbe
def normalize_argv(
    input_path: Path,
    output_path: Path,
    explicit_demuxer: str,
) -> tuple[str, ...]
def revalidate_for_subprocess(
    root: Path,
    relative_path: PurePosixPath,
    expected_device: int,
    expected_inode: int,
) -> Path
```

`probe_media` opens and validates the regular file, records device/inode,
closes it, revalidates immediately before invoking FFprobe, parses one video
stream, and returns the explicit preselected demuxer used for FFprobe and later
as `-f mov` or `-f matroska`. `ffprobe_argv` includes that `-f` before `-i`;
no playlist-capable or auto-selected demuxer reaches FFprobe or FFmpeg.
The same sandboxed FFmpeg invocation normalizes accepted hostile input into a
deterministic H.264/AAC MP4 below the owned run directory. All transformations
operate on that normalized file, and vPDQ/TMK receive only normalized or
benchmark-generated variants with validated opaque paths. Raw caller media is
never passed to either upstream native hasher; this is required because pinned
vPDQ opens through libav without protocol CLI controls and pinned TMK invokes
FFmpeg through `popen()`.
`Limits` contains wall seconds, CPU seconds, address-space bytes, process
count, output bytes, and output-file bytes. `run_bounded` applies POSIX rlimits
inside the container and classifies each limit separately.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all media-boundary tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): constrain hostile media probing"
```

### Task 5: Generate deterministic transformation commands

**Files:**

- Create: `experiments/perceptual-video-hashing/config/defaults.json`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/transforms.py`
- Create: `experiments/perceptual-video-hashing/tests/test_transforms.py`

- [ ] **Step 1: Write failing transform tests**

Table-test exact argument arrays for remux, CRF 23/32 re-encode, 480p/240p
downscale, 15fps, overlay, letterbox, 5%/10% crop, hflip, 0.9x/1.1x speed,
middle subsequence, and two-copy loop. Assert:

- the first argument is `ffmpeg`;
- `-nostdin`, `-protocol_whitelist file,pipe`, deterministic metadata removal,
  bounded threads, and overwrite refusal are always present;
- no argument contains a shell control operator;
- outputs are derived from opaque IDs below the run transform directory;
- the same input/config returns identical arrays and transform IDs.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_transforms -v
```

Expected: import failure for `phash_benchmark.transforms`.

- [ ] **Step 3: Implement argument construction**

Define a frozen `TransformSpec(name, variant, video_filter, audio_filter,
duration_mode)` and:

```python
def default_transform_specs() -> tuple[TransformSpec, ...]
def transform_id(parent_id: str, spec: TransformSpec) -> str
def build_ffmpeg_command(
    input_path: Path,
    output_path: Path,
    spec: TransformSpec,
    duration_seconds: float,
) -> tuple[str, ...]
```

Use argument arrays only. Use `drawtext=text=DIVINE_TEST` with a checked-in
DejaVu font path from the container, `setpts`/`atempo` for speed, deterministic
`-map_metadata -1`, `-fflags +bitexact`, `-flags:v +bitexact`, H.264
`libx264`, AAC where audio exists, and no timestamps derived from wall time.
Validate every configured transformation name against a closed enum.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all transform tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): define deterministic video transforms"
```

### Task 6: Add bounded native-tool adapters and parsers

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/adapters.py`
- Create: `experiments/perceptual-video-hashing/tests/test_adapters.py`

- [ ] **Step 1: Write failing adapter tests**

Test exact vPDQ hash arguments:

```text
vpdq-hash-video -i INPUT -o OUTPUT -r 1.0 -s 160 -t 1
```

Test exact vPDQ comparison arguments:

```text
match-hashes-brute QUERY REFERENCE D F
```

Parse:

```text
67.76 Percentage Query Video match
80.85 Percentage Target Video match
```

into query `67.76` and reference `80.85`.

Test TMK hash arguments and parse:

```text
tmk-hash-video -f /usr/bin/ffmpeg -i INPUT -o OUTPUT
```

Test TMK raw-score arguments and parse:

```text
tmk-two-level-score --c1 -1 --c2 0 QUERY.tmk REFERENCE.tmk
0.952329 0.961902 QUERY.tmk REFERENCE.tmk
```

into level-one and level-two scores. Test malformed, duplicate, non-finite,
out-of-range, timeout, nonzero-exit, oversized-output, and path-leak
redaction behavior.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_adapters -v
```

Expected: import failure for `phash_benchmark.adapters`.

- [ ] **Step 3: Implement adapters**

Implement:

```python
def run_bounded(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    env: Mapping[str, str],
) -> CommandResult

def vpdq_hash_argv(input_path: Path, output_path: Path) -> tuple[str, ...]
def vpdq_compare_argv(
    query_hash: Path, reference_hash: Path, distance: int, quality: int
) -> tuple[str, ...]
def parse_vpdq_scores(stdout: str) -> tuple[float, float]
def tmk_hash_argv(input_path: Path, output_path: Path) -> tuple[str, ...]
def tmk_score_argv(query_hash: Path, reference_hash: Path) -> tuple[str, ...]
def parse_tmk_scores(stdout: str) -> tuple[float, float]
```

Run with `shell=False`, `stdin=DEVNULL`, `start_new_session=True`, a minimal
environment containing only `PATH`, `LANG=C.UTF-8`, and `TZ=UTC`, byte-mode
capturing, timeout-driven process-group termination, and bounded stdout/stderr.
Measure wall time with `time.monotonic_ns()` and child user+system CPU deltas
with `resource.getrusage(resource.RUSAGE_CHILDREN)` around each nonparallel
subprocess. After a successful hash, combine the command measurement with the
probed duration and `stat().st_size` into `HashMeasurement`; record each
comparison's wall/CPU time in `PairScore`. Tests use a real short-lived child
process to verify nonnegative units and a fake clock/resource reader for exact
normalization.
Return structured failures containing command basename and opaque item ID only.
TMK raw scoring uses `tmk-two-level-score --c1 -1 --c2 0 HASH_A HASH_B`.
The pinned tool accepts `--c2` but does not use it to suppress its printed
pair output; the adapter always collects raw scores and Python applies the
selected `c1` and `c2` thresholds. Native paths must first pass the generated
opaque-path validator because pinned TMK constructs an internal shell command.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all adapter tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): wrap perceptual hashing tools"
```

### Task 7: Calculate exhaustive metrics and freeze operating points

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/metrics.py`
- Create: `experiments/perceptual-video-hashing/tests/test_metrics.py`

- [ ] **Step 1: Write failing metric tests**

Cover:

- parent hits, wrong-reference false positives, missing parents, and all
  negative-pair true negatives;
- a query producing both a true positive and a wrong-reference false positive;
- zero denominators;
- query-level distractor matches;
- exact vPDQ Cartesian grid `D=(16,24,31,40)`,
  `F=(0,25,50,75)`, `Pc=(0,25,50,80,100)`, and
  `Pq=(0,25,50,80,100)`, with asymmetric reference/query percentages;
- exact TMK Cartesian grid `c1=(0.70,0.80,0.90,0.95)` and
  `c2=(0.70,0.80,0.90,0.95)`;
- rejection of values outside the official ranges and any combination absent
  from the checked-in configuration;
- lexicographic development selection: pair precision >= 0.99, then recall,
  then lower compute only when the paired source-bootstrap recall-difference
  interval includes zero;
- no passing point selecting highest precision for diagnosis;
- deterministic source-cluster bootstrap and exact one-sided zero-event upper
  bound `1 - 0.05 ** (1 / n)`;
- exhaustive aggregation across every algorithm × configured threshold ×
  split × transform, including expected/attempted/succeeded/failed
  denominators and per-reason failures;
- hash wall/CPU seconds per input second, query wall/CPU seconds per exhaustive
  pair, fingerprint bytes per input second and normalized six-second video,
  and supported-input completion;
- canonical JSON freeze bytes, SHA-256 filename, digest verification, and
  mutation rejection.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_metrics -v
```

Expected: import failure for `phash_benchmark.metrics`.

- [ ] **Step 3: Implement metrics**

Implement pure functions:

```python
@dataclass(frozen=True, slots=True)
class Observation:
    cluster_id: str
    expected_match: bool
    returned_parent: bool
    returned_wrong_reference: bool

@dataclass(frozen=True, slots=True)
class Evaluation:
    point: OperatingPoint
    split: Split
    transform_class: str
    counts: ConfusionCounts
    expected: int
    attempted: int
    succeeded: int
    failed: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    precision_interval: tuple[float, float]
    recall_interval: tuple[float, float]
    distractor_false_match_upper_bound: float
    correct_parent_query_recall: float
    distractor_query_matches: int
    transform_recall: Mapping[str, float]
    completion_rate: float
    hash_wall_per_input_second: float
    hash_cpu_per_input_second: float
    query_wall_seconds_per_pair: float
    query_cpu_seconds_per_pair: float
    fingerprint_bytes_per_input_second: float
    fingerprint_bytes_per_six_seconds: float
    observations: tuple[Observation, ...]

def evaluate_pairs(
    scores: Sequence[PairScore],
    parent_by_query: Mapping[str, str | None],
    point: OperatingPoint,
) -> Evaluation

def choose_operating_point(
    evaluations: Sequence[Evaluation],
) -> Evaluation

def aggregate_evaluations(
    scores: Sequence[PairScore],
    hashes: Sequence[HashMeasurement],
    failures: Sequence[Failure],
    points: Sequence[OperatingPoint],
) -> tuple[Evaluation, ...]

def bootstrap_interval(
    observations: Sequence[Observation],
    statistic: Callable[[Sequence[Observation]], float],
    *,
    seed: int,
    iterations: int = 10_000,
) -> tuple[float, float]

def zero_event_upper_bound(sample_size: int, alpha: float = 0.05) -> float
def write_freeze(path: Path, selections: Mapping[str, Evaluation]) -> Path
def load_freeze(path: Path, expected_digest: str) -> Mapping[str, object]
```

`aggregate_evaluations` emits one row for every algorithm, configured
operating point, split, and concrete transform plus an explicit
`transform_class="__overall__"` row. Every row carries both fingerprint bytes
per input second and normalized six-second bytes, so `Summary.evaluations`
serializes the complete `metrics.json` matrix without implicit dimensions.

For vPDQ, match when distance/quality were used to generate the raw score and
`reference_percent >= Pc` and `query_percent >= Pq`. For TMK, match when
`level_one >= c1` and `level_two >= c2`. Serialize with sorted keys, compact
separators, UTF-8, and no NaN. `choose_operating_point` first filters
development evaluations below 0.99 pair precision, selects maximum
correct-parent recall, and uses lower measured compute only when the
deterministic paired source-bootstrap interval of the recall difference
includes zero. It never reads held-out test observations.

The canonical freeze object has exactly:

```json
{
  "schema_version": 1,
  "orientation": "reference=canonical,query=variant_or_distractor",
  "seconds_per_hash": 1.0,
  "tool_version": "0.1.0",
  "threatexchange_commit": "baefb4ed67b6cdc1d4c82dbaef858d50866ac424",
  "development_result_digest": "<sha256>",
  "configuration_digest": "<sha256>",
  "selections": {
    "vpdq": {
      "distance": 31,
      "quality": 50,
      "reference_percent": 80.0,
      "query_percent": 0.0
    },
    "tmk": {
      "level_one": 0.9,
      "level_two": 0.9
    }
  }
}
```

The angle-bracket digest strings describe test fixtures; real serialization
requires lowercase 64-hex values. Mutation tests alter each field
independently and require digest verification to fail.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all metric tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): select frozen hashing thresholds"
```

### Artifact schema contract

Tasks 6–8 serialize only schema-versioned JSON with strict key validation and
round-trip tests:

- `provenance.json` (`schema_version`, four `roles`, `tool_version`,
  `threatexchange_commit`, `container_image_digest`, `base_image_digest`,
  `installed_packages`, `ffmpeg_version`, `binary_sha256`, `sbom_sha256`,
  `host_os`, `host_architecture`, `host_cpu`, `command`, `started_at_utc`,
  `manifest_digest`, `config_digest`, `seed`, and `budget`);
- `normalized-manifest.json` (`schema_version`, `corpus_id`, `roles`, opaque
  item IDs, roles/corpora/use bases/classes/groups, SHA-256, and assigned
  splits; local paths are excluded);
- `raw-results.jsonl` (one exact `PairScore` object per line);
- `metrics.json` (`schema_version`, expected/attempted/succeeded/failed counts,
  per-algorithm/per-threshold/per-split/per-transform confusion counts,
  pair/query metrics, confidence intervals, timing, bytes, completion rates,
  gate results, projections, and the machine-readable conclusion);
- `failures.jsonl` (one exact `Failure` object per line);
- `frozen-operating-points.json` (`schema_version`, canonical orientation
  `reference=canonical,query=variant_or_distractor`, cadence, tool version,
  ThreatExchange commit, development-result digest, configuration digest, and
  complete selected vPDQ or TMK fields from `OperatingPoint`);
- `report.md`, derived only from aggregate `metrics.json` and
  `provenance.json`;
- `pilot-acceptance.json` (pilot metrics digest, safety-reviewer role alias,
  boolean acceptance, and UTC acceptance time);
- `decision-acceptance.json` (report digest, one permitted conclusion, safety
  reviewer role alias, distinct decision owner role alias, boolean acceptance,
  and UTC acceptance time).

`normalized-manifest.json`, raw results, failures, native hashes, media, and
exact digests are restricted run data and removed by successful cleanup.
Aggregate metrics, aggregate report, and non-identifying provenance are
retained. Diagnostic failures and raw results expire after seven days.
Round-trip tests reject unknown keys, missing keys, NaN/infinity, wrong schema
versions, and type changes in every JSON/JSONL artifact.

### Task 8: Add owned run storage and aggregate reporting

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/store.py`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/report.py`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/provenance.py`
- Create: `experiments/perceptual-video-hashing/tests/test_store.py`
- Create: `experiments/perceptual-video-hashing/tests/test_report.py`
- Create: `experiments/perceptual-video-hashing/tests/test_provenance.py`

- [ ] **Step 1: Write failing store and report tests**

Store tests require:

- run IDs matching `^[a-z0-9][a-z0-9_-]{2,63}$`;
- atomic create with mode `0700`;
- a random ownership nonce in `.phash-benchmark-owned.json`;
- canonical runs-root containment on create, every open, and cleanup;
- cleanup refusal for missing/mismatched markers, symlinks, root itself, and
  caller inputs;
- success cleanup removing media, hashes, and raw pairs while retaining
  aggregate report/provenance;
- success cleanup refusing a valid report until a matching atomic
  `decision-acceptance.json` exists;
- atomic pilot/final acceptance rejecting wrong role aliases, changed metric
  or report digests, unknown conclusions, every recognized conclusion that
  differs from the current machine-readable `metrics.json` conclusion, and
  duplicate mutation;
- diagnostic cleanup retaining bounded failures for no more than seven days.

Report tests require the first heading to be the conclusion, then a gate table,
transform metrics, failures, confidence intervals, provenance, limitations,
and 10k/100k/1m projections. Assert reports contain no paths, URLs, 64-hex
digests, frame hashes, usernames, or non-aggregate item IDs.

Table-test the decision engine for:

- `NO DECISION` on partial/incomplete/invalid runs;
- no adoption when neither standalone candidate passes;
- the sole passing candidate;
- vPDQ and TMK quality wins when paired recall advantage is at least five
  percentage points, its 95% interval excludes zero, and no required transform
  regresses by more than two points;
- lower hash CPU when quality is indistinguishable;
- lower fingerprint bytes when CPU is within 10%;
- TMK's fixed-length model when both CPU and bytes are within 10%.

Each passing candidate must have pair precision >= 0.99, zero held-out
distractor-query matches, an exact upper bound, recall >= 0.90 for remux,
reencode, downscale, and watermark, completion >= 0.99, hash CPU/input second
<= 0.1, and fingerprint bytes/six-second video <= 10 KiB. Crop, padding,
speed, subsequence, and remix must be present separately but have no hard
recall floor.

Projection tests use:

```text
daily_cpu_seconds = daily_uploads * measured_cpu_seconds_per_six_second_video
daily_storage_bytes = daily_uploads * measured_fingerprint_bytes_per_six_seconds
daily_review_upper = daily_uploads * false_match_upper_bound
```

for daily uploads 10,000, 100,000, and 1,000,000.

Provenance tests inject platform/clock/command readers and require every field
in the artifact contract, exact sorted installed-package versions, FFmpeg
version, image/base digests, binary and SBOM checksums, host OS/architecture/CPU,
UTC start time, manifest/config digests, seed, budget, and all four role
aliases. Environment variables, home paths, usernames, media paths, and
credentials must never be captured.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_store tests.test_report tests.test_provenance -v
```

Expected: import failures for `store` and `report`.

- [ ] **Step 3: Implement owned storage and reports**

Implement:

```python
def create_run(runs_root: Path, run_id: str) -> RunPaths
def open_owned_run(runs_root: Path, run_id: str) -> RunPaths
def atomic_json(path: Path, value: object) -> None
def cleanup_run(paths: RunPaths, *, diagnostic: bool) -> None
def cleanup_expired(runs_root: Path, *, now: datetime) -> tuple[str, ...]
def accept_pilot(paths: RunPaths, reviewer_role: str, *, now: datetime) -> None
def accept_decision(
    paths: RunPaths,
    conclusion: str,
    reviewer_role: str,
    decision_owner_role: str,
    *,
    now: datetime,
) -> None
def collect_provenance(context: Context, command: Sequence[str]) -> Mapping[str, object]
def candidate_gates(evaluation: Evaluation) -> Mapping[str, bool]
def choose_conclusion(
    vpdq: Evaluation,
    tmk: Evaluation,
    *,
    partial: bool,
) -> str
def project_shadow_load(
    evaluation: Evaluation,
    false_match_upper_bound: float,
) -> Mapping[str, Mapping[str, float]]
def render_report(summary: Summary) -> str
def sanitized_report(report: str) -> None
```

Use `os.open` exclusive creation, `fsync`, `os.replace`, non-following
directory traversal, explicit known child names, and no recursive deletion of
an unresolved path. `sanitized_report` fails closed on forbidden patterns.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: all store/report tests pass.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): secure run artifacts and reports"
```

### Task 9: Orchestrate preflight, staged execution, and stable CLI

**Files:**

- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/pipeline.py`
- Create: `experiments/perceptual-video-hashing/src/phash_benchmark/cli.py`
- Create: `experiments/perceptual-video-hashing/tests/test_pipeline.py`
- Create: `experiments/perceptual-video-hashing/tests/test_cli.py`
- Create: `experiments/perceptual-video-hashing/benchmark`

- [ ] **Step 1: Write failing phase and CLI tests**

Use fake adapters with real temporary files. Verify:

- `preflight` is read-only and checks attestation, exactly 50
  `divine_public` sources, exactly 50 `archive_public` sources, no other real
  source corpus, at least 400 distractors, all four recorded role aliases,
  corpus-approver/decision-owner separation, representation minima, disk +25%,
  estimated CPU, wall time, peak memory, disk, and sandbox runtime;
- `smoke` generates safe media and requires exact/re-encode positives plus an
  unrelated negative for both algorithms;
- `pilot` uses exactly five sources per real corpus and 20 distractors;
- per-item failures continue but produce exit 4 and `NO DECISION`;
- containment, freeze, ground-truth, or isolation errors abort;
- budget guards stop before an operation would exceed 720,000 cumulative CPU
  seconds or 268,435,456,000 generated bytes, and stop a resumed run seven
  days after `started_at_utc`;
- full real-media execution requires the human-recorded
  `engineering_time_budget_confirmed` flag for the five-engineering-day cap;
- stage 1 stops when either official candidate fails build, regression, or any
  required synthetic smoke assertion;
- stage 2 stops on two occurrences of the same sandbox-limit failure, any
  transform class below 80% successful generation in the pilot, or a projected
  full run above the remaining CPU/disk budget;
- tune only uses train/development and emits the freeze;
- test requires and verifies the freeze and never calls selection;
- every query/reference pair is scored;
- `full` hands one explicit runs root/run ID through every phase;
- `full` allocates when `--run` is absent, pauses real media after pilot with
  `pilot_acceptance_required`, and resumes the same explicit run only after
  immutable pilot acceptance;
- `smoke` allocates and prints a run ID when `--run` is omitted and opens that
  explicit owned run when it is supplied;
- `pilot` accepts manifest/input/runs root, allocates and prints a run ID when
  omitted, and may explicitly reopen only the same manifest-digest run;
- `accept-pilot`, `tune`, `test`, `report`, `accept`, and `cleanup` require
  both `--runs-root` and `--run`;
- `tune` refuses a real-media run without immutable pilot acceptance;
- exit statuses are exactly 0, 2, 3, and 4.
- success cleanup removes restricted artifacts after report acceptance;
  handled failure cleanup removes generated media/hashes immediately, retains
  bounded diagnostics with expiry metadata, and returns exit 4; expired-run
  cleanup returns exit 0 only when every selected owned run was removed.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_pipeline tests.test_cli -v
```

Expected: import failures for `pipeline` and `cli`.

- [ ] **Step 3: Implement phases and CLI**

Implement:

```python
def preflight(
    manifest_path: Path,
    input_root: Path,
    runs_root: Path,
) -> PreflightPlan
def smoke(context: Context) -> PhaseResult
def pilot(context: Context) -> PhaseResult
def tune(context: Context) -> PhaseResult
def test_frozen(context: Context, freeze_path: Path) -> PhaseResult
def report(context: Context) -> PhaseResult
def full(
    manifest_path: Path,
    input_root: Path,
    runs_root: Path,
    run_id: str | None = None,
) -> ExitCode
def main(argv: Sequence[str] | None = None) -> int
```

Every phase records expected/attempted/succeeded/failed counts. For automated
synthetic fixtures, `full` executes preflight, smoke, pilot, tune, frozen test,
and report. For real media it pauses after pilot until `accept-pilot`; the
operator resumes with the same `full ... --run <id>` or uses individual
tune/test/report commands. The resumed path ends in `pending_acceptance`; it
never performs success cleanup before human decision acceptance. It
applies pure `check_stage_one`, `check_stage_two`, and `check_budget`
predicates with the exact limits above before advancing. The launcher sets
`PYTHONPATH` relative to its real directory and executes
`python3 -m phash_benchmark.cli "$@"` without `eval`.

The exact lifecycle is:

| Command | Allocates run | Required location arguments |
|---|---:|---|
| `build` | no | none |
| `preflight` | no | `--manifest --input-root --runs-root` |
| `smoke` | yes unless reopening | `--runs-root [--run]` |
| `pilot` | yes unless reopening | `--manifest --input-root --runs-root [--run]` |
| `accept-pilot` | no | `--runs-root --run --safety-reviewer-role` |
| `tune` | no | `--runs-root --run` |
| `test` | no | `--runs-root --run --freeze` |
| `report` | no | `--runs-root --run` |
| `accept` | no | `--runs-root --run --conclusion --safety-reviewer-role --decision-owner-role` |
| `cleanup` | no | `--runs-root --run` |
| `full` | yes unless reopening | `--manifest --input-root --runs-root [--run]` |

Allocated IDs are printed on stdout as `run_id=<opaque-id>`. Reopening verifies
the ownership marker, manifest digest, configuration digest, and immutable
completed-phase artifacts before resuming.
`accept-pilot` and `accept` call the atomic validated store APIs from Task 8.
`accept` reads the strict current metrics artifact and requires its conclusion
to equal the supplied recognized conclusion before it hashes the report and
writes acceptance.
`cleanup` refuses success cleanup until `accept` exists and matches the current
report digest; handled partial runs use diagnostic cleanup without acceptance.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command, then:

```bash
./benchmark --help
```

Expected: tests pass and help lists `build`, `preflight`, `smoke`, `pilot`,
`accept-pilot`, `tune`, `test`, `report`, `accept`, `cleanup`, and `full`.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "feat(phash-spike): orchestrate benchmark phases"
```

### Task 10: Build the pinned, non-root native container

**Files:**

- Create: `experiments/perceptual-video-hashing/Dockerfile`
- Create: `experiments/perceptual-video-hashing/container/apt-packages.lock`
- Create: `experiments/perceptual-video-hashing/container/spdx_from_dpkg.py`
- Create: `experiments/perceptual-video-hashing/tests/test_container_contract.py`
- Modify: `experiments/perceptual-video-hashing/benchmark`

- [ ] **Step 1: Write failing container-contract tests**

Parse the Dockerfile and launcher as text and require:

- base `ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90`;
- exact ThreatExchange commit;
- Ubuntu snapshot `20260610T000000Z` and exact direct package lock;
- release CMake build and nonparallel TMK build;
- upstream vPDQ/TMK regression invocations;
- copied binary checksums and an SPDX JSON SBOM;
- final runtime contains `/bin/sh` for pinned TMK's internal `popen()` and
  DejaVu Sans from the pinned font package;
- numeric non-root user and read-only work paths;
- runtime command flags `--network none`, `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, PID/memory/CPU limits, tmpfs, read-only
  input mount, writable run mount, and an environment allowlist;
- no home, cloud, SSH agent, Docker socket, or host-root mount.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_container_contract -v
```

Expected: missing Dockerfile contract.

- [ ] **Step 3: Implement the container contract**

Use a multi-stage Dockerfile:

```dockerfile
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS build
ARG THREATEXCHANGE_COMMIT=baefb4ed67b6cdc1d4c82dbaef858d50866ac424
ARG UBUNTU_SNAPSHOT=20260610T000000Z
```

Rewrite both Ubuntu archive and security sources to the fixed snapshot.
`apt-packages.lock` pins these direct packages:

```text
build-essential=12.10ubuntu1
ca-certificates=20240203
cmake=3.28.3-1build7
ffmpeg=7:6.1.1-3ubuntu5
fonts-dejavu-core=2.37-8
git=1:2.43.0-1ubuntu7.3
libavcodec-dev=7:6.1.1-3ubuntu5
libavdevice-dev=7:6.1.1-3ubuntu5
libavfilter-dev=7:6.1.1-3ubuntu5
libavformat-dev=7:6.1.1-3ubuntu5
libavutil-dev=7:6.1.1-3ubuntu5
libgomp1=14.2.0-4ubuntu2~24.04.1
libswresample-dev=7:6.1.1-3ubuntu5
libswscale-dev=7:6.1.1-3ubuntu5
make=4.3-4.1build2
pkg-config=1.8.1-2build1
python3=3.12.3-0ubuntu2.1
python3-venv=3.12.3-0ubuntu2.1
```

Install the lock with `--no-install-recommends`, clone without credentials,
verify
`HEAD`, build vPDQ with `-DCMAKE_BUILD_TYPE=Release`, build TMK without FAISS,
run upstream regression vectors, generate binary SHA-256 files and an SPDX
2.3 JSON SBOM using the checked-in standard-library
`spdx_from_dpkg.py` over `dpkg-query`, and copy only runtime
libraries/binaries plus the Python package into a non-root final stage. The
SBOM generator itself has unit tests for deterministic namespace, package
records, checksums, and invalid dpkg input. The launcher has separate `build`
and safe `docker run` paths; `full` builds first, then runs offline with the
mandatory isolation flags and explicit mounts. The container contract asserts
`test -x /bin/sh`, the exact font file, and the recorded versions.

- [ ] **Step 4: Run contract test and attempt the build**

```bash
PYTHONPATH=src python3 -m unittest tests.test_container_contract -v
./benchmark build
```

Expected: contract test passes. The build passes when a Docker daemon and
network are available; otherwise record the exact infrastructure failure
without weakening the Dockerfile.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "build(phash-spike): pin native hashing toolchain"
```

### Task 11: Generate synthetic fixtures and prove both algorithms end to end

**Files:**

- Create: `experiments/perceptual-video-hashing/fixtures/generate.py`
- Create: `experiments/perceptual-video-hashing/tests/test_synthetic_fixture.py`
- Create: `experiments/perceptual-video-hashing/tests/test_native_smoke.py`

- [ ] **Step 1: Write failing fixture tests**

Require argument-array generation for three six-second MP4s:

- source: moving test pattern plus 440 Hz tone;
- re-encode: same visual content at CRF 32;
- unrelated: different generated pattern plus 880 Hz tone.

Assert deterministic metadata, output containment, no shell, and a generated
manifest with opaque IDs and attestations. Gate the native smoke test behind
`PHASH_NATIVE_SMOKE=1`; when enabled it must hash all three with both tools and
assert source/re-encode matches while unrelated does not at documented smoke
thresholds: vPDQ `D=31,F=50,Pc=80,Pq=0` and TMK
`c1=0.70,c2=0.70`.

Also generate a truncated MP4 and a text file with an `.mp4` suffix; native
integration must classify both as bounded `unsupported_media` or
`decode_failed`, emit no source path, and continue to the next item. Run the
same generated manifest twice with the same seed in separate owned run roots
and assert byte-identical split assignments, metric JSON, and frozen operating
points after removing permitted provenance timestamps/run IDs.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_synthetic_fixture tests.test_native_smoke -v
```

Expected: fixture import failure.

- [ ] **Step 3: Implement safe generation**

Implement `generate(output_root: Path) -> Path` using direct FFmpeg argument
arrays and return the manifest path. The native smoke invokes only container
binaries and records exact scores; it never substitutes a mock when enabled.

- [ ] **Step 4: Run and verify GREEN**

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_synthetic_fixture tests.test_native_smoke -v
PHASH_NATIVE_SMOKE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_native_smoke -v
PHASH_NATIVE_SMOKE=1 ./benchmark smoke --runs-root /tmp/divine-phash-smoke
```

Expected: unit tests pass. Native smoke is a required completion gate; if
Docker is unavailable or either official tool fails, Task 11 and the overall
spike remain incomplete with the exact infrastructure error recorded.

- [ ] **Step 5: Commit**

```bash
git add experiments/perceptual-video-hashing
git commit -m "test(phash-spike): add native synthetic smoke"
```

### Task 12: Document operation, retention, and limitations

**Files:**

- Create: `experiments/perceptual-video-hashing/README.md`
- Modify: `.gitignore`
- Create: `experiments/perceptual-video-hashing/tests/test_documentation.py`

- [ ] **Step 1: Write failing documentation tests**

Require the README to contain:

- every command and stable exit code;
- exact manifest schema/example;
- corpus approver, operator, safety reviewer, and decision owner roles;
- Docker daemon prerequisite and safe command preview;
- 5-day/200-CPU-hour/250-GiB/seven-day caps;
- cleanup success/failure behavior and statement that originals are never
  deleted;
- no-enforcement and benign-proxy limitations;
- aggregate report order and decision rule;
- explicit instruction that a passing result authorizes only a separate
  shadow-pilot design.

Require `.gitignore` entries for input media, `runs/`, generated variants,
`.vpdq`, `.tmk`, hash text, `.coverage`, and HTML coverage.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_documentation -v
```

Expected: missing README requirements.

- [ ] **Step 3: Write the runbook and ignore rules**

Document copy-paste commands for build, preflight, full, each follow-up phase,
report review, exact-run cleanup, and expired-run cleanup. Include no real
source URLs, IDs, fingerprints, or credentials. Add only experiment-scoped
ignore rules without changing existing user entries.

- [ ] **Step 4: Run and verify GREEN**

Run the Step 2 command. Expected: documentation tests pass.

- [ ] **Step 5: Commit**

```bash
git add .gitignore experiments/perceptual-video-hashing
git commit -m "docs(phash-spike): document safe benchmark operation"
```

### Task 13: Enforce 100% coverage and final verification

**Files:**

- Create: `experiments/perceptual-video-hashing/.coveragerc`
- Create: `experiments/perceptual-video-hashing/tests/test_config_contract.py`

- [ ] **Step 1: Write the failing coverage/config contract test**

Require `.coveragerc` to enable branch coverage, measure
`src/phash_benchmark`, `fixtures/generate.py`, and
`container/spdx_from_dpkg.py`, omit no Divine source files, and fail under 100.
Require `requirements.lock` to pin coverage exactly.

- [ ] **Step 2: Run and verify RED**

```bash
PYTHONPATH=src python3 -m unittest tests.test_config_contract -v
```

Expected: `.coveragerc` missing.

- [ ] **Step 3: Add exact coverage configuration**

```ini
[run]
branch = True
source =
    src/phash_benchmark
    fixtures
    container

[report]
fail_under = 100
show_missing = True
skip_covered = False
```

- [ ] **Step 4: Run full fresh verification**

Create a temporary venv outside the repository, install
`requirements.lock`, then run:

```bash
python -m coverage erase
PYTHONPATH=src python -m coverage run --branch -m unittest discover -s tests -v
python -m coverage report --fail-under=100
./benchmark --help
git diff --check
git status --short
```

Expected: every test passes, line and branch coverage are 100%, help succeeds,
the diff has no whitespace errors, and only planned files are staged or
committed.

Native verification is mandatory:

```bash
./benchmark build
PHASH_NATIVE_SMOKE=1 PYTHONPATH=src python -m unittest \
  tests.test_native_smoke -v
PHASH_NATIVE_SMOKE=1 ./benchmark smoke --runs-root /tmp/divine-phash-smoke
```

If Docker is unavailable or either command fails, record the exact
infrastructure failure and leave the task and spike incomplete. Do not commit
the final verification step or claim the harness complete until both commands
pass.

- [ ] **Step 5: Request code review and commit verification config**

Apply `superpowers:requesting-code-review`, address blocking findings, rerun
Step 4, then:

```bash
git add experiments/perceptual-video-hashing/.coveragerc \
  experiments/perceptual-video-hashing/tests/test_config_contract.py
git commit -m "test(phash-spike): enforce complete harness coverage"
```

### Task 14: Execute the authorized corpus and accept the decision

**External inputs (not committed):**

- Authorized manifest implementing the exact v1 contract.
- Read-only input root containing exactly 50 `divine_public` sources, exactly
  50 `archive_public` sources, and at least 400 attested distinct distractors.
- Operator-selected runs root with at least the preflight disk requirement.
- Task-specific run ID, freeze path, selected conclusion, safety-reviewer role,
  and decision-owner role values copied exactly from validated command output
  and manifest provenance as their `PHASH_*` variables are needed.

- [ ] **Step 1: Verify external authorization and preflight**

The operator supplies explicit absolute paths through task-specific variables:

```bash
test -f "$PHASH_CORPUS_MANIFEST"
test -d "$PHASH_INPUT_ROOT"
test -d "$PHASH_RUNS_ROOT"
./benchmark preflight \
  --manifest "$PHASH_CORPUS_MANIFEST" \
  --input-root "$PHASH_INPUT_ROOT" \
  --runs-root "$PHASH_RUNS_ROOT"
```

Expected: exit 0 with exact 50/50/400+ counts, technical-class representation
counts, all four role aliases, authorization/non-sensitive/distinctness
attestations, resource estimates, and 25% disk headroom. If these external
inputs are absent or invalid, this task and the research spike remain blocked;
do not substitute downloaded or synthetic media.

- [ ] **Step 2: Run and review the bounded pilot**

```bash
./benchmark pilot \
  --manifest "$PHASH_CORPUS_MANIFEST" \
  --input-root "$PHASH_INPUT_ROOT" \
  --runs-root "$PHASH_RUNS_ROOT"
```

Expected: exit 0, a printed run ID, five sources from each real corpus, 20
distractors, every transform represented, no repeated sandbox exhaustion, and
resource projections within the remaining caps. The safety reviewer records
the aggregate pilot acceptance before full execution:

```bash
./benchmark accept-pilot \
  --runs-root "$PHASH_RUNS_ROOT" \
  --run "$PHASH_RUN_ID" \
  --safety-reviewer-role "$PHASH_SAFETY_REVIEWER_ROLE"
```

- [ ] **Step 3: Execute tune, immutable freeze, and held-out test**

Use the pilot-approved run ID:

```bash
./benchmark tune --runs-root "$PHASH_RUNS_ROOT" --run "$PHASH_RUN_ID"
./benchmark test \
  --runs-root "$PHASH_RUNS_ROOT" \
  --run "$PHASH_RUN_ID" \
  --freeze "$PHASH_FREEZE_PATH"
./benchmark report --runs-root "$PHASH_RUNS_ROOT" --run "$PHASH_RUN_ID"
```

`tune` first generates and hashes the full authorized corpus, then consumes
only train/development data for threshold selection. `test` verifies the
content-addressed freeze and has no tuning path; report is aggregate-only and
selects exactly vPDQ, TMK+PDQF, or no adoption. Exit 4 means `NO DECISION` and
the spike remains incomplete.

- [ ] **Step 4: Record human review and decision-owner acceptance**

After the safety reviewer confirms omissions, failure denominators,
confidence bounds, and sanitization, invoke:

```bash
./benchmark accept \
  --runs-root "$PHASH_RUNS_ROOT" \
  --run "$PHASH_RUN_ID" \
  --conclusion "$PHASH_CONCLUSION" \
  --safety-reviewer-role "$PHASH_SAFETY_REVIEWER_ROLE" \
  --decision-owner-role "$PHASH_DECISION_OWNER_ROLE"
```

The command atomically writes an owned `decision-acceptance.json` containing
exactly:

```json
{
  "schema_version": 1,
  "report_sha256": "<lowercase-64-hex>",
  "conclusion": "vpdq|tmk|no_adoption",
  "safety_reviewer_role": "<opaque-role-alias>",
  "decision_owner_role": "<different-opaque-role-alias>",
  "accepted": true,
  "accepted_at_utc": "<RFC3339>"
}
```

The CLI validates aliases against provenance and rejects personal identifiers,
unknown fields, a changed report digest, or an unrecognized conclusion.

- [ ] **Step 5: Clean restricted data and verify retained evidence**

```bash
./benchmark cleanup --runs-root "$PHASH_RUNS_ROOT" --run "$PHASH_RUN_ID"
```

Expected: caller originals remain untouched; normalized media, variants,
native hashes, raw pairs, exact digests, and restricted failure details are
removed; aggregate metrics, sanitized report, non-identifying provenance,
freeze, and decision acceptance remain. Only after this verification is the
research spike complete.

## Implementation constraints

- Follow RED → verify failure → GREEN for every production behavior.
- Never stage or modify unrelated dirty-worktree files.
- Use a clean feature worktree created with
  `superpowers:using-git-worktrees` before Task 1.
- Do not fetch, select, or commit the real 100-source/400-distractor corpus.
  Task 14 runs only when the authorized operator-provided manifest and files
  exist.
- Do not weaken sandbox flags or tests because Docker Desktop is unavailable.
- Do not add a production integration, external hash list, FAISS path,
  moderation call, or automatic action.
- The actual held-out benchmark and research spike remain incomplete until
  Task 14 produces and accepts a valid frozen decision.
