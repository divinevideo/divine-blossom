# Internal Compilation Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the internal `compiler.divine.video` editor, its private Cloud Run compilation API, and the trusted resumable upload behavior needed to produce downloadable external-platform compilations from existing ordered Nostr lists.

**Architecture:** A React/Vite editor and Cloudflare Worker live in `compiler-web/`; the Worker serves assets, enforces the Cloudflare Access boundary, and invokes a private Cloud Run service with a Google identity token. `cloud-run-compiler/` verifies NIP-98 plus the exact signed list event, persists jobs in Firestore, resolves ordered video events from the Divine relay, renders each aspect independently with FFmpeg, and streams final files through `cloud-run-upload/`.

**Tech Stack:** Rust 1.83, axum 0.7, tokio, `nostr`/`nostr-sdk` 0.44, Firestore, FFmpeg/NVENC, React 18, TypeScript, Vite, Vitest, `@divinevideo/login`, `nostr-tools`, Cloudflare Workers, Wrangler.

**Design:** `docs/superpowers/specs/2026-07-26-compilation-editor-design.md`

---

## File Structure

```text
cloud-run-upload/
├── src/main.rs                    # authorize compiler-only derivative suppression
├── src/resumable.rs               # persist generate_derivatives on upload sessions
└── Cargo.lock

cloud-run-compiler/
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── deploy.sh
├── .dockerignore
├── src/
│   ├── lib.rs                     # module exports and shared AppState
│   ├── main.rs                    # Cloud Run bootstrap
│   ├── config.rs                  # environment validation
│   ├── domain.rs                  # request, event, job, output, and error types
│   ├── auth.rs                    # NIP-98 and signed-list verification
│   ├── store.rs                   # JobStore trait, memory tests, Firestore implementation
│   ├── source.rs                  # ordered a-coordinate resolution and media metadata
│   ├── render.rs                  # probe, filters, FFmpeg, NVENC fallback
│   ├── upload.rs                  # Blossom auth and resumable upload client
│   ├── worker.rs                  # queued-job orchestration
│   └── http.rs                    # health, compile, status, and recent-job routes
└── tests/
    ├── api.rs
    ├── auth.rs
    ├── domain.rs
    ├── source.rs
    ├── render.rs
    ├── upload.rs
    └── worker.rs

compiler-web/
├── package.json
├── package-lock.json
├── tsconfig.json
├── vite.config.ts
├── vitest.setup.ts
├── index.html
├── wrangler.jsonc
├── worker/
│   ├── index.ts                   # Access check, static assets, and API proxy
│   ├── googleIdentity.ts          # cached Cloud Run identity-token exchange
│   └── index.test.ts
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── styles.css
    ├── types.ts
    ├── auth/
    │   ├── divineLogin.ts         # OAuth PKCE and hosted signer session
    │   └── signer.ts              # Divine RPC and NIP-98 event signing
    ├── nostr/
    │   ├── relay.ts               # list/event query and publish
    │   ├── lists.ts               # list parsing and safe reorder replacement
    │   └── lists.test.ts
    ├── compiler/
    │   ├── api.ts                 # same-origin compiler API client
    │   └── api.test.ts
    └── components/
        ├── Header.tsx
        ├── Preview.tsx
        ├── Timeline.tsx
        ├── RenderControls.tsx
        └── RecentJobs.tsx
```

## Task 1: Trusted Upload Derivative Suppression

**Files:**
- Modify: `cloud-run-upload/src/resumable.rs`
- Modify: `cloud-run-upload/src/main.rs`
- Modify: `cloud-run-upload/Cargo.lock`

- [ ] **Step 1: Write failing request and completion tests**

Add tests that deserialize `generateDerivatives`, preserve it in
`UploadSession`, and verify completion calls no derivative endpoint only when
the authenticated owner is in `COMPILER_OUTPUT_OWNER_PUBKEYS`.

```rust
#[test]
fn init_accepts_generate_derivatives_false() {
    let request: ResumableUploadInitRequest = serde_json::from_value(serde_json::json!({
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size": 4,
        "contentType": "video/mp4",
        "generateDerivatives": false
    })).unwrap();
    assert!(!request.generate_derivatives);
}

#[tokio::test]
async fn compiler_owner_can_suppress_derivatives() {
    assert!(!should_generate_derivatives(
        false,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        &["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()],
    ));
}

#[tokio::test]
async fn ordinary_owner_cannot_suppress_derivatives() {
    assert!(should_generate_derivatives(
        false,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        &["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()],
    ));
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-upload/Cargo.toml init_accepts_generate_derivatives_false compiler_owner_can_suppress_derivatives ordinary_owner_cannot_suppress_derivatives
```

Expected: compilation fails because the request field and policy function do
not exist.

- [ ] **Step 3: Implement the policy and persisted session flag**

Add `generate_derivatives: bool` with a serde default of `true` to init requests
and sessions. Parse `COMPILER_OUTPUT_OWNER_PUBKEYS` into full lowercase
64-character hex pubkeys. Reject malformed configured pubkeys at startup.
Effective behavior is:

```rust
pub(crate) fn should_generate_derivatives(
    requested: bool,
    owner: &str,
    compiler_owners: &[String],
) -> bool {
    requested || !compiler_owners.iter().any(|candidate| candidate == owner)
}
```

Use the effective value saved on the session when
`handle_resumable_complete` decides whether to call
`maybe_trigger_derivatives`.

- [ ] **Step 4: Run upload tests and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked
```

Expected: all upload tests pass, including the existing ordinary-video
derivative regression tests.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-upload/src/main.rs cloud-run-upload/src/resumable.rs cloud-run-upload/Cargo.lock
git commit -m "feat(upload): allow compiler outputs to skip derivatives"
```

## Task 2: Compiler Domain and Validation

**Files:**
- Create: `cloud-run-compiler/Cargo.toml`
- Create: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/src/domain.rs`
- Create: `cloud-run-compiler/tests/domain.rs`

- [ ] **Step 1: Write failing domain tests**

Tests cover literal `a` tag order, kind restrictions, unique aspects, override
coordinates, and partial aspect success:

```rust
#[test]
fn list_coordinates_keep_literal_tag_order() {
    let event = signed_list_fixture(vec![
        tag(["a", &coordinate(34236, 'a'), "wss://relay.divine.video"]),
        tag(["title", "Friday"]),
        tag(["a", &coordinate(34235, 'b')]),
    ]);
    assert_eq!(
        event.video_coordinates().unwrap(),
        vec![coordinate(34236, 'a'), coordinate(34235, 'b')]
    );
}

#[test]
fn one_output_and_one_failure_is_done() {
    let result = JobResult {
        outputs: vec![output(Aspect::Portrait)],
        aspect_failures: vec![failure(Aspect::Square)],
        ..JobResult::default()
    };
    assert_eq!(result.terminal_status(), JobStatus::Done);
}
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test domain
```

Expected: the new crate or domain symbols do not exist.

- [ ] **Step 3: Implement strict serde types and validation**

Implement `NostrEvent`, `CompileRequest`, `RenderRequest`, `Aspect`, `FitMode`,
`ClipOverride`, `Job`, `JobResult`, `Output`, `AspectFailure`, `ClipDrop`, and
`Credit`. Apply `#[serde(deny_unknown_fields)]` to all request types.

`CompileRequest::validate()` returns stable codes:

```rust
pub enum ValidationError {
    InvalidListKind,
    MissingDTag,
    UnsupportedCoordinate,
    TooManyClips,
    EmptyRenders,
    DuplicateAspect,
    UnknownOverrideCoordinate,
    DuplicateOverrideCoordinate,
}
```

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test domain
```

Expected: all domain tests pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/Cargo.toml cloud-run-compiler/Cargo.lock cloud-run-compiler/src/lib.rs cloud-run-compiler/src/domain.rs cloud-run-compiler/tests/domain.rs
git commit -m "feat(compiler): define compilation job contract"
```

## Task 3: Compiler Authentication and Job Storage

**Files:**
- Create: `cloud-run-compiler/src/auth.rs`
- Create: `cloud-run-compiler/src/store.rs`
- Create: `cloud-run-compiler/src/config.rs`
- Create: `cloud-run-compiler/tests/auth.rs`

- [ ] **Step 1: Write failing signature and identity tests**

Use deterministic full-length fixture keys through the `nostr` crate. Tests
prove:

```rust
#[test]
fn verifies_list_signature_and_matching_nip98_author() {
    let fixture = signed_compile_fixture();
    let identity = verify_editor_request(
        &fixture.nip98_header,
        "POST",
        "https://compiler.divine.video/api/compile",
        &fixture.body,
        fixture.now,
    ).unwrap();
    assert_eq!(identity.pubkey, fixture.list_event.pubkey);
}

#[test]
fn rejects_browser_supplied_initiator() {
    let body = serde_json::json!({
        "initiated_by": "forged@divine.video",
        "source": signed_source_json()
    });
    assert!(serde_json::from_value::<CompileRequest>(body).is_err());
}
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test auth
```

Expected: verifier symbols do not exist.

- [ ] **Step 3: Implement verification and stores**

Verify kind `27235`, signature, `u`, `method`, payload SHA-256, and a five-minute
freshness window through `nostr::nips::nip98`. Verify the list event signature
separately and require equal pubkeys.

Define:

```rust
#[async_trait::async_trait]
pub trait JobStore: Send + Sync {
    async fn create(&self, job: &Job) -> anyhow::Result<()>;
    async fn get(&self, id: &str) -> anyhow::Result<Option<Job>>;
    async fn save(&self, job: &Job) -> anyhow::Result<()>;
    async fn recent_for_initiator(&self, initiated_by: &str, limit: usize)
        -> anyhow::Result<Vec<Job>>;
    async fn claim_next(&self) -> anyhow::Result<Option<Job>>;
}
```

Provide `MemoryJobStore` for tests and local execution and
`FirestoreJobStore` for production collection `compilation_jobs`. Firestore
claiming uses a transaction that only changes `queued` to `running`.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test auth
cargo test --manifest-path cloud-run-compiler/Cargo.toml store::
```

Expected: auth and memory-store tests pass. Firestore emulator tests skip unless
`FIRESTORE_EMULATOR_HOST` is set.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/src/auth.rs cloud-run-compiler/src/store.rs cloud-run-compiler/src/config.rs cloud-run-compiler/tests/auth.rs cloud-run-compiler/Cargo.lock
git commit -m "feat(compiler): verify editor jobs and persist state"
```

## Task 4: Ordered Source Resolution

**Files:**
- Create: `cloud-run-compiler/src/source.rs`
- Create: `cloud-run-compiler/tests/source.rs`

- [ ] **Step 1: Write failing relay-resolution tests**

Wiremock or a `SourceRepository` fake returns events out of order. The resolver
must return them in signed-list order and keep a drop entry in the original
position for missing or unusable items.

```rust
#[tokio::test]
async fn resolves_addressable_events_in_list_order() {
    let repository = FakeRepository::with_events(vec![video_event('b'), video_event('a')]);
    let result = resolve_sources(
        &repository,
        &[coordinate(34236, 'a'), coordinate(34236, 'b')],
    ).await;
    assert_eq!(result.usable.iter().map(|clip| &clip.coordinate).collect::<Vec<_>>(),
        vec![&coordinate(34236, 'a'), &coordinate(34236, 'b')]);
}
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test source
```

Expected: resolver symbols do not exist.

- [ ] **Step 3: Implement relay repository and metadata parsing**

Use `nostr-sdk` against configured read relays. Query each addressable event by
kind, author, and `#d`; select the newest valid event. Parse raw `imeta` and
`url` tags for the original MP4 URL and SHA-256. Query author kind `0` profiles
and derive display name and NIP-05 credit without truncating identifiers.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test source
```

Expected: order, metadata, profile, missing-event, and restricted-media tests
pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/src/source.rs cloud-run-compiler/tests/source.rs cloud-run-compiler/Cargo.lock
git commit -m "feat(compiler): resolve ordered Nostr video lists"
```

## Task 5: FFmpeg Rendering and Resumable Publishing

**Files:**
- Create: `cloud-run-compiler/src/render.rs`
- Create: `cloud-run-compiler/src/upload.rs`
- Create: `cloud-run-compiler/tests/render.rs`
- Create: `cloud-run-compiler/tests/upload.rs`

- [ ] **Step 1: Write failing filter and upload contract tests**

```rust
#[test]
fn per_clip_fit_overrides_aspect_default() {
    let graph = build_filter_graph(&portrait_job_with_square_override()).unwrap();
    assert!(graph.contains("crop="));
    assert!(graph.contains("boxblur="));
}

#[tokio::test]
async fn upload_streams_chunks_and_disables_derivatives() {
    let server = UploadFixture::start().await;
    let result = server.client.publish(&server.fixture_mp4).await.unwrap();
    assert_eq!(result.sha256, server.expected_sha256);
    assert_eq!(server.init_body()["generateDerivatives"], false);
    assert!(server.received_more_than_one_chunk());
}
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test render --test upload
```

Expected: render and publisher symbols do not exist.

- [ ] **Step 3: Implement renderer and publisher**

The renderer normalizes every input to aspect dimensions, 30 fps, yuv420p, and
48 kHz stereo before concat. It applies credits on final-timeline intervals,
brand watermark assets, single-pass loudnorm, H.264/AAC, and `+faststart`.
NVENC failure retries the affected aspect with `libx264`.

The publisher hashes from disk, signs a kind `24242` upload event, calls
`POST /upload/init` with `generateDerivatives: false`, follows the returned
session URL in server-advertised chunk sizes, resumes from `Upload-Offset`, and
calls `POST /upload/:upload_id/complete`.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test render --test upload
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test render -- --ignored
```

Expected: pure tests pass; the ignored CPU smoke passes when FFmpeg is installed.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/src/render.rs cloud-run-compiler/src/upload.rs cloud-run-compiler/tests/render.rs cloud-run-compiler/tests/upload.rs cloud-run-compiler/Cargo.lock
git commit -m "feat(compiler): render and publish compilation outputs"
```

## Task 6: Compiler HTTP API and Worker

**Files:**
- Create: `cloud-run-compiler/src/http.rs`
- Create: `cloud-run-compiler/src/worker.rs`
- Create: `cloud-run-compiler/src/main.rs`
- Create: `cloud-run-compiler/tests/api.rs`
- Create: `cloud-run-compiler/tests/worker.rs`

- [ ] **Step 1: Write failing API and partial-success tests**

Test `POST /compile`, tenant-scoped `GET /compile/:id`,
initiator-scoped `GET /jobs`, forged initiator rejection, zero usable clips,
and one-success/one-failure terminal behavior.

```rust
#[tokio::test]
async fn aspect_failure_does_not_discard_success() {
    let harness = WorkerHarness::with_aspect_results([
        (Aspect::Portrait, Ok(output(Aspect::Portrait))),
        (Aspect::Square, Err(anyhow::anyhow!("square failed"))),
    ]);
    let job = harness.run().await;
    assert_eq!(job.status, JobStatus::Done);
    assert_eq!(job.result.unwrap().outputs.len(), 1);
    assert_eq!(job.result.unwrap().aspect_failures.len(), 1);
}
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --test api --test worker
```

Expected: router and worker symbols do not exist.

- [ ] **Step 3: Implement routes and orchestration**

The edge supplies the validated Access email in
`X-Compiler-Initiated-By` and NIP-98 in
`X-Compiler-Nostr-Authorization`. The Cloud Run IAM boundary authenticates the
edge before axum. The API derives initiator from the header only, persists the
exact request, applies transactional rate limiting, and wakes a bounded worker.

The worker downloads/probes each clip, tail-drops at 600 seconds, renders
aspects independently, uploads successful outputs, saves progress, and removes
its temp directory.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
cargo test --manifest-path cloud-run-compiler/Cargo.toml --all-targets --locked
```

Expected: all compiler unit and integration tests pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/src/http.rs cloud-run-compiler/src/worker.rs cloud-run-compiler/src/main.rs cloud-run-compiler/tests/api.rs cloud-run-compiler/tests/worker.rs cloud-run-compiler/Cargo.lock
git commit -m "feat(compiler): expose asynchronous compilation jobs"
```

## Task 7: Safe Nostr List Editing

**Files:**
- Create: `compiler-web/package.json`
- Create: `compiler-web/package-lock.json`
- Create: `compiler-web/tsconfig.json`
- Create: `compiler-web/vite.config.ts`
- Create: `compiler-web/vitest.setup.ts`
- Create: `compiler-web/src/types.ts`
- Create: `compiler-web/src/nostr/lists.ts`
- Create: `compiler-web/src/nostr/lists.test.ts`
- Create: `compiler-web/src/nostr/relay.ts`

- [ ] **Step 1: Write failing list replacement tests**

```typescript
it('reorders only video slots and canonicalizes manual play order', () => {
  const result = buildReorderedListEvent(baseEvent, [coordinateB, coordinateA], 200);
  expect(result.content).toBe(baseEvent.content);
  expect(result.tags).toEqual([
    ['d', 'staff-picks'],
    ['unknown', 'preserve', 'all', 'values'],
    ['play-order', 'manual'],
    ['a', coordinateB, 'wss://relay.divine.video'],
    ['title', 'Staff picks'],
    ['a', coordinateA],
  ]);
  expect(result.created_at).toBe(200);
});

it('rejects a stale edit base', () => {
  expect(() => assertCurrentEditBase(baseEvent.id, newerEvent.id))
    .toThrow('This list changed. Reload it before saving.');
});
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
npm --prefix compiler-web test -- --run src/nostr/lists.test.ts
```

Expected: list functions do not exist.

- [ ] **Step 3: Implement list parsing, conflict detection, and relay IO**

Use full kind `30005` events and literal kind `34235`/`34236` `a` tags.
`buildReorderedListEvent` reuses video tag arrays rather than rebuilding relay
hints. `saveReorderedList` queries the newest `(kind,pubkey,d)` event, compares
full event IDs, signs with the hosted Divine signer, publishes to
`wss://relay.divine.video`, and requires an `OK` acknowledgement.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
npm --prefix compiler-web test -- --run src/nostr/lists.test.ts
```

Expected: preservation, duplicate play-order, stale edit, created-at, and publish
acknowledgement tests pass.

- [ ] **Step 5: Commit**

```bash
git add compiler-web/package.json compiler-web/package-lock.json compiler-web/tsconfig.json compiler-web/vite.config.ts compiler-web/vitest.setup.ts compiler-web/src/types.ts compiler-web/src/nostr/lists.ts compiler-web/src/nostr/lists.test.ts compiler-web/src/nostr/relay.ts
git commit -m "feat(compiler-web): edit ordered Nostr lists safely"
```

## Task 8: Editor UI and Hosted Signer

**Files:**
- Create: `compiler-web/index.html`
- Create: `compiler-web/src/main.tsx`
- Create: `compiler-web/src/App.tsx`
- Create: `compiler-web/src/styles.css`
- Create: `compiler-web/src/auth/divineLogin.ts`
- Create: `compiler-web/src/auth/signer.ts`
- Create: `compiler-web/src/compiler/api.ts`
- Create: `compiler-web/src/compiler/api.test.ts`
- Create: `compiler-web/src/components/Header.tsx`
- Create: `compiler-web/src/components/Preview.tsx`
- Create: `compiler-web/src/components/Timeline.tsx`
- Create: `compiler-web/src/components/RenderControls.tsx`
- Create: `compiler-web/src/components/RecentJobs.tsx`

- [ ] **Step 1: Write failing API and editor-state tests**

Tests prove the exact signed event is posted, unsaved reorder disables Render,
fit overrides remain aspect-scoped, and recent completed outputs expose only
Preview, Download, and Copy URL.

```typescript
it('posts the exact saved event snapshot', async () => {
  await createCompilation(signer, savedEvent, renders);
  expect(fetchMock).toHaveBeenCalledWith('/api/compile', expect.objectContaining({
    method: 'POST',
    body: JSON.stringify({ source: { list_event: savedEvent }, renders }),
  }));
});
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
npm --prefix compiler-web test -- --run
```

Expected: API and editor components do not exist.

- [ ] **Step 3: Implement the single-workspace editor**

Use `@divinevideo/login` with client id `compiler-divine-video` and callback
`/auth/callback`. Use its hosted RPC signer; never accept an `nsec`. The screen
contains identity/list header, aspect preview, draggable timeline, global and
clip fit controls, Save list, selected-aspect Render, progress, recent jobs,
output players, Download, and Copy URL.

Use Bricolage Grotesque and Inter, Phosphor icons, current Divine colors, and no
gradients. Do not add search, add-video, cancellation, social publishing, or
Publish to Divine controls.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
npm --prefix compiler-web test -- --run
npm --prefix compiler-web run build
```

Expected: TypeScript, Vitest, and Vite build succeed.

- [ ] **Step 5: Commit**

```bash
git add compiler-web/index.html compiler-web/src
git commit -m "feat(compiler-web): build internal compilation workspace"
```

## Task 9: Cloudflare Access Edge and Cloud Run Deployment

**Files:**
- Create: `compiler-web/worker/googleIdentity.ts`
- Create: `compiler-web/worker/index.ts`
- Create: `compiler-web/worker/index.test.ts`
- Create: `compiler-web/wrangler.jsonc`
- Create: `cloud-run-compiler/Dockerfile`
- Create: `cloud-run-compiler/.dockerignore`
- Create: `cloud-run-compiler/deploy.sh`

- [ ] **Step 1: Write failing edge tests**

Tests cover missing Access identity, static asset passthrough, NIP-98 forwarding,
initiator overwrite, and Cloud Run bearer-token use:

```typescript
it('overwrites browser initiator headers with Access identity', async () => {
  const request = apiRequest({
    'CF-Access-Authenticated-User-Email': 'curator@divine.video',
    'X-Compiler-Initiated-By': 'forged@divine.video',
    Authorization: 'Nostr signed-event',
  });
  await worker.fetch(request, env, context);
  expect(backendRequest.headers.get('X-Compiler-Initiated-By'))
    .toBe('curator@divine.video');
  expect(backendRequest.headers.get('X-Compiler-Nostr-Authorization'))
    .toBe('Nostr signed-event');
  expect(backendRequest.headers.get('Authorization')).toMatch(/^Bearer /);
});
```

- [ ] **Step 2: Run and confirm RED**

Run:

```bash
npm --prefix compiler-web test -- --run worker/index.test.ts
```

Expected: Worker modules do not exist.

- [ ] **Step 3: Implement edge and deployment**

Cloudflare Access protects the custom domain. The Worker additionally rejects
requests lacking the Access email header. For `/api/*`, it signs a service
account JWT with Web Crypto, exchanges it for a Google identity token whose
audience is `COMPILER_SERVICE_URL`, caches it until one minute before expiry,
replaces `Authorization` with the Google bearer token, and forwards browser
NIP-98 separately.

Deploy Cloud Run without `--allow-unauthenticated`, grant only the Worker
service account `roles/run.invoker`, set GPU/NVENC resources, Firestore config,
relay URLs, upload URL, and Secret Manager bindings. The Docker image includes
FFmpeg, NVENC runtime, Noto fonts, and the reviewed Divine watermark asset.

- [ ] **Step 4: Run and confirm GREEN**

Run:

```bash
npm --prefix compiler-web test -- --run worker/index.test.ts
npm --prefix compiler-web run build
cargo test --manifest-path cloud-run-compiler/Cargo.toml --all-targets --locked
docker build -t divine-compiler:test cloud-run-compiler
```

Expected: edge tests, web build, compiler tests, and container build succeed.

- [ ] **Step 5: Commit**

```bash
git add compiler-web/worker compiler-web/wrangler.jsonc cloud-run-compiler/Dockerfile cloud-run-compiler/.dockerignore cloud-run-compiler/deploy.sh
git commit -m "feat(compiler): add protected edge and deployment"
```

## Task 10: Integrated Verification

**Files:**
- Create: `cloud-run-compiler/tests/fixtures/`
- Create: `cloud-run-compiler/scripts/smoke-test.sh`
- Modify: `README.md`

- [ ] **Step 1: Add deterministic local smoke fixtures**

Generate two one-second, six-frame source clips during the test with FFmpeg
lavfi colors and sine audio. The smoke script starts the memory-store compiler,
uses a local source/upload fixture server, submits a signed list, and checks all
three outputs with `ffprobe`.

- [ ] **Step 2: Run all repository-relevant gates**

Run:

```bash
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked
cargo test --manifest-path cloud-run-compiler/Cargo.toml --all-targets --locked
cargo clippy --manifest-path cloud-run-compiler/Cargo.toml --all-targets --all-features --locked -- -D warnings
npm --prefix compiler-web test -- --run
npm --prefix compiler-web run build
cloud-run-compiler/scripts/smoke-test.sh
cargo check --tests --locked
git diff --check
```

Expected: every command exits zero.

- [ ] **Step 3: Update operational documentation**

Document local commands, required non-secret variables, Secret Manager names,
OAuth client registration for `compiler-divine-video`, Cloudflare Access
application setup for `compiler.divine.video`, service-account invoker grant,
and the staging three-aspect GPU smoke command. Do not include secret values.

- [ ] **Step 4: Commit**

```bash
git add README.md cloud-run-compiler/tests/fixtures cloud-run-compiler/scripts/smoke-test.sh
git commit -m "test(compiler): add integrated compilation smoke coverage"
```

- [ ] **Step 5: Final review**

Run `git status --short`, inspect every implementation commit, verify no secret
or shortened Nostr identifier entered tracked files, and use the
verification-before-completion skill before reporting the branch ready.
