// ABOUTME: Verifies non-Active media never reaches the shared edge cache.
// ABOUTME: Creates its own throwaway blobs, exercises the matrix, and deletes them.

/**
 * Gate for the vcl_fetch private/no-store check.
 *
 * The edge shares one cache entry across all callers of a given object. Nothing
 * whose response varies by identity may enter it, and BlobMetadata::access_for
 * varies by identity for two statuses:
 *
 *   Restricted     owner -> 200, any other authenticated caller -> 404
 *   Banned/Deleted admin -> 200, everyone else -> 404
 *
 * main.rs serves anything whose status is not Active as `private, no-store`, and
 * the vcl_fetch snippet refuses to cache responses matching that. Before
 * 2026-08-11 the snippet overwrote Cache-Control unconditionally, so these
 * responses WERE force-cached as public -- this is the regression guard for that.
 *
 * Asserts the dangerous ordering specifically: the privileged caller fetches
 * FIRST, populating whatever the edge is willing to store, and only then do the
 * unprivileged callers ask. If the cache ever serves them the privileged
 * response, that is a disclosure and this script fails.
 *
 * Runs against real infrastructure with real credentials. It never mocks, and it
 * creates its own blobs so it never moderates user content.
 *
 * Usage:
 *   WEBHOOK_SECRET=... node scripts/verify_auth_cache_boundary.mjs
 *   WEBHOOK_SECRET=... SERVER=https://media.divine.video PUBLIC_HASH=<active-hash> node scripts/verify_auth_cache_boundary.mjs
 *
 * WEBHOOK_SECRET must match `webhook_secret` in the blossom_secrets store; it is
 * required to set moderation status and is never read from anywhere but the env.
 *
 * Exit codes: 0 all assertions held, 1 a boundary was violated, 2 setup failed
 * or the boundary cases could not run.
 */


import { generateSecretKey, finalizeEvent } from 'nostr-tools/pure';
import crypto from 'crypto';
import fs from 'fs';

const SERVER = process.env.SERVER || 'https://media.divine.video';
const FILE = process.env.FILE || 'test.mp4';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
// Case 3 needs a blob that is already Active. A freshly uploaded one starts
// Pending, and main.rs serves anything with `status != Active` as
// `private, no-store`, so it can never cache no matter what the VCL does.
// Uploading a fixture for the cache control would test nothing.
const PUBLIC_HASH = process.env.PUBLIC_HASH
  || '832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1';

// Without the secret the identity-varying cases cannot be built at all. Those
// are the security half, so their absence must never look like a pass. The
// public control needs no moderation, so it still runs and still reports —
// but the script exits 2, never 0, so no caller can mistake a partial run for
// a verified boundary.
const CAN_MODERATE = Boolean(WEBHOOK_SECRET);
if (!CAN_MODERATE) {
  console.log('WEBHOOK_SECRET not set — cases 1 and 2 (the auth boundary) CANNOT RUN.');
  console.log('Running case 3 (public cache control) only. This does NOT verify the');
  console.log('auth boundary and will exit non-zero regardless of case 3\'s result.\n');
}

const owner = generateSecretKey();
const stranger = generateSecretKey();

function authFor(sk, verb, extraTags = []) {
  const event = finalizeEvent(
    {
      kind: 24242,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['t', verb],
        ['expiration', String(Math.floor(Date.now() / 1000) + 3600)],
        ...extraTags,
      ],
      content: `auth-boundary ${verb}`,
    },
    sk,
  );
  return 'Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
function assertStatus(label, actual, allowed) {
  const ok = allowed.includes(actual);
  console.log(`  ${ok ? 'PASS' : 'FAIL'}: ${label} (got ${actual}, allowed ${allowed.join('/')})`);
  if (!ok) failures++;
  return ok;
}

async function fetchStatus(url, authHeader) {
  const headers = authHeader ? { Authorization: authHeader } : {};
  // No `cache: 'no-store'` — undici turns it into a request Cache-Control
  // header, which changes what the edge does and contaminates the measurement.
  const r = await fetch(url, { headers });
  await r.arrayBuffer();
  return {
    status: r.status,
    // Age is the reliable signal that a response came from cache. X-Cache is
    // not: deliver.vcl runs on every node in the chain and the client sees the
    // outermost one, which routinely reports MISS while an inner node holds the
    // object and serves it (observed: age=830 alongside X-Cache: MISS).
    age: Number(r.headers.get('age') ?? -1),
    cache: r.headers.get('x-cache'),
    cc: r.headers.get('cache-control'),
  };
}

async function upload(bytes, hash) {
  return fetch(`${SERVER}/upload`, {
    method: 'PUT',
    headers: {
      Authorization: authFor(owner, 'upload', [['x', hash], ['size', String(bytes.length)]]),
      'Content-Type': 'video/mp4',
      'Content-Length': String(bytes.length),
    },
    body: bytes,
  });
}

async function moderate(hash, action) {
  const r = await fetch(`${SERVER}/admin/moderate`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${WEBHOOK_SECRET}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ sha256: hash, action }),
  });
  if (!r.ok) {
    console.error(`  setup failed: moderate ${action} returned ${r.status} — ${(await r.text()).slice(0, 200)}`);
    return false;
  }
  return true;
}

async function cleanup(hash) {
  await fetch(`${SERVER}/${hash}`, {
    method: 'DELETE',
    headers: { Authorization: authFor(owner, 'delete', [['x', hash]]) },
  }).catch(() => {});
}

// A distinct body per run, so every fixture is a genuinely cold object and no
// previous run's cache state can mask a failure.
function freshBlob(tag) {
  const base = fs.readFileSync(FILE);
  const salt = Buffer.from(`\n<!-- auth-boundary ${tag} ${crypto.randomUUID()} -->`);
  const bytes = Buffer.concat([base, salt]);
  return { bytes, hash: crypto.createHash('sha256').update(bytes).digest('hex') };
}

const created = [];

try {
  console.log(`server ${SERVER}\n`);

  // ---- Case 1: Restricted is owner-only, and must not leak via the shared key.
  if (CAN_MODERATE) {
  console.log('[1] Restricted: owner-only, must not reach the shared cache');
  const r1 = freshBlob('restricted');
  const up1 = await upload(r1.bytes, r1.hash);
  if (up1.status !== 200) {
    console.error(`  setup failed: upload returned ${up1.status}`);
    process.exit(2);
  }
  created.push(r1.hash);
  if (!(await moderate(r1.hash, 'RESTRICT'))) process.exit(2);
  await sleep(2000);

  const url1 = `${SERVER}/${r1.hash}`;
  // Privileged caller goes FIRST, so anything cacheable is now cached.
  const ownerRes = await fetchStatus(url1, authFor(owner, 'get', [['x', r1.hash]]));
  assertStatus('owner can read own restricted blob', ownerRes.status, [200]);
  if (ownerRes.cc && /public/i.test(ownerRes.cc) && !/private|no-store/i.test(ownerRes.cc)) {
    console.log(`  FAIL: restricted response advertised a public cache policy (${ownerRes.cc})`);
    failures++;
  } else {
    console.log(`  PASS: restricted response is not publicly cacheable (${ownerRes.cc})`);
  }
  await sleep(1000);
  // Same auth=1 cache key as the owner. This is the dangerous one.
  const strangerRes = await fetchStatus(url1, authFor(stranger, 'get', [['x', r1.hash]]));
  assertStatus('another authenticated caller is refused', strangerRes.status, [404]);
  const anonRes = await fetchStatus(url1, null);
  assertStatus('anonymous caller is refused', anonRes.status, [404]);

  } // end case 1

  // ---- Case 2: AgeRestricted varies by auth presence only.
  if (CAN_MODERATE) {
  console.log('\n[2] AgeRestricted: authenticated allowed, anonymous age-gated');
  const r2 = freshBlob('age');
  const up2 = await upload(r2.bytes, r2.hash);
  if (up2.status !== 200) {
    console.error(`  setup failed: upload returned ${up2.status}`);
    process.exit(2);
  }
  created.push(r2.hash);
  if (!(await moderate(r2.hash, 'AGE_RESTRICT'))) process.exit(2);
  await sleep(2000);

  const url2 = `${SERVER}/${r2.hash}`;
  const ageAuthed = await fetchStatus(url2, authFor(stranger, 'get', [['x', r2.hash]]));
  assertStatus('authenticated caller passes the age gate', ageAuthed.status, [200]);
  await sleep(1000);
  const ageAnon = await fetchStatus(url2, null);
  assertStatus('anonymous caller is age-gated, not served', ageAnon.status, [401]);

  } // end case 2

  // ---- Case 3: public control. Both variants must actually cache, or the
  // whole change is pointless. Warm each key, then require a HIT.
  console.log(`\n[3] Public control on an Active blob: both cache-key variants go hot`);
  const url3 = `${SERVER}/${PUBLIC_HASH}`;
  const control = await fetchStatus(url3, null);
  if (control.status !== 200 || !/public/i.test(control.cc || '')) {
    console.error(`  setup failed: PUBLIC_HASH is not an Active public blob `
      + `(status ${control.status}, cache-control ${control.cc}). `
      + `Set PUBLIC_HASH to a blob whose status is Active.`);
    process.exit(2);
  }

  const cached = (r) => r.age > 0;

  const authHdr = authFor(stranger, 'get', [['x', PUBLIC_HASH]]);
  await fetchStatus(url3, authHdr);
  await sleep(1500);
  const authWarm = await fetchStatus(url3, authHdr);
  assertStatus('credentialed public read succeeds', authWarm.status, [200]);
  if (cached(authWarm)) {
    console.log(`  PASS: credentialed public read came from cache (age=${authWarm.age})`);
  } else {
    console.log(`  FAIL: credentialed public read did not come from cache (age=${authWarm.age}) — auth traffic is still uncached`);
    failures++;
  }

  await fetchStatus(url3, null);
  await sleep(1500);
  const anonWarm = await fetchStatus(url3, null);
  assertStatus('anonymous public read succeeds', anonWarm.status, [200]);
  if (cached(anonWarm)) {
    console.log(`  PASS: anonymous public read came from cache (age=${anonWarm.age})`);
  } else {
    console.log(`  FAIL: anonymous public read did not come from cache (age=${anonWarm.age})`);
    failures++;
  }
} finally {
  console.log('\ncleanup');
  for (const h of created) await cleanup(h);
  console.log(`  removed ${created.length} fixture blob(s)`);
}

if (!CAN_MODERATE) {
  console.log(`\n=== AUTH BOUNDARY NOT VERIFIED (cases 1-2 skipped; case 3 had ${failures} failure(s)) ===`);
  process.exit(2);
}
console.log(`\n=== ${failures === 0 ? 'ALL BOUNDARIES HELD' : `${failures} BOUNDARY FAILURE(S)`} ===`);
process.exit(failures === 0 ? 0 : 1);
