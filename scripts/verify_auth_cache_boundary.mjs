// ABOUTME: Verifies restricted media never crosses the auth boundary via the edge cache.
// ABOUTME: Creates its own throwaway blobs, exercises the matrix, and deletes them.

/**
 * Gate for the auth-presence cache key (vcl/hash.vcl, vcl/recv.vcl, vcl/fetch.vcl).
 *
 * The edge caches credentialed media under a single shared "auth present" key.
 * That is safe only while responses which vary by *identity* never enter that
 * entry. BlobMetadata::access_for varies by identity for two statuses:
 *
 *   Restricted     owner -> 200, any other authenticated caller -> 404
 *   Banned/Deleted admin -> 200, everyone else -> 404
 *
 * So this asserts the dangerous orderings specifically: the privileged caller
 * fetches FIRST, populating whatever the edge is willing to store, and only then
 * do the unprivileged callers ask. If the cache ever serves them the privileged
 * response, that is a disclosure and this script fails.
 *
 * Runs against real infrastructure with real credentials. It never mocks, and it
 * creates its own blobs so it never moderates user content.
 *
 * Usage:
 *   WEBHOOK_SECRET=... node scripts/verify_auth_cache_boundary.mjs
 *   WEBHOOK_SECRET=... SERVER=https://media.divine.video FILE=test.mp4 node scripts/verify_auth_cache_boundary.mjs
 *
 * WEBHOOK_SECRET must match `webhook_secret` in the blossom_secrets store; it is
 * required to set moderation status and is never read from anywhere but the env.
 *
 * Exit codes: 0 all assertions held, 1 a boundary was violated, 2 setup failed.
 */

import { generateSecretKey, finalizeEvent } from 'nostr-tools/pure';
import crypto from 'crypto';
import fs from 'fs';

const SERVER = process.env.SERVER || 'https://media.divine.video';
const FILE = process.env.FILE || 'test.mp4';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  console.error('WEBHOOK_SECRET is required — it is needed to set moderation status.');
  console.error('Without it this script cannot create restricted fixtures and must not');
  console.error('report success. Refusing to run.');
  process.exit(2);
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
  const r = await fetch(url, { headers, cache: 'no-store' });
  await r.arrayBuffer();
  return { status: r.status, cache: r.headers.get('x-cache'), cc: r.headers.get('cache-control') };
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
  console.log('[1] Restricted: owner-only, shared auth=1 cache key');
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

  // ---- Case 2: AgeRestricted varies by auth presence only.
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

  // ---- Case 3: public control. Both variants must actually cache, or the
  // whole change is pointless. Warm each key, then require a HIT.
  console.log('\n[3] Public control: both cache-key variants go hot');
  const r3 = freshBlob('public');
  const up3 = await upload(r3.bytes, r3.hash);
  if (up3.status !== 200) {
    console.error(`  setup failed: upload returned ${up3.status}`);
    process.exit(2);
  }
  created.push(r3.hash);
  await sleep(2000);

  const url3 = `${SERVER}/${r3.hash}`;
  const authHdr = authFor(stranger, 'get', [['x', r3.hash]]);
  await fetchStatus(url3, authHdr);
  await sleep(1500);
  const authWarm = await fetchStatus(url3, authHdr);
  assertStatus('credentialed public read succeeds', authWarm.status, [200]);
  if (authWarm.cache && /HIT/i.test(authWarm.cache)) {
    console.log(`  PASS: credentialed public read is served from cache (${authWarm.cache})`);
  } else {
    console.log(`  FAIL: credentialed public read did not HIT (${authWarm.cache}) — auth traffic is still uncached`);
    failures++;
  }

  await fetchStatus(url3, null);
  await sleep(1500);
  const anonWarm = await fetchStatus(url3, null);
  assertStatus('anonymous public read succeeds', anonWarm.status, [200]);
  if (anonWarm.cache && /HIT/i.test(anonWarm.cache)) {
    console.log(`  PASS: anonymous public read is served from cache (${anonWarm.cache})`);
  } else {
    console.log(`  FAIL: anonymous public read did not HIT (${anonWarm.cache})`);
    failures++;
  }
} finally {
  console.log('\ncleanup');
  for (const h of created) await cleanup(h);
  console.log(`  removed ${created.length} fixture blob(s)`);
}

console.log(`\n=== ${failures === 0 ? 'ALL BOUNDARIES HELD' : `${failures} BOUNDARY FAILURE(S)`} ===`);
process.exit(failures === 0 ? 0 : 1);
