// ABOUTME: End-to-end smoke test that a real video uploads and gains a playable 720p derivative.
// ABOUTME: Requires HTTP 200 specifically — 202 means "still transcoding" and is not success.

/**
 * Post-deploy smoke test for the transcode path.
 *
 * Written after a deploy pointed the production transcoder at the staging
 * bucket and broke transcoding for four and a half hours without anyone
 * noticing. Two rules come from that incident:
 *
 *   1. Only HTTP 200 counts. The rendition endpoint returns 202 while
 *      transcoding is in progress and 422 when it has failed, and both are
 *      easy to mistake for success — an earlier version of this test used
 *      `response.ok`, which is true for 202, and reported a confident PASS
 *      against a video that never transcoded.
 *
 *   2. Do not clean up until the verdict is known. Deleting the source blob
 *      while a transcode is still running destroys the thing under test.
 *
 * Usage:
 *   node scripts/smoke_transcode.mjs
 *   SERVER=https://media.divine.video FILE=test.mp4 node scripts/smoke_transcode.mjs
 *
 * Exit codes: 0 pass, 1 no derivative, 2 upload rejected, 3 transcode failed.
 */

import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import crypto from 'crypto';
import fs from 'fs';

const SERVER = process.env.SERVER || 'https://media.divine.video';
const FILE = process.env.FILE || 'test.mp4';
const TIMEOUT_MS = Number(process.env.TIMEOUT_MS || 600000);
const KEEP = process.env.KEEP === '1';

const sk = generateSecretKey();
const bytes = fs.readFileSync(FILE);
const hash = crypto.createHash('sha256').update(bytes).digest('hex');

function authHeader(verb, extraTags = []) {
  const event = finalizeEvent(
    {
      kind: 24242,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['t', verb],
        ['expiration', String(Math.floor(Date.now() / 1000) + 3600)],
        ...extraTags,
      ],
      content: `smoke ${verb}`,
    },
    sk,
  );
  return 'Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log(`server ${SERVER}`);
console.log(`file   ${FILE} (${bytes.length} bytes)`);
console.log(`sha256 ${hash}`);

console.log('\n1. upload');
const up = await fetch(`${SERVER}/upload`, {
  method: 'PUT',
  headers: {
    Authorization: authHeader('upload', [['x', hash], ['size', String(bytes.length)]]),
    'Content-Type': 'video/mp4',
    'Content-Length': String(bytes.length),
  },
  body: bytes,
});
if (up.status !== 200) {
  console.log(`   HTTP ${up.status} — ${(await up.text()).slice(0, 300)}`);
  console.log('\nFAIL: upload rejected');
  process.exit(2);
}
console.log(`   HTTP 200`);

console.log('\n2. waiting for the 720p derivative (200 = ready, 202 = transcoding, 422 = failed)');
const deadline = Date.now() + TIMEOUT_MS;
let verdict = null;
let last = null;

while (Date.now() < deadline) {
  await sleep(10000);
  const r = await fetch(`${SERVER}/${hash}/720p.mp4`, { method: 'HEAD' });
  if (r.status !== last) {
    console.log(`   ${new Date().toISOString().slice(11, 19)}  HTTP ${r.status}`);
    last = r.status;
  }
  if (r.status === 200) {
    verdict = 'pass';
    break;
  }
  if (r.status === 422) {
    verdict = 'failed';
    break;
  }
}

if (verdict === 'pass') {
  console.log('\nPASS: derivative is served with HTTP 200');
} else if (verdict === 'failed') {
  const body = await (await fetch(`${SERVER}/${hash}/720p.mp4`)).text();
  console.log(`\nFAIL: transcode reported failure — ${body.slice(0, 300)}`);
} else {
  console.log('\nFAIL: no derivative within the timeout (still 202)');
}

if (!KEEP) {
  console.log('\n3. cleanup');
  const del = await fetch(`${SERVER}/${hash}`, {
    method: 'DELETE',
    headers: { Authorization: authHeader('delete', [['x', hash]]) },
  });
  console.log(`   DELETE HTTP ${del.status}`);
}

process.exit(verdict === 'pass' ? 0 : verdict === 'failed' ? 3 : 1);
