// Real SQLite + SigV4 + B2 erasure + Bunny purge adapter tests.

import { DatabaseSync } from "node:sqlite";
import { B2Blobs, BunnyPurger, SqlCatalog } from "./adapters.ts";
import type { BlobRecord } from "./types.ts";

function equal(a: unknown, b: unknown) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`values differ:\n  got:  ${JSON.stringify(a)}\n  want: ${JSON.stringify(b)}`);
  }
}

async function rejects(fn: () => unknown) {
  let rejected = false;
  try {
    await fn();
  } catch {
    rejected = true;
  }
  equal(rejected, true);
}

const HASH = "a".repeat(64);
const HASH2 = "d".repeat(64);
const OWNER = "b".repeat(64);
const ROW: BlobRecord = {
  hash: HASH,
  revision: 1,
  size: 3,
  type: "video/mp4",
  uploaded: 1800000000,
  owners: [OWNER],
  status: "pending",
  ageRestricted: false,
  held: false,
  gate: null,
  cleanupPending: false,
};

Deno.test("SQL adapter executes atomic CAS, indexed owner pagination, quarantine, subtitles, and purge outbox", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec(await Deno.readTextFile("schema.sql"));
  const catalog = new SqlCatalog("https://primary.invalid", "synthetic", {
    execute({ sql, args }) {
      return Promise.resolve({
        rows: db.prepare(sql).all(...args) as Record<string, unknown>[],
      });
    },
  });
  try {
    equal(await catalog.get(HASH), null);
    equal(await catalog.cas(HASH, null, ROW), true);
    equal(await catalog.cas(HASH, null, ROW), false);
    equal((await catalog.get(HASH))?.hash, HASH);

    const concurrent = await Promise.all(
      Array.from(
        { length: 10 },
        () => catalog.cas(HASH, 1, { ...ROW, revision: 2, status: "active" }),
      ),
    );
    equal(concurrent.filter(Boolean).length, 1);

    // Insert second blob and verify cursor pagination via blob_owners index
    equal(
      await catalog.cas(HASH2, null, {
        ...ROW,
        hash: HASH2,
        uploaded: 1800000005,
        status: "active",
      }),
      true,
    );
    const page1 = await catalog.list(OWNER, 1);
    equal(page1.items.length, 1);
    equal(page1.items[0].hash, HASH2);
    equal(page1.nextCursor !== null, true);

    const page2 = await catalog.list(OWNER, 1, page1.nextCursor);
    equal(page2.items.length, 1);
    equal(page2.items[0].hash, HASH);
    equal(page2.nextCursor, null);

    // Stats & users
    const stats = await catalog.stats();
    equal(stats.total_blobs, 2);
    equal(stats.total_bytes, 6);
    const users = await catalog.users(10);
    equal(users.length, 1);
    equal(users[0].blob_count, 2);

    // Quarantine holds
    await catalog.addQuarantineHold(HASH, "hold-1", 1800000100);
    equal(await catalog.getQuarantineHolds(HASH), ["hold-1"]);
    // Uploads must not publish if a hold arrived after the admission read.
    equal(
      await catalog.cas(HASH, 2, { ...ROW, revision: 3 }, { requireUnquarantined: true }),
      false,
    );
    const heldNewHash = "e".repeat(64);
    await catalog.addQuarantineHold(heldNewHash, "hold-2", 1800000100);
    equal(
      await catalog.cas(heldNewHash, null, { ...ROW, hash: heldNewHash }, {
        requireUnquarantined: true,
      }),
      false,
    );
    equal(await catalog.get(heldNewHash), null);
    await catalog.removeQuarantineHold(HASH, "hold-1");
    equal(await catalog.getQuarantineHolds(HASH), []);

    // Subtitles
    await catalog.upsertSubtitleJob({
      job_id: "job-1",
      video_sha256: HASH,
      lang: "en",
      status: "queued",
      vtt_key: `${HASH}.vtt`,
      error: null,
      created_at: 1800000100,
      updated_at: 1800000100,
    });
    equal((await catalog.getSubtitleJob("job-1"))?.status, "queued");
    equal((await catalog.getSubtitleByHash(HASH, "en"))?.job_id, "job-1");

    // Purge outbox
    await catalog.enqueuePurge(HASH, "owner_delete", true, 1800000100);
    const due = await catalog.listDuePurges(1800000100, 10);
    equal(due.length, 1);
    await catalog.deferPurge(due[0].id, 1, 1800000200);
    equal((await catalog.listDuePurges(1800000150, 10)).length, 0);
    equal((await catalog.listDuePurges(1800000200, 10)).length, 1);
    await catalog.completePurge(due[0].id);
    equal((await catalog.listDuePurges(1800000300, 10)).length, 0);

    // Deleting removes from blob_owners index
    equal(
      await catalog.cas(HASH, 2, { ...ROW, revision: 3, status: "deleted", cleanupPending: true }),
      true,
    );
    equal((await catalog.list(OWNER, 100)).items.length, 1);
    await rejects(() => catalog.cas(HASH, 3, { ...ROW, revision: 9 }));
    db.prepare("UPDATE blobs SET body = ? WHERE hash = ?").run('{"status":"active"}', HASH);
    await rejects(() => catalog.get(HASH));
  } finally {
    db.close();
  }
});

const B2_CONFIG = {
  region: "us-east-005",
  bucket: "synthetic-spike-bucket",
  prefix: "blossom-runtime-spike/00000000-0000-4000-8000-000000000001/",
  id: "synthetic-id",
  key: "synthetic-secret",
};

Deno.test("missing/range errors normalize 403/404 and never expose provider diagnostics", async () => {
  for (const [providerStatus, expectedStatus] of [[403, 404], [404, 404], [416, 416]]) {
    const blobs = new B2Blobs(
      B2_CONFIG,
      () =>
        Promise.resolve(
          new Response("provider diagnostics", {
            status: providerStatus,
            headers: {
              "content-length": "20",
              "content-type": "application/xml",
              "content-range": "bytes */3",
            },
          }),
        ),
    );
    const result = await blobs.read(HASH, new Request("https://spike.invalid"));
    equal(result.status, expectedStatus);
    equal(await result.text(), "");
    equal(result.headers.get("content-length"), null);
  }
});

Deno.test("S3 read signs fixed key and range, strips viewer credentials and provider headers", async () => {
  let calls = 0;
  const blobs = new B2Blobs(B2_CONFIG, (input, init) => {
    calls++;
    const req = input as Request;
    equal(
      req.url,
      `https://s3.us-east-005.backblazeb2.com/${B2_CONFIG.bucket}/${B2_CONFIG.prefix}${HASH}/hls/master.m3u8`,
    );
    equal(req.headers.get("range"), "bytes=0-2");
    equal(req.headers.get("cookie"), null);
    equal(req.headers.get("authorization")?.startsWith("AWS4-HMAC-SHA256 "), true);
    equal(init?.redirect, "error");
    return Promise.resolve(
      new Response("abc", {
        status: 206,
        headers: {
          "content-type": "application/vnd.apple.mpegurl",
          "content-range": "bytes 0-2/10",
          "content-length": "3",
          "x-bz-file-id": "must-not-reach-viewer",
          "set-cookie": "unsafe=1",
        },
      }),
    );
  });
  const result = await blobs.read(
    `${HASH}/hls/master.m3u8`,
    new Request(`https://spike.invalid/${HASH}`, {
      headers: {
        range: "bytes=0-2",
        authorization: "Nostr synthetic",
        cookie: "viewer=private",
      },
    }),
  );
  equal(result.status, 206);
  equal(result.headers.get("content-range"), "bytes 0-2/10");
  equal(result.headers.get("x-bz-file-id"), null);
  equal(result.headers.get("set-cookie"), null);
  await result.body?.cancel();
  await rejects(() => blobs.read(`../${HASH}`, new Request("https://spike.invalid")));
  equal(calls, 1);
});

Deno.test("B2 Native deletePrefix erases all versions and BunnyPurger purges exact + wildcard URLs", async () => {
  const deletedIds: string[] = [];
  const blobs = new B2Blobs(
    {
      ...B2_CONFIG,
      prefix: "",
      allowCanonicalRoot: true,
      eraser: { id: "eraser-id", key: "eraser-key", bucketId: "bucket-1" },
    },
    (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url.endsWith("/b2_authorize_account")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              authorizationToken: "tok",
              apiInfo: { storageApi: { apiUrl: "https://api005.backblazeb2.com" } },
            }),
          ),
        );
      }
      if (url.endsWith("/b2_list_file_versions")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              files: [
                { fileName: HASH, fileId: "f1" },
                { fileName: `${HASH}/hls/master.m3u8`, fileId: "f2" },
              ],
              nextFileName: null,
            }),
          ),
        );
      }
      if (url.endsWith("/b2_delete_file_version")) {
        const body = JSON.parse(String(init?.body)) as { fileId: string };
        deletedIds.push(body.fileId);
        return Promise.resolve(new Response(JSON.stringify({ fileId: body.fileId })));
      }
      throw new Error(`unexpected fetch ${url}`);
    },
  );
  const withdrawn = await blobs.deletePrefix(HASH, () => Promise.resolve(false));
  equal(withdrawn, { deleted: 0, remaining: true });
  equal(deletedIds, []);

  const erased = await blobs.deletePrefix(HASH);
  equal(erased, { deleted: 2, remaining: false });
  equal(deletedIds, ["f1", "f2"]);

  const purgedUrls: string[] = [];
  const purger = new BunnyPurger("synthetic-bunny-key", ["media.divine.video"], (input) => {
    purgedUrls.push(String(input));
    return Promise.resolve(new Response(null, { status: 200 }));
  });
  await purger.purgeHash(HASH);
  equal(purgedUrls.length, 2);
  equal(purgedUrls[0].includes(encodeURIComponent(`https://media.divine.video/${HASH}`)), true);
  equal(purgedUrls[1].includes(encodeURIComponent(`https://media.divine.video/${HASH}*`)), true);
});
