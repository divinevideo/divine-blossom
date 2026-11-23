import { DatabaseSync } from "node:sqlite";
import { B2Blobs, SqlCatalog } from "./adapters.ts";
import type { RecordState } from "./app.ts";

function equal(a: unknown, b: unknown) {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error("values differ");
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
const OWNER = "b".repeat(64);
const ROW: RecordState = {
  hash: HASH,
  revision: 1,
  size: 3,
  type: "video/mp4",
  uploaded: 1800000000,
  owners: [OWNER],
  status: "Pending",
  ageRestricted: false,
  held: false,
  gate: null,
  cleanupPending: false,
};

Deno.test("SQL adapter executes atomic insert/update CAS and owner query against real SQLite", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec(await Deno.readTextFile("schema.sql"));
  const catalog = new SqlCatalog("https://primary.invalid", "synthetic", {
    execute({ sql, args }) {
      return Promise.resolve({ rows: db.prepare(sql).all(...args) });
    },
  });
  try {
    equal(await catalog.get(HASH), null);
    equal(await catalog.cas(HASH, null, ROW), true);
    equal(await catalog.cas(HASH, null, ROW), false);
    equal(await catalog.get(HASH), ROW);
    const concurrent = await Promise.all(
      Array.from(
        { length: 10 },
        () => catalog.cas(HASH, 1, { ...ROW, revision: 2, ageRestricted: true }),
      ),
    );
    equal(concurrent.filter(Boolean).length, 1);
    equal((await catalog.list(OWNER, 100)).length, 1);
    equal((await catalog.list("c".repeat(64), 100)).length, 0);
    equal(
      await catalog.cas(HASH, 2, { ...ROW, revision: 3, status: "Deleted", cleanupPending: true }),
      true,
    );
    equal((await catalog.list(OWNER, 100)).length, 0);
    await rejects(() => catalog.cas(HASH, 3, { ...ROW, revision: 9 }));
    db.prepare("UPDATE spike_blobs SET body = ? WHERE hash = ?").run('{"status":"Active"}', HASH);
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

Deno.test("missing/range errors do not expose provider diagnostic payloads", async () => {
  for (const status of [404, 416]) {
    const blobs = new B2Blobs(
      B2_CONFIG,
      () =>
        Promise.resolve(
          new Response("provider diagnostics", {
            status,
            headers: {
              "content-length": "20",
              "content-type": "application/xml",
              "content-range": "bytes */3",
            },
          }),
        ),
    );
    const result = await blobs.read(HASH, new Request("https://spike.invalid"));
    equal(result.status, status);
    equal(await result.text(), "");
    equal(result.headers.get("content-length"), null);
  }
});

Deno.test("S3 read signs fixed fixture key and range, strips viewer credentials and provider headers", async () => {
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
    equal(req.headers.get("x-viewer"), null);
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
        "x-viewer": "private",
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

Deno.test("S3 writer uses isolated scope, never retries an uncertain mutation or accepts a redirect", async () => {
  let calls = 0;
  const blobs = new B2Blobs(B2_CONFIG, (_input, init) => {
    calls++;
    equal(init?.redirect, "error");
    return Promise.resolve(
      new Response(null, { status: 302, headers: { location: "https://wrong.invalid" } }),
    );
  });
  await rejects(() => blobs.write(HASH, new Uint8Array([1, 2, 3]), "video/mp4"));
  equal(calls, 1);
  await rejects(() => Promise.resolve(new B2Blobs({ ...B2_CONFIG, prefix: "bunny-delivery/" })));
  await rejects(() => Promise.resolve(new SqlCatalog("http://insecure.invalid", "synthetic")));
});
