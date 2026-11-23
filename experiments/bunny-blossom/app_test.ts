// Comprehensive unit & integration tests for native Bunny Blossom route parity.

import { DatabaseSync } from "node:sqlite";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { SqlCatalog } from "./adapters.ts";
import { createApp, hex } from "./app.ts";
import type { Blobs, CdnPurger } from "./types.ts";

function equal(a: unknown, b: unknown) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`values differ:\n  got:  ${JSON.stringify(a)}\n  want: ${JSON.stringify(b)}`);
  }
}

class FakeBlobs implements Blobs {
  store = new Map<string, { body: Uint8Array; type: string }>();
  deletedPrefixes: string[] = [];

  read(key: string, req: Request): Promise<Response> {
    const entry = this.store.get(key);
    if (!entry) return Promise.resolve(new Response(null, { status: 404 }));
    const range = req.headers.get("range");
    if (range) {
      const m = /^bytes=(\d+)-(\d+)$/.exec(range);
      if (m) {
        const start = Number(m[1]);
        const end = Number(m[2]);
        const slice = entry.body.slice(start, end + 1);
        return Promise.resolve(
          new Response(slice, {
            status: 206,
            headers: {
              "content-type": entry.type,
              "content-length": String(slice.length),
              "content-range": `bytes ${start}-${end}/${entry.body.length}`,
              "accept-ranges": "bytes",
            },
          }),
        );
      }
    }
    return Promise.resolve(
      new Response(entry.body.slice(), {
        status: 200,
        headers: {
          "content-type": entry.type,
          "content-length": String(entry.body.length),
          "accept-ranges": "bytes",
        },
      }),
    );
  }

  write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void> {
    this.store.set(key, { body: body.slice(), type });
    return Promise.resolve();
  }

  deletePrefix(prefix: string): Promise<{ deleted: number; remaining: boolean }> {
    this.deletedPrefixes.push(prefix);
    let deleted = 0;
    for (const k of [...this.store.keys()]) {
      if (k === prefix || k.startsWith(`${prefix}/`) || k.startsWith(`${prefix}.`)) {
        this.store.delete(k);
        deleted++;
      }
    }
    return Promise.resolve({ deleted, remaining: false });
  }
}

class FakePurger implements CdnPurger {
  purged: string[] = [];
  purgeHash(hash: string): Promise<void> {
    this.purged.push(hash);
    return Promise.resolve();
  }
}

function blossomAuth(
  sk: Uint8Array,
  action: string,
  now: number,
  hash?: string,
  omitExpiration = false,
): string {
  const tags: string[][] = [["t", action]];
  if (!omitExpiration) tags.push(["expiration", String(now + 60)]);
  if (hash) tags.push(["x", hash]);
  const ev = finalizeEvent({ kind: 24242, created_at: now, tags, content: action }, sk);
  return `Nostr ${btoa(JSON.stringify(ev))}`;
}

function nip98Auth(sk: Uint8Array, url: string, method: string, now: number): string {
  const ev = finalizeEvent(
    { kind: 27235, created_at: now, tags: [["u", url], ["method", method]], content: "" },
    sk,
  );
  return `Nostr ${btoa(JSON.stringify(ev))}`;
}

async function setup() {
  const db = new DatabaseSync(":memory:");
  db.exec(await Deno.readTextFile("schema.sql"));
  const catalog = new SqlCatalog("https://primary.invalid", "synthetic", {
    execute({ sql, args }) {
      return Promise.resolve({
        rows: db.prepare(sql).all(...args) as Record<string, unknown>[],
      });
    },
  });
  const blobs = new FakeBlobs();
  const purger = new FakePurger();
  const now = 1800000000;
  const origin = "https://media.divine.video";
  const adminToken = "synthetic-admin-token-1234567890";
  const webhookSecret = "synthetic-webhook-secret-1234567890";
  const archiveToken = "synthetic-archive-token-1234567890";
  const drainToken = "synthetic-drain-token-1234567890";

  const app = createApp({
    origin,
    catalog,
    blobs,
    purger,
    secrets: {
      adminToken,
      webhookSecret,
      transcoderWebhookSecret: webhookSecret,
      archiveImportToken: archiveToken,
      purgeDrainToken: drainToken,
    },
    cache: { publicMediaCaching: true, browserMaxAgeSecs: 300, edgeMaxAgeSecs: 86400 },
    writesEnabled: true,
    bunnyDeliveryHost: "media-bunny.divine.video",
    now: () => now,
  });

  return {
    db,
    catalog,
    blobs,
    purger,
    app,
    origin,
    now,
    adminToken,
    webhookSecret,
    archiveToken,
    drainToken,
  };
}

Deno.test("full media lifecycle: upload, transcode webhook, HLS/MP4/VTT/Range caching, age-gate, quarantine, delete & purge drain", async () => {
  const ctx = await setup();
  try {
    const ownerSk = generateSecretKey();
    const ownerPub = getPublicKey(ownerSk);
    const viewerSk = generateSecretKey();
    const payload = new TextEncoder().encode("synthetic-mp4-video-bytes-0123456789");
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", payload)));

    // Landing, version, health, BUD-06 HEAD /upload
    equal((await ctx.app(new Request(`${ctx.origin}/`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/version`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/health`))).status, 200);
    const headUpload = await ctx.app(new Request(`${ctx.origin}/upload`, { method: "HEAD" }));
    equal(headUpload.status, 200);
    equal(headUpload.headers.get("x-divine-upload-extensions"), "resumable-v1");

    // PUT /upload
    const up = await ctx.app(
      new Request(`${ctx.origin}/upload`, {
        method: "PUT",
        body: payload,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(ownerSk, "upload", ctx.now, hash),
        },
      }),
    );
    equal(up.status, 200);
    const desc = await up.json() as { sha256: string; url: string };
    equal(desc.sha256, hash);
    equal(desc.url, `${ctx.origin}/${hash}`);

    // Pending blob serves privately (never publicly cached before approval)
    const pendingGet = await ctx.app(new Request(`${ctx.origin}/${hash}`));
    equal(pendingGet.status, 200);
    equal(pendingGet.headers.get("cache-control"), "private, no-store");

    // Transcode + transcript webhooks (including stale generation rejection)
    const tc1 = await ctx.app(
      new Request(`${ctx.origin}/admin/transcode-status`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.webhookSecret}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, status: "complete", generation: 10, dim: "720x1280" }),
      }),
    );
    equal(tc1.status, 200);

    const tcStale = await ctx.app(
      new Request(`${ctx.origin}/admin/transcode-status`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.webhookSecret}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, status: "failed", generation: 5 }),
      }),
    );
    equal((await tcStale.json() as { ignored: boolean }).ignored, true);

    // Seed derived HLS + 720p + VTT + audio in fake B2
    await ctx.blobs.write(
      `${hash}/hls/master.m3u8`,
      new TextEncoder().encode("#EXTM3U\n"),
      "application/vnd.apple.mpegurl",
    );
    await ctx.blobs.write(`${hash}/hls/stream_720p.mp4`, payload, "video/mp4");
    await ctx.blobs.write(`${hash}.vtt`, new TextEncoder().encode("WEBVTT\n\n"), "text/vtt");
    await ctx.blobs.write(`${hash}.audio.m4a`, new Uint8Array([1, 2, 3]), "audio/mp4");

    // Approve blob -> becomes publicly cacheable at Bunny edge
    const approve = await ctx.app(
      new Request(`${ctx.origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, action: "APPROVE" }),
      }),
    );
    equal(approve.status, 200);

    const activeGet = await ctx.app(new Request(`${ctx.origin}/${hash}.mp4`));
    equal(activeGet.status, 200);
    equal(activeGet.headers.get("cache-control"), "public, max-age=300, s-maxage=86400");

    // Range 206, .hls, /720p, .vtt, .audio.m4a, /provenance, /api/bunny-playback
    const ranged = await ctx.app(
      new Request(`${ctx.origin}/${hash}`, { headers: { range: "bytes=0-3" } }),
    );
    equal(ranged.status, 206);
    equal(await ranged.text(), "synt");
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}.hls`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}/720p`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}.vtt`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}.audio.m4a`))).status, 200);
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}/provenance`))).status, 200);

    const playback = await ctx.app(new Request(`${ctx.origin}/api/bunny-playback/${hash}`));
    equal(playback.status, 200);
    const pbJson = await playback.json() as { host: string; paths: string[] };
    equal(pbJson.host, "media-bunny.divine.video");
    equal(pbJson.paths.includes(`/${hash}/hls/master.m3u8`), true);

    // Subtitle jobs API requires auth (rejects anonymous with 401)
    const subAnon = await ctx.app(
      new Request(`${ctx.origin}/v1/subtitles/jobs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ video_sha256: hash, lang: "en" }),
      }),
    );
    equal(subAnon.status, 401);

    const subCreate = await ctx.app(
      new Request(`${ctx.origin}/v1/subtitles/jobs`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: blossomAuth(ownerSk, "media", ctx.now),
        },
        body: JSON.stringify({ video_sha256: hash, lang: "en" }),
      }),
    );
    equal(subCreate.status, 202);
    const job = await subCreate.json() as { job_id: string };
    equal(
      (await ctx.app(new Request(`${ctx.origin}/v1/subtitles/jobs/${job.job_id}`))).status,
      200,
    );
    equal((await ctx.app(new Request(`${ctx.origin}/v1/subtitles/by-hash/${hash}`))).status, 200);

    // Age restriction -> 401 anonymous, 200 private with NIP-98 or legacy optional-expiry Blossom GET
    await ctx.app(
      new Request(`${ctx.origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, action: "AGE_RESTRICTED" }),
      }),
    );
    equal(ctx.purger.purged.includes(hash), true);
    const anonAge = await ctx.app(new Request(`${ctx.origin}/${hash}`));
    equal(anonAge.status, 401);
    equal((await anonAge.json() as { error: string }).error, "age_restricted");

    const nip98Res = await ctx.app(
      new Request(`${ctx.origin}/${hash}`, {
        headers: { authorization: nip98Auth(viewerSk, `${ctx.origin}/${hash}`, "GET", ctx.now) },
      }),
    );
    equal(nip98Res.status, 200);
    equal(nip98Res.headers.get("cache-control"), "private, no-store");

    const legacyBlossomRes = await ctx.app(
      new Request(`${ctx.origin}/${hash}`, {
        headers: { authorization: blossomAuth(viewerSk, "get", ctx.now, hash, true) },
      }),
    );
    equal(legacyBlossomRes.status, 200);

    // Quarantine hold blocks even authenticated viewers (404), but admin bypass still works
    await ctx.app(
      new Request(`${ctx.origin}/admin/api/quarantine`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, hold_id: "review-1", action: "add" }),
      }),
    );
    equal(
      (await ctx.app(
        new Request(`${ctx.origin}/${hash}`, {
          headers: { authorization: nip98Auth(viewerSk, `${ctx.origin}/${hash}`, "GET", ctx.now) },
        }),
      )).status,
      404,
    );
    equal(
      (await ctx.app(
        new Request(`${ctx.origin}/admin/api/blob/${hash}/content`, {
          headers: { authorization: `Bearer ${ctx.adminToken}` },
        }),
      )).status,
      200,
    );

    // Unauthenticated /list/<pubkey> hides quarantined blobs; authenticated owner still sees them
    const anonListRes = await ctx.app(new Request(`${ctx.origin}/list/${ownerPub}`));
    equal(anonListRes.status, 200);
    equal((await anonListRes.json() as unknown[]).length, 0);

    const listRes = await ctx.app(
      new Request(`${ctx.origin}/list/${ownerPub}`, {
        headers: { authorization: blossomAuth(ownerSk, "list", ctx.now) },
      }),
    );
    equal(listRes.status, 200);
    equal((await listRes.json() as unknown[]).length, 1);

    // Owner DELETE and DELETE /vanish must refuse to delete quarantined blobs
    const delWhileQuarantined = await ctx.app(
      new Request(`${ctx.origin}/${hash}`, {
        method: "DELETE",
        headers: { authorization: blossomAuth(ownerSk, "delete", ctx.now, hash) },
      }),
    );
    equal(delWhileQuarantined.status, 403);

    const vanishWhileQuarantined = await ctx.app(
      new Request(`${ctx.origin}/vanish`, {
        method: "DELETE",
        headers: { authorization: blossomAuth(ownerSk, "vanish", ctx.now) },
      }),
    );
    equal(vanishWhileQuarantined.status, 202);
    const vanishQJson = await vanishWhileQuarantined.json() as {
      erased: number;
      skipped_held: number;
    };
    equal(vanishQJson.erased, 0);
    equal(vanishQJson.skipped_held, 1);

    // Legal hold soft delete blocks re-upload (403)
    await ctx.app(
      new Request(`${ctx.origin}/admin/api/delete`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, reason: "DMCA test", legal_hold: true }),
      }),
    );
    const reup = await ctx.app(
      new Request(`${ctx.origin}/upload`, {
        method: "PUT",
        body: payload,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(ownerSk, "upload", ctx.now, hash),
        },
      }),
    );
    equal(reup.status, 403);

    // Release quarantine hold and restore, then verify GET drain is 405, then DELETE + POST drain erases B2
    await ctx.app(
      new Request(`${ctx.origin}/admin/api/quarantine`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, hold_id: "review-1", action: "remove" }),
      }),
    );
    await ctx.app(
      new Request(`${ctx.origin}/admin/api/restore`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: hash, status: "active" }),
      }),
    );
    equal(
      (await ctx.app(
        new Request(`${ctx.origin}/admin/api/b2-cdn-purge/drain`, {
          method: "GET",
          headers: { authorization: `Bearer ${ctx.drainToken}` },
        }),
      )).status,
      405,
    );
    const delRes = await ctx.app(
      new Request(`${ctx.origin}/${hash}`, {
        method: "DELETE",
        headers: { authorization: blossomAuth(ownerSk, "delete", ctx.now, hash) },
      }),
    );
    equal(delRes.status, 202);
    const drain = await ctx.app(
      new Request(`${ctx.origin}/admin/api/b2-cdn-purge/drain?max=10`, {
        method: "POST",
        headers: { authorization: `Bearer ${ctx.drainToken}` },
      }),
    );
    equal(drain.status, 200);
    const drainJson = await drain.json() as { completed: number };
    equal(drainJson.completed >= 1, true);
    equal(ctx.blobs.deletedPrefixes.includes(hash), true);
    equal(ctx.blobs.store.size, 0);
  } finally {
    ctx.db.close();
  }
});

Deno.test("security hardening: mirror SSRF, report signature, drain hold-guard, and restricted list hiding", async () => {
  const ctx = await setup();
  try {
    const sk = generateSecretKey();
    const pub = getPublicKey(sk);

    // PUT /mirror rejects SSRF / non-public targets
    for (
      const badUrl of [
        "https://127.0.0.1/secret",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/internal",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://[::1]/loopback",
        "https://user:pass@example.com/a.mp4",
        "https://example.com:8443/a.mp4",
      ]
    ) {
      const res = await ctx.app(
        new Request(`${ctx.origin}/mirror`, {
          method: "PUT",
          headers: {
            authorization: blossomAuth(sk, "mirror", ctx.now),
            "content-type": "application/json",
          },
          body: JSON.stringify({ url: badUrl }),
        }),
      );
      equal(res.status, 400);
    }

    // PUT /report rejects unsigned kind 1984 events and accepts properly signed ones
    const unsignedReport = await ctx.app(
      new Request(`${ctx.origin}/report`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind: 1984, id: "fake", tags: [], content: "spam" }),
      }),
    );
    equal(unsignedReport.status, 400);

    const signedEvent = finalizeEvent(
      { kind: 1984, created_at: ctx.now, tags: [["x", "a".repeat(64), "spam"]], content: "spam" },
      sk,
    );
    const signedReport = await ctx.app(
      new Request(`${ctx.origin}/report`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(signedEvent),
      }),
    );
    equal(signedReport.status, 200);

    // Restricted blob is hidden from unauthenticated GET /list/<pubkey>
    const h = "f".repeat(64);
    await ctx.catalog.cas(h, null, {
      revision: 1,
      hash: h,
      size: 128,
      type: "video/mp4",
      uploaded: ctx.now,
      owners: [pub],
      status: "restricted",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    const anonList = await ctx.app(new Request(`${ctx.origin}/list/${pub}`));
    equal(anonList.status, 200);
    equal((await anonList.json() as unknown[]).length, 0);

    // Purge drain skips B2 deletePrefix when blob was restored to active or placed under legal hold
    await ctx.blobs.write(h, new Uint8Array([1, 2, 3]), "video/mp4");
    await ctx.catalog.enqueuePurge(h, "stale_delete", true, ctx.now);
    const drainRes = await ctx.app(
      new Request(`${ctx.origin}/admin/api/b2-cdn-purge/drain`, {
        method: "POST",
        headers: { authorization: `Bearer ${ctx.drainToken}` },
      }),
    );
    equal(drainRes.status, 200);
    const drainBody = await drainRes.json() as { skipped_held: number };
    equal(drainBody.skipped_held, 1);
    equal(ctx.blobs.deletedPrefixes.includes(h), false);
    equal(ctx.blobs.store.has(h), true);
  } finally {
    ctx.db.close();
  }
});

Deno.test("archive import and GDPR vanish work end-to-end", async () => {
  const ctx = await setup();
  try {
    const sk = generateSecretKey();
    const pub = getPublicKey(sk);
    const h = "e".repeat(64);
    const imp = await ctx.app(
      new Request(`${ctx.origin}/internal/archive/v1/register`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.archiveToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sha256: h,
          size: 4096,
          type: "video/mp4",
          owner: pub,
          status: "active",
        }),
      }),
    );
    equal(imp.status, 200);
    const vanish = await ctx.app(
      new Request(`${ctx.origin}/vanish`, {
        method: "DELETE",
        headers: { authorization: blossomAuth(sk, "vanish", ctx.now) },
      }),
    );
    equal(vanish.status, 202);
    equal((await vanish.json() as { erased: number }).erased, 1);
    equal((await ctx.app(new Request(`${ctx.origin}/${h}`))).status, 404);
  } finally {
    ctx.db.close();
  }
});
