// Comprehensive unit & integration tests for native Bunny Blossom route parity.

import { Buffer } from "node:buffer";
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
    // Without uploadServiceUrl configured, resumable-sessions is not advertised.
    equal(headUpload.headers.get("x-divine-upload-extensions"), null);

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
    equal(up.status, 201);
    const desc = await up.json() as { sha256: string; url: string; uploaded: number };
    equal(desc.sha256, hash);
    equal(desc.url, `${ctx.origin}/${hash}.mp4`);
    equal(desc.uploaded, ctx.now);

    // Pending blob serves privately (never publicly cached before approval),
    // and missing video poster /{hash}.jpg returns 404 (never raw MP4 bytes).
    const pendingGet = await ctx.app(new Request(`${ctx.origin}/${hash}`));
    equal(pendingGet.status, 200);
    equal(pendingGet.headers.get("cache-control"), "private, no-store");
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}.jpg`))).status, 404);

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
    const repost = await ctx.app(
      new Request(`${ctx.origin}/upload`, {
        method: "PUT",
        body: payload,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(ownerSk, "upload", ctx.now, hash),
        },
      }),
    );
    equal(repost.status, 201);
    equal((await ctx.app(new Request(`${ctx.origin}/${hash}.mp4`))).status, 200);
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

Deno.test("delegated PUT /upload publishes to SQL catalog, supports chunked bodies, dedupe, ProofMode forwarding, and hold enforcement", async () => {
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
  const now = 1800000100;
  let clock = now;
  const origin = "https://media-bunny.divine.video";
  const adminToken = "synthetic-admin-token-1234567890";

  const seenRequests: { url: string; method: string; headers: Headers; bodyLen: number }[] = [];
  const modScans: { sha256: string; pubkey: string }[] = [];
  let nextUpstreamResponse: (() => Response) | null = null;

  const fakeFetcher: typeof fetch = async (input, init) => {
    const reqUrl = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : {}));
    const bodyBytes = init?.body
      ? new Uint8Array(
        await new Response(init.body as BodyInit).arrayBuffer(),
      )
      : new Uint8Array();
    seenRequests.push({ url: reqUrl, method, headers, bodyLen: bodyBytes.length });

    if (reqUrl === "https://moderation-api.divine.video/api/v1/scan") {
      const parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as {
        sha256: string;
        pubkey: string;
      };
      modScans.push(parsed);
      return new Response(JSON.stringify({ queued: true }), { status: 202 });
    }

    if (nextUpstreamResponse) {
      const fn = nextUpstreamResponse;
      nextUpstreamResponse = null;
      return fn();
    }

    if (reqUrl.startsWith("https://upload.divine.video/thumbnail/") && method === "GET") {
      return new Response(new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), {
        status: 200,
        headers: { "content-type": "image/jpeg", "content-length": "4" },
      });
    }

    if (reqUrl === "https://upload.divine.video/upload" && method === "PUT") {
      // Enforce real Cloud Run header invariants: exact "Nostr " prefix and strict "copy-only" value.
      const authHeader = headers.get("authorization") ?? "";
      if (!authHeader.startsWith("Nostr ")) {
        return new Response(JSON.stringify({ error: "Invalid Authorization prefix" }), {
          status: 401,
        });
      }
      const procHeader = headers.get("x-divine-video-processing");
      if (procHeader !== null && procHeader !== "copy-only") {
        return new Response(
          JSON.stringify({
            error: "X-Divine-Video-Processing must contain exactly one copy-only value",
          }),
          { status: 400 },
        );
      }
      const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bodyBytes)));
      const contentType = headers.get("content-type") ?? "application/octet-stream";
      const signed = headers.get("authorization")?.slice("Nostr ".length) ?? "";
      // The current Cloud Run upload service accepts padded standard base64.
      if (btoa(atob(signed)) !== signed) return new Response(null, { status: 401 });
      await blobs.write(hash, bodyBytes, contentType);
      return new Response(
        JSON.stringify({
          sha256: hash,
          size: bodyBytes.length,
          type: contentType,
          uploaded: now,
          // Cloud Run returns its canonical CDN_BASE_URL; Bunny Blossom must still return its own origin in descriptor.url.
          url: `https://media.divine.video/${hash}`,
          thumbnail_url: contentType.startsWith("video/")
            ? `https://media.divine.video/${hash}.jpg`
            : undefined,
          dim: contentType.startsWith("video/") ? "720x1280" : undefined,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    return new Response(JSON.stringify({ error: "unexpected upstream route" }), { status: 500 });
  };

  const app = createApp({
    origin,
    catalog,
    blobs,
    purger,
    secrets: { adminToken },
    upstreams: {
      uploadServiceUrl: "https://upload.divine.video",
      moderationApiUrl: "https://moderation-api.divine.video",
      moderationApiToken: "synthetic-mod-token",
      fetcher: fakeFetcher,
    },
    cache: { publicMediaCaching: true },
    writesEnabled: true,
    bunnyDeliveryHost: "media-bunny.divine.video",
    now: () => clock,
  });

  try {
    const sk1 = generateSecretKey();
    const pub1 = getPublicKey(sk1);
    const sk2 = generateSecretKey();
    const pub2 = getPublicKey(sk2);

    // 1. Streaming/chunked thumbnail PUT (> 8 KB, NO Content-Length header) like divine-mobile ThumbnailLegUploader
    const thumbBytes = new Uint8Array(16 * 1024);
    thumbBytes.fill(0xab);
    const thumbHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", thumbBytes)));
    const thumbStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(thumbBytes.slice(0, 8192));
        controller.enqueue(thumbBytes.slice(8192));
        controller.close();
      },
    });
    const authEvent = finalizeEvent({
      kind: 24242,
      created_at: now,
      tags: [["t", "upload"], ["x", thumbHash], ["expiration", String(now + 60)]],
      content: "Upload 📷️ 📷️ 📷️",
    }, sk1);
    const base64url = Buffer.from(JSON.stringify(authEvent)).toString("base64url");
    equal(/[-_]/.test(base64url), true);
    const thumbRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: thumbStream,
        headers: {
          "content-type": "image/jpeg",
          authorization: `Nostr ${base64url}`,
        },
      }),
    );
    equal(thumbRes.status, 201);
    const thumbDesc = await thumbRes.json() as {
      url: string;
      sha256: string;
      size: number;
      type: string;
      uploaded: number;
    };
    equal(thumbDesc.url, `${origin}/${thumbHash}.jpeg`);
    equal(thumbDesc.uploaded, now);
    equal(thumbDesc.sha256, thumbHash);
    equal(thumbDesc.size, thumbBytes.length);
    equal(thumbDesc.type, "image/jpeg");
    // Immediately readable via Blossom GET /<sha256> and GET /list/<pubkey>
    equal((await app(new Request(thumbDesc.url))).status, 200);
    equal((await (await app(new Request(`${origin}/list/${pub1}`))).json() as unknown[]).length, 1);
    const uploadThumbAgain = () =>
      app(
        new Request(`${origin}/upload`, {
          method: "PUT",
          body: thumbBytes,
          headers: {
            "content-type": "image/jpeg",
            authorization: blossomAuth(sk1, "upload", now, thumbHash),
          },
        }),
      );
    equal(
      (await app(
        new Request(`${origin}/${thumbHash}`, {
          method: "DELETE",
          headers: { authorization: blossomAuth(sk1, "delete", now, thumbHash) },
        }),
      )).status,
      202,
    );
    const beforeCleanup = seenRequests.length;
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "HEAD",
          headers: { "x-sha-256": thumbHash },
        }),
      )).status,
      409,
    );
    const pendingRepost = await uploadThumbAgain();
    equal(pendingRepost.status, 503);
    equal(pendingRepost.headers.get("retry-after"), "5");
    equal(seenRequests.length, beforeCleanup);
    const drain = () =>
      app(
        new Request(`${origin}/admin/api/b2-cdn-purge/drain`, {
          method: "POST",
          headers: { authorization: `Bearer ${adminToken}` },
        }),
      );
    await catalog.addQuarantineHold(thumbHash, "cleanup-hold", now);
    equal((await (await drain()).json()).deferred, 1);
    equal(blobs.store.has(thumbHash), true);
    await catalog.removeQuarantineHold(thumbHash, "cleanup-hold");
    clock += 60;
    equal((await (await drain()).json()).completed, 1);
    clock = now;
    const staleCompletion = await app(
      new Request(`${origin}/upload/up_previous/complete`, {
        method: "POST",
        headers: { authorization: blossomAuth(sk1, "upload", now, thumbHash) },
        body: JSON.stringify({ sha256: thumbHash }),
      }),
    );
    equal(staleCompletion.status, 503);
    equal(seenRequests.length, beforeCleanup);
    equal((await app(new Request(thumbDesc.url))).status, 404);
    equal((await uploadThumbAgain()).status, 201);
    equal((await app(new Request(thumbDesc.url))).status, 200);
    equal((await catalog.get(thumbHash))?.owners, [pub1]);

    // Image uploads do not trigger video moderation scans
    equal(modScans.length, 0);

    // 2. Video PUT with ProofMode + copy-only headers
    const videoBytes = new TextEncoder().encode("synthetic-delegated-video-bytes-abcdef0123456789");
    const videoHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", videoBytes)));
    const videoRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: videoBytes,
        headers: {
          "content-type": "video/mp4",
          "x-divine-video-processing": "copy-only",
          "x-proofmode-manifest": "synthetic-proof-manifest",
          authorization: blossomAuth(sk1, "upload", now, videoHash),
        },
      }),
    );
    equal(videoRes.status, 201);
    const videoDesc = await videoRes.json() as {
      url: string;
      sha256: string;
      thumbnail?: string;
      dim?: string;
    };
    equal(videoDesc.url, `${origin}/${videoHash}.mp4`);
    equal(videoDesc.thumbnail, `${origin}/${videoHash}.jpg`);
    equal(videoDesc.dim, "720x1280");
    // Fetching the rewritten thumbnail URL delegates to Cloud Run /thumbnail/:hash (image/jpeg, NEVER raw MP4)
    const fetchedThumb = await app(new Request(videoDesc.thumbnail!));
    equal(fetchedThumb.status, 200);
    equal(fetchedThumb.headers.get("content-type"), "image/jpeg");
    equal(
      new Uint8Array(await fetchedThumb.arrayBuffer()),
      new Uint8Array([0xff, 0xd8, 0xff, 0xd9]),
    );
    equal(modScans.length, 1);
    equal(modScans[0].sha256, videoHash);
    const forwardedPut = seenRequests.find((r) =>
      r.url === "https://upload.divine.video/upload" &&
      r.headers.get("x-proofmode-manifest") === "synthetic-proof-manifest"
    );
    equal(Boolean(forwardedPut), true);
    equal(forwardedPut?.headers.get("x-divine-video-processing"), "copy-only");

    const storedVideo = await catalog.get(videoHash);
    equal(storedVideo?.videoEncodingAllowed, false);
    equal(storedVideo?.transcodeStatus, "pending");
    equal(storedVideo?.transcriptStatus, "pending");

    // 3. Re-upload dedupe by second owner adds second owner without duplicating moderation scan
    const reupRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: videoBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk2, "upload", now, videoHash),
        },
      }),
    );
    equal(reupRes.status, 200);
    equal(modScans.length, 1);
    const deduped = await catalog.get(videoHash);
    equal(deduped?.owners, [pub1, pub2]);

    // 4. Auth x-tag mismatch rejected with 401
    const wrongHash = "1".repeat(64);
    const mismatchRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: videoBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now, wrongHash),
        },
      }),
    );
    equal(mismatchRes.status, 401);

    // 5. Legal-held blob rejected with 403 BOTH pre-proxy (with x tag) and post-proxy (without x tag)
    await app(
      new Request(`${origin}/admin/api/delete`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: videoHash, reason: "legal", legal_hold: true }),
      }),
    );
    const reqCountBefore = seenRequests.length;
    const heldPrecheck = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: videoBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now, videoHash),
        },
      }),
    );
    equal(heldPrecheck.status, 403);
    // Blocked before hitting Cloud Run!
    equal(seenRequests.length, reqCountBefore);

    const heldNoXTag = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: videoBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now),
        },
      }),
    );
    equal(heldNoXTag.status, 403);

    // 6. Upstream 503 preserves Retry-After header
    nextUpstreamResponse = () =>
      new Response(JSON.stringify({ error: "overloaded" }), {
        status: 503,
        headers: { "content-type": "application/json", "retry-after": "12" },
      });
    const busyBytes = new TextEncoder().encode("synthetic-busy-upload");
    const busyHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", busyBytes)));
    const busyRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: busyBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now, busyHash),
        },
      }),
    );
    equal(busyRes.status, 503);
    equal(busyRes.headers.get("retry-after"), "12");
  } finally {
    db.close();
  }
});

Deno.test("BUD-06 HEAD /upload pre-validation and Divine resumable init/complete publish to SQL catalog and Track 1 playback", async () => {
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
  const now = 1800000200;
  const origin = "https://media-bunny.divine.video";
  const adminToken = "synthetic-admin-token-1234567890";

  const videoBytes = new TextEncoder().encode("synthetic-resumable-video-stream-payload-9999");
  const videoHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", videoBytes)));

  const fakeFetcher: typeof fetch = async (input, init) => {
    const reqUrl = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");

    if (reqUrl === "https://upload.divine.video/upload/init" && method === "POST") {
      return new Response(
        JSON.stringify({
          uploadId: "up_0123456789abcdef01234567",
          uploadUrl: "https://upload.divine.video/sessions/up_0123456789abcdef01234567",
          expiresAt: "2026-11-25T00:00:00Z",
          chunkSize: 8 * 1024 * 1024,
          nextOffset: 0,
          requiredHeaders: { "X-Upload-Token": "tok" },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (
      reqUrl === "https://upload.divine.video/upload/up_0123456789abcdef01234567/complete" &&
      method === "POST"
    ) {
      await blobs.write(videoHash, videoBytes, "video/mp4");
      return new Response(
        JSON.stringify({
          sha256: videoHash,
          size: videoBytes.length,
          contentType: "video/mp4",
          thumbnailUrl: `https://media.divine.video/${videoHash}.jpg`,
          dim: "1080x1920",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    return new Response(JSON.stringify({ error: "unexpected route" }), { status: 500 });
  };

  const app = createApp({
    origin,
    catalog,
    blobs,
    secrets: { adminToken },
    upstreams: {
      uploadServiceUrl: "https://upload.divine.video",
      fetcher: fakeFetcher,
    },
    cache: { publicMediaCaching: true },
    writesEnabled: true,
    maxUploadBytes: 1024 * 1024,
    bunnyDeliveryHost: "media-bunny.divine.video",
    now: () => now,
  });

  try {
    const sk = generateSecretKey();
    const pub = getPublicKey(sk);

    // 1. BUD-06 HEAD /upload capability discovery and pre-validation
    const capRes = await app(new Request(`${origin}/upload`, { method: "HEAD" }));
    equal(capRes.status, 200);
    equal(capRes.headers.get("x-divine-upload-extensions"), "resumable-sessions");
    equal(capRes.headers.get("x-divine-upload-control-host"), "media-bunny.divine.video");
    equal(capRes.headers.get("x-divine-upload-data-host"), "upload.divine.video");

    const getCapRes = await app(new Request(`${origin}/upload`, { method: "GET" }));
    equal(getCapRes.status, 200);
    const getCapJson = await getCapRes.json() as { extensions: string[]; max_size: number };
    equal(getCapJson.extensions, ["resumable-sessions"]);
    equal(getCapJson.max_size, 1024 * 1024);

    const badShaHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: { "x-sha-256": "not-a-hash" },
      }),
    );
    equal(badShaHead.status, 400);

    const zeroLenHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: { "x-content-length": "0" },
      }),
    );
    equal(zeroLenHead.status, 400);

    const tooLargeHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: { "x-content-length": String(2 * 1024 * 1024) },
      }),
    );
    equal(tooLargeHead.status, 413);

    const okPreHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: {
          "x-sha-256": videoHash,
          "x-content-length": String(videoBytes.length),
          "x-content-type": "video/mp4",
        },
      }),
    );
    equal(okPreHead.status, 200);
    equal(okPreHead.headers.get("x-exists"), null);

    // 2. POST /upload/init rejects copy-only, auth hash mismatch, invalid size; accepts valid init
    const copyOnlyInit = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, videoHash),
          "content-type": "application/json",
          "x-divine-video-processing": "copy-only",
        },
        body: JSON.stringify({
          sha256: videoHash,
          size: videoBytes.length,
          contentType: "video/mp4",
        }),
      }),
    );
    equal(copyOnlyInit.status, 400);

    const mismatchInit = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, "2".repeat(64)),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sha256: videoHash,
          size: videoBytes.length,
          contentType: "video/mp4",
        }),
      }),
    );
    equal(mismatchInit.status, 401);

    const initRes = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, videoHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sha256: videoHash,
          size: videoBytes.length,
          contentType: "video/mp4",
          fileName: "clip.mp4",
        }),
      }),
    );
    equal(initRes.status, 200);
    equal(initRes.headers.get("x-divine-upload-data-host"), "upload.divine.video");
    const initJson = await initRes.json() as { uploadId: string; uploadUrl: string };
    equal(initJson.uploadId, "up_0123456789abcdef01234567");

    // 3. POST /upload/<id>/complete rejects path traversal and hash mismatches, then succeeds and publishes to catalog
    const badIdRes = await app(
      new Request(`${origin}/upload/bad..id/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, videoHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: videoHash }),
      }),
    );
    equal(badIdRes.status, 400);

    const authMismatchComplete = await app(
      new Request(`${origin}/upload/up_0123456789abcdef01234567/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, "3".repeat(64)),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: videoHash }),
      }),
    );
    equal(authMismatchComplete.status, 401);

    const responseMismatchComplete = await app(
      new Request(`${origin}/upload/up_0123456789abcdef01234567/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: "4".repeat(64) }),
      }),
    );
    equal(responseMismatchComplete.status, 502);

    const completeRes = await app(
      new Request(`${origin}/upload/up_0123456789abcdef01234567/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, videoHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: videoHash }),
      }),
    );
    equal(completeRes.status, 200);
    const completeDesc = await completeRes.json() as {
      thumbnail?: string;
      url: string;
      sha256: string;
      size: number;
      dim?: string;
    };
    equal(completeDesc.url, `${origin}/${videoHash}.mp4`);
    equal(completeDesc.sha256, videoHash);
    equal(completeDesc.size, videoBytes.length);
    equal(completeDesc.thumbnail, `${origin}/${videoHash}.jpg`);
    equal(completeDesc.dim, "1080x1920");

    // 4. Subsequent HEAD /upload reports X-Exists: true, POST /upload/init returns 409 with descriptor
    const existsHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: { "x-sha-256": videoHash },
      }),
    );
    equal(existsHead.status, 200);
    equal(existsHead.headers.get("x-exists"), "true");

    const dupInit = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk, "upload", now, videoHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sha256: videoHash,
          size: videoBytes.length,
          contentType: "video/mp4",
        }),
      }),
    );
    equal(dupInit.status, 409);
    const dupBody = await dupInit.json() as { descriptor: { sha256: string; url: string } };
    equal(dupBody.descriptor.sha256, videoHash);
    equal(dupBody.descriptor.url, `${origin}/${videoHash}.mp4`);

    // 5. Blob is immediately readable, listed for owner, and selectable by Track 1 /api/bunny-playback after approval
    equal((await app(new Request(`${origin}/${videoHash}`))).status, 200);
    equal((await (await app(new Request(`${origin}/list/${pub}`))).json() as unknown[]).length, 1);

    await app(
      new Request(`${origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: videoHash, action: "APPROVE" }),
      }),
    );
    const pbRes = await app(new Request(`${origin}/api/bunny-playback/${videoHash}`));
    equal(pbRes.status, 200);
    const pbBody = await pbRes.json() as { host: string; paths: string[] };
    equal(pbBody.host, "media-bunny.divine.video");
    equal(pbBody.paths, [`/${videoHash}`]);
  } finally {
    db.close();
  }
});

Deno.test("upload hardening: quarantine holds, restricted privacy, encoding policy, chunked size bounds, auth normalization, and derivative failures", async () => {
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
  const now = 1800000300;
  const origin = "https://media-bunny.divine.video";
  const adminToken = "synthetic-admin-token-1234567890";

  let upstreamCalls = 0;
  let customUpstreamHandler:
    | ((
      reqUrl: string,
      method: string,
      headers: Headers,
      body: Uint8Array,
    ) => Response | Promise<Response>)
    | null = null;

  const fakeFetcher: typeof fetch = async (input, init) => {
    upstreamCalls++;
    const reqUrl = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : {}));
    const bodyBytes = init?.body
      ? new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer())
      : new Uint8Array();
    if (customUpstreamHandler) {
      return await customUpstreamHandler(reqUrl, method, headers, bodyBytes);
    }
    const authHeader = headers.get("authorization") ?? "";
    if (!authHeader.startsWith("Nostr ")) {
      return new Response(JSON.stringify({ error: "Invalid Authorization prefix" }), {
        status: 401,
      });
    }
    const procHeader = headers.get("x-divine-video-processing");
    if (procHeader !== null && procHeader !== "copy-only") {
      return new Response(
        JSON.stringify({
          error: "X-Divine-Video-Processing must contain exactly one copy-only value",
        }),
        { status: 400 },
      );
    }
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bodyBytes)));
    return new Response(
      JSON.stringify({
        sha256: hash,
        size: bodyBytes.length,
        type: headers.get("content-type") ?? "application/octet-stream",
        uploaded: now,
        url: `https://media.divine.video/${hash}`,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  const makeApp = (writesEnabled = true) =>
    createApp({
      origin,
      catalog,
      blobs,
      secrets: { adminToken },
      upstreams: {
        uploadServiceUrl: "https://upload.divine.video",
        fetcher: fakeFetcher,
      },
      writesEnabled,
      maxUploadBytes: 32 * 1024,
      now: () => now,
    });

  const app = makeApp(true);

  try {
    const sk1 = generateSecretKey();
    const pub1 = getPublicKey(sk1);
    const sk2 = generateSecretKey();
    const pub2 = getPublicKey(sk2);

    // 1. writesEnabled: false makes HEAD /upload return 503 even when uploadServiceUrl is set
    const readOnlyApp = makeApp(false);
    equal((await readOnlyApp(new Request(`${origin}/upload`, { method: "HEAD" }))).status, 503);

    // 2. Quarantine hold blocks HEAD /upload, POST /upload/init, PUT /upload, and POST /upload/:id/complete before upstream
    const qBytes = new TextEncoder().encode("synthetic-quarantined-payload-1");
    const qHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", qBytes)));
    await catalog.cas(qHash, null, {
      revision: 1,
      hash: qHash,
      size: qBytes.length,
      type: "video/mp4",
      uploaded: now,
      owners: [pub1],
      status: "active",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    await catalog.addQuarantineHold(qHash, "review-hold-42", now);

    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "HEAD",
          headers: { "x-sha-256": qHash },
        }),
      )).status,
      403,
    );
    const callsBeforeQuarantine = upstreamCalls;
    equal(
      (await app(
        new Request(`${origin}/upload/init`, {
          method: "POST",
          headers: {
            authorization: blossomAuth(sk2, "upload", now, qHash),
            "content-type": "application/json",
          },
          body: JSON.stringify({ sha256: qHash, size: qBytes.length, contentType: "video/mp4" }),
        }),
      )).status,
      403,
    );
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "PUT",
          body: qBytes,
          headers: {
            "content-type": "video/mp4",
            authorization: blossomAuth(sk2, "upload", now, qHash),
          },
        }),
      )).status,
      403,
    );
    equal(
      (await app(
        new Request(`${origin}/upload/up_q123/complete`, {
          method: "POST",
          headers: {
            authorization: blossomAuth(sk2, "upload", now, qHash),
            "content-type": "application/json",
          },
          body: JSON.stringify({ sha256: qHash }),
        }),
      )).status,
      403,
    );
    // None of those hit Cloud Run, and sk2 was never added to owners
    equal(upstreamCalls, callsBeforeQuarantine);
    equal((await catalog.get(qHash))?.owners, [pub1]);

    // 3. Restricted blob does not advertise X-Exists on HEAD /upload and blocks non-owner init/upload/complete (403, no owner grant)
    const rBytes = new TextEncoder().encode("synthetic-restricted-video-bytes-only-owner");
    const rHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", rBytes)));
    await catalog.cas(rHash, null, {
      revision: 1,
      hash: rHash,
      size: rBytes.length,
      type: "video/mp4",
      uploaded: now,
      owners: [pub1],
      status: "restricted",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    const restrictedHead = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: { "x-sha-256": rHash },
      }),
    );
    equal(restrictedHead.status, 200);
    equal(restrictedHead.headers.get("x-exists"), null);

    const restrictedInit = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk2, "upload", now, rHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: rHash, size: rBytes.length, contentType: "video/mp4" }),
      }),
    );
    equal(restrictedInit.status, 403);
    const restrictedInitJson = await restrictedInit.json() as Record<string, unknown>;
    equal("descriptor" in restrictedInitJson, false);

    // Non-owner PUT /upload (even without x tag!) and POST /complete must NOT append pub2 to owners
    const restrictedPut = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: rBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk2, "upload", now),
        },
      }),
    );
    equal(restrictedPut.status, 403);
    const restrictedComplete = await app(
      new Request(`${origin}/upload/up_restr/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk2, "upload", now, rHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: rHash }),
      }),
    );
    equal(restrictedComplete.status, 403);
    equal((await catalog.get(rHash))?.owners, [pub1]);

    // HEAD /upload returns 409 for deleted and gated blobs instead of "Upload would be accepted"
    const deletedHash = "9".repeat(64);
    await catalog.cas(deletedHash, null, {
      revision: 1,
      hash: deletedHash,
      size: 64,
      type: "video/mp4",
      uploaded: now,
      owners: [],
      status: "deleted",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: true,
    });
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "HEAD",
          headers: { "x-sha-256": deletedHash },
        }),
      )).status,
      409,
    );
    const gatedHash = "8".repeat(64);
    await catalog.cas(gatedHash, null, {
      revision: 1,
      hash: gatedHash,
      size: 64,
      type: "video/mp4",
      uploaded: now,
      owners: [],
      status: "pending",
      ageRestricted: false,
      held: false,
      gate: "in-flight-gate",
      cleanupPending: false,
    });
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "HEAD",
          headers: { "x-sha-256": gatedHash },
        }),
      )).status,
      409,
    );

    // 4. X-Divine-Video-Processing rejects "encode" with 400 on PUT /upload, POST /upload/init, POST /complete, PUT /mirror
    for (
      const req of [
        new Request(`${origin}/upload`, {
          method: "PUT",
          body: new Uint8Array([1, 2, 3]),
          headers: {
            authorization: blossomAuth(sk1, "upload", now),
            "x-divine-video-processing": "encode",
          },
        }),
        new Request(`${origin}/upload/init`, {
          method: "POST",
          body: JSON.stringify({ sha256: qHash, size: 10, contentType: "video/mp4" }),
          headers: {
            authorization: blossomAuth(sk1, "upload", now),
            "content-type": "application/json",
            "x-divine-video-processing": "encode",
          },
        }),
        new Request(`${origin}/upload/up_abc/complete`, {
          method: "POST",
          body: JSON.stringify({ sha256: qHash }),
          headers: {
            authorization: blossomAuth(sk1, "upload", now),
            "content-type": "application/json",
            "x-divine-video-processing": "encode",
          },
        }),
        new Request(`${origin}/mirror`, {
          method: "PUT",
          body: JSON.stringify({ url: "https://example.com/a.mp4" }),
          headers: {
            authorization: blossomAuth(sk1, "mirror", now),
            "content-type": "application/json",
            "x-divine-video-processing": "encode",
          },
        }),
      ]
    ) {
      equal((await app(req)).status, 400);
    }

    // 5. Lowercase "nostr " auth header is normalized to "Nostr " for Cloud Run, and X-SHA-256 is validated
    const okBytes = new TextEncoder().encode("synthetic-lowercase-nostr-header-test");
    const okHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", okBytes)));
    const lowerAuth = blossomAuth(sk1, "upload", now, okHash).replace(/^Nostr /, "nostr ");
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "PUT",
          body: okBytes,
          headers: {
            "content-type": "image/jpeg",
            "x-sha-256": "not-valid-hex",
            authorization: lowerAuth,
          },
        }),
      )).status,
      400,
    );
    equal(
      (await app(
        new Request(`${origin}/upload`, {
          method: "PUT",
          body: okBytes,
          headers: {
            "content-type": "image/jpeg",
            "x-sha-256": "b".repeat(64),
            authorization: lowerAuth,
          },
        }),
      )).status,
      401,
    );
    const lowerAuthRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: okBytes,
        headers: {
          "content-type": "image/jpeg",
          "x-sha-256": okHash,
          authorization: lowerAuth,
        },
      }),
    );
    equal(lowerAuthRes.status, 201);

    // 6. Chunked PUT exceeding maxUpload (32 KiB) returns 413 even when fetch() wraps stream errors as TypeError
    const origFetcher = customUpstreamHandler;
    customUpstreamHandler = null;
    const typeErrorWrappingApp = createApp({
      origin,
      catalog,
      blobs,
      secrets: { adminToken },
      upstreams: {
        uploadServiceUrl: "https://upload.divine.video",
        fetcher: async (_input, init) => {
          try {
            await new Response(init?.body as BodyInit).arrayBuffer();
          } catch {
            // Simulate WHATWG/Deno fetch() wrapping request-body stream errors in TypeError.
            throw new TypeError("request body stream errored");
          }
          return new Response("{}", { status: 200 });
        },
      },
      writesEnabled: true,
      maxUploadBytes: 32 * 1024,
      now: () => now,
    });
    const bigStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(20 * 1024));
        controller.enqueue(new Uint8Array(20 * 1024));
        controller.close();
      },
    });
    const tooBigChunked = await typeErrorWrappingApp(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: bigStream,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now),
        },
      }),
    );
    equal(tooBigChunked.status, 413);
    customUpstreamHandler = origFetcher;

    customUpstreamHandler = (_u, _m, _h, body) =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            sha256: "c".repeat(64),
            type: "image/jpeg",
            // Intentionally omit `size` on a chunked request (no Content-Length)
            _len: body.length,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );
    const missingSizeStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3, 4]));
        controller.close();
      },
    });
    const missingSizeRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: missingSizeStream,
        headers: {
          "content-type": "image/jpeg",
          authorization: blossomAuth(sk1, "upload", now),
        },
      }),
    );
    equal(missingSizeRes.status, 502);
    customUpstreamHandler = null;

    // 7. JSON null payload on /upload/init returns 400 (not 503), non-string thumbnailUrl on /complete doesn't crash
    const nullInit = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk1, "upload", now),
          "content-type": "application/json",
        },
        body: "null",
      }),
    );
    equal(nullInit.status, 400);

    const weirdThumbHash = "d".repeat(64);
    customUpstreamHandler = () =>
      new Response(
        JSON.stringify({
          sha256: weirdThumbHash,
          size: 512,
          contentType: "video/mp4",
          thumbnailUrl: { unexpected: true },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    const weirdThumbRes = await app(
      new Request(`${origin}/upload/up_weirdthumb/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk1, "upload", now, weirdThumbHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: weirdThumbHash }),
      }),
    );
    equal(weirdThumbRes.status, 200);
    const weirdThumbDesc = await weirdThumbRes.json() as Record<string, unknown>;
    equal("thumbnail" in weirdThumbDesc, false);
    customUpstreamHandler = null;

    // 8. Legacy/archive records (videoEncodingAllowed: undefined) must NOT reset failed transcode on clean re-upload,
    //    and derivative error clamping treats invalid_media as non-terminal while unsupported_media_type is terminal.
    const legacyBytes = new TextEncoder().encode("synthetic-legacy-archive-video-bytes");
    const legacyHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", legacyBytes)));
    await catalog.cas(legacyHash, null, {
      revision: 1,
      hash: legacyHash,
      size: legacyBytes.length,
      type: "video/mp4",
      uploaded: now,
      owners: [pub1],
      status: "active",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
      transcodeStatus: "failed",
      transcodeErrorCode: "old_err",
      // videoEncodingAllowed deliberately omitted (legacy / migrated record)
    });
    const legacyReup = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: legacyBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk2, "upload", now, legacyHash),
        },
      }),
    );
    equal(legacyReup.status, 200);
    const legacyAfter = await catalog.get(legacyHash);
    equal(legacyAfter?.transcodeStatus, "failed");
    equal(legacyAfter?.owners, [pub1, pub2]);

    const errBytes = new TextEncoder().encode("synthetic-error-clamping-video");
    const errHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", errBytes)));
    customUpstreamHandler = () =>
      new Response(
        JSON.stringify({
          sha256: errHash,
          size: errBytes.length,
          type: "video/mp4",
          transcode_error_code: "invalid_media",
          transcode_error_message: "probe failed",
          transcode_terminal: true, // must be clamped to false for invalid_media
          transcript_error_code: "unsupported_media_type",
          transcript_terminal: true, // trusted as terminal
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    const errRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: errBytes,
        headers: {
          "content-type": "video/mp4",
          authorization: blossomAuth(sk1, "upload", now, errHash),
        },
      }),
    );
    equal(errRes.status, 201);
    const errRec = await catalog.get(errHash);
    equal(errRec?.transcodeStatus, "failed");
    equal(errRec?.transcodeTerminal, false);
    equal(errRec?.transcriptStatus, "failed");
    equal(errRec?.transcriptTerminal, true);
    customUpstreamHandler = null;

    // 9. PUT /mirror with copy-only sets videoEncodingAllowed: false; restricting it blocks non-owner reads and mirrors
    const mirrorBytes = new TextEncoder().encode("synthetic-mirrored-copy-only-video");
    const mirrorHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", mirrorBytes)));
    customUpstreamHandler = () =>
      new Response(mirrorBytes, { status: 200, headers: { "content-type": "video/mp4" } });
    const mirrorRes = await app(
      new Request(`${origin}/mirror`, {
        method: "PUT",
        headers: {
          authorization: blossomAuth(sk1, "mirror", now),
          "content-type": "application/json",
          "x-divine-video-processing": "copy-only",
        },
        body: JSON.stringify({ url: "https://cdn.example.com/clip.mp4" }),
      }),
    );
    equal(mirrorRes.status, 200);
    const mirrorRec = await catalog.get(mirrorHash);
    equal(mirrorRec?.videoEncodingAllowed, false);
    equal(mirrorRec?.transcodeStatus, "pending");

    const restrictRes = await app(
      new Request(`${origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, action: "RESTRICT" }),
      }),
    );
    equal(restrictRes.status, 200);
    equal((await app(new Request(`${origin}/${mirrorHash}`))).status, 404);
    const nonOwnerMirror = await app(
      new Request(`${origin}/mirror`, {
        method: "PUT",
        headers: {
          authorization: blossomAuth(sk2, "mirror", now),
          "content-type": "application/json",
        },
        body: JSON.stringify({ url: "https://cdn.example.com/clip.mp4" }),
      }),
    );
    equal(nonOwnerMirror.status, 403);
    customUpstreamHandler = null;

    // 10. Both /admin/api/restore and /admin/api/moderate APPROVE clear cleanupPending so a subsequent
    //     admin soft-delete + drain does NOT erase B2 bytes
    await blobs.write(mirrorHash, mirrorBytes, "video/mp4");
    const modDelRes = await app(
      new Request(`${origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, action: "DELETE" }),
      }),
    );
    equal(modDelRes.status, 200);
    equal((await catalog.get(mirrorHash))?.cleanupPending, true);
    const modApproveRes = await app(
      new Request(`${origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, action: "APPROVE" }),
      }),
    );
    equal(modApproveRes.status, 200);
    equal((await catalog.get(mirrorHash))?.cleanupPending, false);
    equal((await catalog.get(mirrorHash))?.deletedAt, undefined);
    const modDelAgain = await app(
      new Request(`${origin}/admin/api/moderate`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, action: "DELETE" }),
      }),
    );
    equal(modDelAgain.status, 200);
    equal((await catalog.get(mirrorHash))?.cleanupPending, true);
    const restoreRes = await app(
      new Request(`${origin}/admin/api/restore`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, status: "active" }),
      }),
    );
    equal(restoreRes.status, 200);
    equal((await catalog.get(mirrorHash))?.cleanupPending, false);
    const softDelRes = await app(
      new Request(`${origin}/admin/api/delete`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${adminToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: mirrorHash, reason: "soft-only" }),
      }),
    );
    equal(softDelRes.status, 200);
    const softDelRow = await catalog.get(mirrorHash);
    equal(softDelRow?.status, "deleted");
    equal(softDelRow?.cleanupPending, false);
    const drainAfterRestore = await app(
      new Request(`${origin}/admin/api/b2-cdn-purge/drain?max=10`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}` },
      }),
    );
    equal(drainAfterRestore.status, 200);
    const drainAfterRestoreBody = await drainAfterRestore.json() as {
      drained: number;
      completed: number;
      deferred: number;
      skipped_held: number;
    };
    equal(drainAfterRestoreBody.drained >= 2, true);
    equal(drainAfterRestoreBody.completed, drainAfterRestoreBody.drained);
    equal(drainAfterRestoreBody.deferred, 0);
    equal(drainAfterRestoreBody.skipped_held >= 1, true);
    equal(blobs.store.has(mirrorHash), true);

    // 11. /upload/:id/complete preserves Cloud Run 409 ("Upload incomplete"), /upload/init returns 400/503 on
    //     deleted/gated blobs (never 409), conflicting SHA headers return 400, and mixed-case Video/MP4
    //     thumbnail fallback runs policy re-check before returning 422
    customUpstreamHandler = () =>
      new Response(JSON.stringify({ error: "Upload incomplete: 10 of 20 bytes committed" }), {
        status: 409,
        headers: { "content-type": "application/json" },
      });
    const incompleteRes = await app(
      new Request(`${origin}/upload/up_incomplete/complete`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk1, "upload", now),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: "7".repeat(64) }),
      }),
    );
    equal(incompleteRes.status, 409);
    equal(
      (await incompleteRes.json() as { error: string }).error,
      "Upload incomplete: 10 of 20 bytes committed",
    );

    // /upload/init returns 503 on gated/unavailable blobs and 400 on settled owner-deleted blobs
    const gatedInitRes = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk1, "upload", now, gatedHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({ sha256: gatedHash, size: 64, contentType: "video/mp4" }),
      }),
    );
    equal(gatedInitRes.status, 503);
    equal(gatedInitRes.headers.get("retry-after"), "5");

    const settledOwnerDeletedHash = "4".repeat(64);
    await catalog.cas(settledOwnerDeletedHash, null, {
      revision: 1,
      hash: settledOwnerDeletedHash,
      size: 64,
      type: "video/mp4",
      uploaded: now,
      owners: [],
      status: "deleted",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
      ownerDeleted: true,
    });
    const settledDeletedInitRes = await app(
      new Request(`${origin}/upload/init`, {
        method: "POST",
        headers: {
          authorization: blossomAuth(sk1, "upload", now, settledOwnerDeletedHash),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sha256: settledOwnerDeletedHash,
          size: 64,
          contentType: "video/mp4",
        }),
      }),
    );
    equal(settledDeletedInitRes.status, 400);

    const conflictShaRes = await app(
      new Request(`${origin}/upload`, {
        method: "PUT",
        body: new Uint8Array([1, 2, 3]),
        headers: {
          authorization: blossomAuth(sk1, "upload", now),
          "x-sha-256": "5".repeat(64),
          "x-sha256": "6".repeat(64),
        },
      }),
    );
    equal(conflictShaRes.status, 400);
    const conflictHeadShaRes = await app(
      new Request(`${origin}/upload`, {
        method: "HEAD",
        headers: {
          "x-sha-256": "5".repeat(64),
          "x-sha256": "6".repeat(64),
        },
      }),
    );
    equal(conflictHeadShaRes.status, 400);

    const mixedHash = "f".repeat(64);
    await catalog.cas(mixedHash, null, {
      revision: 1,
      hash: mixedHash,
      size: 16,
      type: "Video/MP4",
      uploaded: now,
      owners: [pub1],
      status: "active",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    await blobs.write(mixedHash, new Uint8Array([9, 9, 9]), "Video/MP4");
    let thumbUpstreamCalls = 0;
    customUpstreamHandler = (reqUrl) => {
      equal(reqUrl, `https://upload.divine.video/thumbnail/${mixedHash}`);
      thumbUpstreamCalls++;
      return new Response(null, { status: 422 });
    };
    const unprocThumbRes = await app(new Request(`${origin}/${mixedHash}.jpg`));
    equal(unprocThumbRes.status, 422);
    equal(thumbUpstreamCalls, 1);

    customUpstreamHandler = async (reqUrl) => {
      equal(reqUrl, `https://upload.divine.video/thumbnail/${mixedHash}`);
      thumbUpstreamCalls++;
      // Simulate concurrent quarantine while Cloud Run generates the thumbnail and returns 422.
      await catalog.addQuarantineHold(mixedHash, "mid-flight-hold", now);
      return new Response(null, { status: 422 });
    };
    const revokedThumbRes = await app(new Request(`${origin}/${mixedHash}.jpg`));
    equal(revokedThumbRes.status, 404);
    equal(
      (await revokedThumbRes.json() as { error: string }).error,
      "policy changed during origin read",
    );
    equal(thumbUpstreamCalls, 2);
    equal((await catalog.getQuarantineHolds(mixedHash)).includes("mid-flight-hold"), true);
    customUpstreamHandler = null;
  } finally {
    db.close();
  }
});

Deno.test("video thumbnail requests never leak MP4 bytes and fall back to on-demand generator", async () => {
  const ctx = await setup();
  try {
    const ownerPub = getPublicKey(generateSecretKey());
    const videoHash = "b".repeat(64);
    const imageHash = "c".repeat(64);
    const mp4Bytes = new TextEncoder().encode("synthetic-mp4-not-jpeg");
    const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);

    await ctx.catalog.cas(videoHash, null, {
      revision: 1,
      hash: videoHash,
      size: mp4Bytes.length,
      type: "video/mp4",
      uploaded: ctx.now,
      owners: [ownerPub],
      status: "active",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    await ctx.blobs.write(videoHash, mp4Bytes, "video/mp4");

    await ctx.catalog.cas(imageHash, null, {
      revision: 1,
      hash: imageHash,
      size: jpegBytes.length,
      type: "image/jpeg",
      uploaded: ctx.now,
      owners: [ownerPub],
      status: "active",
      ageRestricted: false,
      held: false,
      gate: null,
      cleanupPending: false,
    });
    await ctx.blobs.write(imageHash, jpegBytes, "image/jpeg");

    // 1. Without uploadServiceUrl, missing video .jpg returns 404 (never MP4 bytes)
    const missingNoUpstream = await ctx.app(new Request(`${ctx.origin}/${videoHash}.jpg`));
    equal(missingNoUpstream.status, 404);

    // 2. Native JPEG blob requested with .jpg still serves its original bytes
    const nativeJpg = await ctx.app(new Request(`${ctx.origin}/${imageHash}.jpg`));
    equal(nativeJpg.status, 200);
    equal(nativeJpg.headers.get("content-type"), "image/jpeg");
    equal(new Uint8Array(await nativeJpg.arrayBuffer()), jpegBytes);

    // 3. With uploadServiceUrl configured, GET falls back to /thumbnail/<hash>, HEAD does not
    const upstreamCalls: string[] = [];
    let upstreamMode: "ok" | "busy" | "unprocessable" | "throw" = "ok";
    const appWithThumbUpstream = createApp({
      origin: ctx.origin,
      catalog: ctx.catalog,
      blobs: ctx.blobs,
      purger: ctx.purger,
      upstreams: {
        uploadServiceUrl: "https://upload-service.invalid",
        fetcher: (input, init) => {
          const url = typeof input === "string"
            ? input
            : input instanceof URL
            ? input.href
            : input.url;
          upstreamCalls.push(`${init?.method ?? "GET"} ${url}`);
          if (upstreamMode === "throw") {
            return Promise.reject(new Error("timeout"));
          }
          if (upstreamMode === "busy") {
            return Promise.resolve(new Response('{"error":"busy"}', { status: 503 }));
          }
          if (upstreamMode === "unprocessable") {
            return Promise.resolve(new Response('{"error":"invalid"}', { status: 422 }));
          }
          return Promise.resolve(
            new Response(jpegBytes.slice(), {
              status: 200,
              headers: { "content-type": "image/jpeg" },
            }),
          );
        },
      },
      cache: { publicMediaCaching: true, browserMaxAgeSecs: 300, edgeMaxAgeSecs: 86400 },
      now: () => ctx.now,
    });

    const headMissing = await appWithThumbUpstream(
      new Request(`${ctx.origin}/${videoHash}.jpg`, { method: "HEAD" }),
    );
    equal(headMissing.status, 404);
    equal(upstreamCalls.length, 0);

    const generated = await appWithThumbUpstream(new Request(`${ctx.origin}/${videoHash}.jpg`));
    equal(generated.status, 200);
    equal(generated.headers.get("content-type"), "image/jpeg");
    equal(generated.headers.get("cache-control"), "public, max-age=300, s-maxage=86400");
    equal(new Uint8Array(await generated.arrayBuffer()), jpegBytes);
    equal(upstreamCalls, [`GET https://upload-service.invalid/thumbnail/${videoHash}`]);

    // 4. Upstream 503 busy propagates 503 + Retry-After + private no-store (never cached)
    upstreamMode = "busy";
    const busy = await appWithThumbUpstream(new Request(`${ctx.origin}/${videoHash}/thumbnail`));
    equal(busy.status, 503);
    equal(busy.headers.get("retry-after"), "5");
    equal(busy.headers.get("cache-control"), "private, no-store");

    // 5. Upstream network/timeout failure maps to 502 (never unhandled 500)
    upstreamMode = "throw";
    const netErr = await appWithThumbUpstream(new Request(`${ctx.origin}/${videoHash}.jpg`));
    equal(netErr.status, 502);

    // 6. Upstream 422 propagates 422 cleanly
    upstreamMode = "unprocessable";
    const bad = await appWithThumbUpstream(new Request(`${ctx.origin}/${videoHash}.jpg`));
    equal(bad.status, 422);

    // 7. Once {hash}.jpg exists in storage, upstream is never called
    await ctx.blobs.write(`${videoHash}.jpg`, jpegBytes, "image/jpeg");
    const callCountBefore = upstreamCalls.length;
    const stored = await appWithThumbUpstream(new Request(`${ctx.origin}/${videoHash}.jpg`));
    equal(stored.status, 200);
    equal(stored.headers.get("content-type"), "image/jpeg");
    equal(upstreamCalls.length, callCountBefore);
  } finally {
    ctx.db.close();
  }
});
