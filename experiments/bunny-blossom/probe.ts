// Ephemeral runtime conformance probe for Bunny Edge Scripting.
// Runs entirely in-memory with synthetic data to verify Nostr crypto, SQL catalog contract,
// media/auth/quarantine/moderation/delete/list routes on the live Bunny runtime.

import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { createApp, hex } from "./app.ts";
import type {
  BlobRecord,
  Blobs,
  CasOptions,
  Catalog,
  GlobalStats,
  ListPage,
  PurgeItem,
  SubtitleJob,
  UserSummary,
} from "./types.ts";

class MemoryCatalog implements Catalog {
  private rows = new Map<string, BlobRecord>();
  private holds = new Map<string, Set<string>>();
  private subs = new Map<string, SubtitleJob>();
  private purges: PurgeItem[] = [];
  private nextPurgeId = 1;

  get(hash: string): Promise<BlobRecord | null> {
    const r = this.rows.get(hash.toLowerCase());
    return Promise.resolve(r ? structuredClone(r) : null);
  }
  cas(
    hash: string,
    expected: number | null,
    value: BlobRecord,
    options?: CasOptions,
  ): Promise<boolean> {
    const k = hash.toLowerCase();
    const cur = this.rows.get(k);
    if (
      (cur?.revision ?? null) !== expected ||
      (options?.requireUnquarantined && this.holds.get(k)?.size)
    ) {
      return Promise.resolve(false);
    }
    this.rows.set(k, structuredClone(value));
    return Promise.resolve(true);
  }
  list(owner: string, limit: number, cursor?: string | null): Promise<ListPage> {
    const low = owner.toLowerCase();
    const all = [...this.rows.values()]
      .filter((r) =>
        r.status !== "deleted" && r.status !== "banned" && !r.held && r.gate === null &&
        r.owners.includes(low)
      )
      .sort((a, b) => b.uploaded - a.uploaded || a.hash.localeCompare(b.hash));
    let filtered = all;
    if (cursor) {
      const [tsStr, lastHash] = cursor.split(":");
      const ts = Number(tsStr);
      filtered = all.filter((r) => r.uploaded < ts || (r.uploaded === ts && r.hash > lastHash));
    }
    const items = filtered.slice(0, limit).map((r) => structuredClone(r));
    const last = items[items.length - 1];
    const nextCursor = filtered.length > limit && last ? `${last.uploaded}:${last.hash}` : null;
    return Promise.resolve({ items, nextCursor });
  }
  recent(limit: number): Promise<BlobRecord[]> {
    return Promise.resolve(
      [...this.rows.values()]
        .sort((a, b) => b.uploaded - a.uploaded)
        .slice(0, limit)
        .map((r) => structuredClone(r)),
    );
  }
  stats(): Promise<GlobalStats> {
    const by_status: Record<string, number> = {};
    let total_bytes = 0;
    let cleanup_pending = 0;
    for (const r of this.rows.values()) {
      by_status[r.status] = (by_status[r.status] ?? 0) + 1;
      total_bytes += r.size;
      if (r.cleanupPending) cleanup_pending++;
    }
    return Promise.resolve({
      total_blobs: this.rows.size,
      total_bytes,
      by_status,
      cleanup_pending,
    });
  }
  users(limit: number): Promise<UserSummary[]> {
    const map = new Map<string, { count: number; latest: number }>();
    for (const r of this.rows.values()) {
      if (r.status === "deleted" || r.held) continue;
      for (const o of r.owners) {
        const cur = map.get(o) ?? { count: 0, latest: 0 };
        cur.count++;
        cur.latest = Math.max(cur.latest, r.uploaded);
        map.set(o, cur);
      }
    }
    return Promise.resolve(
      [...map.entries()]
        .map(([pubkey, v]) => ({ pubkey, blob_count: v.count, latest_uploaded: v.latest }))
        .slice(0, limit),
    );
  }
  getQuarantineHolds(hash: string): Promise<string[]> {
    return Promise.resolve([...(this.holds.get(hash.toLowerCase()) ?? [])]);
  }
  addQuarantineHold(hash: string, holdId: string): Promise<void> {
    const k = hash.toLowerCase();
    const set = this.holds.get(k) ?? new Set<string>();
    set.add(holdId);
    this.holds.set(k, set);
    return Promise.resolve();
  }
  removeQuarantineHold(hash: string, holdId: string): Promise<void> {
    this.holds.get(hash.toLowerCase())?.delete(holdId);
    return Promise.resolve();
  }
  getSubtitleJob(jobId: string): Promise<SubtitleJob | null> {
    return Promise.resolve(this.subs.get(jobId) ?? null);
  }
  getSubtitleByHash(hash: string, lang?: string): Promise<SubtitleJob | null> {
    const match = [...this.subs.values()].find((s) =>
      s.video_sha256 === hash.toLowerCase() && (!lang || s.lang === lang)
    );
    return Promise.resolve(match ?? null);
  }
  upsertSubtitleJob(job: SubtitleJob): Promise<void> {
    this.subs.set(job.job_id, structuredClone(job));
    return Promise.resolve();
  }
  enqueuePurge(hash: string, reason: string, deleteB2: boolean, now: number): Promise<void> {
    this.purges.push({
      id: this.nextPurgeId++,
      hash: hash.toLowerCase(),
      reason,
      deleteB2,
      attempts: 0,
      nextRetryAt: now,
      createdAt: now,
    });
    return Promise.resolve();
  }
  listDuePurges(now: number, limit: number): Promise<PurgeItem[]> {
    return Promise.resolve(this.purges.filter((p) => p.nextRetryAt <= now).slice(0, limit));
  }
  completePurge(id: number): Promise<void> {
    this.purges = this.purges.filter((p) => p.id !== id);
    return Promise.resolve();
  }
  deferPurge(id: number, attempts: number, nextRetryAt: number): Promise<void> {
    const p = this.purges.find((item) => item.id === id);
    if (p) {
      p.attempts = attempts;
      p.nextRetryAt = nextRetryAt;
    }
    return Promise.resolve();
  }
}

class MemoryBlobs implements Blobs {
  private map = new Map<string, { body: Uint8Array; type: string }>();
  read(key: string): Promise<Response> {
    const hit = this.map.get(key);
    if (!hit) return Promise.resolve(new Response(null, { status: 404 }));
    return Promise.resolve(
      new Response(hit.body.slice(), {
        status: 200,
        headers: {
          "content-type": hit.type,
          "content-length": String(hit.body.length),
          "accept-ranges": "bytes",
        },
      }),
    );
  }
  write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void> {
    this.map.set(key, { body: body.slice(), type });
    return Promise.resolve();
  }
}

function authHeader(
  sk: Uint8Array,
  action: "upload" | "delete" | "list",
  now: number,
  hash?: string,
): string {
  const tags: string[][] = [["t", action], ["expiration", String(now + 60)]];
  if (hash) tags.push(["x", hash]);
  const ev = finalizeEvent({ kind: 24242, created_at: now, tags, content: action }, sk);
  return `Nostr ${btoa(JSON.stringify(ev))}`;
}

export async function runtimeProbe(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname !== "/health" || !["GET", "HEAD"].includes(req.method)) {
    return new Response(JSON.stringify({ error: "probe only serves GET/HEAD /health" }), {
      status: 404,
      headers: { "content-type": "application/json", "cache-control": "private, no-store" },
    });
  }
  const now = Math.floor(Date.now() / 1000);
  const sk = generateSecretKey();
  const owner = getPublicKey(sk);
  const body = new TextEncoder().encode(`probe-${crypto.randomUUID()}`);
  const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  const origin = "https://probe.invalid";
  const app = createApp({
    origin,
    catalog: new MemoryCatalog(),
    blobs: new MemoryBlobs(),
    writesEnabled: true,
    fixture: { hash, owners: [owner] },
    now: () => now,
  });

  const up = await app(
    new Request(`${origin}/upload`, {
      method: "PUT",
      body,
      headers: {
        "content-type": "video/mp4",
        authorization: authHeader(sk, "upload", now, hash),
      },
    }),
  );
  const upJson = await up.json() as { sha256?: string; size?: number };
  const get = await app(new Request(`${origin}/${hash}`));
  const getBytes = new Uint8Array(await get.arrayBuffer());
  const head = await app(new Request(`${origin}/${hash}`, { method: "HEAD" }));
  const list = await app(
    new Request(`${origin}/list/${owner}`, {
      headers: { authorization: authHeader(sk, "list", now) },
    }),
  );
  const listJson = await list.json() as { sha256?: string }[];
  const del = await app(
    new Request(`${origin}/${hash}`, {
      method: "DELETE",
      headers: { authorization: authHeader(sk, "delete", now, hash) },
    }),
  );
  const delJson = await del.json() as { status?: string };
  const denied = await app(new Request(`${origin}/${hash}`));
  const deniedJson = await denied.json() as { error?: string };

  const bodyChecksPassed = upJson.sha256 === hash && upJson.size === body.length &&
    hex(getBytes) === hex(body) && listJson.length === 1 && listJson[0].sha256 === hash &&
    delJson.status === "cleanup_pending" && typeof deniedJson.error === "string";
  const passed = up.status === 201 && get.status === 200 && head.status === 200 &&
    list.status === 200 && del.status === 202 && denied.status === 404 && bodyChecksPassed;

  return new Response(
    req.method === "HEAD" ? null : JSON.stringify({
      passed,
      bodyChecksPassed,
      persistentStorageTested: false,
      productionReady: false,
      statuses: {
        upload: up.status,
        get: get.status,
        head: head.status,
        list: list.status,
        delete: del.status,
        denied: denied.status,
      },
    }),
    {
      status: passed ? 200 : 500,
      headers: { "content-type": "application/json", "cache-control": "private, no-store" },
    },
  );
}
