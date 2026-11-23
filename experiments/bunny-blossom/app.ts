// Isolated feasibility implementation. No Fastly SDK or fallback origin.
import { verifyEvent } from "nostr-tools/pure";

export type RecordState = {
  revision: number;
  hash: string;
  size: number;
  type: string;
  uploaded: number;
  owners: string[];
  status: "Pending" | "Active" | "Restricted" | "Deleted";
  ageRestricted: boolean;
  held: boolean;
  gate: string | null;
  cleanupPending: boolean;
};

export interface Catalog {
  get(hash: string): Promise<RecordState | null>;
  // Must be atomic at the primary, not a read-replica read then unconditional write.
  cas(hash: string, expectedRevision: number | null, value: RecordState): Promise<boolean>;
  list(owner: string, limit: number): Promise<RecordState[]>;
}

export interface Blobs {
  read(key: string, request: Request): Promise<Response>;
  write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void>;
}

export type Config = {
  origin: string;
  catalog: Catalog;
  blobs: Blobs;
  now?: () => number;
  // Writes are off in the Bunny entry point unless explicitly enabled for an owned fixture.
  writesEnabled?: boolean;
  fixture?: { hash: string; owners: string[] };
  maxUploadBytes?: number;
};

const HASH = /^[0-9a-f]{64}$/;
const PUBLIC_READ =
  /^\/([0-9a-f]{64})(?:\.(?:mp4|webm)|\/(?:720p\.mp4|480p\.mp4|hls\/(?:master\.m3u8|stream_(?:720|480)p\.(?:m3u8|ts|mp4))))?$/;
const MAX_AUTH = 16 * 1024;
export const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function response(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function auth(
  req: Request,
  action: "upload" | "delete" | "list" | "get",
  now: number,
  hash?: string,
): string {
  const header = req.headers.get("authorization") ?? "";
  if (header.length > MAX_AUTH || !/^nostr\s+/i.test(header)) throw new Error("unauthorized");
  const encoded = atob(header.replace(/^nostr\s+/i, ""));
  const event = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
    Uint8Array.from(encoded, (c) => c.charCodeAt(0)),
  ));
  if (!verifyEvent(event)) throw new Error("unauthorized");
  const tags = (key: string): string[] =>
    event.tags.filter((t: string[]) => t[0] === key && t.length >= 2).map((t: string[]) => t[1]);
  if (event.kind === 27235 && action === "get") {
    if (
      Math.abs(event.created_at - now) > 60 || tags("u").length !== 1 ||
      tags("u")[0] !== req.url || tags("method").length !== 1 ||
      tags("method")[0] !== req.method
    ) throw new Error("unauthorized");
  } else {
    if (event.kind !== 24242 || tags("t")[0] !== action) throw new Error("unauthorized");
    const expiration = tags("expiration");
    // Spike uses a required expiry; legacy optional-expiry parity is not claimed.
    if (expiration.length !== 1 || !/^\d+$/.test(expiration[0]) || +expiration[0] < now) {
      throw new Error("unauthorized");
    }
    if (hash && !tags("x").some((x) => x.toLowerCase() === hash)) {
      throw new Error("unauthorized");
    }
    if (tags("server").some((s) => s !== new URL(req.url).host)) {
      throw new Error("unauthorized");
    }
  }
  return event.pubkey;
}

function descriptor(row: RecordState, origin: string) {
  return {
    url: `${origin}/${row.hash}`,
    sha256: row.hash,
    size: row.size,
    type: row.type,
    uploaded: row.uploaded,
  };
}

async function boundedBody(req: Request, max: number): Promise<Uint8Array<ArrayBuffer>> {
  if (req.headers.has("content-length") && Number(req.headers.get("content-length")) > max) {
    throw new RangeError("body limit");
  }
  const reader = req.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.length;
    if (size > max) {
      await reader.cancel();
      throw new RangeError("body limit");
    }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

export function createApp(config: Config): (req: Request) => Promise<Response> {
  const origin = new URL(config.origin).origin;
  if (!origin.startsWith("https://")) throw new Error("HTTPS public origin required");
  const fixture = config.fixture;
  if (
    config.writesEnabled && (!fixture || !HASH.test(fixture.hash) ||
      !fixture.owners.length || fixture.owners.length > 4 || fixture.owners.some((key) =>
        !HASH.test(key)
      ))
  ) {
    throw new Error("explicit owned fixture scope required for writes");
  }
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  async function route(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.origin !== origin) return response(421, { error: "unrecognized host" });
    if (req.method === "OPTIONS") return new Response(null, { status: 204 });
    if (url.pathname === "/health" && req.method === "GET") {
      return response(200, { runtime: "bunny-blossom-spike", productionReady: false });
    }
    if (url.pathname === "/upload" && req.method === "HEAD") {
      return new Response(null, { status: config.writesEnabled ? 200 : 503 });
    }
    if (url.pathname === "/upload" && req.method === "PUT") {
      if (url.search) return response(400, { error: "unsupported query" });
      if (!config.writesEnabled) return response(503, { error: "fixture writes disabled" });
      let owner: string;
      try {
        owner = auth(req, "upload", now(), fixture!.hash);
      } catch {
        return response(401, { error: "invalid upload authorization" });
      }
      if (!fixture!.owners.includes(owner)) {
        return response(403, { error: "fixture signer required" });
      }
      const body = await boundedBody(req, config.maxUploadBytes ?? 4 * 1024 * 1024);
      const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
      try {
        auth(req, "upload", now(), hash);
      } catch {
        return response(401, { error: "upload hash mismatch" });
      }
      const old = await config.catalog.get(hash);
      if (old?.status === "Deleted" || old?.held || old?.gate) {
        return response(409, { error: "parent unavailable" });
      }
      const gate = crypto.randomUUID();
      const row: RecordState = old ? { ...old, revision: old.revision + 1, gate } : {
        revision: 1,
        hash,
        size: body.length,
        type: req.headers.get("content-type") ?? "application/octet-stream",
        uploaded: now(),
        owners: [],
        status: "Pending",
        ageRestricted: false,
        held: false,
        gate,
        cleanupPending: false,
      };
      if (!await config.catalog.cas(hash, old?.revision ?? null, row)) {
        return response(409, { error: "concurrent parent change" });
      }
      // Any lost storage reply retains the gate. There is no automatic release or mutation replay.
      await config.blobs.write(hash, body, row.type);
      const current = await config.catalog.get(hash);
      if (
        !current || current.revision !== row.revision || current.gate !== gate ||
        current.status === "Deleted" || current.held
      ) {
        return response(409, { error: "publication withdrawn" });
      }
      const ready = {
        ...current,
        revision: current.revision + 1,
        gate: null,
        owners: [...new Set([...current.owners, owner])],
      };
      if (!await config.catalog.cas(hash, current.revision, ready)) {
        return response(409, { error: "publication changed" });
      }
      return response(200, descriptor(ready, origin));
    }
    const listing = /^\/list\/([0-9a-f]{64})$/.exec(url.pathname);
    if (listing && req.method === "GET") {
      let owner: string;
      try {
        owner = auth(req, "list", now());
      } catch {
        return response(401, { error: "invalid list authorization" });
      }
      if (owner !== listing[1]) return response(403, { error: "owner mismatch" });
      if (url.search) return response(400, { error: "pagination not implemented" });
      const rows = await config.catalog.list(owner, 100);
      return response(200, rows.map((row) => descriptor(row, origin)));
    }
    const deletion = /^\/([0-9a-f]{64})$/.exec(url.pathname);
    if (deletion && req.method === "DELETE") {
      if (!config.writesEnabled) return response(503, { error: "fixture writes disabled" });
      let owner: string;
      try {
        owner = auth(req, "delete", now(), deletion[1]);
      } catch {
        return response(401, { error: "invalid delete authorization" });
      }
      if (deletion[1] !== fixture!.hash || !fixture!.owners.includes(owner)) {
        return response(403, { error: "fixture signer required" });
      }
      const row = await config.catalog.get(deletion[1]);
      if (!row) return response(404, { error: "not found" });
      if (!row.owners.includes(owner)) return response(403, { error: "owner mismatch" });
      const owners = row.owners.filter((key) => key !== owner);
      const last = owners.length === 0;
      const next: RecordState = {
        ...row,
        owners,
        revision: row.revision + 1,
        status: last ? "Deleted" : row.status,
        cleanupPending: last || row.cleanupPending,
      };
      if (!await config.catalog.cas(row.hash, row.revision, next)) {
        return response(409, { error: "concurrent parent change" });
      }
      // Never claim physical erasure: version removal and CDN drain are not implemented in this spike.
      return response(202, { status: last ? "cleanup_pending" : "reference_removed" });
    }
    const media = PUBLIC_READ.exec(url.pathname);
    if (media && (req.method === "GET" || req.method === "HEAD")) {
      if (url.search) return response(400, { error: "unsupported query" });
      const row = await config.catalog.get(media[1]);
      if (!row || row.status === "Deleted" || row.held || row.gate) {
        return response(404, { error: "not found" });
      }
      if (row.status === "Restricted" || row.ageRestricted) {
        try {
          auth(req, "get", now(), media[1]);
        } catch {
          return response(401, { error: "viewer authorization required" });
        }
      }
      // Fixed allowlist; no bucket listing, encoded alternate keys or arbitrary origin URLs.
      const key = url.pathname.slice(1).replace(
        /\.(mp4|webm)$/,
        (suffix) => HASH.test(url.pathname.slice(1, -suffix.length)) ? "" : suffix,
      );
      const result = await config.blobs.read(key, req);
      let latest: RecordState | null;
      try {
        latest = await config.catalog.get(media[1]);
      } catch (error) {
        await result.body?.cancel().catch(() => {});
        throw error;
      }
      if (
        !latest || latest.revision !== row.revision || latest.status === "Deleted" || latest.held ||
        latest.gate
      ) {
        await result.body?.cancel().catch(() => {});
        return response(404, { error: "policy changed during origin read" });
      }
      return result;
    }
    return response(501, { error: "route outside feasibility slice" });
  }
  return async (req) => {
    let result: Response;
    try {
      result = await route(req);
    } catch (error) {
      result = response(error instanceof RangeError ? 413 : 503, {
        error: error instanceof RangeError
          ? "upload exceeds fixture limit"
          : "dependency unavailable",
      });
    }
    const headers = new Headers(result.headers);
    headers.set("cache-control", "private, no-store");
    headers.set("surrogate-control", "no-store");
    headers.set("access-control-allow-origin", "*");
    headers.set("access-control-allow-methods", "GET, HEAD, PUT, DELETE, OPTIONS");
    headers.set("access-control-allow-headers", "Authorization, Content-Type, Range");
    headers.set("access-control-expose-headers", "Content-Length, Content-Range, Accept-Ranges");
    return new Response(req.method === "HEAD" ? null : result.body, {
      status: result.status,
      headers,
    });
  };
}
