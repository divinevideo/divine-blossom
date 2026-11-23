// Native Bunny Edge Scripting Blossom application with full route parity.
// Covers BUD-01/02/04/06/09, NIP-98 viewer auth, HLS/MP4/VTT/audio/provenance,
// subtitle jobs, resumable upload proxy, webhooks, quarantine, erasure/purge outbox, and admin API.

import {
  isAdminRequest,
  isArchiveImportAuthorized,
  isPurgeDrainAuthorized,
  isTranscodeWebhook,
  optionalViewerPubkey,
  requireNostrAuth,
} from "./auth.ts";
import {
  type BlobRecord,
  type BlobStatus,
  buildDescriptor,
  type Config,
  evaluateAccess,
  normalizeStatus,
  type SubtitleJob,
} from "./types.ts";

export type { BlobRecord as RecordState, Blobs, Catalog, Config } from "./types.ts";

const HASH = /^[0-9a-f]{64}$/;
const DEFAULT_VERSION = "v128-bunny-edge-blossom";
const DEFAULT_MAX_DIRECT_UPLOAD = 16 * 1024 * 1024;
const DEFAULT_MAX_UPLOAD = 50 * 1024 * 1024 * 1024;

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Divine Blossom Media Server</title></head>
<body>
<h1>Divine Blossom Media Server</h1>
<p>Content-addressed Nostr media storage implementing BUD-01, BUD-02, BUD-04, BUD-06, and BUD-09.</p>
</body>
</html>`;

export const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function jsonResp(status: number, value: unknown, extraHeaders?: Record<string, string>): Response {
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": "private, no-store",
    "surrogate-control": "no-store",
  });
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  }
  return new Response(JSON.stringify(value), { status, headers });
}

function corsHeaders(existing?: Headers): Headers {
  const headers = new Headers(existing);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS");
  headers.set(
    "access-control-allow-headers",
    "Authorization, Content-Type, Range, X-Sha256, X-Request-Id, X-Content-Length",
  );
  headers.set(
    "access-control-expose-headers",
    "Content-Length, Content-Range, Accept-Ranges, X-Sha256, X-Content-Length, X-C2PA-Manifest-Id, X-Source-Sha256, X-Content-SHA256, X-Audio-Duration, X-Audio-Size, X-Divine-Upload-Extensions, X-Divine-Upload-Control-Host, X-Divine-Upload-Data-Host, Retry-After, Content-Language, X-Divine-Machine-Translated",
  );
  return headers;
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

async function readJson<T>(req: Request, maxBytes = 64 * 1024): Promise<T> {
  const bytes = await boundedBody(req, maxBytes);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as T;
}

interface MediaRoute {
  hash: string;
  storageKey: string;
  kind:
    | "original"
    | "hls_master"
    | "hls_child"
    | "quality"
    | "vtt"
    | "audio"
    | "sound"
    | "thumbnail";
  defaultContentType?: string;
  lang?: string;
}

function parseMediaRoute(pathname: string): MediaRoute | null {
  // /{hash}.hls
  let m = /^\/([0-9a-fA-F]{64})\.hls$/.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    return {
      hash,
      storageKey: `${hash}/hls/master.m3u8`,
      kind: "hls_master",
      defaultContentType: "application/vnd.apple.mpegurl",
    };
  }

  // /{hash}/hls/{child}
  m =
    /^\/([0-9a-fA-F]{64})\/hls\/(master\.m3u8|stream_(?:1080|720|480|360)p\.(?:m3u8|ts|mp4)|segment_\d+\.ts)$/
      .exec(
        pathname,
      );
  if (m) {
    const hash = m[1].toLowerCase();
    const child = m[2];
    const ct = child.endsWith(".m3u8")
      ? "application/vnd.apple.mpegurl"
      : child.endsWith(".ts")
      ? "video/mp2t"
      : "video/mp4";
    return {
      hash,
      storageKey: `${hash}/hls/${child}`,
      kind: child === "master.m3u8" ? "hls_master" : "hls_child",
      defaultContentType: ct,
    };
  }

  // /{hash}.{lang}.vtt or /{hash}.vtt
  m = /^\/([0-9a-fA-F]{64})(?:\.([a-z]{2}(?:-[a-z0-9]{2,8})?))?\.vtt$/i.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    const lang = m[2]?.toLowerCase();
    return {
      hash,
      storageKey: lang ? `${hash}/vtt/${lang}.vtt` : `${hash}/vtt/main.vtt`,
      kind: "vtt",
      defaultContentType: "text/vtt; charset=utf-8",
      lang,
    };
  }

  // /{hash}/VTT or /{hash}/vtt or /{hash}/transcript
  m = /^\/([0-9a-fA-F]{64})\/(?:vtt|transcript)$/i.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    return {
      hash,
      storageKey: `${hash}/vtt/main.vtt`,
      kind: "vtt",
      defaultContentType: "text/vtt; charset=utf-8",
    };
  }

  // /{hash}/sound
  m = /^\/([0-9a-fA-F]{64})\/sound$/.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    return {
      hash,
      storageKey: `${hash}/audio/analysis.json`,
      kind: "sound",
      defaultContentType: "application/json",
    };
  }

  // /{hash}.audio.m4a or /{hash}/audio
  m = /^\/([0-9a-fA-F]{64})(?:\.audio\.m4a|\/audio)$/.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    return {
      hash,
      storageKey: `${hash}.audio.m4a`,
      kind: "audio",
      defaultContentType: "audio/mp4",
    };
  }

  // /{hash}/720p, /{hash}/480p, /{hash}/720p.mp4, /{hash}/480p.mp4, /{hash}/1080p, /{hash}/360p
  m = /^\/([0-9a-fA-F]{64})\/(1080p|720p|480p|360p)(?:\.mp4)?$/.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    const quality = m[2];
    return {
      hash,
      storageKey: `${hash}/hls/stream_${quality}.mp4`,
      kind: "quality",
      defaultContentType: "video/mp4",
    };
  }

  // /{hash}/thumbnail
  m = /^\/([0-9a-fA-F]{64})\/thumbnail$/.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    return {
      hash,
      storageKey: `${hash}.jpg`,
      kind: "thumbnail",
      defaultContentType: "image/jpeg",
    };
  }

  // /{hash}[.<ext>]
  m = /^\/([0-9a-fA-F]{64})(?:\.([a-z0-9]{1,8}))?$/i.exec(pathname);
  if (m) {
    const hash = m[1].toLowerCase();
    const ext = m[2]?.toLowerCase();
    if (ext === "jpg" || ext === "jpeg") {
      // Allow thumbnail alias fallback if original isn't jpeg; caller checks original or jpg key.
      return { hash, storageKey: hash, kind: "original" };
    }
    return { hash, storageKey: hash, kind: "original" };
  }

  return null;
}

function mapModerationAction(action: string, isWebhook: boolean): BlobStatus | "delete" | null {
  const upper = action.trim().toUpperCase();
  if (upper === "DELETE") return "delete";
  if (isWebhook) {
    switch (upper) {
      case "BLOCK":
      case "BAN":
      case "PERMANENT_BAN":
        return "banned";
      case "AGE_RESTRICTED":
      case "AGE_RESTRICT":
        return "age_restricted";
      case "RESTRICT":
      case "QUARANTINE":
        return "restricted";
      case "APPROVE":
      case "SAFE":
        return "active";
      default:
        return null;
    }
  }
  switch (upper) {
    case "BAN":
    case "BLOCK":
      return "banned";
    case "RESTRICT":
      return "restricted";
    case "AGE_RESTRICT":
    case "AGE_RESTRICTED":
      return "age_restricted";
    case "APPROVE":
    case "ACTIVE":
      return "active";
    case "PENDING":
      return "pending";
    default:
      return null;
  }
}

export function createApp(config: Config): (req: Request) => Promise<Response> {
  const origin = new URL(config.origin).origin;
  if (!origin.startsWith("https://")) throw new Error("HTTPS public origin required");
  const originHost = new URL(origin).host;
  const fixture = config.fixture;
  if (
    fixture &&
    (!HASH.test(fixture.hash) || !fixture.owners.length || fixture.owners.length > 4 ||
      fixture.owners.some((owner) => !HASH.test(owner)))
  ) {
    throw new Error("invalid fixture guard configuration");
  }

  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const fetcher = config.upstreams?.fetcher ?? fetch;
  const maxDirectUpload = config.maxDirectUploadBytes ?? config.maxUploadBytes ??
    DEFAULT_MAX_DIRECT_UPLOAD;
  const maxUpload = config.maxUploadBytes ?? DEFAULT_MAX_UPLOAD;
  const publicCaching = Boolean(config.cache?.publicMediaCaching);
  const browserMaxAge = config.cache?.browserMaxAgeSecs ?? 300;
  const edgeMaxAge = config.cache?.edgeMaxAgeSecs ?? 86400;

  async function bestEffortPurge(hash: string, reason: string, deleteB2 = false): Promise<void> {
    await config.catalog.enqueuePurge(hash, reason, deleteB2, now());
    if (config.purger && !deleteB2) {
      try {
        await config.purger.purgeHash(hash);
      } catch {
        // Outbox retains durable retry.
      }
    }
  }

  async function serveMedia(
    req: Request,
    media: MediaRoute,
    forceAdminBypass = false,
  ): Promise<Response> {
    const isAdmin = forceAdminBypass || isAdminRequest(req, config.secrets);
    const row = await config.catalog.get(media.hash);
    if (!row) return jsonResp(404, { error: "not found" });

    const holds = await config.catalog.getQuarantineHolds(media.hash);
    const viewer = isAdmin ? null : optionalViewerPubkey(req, now(), media.hash, origin);
    const access = evaluateAccess(row, holds, viewer, isAdmin);

    if (access === "not_found") {
      return jsonResp(404, { error: "not found" });
    }
    if (access === "age_gated") {
      return jsonResp(401, { error: "age_restricted" });
    }

    // Try primary storage key (and alternate quality / thumbnail / legacy vtt fallbacks)
    let targetKey = media.storageKey;
    if (media.kind === "original" && row.type.startsWith("video/")) {
      if (/^\/[0-9a-fA-F]{64}\.(jpg|jpeg)$/i.test(new URL(req.url).pathname)) {
        targetKey = `${media.hash}.jpg`;
      }
    }
    let storageResp = await config.blobs.read(targetKey, req);
    if (storageResp.status === 404 && media.kind === "quality") {
      const altKey = media.storageKey.replace("/hls/stream_", "/");
      storageResp = await config.blobs.read(altKey, req);
    }
    if (storageResp.status === 404 && media.kind === "vtt") {
      const legacyVtt = media.lang ? `${media.hash}.${media.lang}.vtt` : `${media.hash}.vtt`;
      storageResp = await config.blobs.read(legacyVtt, req);
    }
    if (storageResp.status === 404 && targetKey !== media.storageKey) {
      storageResp = await config.blobs.read(media.storageKey, req);
    }

    // Re-check policy after storage headers return to close race windows.
    let latest: BlobRecord | null;
    let latestHolds: string[];
    try {
      [latest, latestHolds] = await Promise.all([
        config.catalog.get(media.hash),
        config.catalog.getQuarantineHolds(media.hash),
      ]);
    } catch (error) {
      await storageResp.body?.cancel().catch(() => {});
      throw error;
    }

    if (
      !latest || latest.revision !== row.revision ||
      evaluateAccess(latest, latestHolds, viewer, isAdmin) !== "allowed"
    ) {
      await storageResp.body?.cancel().catch(() => {});
      return jsonResp(404, { error: "policy changed during origin read" });
    }

    if (storageResp.status === 404) {
      return jsonResp(404, { error: "blob bytes not found" });
    }

    const headers = new Headers(storageResp.headers);
    if (!headers.has("content-type") && media.defaultContentType) {
      headers.set("content-type", media.defaultContentType);
    }
    if (!headers.has("accept-ranges")) {
      headers.set("accept-ranges", "bytes");
    }
    headers.set("x-sha256", media.hash);
    if (latest.c2paManifestId) {
      headers.set("x-c2pa-manifest-id", latest.c2paManifestId);
    }
    if (media.lang) {
      headers.set("content-language", media.lang);
    }

    const isPubliclyCacheable = publicCaching &&
      !isAdmin &&
      viewer === null &&
      !req.headers.has("authorization") &&
      latest.status === "active" &&
      !latest.ageRestricted &&
      !latest.held &&
      latestHolds.length === 0 &&
      (storageResp.status === 200 || storageResp.status === 206);

    if (isPubliclyCacheable) {
      headers.set("cache-control", `public, max-age=${browserMaxAge}, s-maxage=${edgeMaxAge}`);
      headers.delete("surrogate-control");
    } else {
      headers.set("cache-control", "private, no-store");
      headers.set("surrogate-control", "no-store");
    }

    return new Response(req.method === "HEAD" ? null : storageResp.body, {
      status: storageResp.status,
      headers,
    });
  }

  async function proxyUpstream(
    upstreamBase: string,
    targetPath: string,
    req: Request,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const reqUrl = new URL(req.url);
    const targetUrl = `${upstreamBase.replace(/\/+$/, "")}${targetPath}${reqUrl.search}`;
    const headers = new Headers();
    for (
      const name of [
        "authorization",
        "content-type",
        "content-length",
        "x-sha256",
        "x-request-id",
        "accept",
      ]
    ) {
      const val = req.headers.get(name);
      if (val !== null) headers.set(name, val);
    }
    headers.set("x-original-host", originHost);
    if (extraHeaders) {
      for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
    }
    const hasBody = !["GET", "HEAD"].includes(req.method.toUpperCase());
    const res = await fetcher(targetUrl, {
      method: req.method,
      headers,
      body: hasBody ? req.body : undefined,
      redirect: "error",
      signal: AbortSignal.timeout(60_000),
    });
    const outHeaders = new Headers(res.headers);
    outHeaders.set("cache-control", "private, no-store");
    return new Response(res.body, { status: res.status, headers: outHeaders });
  }

  async function handleDirectUpload(req: Request, owner: string): Promise<Response> {
    if (fixture && !fixture.owners.includes(owner)) {
      return jsonResp(403, { error: "fixture signer required" });
    }
    const body = await boundedBody(req, maxDirectUpload);
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
    if (fixture && hash !== fixture.hash) {
      return jsonResp(403, { error: "fixture digest required" });
    }
    try {
      requireNostrAuth(req, "upload", now(), hash, { publicOrigin: origin });
    } catch {
      return jsonResp(401, { error: "upload hash mismatch" });
    }

    const old = await config.catalog.get(hash);
    if (old?.held) {
      return jsonResp(403, { error: "content blocked by legal hold" });
    }
    if (old?.status === "banned") {
      return jsonResp(403, { error: "content banned" });
    }
    if (old?.status === "deleted" || old?.gate) {
      return jsonResp(409, { error: "parent unavailable" });
    }

    const gate = crypto.randomUUID();
    const row: BlobRecord = old ? { ...old, revision: old.revision + 1, gate } : {
      revision: 1,
      hash,
      size: body.length,
      type: req.headers.get("content-type") ?? "application/octet-stream",
      uploaded: now(),
      owners: [],
      status: "pending",
      ageRestricted: false,
      held: false,
      gate,
      cleanupPending: false,
    };

    if (!await config.catalog.cas(hash, old?.revision ?? null, row)) {
      return jsonResp(409, { error: "concurrent parent change" });
    }

    // Any lost storage reply retains the gate — never silently cleared.
    await config.blobs.write(hash, body, row.type);

    const current = await config.catalog.get(hash);
    if (
      !current || current.revision !== row.revision || current.gate !== gate ||
      current.status === "deleted" || current.held
    ) {
      return jsonResp(409, { error: "publication withdrawn" });
    }

    const ready: BlobRecord = {
      ...current,
      revision: current.revision + 1,
      gate: null,
      owners: [...new Set([...current.owners, owner])],
    };
    if (!await config.catalog.cas(hash, current.revision, ready)) {
      return jsonResp(409, { error: "publication changed" });
    }
    return jsonResp(200, buildDescriptor(ready, origin));
  }

  async function route(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.origin !== origin) {
      return jsonResp(421, { error: "unrecognized host" });
    }
    const method = req.method.toUpperCase();
    const path = url.pathname;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Landing, health, version
    if (path === "/" && (method === "GET" || method === "HEAD")) {
      return new Response(method === "HEAD" ? null : LANDING_HTML, {
        status: 200,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "public, max-age=300",
        },
      });
    }
    if (path === "/version" && method === "GET") {
      return new Response(config.versionBanner ?? DEFAULT_VERSION, {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "private, no-store",
        },
      });
    }
    if (path === "/health" && (method === "GET" || method === "HEAD")) {
      return jsonResp(200, {
        runtime: "bunny-blossom",
        status: "ok",
        cachingEnabled: publicCaching,
        uploadDelegation: Boolean(config.upstreams?.uploadServiceUrl),
      });
    }

    // Bunny playback selection endpoint (compatible with divine-mobile bunnyPlayback flag)
    if (path.startsWith("/api/bunny-playback/") && method === "GET") {
      const parent = path.slice("/api/bunny-playback/".length).toLowerCase();
      if (!HASH.test(parent) || url.search) return jsonResp(404, { error: "Not found" });
      if (req.headers.has("authorization") || req.headers.has("cookie")) {
        return jsonResp(200, {
          version: 1,
          host: config.bunnyDeliveryHost ?? originHost,
          paths: [],
        });
      }
      const row = await config.catalog.get(parent);
      const holds = row ? await config.catalog.getQuarantineHolds(parent) : [];
      if (!row || evaluateAccess(row, holds, null, false) !== "allowed") {
        return jsonResp(404, { error: "Not found" });
      }
      if (row.status !== "active") {
        return jsonResp(200, {
          version: 1,
          host: config.bunnyDeliveryHost ?? originHost,
          paths: [],
        });
      }
      const paths: string[] = [];
      if (row.type === "video/mp4") paths.push(`/${parent}`);
      if (row.transcodeStatus === "complete") {
        paths.push(`/${parent}/720p.mp4`, `/${parent}/480p.mp4`, `/${parent}/hls/master.m3u8`);
      }
      return jsonResp(200, { version: 1, host: config.bunnyDeliveryHost ?? originHost, paths });
    }

    // BUD-06: HEAD /upload (also handle GET when a proxy converts HEAD to GET)
    if (path === "/upload" && (method === "HEAD" || method === "GET")) {
      if (!config.writesEnabled && !config.upstreams?.uploadServiceUrl) {
        return new Response(null, { status: 503 });
      }
      const headers = new Headers({
        "x-content-length": String(maxUpload),
        "x-divine-upload-extensions": "resumable-v1",
        "x-divine-upload-control-host": originHost,
        "cache-control": "private, no-store",
      });
      if (config.upstreams?.uploadServiceUrl) {
        headers.set("x-divine-upload-data-host", new URL(config.upstreams.uploadServiceUrl).host);
      }
      return new Response(null, { status: 200, headers });
    }

    // BUD-02: PUT /upload
    if (path === "/upload" && method === "PUT") {
      if (url.search) return jsonResp(400, { error: "unsupported query" });
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      let owner: string;
      try {
        owner = requireNostrAuth(req, "upload", now(), fixture?.hash, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }

      // Check legal hold / ban before delegating if X-Sha256 is supplied
      const declaredSha = req.headers.get("x-sha256")?.trim().toLowerCase();
      if (declaredSha && HASH.test(declaredSha)) {
        const existing = await config.catalog.get(declaredSha);
        if (existing?.held || existing?.status === "banned") {
          return jsonResp(403, { error: "content blocked" });
        }
      }

      // Delegate streaming uploads to Cloud Run upload service when configured (production mode)
      if (config.upstreams?.uploadServiceUrl && !fixture) {
        return await proxyUpstream(config.upstreams.uploadServiceUrl, "/upload", req);
      }
      return await handleDirectUpload(req, owner);
    }

    // Resumable upload control plane
    if (path === "/upload/init" && method === "POST") {
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "upload service not configured" });
      }
      try {
        requireNostrAuth(req, "upload", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }
      return await proxyUpstream(config.upstreams.uploadServiceUrl, "/upload/init", req);
    }
    if (path.startsWith("/upload/") && path.endsWith("/complete") && method === "POST") {
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "upload service not configured" });
      }
      try {
        requireNostrAuth(req, "upload", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }
      return await proxyUpstream(config.upstreams.uploadServiceUrl, path, req);
    }

    // Synchronous transcription proxy
    if (path === "/transcribe" && method === "POST") {
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "transcription upstream not configured" });
      }
      try {
        requireNostrAuth(req, "media", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid transcribe authorization" });
      }
      return await proxyUpstream(config.upstreams.uploadServiceUrl, "/transcribe", req);
    }

    // Subtitle jobs API
    if (path === "/v1/subtitles/jobs" && method === "POST") {
      const body = await readJson<{ video_sha256?: string; lang?: string; force?: boolean }>(req);
      const hash = body.video_sha256?.toLowerCase() ?? "";
      const lang = (body.lang ?? "en").toLowerCase();
      if (!HASH.test(hash) || !/^[a-z]{2}(?:-[a-z0-9]{2,8})?$/.test(lang)) {
        return jsonResp(400, { error: "invalid video_sha256 or lang" });
      }
      const blob = await config.catalog.get(hash);
      if (!blob || blob.status === "deleted" || blob.status === "banned") {
        return jsonResp(404, { error: "video not found" });
      }
      const existing = await config.catalog.getSubtitleByHash(hash, lang);
      if (existing && !body.force && existing.status !== "failed") {
        return jsonResp(200, existing);
      }
      const ts = now();
      const job: SubtitleJob = {
        job_id: crypto.randomUUID(),
        video_sha256: hash,
        lang,
        status: "queued",
        vtt_key: lang === "en" ? `${hash}.vtt` : `${hash}.${lang}.vtt`,
        error: null,
        created_at: ts,
        updated_at: ts,
      };
      await config.catalog.upsertSubtitleJob(job);
      return jsonResp(202, job);
    }
    if (path.startsWith("/v1/subtitles/jobs/") && method === "GET") {
      const jobId = path.slice("/v1/subtitles/jobs/".length);
      if (!jobId || jobId.includes("/")) return jsonResp(400, { error: "invalid job id" });
      const job = await config.catalog.getSubtitleJob(jobId);
      return job ? jsonResp(200, job) : jsonResp(404, { error: "job not found" });
    }
    if (path.startsWith("/v1/subtitles/by-hash/") && method === "GET") {
      const hash = path.slice("/v1/subtitles/by-hash/".length).toLowerCase();
      if (!HASH.test(hash)) return jsonResp(400, { error: "invalid sha256" });
      const lang = url.searchParams.get("lang")?.toLowerCase() ?? undefined;
      const job = await config.catalog.getSubtitleByHash(hash, lang);
      return job ? jsonResp(200, job) : jsonResp(404, { error: "subtitle job not found" });
    }

    // Provenance endpoint
    if (path.endsWith("/provenance") && method === "GET") {
      const hash = path.slice(1, -"/provenance".length).toLowerCase();
      if (!HASH.test(hash)) return jsonResp(400, { error: "invalid sha256" });
      const row = await config.catalog.get(hash);
      const holds = row ? await config.catalog.getQuarantineHolds(hash) : [];
      if (
        !row || evaluateAccess(row, holds, null, isAdminRequest(req, config.secrets)) !== "allowed"
      ) {
        return jsonResp(404, { error: "not found" });
      }
      return jsonResp(200, {
        sha256: row.hash,
        owner: row.owners[0] ?? null,
        uploaders: row.owners,
        uploaded: new Date(row.uploaded * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        c2pa_manifest_id: row.c2paManifestId ?? null,
      });
    }

    // BUD-02: GET /list/<pubkey> with cursor pagination
    const listMatch = /^\/list\/([0-9a-fA-F]{64})$/.exec(path);
    if (listMatch && method === "GET") {
      const targetPubkey = listMatch[1].toLowerCase();
      if (req.headers.has("authorization")) {
        let authPubkey: string;
        try {
          authPubkey = requireNostrAuth(req, "list", now(), undefined, {
            allowLegacyOptionalExpiry: true,
            publicOrigin: origin,
          });
        } catch {
          return jsonResp(401, { error: "invalid list authorization" });
        }
        if (authPubkey !== targetPubkey) return jsonResp(403, { error: "owner mismatch" });
      } else if (fixture) {
        return jsonResp(401, { error: "invalid list authorization" });
      }
      const limitParam = url.searchParams.get("limit");
      const cursor = url.searchParams.get("cursor");
      const limit = limitParam ? Number(limitParam) : 100;
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return jsonResp(400, { error: "invalid limit" });
      }
      let page;
      try {
        page = await config.catalog.list(targetPubkey, limit, cursor);
      } catch {
        return jsonResp(400, { error: "invalid cursor" });
      }
      const extra: Record<string, string> = {};
      if (page.nextCursor) extra["x-next-cursor"] = page.nextCursor;
      return jsonResp(200, page.items.map((r) => buildDescriptor(r, origin)), extra);
    }

    // BUD-02: DELETE /<sha256>
    const delMatch = /^\/([0-9a-fA-F]{64})$/.exec(path);
    if (delMatch && method === "DELETE") {
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      const hash = delMatch[1].toLowerCase();
      let owner: string;
      try {
        owner = requireNostrAuth(req, "delete", now(), hash, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid delete authorization" });
      }
      if (fixture && (hash !== fixture.hash || !fixture.owners.includes(owner))) {
        return jsonResp(403, { error: "fixture signer required" });
      }
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "not found" });
      if (!row.owners.includes(owner)) return jsonResp(403, { error: "owner mismatch" });

      const owners = row.owners.filter((k) => k !== owner);
      const last = owners.length === 0;
      const next: BlobRecord = {
        ...row,
        owners,
        revision: row.revision + 1,
        status: last ? "deleted" : row.status,
        cleanupPending: last || row.cleanupPending,
        deletedAt: last ? now() : row.deletedAt,
      };
      if (!await config.catalog.cas(row.hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent parent change" });
      }
      if (last) {
        await bestEffortPurge(row.hash, "owner_delete", true);
      }
      return jsonResp(202, { status: last ? "cleanup_pending" : "reference_removed" });
    }

    // GDPR Vanish: DELETE /vanish
    if (path === "/vanish" && method === "DELETE") {
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      let owner: string;
      try {
        owner = requireNostrAuth(req, "vanish", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid vanish authorization" });
      }
      const page = await config.catalog.list(owner, 100);
      let erased = 0;
      let unlinked = 0;
      for (const row of page.items) {
        const owners = row.owners.filter((k) => k !== owner);
        const last = owners.length === 0;
        const next: BlobRecord = {
          ...row,
          owners,
          revision: row.revision + 1,
          status: last ? "deleted" : row.status,
          cleanupPending: last || row.cleanupPending,
          deletedAt: last ? now() : row.deletedAt,
        };
        if (await config.catalog.cas(row.hash, row.revision, next)) {
          if (last) {
            erased++;
            await bestEffortPurge(row.hash, "user_vanish", true);
          } else {
            unlinked++;
          }
        }
      }
      return jsonResp(202, {
        pubkey: owner,
        erased,
        unlinked,
        remaining: page.nextCursor !== null,
      });
    }

    // BUD-09: PUT /report
    if (path === "/report" && method === "PUT") {
      const event = await readJson<{ kind?: number; id?: string }>(req, 32 * 1024);
      if (event.kind !== 1984) {
        return jsonResp(400, { error: "NIP-56 kind 1984 report event required" });
      }
      if (config.upstreams?.moderationApiUrl) {
        const modHeaders: Record<string, string> = { "content-type": "application/json" };
        if (config.upstreams.moderationApiToken) {
          modHeaders["authorization"] = `Bearer ${config.upstreams.moderationApiToken}`;
        }
        await fetcher(`${config.upstreams.moderationApiUrl.replace(/\/+$/, "")}/report`, {
          method: "POST",
          headers: modHeaders,
          body: JSON.stringify(event),
          signal: AbortSignal.timeout(10_000),
        }).then((r) => r.body?.cancel()).catch(() => {});
      }
      return jsonResp(200, { reported: true, event_id: event.id ?? null });
    }

    // BUD-04: PUT /mirror
    if (path === "/mirror" && method === "PUT") {
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      let owner: string;
      try {
        owner = requireNostrAuth(req, "mirror", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid mirror authorization" });
      }
      const body = await readJson<{ url?: string }>(req, 8 * 1024);
      if (!body.url || !body.url.startsWith("https://")) {
        return jsonResp(400, { error: "HTTPS mirror url required" });
      }
      const remote = await fetcher(body.url, {
        redirect: "error",
        signal: AbortSignal.timeout(20_000),
      });
      if (!remote.ok) {
        await remote.body?.cancel();
        return jsonResp(502, { error: "mirror source unavailable" });
      }
      const bytes = await boundedBody(
        new Request(body.url, { method: "POST", body: remote.body, headers: remote.headers }),
        maxDirectUpload,
      );
      const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
      const existing = await config.catalog.get(hash);
      if (existing?.held || existing?.status === "banned") {
        return jsonResp(403, { error: "content blocked" });
      }
      if (!existing) {
        const mime = remote.headers.get("content-type") ?? "application/octet-stream";
        await config.blobs.write(hash, bytes, mime);
        const rec: BlobRecord = {
          revision: 1,
          hash,
          size: bytes.length,
          type: mime,
          uploaded: now(),
          owners: [owner],
          status: "pending",
          ageRestricted: false,
          held: false,
          gate: null,
          cleanupPending: false,
        };
        await config.catalog.cas(hash, null, rec);
        return jsonResp(200, buildDescriptor(rec, origin));
      }
      return jsonResp(200, buildDescriptor(existing, origin));
    }

    // Webhook: POST /admin/transcode-status
    if (path === "/admin/transcode-status" && method === "POST") {
      if (!isTranscodeWebhook(req, config.secrets)) {
        return jsonResp(401, { error: "Webhook authentication required" });
      }
      const body = await readJson<{
        sha256?: string;
        status?: string;
        generation?: number;
        dim?: string;
        thumbnail?: string;
        error_code?: string;
        error_message?: string;
        terminal?: boolean;
      }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      if (!HASH.test(hash) || !body.status) return jsonResp(400, { error: "invalid payload" });
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "blob not found" });
      if (
        typeof row.transcodeGeneration === "number" &&
        typeof body.generation === "number" &&
        body.generation < row.transcodeGeneration
      ) {
        return jsonResp(200, { ignored: true, reason: "stale_generation" });
      }
      const next: BlobRecord = {
        ...row,
        revision: row.revision + 1,
        transcodeStatus: body.status.toLowerCase() as BlobRecord["transcodeStatus"],
        transcodeGeneration: body.generation ?? row.transcodeGeneration,
        dim: body.dim ?? row.dim,
        thumbnail: body.thumbnail ?? row.thumbnail,
        transcodeErrorCode: body.error_code ?? row.transcodeErrorCode,
        transcodeErrorMessage: body.error_message ?? row.transcodeErrorMessage,
        transcodeTerminal: body.terminal ?? row.transcodeTerminal,
        transcodeLastAttemptAt: new Date(now() * 1000).toISOString(),
      };
      if (!await config.catalog.cas(hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent update" });
      }
      return jsonResp(200, { success: true, sha256: hash, transcode_status: next.transcodeStatus });
    }

    // Webhook: POST /admin/transcript-status
    if (path === "/admin/transcript-status" && method === "POST") {
      if (!isTranscodeWebhook(req, config.secrets)) {
        return jsonResp(401, { error: "Webhook authentication required" });
      }
      const body = await readJson<{
        sha256?: string;
        status?: string;
        generation?: number;
        error_code?: string;
        error_message?: string;
        terminal?: boolean;
      }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      if (!HASH.test(hash) || !body.status) return jsonResp(400, { error: "invalid payload" });
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "blob not found" });
      if (
        typeof row.transcriptGeneration === "number" &&
        typeof body.generation === "number" &&
        body.generation < row.transcriptGeneration
      ) {
        return jsonResp(200, { ignored: true, reason: "stale_generation" });
      }
      const next: BlobRecord = {
        ...row,
        revision: row.revision + 1,
        transcriptStatus: body.status.toLowerCase() as BlobRecord["transcriptStatus"],
        transcriptGeneration: body.generation ?? row.transcriptGeneration,
        transcriptErrorCode: body.error_code ?? row.transcriptErrorCode,
        transcriptErrorMessage: body.error_message ?? row.transcriptErrorMessage,
        transcriptTerminal: body.terminal ?? row.transcriptTerminal,
        transcriptLastAttemptAt: new Date(now() * 1000).toISOString(),
      };
      if (!await config.catalog.cas(hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent update" });
      }
      return jsonResp(200, {
        success: true,
        sha256: hash,
        transcript_status: next.transcriptStatus,
      });
    }

    // Internal archive import: /internal/archive/v1/*
    if (path.startsWith("/internal/archive/v1/")) {
      if (!isArchiveImportAuthorized(req, config.secrets)) {
        return jsonResp(401, { error: "Archive import authorization required" });
      }
      if (method === "POST") {
        const body = await readJson<{
          sha256?: string;
          size?: number;
          type?: string;
          owner?: string;
          uploaded?: number;
          status?: string;
          archive_storage?: { bucket: string; file_id: string };
        }>(req);
        const hash = body.sha256?.toLowerCase() ?? "";
        const owner = body.owner?.toLowerCase() ?? "";
        if (!HASH.test(hash) || !HASH.test(owner) || !body.size || body.size <= 0) {
          return jsonResp(400, { error: "invalid archive registration" });
        }
        const existing = await config.catalog.get(hash);
        if (existing?.held || existing?.status === "banned") {
          return jsonResp(403, { error: "content blocked" });
        }
        const rec: BlobRecord = existing
          ? {
            ...existing,
            revision: existing.revision + 1,
            owners: [...new Set([...existing.owners, owner])],
            archiveStorage: body.archive_storage ?? existing.archiveStorage,
          }
          : {
            revision: 1,
            hash,
            size: body.size,
            type: body.type ?? "video/mp4",
            uploaded: body.uploaded ?? now(),
            owners: [owner],
            status: body.status ? normalizeStatus(body.status) : "active",
            ageRestricted: false,
            held: false,
            gate: null,
            cleanupPending: false,
            archiveStorage: body.archive_storage,
          };
        if (!await config.catalog.cas(hash, existing?.revision ?? null, rec)) {
          return jsonResp(409, { error: "concurrent update" });
        }
        return jsonResp(200, { registered: true, sha256: hash, revision: rec.revision });
      }
      return jsonResp(405, { error: "method not allowed" });
    }

    // Durable purge & B2 erasure outbox drain: POST /admin/api/b2-cdn-purge/drain
    if (path === "/admin/api/b2-cdn-purge/drain") {
      if (!isPurgeDrainAuthorized(req, config.secrets)) {
        return jsonResp(401, { error: "Purge drain authorization required" });
      }
      const maxParam = Number(url.searchParams.get("max") ?? "5");
      const limit = Number.isInteger(maxParam) && maxParam > 0 ? Math.min(maxParam, 25) : 5;
      const due = await config.catalog.listDuePurges(now(), limit);
      let completed = 0;
      let deferred = 0;
      for (const item of due) {
        try {
          if (item.deleteB2 && config.blobs.deletePrefix) {
            const res = await config.blobs.deletePrefix(item.hash);
            if (res.remaining) {
              await config.catalog.deferPurge(item.id, item.attempts + 1, now() + 5);
              deferred++;
              continue;
            }
          }
          if (config.purger) {
            await config.purger.purgeHash(item.hash);
          }
          await config.catalog.completePurge(item.id);
          // Clear cleanupPending marker if blob is still deleted
          const row = await config.catalog.get(item.hash);
          if (row && row.cleanupPending) {
            await config.catalog.cas(row.hash, row.revision, {
              ...row,
              revision: row.revision + 1,
              cleanupPending: false,
            });
          }
          completed++;
        } catch {
          const backoff = Math.min(300, 10 * Math.pow(2, Math.min(item.attempts, 5)));
          await config.catalog.deferPurge(item.id, item.attempts + 1, now() + backoff);
          deferred++;
        }
      }
      return jsonResp(200, { drained: due.length, completed, deferred });
    }

    // Admin & Moderation endpoints
    if (path === "/admin/moderate" || path === "/admin/api/moderate") {
      if (method !== "POST") return jsonResp(405, { error: "POST required" });
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const isWebhook = path === "/admin/moderate";
      const body = await readJson<{ sha256?: string; action?: string; reason?: string }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      if (!HASH.test(hash) || !body.action) {
        return jsonResp(400, { error: "Invalid sha256 or action" });
      }
      const mapped = mapModerationAction(body.action, isWebhook);
      if (!mapped) return jsonResp(400, { error: `Unknown action: ${body.action}` });
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "Blob not found" });

      const oldStatus = row.status;
      const newStatus: BlobStatus = mapped === "delete" ? "deleted" : mapped;
      const needsPurge = newStatus !== "active" && newStatus !== "pending";
      const next: BlobRecord = {
        ...row,
        revision: row.revision + 1,
        status: newStatus,
        ageRestricted: newStatus === "age_restricted",
        cleanupPending: mapped === "delete" ? true : row.cleanupPending,
        deleteReason: body.reason ?? row.deleteReason,
        deletedAt: mapped === "delete" ? now() : row.deletedAt,
      };
      if (!await config.catalog.cas(hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent update" });
      }
      if (needsPurge) {
        await bestEffortPurge(hash, `moderate_${newStatus}`, mapped === "delete");
      }
      return jsonResp(200, {
        success: true,
        sha256: hash,
        old_status: oldStatus,
        new_status: newStatus,
      });
    }

    if (path === "/admin/api/delete" && method === "POST") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const body = await readJson<{ sha256?: string; reason?: string; legal_hold?: boolean }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      if (!HASH.test(hash)) return jsonResp(400, { error: "Invalid sha256 format" });
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "Blob not found" });
      const next: BlobRecord = {
        ...row,
        revision: row.revision + 1,
        status: "deleted",
        held: Boolean(body.legal_hold) || row.held,
        deleteReason: body.reason ?? row.deleteReason,
        deletedAt: now(),
      };
      if (!await config.catalog.cas(hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent update" });
      }
      await bestEffortPurge(hash, "admin_soft_delete", false);
      return jsonResp(200, { success: true, sha256: hash, legal_hold: next.held });
    }

    if (path === "/admin/api/restore" && method === "POST") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const body = await readJson<{ sha256?: string; status?: string }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      if (!HASH.test(hash)) return jsonResp(400, { error: "Invalid sha256 format" });
      const target = normalizeStatus(body.status ?? "active");
      if (target === "deleted" || target === "banned") {
        return jsonResp(400, { error: "Invalid restore target status" });
      }
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "Blob not found" });
      const next: BlobRecord = {
        ...row,
        revision: row.revision + 1,
        status: target,
        ageRestricted: target === "age_restricted",
        held: false,
        deletedAt: undefined,
      };
      if (!await config.catalog.cas(hash, row.revision, next)) {
        return jsonResp(409, { error: "concurrent update" });
      }
      return jsonResp(200, { success: true, sha256: hash, status: target });
    }

    if (path === "/admin/api/quarantine" && method === "POST") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const body = await readJson<{ sha256?: string; hold_id?: string; action?: string }>(req);
      const hash = body.sha256?.toLowerCase() ?? "";
      const holdId = body.hold_id?.trim() ?? "";
      const action = (body.action ?? "add").toLowerCase();
      if (!HASH.test(hash) || !holdId || holdId.length > 128) {
        return jsonResp(400, { error: "Invalid quarantine parameters" });
      }
      if (action === "add") {
        await config.catalog.addQuarantineHold(hash, holdId, now());
        await bestEffortPurge(hash, "quarantine_add", false);
      } else if (action === "remove") {
        await config.catalog.removeQuarantineHold(hash, holdId);
      } else {
        return jsonResp(400, { error: "action must be add or remove" });
      }
      const holds = await config.catalog.getQuarantineHolds(hash);
      return jsonResp(200, { sha256: hash, holds });
    }

    if (path.startsWith("/admin/api/quarantine/") && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const hash = path.slice("/admin/api/quarantine/".length).toLowerCase();
      if (!HASH.test(hash)) return jsonResp(400, { error: "Invalid sha256" });
      const holds = await config.catalog.getQuarantineHolds(hash);
      return jsonResp(200, { sha256: hash, holds });
    }

    if (path === "/admin/api/bulk-approve" && method === "POST") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const body = await readJson<{ hashes?: string[] }>(req);
      const hashes = body.hashes ?? [];
      if (!Array.isArray(hashes) || hashes.length > 100) {
        return jsonResp(400, { error: "hashes array (<=100) required" });
      }
      let approved = 0;
      for (const raw of hashes) {
        const hash = String(raw).toLowerCase();
        if (!HASH.test(hash)) continue;
        const row = await config.catalog.get(hash);
        if (row && row.status === "pending" && !row.held) {
          if (
            await config.catalog.cas(hash, row.revision, {
              ...row,
              revision: row.revision + 1,
              status: "active",
            })
          ) {
            approved++;
          }
        }
      }
      return jsonResp(200, { approved });
    }

    if (path === "/admin/api/vanish" && method === "POST") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const body = await readJson<{ pubkey?: string }>(req);
      const pubkey = body.pubkey?.toLowerCase() ?? "";
      if (!HASH.test(pubkey)) return jsonResp(400, { error: "Invalid pubkey" });
      const page = await config.catalog.list(pubkey, 100);
      let erased = 0;
      for (const row of page.items) {
        const owners = row.owners.filter((k) => k !== pubkey);
        const last = owners.length === 0;
        if (
          await config.catalog.cas(row.hash, row.revision, {
            ...row,
            owners,
            revision: row.revision + 1,
            status: last ? "deleted" : row.status,
            cleanupPending: last || row.cleanupPending,
            deletedAt: last ? now() : row.deletedAt,
          })
        ) {
          if (last) {
            erased++;
            await bestEffortPurge(row.hash, "admin_vanish", true);
          }
        }
      }
      return jsonResp(202, { pubkey, erased, remaining: page.nextCursor !== null });
    }

    if (path === "/admin/api/stats" && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      return jsonResp(200, await config.catalog.stats());
    }

    if (path === "/admin/api/recent" && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") ?? "50")));
      const rows = await config.catalog.recent(limit);
      return jsonResp(200, { blobs: rows });
    }

    if (path === "/admin/api/users" && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") ?? "50")));
      return jsonResp(200, { users: await config.catalog.users(limit) });
    }

    if (path.startsWith("/admin/api/user/") && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const pubkey = path.slice("/admin/api/user/".length).toLowerCase();
      if (!HASH.test(pubkey)) return jsonResp(400, { error: "Invalid pubkey" });
      const cursor = url.searchParams.get("cursor");
      const page = await config.catalog.list(pubkey, 100, cursor);
      return jsonResp(200, { pubkey, blobs: page.items, next_cursor: page.nextCursor });
    }

    if (path.startsWith("/admin/api/blob/") && method === "GET") {
      if (!isAdminRequest(req, config.secrets)) {
        return jsonResp(401, { error: "Admin authentication required" });
      }
      const rest = path.slice("/admin/api/blob/".length);
      if (rest.endsWith("/content")) {
        const hash = rest.slice(0, -"/content".length).toLowerCase();
        if (!HASH.test(hash)) return jsonResp(400, { error: "Invalid sha256" });
        return await serveMedia(req, { hash, storageKey: hash, kind: "original" }, true);
      }
      const adminMedia = parseMediaRoute(`/${rest}`);
      if (adminMedia && adminMedia.kind !== "original") {
        return await serveMedia(req, adminMedia, true);
      }
      const hash = rest.toLowerCase();
      if (!HASH.test(hash)) return jsonResp(400, { error: "Invalid sha256" });
      const row = await config.catalog.get(hash);
      if (!row) return jsonResp(404, { error: "Blob not found" });
      const holds = await config.catalog.getQuarantineHolds(hash);
      return jsonResp(200, {
        sha256: row.hash,
        size: row.size,
        type: row.type,
        uploaded: new Date(row.uploaded * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        owner: row.owners[0] ?? null,
        owners: row.owners,
        status: row.status,
        held: row.held,
        quarantine_holds: holds,
        thumbnail: row.thumbnail ?? null,
        dim: row.dim ?? null,
        transcode_status: row.transcodeStatus ?? null,
        transcode_generation: row.transcodeGeneration ?? null,
        transcript_status: row.transcriptStatus ?? null,
        transcript_generation: row.transcriptGeneration ?? null,
        cleanup_pending: row.cleanupPending,
      });
    }

    // Public & Authenticated Media Retrieval (GET / HEAD)
    if (method === "GET" || method === "HEAD") {
      const media = parseMediaRoute(path);
      if (media) {
        if (url.search && media.kind !== "vtt") {
          return jsonResp(400, { error: "unsupported query" });
        }
        return await serveMedia(req, media, false);
      }
    }

    return jsonResp(404, { error: "Not found" });
  }

  return async (req: Request): Promise<Response> => {
    let result: Response;
    try {
      result = await route(req);
    } catch (error) {
      result = jsonResp(error instanceof RangeError ? 413 : 503, {
        error: error instanceof RangeError ? "payload too large" : "dependency unavailable",
      });
    }
    const headers = corsHeaders(result.headers);
    if (!headers.has("cache-control")) {
      headers.set("cache-control", "private, no-store");
    }
    return new Response(req.method.toUpperCase() === "HEAD" ? null : result.body, {
      status: result.status,
      headers,
    });
  };
}
