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
  requireNostrAuthEvent,
  verifySignedNostrEvent,
} from "./auth.ts";
import { LANDING_HTML } from "./landing.ts";
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
const DIVINE_UPLOAD_EXTENSION_RESUMABLE = "resumable-sessions";
const DEFAULT_MAX_DIRECT_UPLOAD = 16 * 1024 * 1024;
const DEFAULT_MAX_UPLOAD = 50 * 1024 * 1024 * 1024;

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

// Mobile treats 409 upload results as a successful deduplication.
function uploadUnavailable(error: string): Response {
  return jsonResp(503, { error }, { "retry-after": "5" });
}

function corsHeaders(existing?: Headers): Headers {
  const headers = new Headers(existing);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS");
  headers.set(
    "access-control-allow-headers",
    "Authorization, Content-Type, Range, X-Sha256, X-SHA-256, X-Request-Id, X-Content-Length, X-Content-Type, X-Divine-Video-Processing, X-ProofMode-Manifest, X-ProofMode-Signature, X-ProofMode-Pubkey, X-ProofMode-Attestation, X-C2PA-Manifest-Id",
  );
  headers.set(
    "access-control-expose-headers",
    "Content-Length, Content-Range, Accept-Ranges, X-Sha256, X-Content-Length, X-C2PA-Manifest-Id, X-Source-Sha256, X-Content-SHA256, X-Audio-Duration, X-Audio-Size, X-Divine-Upload-Extensions, X-Divine-Upload-Control-Host, X-Divine-Upload-Data-Host, X-Reason, X-Exists, Retry-After, Content-Language, X-Divine-Machine-Translated",
  );
  return headers;
}

function canReplaceOwnerDeletion(row: BlobRecord): boolean {
  return row.status === "deleted" && row.ownerDeleted === true && !row.cleanupPending;
}

function isUploadUnavailable(row: BlobRecord | null): boolean {
  return Boolean(row?.gate || (row?.status === "deleted" && !canReplaceOwnerDeletion(row)));
}

function isVideoMimeType(mime: string): boolean {
  return mime.trim().toLowerCase().startsWith("video/");
}

function isTranscribableMimeType(mime: string): boolean {
  const normalized = mime.trim().toLowerCase();
  return normalized.startsWith("video/") || normalized.startsWith("audio/");
}

function parseVideoEncodingRequested(req: Request): boolean | null {
  const raw = req.headers.get("x-divine-video-processing");
  if (raw === null) return true;
  if (raw === "copy-only") return false;
  return null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function allowsVideoEncoding(record: BlobRecord): boolean {
  return record.videoEncodingAllowed === true && !record.archiveStorage;
}

function limitStreamBytes(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  onExceeded: () => void,
): ReadableStream<Uint8Array> {
  let seen = 0;
  return stream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > maxBytes) {
          onExceeded();
          controller.error(new RangeError("body limit"));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
}

function normalizeThumbnailForOrigin(
  rawThumbnail: unknown,
  hash: string,
  origin: string,
): string | undefined {
  if (typeof rawThumbnail !== "string") return undefined;
  const trimmed = rawThumbnail.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed, origin);
    const lowerPath = parsed.pathname.toLowerCase();
    if (lowerPath === `/${hash}.jpg` || lowerPath === `/${hash}/thumbnail`) {
      return `${origin}${lowerPath}`;
    }
  } catch {
    // Fall through to trimmed value if not a parseable URL.
  }
  return trimmed;
}

function trustedUploadServiceTerminalError(
  errorCode: string | undefined,
  uploadServiceTerminal: boolean,
): boolean {
  return uploadServiceTerminal && errorCode === "unsupported_media_type";
}

function isValidRetryAfter(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/^\d+$/.test(trimmed)) return true;
  return !Number.isNaN(Date.parse(trimmed));
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

function assertSafeMirrorUrl(raw: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("invalid url");
  }
  if (parsed.protocol !== "https:") throw new Error("https required");
  if (parsed.username || parsed.password) throw new Error("credentials forbidden");
  if (parsed.port && parsed.port !== "443") throw new Error("non-standard port forbidden");
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  // Reject bare IPv4/IPv6 literals, localhost, single-label names, and internal suffixes.
  if (
    !host ||
    !host.includes(".") ||
    host.includes(":") ||
    host.startsWith("[") ||
    /^\d+(?:\.\d+){1,3}$/.test(host) ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".arpa")
  ) {
    throw new Error("disallowed mirror host");
  }
  return parsed;
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
    const isVideoThumbnail = media.kind === "thumbnail" ||
      (media.kind === "original" &&
        row.type.startsWith("video/") &&
        /^\/[0-9a-fA-F]{64}\.(jpg|jpeg)$/i.test(new URL(req.url).pathname));
    let targetKey = media.storageKey;
    if (isVideoThumbnail) {
      targetKey = `${media.hash}.jpg`;
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
    if (storageResp.status === 404 && isVideoThumbnail && config.upstreams?.uploadServiceUrl) {
      const thumbUrl = `${
        config.upstreams.uploadServiceUrl.replace(/\/+$/, "")
      }/thumbnail/${media.hash}`;
      const thumbRes = await fetcher(thumbUrl, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
      if (thumbRes.status === 200) {
        const thumbHeaders = new Headers({
          "content-type": "image/jpeg",
          "accept-ranges": "bytes",
        });
        const cl = thumbRes.headers.get("content-length");
        if (cl) thumbHeaders.set("content-length", cl);
        storageResp = new Response(req.method === "HEAD" ? null : thumbRes.body, {
          status: 200,
          headers: thumbHeaders,
        });
        if (req.method === "HEAD") {
          await thumbRes.body?.cancel().catch(() => {});
        }
      } else {
        await thumbRes.body?.cancel().catch(() => {});
        if (thumbRes.status === 422) {
          return jsonResp(422, { error: "Thumbnail cannot be generated for this video" });
        }
        if (thumbRes.status !== 404) {
          return jsonResp(503, { error: "Thumbnail generation unavailable" });
        }
      }
    } else if (storageResp.status === 404 && !isVideoThumbnail && targetKey !== media.storageKey) {
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

  function effectiveMaxUploadBytes(): number {
    return config.upstreams?.uploadServiceUrl ? maxUpload : maxDirectUpload;
  }

  function uploadCapabilityHeaders(): Record<string, string> {
    const out: Record<string, string> = {
      "x-content-length": String(effectiveMaxUploadBytes()),
      "x-divine-upload-control-host": originHost,
      "cache-control": "private, no-store",
      "surrogate-control": "no-store",
    };
    if (config.upstreams?.uploadServiceUrl) {
      out["x-divine-upload-extensions"] = DIVINE_UPLOAD_EXTENSION_RESUMABLE;
      out["x-divine-upload-data-host"] = new URL(config.upstreams.uploadServiceUrl).host;
    }
    return out;
  }

  async function checkUpload(hash: string, actorPubkey: string): Promise<{
    existing: BlobRecord | null;
    blocked: "forbidden" | "unavailable" | null;
  }> {
    const [existing, holds] = await Promise.all([
      config.catalog.get(hash),
      config.catalog.getQuarantineHolds(hash),
    ]);
    if (
      existing?.held ||
      existing?.status === "banned" ||
      holds.length > 0 ||
      (existing?.status === "restricted" &&
        (!actorPubkey || !existing.owners.includes(actorPubkey)))
    ) {
      return { existing, blocked: "forbidden" };
    }
    return { existing, blocked: isUploadUnavailable(existing) ? "unavailable" : null };
  }

  async function triggerModerationScan(hash: string, pubkey: string): Promise<void> {
    if (!config.upstreams?.moderationApiUrl || !config.upstreams.moderationApiToken) return;
    try {
      const res = await fetcher(
        `${config.upstreams.moderationApiUrl.replace(/\/+$/, "")}/api/v1/scan`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${config.upstreams.moderationApiToken.trim()}`,
          },
          body: JSON.stringify({ sha256: hash, source: "blossom", pubkey }),
          redirect: "error",
          signal: AbortSignal.timeout(5_000),
        },
      );
      await res.body?.cancel();
    } catch {
      // Moderation queuing is best-effort and must not fail uploads.
    }
  }

  async function forwardUpstream(
    upstreamBase: string,
    targetPath: string,
    req: Request,
    options?: {
      body?: BodyInit | null;
      extraHeaders?: Record<string, string>;
      timeoutMs?: number;
      maxBodyBytes?: number;
    },
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
    if (!headers.has("x-sha256")) {
      const hyphenatedSha = req.headers.get("x-sha-256");
      if (hyphenatedSha !== null) headers.set("x-sha256", hyphenatedSha);
    }
    for (const [key, val] of req.headers.entries()) {
      const lower = key.toLowerCase();
      if (lower.startsWith("x-proofmode-") || lower.startsWith("x-c2pa-")) {
        headers.set(key, val);
      }
    }
    headers.set("x-original-host", originHost);
    if (options?.extraHeaders) {
      for (const [k, v] of Object.entries(options.extraHeaders)) headers.set(k, v);
    }
    const hasBody = !["GET", "HEAD"].includes(req.method.toUpperCase());
    let body: BodyInit | undefined;
    let bodyLimitExceeded = false;
    if (options && "body" in options) {
      body = options.body ?? undefined;
      headers.delete("content-length");
    } else if (hasBody && req.body) {
      body = options?.maxBodyBytes !== undefined
        ? limitStreamBytes(req.body, options.maxBodyBytes, () => {
          bodyLimitExceeded = true;
        })
        : req.body;
    }
    try {
      return await fetcher(targetUrl, {
        method: req.method,
        headers,
        body,
        redirect: "error",
        signal: AbortSignal.timeout(options?.timeoutMs ?? 60_000),
      });
    } catch (error) {
      // Standard WHATWG/Deno fetch wraps stream errors as TypeError; preserve our explicit body-limit signal.
      if (bodyLimitExceeded) {
        throw new RangeError("body limit");
      }
      throw error;
    }
  }

  async function proxyUpstream(
    upstreamBase: string,
    targetPath: string,
    req: Request,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const res = await forwardUpstream(upstreamBase, targetPath, req, { extraHeaders });
    const outHeaders = new Headers(res.headers);
    outHeaders.set("cache-control", "private, no-store");
    return new Response(res.body, { status: res.status, headers: outHeaders });
  }

  async function mapUpstreamErrorResponse(
    res: Response,
    options?: { uploadResult?: boolean },
  ): Promise<Response> {
    const uploadConflict = options?.uploadResult && res.status === 409;
    const status = uploadConflict ? 503 : res.status >= 400 && res.status <= 599 ? res.status : 502;
    const extra: Record<string, string> = uploadConflict ? { "retry-after": "5" } : {};
    const retryAfter = res.headers.get("retry-after");
    if (retryAfter && (status === 503 || status === 429) && isValidRetryAfter(retryAfter)) {
      extra["retry-after"] = retryAfter.trim();
    }
    let message = status === 503
      ? "Upload service unavailable"
      : `Upload service error (${status})`;
    try {
      const rawBytes = await boundedBody(
        new Request("https://upstream.invalid/", { method: "POST", body: res.body }),
        16 * 1024,
      );
      const rawText = new TextDecoder("utf-8", { fatal: false }).decode(rawBytes).trim();
      if (rawText) {
        try {
          const parsed = JSON.parse(rawText) as { error?: unknown };
          if (typeof parsed.error === "string" && parsed.error.trim().length > 0) {
            message = parsed.error.trim().slice(0, 512);
          } else {
            message = rawText.slice(0, 512);
          }
        } catch {
          message = rawText.slice(0, 512);
        }
      }
    } catch {
      await res.body?.cancel().catch(() => {});
    }
    return jsonResp(status, { error: message }, extra);
  }

  interface DelegatedUploadPayload {
    expectedDeletionRevision?: number;
    sha256: string;
    size: number;
    contentType: string;
    thumbnailUrl?: string;
    dim?: string;
    derivativesEvaluated: boolean;
    transcodeErrorCode?: string;
    transcodeErrorMessage?: string;
    transcodeTerminal: boolean;
    transcriptErrorCode?: string;
    transcriptErrorMessage?: string;
    transcriptTerminal: boolean;
  }

  async function publishDelegatedUpload(
    owner: string,
    authHashes: string[],
    encodingRequested: boolean,
    upload: DelegatedUploadPayload,
    createdStatus: 200 | 201,
  ): Promise<Response> {
    const hash = upload.sha256.toLowerCase();
    if (!HASH.test(hash) || !Number.isInteger(upload.size) || upload.size < 0) {
      return jsonResp(502, { error: "Invalid upload service response" });
    }
    if (authHashes.length > 0 && !authHashes.includes(hash)) {
      return jsonResp(401, { error: "upload hash mismatch" });
    }
    const contentType = upload.contentType.trim() || "application/octet-stream";
    const isVideo = isVideoMimeType(contentType);
    const isTranscribable = isTranscribableMimeType(contentType);
    const ts = now();
    const failureRecordedAt = upload.transcodeErrorCode || upload.transcriptErrorCode
      ? new Date(ts * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
      : undefined;

    for (let attempt = 0; attempt < 3; attempt++) {
      const [existing, holds] = await Promise.all([
        config.catalog.get(hash),
        config.catalog.getQuarantineHolds(hash),
      ]);
      if (existing?.held || holds.length > 0) {
        return jsonResp(403, { error: "content blocked by legal hold or quarantine" });
      }
      if (existing?.status === "banned") {
        return jsonResp(403, { error: "content banned" });
      }
      if (existing?.status === "restricted" && !existing.owners.includes(owner)) {
        return jsonResp(403, { error: "content blocked" });
      }
      if (
        isUploadUnavailable(existing) ||
        (existing?.status === "deleted" && existing.revision !== upload.expectedDeletionRevision)
      ) {
        return uploadUnavailable("parent unavailable");
      }

      if (existing && existing.status !== "deleted") {
        const next: BlobRecord = {
          ...existing,
          revision: existing.revision + 1,
          owners: existing.owners.includes(owner) ? existing.owners : [...existing.owners, owner],
          thumbnail: existing.thumbnail ?? upload.thumbnailUrl,
          dim: existing.dim ?? upload.dim,
          videoEncodingAllowed: !encodingRequested ? false : existing.videoEncodingAllowed,
        };
        const existingIsVideo = isVideoMimeType(existing.type);
        const existingIsTranscribable = isTranscribableMimeType(existing.type);
        const canEncode = allowsVideoEncoding(next);

        if (
          upload.transcodeErrorCode &&
          existing.transcodeStatus !== "complete" &&
          existing.transcodeStatus !== "processing"
        ) {
          next.transcodeStatus = "failed";
          next.transcodeErrorCode = upload.transcodeErrorCode;
          next.transcodeErrorMessage = upload.transcodeErrorMessage;
          next.transcodeLastAttemptAt = failureRecordedAt;
          next.transcodeAttemptCount = Math.max(existing.transcodeAttemptCount ?? 0, 1);
          next.transcodeTerminal = Boolean(existing.transcodeTerminal || upload.transcodeTerminal);
        } else if (
          canEncode &&
          upload.derivativesEvaluated &&
          !upload.transcodeErrorCode &&
          existingIsVideo &&
          (existing.transcodeStatus === undefined || existing.transcodeStatus === "failed")
        ) {
          next.transcodeStatus = "pending";
          next.transcodeErrorCode = undefined;
          next.transcodeErrorMessage = undefined;
          next.transcodeLastAttemptAt = undefined;
          next.transcodeAttemptCount = 0;
          next.transcodeTerminal = false;
        }

        if (
          upload.transcriptErrorCode &&
          existing.transcriptStatus !== "complete" &&
          existing.transcriptStatus !== "processing"
        ) {
          next.transcriptStatus = "failed";
          next.transcriptErrorCode = upload.transcriptErrorCode;
          next.transcriptErrorMessage = upload.transcriptErrorMessage;
          next.transcriptLastAttemptAt = failureRecordedAt;
          next.transcriptAttemptCount = Math.max(existing.transcriptAttemptCount ?? 0, 1);
          next.transcriptTerminal = Boolean(
            existing.transcriptTerminal || upload.transcriptTerminal,
          );
        } else if (
          upload.derivativesEvaluated &&
          !upload.transcriptErrorCode &&
          existingIsTranscribable &&
          (existing.transcriptStatus === undefined || existing.transcriptStatus === "failed")
        ) {
          next.transcriptStatus = "pending";
          next.transcriptErrorCode = undefined;
          next.transcriptErrorMessage = undefined;
          next.transcriptLastAttemptAt = undefined;
          next.transcriptAttemptCount = 0;
          next.transcriptTerminal = false;
        }

        if (
          await config.catalog.cas(hash, existing.revision, next, { requireUnquarantined: true })
        ) {
          return jsonResp(200, buildDescriptor(next, origin));
        }
        continue;
      }

      const fresh: BlobRecord = {
        revision: (existing?.revision ?? 0) + 1,
        hash,
        size: upload.size,
        type: contentType,
        uploaded: ts,
        owners: [owner],
        status: "pending",
        ageRestricted: false,
        held: false,
        gate: null,
        cleanupPending: false,
        thumbnail: upload.thumbnailUrl,
        dim: upload.dim,
        videoEncodingAllowed: encodingRequested && isVideo,
        transcodeStatus: isVideo ? (upload.transcodeErrorCode ? "failed" : "pending") : undefined,
        transcodeErrorCode: upload.transcodeErrorCode,
        transcodeErrorMessage: upload.transcodeErrorMessage,
        transcodeLastAttemptAt: upload.transcodeErrorCode ? failureRecordedAt : undefined,
        transcodeAttemptCount: isVideo && upload.transcodeErrorCode ? 1 : 0,
        transcodeTerminal: upload.transcodeTerminal,
        transcriptStatus: isTranscribable
          ? (upload.transcriptErrorCode ? "failed" : "pending")
          : undefined,
        transcriptErrorCode: upload.transcriptErrorCode,
        transcriptErrorMessage: upload.transcriptErrorMessage,
        transcriptLastAttemptAt: upload.transcriptErrorCode ? failureRecordedAt : undefined,
        transcriptAttemptCount: isTranscribable && upload.transcriptErrorCode ? 1 : 0,
        transcriptTerminal: upload.transcriptTerminal,
      };
      if (
        await config.catalog.cas(hash, existing?.revision ?? null, fresh, {
          requireUnquarantined: true,
        })
      ) {
        if (isVideo) {
          await triggerModerationScan(hash, owner);
        }
        return jsonResp(createdStatus, buildDescriptor(fresh, origin));
      }
    }
    return uploadUnavailable("concurrent parent change");
  }

  async function handleDirectUpload(
    req: Request,
    encodingRequested: boolean,
    declaredSha: string | null,
  ): Promise<Response> {
    const body = await boundedBody(req, maxDirectUpload);
    if (body.length === 0) {
      return jsonResp(400, { error: "File cannot be empty" });
    }
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
    if (declaredSha && hash !== declaredSha) {
      return jsonResp(400, { error: "Declared X-Sha256 does not match uploaded content" });
    }
    if (fixture && hash !== fixture.hash) {
      return jsonResp(403, { error: "fixture digest required" });
    }
    let owner: string;
    try {
      owner = requireNostrAuth(req, "upload", now(), hash, { publicOrigin: origin });
    } catch {
      return jsonResp(401, { error: "upload hash mismatch" });
    }
    if (fixture && !fixture.owners.includes(owner)) {
      return jsonResp(403, { error: "fixture signer required" });
    }

    const [old, holds] = await Promise.all([
      config.catalog.get(hash),
      config.catalog.getQuarantineHolds(hash),
    ]);
    if (old?.held || holds.length > 0) {
      return jsonResp(403, { error: "content blocked by legal hold or quarantine" });
    }
    if (old?.status === "banned") {
      return jsonResp(403, { error: "content banned" });
    }
    if (old?.status === "restricted" && !old.owners.includes(owner)) {
      return jsonResp(403, { error: "content blocked" });
    }
    if (isUploadUnavailable(old)) {
      return uploadUnavailable("parent unavailable");
    }

    // Deduplicate existing live blobs without rewriting storage bytes.
    if (old && old.status !== "deleted") {
      const deduped: BlobRecord = {
        ...old,
        revision: old.revision + 1,
        owners: old.owners.includes(owner) ? old.owners : [...old.owners, owner],
        videoEncodingAllowed: !encodingRequested ? false : old.videoEncodingAllowed,
      };
      if (!await config.catalog.cas(hash, old.revision, deduped, { requireUnquarantined: true })) {
        return uploadUnavailable("concurrent parent change");
      }
      return jsonResp(200, buildDescriptor(deduped, origin));
    }

    const contentType = req.headers.get("content-type")?.trim() || "application/octet-stream";
    const isVideo = isVideoMimeType(contentType);
    const isTranscribable = isTranscribableMimeType(contentType);
    const gate = crypto.randomUUID();
    const row: BlobRecord = {
      revision: (old?.revision ?? 0) + 1,
      hash,
      size: body.length,
      type: contentType,
      uploaded: now(),
      owners: [],
      status: "pending",
      ageRestricted: false,
      held: false,
      gate,
      cleanupPending: false,
      videoEncodingAllowed: encodingRequested && isVideo,
      transcodeStatus: isVideo ? "pending" : undefined,
      transcriptStatus: isTranscribable ? "pending" : undefined,
    };

    if (
      !await config.catalog.cas(hash, old?.revision ?? null, row, { requireUnquarantined: true })
    ) {
      return uploadUnavailable("concurrent parent change");
    }

    // Any lost storage reply retains the gate — never silently cleared.
    await config.blobs.write(hash, body, row.type);

    const current = await config.catalog.get(hash);
    if (
      !current || current.revision !== row.revision || current.gate !== gate ||
      current.status === "deleted" || current.held
    ) {
      return uploadUnavailable("publication withdrawn");
    }

    const ready: BlobRecord = {
      ...current,
      revision: current.revision + 1,
      gate: null,
      owners: [...new Set([...current.owners, owner])],
    };
    if (!await config.catalog.cas(hash, current.revision, ready, { requireUnquarantined: true })) {
      return uploadUnavailable("publication changed");
    }
    if (isVideo) {
      await triggerModerationScan(hash, owner);
    }
    return jsonResp(201, buildDescriptor(ready, origin));
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
      if (!config.writesEnabled) {
        return new Response(null, { status: 503 });
      }
      const capHeaders = uploadCapabilityHeaders();
      const preSha = req.headers.get("x-sha-256") ?? req.headers.get("x-sha256");
      const preLenRaw = req.headers.get("x-content-length");
      const preType = req.headers.get("x-content-type");

      if (preSha !== null || preLenRaw !== null || preType !== null) {
        if (preSha !== null) {
          const normalizedSha = preSha.trim().toLowerCase();
          if (!HASH.test(normalizedSha)) {
            return new Response(null, {
              status: 400,
              headers: {
                ...capHeaders,
                "x-reason": "Invalid X-SHA-256 format (must be 64 hex characters)",
              },
            });
          }
          const [existing, holds] = await Promise.all([
            config.catalog.get(normalizedSha),
            config.catalog.getQuarantineHolds(normalizedSha),
          ]);
          if (existing?.held || existing?.status === "banned" || holds.length > 0) {
            return new Response(null, {
              status: 403,
              headers: {
                ...capHeaders,
                "x-reason": "This content has been removed and cannot be re-uploaded",
              },
            });
          }
          if (isUploadUnavailable(existing)) {
            return new Response(null, {
              status: 409,
              headers: { ...capHeaders, "x-reason": "Parent unavailable" },
            });
          }
          if (
            existing &&
            existing.status !== "deleted" &&
            existing.status !== "restricted"
          ) {
            return new Response(null, {
              status: 200,
              headers: {
                ...capHeaders,
                "x-reason": "Blob already exists",
                "x-exists": "true",
              },
            });
          }
        }
        if (preLenRaw !== null) {
          const trimmedLen = preLenRaw.trim();
          const parsedLen = /^\d+$/.test(trimmedLen) ? Number(trimmedLen) : NaN;
          const allowedMax = effectiveMaxUploadBytes();
          if (!Number.isSafeInteger(parsedLen) || parsedLen === 0) {
            return new Response(null, {
              status: 400,
              headers: {
                ...capHeaders,
                "x-reason": parsedLen === 0
                  ? "File cannot be empty"
                  : "Invalid X-Content-Length header",
              },
            });
          }
          if (parsedLen > allowedMax) {
            return new Response(null, {
              status: 413,
              headers: {
                ...capHeaders,
                "x-reason": `File too large. Maximum size is ${allowedMax} bytes`,
              },
            });
          }
        }
        return new Response(null, {
          status: 200,
          headers: {
            ...capHeaders,
            "x-reason": "Upload would be accepted",
          },
        });
      }

      return jsonResp(
        200,
        {
          max_size: effectiveMaxUploadBytes(),
          allowed_types: null,
          extensions: config.upstreams?.uploadServiceUrl ? [DIVINE_UPLOAD_EXTENSION_RESUMABLE] : [],
        },
        capHeaders,
      );
    }

    // BUD-02: PUT /upload
    if (path === "/upload" && method === "PUT") {
      if (url.search) return jsonResp(400, { error: "unsupported query" });
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      const encodingRequested = parseVideoEncodingRequested(req);
      if (encodingRequested === null) {
        return jsonResp(400, {
          error: "X-Divine-Video-Processing must be copy-only when supplied",
        });
      }
      let auth;
      try {
        auth = requireNostrAuthEvent(req, "upload", now(), fixture?.hash, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }

      const declaredShaHeader = req.headers.get("x-sha-256") ?? req.headers.get("x-sha256");
      let declaredSha: string | null = null;
      if (declaredShaHeader !== null) {
        const normalized = declaredShaHeader.trim().toLowerCase();
        if (!HASH.test(normalized)) {
          return jsonResp(400, {
            error: "Invalid X-SHA-256 format (must be 64 hex characters)",
          });
        }
        if (auth.hashes.length > 0 && !auth.hashes.includes(normalized)) {
          return jsonResp(401, { error: "upload hash mismatch" });
        }
        declaredSha = normalized;
      }

      // Pre-check legal hold / ban / quarantine / deleted status before streaming bytes upstream.
      const precheckHashes = new Set<string>();
      if (declaredSha) precheckHashes.add(declaredSha);
      for (const authHash of auth.hashes) {
        if (HASH.test(authHash)) precheckHashes.add(authHash);
      }
      const deletionRevisions = new Map<string, number>();
      for (const candidate of precheckHashes) {
        const { existing, blocked } = await checkUpload(candidate, auth.pubkey);
        if (blocked === "forbidden") {
          return jsonResp(403, { error: "content blocked" });
        }
        if (blocked === "unavailable") {
          return uploadUnavailable("parent unavailable");
        }
        if (existing?.status === "deleted") deletionRevisions.set(candidate, existing.revision);
      }

      // Delegate streaming uploads to Cloud Run upload service when configured (production mode),
      // then publish the verified upload into the Blossom catalog so reads/lists/moderation stay authoritative.
      if (config.upstreams?.uploadServiceUrl && !fixture) {
        const contentType = req.headers.get("content-type")?.trim() || "application/octet-stream";
        const contentLengthHeader = req.headers.get("content-length");
        let declaredContentLength: number | null = null;
        if (contentLengthHeader !== null) {
          const trimmedLen = contentLengthHeader.trim();
          const parsedLen = /^\d+$/.test(trimmedLen) ? Number(trimmedLen) : NaN;
          if (!Number.isSafeInteger(parsedLen) || parsedLen === 0) {
            return jsonResp(400, { error: "Invalid Content-Length header" });
          }
          if (parsedLen > maxUpload) {
            return jsonResp(413, { error: `File too large. Maximum size is ${maxUpload} bytes` });
          }
          declaredContentLength = parsedLen;
        }
        const extraHeaders: Record<string, string> = {
          authorization: auth.headerValue,
        };
        if (!encodingRequested) {
          extraHeaders["x-divine-video-processing"] = "copy-only";
        }
        let upstreamRes: Response;
        try {
          upstreamRes = await forwardUpstream(
            config.upstreams.uploadServiceUrl,
            "/upload",
            req,
            { extraHeaders, maxBodyBytes: maxUpload },
          );
        } catch (error) {
          if (error instanceof RangeError) {
            return jsonResp(413, { error: `File too large. Maximum size is ${maxUpload} bytes` });
          }
          throw error;
        }
        if (!upstreamRes.ok) {
          return await mapUpstreamErrorResponse(upstreamRes, { uploadResult: true });
        }
        let rawBody: unknown;
        try {
          rawBody = await readJson<unknown>(
            new Request("https://upstream.invalid/", { method: "POST", body: upstreamRes.body }),
            64 * 1024,
          );
        } catch {
          return jsonResp(502, { error: "Invalid Cloud Run upload response" });
        }
        if (!isPlainObject(rawBody)) {
          return jsonResp(502, { error: "Invalid Cloud Run upload response" });
        }
        const body = rawBody;
        const sha256 = typeof body.sha256 === "string" ? body.sha256.toLowerCase() : "";
        if (declaredSha && sha256 !== declaredSha) {
          return jsonResp(400, { error: "Declared X-Sha256 does not match uploaded content" });
        }
        if (body.size === 0) {
          return jsonResp(400, { error: "File cannot be empty" });
        }
        const size = typeof body.size === "number" && Number.isInteger(body.size) && body.size > 0
          ? body.size
          : declaredContentLength ?? -1;
        const resolvedType = typeof body.type === "string" && body.type.trim().length > 0
          ? body.type.trim()
          : contentType;
        const transcodeErrorCode = typeof body.transcode_error_code === "string"
          ? body.transcode_error_code
          : undefined;
        const transcriptErrorCode = typeof body.transcript_error_code === "string"
          ? body.transcript_error_code
          : undefined;
        return await publishDelegatedUpload(auth.pubkey, auth.hashes, encodingRequested, {
          sha256,
          expectedDeletionRevision: deletionRevisions.get(sha256),
          size,
          contentType: resolvedType,
          thumbnailUrl: normalizeThumbnailForOrigin(body.thumbnail_url, sha256, origin),
          dim: typeof body.dim === "string" ? body.dim : undefined,
          derivativesEvaluated: isVideoMimeType(resolvedType),
          transcodeErrorCode,
          transcodeErrorMessage: typeof body.transcode_error_message === "string"
            ? body.transcode_error_message
            : undefined,
          transcodeTerminal: trustedUploadServiceTerminalError(
            transcodeErrorCode,
            Boolean(body.transcode_terminal),
          ),
          transcriptErrorCode,
          transcriptErrorMessage: typeof body.transcript_error_message === "string"
            ? body.transcript_error_message
            : undefined,
          transcriptTerminal: trustedUploadServiceTerminalError(
            transcriptErrorCode,
            Boolean(body.transcript_terminal),
          ),
        }, 201);
      }
      return await handleDirectUpload(req, encodingRequested, declaredSha);
    }

    // Resumable upload control plane
    if (path === "/upload/init" && method === "POST") {
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "upload service not configured" });
      }
      const encodingRequested = parseVideoEncodingRequested(req);
      if (encodingRequested === null) {
        return jsonResp(400, {
          error: "X-Divine-Video-Processing must be copy-only when supplied",
        });
      }
      if (!encodingRequested) {
        return jsonResp(400, { error: "Copy-only uploads must use PUT /upload or PUT /mirror" });
      }
      let auth;
      try {
        auth = requireNostrAuthEvent(req, "upload", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }

      let rawBody: string;
      let initReq: Record<string, unknown>;
      try {
        const bytes = await boundedBody(req, 64 * 1024);
        rawBody = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (!rawBody.trim()) return jsonResp(400, { error: "Request body required" });
        const parsed = JSON.parse(rawBody);
        if (!isPlainObject(parsed)) return jsonResp(400, { error: "Invalid JSON" });
        initReq = parsed;
      } catch {
        return jsonResp(400, { error: "Invalid JSON" });
      }

      const hash = typeof initReq.sha256 === "string" ? initReq.sha256.trim().toLowerCase() : "";
      const size = initReq.size;
      const contentTypeRaw = initReq.contentType ?? initReq.content_type;
      const contentType = typeof contentTypeRaw === "string" ? contentTypeRaw.trim() : "";
      if (!HASH.test(hash)) {
        return jsonResp(400, { error: "sha256 must be a 64-character hexadecimal string" });
      }
      if (typeof size !== "number" || !Number.isInteger(size) || size <= 0) {
        return jsonResp(400, { error: "Upload size must be greater than zero" });
      }
      if (size > maxUpload) {
        return jsonResp(400, { error: `File too large. Maximum size is ${maxUpload} bytes` });
      }
      if (!contentType) {
        return jsonResp(400, { error: "Content type is required" });
      }
      if (auth.hashes.length > 0 && !auth.hashes.includes(hash)) {
        return jsonResp(401, { error: "Hash in auth event doesn't match init request" });
      }

      const capHeaders = uploadCapabilityHeaders();
      const [existing, holds] = await Promise.all([
        config.catalog.get(hash),
        config.catalog.getQuarantineHolds(hash),
      ]);
      if (
        existing?.held ||
        existing?.status === "banned" ||
        holds.length > 0 ||
        (existing?.status === "restricted" && !existing.owners.includes(auth.pubkey))
      ) {
        return jsonResp(403, {
          error: "This content has been removed and cannot be re-uploaded",
        });
      }
      if (existing?.status === "deleted" || existing?.gate) {
        const error = existing && canReplaceOwnerDeletion(existing)
          ? "Use PUT /upload to repost a deleted blob"
          : "parent unavailable";
        return jsonResp(409, { error }, capHeaders);
      }
      if (existing) {
        return jsonResp(
          409,
          { error: "Blob already exists", descriptor: buildDescriptor(existing, origin) },
          capHeaders,
        );
      }

      const upstreamRes = await forwardUpstream(
        config.upstreams.uploadServiceUrl,
        "/upload/init",
        req,
        {
          body: rawBody,
          extraHeaders: {
            authorization: auth.headerValue,
            "content-type": "application/json",
          },
        },
      );
      if (!upstreamRes.ok) {
        return await mapUpstreamErrorResponse(upstreamRes);
      }
      let initResp: unknown;
      try {
        initResp = await readJson<unknown>(
          new Request("https://upstream.invalid/", { method: "POST", body: upstreamRes.body }),
          64 * 1024,
        );
      } catch {
        return jsonResp(502, { error: "Invalid upload service init response" });
      }
      if (!isPlainObject(initResp)) {
        return jsonResp(502, { error: "Invalid upload service init response" });
      }
      return jsonResp(200, initResp, capHeaders);
    }

    if (path.startsWith("/upload/") && path.endsWith("/complete") && method === "POST") {
      if (!config.writesEnabled) return jsonResp(503, { error: "writes disabled" });
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "upload service not configured" });
      }
      const uploadId = path.slice("/upload/".length, -"/complete".length);
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(uploadId)) {
        return jsonResp(400, { error: "Invalid upload complete path" });
      }
      const encodingRequested = parseVideoEncodingRequested(req);
      if (encodingRequested === null) {
        return jsonResp(400, {
          error: "X-Divine-Video-Processing must be copy-only when supplied",
        });
      }
      let auth;
      try {
        auth = requireNostrAuthEvent(req, "upload", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid upload authorization" });
      }

      let rawBody = "";
      let expectedRequestHash: string | null = null;
      try {
        const bytes = await boundedBody(req, 64 * 1024);
        rawBody = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (rawBody.trim().length > 0) {
          const parsed = JSON.parse(rawBody);
          if (!isPlainObject(parsed)) {
            return jsonResp(400, { error: "Invalid JSON in completion request" });
          }
          if (parsed.sha256 !== undefined) {
            if (
              typeof parsed.sha256 !== "string" || !HASH.test(parsed.sha256.trim().toLowerCase())
            ) {
              return jsonResp(400, { error: "Invalid sha256 in completion request" });
            }
            expectedRequestHash = parsed.sha256.trim().toLowerCase();
          }
        }
      } catch {
        return jsonResp(400, { error: "Invalid JSON in completion request" });
      }

      if (
        expectedRequestHash && auth.hashes.length > 0 && !auth.hashes.includes(expectedRequestHash)
      ) {
        return jsonResp(401, { error: "Hash in auth event doesn't match completion request" });
      }

      // Pre-check legal hold / ban / quarantine / deleted status before finalizing upload in Cloud Run.
      const completePrecheckHashes = new Set<string>();
      if (expectedRequestHash) completePrecheckHashes.add(expectedRequestHash);
      for (const authHash of auth.hashes) {
        if (HASH.test(authHash)) completePrecheckHashes.add(authHash);
      }
      for (const candidate of completePrecheckHashes) {
        const { existing, blocked } = await checkUpload(candidate, auth.pubkey);
        if (blocked === "forbidden") {
          return jsonResp(403, { error: "content blocked" });
        }
        // Cloud Run may replay a finalized session without writing again.
        if (blocked === "unavailable" || existing?.status === "deleted") {
          return uploadUnavailable("parent unavailable");
        }
      }

      const extraHeaders: Record<string, string> = {
        authorization: auth.headerValue,
      };
      if (!encodingRequested) {
        extraHeaders["x-divine-video-processing"] = "copy-only";
      }
      if (rawBody.trim().length > 0) {
        extraHeaders["content-type"] = "application/json";
      }

      const upstreamRes = await forwardUpstream(
        config.upstreams.uploadServiceUrl,
        `/upload/${uploadId}/complete`,
        req,
        {
          body: rawBody.trim().length > 0 ? rawBody : null,
          extraHeaders,
        },
      );
      if (!upstreamRes.ok) {
        return await mapUpstreamErrorResponse(upstreamRes, { uploadResult: true });
      }

      let rawComplete: unknown;
      try {
        rawComplete = await readJson<unknown>(
          new Request("https://upstream.invalid/", { method: "POST", body: upstreamRes.body }),
          64 * 1024,
        );
      } catch {
        return jsonResp(502, { error: "Invalid upload service completion response" });
      }
      if (!isPlainObject(rawComplete)) {
        return jsonResp(502, { error: "Invalid upload service completion response" });
      }

      const completeHash = typeof rawComplete.sha256 === "string"
        ? rawComplete.sha256.trim().toLowerCase()
        : "";
      if (expectedRequestHash && completeHash !== expectedRequestHash) {
        return jsonResp(502, { error: "Completion response hash did not match requested hash" });
      }
      const rawContentType = rawComplete.contentType ?? rawComplete.content_type;
      const resolvedContentType =
        typeof rawContentType === "string" && rawContentType.trim().length > 0
          ? rawContentType.trim()
          : "application/octet-stream";
      const rawThumb = rawComplete.thumbnailUrl ?? rawComplete.thumbnail_url;
      const resolvedThumb = normalizeThumbnailForOrigin(rawThumb, completeHash, origin);

      return await publishDelegatedUpload(auth.pubkey, auth.hashes, encodingRequested, {
        sha256: completeHash,
        size: typeof rawComplete.size === "number" && Number.isInteger(rawComplete.size) &&
            rawComplete.size > 0
          ? rawComplete.size
          : -1,
        contentType: resolvedContentType,
        thumbnailUrl: resolvedThumb,
        dim: typeof rawComplete.dim === "string" ? rawComplete.dim : undefined,
        derivativesEvaluated: false,
        transcodeTerminal: false,
        transcriptTerminal: false,
      }, 200);
    }

    // Synchronous transcription proxy
    if (path === "/transcribe" && method === "POST") {
      if (!config.upstreams?.uploadServiceUrl) {
        return jsonResp(503, { error: "transcription upstream not configured" });
      }
      let auth;
      try {
        auth = requireNostrAuthEvent(req, "media", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid transcribe authorization" });
      }
      return await proxyUpstream(config.upstreams.uploadServiceUrl, "/transcribe", req, {
        authorization: auth.headerValue,
      });
    }

    // Subtitle jobs API
    if (path === "/v1/subtitles/jobs" && method === "POST") {
      const isAdmin = isAdminRequest(req, config.secrets);
      let callerPubkey: string | null = null;
      if (!isAdmin) {
        try {
          callerPubkey = requireNostrAuth(req, "media", now(), undefined, { publicOrigin: origin });
        } catch {
          try {
            callerPubkey = requireNostrAuth(req, "upload", now(), undefined, {
              publicOrigin: origin,
            });
          } catch {
            return jsonResp(401, { error: "subtitle job authorization required" });
          }
        }
      }
      const body = await readJson<{ video_sha256?: string; lang?: string; force?: boolean }>(req);
      const hash = body.video_sha256?.toLowerCase() ?? "";
      const lang = (body.lang ?? "en").toLowerCase();
      if (!HASH.test(hash) || !/^[a-z]{2}(?:-[a-z0-9]{2,8})?$/.test(lang)) {
        return jsonResp(400, { error: "invalid video_sha256 or lang" });
      }
      const blob = await config.catalog.get(hash);
      const holds = blob ? await config.catalog.getQuarantineHolds(hash) : [];
      if (
        !blob || blob.status === "deleted" || blob.status === "banned" || blob.held ||
        holds.length > 0
      ) {
        return jsonResp(404, { error: "video not found" });
      }
      if (!isAdmin && (!callerPubkey || !blob.owners.includes(callerPubkey))) {
        return jsonResp(403, { error: "owner or admin authorization required" });
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
      let isAuthenticatedOwner = false;
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
        isAuthenticatedOwner = true;
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
        page = await config.catalog.list(targetPubkey, limit, cursor, {
          includeRestricted: isAuthenticatedOwner,
        });
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
      const holds = await config.catalog.getQuarantineHolds(hash);
      if (row.held || holds.length > 0) {
        return jsonResp(403, { error: "content under legal hold or quarantine" });
      }

      const owners = row.owners.filter((k) => k !== owner);
      const last = owners.length === 0;
      const next: BlobRecord = {
        ...row,
        owners,
        revision: row.revision + 1,
        status: last ? "deleted" : row.status,
        cleanupPending: last || row.cleanupPending,
        deletedAt: last ? now() : row.deletedAt,
        ownerDeleted: last && !row.ageRestricted && !row.gate &&
            (row.status === "active" || row.status === "pending")
          ? true
          : undefined,
      };
      if (
        !await config.catalog.cas(row.hash, row.revision, next, {
          requireUnquarantined: true,
          purge: last ? { reason: "owner_delete", deleteB2: true, createdAt: now() } : undefined,
        })
      ) {
        return jsonResp(409, { error: "concurrent parent change" });
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
      const page = await config.catalog.list(owner, 100, null, { includeRestricted: true });
      let erased = 0;
      let unlinked = 0;
      let skippedHeld = 0;
      for (const row of page.items) {
        const holds = await config.catalog.getQuarantineHolds(row.hash);
        if (row.held || holds.length > 0) {
          skippedHeld++;
          continue;
        }
        const owners = row.owners.filter((k) => k !== owner);
        const last = owners.length === 0;
        const next: BlobRecord = {
          ...row,
          owners,
          revision: row.revision + 1,
          status: last ? "deleted" : row.status,
          cleanupPending: last || row.cleanupPending,
          deletedAt: last ? now() : row.deletedAt,
          ownerDeleted: undefined,
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
        skipped_held: skippedHeld,
        remaining: page.nextCursor !== null,
      });
    }

    // BUD-09: PUT /report
    if (path === "/report" && method === "PUT") {
      const event = await readJson<{ kind?: number; id?: string }>(req, 32 * 1024);
      if (event.kind !== 1984 || !verifySignedNostrEvent(event)) {
        return jsonResp(400, { error: "signed NIP-56 kind 1984 report event required" });
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
      const encodingRequested = parseVideoEncodingRequested(req);
      if (encodingRequested === null) {
        return jsonResp(400, {
          error: "X-Divine-Video-Processing must be copy-only when supplied",
        });
      }
      let owner: string;
      try {
        owner = requireNostrAuth(req, "mirror", now(), undefined, { publicOrigin: origin });
      } catch {
        return jsonResp(401, { error: "invalid mirror authorization" });
      }
      if (fixture && !fixture.owners.includes(owner)) {
        return jsonResp(403, { error: "fixture signer required" });
      }
      const body = await readJson<{ url?: string }>(req, 8 * 1024);
      let mirrorUrl: URL;
      try {
        mirrorUrl = assertSafeMirrorUrl(body.url ?? "");
      } catch {
        return jsonResp(400, { error: "public HTTPS mirror url required" });
      }
      const remote = await fetcher(mirrorUrl.toString(), {
        redirect: "error",
        signal: AbortSignal.timeout(20_000),
      });
      if (!remote.ok) {
        await remote.body?.cancel();
        return jsonResp(502, { error: "mirror source unavailable" });
      }
      const bytes = await boundedBody(
        new Request(mirrorUrl.toString(), {
          method: "POST",
          body: remote.body,
          headers: remote.headers,
        }),
        maxDirectUpload,
      );
      const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
      if (fixture && hash !== fixture.hash) {
        return jsonResp(403, { error: "fixture digest required" });
      }
      const [existing, existingHolds] = await Promise.all([
        config.catalog.get(hash),
        config.catalog.getQuarantineHolds(hash),
      ]);
      if (
        existing?.held || existing?.status === "banned" || existing?.status === "restricted" ||
        existingHolds.length > 0
      ) {
        return jsonResp(403, { error: "content blocked" });
      }
      if (existing?.status === "deleted" || existing?.gate) {
        return jsonResp(409, { error: "parent unavailable" });
      }
      if (!existing) {
        const mime = remote.headers.get("content-type")?.trim() || "application/octet-stream";
        const isVideo = isVideoMimeType(mime);
        const isTranscribable = isTranscribableMimeType(mime);
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
          videoEncodingAllowed: encodingRequested && isVideo,
          transcodeStatus: isVideo ? "pending" : undefined,
          transcriptStatus: isTranscribable ? "pending" : undefined,
        };
        if (!await config.catalog.cas(hash, null, rec, { requireUnquarantined: true })) {
          return jsonResp(409, { error: "concurrent parent change" });
        }
        return jsonResp(200, buildDescriptor(rec, origin));
      }
      const needsOwner = !existing.owners.includes(owner);
      const needsRestrict = !encodingRequested && existing.videoEncodingAllowed !== false;
      if (needsOwner || needsRestrict) {
        const updated: BlobRecord = {
          ...existing,
          revision: existing.revision + 1,
          owners: needsOwner ? [...existing.owners, owner] : existing.owners,
          videoEncodingAllowed: needsRestrict ? false : existing.videoEncodingAllowed,
        };
        if (
          !await config.catalog.cas(hash, existing.revision, updated, {
            requireUnquarantined: true,
          })
        ) {
          return jsonResp(409, { error: "concurrent parent change" });
        }
        return jsonResp(200, buildDescriptor(updated, origin));
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
      if (method !== "POST") return jsonResp(405, { error: "POST required" });
      if (!isPurgeDrainAuthorized(req, config.secrets)) {
        return jsonResp(401, { error: "Purge drain authorization required" });
      }
      const maxParam = Number(url.searchParams.get("max") ?? "5");
      const limit = Number.isInteger(maxParam) && maxParam > 0 ? Math.min(maxParam, 25) : 5;
      const due = await config.catalog.listDuePurges(now(), limit);
      let completed = 0;
      let deferred = 0;
      let skippedHeld = 0;
      for (const item of due) {
        try {
          const currentRow = await config.catalog.get(item.hash);
          const currentHolds = await config.catalog.getQuarantineHolds(item.hash);
          const waitingForHoldRelease = item.deleteB2 && currentRow?.status === "deleted" &&
            currentRow.cleanupPending && (currentRow.held || currentHolds.length > 0);
          const allowB2Delete = item.deleteB2 &&
            currentHolds.length === 0 &&
            (!currentRow ||
              (!currentRow.held && currentRow.status === "deleted" && currentRow.cleanupPending));
          if (item.deleteB2 && !allowB2Delete) {
            skippedHeld++;
          } else if (allowB2Delete) {
            if (!config.blobs.deletePrefix) throw new Error("blob erasure unavailable");
            const res = await config.blobs.deletePrefix(item.hash, async () => {
              const [latest, holds] = await Promise.all([
                config.catalog.get(item.hash),
                config.catalog.getQuarantineHolds(item.hash),
              ]);
              return (latest?.revision ?? null) === (currentRow?.revision ?? null) &&
                holds.length === 0;
            });
            if (res.remaining) {
              await config.catalog.deferPurge(item.id, item.attempts + 1, now() + 5);
              deferred++;
              continue;
            }
          }
          if (config.purger) {
            await config.purger.purgeHash(item.hash);
          }
          if (waitingForHoldRelease) {
            await config.catalog.deferPurge(item.id, item.attempts + 1, now() + 60);
            deferred++;
            continue;
          }
          if (allowB2Delete && currentRow) {
            if (
              !await config.catalog.cas(item.hash, currentRow.revision, {
                ...currentRow,
                revision: currentRow.revision + 1,
                cleanupPending: false,
              })
            ) {
              await config.catalog.deferPurge(item.id, item.attempts + 1, now() + 5);
              deferred++;
              continue;
            }
          }
          await config.catalog.completePurge(item.id);
          completed++;
        } catch {
          const backoff = Math.min(300, 10 * Math.pow(2, Math.min(item.attempts, 5)));
          await config.catalog.deferPurge(item.id, item.attempts + 1, now() + backoff);
          deferred++;
        }
      }
      return jsonResp(200, { drained: due.length, completed, deferred, skipped_held: skippedHeld });
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
        ownerDeleted: undefined,
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
        ownerDeleted: undefined,
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
        ownerDeleted: undefined,
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
      const page = await config.catalog.list(pubkey, 100, null, { includeRestricted: true });
      let erased = 0;
      let skippedHeld = 0;
      for (const row of page.items) {
        const holds = await config.catalog.getQuarantineHolds(row.hash);
        if (row.held || holds.length > 0) {
          skippedHeld++;
          continue;
        }
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
            ownerDeleted: undefined,
          })
        ) {
          if (last) {
            erased++;
            await bestEffortPurge(row.hash, "admin_vanish", true);
          }
        }
      }
      return jsonResp(202, {
        pubkey,
        erased,
        skipped_held: skippedHeld,
        remaining: page.nextCursor !== null,
      });
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
      const page = await config.catalog.list(pubkey, 100, cursor, { includeRestricted: true });
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
