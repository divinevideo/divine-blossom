// Nostr (BUD-01/02/11 kind 24242 + NIP-98 kind 27235) and Bearer token authentication.
// Matches src/viewer_auth.rs and src/admin.rs semantics.

import { verifyEvent } from "nostr-tools/pure";
import type { AuthSecrets } from "./types.ts";

const MAX_AUTH_HEADER = 16 * 1024;
const NIP98_MAX_AGE_SECS = 60;

export type BlossomAction = "upload" | "delete" | "list" | "get" | "mirror" | "vanish" | "media";

export interface ParsedNostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length || ab.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) {
    diff |= ab[i] ^ bb[i];
  }
  return diff === 0;
}

export function extractBearer(req: Request): string | null {
  const raw = req.headers.get("authorization");
  if (!raw) return null;
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (/^bearer\s+/i.test(trimmed)) {
      const token = trimmed.replace(/^bearer\s+/i, "").trim();
      if (token.length > 0) return token;
    }
  }
  return null;
}

export function hasValidBearer(req: Request, allowedTokens: (string | undefined)[]): boolean {
  const provided = extractBearer(req);
  if (!provided) return false;
  for (const expected of allowedTokens) {
    const trimmed = expected?.trim();
    if (trimmed && timingSafeEqual(provided, trimmed)) {
      return true;
    }
  }
  return false;
}

export function isAdminRequest(req: Request, secrets?: AuthSecrets): boolean {
  return hasValidBearer(req, [secrets?.adminToken, secrets?.webhookSecret]);
}

export function isTranscodeWebhook(req: Request, secrets?: AuthSecrets): boolean {
  return hasValidBearer(req, [
    secrets?.transcoderWebhookSecret,
    secrets?.webhookSecret,
    secrets?.adminToken,
  ]);
}

export function isPurgeDrainAuthorized(req: Request, secrets?: AuthSecrets): boolean {
  return hasValidBearer(req, [
    secrets?.purgeDrainToken,
    secrets?.adminToken,
    secrets?.webhookSecret,
  ]);
}

export function isArchiveImportAuthorized(req: Request, secrets?: AuthSecrets): boolean {
  return hasValidBearer(req, [secrets?.archiveImportToken]);
}

function decodeNostrHeader(headerValue: string): ParsedNostrEvent | null {
  const trimmed = headerValue.trim();
  if (trimmed.length > MAX_AUTH_HEADER || !/^nostr\s+/i.test(trimmed)) return null;
  const b64 = trimmed.replace(/^nostr\s+/i, "").trim();
  try {
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const jsonText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const event = JSON.parse(jsonText) as ParsedNostrEvent;
    if (!event || typeof event !== "object" || !Array.isArray(event.tags)) return null;
    if (!verifyEvent(event)) return null;
    return event;
  } catch {
    return null;
  }
}

function tagValues(event: ParsedNostrEvent, key: string): string[] {
  return event.tags
    .filter((t) => Array.isArray(t) && t[0] === key && typeof t[1] === "string")
    .map((t) => t[1]);
}

function serverTagMatches(event: ParsedNostrEvent, reqHost: string): boolean {
  const servers = tagValues(event, "server");
  if (servers.length === 0) return true;
  const normalizedReq = reqHost.toLowerCase();
  return servers.every((s) => {
    const cleaned = s.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
    return cleaned === normalizedReq;
  });
}

function splitAuthorizationHeaders(req: Request): string[] {
  const raw = req.headers.get("authorization");
  if (!raw) return [];
  // Multiple Authorization headers joined by ", " per Fetch spec.
  // Nostr base64 payloads never contain commas, so splitting on comma is exact.
  return raw.split(",").map((s) => s.trim()).filter((s) => /^nostr\s+/i.test(s));
}

function validateEventForAction(
  event: ParsedNostrEvent,
  req: Request,
  action: BlossomAction,
  now: number,
  hash?: string,
  options?: { allowLegacyOptionalExpiry?: boolean; publicOrigin?: string },
): boolean {
  const reqUrl = new URL(req.url);
  const publicOrigin = options?.publicOrigin ?? reqUrl.origin;
  const expectedUrl = `${publicOrigin}${reqUrl.pathname}${reqUrl.search}`;
  const reqHost = new URL(publicOrigin).host;

  // NIP-98 (kind 27235) allowed for viewer GET/HEAD and list
  if (event.kind === 27235 && (action === "get" || action === "list")) {
    if (Math.abs(event.created_at - now) > NIP98_MAX_AGE_SECS) return false;
    const urls = tagValues(event, "u");
    const methods = tagValues(event, "method");
    if (urls.length !== 1 || methods.length !== 1) return false;
    const uTag = urls[0];
    if (uTag !== expectedUrl && uTag !== req.url) return false;
    const methodMatch = methods[0].toUpperCase() === req.method.toUpperCase() ||
      (req.method.toUpperCase() === "HEAD" && methods[0].toUpperCase() === "GET");
    return methodMatch;
  }

  // Blossom auth (kind 24242)
  if (event.kind !== 24242) return false;
  const actions = tagValues(event, "t");
  if (actions[0] !== action) return false;

  const expirations = tagValues(event, "expiration");
  if (expirations.length === 0) {
    if (!options?.allowLegacyOptionalExpiry) return false;
  } else {
    if (expirations.length !== 1 || !/^\d+$/.test(expirations[0])) return false;
    if (Number(expirations[0]) < now) return false;
  }

  if (hash) {
    const xTags = tagValues(event, "x").map((x) => x.toLowerCase());
    if (action === "get") {
      // For GET, x tag is optional on unscoped viewer tokens unless present; if present must match hash.
      if (xTags.length > 0 && !xTags.includes(hash.toLowerCase())) return false;
    } else if (!xTags.includes(hash.toLowerCase())) {
      return false;
    }
  }

  if (!serverTagMatches(event, reqHost)) return false;
  return true;
}

/**
 * Require a valid Nostr auth header for a management action (upload, delete, vanish, mirror, list, media).
 * Returns the authenticated lowercase hex pubkey or throws.
 */
export function requireNostrAuth(
  req: Request,
  action: BlossomAction,
  now: number,
  hash?: string,
  options?: { allowLegacyOptionalExpiry?: boolean; publicOrigin?: string },
): string {
  const candidates = splitAuthorizationHeaders(req);
  for (const candidate of candidates) {
    const event = decodeNostrHeader(candidate);
    if (event && validateEventForAction(event, req, action, now, hash, options)) {
      return event.pubkey.toLowerCase();
    }
  }
  throw new Error("unauthorized");
}

/**
 * Postel-compliant optional viewer auth: malformed or invalid headers degrade cleanly to null
 * so public media still serves while age-restricted / restricted media enforces policy.
 */
export function optionalViewerPubkey(
  req: Request,
  now: number,
  hash: string,
  publicOrigin?: string,
): string | null {
  try {
    return requireNostrAuth(req, "get", now, hash, {
      allowLegacyOptionalExpiry: true,
      publicOrigin,
    });
  } catch {
    return null;
  }
}
