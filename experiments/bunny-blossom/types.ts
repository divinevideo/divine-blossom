// Shared types and interfaces for the native Bunny Blossom edge runtime.
// Matches blossom-core/src/types.rs wire formats and access control semantics.

export type BlobStatus =
  | "active"
  | "restricted"
  | "pending"
  | "banned"
  | "deleted"
  | "age_restricted";

export type TranscodeStatus = "pending" | "processing" | "complete" | "failed";
export type TranscriptStatus = "pending" | "processing" | "complete" | "failed";

export type BlobAccess = "allowed" | "not_found" | "age_gated";

export interface ArchiveStorage {
  bucket: string;
  file_id: string;
}

export interface ModerationResult {
  checked_at: string;
  is_safe: boolean;
  scores?: {
    adult: string;
    violence: string;
    racy: string;
  };
}

export interface BlobRecord {
  revision: number;
  hash: string;
  size: number;
  type: string;
  uploaded: number;
  owners: string[];
  status: BlobStatus;
  ageRestricted: boolean;
  held: boolean;
  gate: string | null;
  cleanupPending: boolean;
  thumbnail?: string;
  dim?: string;
  c2paManifestId?: string;
  moderation?: ModerationResult;
  archiveStorage?: ArchiveStorage;
  videoEncodingAllowed?: boolean;
  transcodeStatus?: TranscodeStatus;
  transcodeGeneration?: number;
  transcodeErrorCode?: string;
  transcodeErrorMessage?: string;
  transcodeLastAttemptAt?: string;
  transcodeAttemptCount?: number;
  transcodeTerminal?: boolean;
  transcriptStatus?: TranscriptStatus;
  transcriptGeneration?: number;
  transcriptErrorCode?: string;
  transcriptErrorMessage?: string;
  transcriptLastAttemptAt?: string;
  transcriptAttemptCount?: number;
  transcriptTerminal?: boolean;
  deleteReason?: string;
  deletedAt?: number;
  ownerDeleted?: boolean;
}

export interface BlobDescriptor {
  url: string;
  sha256: string;
  size: number;
  type?: string;
  uploaded?: number;
  thumbnail?: string;
  hls?: string;
  dim?: string;
  vtt?: string;
}

export interface SubtitleJob {
  job_id: string;
  video_sha256: string;
  lang: string;
  status: "queued" | "processing" | "ready" | "failed";
  vtt_key?: string | null;
  error?: string | null;
  created_at: number;
  updated_at: number;
}

export interface PurgeItem {
  id: number;
  hash: string;
  reason: string;
  deleteB2: boolean;
  attempts: number;
  nextRetryAt: number;
  createdAt: number;
}

export interface ListPage {
  items: BlobRecord[];
  nextCursor: string | null;
}

export interface GlobalStats {
  total_blobs: number;
  total_bytes: number;
  by_status: Record<string, number>;
  cleanup_pending: number;
}

export interface UserSummary {
  pubkey: string;
  blob_count: number;
  latest_uploaded: number;
}

export interface ListOptions {
  /** Include owner-only `restricted` and quarantined rows (only for authenticated owner / admin / vanish). */
  includeRestricted?: boolean;
}

export interface CasOptions {
  requireUnquarantined?: boolean;
}

export interface Catalog {
  get(hash: string): Promise<BlobRecord | null>;
  cas(
    hash: string,
    expectedRevision: number | null,
    value: BlobRecord,
    options?: CasOptions,
  ): Promise<boolean>;
  list(
    owner: string,
    limit: number,
    cursor?: string | null,
    options?: ListOptions,
  ): Promise<ListPage>;
  recent(limit: number): Promise<BlobRecord[]>;
  stats(): Promise<GlobalStats>;
  users(limit: number): Promise<UserSummary[]>;
  getQuarantineHolds(hash: string): Promise<string[]>;
  addQuarantineHold(hash: string, holdId: string, now: number): Promise<void>;
  removeQuarantineHold(hash: string, holdId: string): Promise<void>;
  getSubtitleJob(jobId: string): Promise<SubtitleJob | null>;
  getSubtitleByHash(hash: string, lang?: string): Promise<SubtitleJob | null>;
  upsertSubtitleJob(job: SubtitleJob): Promise<void>;
  enqueuePurge(hash: string, reason: string, deleteB2: boolean, now: number): Promise<void>;
  listDuePurges(now: number, limit: number): Promise<PurgeItem[]>;
  completePurge(id: number): Promise<void>;
  deferPurge(id: number, attempts: number, nextRetryAt: number): Promise<void>;
}

export interface Blobs {
  read(key: string, request: Request): Promise<Response>;
  write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void>;
  deletePrefix?(
    prefix: string,
    stillDeletable?: () => Promise<boolean>,
  ): Promise<{ deleted: number; remaining: boolean }>;
}

export interface CdnPurger {
  purgeHash(hash: string): Promise<void>;
}

export interface UpstreamServices {
  uploadServiceUrl?: string;
  transcoderUrl?: string;
  moderationApiUrl?: string;
  moderationApiToken?: string;
  fallbackCdnHosts?: string[];
  fetcher?: typeof fetch;
}

export interface AuthSecrets {
  adminToken?: string;
  webhookSecret?: string;
  transcoderWebhookSecret?: string;
  archiveImportToken?: string;
  purgeDrainToken?: string;
}

export interface CacheConfig {
  /** Enable public CDN caching on unrestricted Active media responses. */
  publicMediaCaching?: boolean;
  /** Browser max-age in seconds for public immutable media (default 300). */
  browserMaxAgeSecs?: number;
  /** CDN edge s-maxage in seconds for public media (default 86400). */
  edgeMaxAgeSecs?: number;
}

export interface Config {
  origin: string;
  catalog: Catalog;
  blobs: Blobs;
  purger?: CdnPurger;
  upstreams?: UpstreamServices;
  secrets?: AuthSecrets;
  cache?: CacheConfig;
  now?: () => number;
  writesEnabled?: boolean;
  /** Optional fixture guard for isolated staging tests. Omit in production. */
  fixture?: { hash: string; owners: string[] };
  maxDirectUploadBytes?: number;
  maxUploadBytes?: number;
  /** Optional Bunny playback hostname returned by /api/bunny-playback/<parent>. */
  bunnyDeliveryHost?: string;
  /** Version banner returned by GET /version. */
  versionBanner?: string;
}

/**
 * Normalize legacy TitleCase status strings from earlier spike records into canonical lowercase.
 */
export function normalizeStatus(raw: string): BlobStatus {
  switch (raw.toLowerCase()) {
    case "active":
      return "active";
    case "restricted":
      return "restricted";
    case "pending":
      return "pending";
    case "banned":
      return "banned";
    case "deleted":
      return "deleted";
    case "age_restricted":
    case "agerestricted":
      return "age_restricted";
    default:
      throw new Error(`invalid blob status: ${raw}`);
  }
}

/**
 * Evaluate viewer access matching blossom-core BlobMetadata::access_for.
 */
export function evaluateAccess(
  record: BlobRecord,
  quarantineHolds: string[],
  viewerPubkey: string | null,
  isAdmin: boolean,
): BlobAccess {
  if (isAdmin) return "allowed";
  if (record.held || record.gate || quarantineHolds.length > 0) return "not_found";
  const isOwner = viewerPubkey !== null &&
    record.owners.some((owner) => owner.toLowerCase() === viewerPubkey.toLowerCase());

  if (record.status === "banned" || record.status === "deleted") {
    return "not_found";
  }
  if (record.status === "restricted") {
    return isOwner ? "allowed" : "not_found";
  }
  if (record.status === "age_restricted" || record.ageRestricted) {
    return viewerPubkey !== null ? "allowed" : "age_gated";
  }
  return "allowed";
}

const ORIGINAL_EXTENSIONS: ReadonlyMap<string, string> = new Map([
  ["video/mp4", "mp4"],
  ["video/quicktime", "mov"],
  ["video/webm", "webm"],
  ["audio/mpeg", "mp3"],
  ["audio/mp4", "m4a"],
  ["audio/wav", "wav"],
  ["audio/ogg", "ogg"],
  ["image/jpeg", "jpeg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
  ["image/gif", "gif"],
  ["application/pdf", "pdf"],
]);

export function buildDescriptor(record: BlobRecord, origin: string): BlobDescriptor {
  const mime = record.type.split(";", 1)[0].trim().toLowerCase();
  const extension = ORIGINAL_EXTENSIONS.get(mime) ?? "bin";
  const desc: BlobDescriptor = {
    url: `${origin}/${record.hash}.${extension}`,
    sha256: record.hash,
    size: record.size,
    type: record.type,
    uploaded: record.uploaded,
  };
  if (record.thumbnail) {
    desc.thumbnail = record.thumbnail.startsWith("http")
      ? record.thumbnail
      : `${origin}/${record.thumbnail.replace(/^\/+/, "")}`;
  }
  if (record.transcodeStatus === "complete") {
    desc.hls = `${origin}/${record.hash}/hls/master.m3u8`;
  }
  if (record.dim) {
    desc.dim = record.dim;
  }
  if (record.transcriptStatus === "complete") {
    desc.vtt = `${origin}/${record.hash}.vtt`;
  }
  return desc;
}
