// Production-capable storage, SQL catalog, B2 erasure, and Bunny CDN purge adapters.
// Uses standard Web APIs + @libsql/client/web + aws4fetch so it runs natively on Bunny Edge Scripting.

import { createClient } from "@libsql/client/web";
import { AwsClient } from "aws4fetch";
import {
  type BlobRecord,
  type Blobs,
  type CasOptions,
  type Catalog,
  type CdnPurger,
  type GlobalStats,
  type ListOptions,
  type ListPage,
  normalizeStatus,
  type PurgeItem,
  type SubtitleJob,
  type UserSummary,
} from "./types.ts";

const HASH = /^[0-9a-f]{64}$/;
const CANONICAL_KEY_RE =
  /^[0-9a-f]{64}(?:\/(?:720p\.mp4|480p\.mp4|1080p\.mp4|360p\.mp4|audio|audio\/analysis\.json|thumbnail|sound-analysis\.json|vtt\/(?:main|[a-z]{2}(?:-[a-z0-9]{2,8})?)\.vtt|hls\/(?:master\.m3u8|stream_(?:1080|720|480|360)p\.(?:m3u8|ts|mp4)|segment_\d+\.ts))|\.(?:vtt|[a-z]{2}(?:-[a-z0-9]{2,8})?\.vtt|audio\.m4a|jpg|jpeg|png|webp|mp4|webm|mov))?$/;

const SAFE_READ_HEADERS = [
  "content-type",
  "content-length",
  "content-range",
  "accept-ranges",
  "etag",
  "last-modified",
];

function decodeRecord(raw: unknown, expectedHash?: string): BlobRecord {
  if (typeof raw !== "string") throw new Error("corrupt metadata row");
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const hash = String(parsed.hash ?? parsed.sha256 ?? "").toLowerCase();
  if (!HASH.test(hash) || (expectedHash && hash !== expectedHash)) {
    throw new Error("corrupt metadata hash");
  }
  const revision = Number(parsed.revision);
  if (!Number.isInteger(revision) || revision < 1) throw new Error("corrupt revision");
  const size = Number(parsed.size);
  if (!Number.isInteger(size) || size < 0) throw new Error("corrupt size");
  const uploaded = Number(parsed.uploaded);
  if (!Number.isInteger(uploaded) || uploaded < 0) throw new Error("corrupt uploaded");
  const type = typeof parsed.type === "string" && parsed.type.length > 0
    ? parsed.type
    : "application/octet-stream";
  const rawOwners = Array.isArray(parsed.owners)
    ? parsed.owners
    : typeof parsed.owner === "string" && HASH.test(parsed.owner)
    ? [parsed.owner]
    : [];
  const owners: string[] = [];
  for (const o of rawOwners) {
    if (typeof o !== "string" || !HASH.test(o.toLowerCase())) {
      throw new Error("corrupt owner");
    }
    const lower = o.toLowerCase();
    if (!owners.includes(lower)) owners.push(lower);
  }
  const status = normalizeStatus(String(parsed.status ?? "pending"));
  const ageRestricted = Boolean(parsed.ageRestricted) || status === "age_restricted";
  const held = Boolean(parsed.held);
  const cleanupPending = Boolean(parsed.cleanupPending);
  const gate = parsed.gate === null || parsed.gate === undefined
    ? null
    : typeof parsed.gate === "string" && parsed.gate.length > 0
    ? parsed.gate
    : (() => {
      throw new Error("corrupt gate");
    })();

  return {
    revision,
    hash,
    size,
    type,
    uploaded,
    owners,
    status,
    ageRestricted,
    held,
    gate,
    cleanupPending,
    thumbnail: typeof parsed.thumbnail === "string" ? parsed.thumbnail : undefined,
    dim: typeof parsed.dim === "string" ? parsed.dim : undefined,
    c2paManifestId: typeof parsed.c2paManifestId === "string" ? parsed.c2paManifestId : undefined,
    moderation: parsed.moderation as BlobRecord["moderation"],
    archiveStorage: parsed.archiveStorage as BlobRecord["archiveStorage"],
    videoEncodingAllowed: typeof parsed.videoEncodingAllowed === "boolean"
      ? parsed.videoEncodingAllowed
      : undefined,
    transcodeStatus: parsed.transcodeStatus as BlobRecord["transcodeStatus"],
    transcodeGeneration: typeof parsed.transcodeGeneration === "number"
      ? parsed.transcodeGeneration
      : undefined,
    transcodeErrorCode: typeof parsed.transcodeErrorCode === "string"
      ? parsed.transcodeErrorCode
      : undefined,
    transcodeErrorMessage: typeof parsed.transcodeErrorMessage === "string"
      ? parsed.transcodeErrorMessage
      : undefined,
    transcodeLastAttemptAt: typeof parsed.transcodeLastAttemptAt === "string"
      ? parsed.transcodeLastAttemptAt
      : undefined,
    transcodeAttemptCount: typeof parsed.transcodeAttemptCount === "number"
      ? parsed.transcodeAttemptCount
      : undefined,
    transcodeTerminal: typeof parsed.transcodeTerminal === "boolean"
      ? parsed.transcodeTerminal
      : undefined,
    transcriptStatus: parsed.transcriptStatus as BlobRecord["transcriptStatus"],
    transcriptGeneration: typeof parsed.transcriptGeneration === "number"
      ? parsed.transcriptGeneration
      : undefined,
    transcriptErrorCode: typeof parsed.transcriptErrorCode === "string"
      ? parsed.transcriptErrorCode
      : undefined,
    transcriptErrorMessage: typeof parsed.transcriptErrorMessage === "string"
      ? parsed.transcriptErrorMessage
      : undefined,
    transcriptLastAttemptAt: typeof parsed.transcriptLastAttemptAt === "string"
      ? parsed.transcriptLastAttemptAt
      : undefined,
    transcriptAttemptCount: typeof parsed.transcriptAttemptCount === "number"
      ? parsed.transcriptAttemptCount
      : undefined,
    transcriptTerminal: typeof parsed.transcriptTerminal === "boolean"
      ? parsed.transcriptTerminal
      : undefined,
    deleteReason: typeof parsed.deleteReason === "string" ? parsed.deleteReason : undefined,
    deletedAt: typeof parsed.deletedAt === "number" ? parsed.deletedAt : undefined,
    ownerDeleted: parsed.ownerDeleted === true ? true : undefined,
  };
}

export interface SqlTransaction {
  execute(query: {
    sql: string;
    args: (string | number | null)[];
  }): Promise<{ rows: Record<string, unknown>[] }>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
  close?(): void;
}

export interface SqlExecutor {
  execute(query: {
    sql: string;
    args: (string | number | null)[];
  }): Promise<{ rows: Record<string, unknown>[] }>;
  transaction?(mode: "write" | "read"): Promise<SqlTransaction>;
}

/**
 * Primary SQL catalog compatible with Bunny Database, Turso/libSQL, or any libSQL-over-HTTPS primary.
 * Maintains an indexed `blob_owners` join table for O(log N) cursor-paginated listings.
 */
export class SqlCatalog implements Catalog {
  private readonly client: SqlExecutor;

  constructor(url: string, authToken: string, executor?: SqlExecutor) {
    if (!url.startsWith("https://") && !url.startsWith("libsql://")) {
      throw new Error("secure primary database endpoint required");
    }
    // @libsql/client/web requires https:// (not libsql://) in edge fetch runtimes.
    const httpUrl = url.startsWith("libsql://") ? `https://${url.slice("libsql://".length)}` : url;
    this.client = executor ?? (createClient({ url: httpUrl, authToken }) as unknown as SqlExecutor);
  }

  async get(hash: string): Promise<BlobRecord | null> {
    const result = await this.client.execute({
      sql: "SELECT body FROM blobs WHERE hash = ?",
      args: [hash.toLowerCase()],
    });
    return result.rows.length ? decodeRecord(result.rows[0].body, hash.toLowerCase()) : null;
  }

  async cas(
    hash: string,
    expected: number | null,
    row: BlobRecord,
    options?: CasOptions,
  ): Promise<boolean> {
    const normalizedHash = hash.toLowerCase();
    const encoded = JSON.stringify({ ...row, hash: normalizedHash });
    const decoded = decodeRecord(encoded, normalizedHash);
    if (decoded.revision !== (expected ?? 0) + 1) throw new Error("invalid revision");

    const primaryOwner = decoded.owners[0] ?? "";
    const quarantineGuard = options?.requireUnquarantined
      ? "AND NOT EXISTS (SELECT 1 FROM quarantine_holds WHERE hash = ?)"
      : "";
    const quarantineArgs = options?.requireUnquarantined ? [normalizedHash] : [];
    const casQuery = expected === null
      ? {
        sql: `INSERT INTO blobs(
            hash, revision, status, age_restricted, held, size, mime_type, uploaded, owner,
            transcode_status, transcode_generation, transcript_status, transcript_generation,
            gate, cleanup_pending, body
          ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          WHERE 1 = 1 ${quarantineGuard}
          ON CONFLICT(hash) DO NOTHING RETURNING revision`,
        args: [
          normalizedHash,
          decoded.revision,
          decoded.status,
          decoded.ageRestricted ? 1 : 0,
          decoded.held ? 1 : 0,
          decoded.size,
          decoded.type,
          decoded.uploaded,
          primaryOwner,
          decoded.transcodeStatus ?? null,
          decoded.transcodeGeneration ?? null,
          decoded.transcriptStatus ?? null,
          decoded.transcriptGeneration ?? null,
          decoded.gate,
          decoded.cleanupPending ? 1 : 0,
          encoded,
          ...quarantineArgs,
        ],
      }
      : {
        sql: `UPDATE blobs SET
            revision = ?, status = ?, age_restricted = ?, held = ?, size = ?, mime_type = ?,
            uploaded = ?, owner = ?, transcode_status = ?, transcode_generation = ?,
            transcript_status = ?, transcript_generation = ?, gate = ?, cleanup_pending = ?,
            body = ?
          WHERE hash = ? AND revision = ? ${quarantineGuard} RETURNING revision`,
        args: [
          decoded.revision,
          decoded.status,
          decoded.ageRestricted ? 1 : 0,
          decoded.held ? 1 : 0,
          decoded.size,
          decoded.type,
          decoded.uploaded,
          primaryOwner,
          decoded.transcodeStatus ?? null,
          decoded.transcodeGeneration ?? null,
          decoded.transcriptStatus ?? null,
          decoded.transcriptGeneration ?? null,
          decoded.gate,
          decoded.cleanupPending ? 1 : 0,
          encoded,
          normalizedHash,
          expected,
          ...quarantineArgs,
        ],
      };

    const runWithExecutor = async (
      exec: Pick<SqlExecutor, "execute">,
    ): Promise<boolean> => {
      const result = await exec.execute(casQuery);
      if (result.rows.length !== 1) return false;

      // Synchronize indexed owner join table inside the same write transaction.
      await exec.execute({
        sql: "DELETE FROM blob_owners WHERE hash = ?",
        args: [normalizedHash],
      });
      if (decoded.status !== "deleted" && !decoded.held && decoded.gate === null) {
        for (const owner of decoded.owners) {
          await exec.execute({
            sql: `INSERT OR REPLACE INTO blob_owners(owner, hash, uploaded) VALUES (?, ?, ?)`,
            args: [owner, normalizedHash, decoded.uploaded],
          });
        }
      }
      return true;
    };

    if (typeof this.client.transaction === "function") {
      const tx = await this.client.transaction("write");
      try {
        const applied = await runWithExecutor(tx);
        if (applied) {
          await tx.commit();
        } else {
          await tx.rollback();
        }
        return applied;
      } catch (err) {
        await tx.rollback().catch(() => {});
        throw err;
      } finally {
        tx.close?.();
      }
    }

    return await runWithExecutor(this.client);
  }

  async list(
    owner: string,
    limit: number,
    cursor?: string | null,
    options?: ListOptions,
  ): Promise<ListPage> {
    const bounded = Math.max(1, Math.min(limit, 100));
    const normalizedOwner = owner.toLowerCase();
    const visibilityClause = options?.includeRestricted
      ? `b.status NOT IN ('deleted', 'banned')
          AND b.held = 0
          AND b.gate IS NULL`
      : `b.status NOT IN ('deleted', 'banned', 'restricted')
          AND b.held = 0
          AND b.gate IS NULL
          AND NOT EXISTS (SELECT 1 FROM quarantine_holds q WHERE q.hash = b.hash)`;
    let sql: string;
    let args: (string | number | null)[];

    if (cursor) {
      const [tsStr, lastHash] = cursor.split(":");
      const ts = Number(tsStr);
      if (!Number.isInteger(ts) || !lastHash || !HASH.test(lastHash)) {
        throw new Error("invalid cursor");
      }
      sql = `SELECT b.body FROM blob_owners o
        INNER JOIN blobs b ON b.hash = o.hash
        WHERE o.owner = ?
          AND ${visibilityClause}
          AND (o.uploaded < ? OR (o.uploaded = ? AND o.hash > ?))
        ORDER BY o.uploaded DESC, o.hash ASC
        LIMIT ?`;
      args = [normalizedOwner, ts, ts, lastHash, bounded + 1];
    } else {
      sql = `SELECT b.body FROM blob_owners o
        INNER JOIN blobs b ON b.hash = o.hash
        WHERE o.owner = ?
          AND ${visibilityClause}
        ORDER BY o.uploaded DESC, o.hash ASC
        LIMIT ?`;
      args = [normalizedOwner, bounded + 1];
    }

    const result = await this.client.execute({ sql, args });
    const hasMore = result.rows.length > bounded;
    const sliced = hasMore ? result.rows.slice(0, bounded) : result.rows;
    const items = sliced.map((r) => decodeRecord(r.body));
    const last = items[items.length - 1];
    const nextCursor = hasMore && last ? `${last.uploaded}:${last.hash}` : null;
    return { items, nextCursor };
  }

  async recent(limit: number): Promise<BlobRecord[]> {
    const bounded = Math.max(1, Math.min(limit, 200));
    const result = await this.client.execute({
      sql: "SELECT body FROM blobs ORDER BY uploaded DESC, hash ASC LIMIT ?",
      args: [bounded],
    });
    return result.rows.map((r) => decodeRecord(r.body));
  }

  async stats(): Promise<GlobalStats> {
    const totals = await this.client.execute({
      sql: `SELECT COUNT(*) AS cnt, COALESCE(SUM(size), 0) AS bytes,
        COALESCE(SUM(CASE WHEN cleanup_pending = 1 THEN 1 ELSE 0 END), 0) AS cleanup
        FROM blobs`,
      args: [],
    });
    const byStatusRows = await this.client.execute({
      sql: "SELECT status, COUNT(*) AS cnt FROM blobs GROUP BY status",
      args: [],
    });
    const by_status: Record<string, number> = {};
    for (const row of byStatusRows.rows) {
      by_status[String(row.status)] = Number(row.cnt);
    }
    const t = totals.rows[0] ?? {};
    return {
      total_blobs: Number(t.cnt ?? 0),
      total_bytes: Number(t.bytes ?? 0),
      by_status,
      cleanup_pending: Number(t.cleanup ?? 0),
    };
  }

  async users(limit: number): Promise<UserSummary[]> {
    const bounded = Math.max(1, Math.min(limit, 200));
    const result = await this.client.execute({
      sql: `SELECT owner AS pubkey, COUNT(*) AS blob_count, MAX(uploaded) AS latest_uploaded
        FROM blob_owners
        GROUP BY owner
        ORDER BY blob_count DESC, latest_uploaded DESC
        LIMIT ?`,
      args: [bounded],
    });
    return result.rows.map((r) => ({
      pubkey: String(r.pubkey),
      blob_count: Number(r.blob_count),
      latest_uploaded: Number(r.latest_uploaded),
    }));
  }

  async getQuarantineHolds(hash: string): Promise<string[]> {
    const result = await this.client.execute({
      sql: "SELECT hold_id FROM quarantine_holds WHERE hash = ? ORDER BY hold_id ASC",
      args: [hash.toLowerCase()],
    });
    return result.rows.map((r) => String(r.hold_id));
  }

  async addQuarantineHold(hash: string, holdId: string, now: number): Promise<void> {
    await this.client.execute({
      sql: "INSERT OR IGNORE INTO quarantine_holds(hash, hold_id, created_at) VALUES (?, ?, ?)",
      args: [hash.toLowerCase(), holdId, now],
    });
  }

  async removeQuarantineHold(hash: string, holdId: string): Promise<void> {
    await this.client.execute({
      sql: "DELETE FROM quarantine_holds WHERE hash = ? AND hold_id = ?",
      args: [hash.toLowerCase(), holdId],
    });
  }

  async getSubtitleJob(jobId: string): Promise<SubtitleJob | null> {
    const result = await this.client.execute({
      sql: `SELECT job_id, video_sha256, lang, status, vtt_key, error, created_at, updated_at
        FROM subtitles WHERE job_id = ?`,
      args: [jobId],
    });
    if (!result.rows.length) return null;
    const r = result.rows[0];
    return {
      job_id: String(r.job_id),
      video_sha256: String(r.video_sha256),
      lang: String(r.lang),
      status: String(r.status) as SubtitleJob["status"],
      vtt_key: r.vtt_key === null ? null : String(r.vtt_key),
      error: r.error === null ? null : String(r.error),
      created_at: Number(r.created_at),
      updated_at: Number(r.updated_at),
    };
  }

  async getSubtitleByHash(hash: string, lang?: string): Promise<SubtitleJob | null> {
    const result = lang
      ? await this.client.execute({
        sql: `SELECT job_id, video_sha256, lang, status, vtt_key, error, created_at, updated_at
          FROM subtitles WHERE video_sha256 = ? AND lang = ? ORDER BY updated_at DESC LIMIT 1`,
        args: [hash.toLowerCase(), lang],
      })
      : await this.client.execute({
        sql: `SELECT job_id, video_sha256, lang, status, vtt_key, error, created_at, updated_at
          FROM subtitles WHERE video_sha256 = ? ORDER BY updated_at DESC LIMIT 1`,
        args: [hash.toLowerCase()],
      });
    if (!result.rows.length) return null;
    const r = result.rows[0];
    return {
      job_id: String(r.job_id),
      video_sha256: String(r.video_sha256),
      lang: String(r.lang),
      status: String(r.status) as SubtitleJob["status"],
      vtt_key: r.vtt_key === null ? null : String(r.vtt_key),
      error: r.error === null ? null : String(r.error),
      created_at: Number(r.created_at),
      updated_at: Number(r.updated_at),
    };
  }

  async upsertSubtitleJob(job: SubtitleJob): Promise<void> {
    await this.client.execute({
      sql:
        `INSERT INTO subtitles(job_id, video_sha256, lang, status, vtt_key, error, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id) DO UPDATE SET
          status = excluded.status,
          vtt_key = excluded.vtt_key,
          error = excluded.error,
          updated_at = excluded.updated_at`,
      args: [
        job.job_id,
        job.video_sha256.toLowerCase(),
        job.lang,
        job.status,
        job.vtt_key ?? null,
        job.error ?? null,
        job.created_at,
        job.updated_at,
      ],
    });
  }

  async enqueuePurge(hash: string, reason: string, deleteB2: boolean, now: number): Promise<void> {
    await this.client.execute({
      sql: `INSERT INTO purge_outbox(hash, reason, delete_b2, attempts, next_retry_at, created_at)
        VALUES (?, ?, ?, 0, ?, ?)`,
      args: [hash.toLowerCase(), reason, deleteB2 ? 1 : 0, now, now],
    });
  }

  async listDuePurges(now: number, limit: number): Promise<PurgeItem[]> {
    const bounded = Math.max(1, Math.min(limit, 50));
    const result = await this.client.execute({
      sql: `SELECT id, hash, reason, delete_b2, attempts, next_retry_at, created_at
        FROM purge_outbox WHERE next_retry_at <= ? ORDER BY id ASC LIMIT ?`,
      args: [now, bounded],
    });
    return result.rows.map((r) => ({
      id: Number(r.id),
      hash: String(r.hash),
      reason: String(r.reason),
      deleteB2: Boolean(r.delete_b2),
      attempts: Number(r.attempts),
      nextRetryAt: Number(r.next_retry_at),
      createdAt: Number(r.created_at),
    }));
  }

  async completePurge(id: number): Promise<void> {
    await this.client.execute({
      sql: "DELETE FROM purge_outbox WHERE id = ?",
      args: [id],
    });
  }

  async deferPurge(id: number, attempts: number, nextRetryAt: number): Promise<void> {
    await this.client.execute({
      sql: "UPDATE purge_outbox SET attempts = ?, next_retry_at = ? WHERE id = ?",
      args: [attempts, nextRetryAt, id],
    });
  }
}

export interface B2BlobsConfig {
  region: string;
  bucket: string;
  /** Empty string "" for canonical production bucket root, or isolated prefix ending in "/". */
  prefix: string;
  id: string;
  key: string;
  /** Optional bucket-scoped B2 Native API eraser key (listFiles + deleteFiles). */
  eraser?: { id: string; key: string; bucketId: string };
  /** Optional GCS HMAC fallback reader for unmigrated blobs. */
  gcsFallback?: { bucket: string; id: string; key: string };
  /** Allow root prefix "" (production mode). Defaults false unless explicitly enabled. */
  allowCanonicalRoot?: boolean;
}

/**
 * Private Backblaze B2 S3 SigV4 blob adapter with optional GCS fallback and B2 Native all-version erasure.
 */
export class B2Blobs implements Blobs {
  private readonly aws: AwsClient;
  private readonly gcsAws: AwsClient | null;
  private readonly endpoint: string;
  private readonly gcsEndpoint: string | null;
  private readonly prefix: string;
  private readonly eraser?: { id: string; key: string; bucketId: string };

  constructor(
    config: B2BlobsConfig,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (
      !/^(us-east|us-west|eu-central|ca-east)-\d{3}$/.test(config.region) ||
      !/^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$/.test(config.bucket)
    ) {
      throw new Error("valid B2 region and bucket required");
    }
    if (config.prefix === "") {
      if (!config.allowCanonicalRoot) {
        throw new Error("canonical root prefix requires allowCanonicalRoot=true");
      }
    } else if (
      !/^blossom-runtime-spike\/[0-9a-f-]{36}\/$/.test(config.prefix) &&
      !(config.allowCanonicalRoot && /^[a-z0-9][a-z0-9/_-]{0,120}\/$/.test(config.prefix))
    ) {
      throw new Error("invalid B2 object prefix");
    }
    this.prefix = config.prefix;
    this.endpoint = `https://s3.${config.region}.backblazeb2.com/${config.bucket}/${config.prefix}`;
    this.aws = new AwsClient({
      accessKeyId: config.id,
      secretAccessKey: config.key,
      service: "s3",
      region: config.region,
      retries: 0,
    });
    this.eraser = config.eraser;
    if (config.gcsFallback) {
      this.gcsEndpoint = `https://storage.googleapis.com/${config.gcsFallback.bucket}/`;
      this.gcsAws = new AwsClient({
        accessKeyId: config.gcsFallback.id,
        secretAccessKey: config.gcsFallback.key,
        service: "s3",
        region: "auto",
        retries: 0,
      });
    } else {
      this.gcsEndpoint = null;
      this.gcsAws = null;
    }
  }

  private validateKey(key: string): string {
    if (!CANONICAL_KEY_RE.test(key)) {
      throw new Error("invalid object key");
    }
    return key;
  }

  private async signedRead(
    aws: AwsClient,
    url: string,
    request: Request,
  ): Promise<Response> {
    const headers = new Headers();
    const range = request.headers.get("range");
    if (range) headers.set("range", range);
    const signed = await aws.sign(url, { method: request.method, headers });
    const result = await this.fetcher(signed, {
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (![200, 206, 403, 404, 416].includes(result.status)) {
      await result.body?.cancel();
      throw new Error(`storage unavailable (${result.status})`);
    }
    const safe = new Headers();
    for (const name of SAFE_READ_HEADERS) {
      const value = result.headers.get(name);
      if (value !== null) safe.set(name, value);
    }
    // B2 returns 403 when key lacks listFiles on a missing object; normalize to 404.
    const status = result.status === 403 ? 404 : result.status;
    if (status === 404 || status === 416) {
      await result.body?.cancel();
      safe.delete("content-length");
      safe.delete("content-type");
      safe.delete("etag");
      return new Response(null, { status, headers: safe });
    }
    return new Response(result.body, { status, headers: safe });
  }

  async read(key: string, request: Request): Promise<Response> {
    const valid = this.validateKey(key);
    const primary = await this.signedRead(this.aws, this.endpoint + valid, request);
    if (primary.status !== 404 || !this.gcsAws || !this.gcsEndpoint) {
      return primary;
    }
    return await this.signedRead(this.gcsAws, this.gcsEndpoint + valid, request);
  }

  async write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void> {
    const valid = this.validateKey(key);
    const signed = await this.aws.sign(this.endpoint + valid, {
      method: "PUT",
      body,
      headers: { "content-type": type, "cache-control": "private, no-store" },
    });
    const result = await this.fetcher(signed, {
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    await result.body?.cancel();
    if (!result.ok) throw new Error(`storage write not confirmed (${result.status})`);
  }

  /**
   * Enumerate and delete every B2 version under `<prefix><hash>` using B2 Native API.
   * Returns `{ deleted, remaining }` so the purge outbox can retry bounded batches.
   */
  async deletePrefix(
    hashPrefix: string,
    stillDeletable?: () => Promise<boolean>,
  ): Promise<{ deleted: number; remaining: boolean }> {
    if (!HASH.test(hashPrefix)) throw new Error("invalid erasure hash");
    if (!this.eraser) throw new Error("B2 eraser credentials not configured");

    const basic = btoa(`${this.eraser.id}:${this.eraser.key}`);
    const authRes = await this.fetcher(
      "https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
      {
        headers: { authorization: `Basic ${basic}` },
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!authRes.ok) {
      await authRes.body?.cancel();
      throw new Error(`b2_authorize_account failed (${authRes.status})`);
    }
    const authJson = await authRes.json() as {
      authorizationToken: string;
      apiInfo: { storageApi: { apiUrl: string } };
    };
    const apiUrl = authJson.apiInfo.storageApi.apiUrl;
    const authToken = authJson.authorizationToken;
    const fullPrefix = `${this.prefix}${hashPrefix}`;

    const listRes = await this.fetcher(`${apiUrl}/b2api/v4/b2_list_file_versions`, {
      method: "POST",
      headers: { authorization: authToken, "content-type": "application/json" },
      body: JSON.stringify({
        bucketId: this.eraser.bucketId,
        prefix: fullPrefix,
        maxFileCount: 100,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!listRes.ok) {
      await listRes.body?.cancel();
      throw new Error(`b2_list_file_versions failed (${listRes.status})`);
    }
    const listed = await listRes.json() as {
      files: { fileName: string; fileId: string }[];
      nextFileName: string | null;
    };

    const matching = (listed.files ?? []).filter(
      (f) =>
        f.fileName === fullPrefix || f.fileName.startsWith(`${fullPrefix}/`) ||
        f.fileName.startsWith(`${fullPrefix}.`),
    );

    // A concurrent drain may have finished cleanup and allowed a repost while we listed.
    // Revalidate after listing. The version IDs in this batch then cannot include a later repost.
    if (stillDeletable && !await stillDeletable()) return { deleted: 0, remaining: true };

    let deleted = 0;
    const batch = matching.slice(0, 20);
    for (const file of batch) {
      const delRes = await this.fetcher(`${apiUrl}/b2api/v4/b2_delete_file_version`, {
        method: "POST",
        headers: { authorization: authToken, "content-type": "application/json" },
        body: JSON.stringify({ fileName: file.fileName, fileId: file.fileId }),
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      await delRes.body?.cancel();
      if (!delRes.ok && delRes.status !== 404) {
        throw new Error(`b2_delete_file_version failed (${delRes.status})`);
      }
      deleted++;
    }

    const remaining = matching.length > batch.length || listed.nextFileName !== null;
    return { deleted, remaining };
  }
}

/**
 * Bunny CDN targeted URL/wildcard purge client.
 * Purges `/<hash>` and `/<hash>*` across every configured custom and vendor hostname.
 */
export class BunnyPurger implements CdnPurger {
  constructor(
    private readonly apiKey: string,
    private readonly hosts: string[],
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (!apiKey.trim()) throw new Error("Bunny API key required");
    if (!hosts.length) throw new Error("at least one purge host required");
  }

  async purgeHash(hash: string): Promise<void> {
    if (!HASH.test(hash)) throw new Error("invalid purge hash");
    for (const host of this.hosts) {
      for (const target of [`https://${host}/${hash}`, `https://${host}/${hash}*`]) {
        const url = `https://api.bunny.net/purge?url=${encodeURIComponent(target)}`;
        const res = await this.fetcher(url, {
          method: "POST",
          headers: { AccessKey: this.apiKey },
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        await res.body?.cancel();
        if (!res.ok) {
          throw new Error(`Bunny purge failed (${res.status}) for ${host}`);
        }
      }
    }
  }
}
