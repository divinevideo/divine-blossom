import { createClient } from "@libsql/client/web";
import { AwsClient } from "aws4fetch";
import type { Blobs, Catalog, RecordState } from "./app.ts";

function decode(value: unknown, hash?: string): RecordState {
  if (typeof value !== "string") throw new Error("invalid metadata");
  const row = JSON.parse(value) as RecordState;
  if (
    !/^[0-9a-f]{64}$/.test(row.hash) || (hash && hash !== row.hash) ||
    !Number.isSafeInteger(row.revision) || row.revision < 1 ||
    !["Pending", "Active", "Restricted", "Deleted"].includes(row.status) ||
    typeof row.held !== "boolean" || typeof row.ageRestricted !== "boolean" ||
    typeof row.cleanupPending !== "boolean" ||
    !(row.gate === null || typeof row.gate === "string") ||
    !Array.isArray(row.owners) || row.owners.some((key) => !/^[0-9a-f]{64}$/.test(key)) ||
    !Number.isSafeInteger(row.size) || row.size < 0 || typeof row.type !== "string" ||
    !Number.isSafeInteger(row.uploaded)
  ) throw new Error("invalid metadata");
  return row;
}

// Supply the PRIMARY endpoint explicitly. Replica freshness is a production feasibility gate.
export class SqlCatalog implements Catalog {
  readonly client: {
    execute(statement: { sql: string; args: (string | number)[] }): Promise<{
      rows: Record<string, unknown>[];
    }>;
  };
  constructor(url: string, authToken: string, executor?: SqlCatalog["client"]) {
    if (!url.startsWith("https://") && !url.startsWith("libsql://")) {
      throw new Error("secure primary database endpoint required");
    }
    this.client = executor ?? createClient({ url, authToken });
  }
  async get(hash: string): Promise<RecordState | null> {
    const result = await this.client.execute({
      sql: "SELECT body FROM spike_blobs WHERE hash = ?",
      args: [hash],
    });
    return result.rows.length ? decode(result.rows[0].body, hash) : null;
  }
  async cas(hash: string, expected: number | null, row: RecordState): Promise<boolean> {
    decode(JSON.stringify(row), hash);
    if (row.revision !== (expected ?? 0) + 1) throw new Error("invalid revision");
    const result = await this.client.execute(
      expected === null
        ? {
          sql:
            "INSERT INTO spike_blobs(hash, revision, body) VALUES (?, ?, ?) ON CONFLICT(hash) DO NOTHING RETURNING revision",
          args: [hash, row.revision, JSON.stringify(row)],
        }
        : {
          sql:
            "UPDATE spike_blobs SET revision = ?, body = ? WHERE hash = ? AND revision = ? RETURNING revision",
          args: [row.revision, JSON.stringify(row), hash, expected],
        },
    );
    return result.rows.length === 1;
  }
  async list(owner: string, limit: number): Promise<RecordState[]> {
    const result = await this.client.execute({
      sql: `SELECT body FROM spike_blobs
        WHERE json_extract(body, '$.status') != 'Deleted'
        AND json_extract(body, '$.held') = 0
        AND json_extract(body, '$.gate') IS NULL
        AND EXISTS (SELECT 1 FROM json_each(json_extract(body, '$.owners')) WHERE value = ?)
        ORDER BY hash LIMIT ?`,
      args: [owner, Math.min(101, limit + 1)],
    });
    if (result.rows.length > limit) throw new Error("pagination not implemented");
    return result.rows.map((row) => decode(row.body));
  }
}

export class B2Blobs implements Blobs {
  private readonly aws: AwsClient;
  private readonly endpoint: string;
  constructor(
    config: { region: string; bucket: string; prefix: string; id: string; key: string },
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (
      !/^(us-east|us-west|eu-central|ca-east)-\d{3}$/.test(config.region) ||
      !/^[a-z0-9][a-z0-9-]{4,61}[a-z0-9]$/.test(config.bucket) ||
      !/^blossom-runtime-spike\/[0-9a-f-]{36}\/$/.test(config.prefix)
    ) throw new Error("dedicated fixture scope required");
    this.endpoint = `https://s3.${config.region}.backblazeb2.com/${config.bucket}/${config.prefix}`;
    this.aws = new AwsClient({
      accessKeyId: config.id,
      secretAccessKey: config.key,
      service: "s3",
      region: config.region,
      retries: 0,
    });
  }
  private url(key: string): string {
    if (
      !/^[0-9a-f]{64}(?:\/(?:720p\.mp4|480p\.mp4|hls\/(?:master\.m3u8|stream_(?:720|480)p\.(?:m3u8|ts|mp4))))?$/
        .test(key)
    ) {
      throw new Error("invalid object key");
    }
    return this.endpoint + key;
  }
  async read(key: string, request: Request): Promise<Response> {
    const headers = new Headers();
    const range = request.headers.get("range");
    if (range) headers.set("range", range);
    const signed = await this.aws.sign(this.url(key), { method: request.method, headers });
    const result = await this.fetcher(signed, {
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (![200, 206, 404, 416].includes(result.status)) {
      await result.body?.cancel();
      throw new Error("storage unavailable");
    }
    const safe = new Headers();
    for (
      const name of ["content-type", "content-length", "content-range", "accept-ranges", "etag"]
    ) {
      const value = result.headers.get(name);
      if (value !== null) safe.set(name, value);
    }
    return new Response(result.body, { status: result.status, headers: safe });
  }
  async write(key: string, body: Uint8Array<ArrayBuffer>, type: string): Promise<void> {
    const signed = await this.aws.sign(this.url(key), {
      method: "PUT",
      body,
      headers: { "content-type": type, "cache-control": "private, no-store" },
    });
    const result = await this.fetcher(signed, {
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    await result.body?.cancel();
    if (!result.ok) throw new Error("storage write not confirmed");
  }
}
