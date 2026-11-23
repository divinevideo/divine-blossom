import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { type Blobs, type Catalog, createApp, hex, type RecordState } from "./app.ts";

function equal(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}
const ORIGIN = "https://bunny-spike.invalid";
const NOW = 1_800_000_000;
// Synthetic, fixed test signers. Never use these keys for real uploads.
const KEY = new Uint8Array(32).fill(1);
const OTHER = new Uint8Array(32).fill(2);
const OWNER = getPublicKey(KEY);
const BODY = new TextEncoder().encode("owned synthetic runtime fixture");
const HASH = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", BODY)));

function signed(action: string, hash = HASH, key = KEY, extra: string[][] = []) {
  const event = finalizeEvent({
    kind: 24242,
    created_at: NOW,
    content: "",
    tags: [
      ["t", action],
      ["x", hash],
      ["expiration", String(NOW + 60)],
      ...extra,
    ],
  }, key);
  return `Nostr ${btoa(JSON.stringify(event))}`;
}

class MemoryCatalog implements Catalog {
  rows = new Map<string, RecordState>();
  reads = 0;
  failReads = false;
  get(hash: string) {
    this.reads++;
    if (this.failReads) throw new Error("fixture database outage");
    return Promise.resolve(structuredClone(this.rows.get(hash) ?? null));
  }
  cas(hash: string, expected: number | null, value: RecordState) {
    if ((this.rows.get(hash)?.revision ?? null) !== expected) return Promise.resolve(false);
    this.rows.set(hash, structuredClone(value));
    return Promise.resolve(true);
  }
  list(owner: string, limit: number) {
    return Promise.resolve(
      [...this.rows.values()].filter((r) =>
        r.owners.includes(owner) && r.status !== "Deleted" && !r.held && !r.gate
      ).slice(0, limit),
    );
  }
}

class MemoryBlobs implements Blobs {
  rows = new Map<string, Uint8Array<ArrayBuffer>>();
  reads = 0;
  writes = 0;
  readHook?: () => Promise<void>;
  writeHook?: () => Promise<void>;
  failWrite = false;
  lastKey?: string;
  async read(key: string, req: Request) {
    this.reads++;
    this.lastKey = key;
    await this.readHook?.();
    const body = this.rows.get(key);
    if (!body) return new Response(null, { status: 404 });
    const headers = { "content-type": "video/mp4", "content-length": String(body.length) };
    return new Response(req.method === "HEAD" ? null : body, { headers });
  }
  async write(key: string, body: Uint8Array<ArrayBuffer>) {
    this.writes++;
    await this.writeHook?.();
    if (this.failWrite) throw new Error("lost acknowledgement");
    this.rows.set(key, body);
  }
}

function fixture() {
  const catalog = new MemoryCatalog();
  const blobs = new MemoryBlobs();
  const app = createApp({
    origin: ORIGIN,
    catalog,
    blobs,
    now: () => NOW,
    writesEnabled: true,
    fixture: { hash: HASH, owners: [OWNER, getPublicKey(OTHER)] },
    maxUploadBytes: 4096,
  });
  const request = (path: string, method = "GET", authorization?: string, body?: BodyInit) =>
    new Request(ORIGIN + path, {
      method,
      body,
      headers: authorization ? { authorization, "content-type": "video/mp4" } : {},
    });
  const upload = (key = KEY) => app(request("/upload", "PUT", signed("upload", HASH, key), BODY));
  return { catalog, blobs, app, request, upload };
}

Deno.test("signed upload, anonymous Pending read, owner list and tombstone complete without Fastly", async () => {
  const f = fixture();
  const uploaded = await f.upload();
  equal(uploaded.status, 200);
  equal((await uploaded.json()).url, `${ORIGIN}/${HASH}`);
  const read = await f.app(f.request(`/${HASH}`));
  equal(read.status, 200);
  equal(await read.text(), new TextDecoder().decode(BODY));
  equal(read.headers.get("cache-control"), "private, no-store");
  const list = await f.app(f.request(`/list/${OWNER}`, "GET", signed("list")));
  equal((await list.json()).length, 1);
  const deleted = await f.app(f.request(`/${HASH}`, "DELETE", signed("delete")));
  equal(deleted.status, 202);
  equal((await deleted.json()).status, "cleanup_pending");
  equal((await f.app(f.request(`/${HASH}`))).status, 404);
  equal(f.blobs.rows.has(HASH), true); // Explicitly not physical-erasure completion.
});

Deno.test("HEAD has no body and original extension alias resolves canonical object", async () => {
  const f = fixture();
  await f.upload();
  const head = await f.app(f.request(`/${HASH}.mp4`, "HEAD"));
  equal(head.status, 200);
  equal(await head.text(), "");
  equal(f.blobs.lastKey, HASH);
});

Deno.test("HLS master, both variants and segments share fresh parent policy", async () => {
  const f = fixture();
  await f.upload();
  const names = [
    "master.m3u8",
    "stream_720p.m3u8",
    "stream_480p.m3u8",
    "stream_720p.ts",
    "stream_480p.ts",
  ];
  for (const name of names) {
    f.blobs.rows.set(`${HASH}/hls/${name}`, new TextEncoder().encode("fixture"));
    equal((await f.app(f.request(`/${HASH}/hls/${name}`))).status, 200);
  }
  const row = (await f.catalog.get(HASH))!;
  await f.catalog.cas(HASH, row.revision, { ...row, held: true, revision: row.revision + 1 });
  const reads = f.blobs.reads;
  for (const name of names) equal((await f.app(f.request(`/${HASH}/hls/${name}`))).status, 404);
  equal(f.blobs.reads, reads);
});

Deno.test("age-gated read accepts hash-scoped Blossom or exact URL/method NIP98", async () => {
  const f = fixture();
  await f.upload();
  const row = (await f.catalog.get(HASH))!;
  await f.catalog.cas(HASH, row.revision, {
    ...row,
    ageRestricted: true,
    revision: row.revision + 1,
  });
  equal((await f.app(f.request(`/${HASH}`))).status, 401);
  equal((await f.app(f.request(`/${HASH}`, "GET", signed("get")))).status, 200);
  const event = finalizeEvent({
    kind: 27235,
    created_at: NOW,
    content: "",
    tags: [["u", `${ORIGIN}/${HASH}`], ["method", "GET"]],
  }, KEY);
  const authorization = `Nostr ${btoa(JSON.stringify(event))}`;
  equal((await f.app(f.request(`/${HASH}`, "GET", authorization))).status, 200);
  equal((await f.app(f.request(`/${HASH}`, "HEAD", authorization))).status, 401);
  equal((await f.app(f.request(`/${HASH}.mp4`, "GET", authorization))).status, 401);
});

Deno.test("invalid upload signatures and hash scopes never reach storage", async () => {
  const f = fixture();
  equal((await f.app(f.request("/upload", "PUT", undefined, BODY))).status, 401);
  equal(
    (await f.app(f.request("/upload", "PUT", signed("upload", "0".repeat(64)), BODY))).status,
    401,
  );
  equal((await f.app(f.request("/upload", "PUT", signed("delete"), BODY))).status, 401);
  const event = JSON.parse(atob(signed("upload").slice(6)));
  event.content = "modified after signing";
  equal(
    (await f.app(f.request("/upload", "PUT", `Nostr ${btoa(JSON.stringify(event))}`, BODY))).status,
    401,
  );
  equal(f.blobs.writes, 0);
});

Deno.test("non-owner cannot list or delete another owner's reference", async () => {
  const f = fixture();
  await f.upload();
  equal((await f.app(f.request(`/list/${OWNER}`, "GET", signed("list", HASH, OTHER)))).status, 403);
  equal((await f.app(f.request(`/${HASH}`, "DELETE", signed("delete", HASH, OTHER)))).status, 403);
});

Deno.test("deleting one of two references does not delete the other owner's media", async () => {
  const f = fixture();
  await f.upload();
  await f.upload(OTHER);
  equal((await f.app(f.request(`/${HASH}`, "DELETE", signed("delete")))).status, 202);
  equal((await f.app(f.request(`/${HASH}`))).status, 200);
  equal((await f.catalog.get(HASH))!.owners, [getPublicKey(OTHER)]);
});

Deno.test("confirmed policy change while origin responds prevents serving the response", async () => {
  const f = fixture();
  await f.upload();
  f.blobs.readHook = async () => {
    const row = (await f.catalog.get(HASH))!;
    await f.catalog.cas(HASH, row.revision, { ...row, held: true, revision: row.revision + 1 });
  };
  equal((await f.app(f.request(`/${HASH}`))).status, 404);
});

Deno.test("policy change during upload cannot publish and retains exclusion", async () => {
  const f = fixture();
  f.blobs.writeHook = async () => {
    const row = (await f.catalog.get(HASH))!;
    await f.catalog.cas(HASH, row.revision, { ...row, held: true, revision: row.revision + 1 });
  };
  equal((await f.upload()).status, 409);
  equal((await f.app(f.request(`/${HASH}`))).status, 404);
  equal(!!(await f.catalog.get(HASH))!.gate, true);
});

Deno.test("lost write acknowledgement is fenced and not automatically retried", async () => {
  const f = fixture();
  f.blobs.failWrite = true;
  equal((await f.upload()).status, 503);
  equal((await f.upload()).status, 409);
  equal(f.blobs.writes, 1);
  equal((await f.app(f.request(`/${HASH}`))).status, 404);
});

Deno.test("deleted parent cannot be resurrected by replaying signed upload", async () => {
  const f = fixture();
  await f.upload();
  await f.app(f.request(`/${HASH}`, "DELETE", signed("delete")));
  equal((await f.upload()).status, 409);
  equal(f.blobs.writes, 1);
});

Deno.test("database outage fails closed without reading media bytes", async () => {
  const f = fixture();
  await f.upload();
  f.catalog.failReads = true;
  equal((await f.app(f.request(`/${HASH}`))).status, 503);
  equal(f.blobs.reads, 0);
});

Deno.test("unbounded body and unexpected host, query and routes are rejected", async () => {
  const f = fixture();
  equal(
    (await f.app(f.request("/upload", "PUT", signed("upload"), new Uint8Array(4097)))).status,
    413,
  );
  equal((await f.app(new Request(`https://wrong.invalid/${HASH}`))).status, 421);
  equal((await f.app(f.request(`/${HASH}?versionId=old`))).status, 400);
  equal((await f.app(f.request("/admin/api/vanish", "POST"))).status, 501);
  equal((await f.app(f.request(`/${HASH}/hls/foreign.ts`))).status, 501);
  equal(f.blobs.writes, 0);
});

Deno.test("write entry point stays off unless explicitly enabled", async () => {
  const f = fixture();
  const app = createApp({ origin: ORIGIN, catalog: f.catalog, blobs: f.blobs, now: () => NOW });
  equal((await app(f.request("/upload", "PUT", signed("upload"), BODY))).status, 503);
  equal(f.blobs.writes, 0);
});

Deno.test("persistent fixture writes reject an unapproved signer before mutation", async () => {
  const f = fixture();
  equal((await f.upload(new Uint8Array(32).fill(3))).status, 403);
  equal(f.blobs.writes, 0);
  equal(f.catalog.rows.size, 0);
});

Deno.test("a signed multi-hash batch cannot expand the configured fixture digest", async () => {
  const f = fixture();
  const otherBody = new TextEncoder().encode("another synthetic object");
  const otherHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", otherBody)));
  const authorization = signed("upload", HASH, KEY, [["x", otherHash]]);
  equal((await f.app(f.request("/upload", "PUT", authorization, otherBody))).status, 403);
  equal(f.catalog.reads, 0);
  equal(f.catalog.rows.size, 0);
  equal(f.blobs.writes, 0);
});

Deno.test("policy revision changed without a hold still withdraws upload publication", async () => {
  const f = fixture();
  f.blobs.writeHook = async () => {
    const row = (await f.catalog.get(HASH))!;
    await f.catalog.cas(HASH, row.revision, {
      ...row,
      ageRestricted: true,
      revision: row.revision + 1,
    });
  };
  equal((await f.upload()).status, 409);
  equal(!!(await f.catalog.get(HASH))!.gate, true);
});

Deno.test("UTF-8 signed event content interoperates with standard Nostr JSON bytes", async () => {
  const f = fixture();
  const event = finalizeEvent({
    kind: 24242,
    created_at: NOW,
    content: "création 🎬",
    tags: [["t", "upload"], ["x", HASH], ["expiration", String(NOW + 60)]],
  }, KEY);
  const utf8 = new TextEncoder().encode(JSON.stringify(event));
  const header = "Nostr " + btoa(String.fromCharCode(...utf8));
  equal((await f.app(f.request("/upload", "PUT", header, BODY))).status, 200);
});

Deno.test("database failure after origin headers cancels the unconsumed origin stream", async () => {
  const f = fixture();
  await f.upload();
  let cancelled = false;
  f.blobs.read = () => {
    f.catalog.failReads = true;
    return Promise.resolve(
      new Response(
        new ReadableStream({
          cancel() {
            cancelled = true;
          },
        }),
      ),
    );
  };
  equal((await f.app(f.request(`/${HASH}`))).status, 503);
  equal(cancelled, true);
});
