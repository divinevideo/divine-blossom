// Ephemeral SDK conformance probe: no external storage, database, credentials or real data.
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { type Catalog, createApp, hex, type RecordState } from "./app.ts";

export async function runtimeProbe(req: Request): Promise<Response> {
  if (new URL(req.url).pathname !== "/health" || !["GET", "HEAD"].includes(req.method)) {
    return new Response(null, { status: 404, headers: { "cache-control": "private, no-store" } });
  }
  const start = performance.now();
  try {
    const rows = new Map<string, RecordState>();
    const bytes = new Map<string, Uint8Array<ArrayBuffer>>();
    const catalog: Catalog = {
      get(hash) {
        return Promise.resolve(structuredClone(rows.get(hash) ?? null));
      },
      cas(hash, expected, row) {
        if ((rows.get(hash)?.revision ?? null) !== expected) return Promise.resolve(false);
        rows.set(hash, structuredClone(row));
        return Promise.resolve(true);
      },
      list(owner, limit) {
        return Promise.resolve(
          [...rows.values()].filter((r) => r.owners.includes(owner)).slice(0, limit),
        );
      },
    };
    const app = createApp({
      origin: "https://bunny-spike.invalid",
      catalog,
      writesEnabled: true,
      blobs: {
        read(key, request) {
          const body = bytes.get(key);
          return Promise.resolve(
            new Response(request.method === "HEAD" ? null : body, { status: body ? 200 : 404 }),
          );
        },
        write(key, body) {
          bytes.set(key, body);
          return Promise.resolve();
        },
      },
    });
    const body = new TextEncoder().encode("synthetic Bunny runtime conformance fixture");
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
    // Deliberately public synthetic test key; it controls no persistent object or account.
    const key = new Uint8Array(32).fill(3);
    const now = Math.floor(Date.now() / 1000);
    const authorization = (action: string) =>
      "Nostr " + btoa(JSON.stringify(finalizeEvent({
        kind: 24242,
        created_at: now,
        content: "",
        tags: [["t", action], ["x", hash], ["expiration", String(now + 60)]],
      }, key)));
    const invoke = (path: string, method = "GET", action?: string, payload?: BodyInit) =>
      app(
        new Request(
          "https://bunny-spike.invalid" + path,
          {
            method,
            body: payload,
            headers: action ? { authorization: authorization(action) } : {},
          },
        ),
      );
    const checks: number[] = [];
    for (
      const [path, method, action, payload] of [
        ["/upload", "PUT", "upload", body],
        [`/${hash}`, "GET", undefined, undefined],
        [`/${hash}`, "HEAD", undefined, undefined],
        [`/list/${getPublicKey(key)}`, "GET", "list", undefined],
        [`/${hash}`, "DELETE", "delete", undefined],
        [`/${hash}`, "GET", undefined, undefined],
      ] as const
    ) {
      const result = await invoke(path, method, action, payload);
      checks.push(result.status);
      await result.body?.cancel();
    }
    const expected = [200, 200, 200, 200, 202, 404];
    const passed = JSON.stringify(checks) === JSON.stringify(expected);
    return new Response(
      req.method === "HEAD" ? null : JSON.stringify({
        probe: "bunny-blossom-runtime-v1",
        passed,
        checks,
        expected,
        persistentStorageTested: false,
        productionReady: false,
        elapsedWallMs: Math.round((performance.now() - start) * 100) / 100,
      }),
      {
        status: passed ? 200 : 500,
        headers: { "content-type": "application/json", "cache-control": "private, no-store" },
      },
    );
  } catch {
    return Response.json({ probe: "bunny-blossom-runtime-v1", passed: false }, {
      status: 500,
      headers: { "cache-control": "private, no-store" },
    });
  }
}
