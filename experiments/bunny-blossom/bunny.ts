// Standalone Bunny Edge Scripting entrypoint for Divine Blossom.
// Handles all Blossom media, upload delegation, auth, webhooks, and admin routes natively on Bunny.

import * as BunnySDK from "@bunny.net/edgescript-sdk";
import { B2Blobs, BunnyPurger, SqlCatalog } from "./adapters.ts";
import { createApp } from "./app.ts";

function env(name: string, fallback?: string): string | undefined {
  const val = Deno.env.get(name)?.trim();
  return val && val.length > 0 ? val : fallback;
}

function required(primary: string, legacy?: string): string {
  const value = env(primary) ?? (legacy ? env(legacy) : undefined);
  if (!value) throw new Error(`Missing ${primary}${legacy ? ` (or ${legacy})` : ""}`);
  return value;
}

const origin = required("BLOSSOM_PUBLIC_ORIGIN", "SPIKE_PUBLIC_ORIGIN");
const sqlUrl = required("BLOSSOM_SQL_URL", "SPIKE_SQL_PRIMARY_URL");
const sqlToken = required("BLOSSOM_SQL_TOKEN", "SPIKE_SQL_TOKEN");
const b2Region = required("BLOSSOM_B2_REGION", "SPIKE_B2_REGION");
const b2Bucket = required("BLOSSOM_B2_BUCKET", "SPIKE_B2_BUCKET");
const b2KeyId = required("BLOSSOM_B2_KEY_ID", "SPIKE_B2_KEY_ID");
const b2Key = required("BLOSSOM_B2_KEY", "SPIKE_B2_KEY");

const legacyPrefix = env("SPIKE_B2_PREFIX");
const canonicalPrefix = env("BLOSSOM_B2_PREFIX") ?? (legacyPrefix ?? "");
const allowCanonicalRoot = env("BLOSSOM_ALLOW_CANONICAL_ROOT") === "true" ||
  (!legacyPrefix && env("BLOSSOM_B2_BUCKET") !== undefined);

const eraserId = env("BLOSSOM_B2_ERASER_ID");
const eraserKey = env("BLOSSOM_B2_ERASER_KEY");
const eraserBucketId = env("BLOSSOM_B2_BUCKET_ID");

const gcsBucket = env("BLOSSOM_GCS_BUCKET");
const gcsId = env("BLOSSOM_GCS_ACCESS_KEY");
const gcsKey = env("BLOSSOM_GCS_SECRET_KEY");

const bunnyApiKey = env("BLOSSOM_BUNNY_API_KEY");
const purgeHosts = (env("BLOSSOM_PURGE_HOSTS") ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const writesEnabled = env("BLOSSOM_WRITES_ENABLED") === "true" ||
  env("SPIKE_ENABLE_FIXTURE_WRITES") === "true";

const fixtureHash = env("SPIKE_FIXTURE_SHA256");
const fixtureOwners = env("SPIKE_FIXTURE_OWNERS");

const handler = createApp({
  origin,
  catalog: new SqlCatalog(sqlUrl, sqlToken),
  blobs: new B2Blobs({
    region: b2Region,
    bucket: b2Bucket,
    prefix: canonicalPrefix,
    id: b2KeyId,
    key: b2Key,
    allowCanonicalRoot,
    eraser: eraserId && eraserKey && eraserBucketId
      ? { id: eraserId, key: eraserKey, bucketId: eraserBucketId }
      : undefined,
    gcsFallback: gcsBucket && gcsId && gcsKey
      ? { bucket: gcsBucket, id: gcsId, key: gcsKey }
      : undefined,
  }),
  purger: bunnyApiKey && purgeHosts.length > 0
    ? new BunnyPurger(bunnyApiKey, purgeHosts)
    : undefined,
  upstreams: {
    uploadServiceUrl: env("BLOSSOM_UPLOAD_SERVICE_URL"),
    transcoderUrl: env("BLOSSOM_TRANSCODER_URL"),
    moderationApiUrl: env("BLOSSOM_MODERATION_API_URL"),
    moderationApiToken: env("BLOSSOM_MODERATION_API_TOKEN"),
  },
  secrets: {
    adminToken: env("BLOSSOM_ADMIN_TOKEN"),
    webhookSecret: env("BLOSSOM_WEBHOOK_SECRET"),
    transcoderWebhookSecret: env("BLOSSOM_TRANSCODER_WEBHOOK_SECRET"),
    archiveImportToken: env("BLOSSOM_ARCHIVE_IMPORT_TOKEN"),
    purgeDrainToken: env("BLOSSOM_PURGE_DRAIN_TOKEN"),
  },
  cache: {
    publicMediaCaching: env("BLOSSOM_PUBLIC_CACHING") === "true",
    browserMaxAgeSecs: Number(env("BLOSSOM_BROWSER_MAX_AGE") ?? "300"),
    edgeMaxAgeSecs: Number(env("BLOSSOM_EDGE_MAX_AGE") ?? "86400"),
  },
  writesEnabled,
  fixture: fixtureHash && fixtureOwners
    ? { hash: fixtureHash, owners: fixtureOwners.split(",").map((s) => s.trim()) }
    : undefined,
  bunnyDeliveryHost: env("BLOSSOM_DELIVERY_HOST"),
});

BunnySDK.net.http.serve(handler);
