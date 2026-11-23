import * as BunnySDK from "@bunny.net/edgescript-sdk";
import { B2Blobs, SqlCatalog } from "./adapters.ts";
import { createApp } from "./app.ts";

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

const handler = createApp({
  origin: required("SPIKE_PUBLIC_ORIGIN"),
  catalog: new SqlCatalog(required("SPIKE_SQL_PRIMARY_URL"), required("SPIKE_SQL_TOKEN")),
  blobs: new B2Blobs({
    region: required("SPIKE_B2_REGION"),
    bucket: required("SPIKE_B2_BUCKET"),
    prefix: required("SPIKE_B2_PREFIX"),
    id: required("SPIKE_B2_KEY_ID"),
    key: required("SPIKE_B2_KEY"),
  }),
  writesEnabled: Deno.env.get("SPIKE_ENABLE_FIXTURE_WRITES") === "true",
});

BunnySDK.net.http.serve(handler);
