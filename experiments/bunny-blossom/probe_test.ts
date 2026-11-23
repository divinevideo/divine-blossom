import { runtimeProbe } from "./probe.ts";

Deno.test("ephemeral runtime probe checks native handlers without persistent data", async () => {
  const result = await runtimeProbe(new Request("https://probe.invalid/health"));
  const body = await result.json();
  if (
    result.status !== 200 || !body.passed || !body.bodyChecksPassed ||
    body.persistentStorageTested || body.productionReady
  ) {
    throw new Error("runtime conformance failed or overclaimed");
  }
  if (
    (await runtimeProbe(new Request("https://probe.invalid/upload", { method: "PUT" }))).status !==
      404
  ) {
    throw new Error("probe exposed a mutable public route");
  }
});
