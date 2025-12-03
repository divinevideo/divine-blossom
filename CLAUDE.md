# Fastly Compute Deployment Rules

**ALWAYS use `fastly compute publish` instead of `fastly compute build` + `fastly compute deploy`**

The `publish` command does build+deploy in a single atomic operation.

## Deployment Workflow
```bash
fastly compute publish --comment "description" && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

## Key Lessons
- `fastly compute publish --comment "description"` is the correct way to deploy
- Do NOT use `fastly compute deploy` separately
- Local testing with `fastly compute serve` works correctly for verification
- **CRITICAL: Always purge after deploy!** Run `fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR` after publishing
- **Propagation can be SLOW** - even after purge, Compute package propagation to all POPs can take several minutes. The version may show as "active" in the API but edge POPs may still serve old code. Be patient.