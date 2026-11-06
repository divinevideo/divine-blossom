# B2 outer probe evidence implementation

Scope: source only, based on99848b73. No endpoint, route, provider, media or deployment changes. Release owner integrates this patch with admission/purge source.

1. Add failing VCL source contracts for bounded synthetic probe gating, canonical fresh UUIDs preserved through restart/shield continuation, privacy-only event fields and conservative backend-path classification.
2. Add a versioned client-edge `log` snippet through existing placement-none `vcl-error-diagnostics`; use final `fastly_info.state`, not cached headers or request counters set on fetch nodes. Ordinary HIT with zero restarts means backend_fetch0; ordinary MISS/PASS means1 (possibly shield); every other state/restart means null.
3. Run source contracts and the Python scripts suite; obtain independent full-diff review. Provider VCL compilation and real delayed/batched logging remain separate operator checks.
4. Hand frozen commit to the release owner. Adapter accepts only correlated positive ordinary HIT evidence; absent or ambiguous evidence cannot pass. Preserve existing diagnostics/view/QoE semantics.
