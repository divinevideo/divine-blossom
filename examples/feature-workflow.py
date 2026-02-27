#!/usr/bin/env python3
"""
Multi-phase feature workflow: Planning → Implementing → Verifying → Done.

Demonstrates prompt chaining — the simplest of Anthropic's five composable agent
patterns. Each state reveals only its own actions; the LLM never sees ahead.

Launch:
    session_start(
        name="feat-1",
        workflow="examples/feature-workflow.py",
        workflow_params={"issue": "Add rate limiting to /api/upload"},
        prompt="You are implementing a feature. Call workflow('init') to start.",
        project_dir="/path/to/project",
    )

── LLM conversation trace ──────────────────────────────────────────────

  LLM → workflow('init')                          # lands in Planning
    ← "## Planning
        Issue: Add rate limiting to /api/upload

        Analyze the codebase and create an implementation plan.
        Call workflow('plan_done', {plan: '...', chunks: [...]})."

  LLM reads code, thinks, creates plan...

  LLM → workflow('plan_done', {plan: "Token bucket...",
                               chunks: ["rate_limiter", "middleware", "tests"]})
    ← "Plan accepted. 3 chunks."                  # transition → Implementing
    ← "Start: rate_limiter."                       # on_enter fires
    ← verify: "cargo build succeeds"

  Note: Planning never mentioned chunks, verify, or phases.
  The LLM learned about them only upon entering Implementing.

  LLM builds the rate limiter module, cargo build passes...

  LLM → workflow('chunk_done')
    ← "Chunk 1/3 done. Next: middleware."
    ← verify: "cargo build succeeds"

  LLM builds middleware, cargo build passes...

  LLM → workflow('chunk_done')
    ← "Chunk 2/3 done. Next: tests."

  LLM writes tests...

  LLM → workflow('chunk_done')
    ← "All 3 chunks implemented."                 # transition → Verifying
    ← "Run the full test suite and review."        # on_enter fires
    ← verify: "cargo test passes with 0 failures"

  Note: the LLM didn't know about the verification phase until now.

  LLM runs cargo test (passes), reviews diff...

  LLM → workflow('verified', {summary: "Rate limiter: 100 req/min/IP, 12 tests"})
    ← "Feature complete."                          # transition → Done
    ← "Call session_send(done=true)."              # on_enter fires

─────────────────────────────────────────────────────────────────────────
"""
from ouija_workflow import Workflow, State


class Planning(State):

    def handle_init(self, ctx, params):
        issue = ctx.params.get("issue", "No issue specified")
        return self.respond(
            f"## Planning\nIssue: {issue}\n\n"
            "Analyze the codebase and create an implementation plan.\n"
            "Call workflow('plan_done', {plan: '<plan>', chunks: ['chunk1', ...]})."
        )

    def handle_plan_done(self, ctx, params):
        if "chunks" not in params:
            return self.respond("Error: plan_done requires {plan: '...', chunks: ['...']}.")
        ctx.data["plan"] = params.get("plan", "")
        ctx.data["chunks"] = params["chunks"]
        ctx.data["chunks_done"] = 0
        n = len(ctx.data["chunks"])
        return self.transition_to(
            Implementing,
            f"Plan accepted. {n} chunks to implement.",
            verify="cargo build succeeds with no errors",
        )


class Implementing(State):

    def on_enter(self, ctx):
        """Fires on every transition INTO this state — including back-transitions."""
        chunks = ctx.data["chunks"]
        done = ctx.data["chunks_done"]
        if done < len(chunks):
            return f"Start: {chunks[done]}. Call workflow('chunk_done') when finished."

    def handle_init(self, ctx, params):
        """Handles restart/resume — LLM calls init again after context reset."""
        done = ctx.data.get("chunks_done", 0)
        chunks = ctx.data.get("chunks", [])
        nxt = chunks[done] if done < len(chunks) else "?"
        return self.respond(
            f"## Resuming: Implementing\n"
            f"Chunk {done + 1}/{len(chunks)}: {nxt}. Call workflow('chunk_done')."
        )

    def handle_chunk_done(self, ctx, params):
        ctx.data["chunks_done"] += 1
        done = ctx.data["chunks_done"]
        total = len(ctx.data["chunks"])

        if done >= total:
            return self.transition_to(
                Verifying, f"All {total} chunks implemented.",
                verify="cargo test passes with 0 failures",
            )

        nxt = ctx.data["chunks"][done]
        return self.respond(
            f"Chunk {done}/{total} done. Next: {nxt}. Call workflow('chunk_done').",
            verify="cargo build succeeds",
        )


class Verifying(State):

    def on_enter(self, ctx):
        return (
            "Run the full test suite and review your changes.\n"
            "Call workflow('verified', {summary: '<what you built>'})."
        )

    def handle_init(self, ctx, params):
        return self.respond(
            "Run tests and review. Call workflow('verified', {summary: '...'}).",
            verify="cargo test passes with 0 failures",
        )

    def handle_verified(self, ctx, params):
        ctx.data["summary"] = params.get("summary", "")
        return self.transition_to(Done, "Feature complete.")


class Done(State):
    terminal = True

    def on_enter(self, ctx):
        return "Call session_send(done=true)."


Workflow(
    initial=Planning,
    states=[Planning, Implementing, Verifying, Done],
    instructions="You have a workflow guiding you through a structured implementation.",
).run()
