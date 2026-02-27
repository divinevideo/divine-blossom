#!/usr/bin/env python3
"""
Worker + Reviewer: evaluator-optimizer pattern with back-transitions.

Two sessions share one workflow script and one state file. Role-based dispatch
gives each session its own state graph. The async push channel (REST API inject)
lets the workflow notify sessions without polling.

Launch:
    # Worker
    session_start(
        name="feat-worker",
        workflow="examples/review-workflow.py",
        workflow_params={"role": "worker", "issue": "Add caching layer"},
        prompt="Implement the feature. Call workflow('init').",
        project_dir="/path/to/project",
    )

    # Reviewer (spawn after worker submits, or let it idle)
    session_start(
        name="feat-reviewer",
        workflow="examples/review-workflow.py",
        workflow_params={"role": "reviewer", "worker_session": "feat-worker"},
        prompt="Review code changes. Call workflow('init').",
        project_dir="/path/to/project",
    )

── Worker LLM trace ────────────────────────────────────────────────────

  System prompt: "You are a feature worker. workflow('init') gives your task."
  Inject: "Call workflow('init') to start."

  LLM → workflow('init')                              # WorkerImpl state
    ← "## Implementing
        Issue: Add caching layer

        Implement the feature.
        Call workflow('submit', {summary: '...'}) when done."
    ← verify: "cargo test passes"

  LLM implements caching, runs tests...

  LLM → workflow('submit', {summary: "Redis cache, 5min TTL on /api/search"})
    ← "Submitted for review."                         # → WorkerWaiting
    ← "Idle or work on docs while reviewer checks."

  [Injected by workflow: "Changes requested: make TTL configurable"]

  LLM → workflow('init')                              # back in WorkerImpl!
    ← "## Changes requested
        Feedback: make TTL configurable

        Address the feedback.
        Call workflow('submit', {summary: '...'})."

  LLM fixes, resubmits...

  [Injected: "Approved!"]

── Reviewer LLM trace ──────────────────────────────────────────────────

  System prompt: "You are a code reviewer. workflow('init') shows what to review."
  Inject: "Call workflow('init') to see the submission."

  LLM → workflow('init')                              # Reviewing state
    ← "## Review round 1
        Worker summary: Redis cache, 5min TTL on /api/search

        Read the diff. Then:
        - workflow('approve') if it looks good
        - workflow('request_changes', {feedback: '...'}) if not"

  LLM reads diff, spots hardcoded TTL...

  LLM → workflow('request_changes', {feedback: "TTL should be configurable"})
    ← "Feedback sent to worker. Wait for resubmission."

  [Injected: "Worker resubmitted. Call workflow('init')."]

  LLM → workflow('init')
    ← "## Review round 2
        Worker summary: TTL from CACHE_TTL_SECS env var

        workflow('approve') or workflow('request_changes')."

  LLM → workflow('approve')
    ← "Approved! Feature complete."                   # → ReviewerDone
    ← "Call session_send(done=true)."

  Worker receives inject: "Review approved!"

─────────────────────────────────────────────────────────────────────────
"""
from ouija_workflow import Workflow, State
from pathlib import Path
import json


# ── Worker states ─────────────────────────────────────────────────────


class WorkerImpl(State):
    """Worker is actively implementing or addressing feedback."""

    def handle_init(self, ctx, params):
        feedback = ctx.data.get("feedback")
        if feedback:
            return self.respond(
                f"## Changes requested\nFeedback: {feedback}\n\n"
                "Address the feedback.\n"
                "Call workflow('submit', {summary: '...'}) when done.",
                verify="cargo test passes",
            )

        issue = ctx.params.get("issue", "No issue specified")
        return self.respond(
            f"## Implementing\nIssue: {issue}\n\n"
            "Implement the feature.\n"
            "Call workflow('submit', {summary: '...'}) when done.",
            verify="cargo test passes",
        )

    def handle_submit(self, ctx, params):
        if "summary" not in params:
            return self.respond("Error: submit requires {summary: '<what you built>'}.")

        ctx.data["summary"] = params["summary"]
        ctx.data["submitted"] = True
        ctx.data.pop("feedback", None)
        ctx.data["review_round"] = ctx.data.get("review_round", 0) + 1

        # Notify reviewer via async push channel
        for rid in ctx.data.get("reviewer_sessions", []):
            ctx.api.inject(
                rid,
                f"Worker resubmitted (round {ctx.data['review_round']}). "
                "Call workflow('init') to review.",
            )

        round_label = f" (round {ctx.data['review_round']})" if ctx.data["review_round"] > 1 else ""
        return self.transition_to(WorkerWaiting, f"Submitted for review{round_label}.")


class WorkerWaiting(State):
    """Worker idles here while reviewer works."""

    def on_enter(self, ctx):
        return "Idle or work on docs while reviewer checks."

    def handle_init(self, ctx, params):
        if ctx.data.get("feedback"):
            # Reviewer requested changes — back-transition!
            return self.transition_to(WorkerImpl)
        if ctx.data.get("approved"):
            return self.done("Approved! Feature complete.")
        return self.respond("Still waiting for review.")


# ── Reviewer states ───────────────────────────────────────────────────


class Reviewing(State):
    """Reviewer examines the worker's submission."""

    def handle_init(self, ctx, params):
        if not ctx.data.get("submitted"):
            return self.respond("No submission yet. Wait for the worker.")

        round_n = ctx.data.get("review_round", 1)
        summary = ctx.data.get("summary", "?")
        return self.respond(
            f"## Review round {round_n}\n"
            f"Worker summary: {summary}\n\n"
            "Read the diff. Then:\n"
            "- workflow('approve') if it looks good\n"
            "- workflow('request_changes', {feedback: '...'}) if not"
        )

    def handle_approve(self, ctx, params):
        ctx.data["approved"] = True
        worker = ctx.params.get("worker_session")
        if worker:
            ctx.api.inject(worker, "Review approved! Call workflow('init').")
        return self.transition_to(ReviewerDone, "Approved! Feature complete.")

    def handle_request_changes(self, ctx, params):
        if "feedback" not in params:
            return self.respond("Error: request_changes requires {feedback: '...'}")

        ctx.data["feedback"] = params["feedback"]
        ctx.data["submitted"] = False
        worker = ctx.params.get("worker_session")
        if worker:
            ctx.api.inject(
                worker,
                f"Changes requested: {ctx.data['feedback']}\n"
                "Address the feedback and call workflow('submit', {summary: '...'}).",
            )
        return self.respond(
            "Feedback sent to worker. Wait for resubmission, "
            "then call workflow('init')."
        )


class ReviewerDone(State):
    terminal = True

    def on_enter(self, ctx):
        return "Call session_send(done=true)."


# ── Workflow: role-based dispatch ─────────────────────────────────────


def pick_initial(ctx):
    """Route to different initial states based on registration role."""
    if ctx.params.get("role") == "reviewer":
        return Reviewing
    return WorkerImpl


class ReviewWorkflow(Workflow):
    """Custom registration for role-specific instructions and session tracking."""

    def on_register(self, session_id, params):
        role = params.get("role", "worker")

        # Track reviewer sessions so workers can notify them
        path = Path(self.state_file)
        raw = json.loads(path.read_text()) if path.exists() else {}
        if role == "reviewer":
            reviewers = raw.setdefault("data", {}).setdefault("reviewer_sessions", [])
            if session_id not in reviewers:
                reviewers.append(session_id)
            path.write_text(json.dumps(raw, indent=2))

        if role == "reviewer":
            return {
                "instructions": "You are a code reviewer. workflow('init') shows what to review.",
                "inject_on_start": "Call workflow('init') to see the submission.",
                "max_calls": 50,
            }
        return {
            "instructions": "You are a feature worker. workflow('init') gives your task.",
            "inject_on_start": "Call workflow('init') to start.",
            "max_calls": 100,
        }


ReviewWorkflow(
    initial=pick_initial,
    states=[WorkerImpl, WorkerWaiting, Reviewing, ReviewerDone],
    state_file="review-state.json",
).run()
