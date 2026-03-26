#!/usr/bin/env python3
"""
Simple optimization loop — State Pattern version of autoresearch-workflow.py.

Two states: Running and Done. The LLM iterates: make one change, measure, report.
The workflow commits improvements and reverts regressions.

Launch:
    ouija.start(
        name="optimizer",
        workflow="examples/simple-loop-workflow.py",
        workflow_params={"max_iterations": 10},
        prompt="Read INSTRUCTIONS.md for your optimization target.",
        project_dir="/path/to/project",
    )

── LLM conversation trace ──────────────────────────────────────────────

  System prompt (from registration):
    "You are running an optimization loop. ouija.workflow('init') gets your task.
     ouija.workflow('result', {score, description}) reports each attempt. One
     change per iteration. Never skip measuring."

  Daemon injects: "Call ouija.workflow('init') to begin."

  LLM → ouija.workflow('init')
    ← "## Iteration 1/10
        Read INSTRUCTIONS.md, make ONE change, measure.
        Call ouija.workflow('result', {score: <number>, description: '<what>'})."

  LLM reads INSTRUCTIONS.md, edits code, runs benchmark...

  LLM → ouija.workflow('result', {score: 42.5, description: "added connection pooling"})
    ← "## Iteration 1: improved
        Score: 42.5. Baseline recorded.
        9 iterations remaining. Call ouija.workflow('init')."

  LLM → ouija.workflow('init')
    ← "## Iteration 2/10
        Best so far: 42.5 (added connection pooling)
        Make ONE change, measure, report."

  ...several iterations later...

  LLM → ouija.workflow('result', {score: 38.0, description: "tried batch inserts"})
    ← "## Iteration 6: regressed
        Score 38.0 < best 47.2. Changes reverted.
        4 iterations remaining. Call ouija.workflow('init')."

  Note: the LLM never knew about revert-on-regression until it happened.
  Note: the LLM never knew the total iteration count until init told it.
  That's progressive disclosure.

─────────────────────────────────────────────────────────────────────────
"""
import subprocess

from ouija_workflow import Workflow, State


class Running(State):

    def handle_init(self, ctx, params):
        i = ctx.data.get("iteration", 0)
        max_i = ctx.params.get("max_iterations", 50)
        if i >= max_i:
            return self.transition_to(
                Done, f"Max iterations ({max_i}) reached. Best: {ctx.data.get('best_score')}"
            )

        parts = [f"## Iteration {i + 1}/{max_i}"]
        if ctx.data.get("best_score") is not None:
            parts.append(f"Best so far: {ctx.data['best_score']} ({ctx.data['best_desc']})")
        parts.append(
            "\nMake ONE change, measure, then call "
            "ouija.workflow('result', {score: <number>, description: '<what you changed>'})."
        )
        return self.respond("\n".join(parts))

    def handle_result(self, ctx, params):
        if "score" not in params or "description" not in params:
            return self.respond("Error: result requires {score: <number>, description: '<text>'}.")

        score = float(params["score"])
        desc = str(params["description"])
        ctx.data["iteration"] = ctx.data.get("iteration", 0) + 1
        i = ctx.data["iteration"]
        max_i = ctx.params.get("max_iterations", 50)

        improved = ctx.data.get("best_score") is None or score > ctx.data["best_score"]

        if improved:
            old_best = ctx.data.get("best_score")
            ctx.data["best_score"] = score
            ctx.data["best_desc"] = desc
            subprocess.run(["git", "add", "-A"], capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", f"iter {i}: {desc} ({score})"],
                capture_output=True,
            )
            msg = f"## Iteration {i}: improved\nScore: {score}."
            if old_best is None:
                msg += " Baseline recorded."
            else:
                msg += f" Beat previous best of {old_best}."
        else:
            subprocess.run(["git", "checkout", "."], capture_output=True)
            subprocess.run(["git", "clean", "-fd"], capture_output=True)
            msg = (
                f"## Iteration {i}: regressed\n"
                f"Score {score} < best {ctx.data['best_score']}. Changes reverted."
            )

        remaining = max_i - i
        if remaining <= 0:
            return self.transition_to(Done, msg)
        msg += f"\n\n{remaining} remaining. Call ouija.workflow('init')."
        return self.respond(msg)


class Done(State):
    terminal = True

    def on_enter(self, ctx):
        return "Call ouija.send(done=true)."


Workflow(
    initial=Running,
    states=[Running, Done],
    instructions=(
        "You are running an optimization loop. "
        "ouija.workflow('init') gets your task. "
        "ouija.workflow('result', {score, description}) reports each attempt. "
        "One change per iteration. Never skip measuring."
    ),
    max_calls=120,
).run()
