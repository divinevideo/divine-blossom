#!/usr/bin/env python3
"""
Autoresearch workflow actor for ouija.

This script implements the ouija workflow protocol to drive an optimization/research
loop. The LLM session iterates: read state -> make one change -> measure -> keep or
revert. Results accumulate in results.tsv and findings in FINDINGS.md.

Protocol overview:
  The daemon spawns this script once per interaction, passing a JSON envelope on
  stdin and reading a JSON response from stdout. Two kinds of input:

  1. Lifecycle events (have "event" field):
     - register:          return {instructions, inject_on_start}
     - session_died:      return {}
     - session_restarted: return {}

  2. Runtime actions (have "action" field):
     - init:              return current state + next task prompt
     - result(score, description): log result, commit/revert, return outcome
     - findings(text):    append to FINDINGS.md
     - status:            return state summary

  Environment variables set by the daemon:
     OUIJA_API        - base URL of the daemon REST API (e.g. http://127.0.0.1:7880)
     OUIJA_SESSION_ID - this session's ID

Usage:
  session_start(
    name="optimizer",
    workflow="examples/autoresearch-workflow.py",
    workflow_params={"max_iterations": 30},
    prompt="Read INSTRUCTIONS.md for your task.",
    project_dir="/path/to/project"
  )
"""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

# -- State management --------------------------------------------------------

STATE_FILE = "workflow-state.json"
RESULTS_FILE = "results.tsv"
FINDINGS_FILE = "FINDINGS.md"
INSTRUCTIONS_FILE = "INSTRUCTIONS.md"

DEFAULT_MAX_ITERATIONS = 50


def load_state():
    """Load workflow state from disk, or return defaults."""
    if Path(STATE_FILE).exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {
        "iteration": 0,
        "best_score": None,
        "best_description": None,
        "status": "initialized",
    }


def save_state(state):
    """Persist workflow state to disk."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# -- File helpers -------------------------------------------------------------


def read_file_safe(path):
    """Read a file, returning empty string if missing."""
    try:
        return Path(path).read_text()
    except FileNotFoundError:
        return ""


def read_recent_results(n=10):
    """Read the last N rows from results.tsv."""
    if not Path(RESULTS_FILE).exists():
        return []
    with open(RESULTS_FILE, newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        rows = list(reader)
    return rows[-n:]


def append_result(iteration, score, description, outcome):
    """Append a row to results.tsv, creating the file with headers if needed."""
    exists = Path(RESULTS_FILE).exists()
    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        if not exists:
            writer.writerow(["iteration", "score", "description", "outcome"])
        writer.writerow([iteration, score, description, outcome])


def append_findings(text):
    """Append text to FINDINGS.md."""
    with open(FINDINGS_FILE, "a") as f:
        if Path(FINDINGS_FILE).stat().st_size > 0:
            f.write("\n\n")
        f.write(text.strip())
        f.write("\n")


# -- Git helpers --------------------------------------------------------------


def git_commit(message):
    """Stage all changes and commit."""
    subprocess.run(["git", "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", message], check=True, capture_output=True)


def git_revert():
    """Revert all uncommitted changes."""
    subprocess.run(["git", "checkout", "."], check=True, capture_output=True)
    subprocess.run(["git", "clean", "-fd"], check=True, capture_output=True)


# -- Action handlers ----------------------------------------------------------


def handle_register(params):
    """Return instructions and inject_on_start for session setup.

    The instructions become part of the session's prompt. They describe the
    workflow interface so the LLM knows what tools it has.
    """
    max_iter = (params or {}).get("max_iterations", DEFAULT_MAX_ITERATIONS)

    # Persist max_iterations in state
    state = load_state()
    state["max_iterations"] = max_iter
    save_state(state)

    instructions = f"""You are running an autoresearch optimization loop controlled by a workflow actor.

## Available workflow actions

Call `workflow(action, params)` to interact with the workflow:

- `workflow(action="init")` - Get current iteration, best score, recent results, and your next task.
  Call this at the start and after each restart.

- `workflow(action="result", params={{"score": <number>, "description": "<what you changed>"}})` -
  Report the result of your change. The workflow will compare to the best score, git commit on
  improvement or git revert on regression, and tell you the outcome.

- `workflow(action="findings", params={{"text": "<your finding>"}})` -
  Record a finding or insight to FINDINGS.md. Use this for architectural knowledge, dead ends,
  or anything that should survive across context restarts.

- `workflow(action="status")` - Get a summary of current workflow state.

## Loop rules

1. Call workflow("init") to get your task and current state.
2. Read INSTRUCTIONS.md for what to optimize and how to measure.
3. Make exactly ONE change per iteration.
4. Measure the result (run the benchmark/test as described in INSTRUCTIONS.md).
5. Call workflow("result", {{"score": <number>, "description": "<what you did>"}}).
6. If you discover something important, call workflow("findings", {{"text": "..."}}).
7. Maximum {max_iter} iterations. The workflow will stop you at the limit.
8. Never skip measuring. Never batch multiple changes."""

    return {
        "instructions": instructions,
        "inject_on_start": "Call workflow('init') to begin.",
    }


def handle_init(_params):
    """Return current state and prompt the LLM to make its next change."""
    state = load_state()
    max_iter = state.get("max_iterations", DEFAULT_MAX_ITERATIONS)
    iteration = state["iteration"]

    if iteration >= max_iter:
        return {
            "message": (
                f"Maximum iterations ({max_iter}) reached. "
                f"Best score: {state['best_score']} ({state['best_description']}). "
                "Session complete. Call session_send(done=true)."
            )
        }

    instructions = read_file_safe(INSTRUCTIONS_FILE)
    findings = read_file_safe(FINDINGS_FILE)
    recent = read_recent_results()

    parts = [f"## Iteration {iteration + 1}/{max_iter}"]

    if state["best_score"] is not None:
        parts.append(f"Best score so far: {state['best_score']} ({state['best_description']})")

    if recent:
        header = "iteration\tscore\tdescription\toutcome"
        rows = "\n".join(
            f"{r['iteration']}\t{r['score']}\t{r['description']}\t{r['outcome']}"
            for r in recent
        )
        parts.append(f"## Recent results\n```\n{header}\n{rows}\n```")

    if findings:
        parts.append(f"## Accumulated findings\n{findings}")

    if instructions:
        parts.append(f"## Instructions\n{instructions}")
    else:
        parts.append(
            "WARNING: INSTRUCTIONS.md not found. Create it with your optimization target and "
            "measurement method, then call workflow('init') again."
        )

    parts.append(
        "\nMake exactly ONE change, measure the result, then call "
        "workflow('result', {score: <number>, description: '<what you changed>'})."
    )

    state["status"] = "running"
    save_state(state)

    return {"message": "\n\n".join(parts)}


def handle_result(params):
    """Log a result, commit or revert, return outcome."""
    if not params or "score" not in params or "description" not in params:
        return {"error": "result requires params: {score: <number>, description: '<text>'}"}

    state = load_state()
    max_iter = state.get("max_iterations", DEFAULT_MAX_ITERATIONS)

    score = float(params["score"])
    description = str(params["description"])
    iteration = state["iteration"] + 1
    state["iteration"] = iteration

    improved = state["best_score"] is None or score > state["best_score"]

    if improved:
        outcome = "improved"
        old_best = state["best_score"]
        state["best_score"] = score
        state["best_description"] = description

        try:
            git_commit(f"iteration {iteration}: {description} (score: {score})")
        except subprocess.CalledProcessError:
            outcome = "improved (commit failed)"
    else:
        outcome = "regressed"
        try:
            git_revert()
        except subprocess.CalledProcessError:
            outcome = "regressed (revert failed)"

    append_result(iteration, score, description, outcome)
    save_state(state)

    parts = [f"## Iteration {iteration} result: {outcome}"]
    parts.append(f"Score: {score} | Description: {description}")

    if improved:
        if old_best is not None:
            parts.append(f"New best! Previous best was {old_best}.")
        else:
            parts.append("First result recorded as baseline.")
    else:
        parts.append(
            f"Score {score} did not beat best of {state['best_score']}. Changes reverted."
        )

    if iteration >= max_iter:
        parts.append(
            f"\nMaximum iterations ({max_iter}) reached. Best: {state['best_score']}. "
            "Call session_send(done=true) to finish."
        )
    else:
        parts.append(f"\n{max_iter - iteration} iterations remaining. Call workflow('init') for the next iteration.")

    return {"message": "\n".join(parts)}


def handle_findings(params):
    """Append findings text to FINDINGS.md."""
    if not params or "text" not in params:
        return {"error": "findings requires params: {text: '<your finding>'}"}

    text = str(params["text"])

    # Create FINDINGS.md if it doesn't exist
    if not Path(FINDINGS_FILE).exists():
        Path(FINDINGS_FILE).write_text("# Findings\n\n")

    append_findings(text)
    return {"message": f"Finding recorded in {FINDINGS_FILE}."}


def handle_status(_params):
    """Return a summary of current workflow state."""
    state = load_state()
    max_iter = state.get("max_iterations", DEFAULT_MAX_ITERATIONS)

    parts = [
        f"Iteration: {state['iteration']}/{max_iter}",
        f"Status: {state.get('status', 'unknown')}",
        f"Best score: {state['best_score']}",
    ]
    if state["best_description"]:
        parts.append(f"Best from: {state['best_description']}")

    return {"message": "\n".join(parts)}


# -- Main dispatch ------------------------------------------------------------


def main():
    raw = sys.stdin.read()
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid JSON input: {e}"}))
        sys.exit(1)

    params = envelope.get("params")

    # Lifecycle events (have "event" field)
    event = envelope.get("event")
    if event:
        if event == "register":
            result = handle_register(params)
        elif event in ("session_died", "session_restarted"):
            result = {}
        else:
            result = {"error": f"unknown event: {event}"}

        print(json.dumps(result))
        return

    # Runtime actions (have "action" field)
    action = envelope.get("action")
    if action:
        handlers = {
            "init": handle_init,
            "result": handle_result,
            "findings": handle_findings,
            "status": handle_status,
        }
        handler = handlers.get(action)
        if handler:
            result = handler(params)
        else:
            result = {"error": f"unknown action: {action}"}

        print(json.dumps(result))
        return

    # Neither event nor action
    print(json.dumps({"error": "input must have 'event' or 'action' field"}))
    sys.exit(1)


if __name__ == "__main__":
    main()
