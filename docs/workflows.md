# Workflow Actors

A workflow actor is an external program that drives an LLM session through a deterministic process. The LLM calls an `ouija.workflow()` tool; the program controls state, verification, and progression. Think of it as a process engine where the LLM is the task worker.

## The idea

Most agent harnesses work like this: code calls the LLM API, gets a response, decides the next step, calls the LLM again. The code is the orchestrator; the LLM is a stateless function.

Ouija inverts this. The LLM is a persistent, autonomous session with full tool access. But it needs guidance — left alone, it drifts, skips steps, or declares victory early. A workflow actor provides that guidance without taking away the LLM's autonomy within each step.

The pattern is the same as an MCP tool: the LLM calls deterministic code and gets a response. But this "tool" is custom per session — set at start time, managing its own state, controlling what the LLM does next. The LLM operates inside the steps; the workflow operates between them.

```
Classical harness:    Code → LLM API → Code → LLM API → Code → ...
                      (code is the loop, LLM is a function)

Workflow actor:       LLM → ouija.workflow() → LLM → ouija.workflow() → LLM → ...
                      (LLM is the loop, workflow is a function)
```

Same control flow, inverted. One continuous LLM session instead of many API calls. The LLM retains full context and tool access. The workflow provides deterministic checkpoints.

## Progressive disclosure

A workflow doesn't explain itself upfront. It reveals the process one step at a time, like [HATEOAS](https://en.wikipedia.org/wiki/HATEOAS) in REST APIs — the response tells the client what it can do next, so the client never needs a map of the full API.

```
LLM: ouija.workflow('init')
  → "Implement the auth module. Call ouija.workflow('chunk_done', {chunk: 'auth'}) when finished."

LLM: ouija.workflow('chunk_done', {chunk: 'auth'})
  → "Tests pass. Next: implement the logging module. Call ouija.workflow('chunk_done', {chunk: 'logging'})."

LLM: ouija.workflow('chunk_done', {chunk: 'logging'})
  → "All chunks done. Review your diff, then call ouija.workflow('verify', {summary: '...'})."
```

The LLM didn't know about the verify phase until it got there. The prompt didn't describe a three-phase process. Each response disclosed exactly what was needed — no more, no less.

This is the same principle as BPM systems (Camunda, Activiti): the task participant sees only their current task form, not the process diagram. The engine routes work based on outcomes.

### Why this matters

- **Less context consumed** — the LLM holds only the current step, not a full process description
- **Less drift** — the LLM can't skip ahead because it doesn't know what's ahead
- **Survives restarts** — `ouija.workflow('init')` reconstructs state from the state file; no prompt memory needed
- **Adaptable** — the workflow can change the next step based on results without conflicting with the LLM's cached understanding

### Three levels of context

Information reaches the LLM at three levels:

| Level | What | When loaded | Purpose |
|---|---|---|---|
| 1. Tool description | The `ouija.workflow` MCP tool description | Always in context | Tells the LLM the tool exists and how to call it |
| 2. Registration instructions | From the workflow's `register` response | At session start | Orients the LLM — purpose, rhythm, constraints |
| 3. Runtime responses | From each `ouija.workflow()` call | On demand | Step-specific: current state, next task, verification criteria |

Level 1 helps recognize. Level 2 orients. Level 3 directs. Don't bleed between levels — if you're putting step-specific detail in registration instructions, move it to a runtime response.

## How it works

### Protocol

A workflow is any executable that reads JSON from stdin and writes JSON to stdout. The daemon spawns it once per interaction (stateless process, stateful files).

**Registration** (called by the daemon at `ouija.start`):
```json
// stdin
{"event": "register", "session_id": "worker-1", "params": {"issue_id": 123}}

// stdout
{"instructions": "You are a worker...", "inject_on_start": "Call ouija.workflow('init').", "max_calls": 200}
```

**Runtime** (called when the LLM uses the `ouija.workflow()` MCP tool):
```json
// stdin
{"action": "chunk_done", "session_id": "worker-1", "params": {"chunk": "auth"}}

// stdout
{"message": "Tests pass. Next: implement logging.", "verify": "cargo test --lib logging passes"}
```

**Lifecycle events** (called by the daemon on session death/restart):
```json
// stdin
{"event": "session_died", "session_id": "worker-1"}

// stdout
{}
```

### What the daemon provides

- **MCP tool**: Routes LLM `ouija.workflow()` calls to the executable, injects trusted `session_id`
- **Registration**: Calls the workflow at session start, merges instructions into the prompt
- **Effort budgets**: Enforces `max_calls` from registration — refuses further calls when exhausted
- **Lifecycle events**: Notifies the workflow when sessions die or restart
- **Stall detection**: If the LLM stops calling the workflow, the daemon injects the reminder
- **Push channel**: The workflow calls ouija's REST API to inject messages, spawn sessions, or send notifications asynchronously

### What the daemon does NOT do

- Interpret workflow responses (just passes them through)
- Know the workflow's state machine (black box)
- Manage the workflow's state (the workflow owns its state files)
- Decide when to restart or stop (the workflow communicates this via its responses)

## The bidirectional channel

The workflow communicates with LLM sessions in two directions:

**LLM → Workflow** (synchronous, via MCP tool): The LLM calls `ouija.workflow('action')`, the daemon pipes to the executable, returns the response. This is request-response — the LLM initiates.

**Workflow → LLM** (asynchronous, via ouija REST API): The workflow calls `POST /api/inject` to push text into any session at any time. This is how a reviewer's approval can wake up an idle worker, or how a coordinator can dispatch new tasks.

```python
# Inside a workflow script — push a message to another session
import requests, os
requests.post(f"{os.environ['OUIJA_API']}/api/inject", json={
    "pane": worker_pane_id,
    "message": "Review approved. Call ouija.workflow('init') to continue."
})
```

Without the async push channel, the workflow would be limited to request-response — a polling-based model where the LLM must keep calling `ouija.workflow('status')` to check for updates. The ouija REST API makes it reactive.

## Multi-session coordination

Multiple LLM sessions can share one workflow. The workflow distinguishes them by `session_id` and manages their state independently:

```
                  ┌──────────────┐
                  │   Workflow    │
                  │  (one script) │
                  │   state.json  │
                  └──┬───┬───┬──┘
                     │   │   │
              ┌──────┘   │   └──────┐
              ↕          ↕          ↕
         ┌─────────┐ ┌─────────┐ ┌──────────┐
         │ Worker  │ │ Worker  │ │ Reviewer │
         │  (LLM)  │ │  (LLM)  │ │  (LLM)   │
         └─────────┘ └─────────┘ └──────────┘
```

Each session calls `ouija.workflow('init')` and gets role-appropriate instructions. The workflow is the coordinator — no coordinator LLM session needed, zero tokens spent on orchestration logic.

The workflow can:
- Assign different roles at registration based on `workflow_params`
- Gate worker progress on reviewer approval
- Spawn new sessions via the REST API
- Track a kanban board, manage concurrent slots
- Interact with external systems (Forgejo, GitHub, Slack) deterministically

This replaces patterns where a coordinator LLM session reads a prompt, calls `ouija.start` to spawn workers, polls for `done:` messages, and manages state through conversation context. The workflow script does all of this with deterministic code.

## Verification

Workflow responses can include a `verify` field with machine-checkable success criteria:

```json
{
  "message": "Implement the rate limiter for the /api/upload endpoint.",
  "verify": "cargo test --lib rate_limiter passes with 0 failures"
}
```

The daemon appends this to the message: "Verify before proceeding: cargo test --lib rate_limiter passes with 0 failures." The LLM runs the check before calling the next workflow action.

This is the VERIFY phase from gather-act-verify-repeat loops. The workflow defines what "done" means; the LLM checks it. If verification fails, the LLM fixes the issue before proceeding — the workflow never sees an unverified result.

## Effort budgets

Workflows set a `max_calls` limit at registration. The daemon enforces it — after the limit, further `ouija.workflow()` calls return an error. This prevents the biggest failure mode in multi-agent systems: unbounded looping.

The limit is set by the workflow (deterministic code), not the LLM (probabilistic). The LLM can't override it.

## Pitfalls and best practices

Lessons from building and testing real workflows.

### Per-session state isolation

When multiple sessions share a workflow, everything in the state file that varies by session must be keyed by `session_id`. The most common mistake: storing `workflow_params` globally.

```python
# BUG: second session's registration overwrites the first
raw["workflow_params"] = params

# FIX: store per-session
raw.setdefault("session_params", {})[session_id] = params
```

This matters because `workflow_params` carries role-specific data (e.g. `{"role": "worker"}` vs `{"role": "reviewer"}`). If stored globally, the last session to register wins and all sessions see its params. The daemon passes the correct `session_id` in every call — the workflow must use it to look up the right params.

The same applies to current state tracking. A worker might be in `Implementing` while a reviewer is in `Reviewing`. The state file needs:

```json
{
  "session_params": {
    "worker-1": {"role": "worker", "issue": "..."},
    "reviewer-1": {"role": "reviewer", "worker_session": "worker-1"}
  },
  "sessions": {
    "worker-1": {"state": "WorkerImpl"},
    "reviewer-1": {"state": "Reviewing"}
  },
  "data": {"summary": "...", "approved": false}
}
```

`session_params` and `sessions` are per-session. `data` is shared.

### File locking

The workflow must lock its own state file. Use `fcntl.flock()` with `LOCK_EX` before reading and `LOCK_UN` after writing. Without this, concurrent calls from different sessions can corrupt the state file.

### Handle `init` in every state

The LLM calls `ouija.workflow('init')` after every context reset (session restart, compaction). The workflow's current state must handle `init` gracefully — return a summary of where things stand and what to do next. This is how workflows survive restarts without losing progress.

### Split heavy actions into phases

When a workflow action does too much (git push + API calls + spawn sessions), the LLM's tool call can time out. Split into phases:

```python
def handle_complete(self, ctx, params):
    if not ctx.data.get("pushed"):
        git_push()
        ctx.data["pushed"] = True
        return self.respond("Pushed. Call ouija.workflow('complete') again to finalize.")
    # Second call: do the slow stuff
    ctx.api.session_start(...)
    return self.transition_to(Done, "Finalized.")
```

The LLM calls `ouija.workflow('complete')` twice. First call does the fast part and returns a continuation prompt. Second call finishes. HATEOAS drives the continuation — no special retry logic needed.

### The LLM will adapt around broken workflows

If a workflow returns the wrong response (e.g. reviewer instructions to a worker), the LLM will often "work around it" — using other tools like `ouija.send` instead of workflow actions, or interpreting instructions creatively. This makes bugs hard to detect. Always verify the state file during testing to confirm sessions are in the expected states, not just that the end result looks correct.

### Expand tilde paths before sending to the REST API

`project_dir: "~/code/foo"` fails silently — the daemon passes the literal `~` to the OS. Always expand paths:

```python
project_dir = str(Path(project_dir).expanduser())
```

### Async spawn + self-kill = worktree race

A common multi-session pattern: worker spawns reviewer, then kills itself. But `ouija.start` returns 202 (async) — the reviewer might not be alive yet. If the worker's worktree is cleaned up before the reviewer boots, the reviewer has no code to review.

Fix: poll for the new session before exiting. The retry-after pattern works here — `handle_complete` returns "call again to confirm reviewer" until the reviewer appears in `ouija.list`.

```python
def handle_complete(self, ctx, params):
    if not ctx.data.get("reviewer_spawned"):
        ctx.api.session_start(name="reviewer", ...)
        ctx.data["reviewer_spawned"] = True
        return self.respond("Reviewer spawning. Call ouija.workflow('complete') again to confirm.")
    # Check if reviewer is alive
    sessions = ctx.api.get_sessions()
    if "reviewer" not in sessions:
        return self.respond("Reviewer not ready yet. Call ouija.workflow('complete') again.")
    return self.transition_to(Done, "Reviewer is up. Handing off.")
```

### Make side effects idempotent

When a workflow action crashes mid-way and the LLM retries, any external side effects run twice. If your action writes to an API (issue body, PR review, labels), check whether the write already happened before doing it again.

```python
def handle_request_changes(self, ctx, params):
    feedback = params["feedback"]
    # Idempotent: check before appending
    issue_body = forgejo.get_issue_body(ctx.data["issue_id"])
    if feedback not in issue_body:
        forgejo.append_to_issue(ctx.data["issue_id"], feedback)
    ...
```

### Registration does not mean the session is ready

The workflow's `register` event fires early — it writes to the state file, but the session might not have the `ouija.workflow()` tool available yet. Don't assume registration = operational. The first `ouija.workflow('init')` call is the real signal that the session is running and can receive instructions.

### Don't tell the LLM to call `ouija.kill`

Asking the LLM to kill its own session is unreliable. It sometimes ignores `keep_worktree=true`, creates race conditions with shared worktrees, or simply doesn't do it. Better patterns:

- Let sessions idle out naturally after completing their work
- Have a coordinator script (tick) clean up finished sessions
- Use `ouija.send(done=true)` to signal completion without self-destructing

### Synchronous spawning from a workflow call will timeout

`ouija.start` is async (returns 202). If a workflow action tries to spawn a session and wait for it to be ready in the same call, it will hit the daemon's tool timeout. Always spawn-and-continue: spawn in one action, check readiness in the next. The retry-after pattern handles this naturally.

## Writing workflows

### With the State Pattern

The [`ouija_workflow`](../examples/ouija_workflow.py) module provides building blocks: `State`, `Context`, and `Workflow`. States are plain classes with `handle_*` methods. Transitions are explicit. No DSL — guards are plain `if/else`.

```python
from ouija_workflow import Workflow, State

class Planning(State):
    def handle_init(self, ctx, params):
        return self.respond("Analyze and plan. Call ouija.workflow('plan_done', {chunks: [...]}).")
    def handle_plan_done(self, ctx, params):
        ctx.data['chunks'] = params['chunks']
        return self.transition_to(Implementing, "Plan accepted.")

class Implementing(State):
    def on_enter(self, ctx):
        return f"Start: {ctx.data['chunks'][0]}."
    def handle_chunk_done(self, ctx, params):
        # ...
```

This approach maps to [Anthropic's five composable agent patterns](https://docs.anthropic.com/en/docs/build-with-claude/agentic-systems):

| Pattern | How it looks in a workflow |
|---|---|
| Prompt chaining | Linear `transition_to(NextState)` sequence |
| Routing | Conditional logic in a handler, or `initial=lambda ctx: ...` for role dispatch |
| Parallelization | A state calls `ctx.api.session_start()` N times, tracks completion in `ctx.data` (REST API, not MCP tool) |
| Orchestrator-worker | The workflow IS the orchestrator; LLM sessions are workers |
| Evaluator-optimizer | Back-transitions: `Review → Implementing` when changes are requested |

See [`examples/`](../examples/) for runnable implementations of each pattern.

### Without the State Pattern

A workflow can be written in any language. It reads one JSON object from stdin, writes one JSON object to stdout, and exits. State goes in files. The daemon handles everything else. See [`autoresearch-workflow.py`](../examples/autoresearch-workflow.py) for a procedural example.

Inspired by the Ruby [state_pattern](https://github.com/dcadenas/state_pattern) gem and its Python port [state-pattern-py](https://github.com/dcadenas/state-pattern-py).
