# Workflow Examples

## ouija_workflow.py — State Pattern building blocks

The shared library that the examples below import. Three primitives:

- **State** — subclass, add `handle_*` methods, call `respond()` or `transition_to()`
- **Context** — persistent data dict + ouija REST API client
- **Workflow** — protocol handler, per-session state dispatch, registration

Inspired by the Ruby [state_pattern](https://github.com/dcadenas/state_pattern) gem and its Python port [state-pattern-py](https://github.com/dcadenas/state-pattern-py). Same philosophy: states are plain classes, transitions are explicit, guards are plain conditionals. No DSL.

## Examples

### simple-loop-workflow.py

**Pattern:** Evaluator-optimizer (single session)

An optimization loop. The LLM iterates: make one change, measure, report. The workflow commits improvements and reverts regressions.

```
session_start(
    name="optimizer",
    workflow="examples/simple-loop-workflow.py",
    workflow_params={"max_iterations": 10},
    prompt="Read INSTRUCTIONS.md for your optimization target.",
    project_dir="/path/to/project",
)
```

States: `Running → Done`

Your project directory needs an **INSTRUCTIONS.md** describing what to optimize and how to measure it, plus a git repo with a clean working tree.

### feature-workflow.py

**Pattern:** Prompt chaining (linear state sequence)

A structured implementation workflow that guides the LLM through planning, chunked implementation with build verification, and final test verification.

```
session_start(
    name="feat-1",
    workflow="examples/feature-workflow.py",
    workflow_params={"issue": "Add rate limiting to /api/upload"},
    prompt="You are implementing a feature. Call workflow('init') to start.",
    project_dir="/path/to/project",
)
```

States: `Planning → Implementing → Verifying → Done`

Demonstrates progressive disclosure — the LLM learns about each phase only when it arrives there. Planning never mentions chunks or verification.

### review-workflow.py

**Pattern:** Evaluator-optimizer (multi-session with back-transitions)

Two sessions share one workflow: a worker implements, a reviewer approves or requests changes. Uses the async push channel (REST API inject) to notify sessions without polling.

```
# Worker
session_start(
    name="feat-worker",
    workflow="examples/review-workflow.py",
    workflow_params={"role": "worker", "issue": "Add caching layer"},
    prompt="Implement the feature. Call workflow('init').",
    project_dir="/path/to/project",
)

# Reviewer
session_start(
    name="feat-reviewer",
    workflow="examples/review-workflow.py",
    workflow_params={"role": "reviewer", "worker_session": "feat-worker"},
    prompt="Review code changes. Call workflow('init').",
    project_dir="/path/to/project",
)
```

States (worker): `WorkerImpl → WorkerWaiting → (back to WorkerImpl on rejection)`
States (reviewer): `Reviewing → ReviewerDone`

Demonstrates role-based dispatch (`initial=lambda ctx: ...`), multi-session shared state, and back-transitions.

### autoresearch-workflow.py

The original procedural implementation of the optimization loop — same behavior as `simple-loop-workflow.py` but without the State Pattern library. Useful for comparison or as a template for workflows that don't need the state pattern abstraction.

## Anthropic's five patterns mapped to building blocks

| Pattern | Example | How it works |
|---|---|---|
| **Prompt chaining** | feature-workflow.py | Linear `transition_to(NextState)` sequence |
| **Routing** | review-workflow.py | `pick_initial(ctx)` dispatches by role |
| **Parallelization** | (compose with REST API) | State calls `ctx.api.session_start()` N times |
| **Orchestrator-worker** | review-workflow.py | The workflow IS the orchestrator; sessions are workers |
| **Evaluator-optimizer** | review-workflow.py | Back-transitions: `WorkerWaiting → WorkerImpl` |

## Writing your own workflow

### With ouija_workflow (State Pattern)

```python
#!/usr/bin/env python3
from ouija_workflow import Workflow, State

class MyState(State):
    def handle_init(self, ctx, params):
        return self.respond("Do the thing. Call workflow('done_it').")

    def handle_done_it(self, ctx, params):
        return self.transition_to(Finished, "Nice work.")

class Finished(State):
    terminal = True
    def on_enter(self, ctx):
        return "Call session_send(done=true)."

Workflow(
    initial=MyState,
    states=[MyState, Finished],
    instructions="You have a workflow. Follow its instructions.",
).run()
```

### Without ouija_workflow (raw protocol)

A workflow is any executable that reads one JSON object from stdin and writes one JSON object to stdout. See `autoresearch-workflow.py` for a full example. The protocol:

**Registration** (daemon calls at session start):
```json
// stdin
{"event": "register", "session_id": "worker-1", "params": {"issue_id": 123}}
// stdout
{"instructions": "You are a worker...", "inject_on_start": "Call workflow('init').", "max_calls": 200}
```

**Runtime** (LLM calls workflow tool):
```json
// stdin
{"action": "chunk_done", "session_id": "worker-1", "params": {"chunk": "auth"}}
// stdout
{"message": "Tests pass. Next: implement logging.", "verify": "cargo test --lib logging passes"}
```

**Lifecycle** (daemon notifies on session death/restart):
```json
// stdin
{"event": "session_died", "session_id": "worker-1"}
// stdout
{}
```

### Progressive disclosure: three levels of context

| Level | What | When loaded | Purpose |
|---|---|---|---|
| 1. Tool description | The `workflow` MCP tool | Always in context | LLM knows the tool exists |
| 2. Registration instructions | `instructions` from register | Session start | Orients — purpose, rhythm, constraints |
| 3. Runtime responses | Each `workflow()` return | On demand | Directs — current state, next task, criteria |

Don't bleed between levels. If you're putting step-specific detail in registration instructions, move it to a runtime response.
