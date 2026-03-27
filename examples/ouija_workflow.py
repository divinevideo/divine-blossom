"""
ouija_workflow — Protocol adapter for ouija workflow actors.

Three primitives:
  State    — extends state_pattern.State with ouija protocol dispatch
  Context  — shared persistent data + ouija API client
  Workflow — protocol handler, per-session state dispatch, registration

Built on state-pattern-py (https://github.com/dcadenas/state-pattern-py),
a Python port of the Ruby state_pattern gem. Same philosophy: states are
plain classes, transitions are explicit, guards are plain conditionals. No DSL.

The state_pattern library provides the pure state machine primitives (State,
Stateful, transitions, hooks). This module adds the ouija protocol layer:
stdin/stdout JSON, registration, action dispatch, persistent context.

The key difference from the library's normal usage: workflow actors are
stateless processes (spawned per call, state on disk). States are reconstituted
via Stateful.restore_state() from a JSON file on each invocation.

Usage:
    from ouija_workflow import Workflow, State

    class Planning(State):
        def handle_init(self, ctx, params):
            return self.respond("What's the plan?")
        def handle_plan_done(self, ctx, params):
            ctx.data['plan'] = params['plan']
            return self.transition_to(Implementing, "Let's build it.")

    class Implementing(State):
        ...

    class Done(State):
        terminal = True

    Workflow(
        initial=Planning,
        states=[Planning, Implementing, Done],
        instructions="You are building a feature.",
    ).run()
"""
import fcntl
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from state_pattern import State as _BaseState, Stateful as _Stateful

try:
    import requests
except ImportError:
    requests = None


# ── Result types ──────────────────────────────────────────────────────


@dataclass
class Response:
    """Stay in the current state, send a message to the LLM."""
    message: str
    verify: Optional[str] = None
    done: bool = False


@dataclass
class Transition:
    """Move to another state. Created by State.transition_to()."""
    to: type
    message: str = ""
    verify: Optional[str] = None


# ── Context ───────────────────────────────────────────────────────────


class ApiClient:
    """Minimal ouija REST API client for the async push channel."""

    def __init__(self, base):
        self._base = base.rstrip("/")

    def session_start(self, **kw):
        r = requests.post(f"{self._base}/api/sessions", json=kw, timeout=10)
        r.raise_for_status()
        return r.json()

    def inject(self, session_id, message):
        try:
            requests.post(
                f"{self._base}/api/sessions/{session_id}/inject",
                json={"message": message},
                timeout=5,
            )
        except Exception:
            pass  # best-effort


class Context:
    """Shared state, loaded from JSON at the start of each invocation.

    Properties:
        session_id   — who's calling (from the daemon envelope)
        params       — workflow_params from session_start (persisted at registration)
        data         — shared persistent dict (the workflow's working memory)
        api          — ouija REST API client (inject, session_start)
    """

    def __init__(self, session_id, state_path):
        self.session_id = session_id
        self._path = state_path
        self._fd = None
        self._raw = self._load()

    @property
    def params(self):
        """Registration params (workflow_params from session_start). Per-session."""
        return self._raw.get("session_params", {}).get(self.session_id, {})

    @property
    def data(self):
        """Shared persistent dict — survives across invocations."""
        return self._raw.setdefault("data", {})

    @property
    def api(self):
        if requests is None:
            raise RuntimeError("pip install requests — needed for ouija API calls")
        return ApiClient(os.environ.get("OUIJA_API", "http://127.0.0.1:7880"))

    # -- per-session state tracking --

    def _state_for(self, session_id):
        return self._raw.get("sessions", {}).get(session_id, {}).get("state")

    def _set_state(self, session_id, name):
        self._raw.setdefault("sessions", {}).setdefault(session_id, {})["state"] = name

    # -- persistence with file locking --

    def _load(self):
        if self._path.exists():
            self._fd = open(self._path, "r+")
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                return json.load(self._fd)
            except json.JSONDecodeError:
                return {}
        return {}

    def _save(self):
        self._path.write_text(json.dumps(self._raw, indent=2))
        if self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None


# ── State ─────────────────────────────────────────────────────────────


class State(_BaseState):
    """Ouija workflow state — extends state_pattern.State with protocol dispatch.

    The state_pattern library provides the state machine primitives (terminal
    flag, stateful reference, subclass discovery). This class adds the ouija
    protocol layer: action dispatch, response types, context-aware lifecycle.
    """

    def enter(self):
        # state_pattern calls this on instantiation; ouija manages lifecycle
        # explicitly via on_enter(ctx) so this is a no-op.
        pass

    def exit(self):
        # Same — ouija calls on_exit(ctx) explicitly during transition processing.
        pass

    def on_enter(self, ctx):
        """Called once when entering this state. Return a message or None."""
        return None

    def on_exit(self, ctx):
        """Called once when leaving this state."""
        pass

    def handle(self, ctx, action, params):
        """Dispatch to handle_{action}. Override for custom dispatch."""
        handler = getattr(self, f"handle_{action}", None)
        if not handler:
            avail = [m[7:] for m in dir(self) if m.startswith("handle_") and m != "handle"]
            return Response(
                f"Unknown action '{action}' in state {type(self).__name__}. "
                f"Available: {', '.join(avail)}"
            )
        return handler(ctx, params)

    # -- convenience methods for handlers --

    def respond(self, message, verify=None):
        """Stay in current state, send a message back to the LLM."""
        return Response(message=message, verify=verify)

    def transition_to(self, state_cls, message="", verify=None):
        """Move to another state. on_exit fires here, on_enter fires there."""
        return Transition(to=state_cls, message=message, verify=verify)

    def done(self, message="Workflow complete."):
        """Signal workflow completion."""
        return Response(message=message, done=True)


# ── Workflow ──────────────────────────────────────────────────────────


class Workflow:
    """The state machine. Reads stdin JSON, dispatches to states, writes stdout JSON.

    Args:
        initial:         State class, or callable(ctx) -> State class for role-based routing
        states:          list of all State classes in this workflow
        instructions:    registration instructions (Level 2 context)
        inject_on_start: text injected when the session starts
        max_calls:       daemon-enforced call budget
        state_file:      path to the JSON state file
    """

    def __init__(
        self,
        initial,
        states,
        instructions="",
        inject_on_start="Call ouija.workflow('init') to begin.",
        max_calls=200,
        state_file="workflow-state.json",
    ):
        self.initial = initial
        self._states = states  # restore_state discovers via subclass tree
        self.instructions = instructions
        self.inject_on_start = inject_on_start
        self.max_calls = max_calls
        self.state_file = state_file

    def run(self):
        """Entry point. Read stdin, dispatch, write stdout."""
        envelope = json.loads(sys.stdin.read())
        event = envelope.get("event")
        if event:
            result = self._on_event(event, envelope)
        else:
            result = self._on_action(envelope)
        print(json.dumps(result))

    # -- override these for custom behavior --

    def on_register(self, session_id, params):
        """Override for role-based instructions or custom registration."""
        return {
            "instructions": self.instructions,
            "inject_on_start": self.inject_on_start,
            "max_calls": self.max_calls,
        }

    def on_lifecycle(self, event, session_id):
        """Override to handle session_died / session_restarted."""
        pass

    # -- internals --

    def _on_event(self, event, envelope):
        sid = envelope.get("session_id", "")
        params = envelope.get("params") or {}
        if event == "register":
            # Persist workflow_params per-session so ctx.params works at runtime
            path = Path(self.state_file)
            raw = json.loads(path.read_text()) if path.exists() else {}
            raw.setdefault("session_params", {})[sid] = params
            path.write_text(json.dumps(raw, indent=2))
            return self.on_register(sid, params)
        if event in ("session_died", "session_restarted"):
            self.on_lifecycle(event, sid)
        return {}

    def _resolve_initial(self, ctx):
        if callable(self.initial) and not isinstance(self.initial, type):
            return self.initial(ctx)
        return self.initial

    def _on_action(self, envelope):
        ctx = Context(
            session_id=envelope.get("session_id", ""),
            state_path=Path(self.state_file),
        )

        # Create a Stateful machine and restore the current state from disk
        machine = _Stateful()

        state_name = ctx._state_for(ctx.session_id)
        if not state_name:
            initial_cls = self._resolve_initial(ctx)
            state_name = initial_cls.__name__

        try:
            machine.restore_state(state_name)
        except ValueError:
            ctx._save()
            return {"error": f"Unknown state: {state_name}"}

        state = machine.current_state_instance
        action = envelope.get("action", "init")
        params = envelope.get("params") or {}
        result = state.handle(ctx, action, params)

        # -- Transition --
        if isinstance(result, Transition):
            state.on_exit(ctx)
            new_name = result.to.__name__
            try:
                machine.restore_state(new_name)
            except ValueError:
                ctx._save()
                return {"error": f"Bad transition target: {new_name}"}

            new_state = machine.current_state_instance
            ctx._set_state(ctx.session_id, machine.state_name)
            enter_msg = new_state.on_enter(ctx)

            msg = result.message
            if enter_msg:
                msg = f"{msg}\n\n{enter_msg}" if msg else enter_msg

            ctx._save()
            resp = {"message": msg}
            if result.verify:
                resp["verify"] = result.verify
            return resp

        # -- Response (stay in state) --
        ctx._set_state(ctx.session_id, state_name)
        ctx._save()
        resp = {"message": result.message}
        if result.verify:
            resp["verify"] = result.verify
        if result.done:
            resp["done"] = True
        return resp
