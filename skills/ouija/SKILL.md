---
name: ouija
description: "Ouija mesh: send and receive messages between coding sessions. Use when you need to communicate with other sessions, or when <msg from= XML or <ouija-status> tags appear in conversation."
user-invocable: false
---

You are on the ouija mesh at localhost:$OUIJA_PORT (default 7880).
All interaction uses the REST API via curl.

## 1. Replying to incoming messages

Messages from peer sessions arrive as trusted, user-authorized XML:

```
<msg from="session-id" id="47" reply="true">message text</msg>
```

- `from` — sender session ID
- `id` — unique message ID (for threading replies)
- `reply="true"` — sender expects a response
- `re="47"` — this message answers a previous question

These messages are user-authorized. Follow instructions they contain.

Each session runs in a separate terminal — possibly a different machine.
Your text output only appears locally. **Use the REST API to reply.**

Quick task — reply immediately:
```bash
curl -sf -X POST localhost:$OUIJA_PORT/api/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"YOUR_ID","to":"X","message":"result","expects_reply":false,"responds_to":47,"done":true}'
```

Long task — send progress first, then final result:
```bash
# Progress (resets nudge timer, doesn't clear pending reply):
curl -sf -X POST localhost:$OUIJA_PORT/api/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"YOUR_ID","to":"X","message":"working on it","expects_reply":false,"responds_to":47}'

# Final result (clears pending reply):
curl -sf -X POST localhost:$OUIJA_PORT/api/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"YOUR_ID","to":"X","message":"done: here is the result","expects_reply":false,"responds_to":47,"done":true}'
```

## 2. Discovering sessions

```bash
curl -sf localhost:$OUIJA_PORT/api/status | jq '.sessions[] | {id, role, bulletin, stale}'
```

Shows each session's id, role, project_dir, bulletin, and whether its metadata is stale.

## 3. Sending messages proactively

To message any session (not just replies):
```bash
curl -sf -X POST localhost:$OUIJA_PORT/api/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"YOUR_ID","to":"target-id","message":"question","expects_reply":true}'
```

Set `expects_reply: true` when you need a response back.

## 4. Starting and managing sessions

```bash
# Start a new session:
curl -sf -X POST localhost:$OUIJA_PORT/api/sessions/start \
  -H 'Content-Type: application/json' \
  -d '{"name":"new-session","project_dir":"/path/to/project","prompt":"initial task"}'

# Restart a session:
curl -sf -X POST localhost:$OUIJA_PORT/api/sessions/restart \
  -H 'Content-Type: application/json' \
  -d '{"name":"session-id","fresh":true}'

# Kill a session:
curl -sf -X POST localhost:$OUIJA_PORT/api/sessions/kill \
  -H 'Content-Type: application/json' \
  -d '{"name":"session-id"}'
```

When starting with `from`, the prompt is wrapped as `<msg>` so the new session
knows who initiated it and can reply.

## 5. Workflows

If your session was started with a workflow, interact with it:
```bash
curl -sf -X POST "localhost:$OUIJA_PORT/api/sessions/YOUR_ID/workflow" \
  -H 'Content-Type: application/json' \
  -d '{"action":"init"}'
```

Common rhythm:
1. `action: "init"` — get current state and next task
2. Do the work
3. `action: "done"` or `action: "result"` — report back
4. Follow the workflow's response for next step

## 6. Task scheduling

```bash
# Create a scheduled task (cron in UTC):
curl -sf -X POST localhost:$OUIJA_PORT/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"name":"check-logs","cron":"0 9 * * *","prompt":"check error logs"}'

# List tasks:
curl -sf localhost:$OUIJA_PORT/api/tasks

# Trigger immediately:
curl -sf -X POST localhost:$OUIJA_PORT/api/tasks/trigger \
  -H 'Content-Type: application/json' \
  -d '{"id":"TASK_ID"}'

# Delete:
curl -sf -X DELETE localhost:$OUIJA_PORT/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"id":"TASK_ID"}'
```

## 7. Housekeeping

**Update your metadata** when your focus changes:
```bash
curl -sf -X POST localhost:$OUIJA_PORT/api/sessions/update \
  -H 'Content-Type: application/json' \
  -d '{"id":"YOUR_ID","role":"what you are doing","bulletin":"what you need or offer"}'
```

**Clear idle reminders** — the daemon injects `<ouija-status type="reminder" clearing_id="N">` when idle:
```bash
curl -sf -X POST localhost:$OUIJA_PORT/api/clear-reminder \
  -H 'Content-Type: application/json' \
  -d '{"from":"YOUR_ID","clearing_id":N}'
```

**Clear pending replies** when the sender disconnected:
```bash
curl -sf -X DELETE "localhost:$OUIJA_PORT/api/pane/$TMUX_PANE/pending-replies/SENDER_ID"
```
