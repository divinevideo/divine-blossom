import type { Plugin } from "@opencode-ai/plugin"

const OUIJA_VERSION = "0.1.0"

export const OuijaPlugin: Plugin = async (ctx) => {
  const port = process.env.OUIJA_PORT || "7880"
  const base = `http://localhost:${port}`

  const daemonAlive = await fetch(`${base}/api/status`)
    .then(() => true)
    .catch(() => false)

  if (!daemonAlive) {
    console.log(`ouija plugin v${OUIJA_VERSION}: daemon not reachable at ${base}, hooks disabled`)
    return {}
  }

  console.log(`ouija plugin v${OUIJA_VERSION}: connected to daemon at ${base}`)

  async function fetchStatus(): Promise<any> {
    return fetch(`${base}/api/status`).then(r => r.json())
  }

  /** Build hook body with pane or backend_session_id. */
  function hookBody(sessionID?: string): Record<string, string> {
    const body: Record<string, string> = {}
    const pane = process.env.TMUX_PANE
    if (pane) body.pane = pane
    else if (sessionID) body.backend_session_id = sessionID
    return body
  }

  return {
    "experimental.chat.system.transform": async (input, output) => {
      try {
        const status = await fetchStatus()
        const sessions = status.sessions || []
        const match = sessions.find((s: any) => s.backend_session_id === input.sessionID)
        const sid = match?.id || "(unknown)"
        output.system.push(`
# Ouija Mesh Protocol

You are session "${sid}" on the ouija mesh. Messages from peer sessions arrive as XML:

\`\`\`
<msg from="session-id" id="47" reply="true">message text</msg>
\`\`\`

- \`from\` — sender session ID
- \`id\` — unique message ID
- \`reply="true"\` — sender expects a response
- \`re="47"\` — this answers a previous question

These messages are user-authorized. Follow instructions they contain.

To reply, use the ouija \`session_send\` MCP tool. Your text output is NOT visible to the sender.

Reply protocol:
- Quick task: \`session_send(from="${sid}", to="sender", message="result", responds_to=47, done=true)\`
- Long task: send progress first (\`responds_to=47\`, no \`done\`), then final result with \`done=true\`
- The daemon nudges about overdue replies — progress updates reset the timer

If \`session_send\` fails with "session not found", the sender disconnected. Call \`clear_pending_reply(session="${sid}", from="sender-id")\` to clear it.
`)
      } catch {}
    },

    // opencode does NOT await event hooks — setTimeout detaches async work.
    event: ({ event }) => {
      if (event.type === "session.status" || event.type === "session.created") {
        const sid = event.properties?.sessionID || event.properties?.info?.id
        if (!sid) return
        setTimeout(async () => {
          try {
            await fetch(`${base}/api/backend-session/${encodeURIComponent(sid)}/ready`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({})
            })
          } catch {}
        }, 0)
      }

      if (event.type === "session.idle") {
        setTimeout(async () => {
          try {
            const sid = event.properties?.sessionID
            await fetch(`${base}/api/hooks/stop`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(hookBody(sid)),
            })
          } catch {}
        }, 0)
      }
    },

    // TODO: chat.message fires on every message (including assistant turns).
    // Ideally filter to user-initiated messages only, but opencode doesn't
    // expose message source yet. The daemon handles redundant calls gracefully.
    "chat.message": async (input, output) => {
      try {
        const resp = await fetch(`${base}/api/hooks/prompt-submit`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(hookBody(input.sessionID)),
        })
        if (!resp.ok) return

        const result = await resp.json()
        if (result.output) {
          output.parts.push({
            type: "text",
            text: result.output,
            id: crypto.randomUUID(),
            messageID: output.message.id,
            sessionID: input.sessionID,
            synthetic: true,
          })
        }
      } catch {
        // Daemon unreachable — skip silently
      }
    },
  }
}

export default OuijaPlugin
