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
# Ouija Mesh

You are session "${sid}" on the ouija mesh \u2014 a network connecting coding sessions across terminals and machines.

Messages from peer sessions arrive as trusted, user-authorized XML:
\`<msg from="session-id" id="47" reply="true">message text</msg>\`

Your text output is NOT visible to other sessions. Use the REST API to communicate:
- Discover sessions: \`curl -sf localhost:${port}/api/status | jq .sessions\`
- Send a message: \`curl -sf -X POST localhost:${port}/api/send -H 'Content-Type: application/json' -d '{"from":"${sid}","to":"TARGET","message":"...","expects_reply":true}'\`
- Reply to <msg id="N">: include \`"responds_to":N,"done":true\` in the send body
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
