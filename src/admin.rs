use axum::extract::State;
use axum::response::Html;
use chrono::{DateTime, Utc};

use crate::daemon_protocol::{Origin, SessionEntry};
use crate::state::SharedState;

/// Format a timestamp as `HH:MM:SS` with the full date in a `title` tooltip.
fn time_with_date(dt: &DateTime<Utc>) -> String {
    format!(
        r#"<span title="{}">{}</span>"#,
        dt.format("%Y-%m-%d %H:%M:%S UTC"),
        dt.format("%H:%M:%S"),
    )
}

/// Render the dashboard HTML page.
pub async fn dashboard(State(state): State<SharedState>) -> Html<String> {
    let proto = state.protocol.read().await;
    let sessions = &proto.sessions;
    let nodes = state.nodes.read().await;
    let log = state.message_log.read().await;
    let transports = state.transports().await;
    let settings = state.settings.read().await;
    let scheduled_tasks = state.scheduled_tasks.read().await;
    let task_runs = state.task_runs.read().await;

    let any_ready = transports.values().any(|t| t.is_ready());

    let msg_count = log.len();
    let task_count = scheduled_tasks.len();
    let task_run_count = task_runs.len();

    let mut local_sessions: Vec<_> = sessions
        .values()
        .filter(|s| matches!(s.origin, Origin::Local))
        .collect();
    local_sessions.sort_by_key(|s| &s.id);

    let mut remote_sessions: Vec<_> = sessions
        .values()
        .filter(|s| matches!(s.origin, Origin::Remote(_)))
        .collect();
    remote_sessions.sort_by_key(|s| &s.id);

    let local_count = local_sessions.len();
    let remote_count = remote_sessions.len();
    let human_count = settings.human_sessions.len();

    let all_networked = local_sessions.iter().all(|s| s.metadata.networked);

    let mut sessions_html = String::new();
    for s in &local_sessions {
        let escaped_id = html_escape(&s.id);
        let pane = s.pane.as_deref().unwrap_or("--");
        let role = s.metadata.role.as_deref().unwrap_or("--");
        let mut details = Vec::new();
        if let Some(ref dir) = s.metadata.project_dir {
            details.push(format!("dir: {}", html_escape(dir)));
        }
        if s.metadata.worktree {
            details.push("worktree".to_string());
        }
        if s.metadata.vim_mode {
            details.push("vim".to_string());
        }
        if let Some(ref b) = s.metadata.bulletin {
            details.push(format!("bulletin: {}", html_escape(b)));
        }
        if s.metadata.iteration > 0 {
            details.push(format!("loop: iteration {}", s.metadata.iteration));
        }
        if let Some(ref reminder) = s.metadata.reminder {
            let truncated = if reminder.len() > 80 {
                &reminder[..80]
            } else {
                reminder
            };
            details.push(format!("reminder: {}", html_escape(truncated)));
        }
        let details_html = if details.is_empty() {
            String::new()
        } else {
            format!("<br><small class=\"dim\">{}</small>", details.join(" · "))
        };
        let time = if s.registered_at > 0 {
            let dt = DateTime::from_timestamp(s.registered_at, 0).unwrap_or_default();
            time_with_date(&dt)
        } else {
            "N/A".to_string()
        };
        let networked_checked = if s.metadata.networked { "checked" } else { "" };
        let actions = format!(
            r#"<button class="btn-sm" onclick="renameSession('{id}')">rename</button> <button class="btn-sm btn-danger" onclick="removeSession('{id}')">remove</button>"#,
            id = html_escape(&s.id)
        );
        sessions_html.push_str(&format!(
            "<tr><td class=\"id-cell\">{escaped_id}</td><td>{pane}</td><td class=\"msg-cell\">{role}{details_html}</td><td style=\"text-align:center;\"><input type=\"checkbox\" {networked_checked} onchange=\"updateSessionNetworked('{id}', this.checked)\"></td><td class=\"dim\">{time}</td><td>{actions}</td></tr>",
            id = html_escape(&s.id),
            role = html_escape(role),
        ));
    }
    if local_sessions.is_empty() {
        sessions_html.push_str(
            r#"<tr><td colspan="6" class="empty">No local sessions. Open a coding session in tmux and say <b>"register me as web"</b></td></tr>"#,
        );
    }

    // Group remote sessions by node name, keeping full session data for tooltips
    let mut remote_by_node: std::collections::BTreeMap<String, Vec<(&str, &SessionEntry)>> =
        std::collections::BTreeMap::new();
    for s in &remote_sessions {
        let (node_name, session_name) = s.id.split_once('/').unwrap_or(("unknown", s.id.as_str()));
        remote_by_node
            .entry(node_name.to_string())
            .or_default()
            .push((session_name, s));
    }

    let mut remote_grouped_html = String::new();
    if remote_by_node.is_empty() {
        remote_grouped_html
            .push_str(r#"<div class="empty">No remote sessions. Connect a node below.</div>"#);
    } else {
        for (node_name, session_entries) in &remote_by_node {
            let node_info = nodes.values().find(|n| &n.name == node_name);
            let connected_at = node_info
                .map(|n| time_with_date(&n.connected_at))
                .unwrap_or_default();
            let daemon_id = node_info.map(|n| n.daemon_id.as_str()).unwrap_or_default();
            remote_grouped_html.push_str(&format!(
                r#"<div class="node-group">
<div class="node-group-header">
  <span class="id-cell">{name}</span>
  <span class="dim" style="margin-left:auto;">{connected_at}</span>
  <button class="btn-sm btn-danger" onclick="disconnectNode('{daemon_id}', '{name}')">disconnect</button>
</div>
<div class="chip-list">"#,
                name = html_escape(node_name),
                daemon_id = html_escape(daemon_id),
            ));
            for (sname, sess) in session_entries {
                let mut tooltip_parts = Vec::new();
                if let Some(role) = &sess.metadata.role {
                    tooltip_parts.push(format!("role: {role}"));
                }
                if let Some(dir) = &sess.metadata.project_dir {
                    tooltip_parts.push(format!("dir: {dir}"));
                }
                let tooltip = if tooltip_parts.is_empty() {
                    String::new()
                } else {
                    format!(r#" title="{}""#, html_escape(&tooltip_parts.join("\n")))
                };
                remote_grouped_html.push_str(&format!(
                    r#"<span class="chip"{tooltip}>{}</span>"#,
                    html_escape(sname)
                ));
            }
            remote_grouped_html.push_str("</div></div>");
        }
    }

    // --- Nostr DM Access ---
    let mut humans_html = String::new();
    for h in &settings.human_sessions {
        let default_sess = h.default_session.as_deref().unwrap_or("--");
        humans_html.push_str(&format!(
            r#"<tr><td class="id-cell">{name}</td><td class="dim" style="font-size:11px;">{npub}</td><td>{default_sess}</td><td><button class="btn-sm btn-danger" onclick="removeHuman('{name}')">remove</button></td></tr>"#,
            name = html_escape(&h.name),
            npub = html_escape(&truncate_npub(&h.npub)),
            default_sess = html_escape(default_sess),
        ));
    }
    if settings.human_sessions.is_empty() {
        humans_html.push_str(
            r#"<tr><td colspan="4" class="empty">No Nostr DM users. Add one below or use <b>ouija config add-human</b></td></tr>"#,
        );
    }

    // --- Scheduled Tasks ---
    let mut tasks_html = String::new();
    let mut sorted_tasks: Vec<_> = scheduled_tasks.values().collect();
    sorted_tasks.sort_by_key(|t| &t.created_at);
    for t in &sorted_tasks {
        let enabled_checked = if t.enabled { "checked" } else { "" };
        let next = t.next_run.map_or("--".into(), |dt| time_with_date(&dt));
        let last = t.last_run.map_or("--".into(), |dt| time_with_date(&dt));
        let status = t.last_status.as_ref().map_or("--", |s| match s {
            crate::scheduler::TaskRunStatus::Ok => "ok",
            crate::scheduler::TaskRunStatus::Failed => "failed",
        });
        let status_class = match t.last_status.as_ref() {
            Some(crate::scheduler::TaskRunStatus::Ok) => "status-ok",
            Some(crate::scheduler::TaskRunStatus::Failed) => "status-fail",
            None => "dim",
        };
        let mut task_flags = Vec::new();
        if let Some(ref dir) = t.project_dir {
            task_flags.push(format!("dir: {}", html_escape(dir)));
        }
        match &t.on_fire {
            crate::scheduler::OnFire::ContinueSession => {}
            crate::scheduler::OnFire::NewSession => {
                task_flags.push("new session each fire".to_string());
            }
            crate::scheduler::OnFire::PersistentWorktree { clear_context } => {
                if *clear_context {
                    task_flags.push("persistent worktree, clear context".to_string());
                } else {
                    task_flags.push("persistent worktree".to_string());
                }
            }
            crate::scheduler::OnFire::DisposableWorktree => {
                task_flags.push("disposable worktree".to_string());
            }
        }
        if t.once {
            task_flags.push("once".to_string());
        }
        let task_details = if task_flags.is_empty() {
            String::new()
        } else {
            format!(
                "<br><small class=\"dim\">{}</small>",
                task_flags.join(" · ")
            )
        };
        let msg_preview = if let Some(ref prompt) = t.prompt {
            let preview = if prompt.len() > 50 {
                format!("{}…", html_escape(&prompt[..50]))
            } else {
                html_escape(prompt)
            };
            format!("<br><small class=\"dim\">prompt: {preview}</small>")
        } else {
            String::new()
        };
        tasks_html.push_str(&format!(
            r#"<tr>
<td class="id-cell">{id}</td>
<td>{name}{task_details}{msg_preview}</td>
<td class="dim">{cron}</td>
<td>{target}</td>
<td style="text-align:center;"><input type="checkbox" {enabled_checked} onchange="this.checked ? enableTask('{id}') : disableTask('{id}')"></td>
<td class="dim">{next}</td>
<td class="dim">{last}</td>
<td class="{status_class}">{status}</td>
<td>{run_count}</td>
<td>
  <button class="btn-sm" onclick="triggerTask('{id}')">trigger</button>
  <button class="btn-sm btn-danger" onclick="deleteTask('{id}')">delete</button>
</td>
</tr>"#,
            id = html_escape(&t.id),
            name = html_escape(&t.name),
            cron = html_escape(&t.cron),
            target = html_escape(t.target_session.as_deref().unwrap_or("—")),
            run_count = t.run_count,
        ));
    }
    if sorted_tasks.is_empty() {
        tasks_html.push_str(
            r#"<tr><td colspan="10" class="empty">No scheduled tasks.<br>CLI: <b>ouija task add "check-logs" "0 9 * * *" "check the error logs"</b><br>MCP: use the <b>task_create</b> tool from any coding session</td></tr>"#,
        );
    }

    let mut task_runs_html = String::new();
    for r in task_runs.iter().rev().take(20) {
        let status_class = match r.status {
            crate::scheduler::TaskRunStatus::Ok => "status-ok",
            crate::scheduler::TaskRunStatus::Failed => "status-fail",
        };
        let status_text = match r.status {
            crate::scheduler::TaskRunStatus::Ok => "ok",
            crate::scheduler::TaskRunStatus::Failed => "failed",
        };
        let error = r.error.as_deref().unwrap_or("");
        task_runs_html.push_str(&format!(
            "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td class=\"{status_class}\">{status_text}</td><td class=\"msg-cell\">{}</td></tr>",
            time_with_date(&r.timestamp),
            html_escape(&r.task_name),
            html_escape(&r.session_name),
            html_escape(error),
        ));
    }
    if task_runs.is_empty() {
        task_runs_html.push_str(r#"<tr><td colspan="5" class="empty">No task runs yet.</td></tr>"#);
    }

    let mut log_html = String::new();
    for entry in log.iter().rev().take(50) {
        let (status_icon, status_class) = if entry.delivered {
            ("&#10003;", "status-ok")
        } else {
            ("&#10007;", "status-fail")
        };
        log_html.push_str(&format!(
            "<tr><td class=\"dim\">{}</td><td>{}</td><td>{}</td><td class=\"msg-cell\">{}</td><td class=\"{status_class}\">{status_icon}</td></tr>",
            time_with_date(&entry.timestamp),
            html_escape(&entry.from),
            html_escape(&entry.to),
            html_escape(&entry.message),
        ));
    }

    let p2p_status = if any_ready {
        let names: Vec<&str> = transports
            .values()
            .filter(|t| t.is_ready())
            .map(|t| t.transport_name())
            .collect();
        format!(
            r#"<span class="dot dot-on"></span> P2P ready <span class="dim">({})</span>"#,
            html_escape(&names.join(", "))
        )
    } else {
        r#"<span class="dot dot-off"></span> P2P initializing..."#.to_string()
    };

    let log_empty = if msg_count == 0 {
        r#"<tr><td colspan="5" class="empty">No messages yet. Send one with <b>session_send</b> from a coding session.</td></tr>"#
    } else {
        ""
    };

    let saved_relays = crate::nostr_transport::load_relays(&state.config.data_dir);
    let saved_relays_json = serde_json::to_string(&saved_relays).unwrap_or_else(|_| "[]".into());
    let default_relay = saved_relays.first().cloned().unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ouija — {name}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔮</text></svg>">
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@500;700&display=swap');

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  background: #0c0e14;
  color: #c4c9d4;
  min-height: 100vh;
}}

.shell {{
  max-width: 960px;
  margin: 0 auto;
  padding: 24px 32px 48px;
}}

/* --- Header bar --- */
.header {{
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  border-bottom: 1px solid #1e2230;
  padding-bottom: 16px;
  margin-bottom: 24px;
}}

.header h1 {{
  font-family: 'DM Sans', sans-serif;
  font-size: 22px;
  font-weight: 700;
  color: #e8ecf1;
  letter-spacing: -0.5px;
}}

.header h1 span {{
  color: #3ecf8e;
}}

.status-bar {{
  display: flex;
  gap: 20px;
  font-size: 11px;
  color: #6b7280;
}}

.status-bar .item {{
  display: flex;
  align-items: center;
  gap: 6px;
}}

.dot {{
  width: 7px;
  height: 7px;
  border-radius: 50%;
  display: inline-block;
}}

.dot-on {{
  background: #3ecf8e;
  box-shadow: 0 0 6px #3ecf8e88;
}}

.dot-off {{
  background: #f59e0b;
  animation: pulse 1.5s ease-in-out infinite;
}}

@keyframes pulse {{
  0%, 100% {{ opacity: 1; }}
  50% {{ opacity: 0.4; }}
}}

/* --- Sections --- */
.section {{
  margin-bottom: 28px;
}}

.section-head {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  cursor: pointer;
  user-select: none;
}}

.section-head:hover h2 {{
  color: #c4c9d4;
}}

.section-head h2 {{
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  font-weight: 700;
  color: #8b93a1;
  text-transform: uppercase;
  letter-spacing: 1.2px;
  transition: color 0.15s;
}}

.section-head .toggle {{
  font-size: 10px;
  color: #4b5263;
  transition: transform 0.2s;
}}

.section-head .toggle.open {{
  transform: rotate(90deg);
}}

.section-body {{
  transition: max-height 0.25s ease, opacity 0.2s ease;
}}

.section-body.collapsed {{
  max-height: 0 !important;
  opacity: 0;
  overflow: hidden;
}}

.section-body.animating {{
  overflow: hidden;
}}

.count {{
  font-size: 11px;
  color: #3ecf8e;
  background: #3ecf8e15;
  padding: 1px 7px;
  border-radius: 8px;
}}

.count-zero {{
  color: #4b5263;
  background: #4b526315;
}}

/* --- Tables --- */
table {{
  width: 100%;
  border-collapse: collapse;
}}

th {{
  font-size: 11px;
  font-weight: 600;
  color: #4b5263;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  text-align: left;
  padding: 6px 12px;
  border-bottom: 1px solid #1e2230;
}}

td {{
  padding: 7px 12px;
  border-bottom: 1px solid #13151d;
}}

tr:hover td {{
  background: #12141c;
}}

.id-cell {{
  color: #e8ecf1;
  font-weight: 600;
}}

.dim {{
  color: #4b5263;
}}

.btn-sm {{
  font-size: 11px;
  padding: 2px 8px;
  background: #1e2230;
  color: #6b7280;
  border: 1px solid #2e3340;
  border-radius: 3px;
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
}}

.btn-sm:hover {{
  background: #262b3a;
  color: #c4c9d4;
}}

.btn-danger:hover {{
  background: #3b1c1c;
  color: #ef4444;
  border-color: #ef444444;
}}

.msg-cell {{
  max-width: 340px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #9ca3af;
}}

.empty {{
  color: #3e4451;
  font-style: italic;
  padding: 16px 12px;
  text-align: center;
}}

.empty b {{
  color: #6b7280;
  font-style: normal;
}}

/* --- Badges --- */
.badge {{
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
}}

.badge-local {{
  color: #3ecf8e;
  background: #3ecf8e12;
  border: 1px solid #3ecf8e30;
}}

.badge-remote {{
  color: #818cf8;
  background: #818cf812;
  border: 1px solid #818cf830;
}}

/* --- Status icons --- */
.status-ok {{
  color: #3ecf8e;
  text-align: center;
}}

.status-fail {{
  color: #ef4444;
  text-align: center;
}}

/* --- Node groups (remote sessions) --- */
.node-group {{
  background: #11131a;
  border: 1px solid #1e2230;
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 8px;
}}

.node-group-header {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}}

.chip-list {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}}

.chip {{
  font-size: 11px;
  padding: 3px 10px;
  background: #1a1d28;
  border: 1px solid #252936;
  border-radius: 4px;
  color: #9ca3af;
}}

.chip:hover {{
  background: #22263a;
  color: #c4c9d4;
  border-color: #3e4451;
}}

/* --- Pairing --- */
.pairing {{
  background: #11131a;
  border: 1px solid #1e2230;
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 28px;
}}

.pairing h2 {{
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  font-weight: 700;
  color: #8b93a1;
  text-transform: uppercase;
  letter-spacing: 1.2px;
  margin-bottom: 10px;
}}

.pairing .warn {{
  font-size: 11px;
  color: #f59e0b;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 6px;
}}

.ticket-value {{
  word-break: break-all;
  font-size: 11px;
  color: #6b7280;
  line-height: 1.5;
  margin-bottom: 10px;
}}

.ticket-actions {{
  display: flex;
  gap: 8px;
}}

.connect-row {{
  display: flex;
  gap: 8px;
  margin-top: 12px;
}}

.connect-row input {{
  flex: 1;
  background: #0c0e14;
  color: #c4c9d4;
  border: 1px solid #1e2230;
  border-radius: 4px;
  padding: 7px 10px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  outline: none;
  transition: border-color 0.15s;
}}

.connect-row input:focus {{
  border-color: #3e4451;
}}

.connect-row input::placeholder {{
  color: #2e3340;
}}

.connect-row button {{
  background: #1e2230;
  color: #c4c9d4;
  border: 1px solid #2e3340;
  border-radius: 4px;
  padding: 7px 16px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
  white-space: nowrap;
}}

.connect-row button:hover {{
  background: #262b3a;
  border-color: #3e4451;
}}

#connect-result {{
  font-size: 12px;
  margin-top: 8px;
  min-height: 18px;
}}

.label {{
  font-size: 11px;
  color: #4b5263;
  margin-bottom: 4px;
}}

/* --- Relay config --- */
.relay-config {{
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #1e2230;
}}

.relay-header {{
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 10px;
}}

.relay-label {{
  font-size: 11px;
  font-weight: 600;
  color: #8b93a1;
  text-transform: uppercase;
  letter-spacing: 0.8px;
}}

.relay-item {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 0;
}}

.relay-item code {{
  font-size: 12px;
  color: #9ca3af;
  flex: 1;
}}

.relay-item .btn-sm {{
  opacity: 0.5;
  transition: opacity 0.15s;
}}

.relay-item:hover .btn-sm {{
  opacity: 1;
}}

/* --- Tooltips --- */
.tip {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 14px;
  height: 14px;
  font-size: 9px;
  font-weight: 700;
  color: #3e4451;
  border: 1px solid #2e3340;
  border-radius: 50%;
  cursor: help;
  position: relative;
  vertical-align: middle;
  margin-left: 4px;
  transition: color 0.15s, border-color 0.15s;
  flex-shrink: 0;
}}

.tip:hover {{
  color: #8b93a1;
  border-color: #4b5263;
}}

.tip::after {{
  content: attr(data-tip);
  position: absolute;
  top: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%) scale(0.96);
  background: #1a1d28;
  color: #c4c9d4;
  border: 1px solid #2e3340;
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 11px;
  font-weight: 400;
  line-height: 1.5;
  white-space: normal;
  text-transform: none;
  letter-spacing: 0;
  width: max-content;
  max-width: 260px;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s, transform 0.15s;
  z-index: 100;
  box-shadow: 0 4px 16px rgba(0,0,0,0.5);
}}

.tip:hover::after {{
  opacity: 1;
  transform: translateX(-50%) scale(1);
}}

/* Right-aligned tooltip (for elements near right edge) */
.tip-right::after {{
  left: auto;
  right: 0;
  transform: scale(0.96);
}}

.tip-right:hover::after {{
  transform: scale(1);
}}

/* --- Section subtitles --- */
.section-sub {{
  font-size: 11px;
  color: #3e4451;
  margin-left: auto;
  font-weight: 400;
  letter-spacing: 0;
  text-transform: none;
}}
</style>
</head>
<body>
<div class="shell">

<div class="header">
  <h1><span>ouija</span> / {name}</h1>
  <div class="status-bar">
    <div class="item">{p2p_status}</div>
    <div class="item"><span class="dim">port</span> {port}</div>
    <div class="item"><span class="dim">npub</span> <code style="font-size:11px;background:#1e2230;padding:2px 6px;border-radius:3px;">{daemon_npub_short}</code> <button class="btn-sm" onclick="navigator.clipboard.writeText('{daemon_npub}');this.textContent='copied!';setTimeout(()=>this.textContent='copy',1500)" style="font-size:10px;">copy</button></div>
  </div>
</div>

<div class="section" data-section="local-sessions">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle open">&#9654;</span>
    <h2>Local Sessions</h2>
    <span class="count">{local_count}</span>
    <span class="section-sub">Coding sessions on this machine</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>ID</th><th>Pane <span class="tip" data-tip="tmux pane where this session runs, e.g. %0, %5">?</span></th><th>Role</th><th style="text-align:center;">Networked <span class="tip tip-right" data-tip="Visible to connected remote nodes. Uncheck to hide this session from other machines.">?</span></th><th>Registered</th><th></th></tr>
      {sessions_html}
    </table>
  </div>
</div>

<div class="section" data-section="remote-sessions">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle open">&#9654;</span>
    <h2>Remote Sessions</h2>
    <span class="count {remote_count_class}">{remote_count}</span>
    <span class="section-sub">Sessions on connected nodes &mdash; address as node/session</span>
  </div>
  <div class="section-body">
    {remote_grouped_html}
  </div>
</div>

<div class="section" data-section="human-sessions">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle {humans_toggle}">&#9654;</span>
    <h2>Nostr DM Access</h2>
    <span class="count {humans_count_class}">{human_count}</span>
    <span class="section-sub">Nostr users who can DM this daemon</span>
  </div>
  <div class="section-body {humans_collapsed}">
    <table>
      <tr><th>Name</th><th>Npub</th><th>Default <span class="tip" data-tip="Session that receives bare messages (no @target prefix)">?</span></th><th></th></tr>
      {humans_html}
    </table>
    <div style="margin-top:12px;">
      <div class="label">Add Nostr DM user</div>
      <form onsubmit="addHuman(event)" style="display:flex; gap:8px; flex-wrap:wrap;">
        <input type="text" id="human-name" placeholder="name" style="width:120px; background:#0c0e14; color:#c4c9d4; border:1px solid #1e2230; border-radius:4px; padding:7px 10px; font-family:'JetBrains Mono',monospace; font-size:12px; outline:none;">
        <input type="text" id="human-npub" placeholder="npub1..." style="flex:1; min-width:200px; background:#0c0e14; color:#c4c9d4; border:1px solid #1e2230; border-radius:4px; padding:7px 10px; font-family:'JetBrains Mono',monospace; font-size:12px; outline:none;">
        <button type="submit" class="btn-sm" style="padding:7px 16px;">Add</button>
      </form>
    </div>
  </div>
</div>

<div class="section" data-section="tasks">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle {tasks_toggle}">&#9654;</span>
    <h2>Scheduled Tasks</h2>
    <span class="count {tasks_count_class}">{task_count}</span>
    <span class="section-sub">Cron jobs that inject messages into sessions &mdash; times in UTC</span>
  </div>
  <div class="section-body {tasks_collapsed}">
    <table>
      <tr><th>ID</th><th>Name</th><th>Cron <span class="tip" data-tip="UTC cron schedule, e.g. */5 * * * * (every 5 min), 0 9 * * * (daily 9am), 0 0 * * 1 (Mondays)">?</span></th><th>Target <span class="tip" data-tip="Session that receives the injected message when this task fires">?</span></th><th style="text-align:center;">On <span class="tip tip-right" data-tip="Toggle on/off without deleting the task">?</span></th><th>Next</th><th>Last</th><th>Status <span class="tip tip-right" data-tip="ok = delivered, revived = pane was dead and auto-restarted, failed = see task runs for error">?</span></th><th>Runs</th><th></th></tr>
      {tasks_html}
    </table>
  </div>
</div>

<div class="section" data-section="task-runs">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle {task_runs_toggle}">&#9654;</span>
    <h2>Recent Task Runs</h2>
    <span class="count {task_runs_count_class}">{task_run_count}</span>
    <span class="section-sub">Execution history &mdash; last 20 runs</span>
  </div>
  <div class="section-body {task_runs_collapsed}">
    <table>
      <tr><th>Time</th><th>Task</th><th>Target</th><th>Status <span class="tip" data-tip="ok = delivered, revived = session pane was dead and auto-restarted, failed = see error column">?</span></th><th>Error</th></tr>
      {task_runs_html}
    </table>
  </div>
</div>

<div class="pairing">
  <h2>Pairing <span class="section-sub" style="display:inline; margin-left:12px;">Connect to another machine for cross-node messaging</span></h2>
  <div class="warn">&#9888; Tickets are secrets &mdash; share out-of-band only (copy/paste, not through the coding assistant).</div>
  {ticket_section}
  <div class="label">Connect to node <span class="tip" data-tip="Paste a ticket from another machine's 'ouija ticket' command or dashboard to establish a P2P link">?</span></div>
  <form onsubmit="connectNode(event)">
    <div class="connect-row">
      <input type="text" id="ticket-input" placeholder="Paste a ticket from another machine" autocomplete="off">
      <button type="submit">Connect</button>
    </div>
  </form>
  <div id="connect-result"></div>
</div>

<div class="section" data-section="messages">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle {messages_toggle}">&#9654;</span>
    <h2>Messages</h2>
    <span class="count {messages_count_class}">{msg_count}</span>
    <span class="section-sub">Delivery log &mdash; metadata only, content not persisted to disk</span>
  </div>
  <div class="section-body {messages_collapsed}">
    <table>
      <tr><th>Time</th><th>From</th><th>To</th><th>Message</th><th style="text-align:center;">OK <span class="tip tip-right" data-tip="Checkmark = delivered to target pane, X = delivery failed">?</span></th></tr>
      {log_html}
      {log_empty}
    </table>
  </div>
</div>

<div class="section" data-section="settings">
  <div class="section-head" onclick="toggleSection(this)">
    <span class="toggle open">&#9654;</span>
    <h2>Settings</h2>
    <span class="section-sub">Daemon behavior</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Setting</th><th style="text-align:center;">Value</th></tr>
      <tr>
        <td>Auto-register sessions <span class="tip" data-tip="When enabled, new sessions auto-register with the mesh via the SessionStart hook">?</span></td>
        <td style="text-align:center;">
          <input type="checkbox" id="auto-register" {auto_register_checked} onchange="updateSetting('auto_register', this.checked)">
        </td>
      </tr>
      <tr>
        <td>Idle timeout <span class="tip" data-tip="Seconds of inactivity after a stop before a session is considered idle.">?</span></td>
        <td style="text-align:center;">
          <input type="number" id="idle-timeout" value="{idle_timeout_secs}" min="10" max="600" style="width:60px;text-align:center;" onchange="updateSetting('idle_timeout_secs', parseInt(this.value))">
        </td>
      </tr>
      <tr>
        <td>Max local sessions <span class="tip" data-tip="When exceeded, the most idle sessions are auto-closed. 0 = unlimited.">?</span></td>
        <td style="text-align:center;">
          <input type="number" id="max-local-sessions" value="{max_local_sessions}" min="0" max="50" style="width:60px;text-align:center;" onchange="updateSetting('max_local_sessions', parseInt(this.value))">
        </td>
      </tr>
      <tr>
        <td>All sessions networked <span class="tip" data-tip="Bulk toggle: make all local sessions visible (or hidden) to remote nodes at once">?</span></td>
        <td style="text-align:center;">
          <input type="checkbox" id="bulk-networked" {bulk_networked_checked} onchange="bulkToggleNetworked(this.checked)">
        </td>
      </tr>
    </table>

    <div class="relay-config">
      <div class="relay-header">
        <span class="relay-label">Nostr relays</span>
        <span class="dim" style="font-size:11px;">Required for P2P — messages travel through these relays (encrypted)</span>
      </div>
      <div id="relay-list"></div>
      <div class="connect-row" style="margin-top:8px;">
        <input type="text" id="new-relay-input" placeholder="wss://relay.example.com" autocomplete="off">
        <button onclick="addRelay()">Add</button>
      </div>
    </div>
  </div>
</div>

</div>

<script>
// --- Collapse/expand ---
function toggleSection(head) {{
  const toggle = head.querySelector('.toggle');
  const body = head.nextElementSibling;
  const section = head.closest('.section');
  const key = section?.dataset?.section;
  if (body.classList.contains('collapsed')) {{
    body.classList.add('animating');
    body.classList.remove('collapsed');
    body.style.maxHeight = body.scrollHeight + 'px';
    toggle.classList.add('open');
    if (key) localStorage.setItem('ouija-' + key, 'open');
    body.addEventListener('transitionend', function handler() {{
      body.style.maxHeight = 'none';
      body.classList.remove('animating');
      body.removeEventListener('transitionend', handler);
    }});
  }} else {{
    body.classList.add('animating');
    body.style.maxHeight = body.scrollHeight + 'px';
    body.offsetHeight;
    body.classList.add('collapsed');
    toggle.classList.remove('open');
    if (key) localStorage.setItem('ouija-' + key, 'closed');
    body.addEventListener('transitionend', function handler() {{
      body.classList.remove('animating');
      body.removeEventListener('transitionend', handler);
    }});
  }}
}}

// Restore saved collapse states
document.querySelectorAll('.section[data-section]').forEach(s => {{
  const key = s.dataset.section;
  const saved = localStorage.getItem('ouija-' + key);
  const body = s.querySelector('.section-body');
  const toggle = s.querySelector('.toggle');
  if (saved === 'closed') {{
    body.classList.add('collapsed');
    toggle.classList.remove('open');
  }} else if (saved === 'open') {{
    body.classList.remove('collapsed');
    toggle.classList.add('open');
  }}
  // Open sections need no max-height constraint
  if (!body.classList.contains('collapsed')) {{
    body.style.maxHeight = 'none';
  }}
}});

// Relay management
var savedRelays = {saved_relays_json};

async function connectNode(e) {{
  e.preventDefault();
  const ticket = document.getElementById('ticket-input').value.trim();
  if (!ticket) return;
  const el = document.getElementById('connect-result');
  el.textContent = 'Connecting...';
  el.style.color = '#6b7280';
  try {{
    const resp = await fetch('/api/connect', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{ticket}})
    }});
    const data = await resp.json();
    if (resp.ok) {{
      el.style.color = '#3ecf8e';
      el.textContent = 'Connected to node';
      document.getElementById('ticket-input').value = '';
    }} else {{
      el.style.color = '#ef4444';
      el.textContent = 'Error: ' + (data.error || 'unknown');
    }}
  }} catch(err) {{
    el.style.color = '#ef4444';
    el.textContent = 'Error: ' + err.message;
  }}
}}

async function renameSession(oldId) {{
  const newId = prompt('Rename session "' + oldId + '" to:');
  if (!newId || newId === oldId) return;
  try {{
    const resp = await fetch('/api/rename', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{old_id: oldId, new_id: newId}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function removeSession(id) {{
  if (!confirm('Remove session "' + id + '"?')) return;
  try {{
    const resp = await fetch('/api/remove', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function deleteTask(id) {{
  if (!confirm('Delete task "' + id + '"?')) return;
  try {{
    const resp = await fetch('/api/tasks', {{
      method: 'DELETE',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function enableTask(id) {{
  try {{
    const resp = await fetch('/api/tasks/enable', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id}})
    }});
    if (!resp.ok) {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
      location.reload();
    }}
  }} catch(err) {{ alert('Error: ' + err.message); location.reload(); }}
}}

async function disableTask(id) {{
  try {{
    const resp = await fetch('/api/tasks/disable', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id}})
    }});
    if (!resp.ok) {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
      location.reload();
    }}
  }} catch(err) {{ alert('Error: ' + err.message); location.reload(); }}
}}

async function triggerTask(id) {{
  try {{
    const resp = await fetch('/api/tasks/trigger', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id}})
    }});
    const data = await resp.json();
    if (resp.ok) {{
      alert('Task triggered');
      location.reload();
    }} else {{
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

function copyTicket(btn) {{
  const text = btn.closest('.pairing').querySelector('.ticket-value').textContent.trim();
  navigator.clipboard.writeText(text).then(() => {{
    const orig = btn.textContent;
    btn.textContent = 'copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  }});
}}

async function generateNostrTicket() {{
  const input = document.getElementById('nostr-relay-input');
  const relay = input.value.trim();
  if (!relay) return;
  const el = document.getElementById('nostr-result');
  el.textContent = 'Generating...';
  el.style.color = '#6b7280';
  try {{
    const resp = await fetch('/api/ticket?relay=' + encodeURIComponent(relay));
    const data = await resp.json();
    if (resp.ok && data.ticket) {{
      el.style.color = '#3ecf8e';
      el.textContent = 'Ticket generated. Reloading...';
      location.reload();
    }} else {{
      el.style.color = '#ef4444';
      el.textContent = 'Error: ' + (data.error || 'unknown');
    }}
  }} catch(err) {{
    el.style.color = '#ef4444';
    el.textContent = 'Error: ' + err.message;
  }}
}}

async function regenerateTransport() {{
  if (!confirm('This will DESTROY your nostr identity (nsec). All nodes must re-connect. The daemon must be restarted.')) return;
  try {{
    const resp = await fetch('/api/regenerate-ticket?confirm=true', {{method:'POST'}});
    const data = await resp.json();
    if (resp.ok && data.ticket) {{
      const el = document.querySelector('.ticket-value');
      if (el) el.textContent = data.ticket;
      const banner = document.createElement('div');
      banner.style.cssText = 'background:#f59e0b;color:#000;padding:8px 16px;text-align:center;font-weight:600;position:fixed;top:0;left:0;right:0;z-index:999';
      banner.textContent = 'New identity generated. Restart the daemon for it to take effect.';
      document.body.prepend(banner);
    }} else {{
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function updateSetting(key, value) {{
  try {{
    const resp = await fetch('/api/settings', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{[key]: value}})
    }});
    if (!resp.ok) {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
      location.reload();
    }}
  }} catch(err) {{
    alert('Error: ' + err.message);
    location.reload();
  }}
}}

async function updateSessionNetworked(id, value) {{
  try {{
    const resp = await fetch('/api/sessions/update', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id, networked: value}})
    }});
    if (!resp.ok) {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
      location.reload();
    }}
  }} catch(err) {{
    alert('Error: ' + err.message);
    location.reload();
  }}
}}

async function disconnectNode(daemonId, name) {{
  if (!confirm('Disconnect node "' + name + '"? All remote sessions from this node will be removed.')) return;
  try {{
    const resp = await fetch('/api/nodes/disconnect', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{daemon_id: daemonId}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function addHuman(e) {{
  e.preventDefault();
  const name = document.getElementById('human-name').value.trim();
  const npub = document.getElementById('human-npub').value.trim();
  if (!name || !npub) {{ alert('Name and npub are required'); return; }}
  if (!npub.startsWith('npub1')) {{ alert('Npub must start with npub1'); return; }}
  try {{
    const resp = await fetch('/api/humans', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{name, npub}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function removeHuman(name) {{
  if (!confirm('Remove Nostr DM user "' + name + '"?')) return;
  try {{
    const resp = await fetch('/api/humans', {{
      method: 'DELETE',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{name}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{ alert('Error: ' + err.message); }}
}}

async function bulkToggleNetworked(value) {{
  try {{
    const resp = await fetch('/api/sessions/bulk-update', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{networked: value}})
    }});
    if (resp.ok) location.reload();
    else {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
      location.reload();
    }}
  }} catch(err) {{
    alert('Error: ' + err.message);
    location.reload();
  }}
}}

function renderRelays() {{
  const list = document.getElementById('relay-list');
  if (!list) return;
  if (savedRelays.length === 0) {{
    list.innerHTML = '<div class="dim" style="font-size:12px; padding:4px 0;">No relays configured.</div>';
    return;
  }}
  list.innerHTML = savedRelays.map((r, i) =>
    '<div class="relay-item"><code>' + r.replace(/</g, '&lt;') + '</code>' +
    '<button class="btn-sm btn-danger" onclick="removeRelay(' + i + ')">remove</button></div>'
  ).join('');
}}

async function addRelay() {{
  const input = document.getElementById('new-relay-input');
  const url = input.value.trim();
  if (!url) return;
  if (!url.startsWith('wss://') && !url.startsWith('ws://')) {{
    alert('Relay URL must start with wss:// or ws://');
    return;
  }}
  if (savedRelays.includes(url)) {{ input.value = ''; return; }}
  savedRelays.push(url);
  await saveRelays();
  input.value = '';
  renderRelays();
}}

async function removeRelay(idx) {{
  savedRelays.splice(idx, 1);
  await saveRelays();
  renderRelays();
}}

async function saveRelays() {{
  try {{
    const resp = await fetch('/api/relays', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{relays: savedRelays}})
    }});
    if (!resp.ok) {{
      const data = await resp.json();
      alert('Error: ' + (data.error || 'unknown'));
    }}
  }} catch(err) {{
    alert('Error saving relays: ' + err.message);
  }}
}}

renderRelays();

// Poll for updates
setInterval(async () => {{
  try {{
    const resp = await fetch('/api/status');
    if (resp.ok) {{
      document.title = 'ouija — {name}';
    }}
  }} catch(_) {{
    document.title = 'ouija — {name} (offline)';
  }}
}}, 5000);
</script>
</body>
</html>"#,
        name = html_escape(&state.config.name),
        port = state.config.port,
        daemon_npub = html_escape(&state.config.npub),
        daemon_npub_short = html_escape(&truncate_npub(&state.config.npub)),
        p2p_status = p2p_status,
        local_count = local_count,
        remote_count = remote_count,
        remote_count_class = if remote_count == 0 { "count-zero" } else { "" },
        human_count = human_count,
        humans_html = humans_html,
        humans_toggle = if human_count == 0 { "" } else { "open" },
        humans_collapsed = if human_count == 0 { "collapsed" } else { "" },
        humans_count_class = if human_count == 0 { "count-zero" } else { "" },
        msg_count = msg_count,
        sessions_html = sessions_html,
        remote_grouped_html = remote_grouped_html,
        task_count = task_count,
        tasks_html = tasks_html,
        task_run_count = task_run_count,
        task_runs_html = task_runs_html,
        log_html = log_html,
        log_empty = log_empty,
        saved_relays_json = saved_relays_json,
        idle_timeout_secs = settings.idle_timeout_secs,
        max_local_sessions = settings.max_local_sessions,
        auto_register_checked = if settings.auto_register {
            "checked"
        } else {
            ""
        },
        bulk_networked_checked = if all_networked && !local_sessions.is_empty() {
            "checked"
        } else {
            ""
        },
        // Empty sections start collapsed
        tasks_toggle = if task_count == 0 { "" } else { "open" },
        tasks_collapsed = if task_count == 0 { "collapsed" } else { "" },
        tasks_count_class = if task_count == 0 { "count-zero" } else { "" },
        task_runs_toggle = if task_run_count == 0 { "" } else { "open" },
        task_runs_collapsed = if task_run_count == 0 { "collapsed" } else { "" },
        task_runs_count_class = if task_run_count == 0 {
            "count-zero"
        } else {
            ""
        },
        messages_toggle = if msg_count == 0 { "" } else { "open" },
        messages_collapsed = if msg_count == 0 { "collapsed" } else { "" },
        messages_count_class = if msg_count == 0 { "count-zero" } else { "" },
        ticket_section = {
            let nostr_ticket = match transports.get("nostr") {
                Some(t) => t.ticket_string().await,
                None => None,
            };

            if let Some(ticket) = &nostr_ticket {
                format!(
                    r#"<div class="label">Your ticket <span class="tip" data-tip="Share this with another machine to let it connect. Run 'ouija connect &lt;ticket&gt;' on the other machine, or paste it into their dashboard.">?</span></div>
<div class="ticket-value">{ticket}</div>
<div class="ticket-actions">
  <button class="btn-sm" onclick="copyTicket(this)">copy</button>
  <button class="btn-sm btn-danger" onclick="regenerateTransport('nostr')">regenerate</button>
</div>"#,
                    ticket = html_escape(ticket),
                )
            } else {
                format!(
                    r#"<div class="nostr-setup">
  <div class="dim" style="font-size:12px; margin-bottom:8px;">Enter relay URL to generate a nostr ticket:</div>
  <div class="connect-row" style="margin-top:0;">
    <input type="text" id="nostr-relay-input" placeholder="wss://relay.example.com" value="{default_relay}" autocomplete="off">
    <button onclick="generateNostrTicket()">Generate</button>
  </div>
  <div id="nostr-result" style="font-size:12px; margin-top:8px; min-height:18px;"></div>
</div>"#,
                    default_relay = html_escape(&default_relay)
                )
            }
        },
    );

    Html(html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn truncate_npub(npub: &str) -> String {
    if npub.len() > 20 {
        format!("{}...{}", &npub[..12], &npub[npub.len() - 6..])
    } else {
        npub.to_string()
    }
}
