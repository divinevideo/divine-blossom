use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, GetPromptRequestParams, GetPromptResult, ListPromptsResult, Prompt,
    PromptArgument, PromptMessage, PromptMessageRole, ServerCapabilities, ServerInfo,
};
use rmcp::{RoleServer, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;

use crate::scheduler;
use crate::state::AppState;
use crate::tmux;

/// MCP server exposing session and task tools.
#[derive(Clone, Debug)]
pub struct OuijaMcp {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

impl OuijaMcp {
    /// Create an MCP server instance backed by shared state.
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }
}

/// Parameters for the `session_register` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionRegisterParams {
    /// A short identifier for this session (e.g. "relay", "web", "api")
    pub id: String,
    /// tmux pane ID (e.g. "%42"). Auto-detected from unregistered assistant panes if omitted.
    pub pane: Option<String>,
    /// Whether this session has vim keybindings enabled. If true, text injection
    /// will enter INSERT mode first to avoid vim command interpretation.
    #[serde(default)]
    pub vim_mode: Option<bool>,
    /// The project directory this session is working in.
    pub project_dir: Option<String>,
    /// A short description of what this session is doing.
    pub role: Option<String>,
    /// Whether this session is visible to and reachable from remote nodes.
    /// Defaults to true if omitted.
    #[serde(default)]
    pub networked: Option<bool>,
    /// What this session needs, offers, or is working on.
    /// Used to discover collaboration opportunities with other sessions.
    pub bulletin: Option<String>,
    /// Coding assistant conversation/session ID (UUID) for `--resume` on restart.
    /// If provided, restart will use `--resume <id>` instead of `--continue`.
    #[serde(alias = "claude_session_id")]
    pub backend_session_id: Option<String>,
    /// Which coding assistant backend to use (e.g. "claude-code", "codex").
    /// Defaults to the configured default backend.
    #[serde(default)]
    pub backend: Option<String>,
}

/// Parameters for the `session_unregister` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionUnregisterParams {
    /// Session ID to unregister
    pub id: String,
}

/// Parameters for the `session_send` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionSendParams {
    /// Your session ID (the sender)
    pub from: String,
    /// Target session ID
    pub to: String,
    /// Message to send
    pub message: String,
    /// Whether the sender expects a reply from the target.
    /// If true, the message prefix includes `reply="true"` and the daemon tracks the pending reply.
    pub expects_reply: bool,
    /// Message ID this is responding to. With `done=true`, clears the pending reply.
    /// Without `done`, marks progress without clearing.
    #[serde(default)]
    pub responds_to: Option<u64>,
    /// Whether this completes the referenced task. Only meaningful with responds_to.
    /// If true, clears the pending reply. If false (default), marks progress without clearing.
    #[serde(default)]
    pub done: bool,
}

/// Parameters for the `session_update` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionUpdateParams {
    /// Session ID to update
    pub id: String,
    /// New role/focus description for this session
    pub role: Option<String>,
    /// Updated project directory
    pub project_dir: Option<String>,
    /// What this session needs, offers, or is working on.
    /// Used to discover collaboration opportunities with other sessions.
    pub bulletin: Option<String>,
}

/// Parameters for the `session_rename` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionRenameParams {
    /// Current session ID to rename
    pub old_id: String,
    /// New session ID
    pub new_id: String,
}

/// Parameters for the `clear_pending_reply` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClearPendingReplyParams {
    /// Your session ID
    pub session: String,
    /// The sender whose pending reply to clear
    pub from: String,
}

/// Parameters for the `clear_reminder` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClearReminderParams {
    /// Your session ID
    pub from: String,
    /// The clearing_id from the reminder's clearing_id attribute
    pub clearing_id: u64,
}

/// Parameters for the `task_create` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskCreateParams {
    /// Human-readable name for the task
    pub name: String,
    /// Cron expression (e.g. "*/5 * * * *"). Evaluated in UTC.
    pub cron: String,
    /// Optional: inject into this existing session (only for continue_session mode).
    /// When absent, the task name is used as the session name.
    pub target_session: Option<String>,
    /// Bootstrap: prompt for creating/reviving the target session.
    #[serde(default)]
    pub prompt: Option<String>,
    /// Bootstrap: reminder for the target session.
    #[serde(default)]
    pub reminder: Option<String>,
    /// Override project directory for session revival
    pub project_dir: Option<String>,
    /// If true, the task fires once then auto-deletes itself.
    #[serde(default)]
    pub once: Option<bool>,
    /// Backend session ID for --resume on revival (instead of --continue).
    #[serde(alias = "claude_session_id")]
    pub backend_session_id: Option<String>,
    /// What happens each time the task fires.
    /// Variants: continue_session (default), new_session, persistent_worktree, disposable_worktree.
    /// For persistent_worktree, set clear_context to control conversation persistence.
    #[serde(default)]
    pub on_fire: Option<crate::scheduler::OnFire>,
}

/// Parameters for the `task_delete` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskDeleteParams {
    /// Task ID to delete (8-char hex)
    pub id: String,
}

/// Parameters for task enable/disable/trigger MCP tools.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskIdParams {
    /// Task ID (8-char hex)
    pub id: String,
}

/// Parameters for session start/kill/restart MCP tools.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionNameParams {
    /// Session name to operate on
    pub name: String,
    /// If true, start a fresh session (no --continue/--resume).
    #[serde(default)]
    pub fresh: Option<bool>,
    /// If true, run in an isolated git worktree (backend worktree mode).
    #[serde(default)]
    pub worktree: Option<bool>,
    /// Project directory to open the session in.
    /// If omitted, derives from projects_dir + name.
    #[serde(default)]
    pub project_dir: Option<String>,
    /// Initial prompt to inject into the session after launch.
    /// The text is sent to the pane once the coding assistant is ready.
    #[serde(default)]
    pub prompt: Option<String>,
    /// Sender session ID. When provided with a prompt, the prompt is wrapped
    /// in `<msg from="..." reply="true">` so the new session knows who initiated
    /// it and can reply. Works like session_send's from parameter.
    #[serde(default)]
    pub from: Option<String>,
    /// Whether a reply is expected when `from` is set.
    /// Defaults to true when `from` is present.
    #[serde(default)]
    pub expects_reply: Option<bool>,
    /// Which coding assistant backend to use (e.g. "claude-code", "codex").
    /// Defaults to the configured default backend.
    #[serde(default)]
    pub backend: Option<String>,
    /// Which LLM model to use (e.g. "claude-sonnet-4-6"). Stored in session
    /// metadata for visibility; does not control the backend's model selection.
    #[serde(default)]
    pub model: Option<String>,
    /// Reminder text appended to prompt at start and re-injected on idle.
    #[serde(default)]
    pub reminder: Option<String>,
    /// If true, preserve the git worktree after killing the session.
    #[serde(default)]
    pub keep_worktree: Option<bool>,
    /// Path to a workflow executable. The workflow drives this session's behavior.
    #[serde(default)]
    pub workflow: Option<String>,
    /// JSON params passed to the workflow on registration. Consumed at start, not persisted.
    #[serde(default)]
    pub workflow_params: Option<serde_json::Value>,
}

/// Parameters for the `workflow` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkflowParams {
    /// Your session ID (the caller).
    pub from: String,
    /// Action name (e.g., "init", "done", "status").
    pub action: String,
    /// Action-specific parameters (JSON object).
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Parameters for the `loop_next` MCP tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LoopNextParams {
    /// The session calling loop_next (same pattern as session_send's `from`).
    pub from: String,
    /// Log message for this iteration (visible on admin dashboard).
    #[serde(default)]
    pub message: Option<String>,
    /// When false (default), stay in the current conversation — just log iteration
    /// and return. When true, restart with fresh context (kill + respawn).
    #[serde(default)]
    pub clean_context: bool,
}

#[tool_router]
impl OuijaMcp {
    /// Register this session with the ouija daemon.
    /// Also used to rename: if the pane is already registered under a different
    /// name, the old name is replaced and remote daemons are notified.
    #[tool(
        name = "ouija.register",
        description = "Register this session with the ouija daemon. You MUST provide the `pane` parameter. To get it, first run `echo $TMUX_PANE` in bash, then pass the result here."
    )]
    async fn session_register(
        &self,
        Parameters(params): Parameters<SessionRegisterParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.id.contains('/') {
            return Ok(CallToolResult::error(vec![Content::text(
                "session ID must not contain '/'",
            )]));
        }

        let pane = match params.pane {
            Some(p) => Some(p),
            None => find_unregistered_pane(&self.state).await,
        };

        if pane.is_none() {
            return Ok(CallToolResult::error(vec![Content::text(
                "pane is required for message delivery. \
                 Run `echo $TMUX_PANE` in bash to get your pane ID, \
                 then call ouija.register again with the pane parameter.",
            )]));
        }

        if let Some(ref p) = pane {
            let names = self.state.backends.all_process_names();
            let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            if !crate::tmux::pane_alive(p, &refs) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "pane {p} does not exist — run `echo $TMUX_PANE` to get the correct pane ID"
                ))]));
            }
        }

        let project_description = params
            .project_dir
            .as_deref()
            .and_then(crate::api::extract_project_description);
        let metadata = crate::state::SessionMetadata {
            vim_mode: params.vim_mode.unwrap_or(false),
            project_dir: params.project_dir,
            role: params.role,
            bulletin: params.bulletin,
            networked: params.networked.unwrap_or(true),
            backend_session_id: params.backend_session_id,
            backend: params.backend,
            project_description,
            ..Default::default()
        };
        let proto_meta = crate::daemon_protocol::SessionMeta {
            project_dir: metadata.project_dir.clone(),
            role: metadata.role.clone(),
            bulletin: metadata.bulletin.clone(),
            networked: metadata.networked,
            worktree: metadata.worktree,
            vim_mode: metadata.vim_mode,
            backend: metadata.backend.clone(),
            ..Default::default()
        };
        let effects = self
            .state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: params.id.clone(),
                pane,
                metadata: proto_meta,
            })
            .await;

        let session_id = effects
            .iter()
            .find_map(|e| match e {
                crate::daemon_protocol::Effect::RegisterOk { session_id, .. } => {
                    Some(session_id.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| params.id.clone());

        tracing::info!("registered session: {session_id}");

        Ok(CallToolResult::success(vec![Content::text(format!(
            "registered as {session_id}"
        ))]))
    }

    /// Unregister this session from the ouija daemon.
    #[tool(name = "ouija.unregister", description = "Unregister a session from the ouija daemon")]
    async fn session_unregister(
        &self,
        Parameters(params): Parameters<SessionUnregisterParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let effects = self
            .state
            .apply_and_execute(crate::daemon_protocol::Event::Remove {
                id: params.id.clone(),
                keep_worktree: false,
            })
            .await;
        if effects
            .iter()
            .any(|e| matches!(e, crate::daemon_protocol::Effect::RemoveOk { .. }))
        {
            tracing::info!("unregistered session: {}", params.id);
            Ok(CallToolResult::success(vec![Content::text(format!(
                "unregistered {}",
                params.id
            ))]))
        } else {
            Ok(CallToolResult::error(vec![Content::text(format!(
                "session '{}' not found",
                params.id
            ))]))
        }
    }

    /// Update a session's role, project_dir, and/or bulletin without re-registering.
    #[tool(
        name = "ouija.update",
        description = "Update a session's metadata (role, project_dir, bulletin) without re-registering. Use this to keep your session description fresh. Set `bulletin` to advertise what you need or can offer other sessions."
    )]
    async fn session_update(
        &self,
        Parameters(params): Parameters<SessionUpdateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.role.is_none() && params.project_dir.is_none() && params.bulletin.is_none() {
            return Ok(CallToolResult::error(vec![Content::text(
                "at least one of role, project_dir, or bulletin must be provided",
            )]));
        }

        let effects = self
            .state
            .apply_and_execute(crate::daemon_protocol::Event::UpdateMetadata {
                id: params.id.clone(),
                role: params.role,
                bulletin: params.bulletin,
                project_dir: params.project_dir,
                networked: None,
            })
            .await;

        if effects
            .iter()
            .any(|e| matches!(e, crate::daemon_protocol::Effect::Persist))
        {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "updated session '{}'",
                params.id
            ))]))
        } else {
            Ok(CallToolResult::error(vec![Content::text(format!(
                "session '{}' not found or is remote",
                params.id
            ))]))
        }
    }

    /// Atomically rename a session, preserving metadata, pane, and pending replies.
    #[tool(
        name = "ouija.rename",
        description = "Rename a session. The old name becomes an alias that hints callers to use the new name."
    )]
    async fn session_rename(
        &self,
        Parameters(params): Parameters<SessionRenameParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let effects = self
            .state
            .apply_and_execute(crate::daemon_protocol::Event::Rename {
                old_id: params.old_id.clone(),
                new_id: params.new_id.clone(),
            })
            .await;
        if effects
            .iter()
            .any(|e| matches!(e, crate::daemon_protocol::Effect::RenameOk { .. }))
        {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "renamed '{}' to '{}'",
                params.old_id, params.new_id
            ))]))
        } else {
            let reason = effects
                .iter()
                .find_map(|e| match e {
                    crate::daemon_protocol::Effect::RenameFailed { reason } => Some(reason.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| format!("session '{}' not found", params.old_id));
            Ok(CallToolResult::error(vec![Content::text(reason)]))
        }
    }

    /// Send a message to another session. If the target is on this machine,
    /// it will be injected into their tmux pane. If remote, it goes over the network.
    /// If the target session doesn't exist but exactly one matching project is found,
    /// the session is auto-started with the message as the initial prompt.
    #[tool(name = "ouija.send", description = "Send a message to another session. When replying to a <msg reply=\"true\" id=\"N\">, pass that N as responds_to and set done=true to clear the pending reply and stop reminder nudges.")]
    async fn session_send(
        &self,
        Parameters(params): Parameters<SessionSendParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Auto-fill responds_to: when the sender omits responds_to but owes exactly
        // one pending reply to the target, assume they're replying to that message.
        // If multiple pending replies exist for the same target, don't guess — the
        // LLM must be explicit. This heuristic catches the ~50% of cases where LLMs
        // forget to pass responds_to, preventing stale reminder nudges.
        let responds_to = if params.responds_to.is_none() {
            let proto = self.state.protocol.read().await;
            if let Some(pending) = proto.pending_replies.get(&params.from) {
                let from_target: Vec<_> =
                    pending.iter().filter(|p| p.from == params.to).collect();
                if from_target.len() == 1 {
                    Some(from_target[0].msg_id)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            params.responds_to
        };

        // Clone message before Event::Send consumes it — needed for auto-start path
        let message = params.message.clone();
        let effects = self
            .state
            .apply_and_execute(crate::daemon_protocol::Event::Send {
                from: params.from.clone(),
                to: params.to.clone(),
                message: params.message,
                expects_reply: params.expects_reply,
                responds_to,
                done: params.done,
            })
            .await;

        if let Some(msg_id) = effects.iter().find_map(|e| match e {
            crate::daemon_protocol::Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
            _ => None,
        }) {
            let mut contents = vec![Content::text(format!("delivered (msg_id={msg_id})"))];
            append_staleness_hint(&self.state, &params.from, &mut contents).await;
            Ok(CallToolResult::success(contents))
        } else if let Some(reason) = effects.iter().find_map(|e| match e {
            crate::daemon_protocol::Effect::SendFailed { reason, .. } => Some(reason.clone()),
            _ => None,
        }) {
            // Check for matching projects — auto-start if exactly one match
            let suggestions = crate::project_index::suggest_projects(&self.state, &params.to).await;
            if suggestions.len() == 1 {
                let project = &suggestions[0];
                let project_dir = project.dir.to_string_lossy().to_string();
                // Start the session without a prompt — the message is injected
                // separately as proper <msg> XML so the new session parses it
                // as a peer message rather than treating it as instructions.
                let (start_result, _) = crate::nostr_transport::start_session(
                    &self.state,
                    &params.to,
                    None,
                    Some(&project_dir),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
                if start_result.starts_with("started ") {
                    // Format and inject the message as <msg> XML
                    let msg_id = {
                        let mut proto = self.state.protocol.write().await;
                        proto.next_seq()
                    };
                    let formatted = crate::daemon_protocol::format_session_message(
                        &params.from,
                        &message,
                        params.expects_reply,
                        msg_id,
                        responds_to,
                        params.done,
                    );
                    if let Some(pane) = self
                        .state
                        .protocol
                        .read()
                        .await
                        .sessions
                        .get(&params.to)
                        .and_then(|s| s.pane.clone())
                    {
                        crate::nostr_transport::schedule_prompt_injection(
                            &self.state,
                            &params.to,
                            pane,
                            formatted,
                        );
                    }
                    // Track pending reply
                    if params.expects_reply {
                        let mut proto = self.state.protocol.write().await;
                        proto
                            .pending_replies
                            .entry(params.to.clone())
                            .or_default()
                            .push(crate::daemon_protocol::PendingReplyEntry {
                                msg_id,
                                from: params.from.clone(),
                                message: String::new(),
                                received_at: chrono::Utc::now().timestamp(),
                                last_activity: chrono::Utc::now().timestamp(),
                                in_progress: false,
                            });
                    }
                    let mut contents = vec![Content::text(format!(
                        "auto-started session '{}' in {} and delivered message (msg_id={msg_id})",
                        params.to, project_dir
                    ))];
                    append_staleness_hint(&self.state, &params.from, &mut contents).await;
                    Ok(CallToolResult::success(contents))
                } else {
                    Ok(CallToolResult::error(vec![Content::text(format!(
                        "session '{}' not found; auto-start failed: {}",
                        params.to, start_result
                    ))]))
                }
            } else if suggestions.is_empty() {
                Ok(CallToolResult::error(vec![Content::text(reason)]))
            } else {
                let lines: Vec<String> = suggestions
                    .iter()
                    .map(|p| {
                        let desc = p
                            .description
                            .as_deref()
                            .map(|d| format!(" — {d}"))
                            .unwrap_or_default();
                        format!("  - {} ({}{})", p.name, p.dir.display(), desc)
                    })
                    .collect();
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "session '{}' not found. Matching projects:\n{}\n\
                     Use ouija.start to launch one.",
                    params.to,
                    lines.join("\n")
                ))]))
            }
        } else {
            Ok(CallToolResult::error(vec![Content::text(
                "unexpected send result",
            )]))
        }
    }

    /// List all known sessions across all connected daemons.
    #[tool(name = "ouija.list", description = "List all known sessions across all connected daemons")]
    async fn session_list(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let proto = self.state.protocol.read().await;
        let list: Vec<serde_json::Value> = proto
            .sessions
            .values()
            .map(|s| {
                let stale = s.metadata.is_stale();
                serde_json::json!({
                    "id": s.id,
                    "pane": s.pane,
                    "origin": match &s.origin {
                        crate::daemon_protocol::Origin::Remote(d) => format!("remote({d})"),
                        other => other.label().to_string(),
                    },
                    "project_dir": s.metadata.project_dir,
                    "role": s.metadata.role,
                    "bulletin": s.metadata.bulletin,
                    "worktree": s.metadata.worktree,
                    "last_metadata_update": s.metadata.last_metadata_update,
                    "stale": stale,
                })
            })
            .collect();

        let json = serde_json::to_string(&serde_json::json!({
            "daemon": self.state.config.name,
            "sessions": list,
        }))
        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Clear a pending reply when the sender's session is gone and you cannot reply normally.
    #[tool(
        name = "ouija.clear-reply",
        description = "Clear a pending reply from an unreachable session. Use when ouija.send fails because the sender disconnected."
    )]
    async fn clear_pending_reply(
        &self,
        Parameters(params): Parameters<ClearPendingReplyParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        {
            let mut proto = self.state.protocol.write().await;
            proto.clear_pending_reply_from(&params.session, &params.from);
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "cleared pending reply from '{}' on '{}'",
            params.from, params.session
        ))]))
    }

    /// Acknowledge an idle reminder so it stops re-firing until new activity occurs.
    #[tool(
        name = "ouija.clear-reminder",
        description = "Acknowledge an idle reminder to stop it re-firing. Pass the clearing_id from the reminder XML. The reminder resumes after new activity (incoming message, hook, etc)."
    )]
    async fn clear_reminder(
        &self,
        Parameters(params): Parameters<ClearReminderParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.state
            .notify_agent(
                &params.from,
                crate::session_agent::SessionMsg::ClearReminder {
                    clearing_id: params.clearing_id,
                },
            )
            .await;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "cleared reminder {} for '{}'",
            params.clearing_id, params.from
        ))]))
    }

    /// List all scheduled tasks with their status, next/last run times, and run counts.
    #[tool(name = "ouija.task-list", description = "List all scheduled tasks with status and run info")]
    async fn task_list(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let tasks = self.state.scheduled_tasks.read().await;
        let mut list: Vec<&scheduler::ScheduledTask> = tasks.values().collect();
        list.sort_by_key(|t| &t.created_at);
        let entries: Vec<serde_json::Value> = list
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "cron": t.cron,
                    "target_session": t.target_session,
                    "enabled": t.enabled,
                    "next_run": t.next_run,
                    "last_run": t.last_run,
                    "last_status": t.last_status,
                    "run_count": t.run_count,
                    "once": t.once,
                    "backend_session_id": t.backend_session_id,
                })
            })
            .collect();

        let json = serde_json::to_string_pretty(&serde_json::json!({ "tasks": entries }))
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Create a new scheduled task. The cron expression is evaluated in UTC.
    #[tool(name = "ouija.task-create", description = "Create a new scheduled task. Cron expressions are evaluated in UTC.")]
    async fn task_create(
        &self,
        Parameters(params): Parameters<TaskCreateParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = scheduler::validate_cron(&params.cron) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "invalid cron expression: {e}"
            ))]));
        }

        let mut task = scheduler::new_task(
            params.name,
            params.cron,
            params.target_session,
            params.prompt,
            params.reminder,
            params.once.unwrap_or(false),
            params.backend_session_id,
            params.on_fire.unwrap_or_default(),
        );
        task.project_dir = params.project_dir;

        let id = task.id.clone();
        self.state.add_task(task).await;

        let json = serde_json::to_string_pretty(&serde_json::json!({ "created": id }))
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        let contents = vec![Content::text(json)];

        Ok(CallToolResult::success(contents))
    }

    /// Delete a scheduled task by its ID.
    #[tool(name = "ouija.task-delete", description = "Delete a scheduled task by ID")]
    async fn task_delete(
        &self,
        Parameters(params): Parameters<TaskDeleteParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self.state.remove_task(&params.id).await {
            Some(_) => {
                let json =
                    serde_json::to_string_pretty(&serde_json::json!({ "deleted": params.id }))
                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            None => Ok(CallToolResult::error(vec![Content::text(format!(
                "task '{}' not found",
                params.id
            ))])),
        }
    }

    /// Enable a previously disabled scheduled task so it resumes running on schedule.
    #[tool(name = "ouija.task-enable", description = "Enable a scheduled task so it runs on its cron schedule")]
    async fn task_enable(
        &self,
        Parameters(params): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let exists = self
            .state
            .scheduled_tasks
            .read()
            .await
            .contains_key(&params.id);
        if !exists {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "task '{}' not found",
                params.id
            ))]));
        }
        self.state
            .update_task(&params.id, |t| {
                t.enabled = true;
                t.next_run = scheduler::compute_next_run(&t.cron);
            })
            .await;
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "enabled": params.id
        }))
        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Disable a scheduled task so it stops running. The task is kept but won't fire until re-enabled.
    #[tool(name = "ouija.task-disable", description = "Disable a scheduled task so it stops running")]
    async fn task_disable(
        &self,
        Parameters(params): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let exists = self
            .state
            .scheduled_tasks
            .read()
            .await
            .contains_key(&params.id);
        if !exists {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "task '{}' not found",
                params.id
            ))]));
        }
        self.state
            .update_task(&params.id, |t| {
                t.enabled = false;
                t.next_run = None;
            })
            .await;
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "disabled": params.id
        }))
        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Trigger a scheduled task immediately, regardless of its cron schedule.
    /// Useful for testing or one-off execution.
    #[tool(name = "ouija.task-trigger", description = "Trigger a scheduled task immediately, bypassing its cron schedule")]
    async fn task_trigger(
        &self,
        Parameters(params): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let exists = self
            .state
            .scheduled_tasks
            .read()
            .await
            .contains_key(&params.id);
        if !exists {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "task '{}' not found",
                params.id
            ))]));
        }
        scheduler::execute_task(&self.state, &params.id).await;

        // Read back the updated task for status
        let tasks = self.state.scheduled_tasks.read().await;
        let status = tasks.get(&params.id).map(|t| {
            serde_json::json!({
                "triggered": params.id,
                "last_status": t.last_status,
            })
        });
        drop(tasks);

        let json = serde_json::to_string_pretty(&status.unwrap_or(serde_json::json!({
            "triggered": params.id
        })))
        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        name = "ouija.kill",
        description = "Gracefully stop a coding session — sends /exit first, falls back to SIGTERM after 10s. Only use when the user explicitly asks to kill or stop a specific session. NEVER kill a session to work around a name conflict with ouija.start. Use node/name for remote sessions. Set keep_worktree=true to preserve the git worktree after killing."
    )]
    async fn session_kill(
        &self,
        Parameters(params): Parameters<SessionNameParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.keep_worktree.unwrap_or(false) {
            let result = crate::nostr_transport::kill_session_keep_worktree(&self.state, &params.name).await;
            Ok(CallToolResult::success(vec![Content::text(result)]))
        } else {
            let result = execute_command(&self.state, &params.name, "/kill").await;
            Ok(CallToolResult::success(vec![Content::text(result)]))
        }
    }

    #[tool(
        name = "ouija.start",
        description = "Start a new coding session in a tmux window. Directory is derived from projects_dir/<name> unless project_dir is specified. If a session with this name already exists, NEVER kill it — send it a message, or start a new session with a suffixed name (e.g. name-2) using project_dir pointing to the same repo and worktree=true. Use node/name to start on a remote machine."
    )]
    async fn session_start(
        &self,
        Parameters(mut params): Parameters<SessionNameParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Workflow registration: call the workflow to get instructions before starting
        let workflow_for_meta: Option<(String, u64)> = if let Some(ref wf) = params.workflow {
            match crate::workflow::register_workflow(
                &self.state,
                wf,
                &params.name,
                params.workflow_params.as_ref(),
                params.project_dir.as_deref(),
            )
            .await
            {
                Ok(reg) => {
                    let max_calls = reg.max_calls.unwrap_or(0);
                    // Merge workflow instructions into prompt
                    params.prompt = Some(match params.prompt.take() {
                        Some(user_prompt) => format!("{}\n\n{user_prompt}", reg.instructions),
                        None => reg.instructions,
                    });
                    // Use inject_on_start as reminder if no explicit reminder
                    if params.reminder.is_none() {
                        params.reminder = reg.inject_on_start;
                    }
                    Some((wf.clone(), max_calls))
                }
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "workflow registration failed: {e}"
                    ))]));
                }
            }
        } else {
            None
        };

        let from = params.from.clone();
        let expects_reply = params.expects_reply;
        let (result, prompt_msg_id) = if params.name.contains('/') {
            (
                execute_session_start(
                    &self.state,
                    &params.name,
                    params.worktree,
                    params.project_dir.as_deref(),
                    params.prompt.as_deref(),
                    params.from.as_deref(),
                    params.expects_reply,
                    params.reminder.as_deref(),
                )
                .await,
                None,
            )
        } else {
            crate::nostr_transport::start_session(
                &self.state,
                &params.name,
                params.worktree,
                params.project_dir.as_deref(),
                params.prompt.as_deref(),
                params.from.as_deref(),
                params.expects_reply,
                params.backend.as_deref(),
                params.model.as_deref(),
                params.reminder.as_deref(),
            )
            .await
        };

        // Stamp workflow path and budget on the session metadata
        if let Some((wf_path, max_calls)) = workflow_for_meta {
            let mut proto = self.state.protocol.write().await;
            if let Some(session) = proto.sessions.get_mut(&params.name) {
                session.metadata.workflow = Some(wf_path);
                session.metadata.workflow_max_calls = max_calls;
            }
            self.state.persist_protocol_state(&proto);
        }

        track_pending_reply(
            &self.state,
            &params.name,
            from.as_deref(),
            expects_reply,
            prompt_msg_id,
            params.prompt.as_deref(),
        )
        .await;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    #[tool(
        name = "ouija.restart",
        description = "Restart a coding session — kill then start with --continue in the same directory. Set fresh=true to start without prior context. Use node/name for remote sessions."
    )]
    async fn session_restart(
        &self,
        Parameters(params): Parameters<SessionNameParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let fresh = params.fresh.unwrap_or(false);
        let from = params.from.clone();
        let expects_reply = params.expects_reply;
        let (result, prompt_msg_id) = if params.name.contains('/') {
            (
                execute_session_restart(
                    &self.state,
                    &params.name,
                    fresh,
                    params.prompt.as_deref(),
                    params.from.as_deref(),
                    params.expects_reply,
                    params.reminder.as_deref(),
                )
                .await,
                None,
            )
        } else {
            crate::nostr_transport::restart_session(
                &self.state,
                &params.name,
                fresh,
                params.prompt.as_deref(),
                params.from.as_deref(),
                params.expects_reply,
                params.backend.as_deref(),
                params.model.as_deref(),
                params.reminder.as_deref(),
            )
            .await
        };
        track_pending_reply(
            &self.state,
            &params.name,
            from.as_deref(),
            expects_reply,
            prompt_msg_id,
            params.prompt.as_deref(),
        )
        .await;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    #[tool(name = "ouija.loop-next", description = "Advance a looping session: log an iteration. \
        With clean_context=false (default), stay in current conversation — just logs iteration and returns. \
        With clean_context=true, restart fresh (kill + respawn with prompt + reminder). \
        The session must have been started with a prompt. \
        Use `message` to log what this iteration accomplished (visible on admin dashboard).")]
    async fn loop_next(
        &self,
        Parameters(params): Parameters<LoopNextParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let session_id = params.from.clone();

        // Read session metadata
        let meta = {
            let proto = self.state.protocol.read().await;
            proto.sessions.get(&session_id).map(|s| s.metadata.clone())
        };

        let Some(meta) = meta else {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "session '{}' not found",
                session_id
            ))]));
        };

        let Some(ref prompt) = meta.prompt else {
            return Ok(CallToolResult::success(vec![Content::text(
                "session has no prompt — ouija.loop-next requires a session started with a prompt",
            )]));
        };

        // Log iteration and update pending reply timestamps
        let now = chrono::Utc::now().timestamp();
        let iteration = meta.iteration + 1;
        {
            let mut proto = self.state.protocol.write().await;
            if let Some(session) = proto.sessions.get_mut(&session_id) {
                session.metadata.iteration = iteration;
                session.metadata.last_iteration_at = Some(now);
                let entry = crate::daemon_protocol::IterationLogEntry {
                    iteration,
                    message: params.message.clone(),
                    timestamp: now,
                };
                session.metadata.iteration_log.push(entry);
                // Cap at 100 entries
                if session.metadata.iteration_log.len() > 100 {
                    let drain_count = session.metadata.iteration_log.len() - 100;
                    session.metadata.iteration_log.drain(..drain_count);
                }
            }
            // Update last_activity on pending replies to prevent immediate nudging
            if let Some(pending) = proto.pending_replies.get_mut(&session_id) {
                for entry in pending.iter_mut() {
                    entry.last_activity = now;
                }
            }
        }

        // Notify session agent about loop progress (for stall detection)
        self.state
            .notify_agent(&session_id, crate::session_agent::SessionMsg::LoopProgress)
            .await;

        let reminder = meta.reminder.clone();

        if params.clean_context {
            let prompt = prompt.clone();

            tracing::info!(
                session = %session_id,
                iteration,
                message = ?params.message,
                "loop_next: restarting session (clean_context=true)"
            );

            // Fire-and-forget: restart the session fresh with original prompt + reminder.
            // This kills the calling process via tmux respawn-pane -k, so the MCP
            // response never arrives.
            let state = self.state.clone();
            let sid = session_id.clone();
            // Snapshot loop state AFTER the iteration increment
            let stash = {
                let proto = self.state.protocol.read().await;
                proto
                    .sessions
                    .get(&session_id)
                    .map(|s| s.metadata.clone())
                    .unwrap_or_default()
            };
            tokio::spawn(async move {
                crate::nostr_transport::restart_session(
                    &state,
                    &sid,
                    true, // fresh
                    Some(prompt.as_str()),
                    None, // no from — not wrapped in <msg>
                    None, // no expects_reply on re-injection
                    None, // keep existing backend
                    None, // keep existing model
                    reminder.as_deref(),
                )
                .await;

                // Re-stamp immediately — restart_session's Register is committed,
                // so we can write the authoritative loop state now.
                {
                    let mut proto = state.protocol.write().await;
                    if let Some(session) = proto.sessions.get_mut(&sid) {
                        session.metadata.inherit_recurrence_from(&stash);
                    }
                }
                // Persist so loop state survives daemon restart
                let proto = state.protocol.read().await;
                state.persist_protocol_state(&proto);
            });

            Ok(CallToolResult::success(vec![Content::text(format!(
                "restarting session '{}' (iteration {})",
                session_id, iteration
            ))]))
        } else {
            tracing::info!(
                session = %session_id,
                iteration,
                message = ?params.message,
                "loop_next: iteration logged (clean_context=false)"
            );

            // Persist updated loop state
            let proto = self.state.protocol.read().await;
            self.state.persist_protocol_state(&proto);

            // Build response — include reminder every 10th iteration
            let loop_xml = if iteration % 10 == 0 {
                if let Some(ref reminder_text) = reminder {
                    format!("<loop iteration=\"{iteration}\">{reminder_text}</loop>")
                } else {
                    format!("<loop iteration=\"{iteration}\" />")
                }
            } else {
                format!("<loop iteration=\"{iteration}\" />")
            };

            Ok(CallToolResult::success(vec![Content::text(loop_xml)]))
        }
    }

    #[tool(name = "ouija.workflow", description = "Call this session's workflow actor — a deterministic program that controls \
        your task progression. The workflow tells you what to do; you do the work and report back.\n\
        \n\
        Common rhythm:\n\
        1. ouija.workflow(action='init') — get current state, next task, and success criteria\n\
        2. Do the work the workflow described\n\
        3. Verify your work meets the criteria the workflow gave you\n\
        4. ouija.workflow(action='done', params={...}) — report completion, get next step\n\
        \n\
        Other patterns:\n\
        - ouija.workflow(action='status') — check where you are without advancing\n\
        - ouija.workflow(action='result', params={score: N, description: '...'}) — report a measured outcome\n\
        \n\
        Always follow the workflow's instructions. If an error occurs, retry or call ouija.workflow(action='status') \
        to re-orient. The workflow manages state across context restarts — call 'init' after any restart.")]
    async fn workflow(
        &self,
        Parameters(params): Parameters<WorkflowParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let session_id = params.from.clone();

        let (workflow_path, project_dir) = {
            let mut proto = self.state.protocol.write().await;
            match proto.sessions.get_mut(&session_id) {
                Some(s) => {
                    // Enforce effort budget
                    if s.metadata.workflow_max_calls > 0
                        && s.metadata.workflow_calls >= s.metadata.workflow_max_calls
                    {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "workflow call budget exhausted ({} of {} calls used). \
                             The workflow set this limit at registration to prevent unbounded looping. \
                             Use ouija.send(done=true) to signal completion.",
                            s.metadata.workflow_calls, s.metadata.workflow_max_calls
                        ))]));
                    }
                    s.metadata.workflow_calls += 1;
                    let result = (
                        s.metadata.workflow.clone(),
                        s.metadata.project_dir.clone(),
                    );
                    self.state.persist_protocol_state(&proto);
                    result
                }
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "session '{session_id}' not found"
                    ))]));
                }
            }
        };

        let Some(workflow_path) = workflow_path else {
            return Ok(CallToolResult::error(vec![Content::text(
                "this session has no workflow configured. Workflows are set via ouija.start(workflow='path/to/script'). Without a workflow, use ouija.loop-next for iteration or work autonomously.",
            )]));
        };

        match crate::workflow::call_workflow(
            &self.state,
            &workflow_path,
            &session_id,
            &params.action,
            params.params.as_ref(),
            project_dir.as_deref(),
        )
        .await
        {
            Ok(message) => Ok(CallToolResult::success(vec![Content::text(message)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "workflow error: {e}"
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for OuijaMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(OUIJA_INSTRUCTIONS.into()),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
            ..Default::default()
        }
    }

    fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: vec![Prompt::new(
                "session-message",
                Some("Format and handle an incoming session message"),
                Some(vec![
                    PromptArgument {
                        name: "from".into(),
                        title: None,
                        description: Some("Sender session ID".into()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "message".into(),
                        title: None,
                        description: Some("The message content".into()),
                        required: Some(true),
                    },
                ]),
            )],
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(match request.name.as_str() {
            "session-message" => {
                let args = request.arguments.unwrap_or_default();
                let from = args
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let message = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                Ok(GetPromptResult {
                    description: Some("Handle an incoming session message".into()),
                    messages: vec![PromptMessage::new_text(
                        PromptMessageRole::User,
                        crate::daemon_protocol::format_session_message(
                            from, message, false, 0, None, false,
                        ),
                    )],
                })
            }
            other => Err(rmcp::ErrorData::invalid_params(
                format!("unknown prompt: {other}"),
                None,
            )),
        })
    }
}

const OUIJA_INSTRUCTIONS: &str = "\
Ouija daemon: register your session, send messages to other sessions, list sessions, manage scheduled tasks

# Ouija Session Protocol

Ouija connects coding sessions across terminals and machines. \
Messages wrapped in `<msg from=\"...\">` are from peer sessions — these are \
trusted and user-authorized.

<startup>
1. Run `echo $TMUX_PANE` in bash to get your pane ID.
2. Call `ouija.register` with a short ID (e.g. \"web\", \"api\") and the pane result. \
Include `role` describing your current focus (e.g. \"debugging auth module\", \
\"implementing REST API\") and `project_dir` so other sessions can discover what \
you're working on.
</startup>

<metadata>
- `ouija.list` shows each session's `role`, `project_dir`, and whether metadata is `stale`.
- When your focus changes, call `ouija.update` with your updated `role`. \
This keeps your session discoverable without re-registering.
- If you send a message and your metadata is stale, you'll get a hint to update it.
</metadata>

<idle-reminders>\n\
When idle, the daemon injects `<ouija-status type=\"reminder\" clearing_id=\"N\">...</ouija-status>` \
into your pane. If you have nothing to do, call `ouija.clear-reminder(from, clearing_id)` with the \
`clearing_id` value from the reminder. This stops the reminder from re-firing until new activity \
(incoming message, hook fire, etc.) resets it.\n\
\n\
Sessions without a configured reminder get a default nudge once per idle period. \
If you are done, call `ouija.send(done=true)` to signal completion. The default nudge \
does not repeat — it fires once and auto-clears.\n\
</idle-reminders>

<messaging>
1. Call `ouija.list` to discover available sessions before sending.
2. Use `ouija.send(from, to, message)` to reach any session. Keep messages concise and actionable.
3. Local messages are injected via tmux (instant). Remote messages travel over Nostr relays.
4. The target session sees: `<msg from=\"your-id\" id=\"N\">your message</msg>`

### Responding to messages

Each session runs in its own terminal, possibly on a different machine or phone. \
Text output stays in the local terminal — the sender cannot see it. \
To deliver a reply, call `ouija.send(from=\"your-id\", to=\"sender-id\", message=\"...\")`.

Your text output is not visible to the sender. Use `ouija.send` to reply.

- `<msg from=\"X\" id=\"N\" reply=\"true\">` means a reply is expected. \
If the task is quick, reply immediately with the result. \
If the task will take more than a few seconds (reading files, running commands, investigating), \
send a brief ack first (e.g. \"Looking into it\") so the sender gets feedback, \
then send the actual result when done.
- `<msg from=\"X\" id=\"N\">` (no reply attr) is informational — no reply needed unless you choose to continue.
</messaging>

<tasks>
Tasks ensure sessions stay alive and working on a cron schedule. Each task has a `prompt` \
(the work to do) and optionally a `reminder` (nudge text appended to the prompt and \
re-injected on idle). When a task fires, if the target session is dead the daemon revives it \
with the prompt + reminder. If the session is already alive, `continue_session` and \
`new_session` are no-ops (the reminder handles nudging); worktree modes restart as configured.

- Cron expressions are 5-field standard cron, evaluated in **UTC** \
(e.g. `0 9 * * *` = daily 9am UTC, `*/5 * * * *` = every 5 min)
- Set `once: true` to fire once then auto-delete (useful for reminders and one-shot checks)
- Use `ouija.task-trigger` to test a task immediately without waiting for its schedule
- `on_fire` controls what happens each time the task fires:
  - `continue_session` (default): no-op on alive sessions; revive with --continue if dead
  - `new_session`: no-op on alive sessions; start fresh if dead
  - `persistent_worktree`: named worktree persists across fires; set `clear_context: true` \
to start a new conversation each fire while keeping the worktree
  - `disposable_worktree`: anonymous worktree created and cleaned up each fire

Tasks and loops are the same recurring session primitive with different triggers: \
tasks use cron (passive, scheduled), loops use ouija.loop-next (active, self-driven). \
Both rely on prompt + reminder for session bootstrap and continuity. \
</tasks>

<loops>
Sessions can chain indefinitely using ouija.loop-next. Each call logs an iteration and \
optionally restarts the session. On restart, the session's `prompt` is re-used as \
the seed for the new conversation.

- `ouija.loop-next(from, message?, clean_context?)` — log an iteration. Returns `<loop iteration=\"N\" />` \
(or `<loop iteration=\"N\">reminder text</loop>` every 10th iteration).
  - `clean_context=false` (default): stay in current conversation, keep accumulated context. \
The daemon logs the iteration and returns. Use the iteration number for any policy your prompt \
defines (e.g. restart every tenth iteration to shed context drift).
  - `clean_context=true`: restart with fresh context (kill + respawn with prompt + reminder). \
Fire-and-forget — the session dies and respawns.
- To stop looping, simply don't call ouija.loop-next. Use ouija.send(done=true) to reply \
to whoever started the session.
- The `reminder` parameter on ouija.start provides text that is appended to the prompt \
and re-injected on idle as a nudge.
- The daemon detects loop stalls automatically after 3+ iterations. If no ouija.loop-next arrives \
within 3x the average interval, the reminder is re-injected. At 10x average (or 30 min), \
the session is force-restarted with clean context.

Example — a session started with:
  prompt: \"Find the next .js file in src/ not yet converted to .ts. Convert it, run tests, commit.\"
  reminder: \"Call ouija.loop-next('converted X.js'). If no .js files remain, ouija.send(done=true, message='migration complete').\"
should convert one file, commit, then call ouija.loop-next. On the next iteration it gets the same \
prompt, finds the next unconverted file, and repeats until none remain.
</loops>

<session_guidance>
## When to use ouija sessions vs agents

Ouija sessions are persistent tmux terminals — use them for long-lived work that needs \
its own context, file access in a specific repo, or ongoing collaboration across terminals. \
If the user just needs a quick answer or investigation, prefer the Agent tool (subagent) — \
it's lighter and doesn't consume a terminal.

When the user says \"create an agent\" or \"start an agent\" without mentioning \
\"session\" or \"ouija\", they likely mean a subagent (Agent tool), not an ouija session.
</session_guidance>

<lifecycle_rules>
- Do not kill an existing session to resolve a name conflict. If `ouija.start` returns \
\"already exists\", send a message to the existing session instead, or start a new session \
with a suffixed name (e.g. `name-2`) using `project_dir` pointing to the same repo and \
`worktree=true`.
- Do not kill a session just to get a fresh one. Use `ouija.restart` with `fresh=true` \
to restart cleanly, or start a separate worktree session alongside it.
- Prefer messaging over spawning. If a session already exists for a project, send it a \
message rather than starting a new one.
</lifecycle_rules>

<workflows>
Sessions can be driven by an external workflow executable. Pass `workflow` (path to executable) \
and optionally `workflow_params` (JSON) to `ouija.start`. The daemon calls the workflow at \
startup to get instructions, which become the session's prompt.

During the session, use `ouija.workflow(from, action, params)` to interact with the workflow actor. \
The workflow controls task progression — follow its instructions for what actions to take.

- Call `ouija.workflow(from, action='init')` at session start or after a restart to get current state
- The workflow's response tells you what to do next and what actions are available
- The workflow manages its own state and can push messages via the ouija REST API
- If you stall, the daemon re-injects the reminder which tells you to call ouija.workflow('init')
</workflows>
";

/// Track a pending reply after a successful session start/restart.
/// Called from session_start, session_restart, and session_send auto-start.
async fn track_pending_reply(
    state: &Arc<AppState>,
    session_name: &str,
    from: Option<&str>,
    expects_reply: Option<bool>,
    prompt_msg_id: Option<u64>,
    prompt: Option<&str>,
) {
    let Some(sender) = from else { return };
    if !expects_reply.unwrap_or(true) {
        return;
    }
    let Some(msg_id) = prompt_msg_id else { return };
    let mut proto = state.protocol.write().await;
    proto
        .pending_replies
        .entry(session_name.to_string())
        .or_default()
        .push(crate::daemon_protocol::PendingReplyEntry {
            msg_id,
            from: sender.to_string(),
            message: prompt.unwrap_or_default().to_string(),
            received_at: chrono::Utc::now().timestamp(),
            last_activity: chrono::Utc::now().timestamp(),
            in_progress: false,
        });
}

/// Send a structured wire message to a remote node and wait for the response.
/// Shared by session_start and session_restart for remote (node/name) targets.
async fn execute_remote_command(
    state: &Arc<AppState>,
    name: &str,
    wire_msg: crate::protocol::WireMessage,
    command_key: String,
) -> String {
    let Some((node_name, _)) = name.split_once('/') else {
        return "expected node/name format".to_string();
    };
    let node_exists = {
        let nodes = state.nodes.read().await;
        nodes.values().any(|n| n.name == node_name)
    };
    if !node_exists {
        return format!("node '{node_name}' not found");
    }

    let rx = state.register_pending_command(command_key);
    if !crate::transport::broadcast(state, &wire_msg).await {
        return "P2P not connected".to_string();
    }
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => "command channel closed".to_string(),
        Err(_) => "timeout waiting for remote response".to_string(),
    }
}

/// If the sender's metadata is stale, append a hint nudging them to update.
/// Send a structured SessionStart wire message to a remote node.
async fn execute_session_start(
    state: &Arc<AppState>,
    name: &str,
    worktree: Option<bool>,
    project_dir: Option<&str>,
    prompt: Option<&str>,
    from: Option<&str>,
    expects_reply: Option<bool>,
    reminder: Option<&str>,
) -> String {
    let session_name = name.split_once('/').map(|(_, s)| s).unwrap_or(name);
    let seq = state.protocol.read().await.wire_seq;
    let wire = crate::protocol::WireMessage::SessionStart {
        name: session_name.to_string(),
        project_dir: project_dir.map(String::from),
        worktree,
        prompt: prompt.map(String::from),
        reminder: reminder.map(String::from),
        from: from.map(String::from),
        expects_reply,
        daemon_id: state.config.npub.clone(),
        seq,
    };
    execute_remote_command(state, name, wire, format!("/start {session_name}")).await
}

/// Send a structured SessionRestart wire message to a remote node.
async fn execute_session_restart(
    state: &Arc<AppState>,
    name: &str,
    fresh: bool,
    prompt: Option<&str>,
    from: Option<&str>,
    expects_reply: Option<bool>,
    reminder: Option<&str>,
) -> String {
    let session_name = name.split_once('/').map(|(_, s)| s).unwrap_or(name);
    let seq = state.protocol.read().await.wire_seq;
    let wire = crate::protocol::WireMessage::SessionRestart {
        name: session_name.to_string(),
        fresh: Some(fresh),
        prompt: prompt.map(String::from),
        reminder: reminder.map(String::from),
        from: from.map(String::from),
        expects_reply,
        daemon_id: state.config.npub.clone(),
        seq,
    };
    execute_remote_command(state, name, wire, format!("/restart {session_name}")).await
}

async fn execute_command(state: &Arc<AppState>, name: &str, verb: &str) -> String {
    if let Some((node_name, session_name)) = name.split_once('/') {
        // Find daemon_id for this node name
        let daemon_id = {
            let nodes = state.nodes.read().await;
            nodes
                .values()
                .find(|n| n.name == node_name)
                .map(|n| n.daemon_id.clone())
        };
        let Some(_daemon_id) = daemon_id else {
            return format!("node '{node_name}' not found");
        };

        let command = format!("{verb} {session_name}");
        let rx = state.register_pending_command(command.clone());
        let wire = crate::protocol::WireMessage::Command {
            command,
            daemon_id: state.config.npub.clone(),
        };
        if !crate::transport::broadcast(state, &wire).await {
            return "P2P not connected".to_string();
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => "command channel closed".to_string(),
            Err(_) => "timeout waiting for remote response".to_string(),
        }
    } else {
        let state_arc = state.clone();
        crate::nostr_transport::handle_human_command(&state_arc, &format!("{verb} {name}")).await
    }
}

async fn append_staleness_hint(state: &AppState, sender_id: &str, contents: &mut Vec<Content>) {
    let proto = state.protocol.read().await;
    if let Some(session) = proto.sessions.get(sender_id) {
        if session.metadata.is_stale() {
            contents.push(Content::text(
                "Hint: your session metadata is stale. \
                 Consider calling ouija.update with your current role \
                 so other sessions see what you're working on.",
            ));
        }
    }
}

/// Find an unregistered assistant pane to associate with a new session.
///
/// Scans all tmux panes running the backend process and returns one that
/// isn't already registered. Falls back to `None` if zero or multiple
/// candidates exist (ambiguous).
async fn find_unregistered_pane(state: &AppState) -> Option<String> {
    let names: Vec<String> = state.backends.all_process_names();
    let assistant_panes = tokio::task::spawn_blocking(move || {
        let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        tmux::find_assistant_panes(&name_refs)
    })
    .await
    .ok()?
    .ok()?;
    let proto = state.protocol.read().await;
    let registered_panes: std::collections::HashSet<&str> = proto
        .sessions
        .values()
        .filter_map(|s| s.pane.as_deref())
        .collect();

    let candidates: Vec<_> = assistant_panes
        .iter()
        .filter(|p| !registered_panes.contains(p.pane_id.as_str()))
        .collect();

    if candidates.len() == 1 {
        Some(candidates[0].pane_id.clone())
    } else {
        None
    }
}
