use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use ractor::{Actor, ActorRef};

use crate::config::OuijaConfig;
use crate::persistence::OuijaSettings;
use crate::project_index::ProjectInfo;
use crate::scheduler::{ScheduledTask, TaskRun};
use crate::transport::Transport;

/// Sanitize a name into a valid session ID (lowercase alphanumeric + dashes).
pub fn sanitize_session_id(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Expand `~/` to `$HOME/` in a path string.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/{rest}")
    } else {
        path.to_string()
    }
}

/// Resolve a pane's cwd to the actual project root.
/// If the path is inside a `.claude/worktrees/<branch>` or `.ouija/worktrees/<branch>` directory,
/// walk up to the repo root so autoregistration derives the project name, not the branch.
///
/// Phase 1: hardcoded to the Claude Code and Ouija worktree layouts. This function is called
/// during auto-registration before a per-session backend is known.
/// Phase 2: delegate to `backend.resolve_project_root(path)` once per-session backends are supported.
pub fn resolve_project_root(path: &str) -> &str {
    // Look for `/.claude/worktrees/` or `/.ouija/worktrees/` in the path
    if let Some(idx) = path.find("/.claude/worktrees/") {
        &path[..idx]
    } else if let Some(idx) = path.find("/.ouija/worktrees/") {
        &path[..idx]
    } else {
        path
    }
}

/// Named transport map keyed by transport name (e.g. "nostr").
type TransportMap = HashMap<String, Arc<dyn Transport>>;

/// A node with this npub is already connected.
#[derive(Debug)]
pub struct DuplicateNode(pub String);

impl std::fmt::Display for DuplicateNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DuplicateNode {}

/// Lightweight session snapshot for diff computation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SessionSnapshot {
    pub id: String,
    pub origin: String,
    pub role: Option<String>,
    pub bulletin: Option<String>,
}

/// Thread-safe shared reference to the daemon's application state.
pub type SharedState = Arc<AppState>;

/// Central daemon state holding sessions, nodes, and transports.
pub struct AppState {
    pub config: OuijaConfig,
    /// Pure protocol state machine — source of truth for all sessions.
    pub protocol: RwLock<crate::daemon_protocol::DaemonState>,
    pub nodes: RwLock<HashMap<String, NodeInfo>>,
    pub message_log: RwLock<VecDeque<LogEntry>>,
    pub log_file: PathBuf,
    transports: RwLock<TransportMap>,
    pub settings: RwLock<OuijaSettings>,
    pub scheduled_tasks: RwLock<HashMap<String, ScheduledTask>>,
    pub task_runs: RwLock<VecDeque<TaskRun>>,
    /// Per-pane FIFO injection queues (each backed by a background worker).
    pane_queues: std::sync::Mutex<
        HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::tmux::InjectRequest>>,
    >,
    /// Serializes log file writes to prevent interleaved lines.
    log_file_lock: std::sync::Mutex<()>,
    /// Serializes task_runs.jsonl writes.
    task_run_log_lock: std::sync::Mutex<()>,
    /// Connected remote daemon npubs, prevents duplicate connections.
    /// Maps npub -> node name.
    connected_npubs: std::sync::Mutex<HashMap<String, String>>,
    /// Debounce: last time we reciprocated a session list to each node.
    last_reciprocated: std::sync::Mutex<HashMap<String, std::time::Instant>>,
    /// Active session agents, keyed by session ID.
    session_agents: RwLock<HashMap<String, ActorRef<crate::session_agent::SessionMsg>>>,
    /// Indexed projects from projects_dir, keyed by directory basename.
    pub project_index: RwLock<HashMap<String, ProjectInfo>>,
    /// Pending remote command results: command string → oneshot senders.
    pending_commands: std::sync::Mutex<Vec<(String, tokio::sync::oneshot::Sender<String>)>>,
    /// Cached tmux panes running the coding assistant, refreshed by the reaper loop.
    cached_assistant_panes: RwLock<Vec<crate::tmux::TmuxPane>>,
    /// Per-fire worktree panes: pane_id → project_dir.
    /// Reaper runs `git worktree prune` when these panes die.
    pub perfire_worktree_panes: RwLock<HashMap<String, String>>,
    pub backends: crate::backend::BackendRegistry,
    pub http_client: reqwest::Client,
    /// Queued prompts waiting for a readiness signal from HttpApi sessions.
    /// Maps session_id -> (pane_id, prompt_text).
    pub pending_prompts: std::sync::Mutex<std::collections::HashMap<String, (String, String)>>,
    /// Per-session baseline snapshots used to compute diffs in hook handlers.
    pub session_diff_baselines: std::sync::Mutex<HashMap<String, Vec<SessionSnapshot>>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Mutable metadata describing a session's configuration and context.
///
/// # Design: Trigger + SessionConfig + Runtime
///
/// SessionMetadata = SessionConfig (prompt, reminder, project_dir, on_fire) + Runtime
/// (iteration, iteration_log, last_iteration_at) + Display (role, bulletin, vim_mode).
/// ScheduledTask (scheduler.rs) = SessionConfig + Trigger (cron, enabled, next_run).
/// The shared SessionConfig fields are stamped here when a task creates or revives
/// a session.
///
/// The SessionConfig fields aren't a named type yet — they're copied field-by-field
/// during the trigger→session handoff. Extracting a named SessionConfig would make
/// this explicit, especially if a third trigger type (file watch) is added.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    #[serde(default)]
    pub vim_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether this session is visible to and reachable from remote nodes.
    #[serde(default = "default_true")]
    pub networked: bool,
    /// When the session's role/project_dir was last explicitly set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_metadata_update: Option<DateTime<Utc>>,
    /// Coding assistant conversation/session ID (UUID) for `--resume` on restart.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "claude_session_id"
    )]
    pub backend_session_id: Option<String>,
    /// Which coding assistant backend this session uses (e.g. "claude-code").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Short project description extracted from Cargo.toml, package.json, or README.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_description: Option<String>,
    /// Free-form bulletin: what this session needs, offers, or is working on.
    /// Used by the pairing evaluator to discover collaboration opportunities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bulletin: Option<String>,
    /// Whether this session runs in an isolated git worktree (backend worktree mode).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub worktree: bool,
    /// Which LLM model this session is configured to use (informational only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Reminder text re-injected on idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminder: Option<String>,
    /// Original prompt from session_start, stored for re-injection on iteration.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "original_prompt")]
    pub prompt: Option<String>,
    /// How many times loop_next has been called.
    #[serde(default, alias = "loop_iteration")]
    pub iteration: u64,
    /// Log messages from each iteration. Capped at 100.
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "loop_log")]
    pub iteration_log: Vec<crate::daemon_protocol::IterationLogEntry>,
    /// Unix timestamp of the most recent iteration. Used by stall detection.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "last_loop_next")]
    pub last_iteration_at: Option<i64>,
    /// What happens each time a scheduled task fires for this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_fire: Option<crate::scheduler::OnFire>,
    /// Path to a workflow executable. When set, this session is workflow-driven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// Number of workflow() calls made by this session.
    #[serde(default)]
    pub workflow_calls: u64,
    /// Maximum workflow calls allowed (set by workflow at registration). 0 = unlimited.
    #[serde(default)]
    pub workflow_max_calls: u64,
}

fn default_true() -> bool {
    true
}

impl Default for SessionMetadata {
    fn default() -> Self {
        Self {
            vim_mode: false,
            project_dir: None,
            role: None,
            networked: true,
            last_metadata_update: None,
            backend_session_id: None,
            backend: None,
            project_description: None,
            bulletin: None,
            worktree: false,
            model: None,
            reminder: None,
            prompt: None,
            iteration: 0,
            iteration_log: Vec::new(),
            last_iteration_at: None,
            on_fire: None,
            workflow: None,
            workflow_calls: 0,
            workflow_max_calls: 0,
        }
    }
}

/// A registered coding assistant session bound to a tmux pane.
#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub id: String,
    pub pane: Option<String>,
    pub origin: SessionOrigin,
    pub registered_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub metadata: SessionMetadata,
}

/// Where a session originated: local tmux, remote node, or human.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionOrigin {
    Local,
    Remote(String),
    /// A human Nostr user. The String is their npub.
    Human(String),
}

/// Metadata for a connected remote daemon node.
#[derive(Clone, Debug, Serialize)]
pub struct NodeInfo {
    pub name: String,
    pub daemon_id: String,
    pub connected_at: DateTime<Utc>,
}

/// A recorded inter-session message for the admin log.
#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub from: String,
    pub to: String,
    pub message: String,
    pub delivered: bool,
}

/// Max message log entries retained in memory.
const MAX_LOG: usize = 100;
/// Max task run records retained in memory.
const MAX_TASK_RUNS: usize = 200;
/// Max suffix number when resolving auto-registration name conflicts.
const MAX_NAME_SUFFIX: u32 = 100;
/// Reciprocation debounce interval to prevent session list ping-pong.
const RECIPROCATE_DEBOUNCE_SECS: u64 = 30;

impl AppState {
    #[cfg(test)]
    pub fn new_for_test() -> Arc<Self> {
        Arc::new(Self {
            config: crate::config::OuijaConfig {
                name: "test".into(),
                npub: "npub1test".into(),
                port: 0,
                data_dir: std::path::PathBuf::from("/tmp/ouija-test-agent"),
                config_dir: std::path::PathBuf::from("/tmp/ouija-test-agent"),
            },
            protocol: RwLock::new(crate::daemon_protocol::DaemonState::new(
                "npub1test".into(),
                "test".into(),
            )),
            nodes: RwLock::new(HashMap::new()),
            message_log: RwLock::new(VecDeque::with_capacity(MAX_LOG)),
            log_file: std::path::PathBuf::from("/tmp/ouija-test-agent/messages.jsonl"),
            transports: RwLock::new(HashMap::new()),
            settings: RwLock::new(Default::default()),
            scheduled_tasks: RwLock::new(HashMap::new()),
            task_runs: RwLock::new(VecDeque::with_capacity(MAX_TASK_RUNS)),
            pane_queues: std::sync::Mutex::new(HashMap::new()),
            log_file_lock: std::sync::Mutex::new(()),
            task_run_log_lock: std::sync::Mutex::new(()),
            connected_npubs: std::sync::Mutex::new(HashMap::new()),
            last_reciprocated: std::sync::Mutex::new(HashMap::new()),
            session_agents: RwLock::new(HashMap::new()),
            project_index: RwLock::new(HashMap::new()),
            pending_commands: std::sync::Mutex::new(Vec::new()),
            cached_assistant_panes: RwLock::new(Vec::new()),
            perfire_worktree_panes: RwLock::new(HashMap::new()),
            backends: crate::backend::BackendRegistry::default_registry(),
            http_client: reqwest::Client::new(),
            pending_prompts: std::sync::Mutex::new(std::collections::HashMap::new()),
            session_diff_baselines: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn new(config: OuijaConfig) -> SharedState {
        let log_file = config.data_dir.join("messages.jsonl");
        let settings = crate::persistence::load_settings(&config.config_dir).unwrap_or_default();
        let scheduled_tasks = crate::persistence::load_tasks(&config.data_dir).unwrap_or_default();
        let protocol =
            crate::daemon_protocol::DaemonState::new(config.npub.clone(), config.name.clone());
        Arc::new(Self {
            config,
            protocol: RwLock::new(protocol),
            nodes: RwLock::new(HashMap::new()),
            message_log: RwLock::new(VecDeque::with_capacity(MAX_LOG)),
            log_file,
            transports: RwLock::new(HashMap::new()),
            settings: RwLock::new(settings),
            scheduled_tasks: RwLock::new(scheduled_tasks),
            task_runs: RwLock::new(VecDeque::with_capacity(MAX_TASK_RUNS)),
            pane_queues: std::sync::Mutex::new(HashMap::new()),
            log_file_lock: std::sync::Mutex::new(()),
            task_run_log_lock: std::sync::Mutex::new(()),
            connected_npubs: std::sync::Mutex::new(HashMap::new()),
            last_reciprocated: std::sync::Mutex::new(HashMap::new()),
            session_agents: RwLock::new(HashMap::new()),
            project_index: RwLock::new(HashMap::new()),
            pending_commands: std::sync::Mutex::new(Vec::new()),
            cached_assistant_panes: RwLock::new(Vec::new()),
            perfire_worktree_panes: RwLock::new(HashMap::new()),
            backends: crate::backend::BackendRegistry::default_registry(),
            http_client: reqwest::Client::new(),
            pending_prompts: std::sync::Mutex::new(std::collections::HashMap::new()),
            session_diff_baselines: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Resolve the backend for a given session by looking up its metadata.
    pub async fn backend_for_session(
        &self,
        session_id: &str,
    ) -> std::sync::Arc<dyn crate::backend::CodingAssistant> {
        let backend_name = self
            .protocol
            .read()
            .await
            .sessions
            .get(session_id)
            .and_then(|s| s.metadata.backend.as_deref())
            .map(String::from);
        match backend_name {
            Some(name) => self
                .backends
                .get(&name)
                .unwrap_or_else(|| self.backends.default()),
            None => self.backends.default(),
        }
    }

    /// Find the session ID registered on a given pane (full `%NNN` format).
    pub async fn find_session_by_pane(&self, pane: &str) -> Option<String> {
        let proto = self.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(pane))
            .map(|s| s.id.clone())
    }

    /// Find session by pane OR backend session ID (opencode UUID).
    pub async fn find_session_by_pane_or_backend_sid(
        &self,
        pane: Option<&str>,
        backend_sid: Option<&str>,
    ) -> Option<String> {
        let proto = self.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| {
                pane.is_some_and(|p| s.pane.as_deref() == Some(p))
                    || backend_sid
                        .is_some_and(|b| s.metadata.backend_session_id.as_deref() == Some(b))
            })
            .map(|s| s.id.clone())
    }

    /// Apply a protocol event and execute all resulting effects.
    ///
    /// The pure state transition happens under the protocol lock.
    /// Effects are executed after the lock is released.
    pub fn apply_and_execute(
        self: &Arc<Self>,
        event: crate::daemon_protocol::Event,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<crate::daemon_protocol::Effect>> + Send + '_>,
    > {
        Box::pin(self._apply_and_execute(event))
    }

    async fn _apply_and_execute(
        self: &Arc<Self>,
        event: crate::daemon_protocol::Event,
    ) -> Vec<crate::daemon_protocol::Effect> {
        use crate::daemon_protocol::{Effect, LogLevel};

        let effects = {
            let mut state = self.protocol.write().await;
            state.apply(event)
        };

        for effect in &effects {
            match effect {
                Effect::Broadcast(msg) => {
                    crate::transport::broadcast(self, msg).await;
                }
                Effect::BroadcastSessionList => {
                    crate::transport::broadcast_local_sessions(self).await;
                }
                Effect::InjectMessage {
                    session_id,
                    pane,
                    message,
                    vim_mode,
                } => {
                    let _ = crate::tmux::locked_inject(self, session_id, pane, message, *vim_mode)
                        .await;
                }
                Effect::SetTmuxVar { pane, value, .. } => {
                    let p = pane.clone();
                    let v = value.clone();
                    tokio::task::spawn_blocking(move || crate::tmux_var::set(&p, &v));
                }
                Effect::ClearTmuxVar { pane, .. } => {
                    let p = pane.clone();
                    tokio::task::spawn_blocking(move || crate::tmux_var::clear(&p));
                }
                Effect::RenameWindow { pane, name } => {
                    let p = pane.clone();
                    let n = name.clone();
                    tokio::task::spawn_blocking(move || crate::tmux::rename_window(&p, &n));
                }
                Effect::EnableAutoRename { pane } => {
                    let p = pane.clone();
                    tokio::task::spawn_blocking(move || crate::tmux::enable_automatic_rename(&p));
                }
                Effect::SpawnAgent { session_id, pane } => {
                    self.spawn_session_agent(session_id, pane).await;
                }
                Effect::StopAgent { session_id } => {
                    if let Some(agent) = self
                        .session_agents
                        .write()
                        .await
                        .remove(session_id.as_str())
                    {
                        agent.stop(None);
                    }
                }
                Effect::RenameAgent { old_id, new_id } => {
                    let mut agents = self.session_agents.write().await;
                    if let Some(agent) = agents.remove(old_id.as_str()) {
                        let _ = agent.cast(crate::session_agent::SessionMsg::Renamed {
                            new_id: new_id.clone(),
                        });
                        agents.insert(new_id.clone(), agent);
                    }
                }
                Effect::ClearPendingReplies { removed_ids } => {
                    self.clear_orphaned_pending_replies(removed_ids).await;
                }
                Effect::Persist => {
                    let proto = self.protocol.read().await;
                    self.persist_protocol_state(&proto);
                }
                Effect::CleanupWorktree { project_dir } => {
                    let dir = project_dir.clone();
                    tokio::task::spawn(async move {
                        Self::cleanup_worktree_dir(&dir).await;
                    });
                }
                Effect::SendToHuman { npub, message } => {
                    let _ = crate::nostr_transport::send_plain_dm(self, npub, message).await;
                }
                Effect::ExecuteCommand { command, daemon_id } => {
                    tracing::info!("received command from {daemon_id}: {command}");
                    // Spawn as detached task to break async recursion chain
                    // (command → start_session → revive_or_start_pane → apply_and_execute)
                    let state = Arc::clone(self);
                    let cmd = command.clone();
                    tokio::spawn(async move {
                        let result =
                            crate::nostr_transport::handle_human_command(&state, &cmd).await;
                        let reply = crate::protocol::WireMessage::CommandResult {
                            command: cmd,
                            result,
                            daemon_id: state.config.npub.clone(),
                        };
                        crate::transport::broadcast(&state, &reply).await;
                    });
                }
                Effect::ExecuteSessionStart {
                    name,
                    worktree,
                    project_dir,
                    prompt,
                    reminder,
                    from,
                    expects_reply,
                    daemon_id: sender_id,
                } => {
                    tracing::info!("received session_start from {sender_id}: {name}");
                    let state = Arc::clone(self);
                    let name = name.clone();
                    let worktree = *worktree;
                    let project_dir = project_dir.clone();
                    let prompt = prompt.clone();
                    let reminder = reminder.clone();
                    let from = from.clone();
                    let expects_reply = *expects_reply;
                    tokio::spawn(async move {
                        let (result, _prompt_msg_id) = crate::nostr_transport::start_session(
                            &state,
                            &name,
                            worktree,
                            project_dir.as_deref(),
                            prompt.as_deref(),
                            from.as_deref(),
                            expects_reply,
                            None,
                            None,
                            reminder.as_deref(),
                        )
                        .await;
                        let reply = crate::protocol::WireMessage::CommandResult {
                            command: format!("/start {name}"),
                            result,
                            daemon_id: state.config.npub.clone(),
                        };
                        crate::transport::broadcast(&state, &reply).await;
                    });
                }
                Effect::ExecuteSessionRestart {
                    name,
                    fresh,
                    prompt,
                    reminder,
                    from,
                    expects_reply,
                    daemon_id: sender_id,
                } => {
                    tracing::info!("received session_restart from {sender_id}: {name}");
                    let state = Arc::clone(self);
                    let name = name.clone();
                    let fresh = fresh.unwrap_or(false);
                    let prompt = prompt.clone();
                    let reminder = reminder.clone();
                    let from = from.clone();
                    let expects_reply = *expects_reply;
                    tokio::spawn(async move {
                        let (result, _prompt_msg_id) = crate::nostr_transport::restart_session(
                            &state,
                            &name,
                            fresh,
                            prompt.as_deref(),
                            from.as_deref(),
                            expects_reply,
                            None,
                            None,
                            reminder.as_deref(),
                        )
                        .await;
                        let reply = crate::protocol::WireMessage::CommandResult {
                            command: format!("/restart {name}"),
                            result,
                            daemon_id: state.config.npub.clone(),
                        };
                        crate::transport::broadcast(&state, &reply).await;
                    });
                }
                Effect::DeliverCommandResult {
                    daemon_id,
                    command,
                    result,
                } => {
                    tracing::info!("command result from {daemon_id}: {command} -> {result}");
                    self.deliver_command_result(daemon_id, command, result)
                        .await;
                }
                Effect::RecordNode {
                    daemon_id,
                    daemon_name,
                } => {
                    self.nodes.write().await.insert(
                        daemon_id.clone(),
                        NodeInfo {
                            name: daemon_name.clone(),
                            daemon_id: daemon_id.clone(),
                            connected_at: Utc::now(),
                        },
                    );
                }
                Effect::Reciprocate { daemon_id } => {
                    if self.should_reciprocate(daemon_id) {
                        tracing::info!("reciprocating session list to {daemon_id}");
                        crate::transport::broadcast_local_sessions(self).await;
                    }
                }
                Effect::LogMessage {
                    from,
                    to,
                    message,
                    delivered,
                    transport,
                } => {
                    self.log_message(
                        from.clone(),
                        to.clone(),
                        message.clone(),
                        *delivered,
                        transport,
                    )
                    .await;
                }
                Effect::Log { level, message } => match level {
                    LogLevel::Info => tracing::info!("{message}"),
                    LogLevel::Warn => tracing::warn!("{message}"),
                    LogLevel::Debug => tracing::debug!("{message}"),
                },
                // Result effects handled by callers, not executed
                Effect::RegisterOk { .. }
                | Effect::SendDelivered { .. }
                | Effect::SendFailed { .. }
                | Effect::RenameOk { .. }
                | Effect::RenameFailed { .. }
                | Effect::RemoveOk { .. }
                | Effect::RemoveFailed { .. } => {}
                Effect::NotifyWorkflow {
                    workflow_path,
                    event,
                    session_id,
                    project_dir,
                } => {
                    crate::workflow::notify_workflow(
                        self,
                        workflow_path,
                        event,
                        session_id,
                        project_dir.as_deref(),
                    );
                }
            }
        }

        effects
    }

    /// Persist protocol state sessions to disk.
    pub(crate) fn persist_protocol_state(&self, proto: &crate::daemon_protocol::DaemonState) {
        // Convert DaemonState sessions to the persisted Session format
        let sessions: HashMap<String, Session> = proto
            .sessions
            .iter()
            .map(|(k, entry)| {
                let session = Session {
                    id: entry.id.clone(),
                    pane: entry.pane.clone(),
                    origin: match &entry.origin {
                        crate::daemon_protocol::Origin::Local => SessionOrigin::Local,
                        crate::daemon_protocol::Origin::Remote(d) => {
                            SessionOrigin::Remote(d.clone())
                        }
                        crate::daemon_protocol::Origin::Human(n) => SessionOrigin::Human(n.clone()),
                    },
                    registered_at: Utc::now(),
                    last_activity_at: Utc::now(),
                    metadata: SessionMetadata {
                        vim_mode: entry.metadata.vim_mode,
                        project_dir: entry.metadata.project_dir.clone(),
                        role: entry.metadata.role.clone(),
                        networked: entry.metadata.networked,
                        bulletin: entry.metadata.bulletin.clone(),
                        worktree: entry.metadata.worktree,
                        reminder: entry.metadata.reminder.clone(),
                        prompt: entry.metadata.prompt.clone(),
                        iteration: entry.metadata.iteration,
                        iteration_log: entry.metadata.iteration_log.clone(),
                        workflow: entry.metadata.workflow.clone(),
                        workflow_calls: entry.metadata.workflow_calls,
                        workflow_max_calls: entry.metadata.workflow_max_calls,
                        ..Default::default()
                    },
                };
                (k.clone(), session)
            })
            .collect();
        self.persist_sessions_from(&sessions);
    }

    /// Clean up a git worktree directory if it has no uncommitted changes.
    /// Supports both ouija-managed (`.ouija/worktrees/`) and legacy Claude Code
    /// (`.claude/worktrees/`) paths.
    async fn cleanup_worktree_dir(dir: &str) {
        let dir_owned = dir.to_string();
        let repo = if let Some(i) = dir.find("/.ouija/worktrees/") {
            dir[..i].to_string()
        } else if let Some(i) = dir.find("/.claude/worktrees/") {
            dir[..i].to_string()
        } else {
            return;
        };
        let dir_clone = dir_owned.clone();
        let has_changes = tokio::task::spawn_blocking(move || {
            std::process::Command::new("git")
                .args(["-C", &dir_clone, "status", "--porcelain"])
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(true)
        })
        .await
        .unwrap_or(true);
        if has_changes {
            tracing::info!("worktree {dir_owned} has uncommitted changes, keeping it");
            return;
        }
        tracing::info!("cleaning up worktree: {dir_owned}");
        let _ = tokio::task::spawn_blocking(move || {
            let _ = std::process::Command::new("git")
                .args(["-C", &repo, "worktree", "remove", &dir_owned, "--force"])
                .status();
        })
        .await;
    }

    /// Register a connected node by npub.
    ///
    /// Returns the existing node name if this npub is already connected.
    pub fn try_add_node(&self, npub: &str, name: &str) -> Result<(), DuplicateNode> {
        let mut connected = self
            .connected_npubs
            .lock()
            .expect("connected_npubs poisoned");
        if let Some(existing) = connected.get(npub) {
            return Err(DuplicateNode(existing.clone()));
        }
        connected.insert(npub.to_string(), name.to_string());
        Ok(())
    }

    /// Disconnect a remote node.
    ///
    /// Removes the node from the connected set, deauthorizes the peer in all
    /// transports (so future messages are rejected), removes all its remote
    /// sessions, and removes it from persisted connections.
    /// Returns the number of sessions removed.
    pub async fn disconnect_node(&self, daemon_id: &str) -> usize {
        // Remove from connected_npubs
        self.connected_npubs
            .lock()
            .expect("connected_npubs poisoned")
            .remove(daemon_id);

        // Deauthorize peer in all transports so messages are rejected
        for t in self.transports().await.values() {
            t.deauthorize_peer(daemon_id).await;
        }

        // Remove from nodes map
        self.nodes.write().await.remove(daemon_id);

        // Remove all remote sessions from this daemon
        let mut proto = self.protocol.write().await;
        let to_remove: Vec<String> = proto.sessions
            .iter()
            .filter(|(_, s)| matches!(&s.origin, crate::daemon_protocol::Origin::Remote(d) if d == daemon_id))
            .map(|(key, _)| key.clone())
            .collect();
        let count = to_remove.len();
        for key in &to_remove {
            proto.sessions.remove(key);
        }
        drop(proto);

        // Remove from persisted connections
        if let Ok(mut conns) = crate::persistence::load_connections(&self.config.data_dir) {
            conns.retain(|c| c.daemon_npub.as_deref() != Some(daemon_id));
            let data = serde_json::to_string(&conns).unwrap_or_default();
            let _ = std::fs::write(
                self.config.data_dir.join("connections.json"),
                data.as_bytes(),
            );
        }

        count
    }

    /// Enqueue an injection request for a pane, spawning its worker if needed.
    pub fn enqueue_inject(&self, req: crate::tmux::InjectRequest) {
        let pane_key = req.pane.clone();
        let mut queues = self.pane_queues.lock().expect("pane_queues poisoned");

        // Try existing channel; recover the request if the worker died.
        let req = if let Some(tx) = queues.get(&pane_key) {
            match tx.send(req) {
                Ok(()) => return,
                Err(e) => {
                    queues.remove(&pane_key);
                    e.0
                }
            }
        } else {
            req
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(req).expect("fresh channel cannot be closed");
        tokio::spawn(crate::tmux::pane_inject_loop(rx));
        queues.insert(pane_key, tx);
    }

    /// Return a snapshot of all active transports.
    pub async fn transports(&self) -> TransportMap {
        self.transports.read().await.clone()
    }

    /// Look up a transport by name (e.g. "nostr").
    pub async fn transport_by_name(&self, name: &str) -> Option<Arc<dyn Transport>> {
        self.transports.read().await.get(name).cloned()
    }

    /// Register a transport, keyed by its `transport_name()`.
    pub async fn add_transport(&self, t: Arc<dyn Transport>) {
        self.transports
            .write()
            .await
            .insert(t.transport_name().to_string(), t);
    }

    /// Spawn a session agent for a local session.
    pub async fn spawn_session_agent(self: &Arc<Self>, id: &str, pane: &str) {
        // Stop any existing agent first (e.g. from pane dedup re-registration)
        if let Some(old) = self.session_agents.write().await.remove(id) {
            old.stop(None);
        }
        let agent = crate::session_agent::SessionAgent {
            app_state: Arc::clone(self),
        };
        let args = crate::session_agent::SessionAgentArgs {
            session_id: id.to_string(),
            pane: pane.to_string(),
        };
        match Actor::spawn(None, agent, args).await {
            Ok((actor_ref, _handle)) => {
                self.session_agents
                    .write()
                    .await
                    .insert(id.to_string(), actor_ref);
                tracing::info!("spawned session agent for {id}");
            }
            Err(e) => {
                tracing::error!("failed to spawn session agent for {id}: {e}");
            }
        }
    }

    /// Send a message to a session's agent (if it exists).
    pub async fn notify_agent(&self, session_id: &str, msg: crate::session_agent::SessionMsg) {
        let agent = {
            let agents = self.session_agents.read().await;
            agents.get(session_id).cloned()
        };
        if let Some(agent) = agent {
            let _ = agent.cast(msg);
        }
    }

    /// Query a session agent for its pending replies (RPC).
    pub async fn query_agent_pending_replies(
        &self,
        session_id: &str,
    ) -> Vec<crate::daemon_protocol::PendingReplyEntry> {
        let agents = self.session_agents.read().await;
        if let Some(agent) = agents.get(session_id) {
            ractor::call!(agent, crate::session_agent::SessionMsg::GetPendingReplies)
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Clear pending replies targeting removed sessions from protocol state.
    pub(crate) async fn clear_orphaned_pending_replies(&self, removed_ids: &[String]) {
        let mut proto = self.protocol.write().await;
        proto.clear_orphaned_replies(removed_ids);
    }

    /// If local session count exceeds `max_local_sessions`, return the most
    /// idle sessions that should be closed to bring the count back to the limit.
    pub async fn collect_excess_idle_sessions(&self) -> Vec<String> {
        let max = self.settings.read().await.max_local_sessions as usize;
        if max == 0 {
            return vec![];
        }
        let proto = self.protocol.read().await;
        let mut local: Vec<_> = proto
            .sessions
            .values()
            .filter(|s| matches!(s.origin, crate::daemon_protocol::Origin::Local))
            .collect();
        if local.len() <= max {
            return vec![];
        }
        // Sort by last activity (oldest activity first) so the most idle sessions are evicted.
        // Use last_metadata_update as the activity signal, falling back to registered_at.
        local.sort_by_key(|s| s.metadata.last_metadata_update.unwrap_or(s.registered_at));
        let excess = local.len() - max;
        local[..excess].iter().map(|s| s.id.clone()).collect()
    }

    pub fn persist_sessions_from(&self, sessions: &HashMap<String, Session>) {
        let persisted: Vec<_> = sessions
            .values()
            .filter_map(crate::persistence::PersistedSession::from_session)
            .collect();
        if let Err(e) = crate::persistence::save_sessions(&self.config.data_dir, &persisted) {
            tracing::warn!("failed to persist sessions: {e}");
        }
    }

    pub async fn cached_assistant_panes(&self) -> Vec<crate::tmux::TmuxPane> {
        self.cached_assistant_panes.read().await.clone()
    }

    /// Scan tmux for assistant panes, update cache, and auto-register unregistered ones.
    pub async fn scan_and_autoregister_panes(self: &Arc<Self>) {
        let names: Vec<String> = self.backends.all_process_names();
        let panes = match tokio::task::spawn_blocking(move || {
            let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            crate::tmux::find_assistant_panes(&name_refs)
        })
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("spawn_blocking join error: {e}")))
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("tmux scan failed: {e}");
                return;
            }
        };

        // Update cache
        *self.cached_assistant_panes.write().await = panes.clone();

        let auto_register = self.settings.read().await.auto_register;
        if !auto_register {
            return;
        }

        // Build lookup tables from current sessions (single lock acquisition).
        // These are updated within the loop so subsequent panes see prior registrations.
        let (mut registered_panes, mut id_to_pane) = {
            let proto = self.protocol.read().await;
            let registered: std::collections::HashSet<String> = proto
                .sessions
                .values()
                .filter(|s| matches!(s.origin, crate::daemon_protocol::Origin::Local))
                .filter_map(|s| s.pane.clone())
                .collect();
            let id_to_pane: std::collections::HashMap<String, Option<String>> = proto
                .sessions
                .iter()
                .map(|(id, s)| (id.clone(), s.pane.clone()))
                .collect();
            (registered, id_to_pane)
        };

        for pane in &panes {
            if registered_panes.contains(&pane.pane_id) {
                continue;
            }

            // Skip if the pane has an @ouija_id tmux variable — it was claimed
            // by session_start or the registration hook and may be mid-restart.
            let pane_id_check = pane.pane_id.clone();
            let has_ouija_id = tokio::task::spawn_blocking(move || {
                std::process::Command::new("tmux")
                    .args(["show-options", "-pv", "-t", &pane_id_check, "@ouija_id"])
                    .output()
                    .map(|o| o.status.success() && !o.stdout.is_empty())
                    .unwrap_or(false)
            })
            .await
            .unwrap_or(false);
            if has_ouija_id {
                continue;
            }

            let Some(ref path) = pane.pane_current_path else {
                continue;
            };

            let project_root = resolve_project_root(path);
            let basename = std::path::Path::new(project_root)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let base_id = sanitize_session_id(basename);

            if base_id.is_empty() {
                continue;
            }

            // Resolve name conflicts using pre-computed map (no lock re-acquisition)
            let mut id = base_id.clone();
            let mut suffix = 2u32;
            while let Some(existing_pane) = id_to_pane.get(&id) {
                if existing_pane.as_deref() == Some(pane.pane_id.as_str()) {
                    break; // Same pane, protocol handles idempotent update
                }
                id = format!("{base_id}-{suffix}");
                suffix += 1;
                if suffix > MAX_NAME_SUFFIX {
                    tracing::warn!("could not find available name for pane {}", pane.pane_id);
                    break;
                }
            }

            let proto_meta = crate::daemon_protocol::SessionMeta {
                project_dir: Some(project_root.to_string()),
                role: Some(format!("working on {basename}")),
                ..Default::default()
            };

            tracing::info!("auto-registering pane {} as '{id}'", pane.pane_id);
            self.apply_and_execute(crate::daemon_protocol::Event::Register {
                id: id.clone(),
                pane: Some(pane.pane_id.clone()),
                metadata: proto_meta,
            })
            .await;

            // Update maps so the next pane in this loop sees this registration.
            // Without this, two panes in the same directory both claim the base
            // name and the second overwrites the first.
            id_to_pane.insert(id.clone(), Some(pane.pane_id.clone()));
            registered_panes.insert(pane.pane_id.clone());
        }
    }

    /// Whether we should reciprocate a session list to this node.
    ///
    /// Debounced at 30s to prevent infinite ping-pong over Nostr.
    pub fn should_reciprocate(&self, daemon_id: &str) -> bool {
        let mut map = self
            .last_reciprocated
            .lock()
            .expect("last_reciprocated poisoned");
        let now = std::time::Instant::now();
        if let Some(last) = map.get(daemon_id) {
            if now.duration_since(*last) < std::time::Duration::from_secs(RECIPROCATE_DEBOUNCE_SECS)
            {
                return false;
            }
        }
        map.insert(daemon_id.to_string(), now);
        true
    }

    /// Register a oneshot sender for a pending remote command result.
    pub fn register_pending_command(
        &self,
        command: String,
    ) -> tokio::sync::oneshot::Receiver<String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_commands
            .lock()
            .expect("pending_commands poisoned")
            .push((command, tx));
        rx
    }

    /// Deliver a command result to the first matching pending sender.
    pub async fn deliver_command_result(&self, _daemon_id: &str, command: &str, result: &str) {
        let tx = {
            let mut pending = self
                .pending_commands
                .lock()
                .expect("pending_commands poisoned");
            pending
                .iter()
                .position(|(cmd, _)| cmd == command)
                .map(|idx| pending.remove(idx).1)
        };
        if let Some(tx) = tx {
            let _ = tx.send(result.to_string());
        }
    }

    pub async fn local_session_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let proto = self.protocol.read().await;
        let mut entries: Vec<(&str, bool, Option<&str>, Option<&str>)> = proto
            .sessions
            .values()
            .filter(|s| matches!(s.origin, crate::daemon_protocol::Origin::Local))
            .map(|s| {
                (
                    s.id.as_str(),
                    s.metadata.networked,
                    s.metadata.role.as_deref(),
                    s.metadata.bulletin.as_deref(),
                )
            })
            .collect();
        entries.sort_by_key(|(id, _, _, _)| *id);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        entries.hash(&mut hasher);
        hasher.finish()
    }

    /// Each new pane is registered with a name derived from its working
    /// directory basename (e.g. `/Users/me/code/api` becomes `api`).
    /// Returns `(session_id, pane_id)` pairs for newly registered sessions.
    pub async fn add_task(&self, task: ScheduledTask) {
        let mut tasks = self.scheduled_tasks.write().await;
        tasks.insert(task.id.clone(), task);
        self.persist_tasks_from(&tasks);
    }

    pub async fn remove_task(&self, id: &str) -> Option<ScheduledTask> {
        let mut tasks = self.scheduled_tasks.write().await;
        let removed = tasks.remove(id);
        if removed.is_some() {
            self.persist_tasks_from(&tasks);
        }
        removed
    }

    pub async fn update_task(&self, id: &str, f: impl FnOnce(&mut ScheduledTask)) {
        let mut tasks = self.scheduled_tasks.write().await;
        if let Some(task) = tasks.get_mut(id) {
            f(task);
            self.persist_tasks_from(&tasks);
        }
    }

    pub async fn log_task_run(&self, run: TaskRun) {
        {
            let _guard = self
                .task_run_log_lock
                .lock()
                .expect("task_run_log_lock poisoned");
            if let Err(e) = crate::persistence::append_task_run(&self.config.data_dir, &run) {
                tracing::warn!("failed to append task run: {e}");
            }
        }
        let mut runs = self.task_runs.write().await;
        if runs.len() >= MAX_TASK_RUNS {
            runs.pop_front();
        }
        runs.push_back(run);
    }

    pub fn persist_tasks_from(&self, tasks: &HashMap<String, ScheduledTask>) {
        if let Err(e) = crate::persistence::save_tasks(&self.config.data_dir, tasks) {
            tracing::warn!("failed to persist tasks: {e}");
        }
    }

    pub async fn log_message(
        &self,
        from: String,
        to: String,
        message: String,
        delivered: bool,
        method: &str,
    ) {
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let line = serde_json::json!({
            "ts": ts,
            "from": from,
            "to": to,
            "method": method,
            "delivered": delivered,
        });
        {
            let _guard = self.log_file_lock.lock().expect("log_file_lock poisoned");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                use std::io::Write;
                let _ = writeln!(f, "{}", line);
            }
        }

        let entry = LogEntry {
            timestamp: Utc::now(),
            from,
            to,
            message,
            delivered,
        };
        let mut log = self.message_log.write().await;
        if log.len() >= MAX_LOG {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Port where opencode serve is expected to run.
    /// Convention: daemon_port + 320.
    pub fn opencode_serve_port(&self) -> u16 {
        self.config.port + 320
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // --- Pure functions ---

    #[test]
    fn resolve_project_root_normal_path() {
        assert_eq!(
            resolve_project_root("/Users/dan/code/myproject"),
            "/Users/dan/code/myproject"
        );
    }

    #[test]
    fn resolve_project_root_worktree_path() {
        assert_eq!(
            resolve_project_root("/Users/dan/code/chess-reader/.claude/worktrees/feature-branch"),
            "/Users/dan/code/chess-reader"
        );
    }

    #[test]
    fn resolve_project_root_linux_worktree() {
        assert_eq!(
            resolve_project_root("/home/daniel/code/ouija/.claude/worktrees/auto-register"),
            "/home/daniel/code/ouija"
        );
    }

    #[test]
    fn resolve_project_root_ouija_worktree() {
        assert_eq!(
            resolve_project_root("/home/daniel/code/ouija/.ouija/worktrees/feature-x"),
            "/home/daniel/code/ouija"
        );
    }

    // --- AppState async tests ---

    pub(crate) fn test_config() -> OuijaConfig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        OuijaConfig {
            name: "test".into(),
            data_dir: path.clone(),
            config_dir: path,
            port: 0,
            npub: "npub1test".into(),
        }
    }

    /// Helper: register a session via the protocol path.
    async fn proto_register(state: &Arc<AppState>, id: &str, pane: Option<&str>) {
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: id.into(),
                pane: pane.map(Into::into),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;
    }

    #[tokio::test]
    async fn register_session_basic() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;

        let proto = state.protocol.read().await;
        let sessions = &proto.sessions;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key("s1"));
    }

    #[tokio::test]
    async fn register_session_dedup_by_pane() {
        let state = AppState::new(test_config());
        proto_register(&state, "old", Some("%1")).await;
        proto_register(&state, "new", Some("%1")).await;

        let proto = state.protocol.read().await;
        let sessions = &proto.sessions;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key("new"));
        assert!(!sessions.contains_key("old"));
    }

    #[tokio::test]
    async fn register_session_same_id_different_pane_updates() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;
        let effects = state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "s1".into(),
                pane: Some("%2".into()),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;

        // Re-registering same ID with new pane succeeds (e.g. restart)
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, crate::daemon_protocol::Effect::RegisterOk { .. }))
        );

        let proto = state.protocol.read().await;
        let sessions = &proto.sessions;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions.get("s1").unwrap().pane.as_deref(), Some("%2"));
    }

    #[tokio::test]
    async fn register_session_same_id_same_pane_updates() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "s1".into(),
                pane: Some("%1".into()),
                metadata: crate::daemon_protocol::SessionMeta {
                    vim_mode: true,
                    ..Default::default()
                },
            })
            .await;

        let proto = state.protocol.read().await;
        let sessions = &proto.sessions;
        assert!(sessions.get("s1").unwrap().metadata.vim_mode);
    }

    #[tokio::test]
    async fn rename_session_basic() {
        let state = AppState::new(test_config());
        proto_register(&state, "old", Some("%1")).await;
        state
            .apply_and_execute(crate::daemon_protocol::Event::Rename {
                old_id: "old".into(),
                new_id: "new".into(),
            })
            .await;

        let proto = state.protocol.read().await;
        let sessions = &proto.sessions;
        assert!(!sessions.contains_key("old"));
        assert!(sessions.contains_key("new"));
    }

    #[tokio::test]
    async fn rename_session_rejects_slash() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;
        let effects = state
            .apply_and_execute(crate::daemon_protocol::Event::Rename {
                old_id: "s1".into(),
                new_id: "has/slash".into(),
            })
            .await;
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, crate::daemon_protocol::Effect::RenameFailed { .. }))
        );
        assert!(state.protocol.read().await.sessions.contains_key("s1"));
    }

    #[tokio::test]
    async fn rename_nonexistent_returns_none() {
        let state = AppState::new(test_config());
        let effects = state
            .apply_and_execute(crate::daemon_protocol::Event::Rename {
                old_id: "nope".into(),
                new_id: "new".into(),
            })
            .await;
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, crate::daemon_protocol::Effect::RenameFailed { .. }))
        );
    }

    #[tokio::test]
    async fn remove_session_basic() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;
        state
            .apply_and_execute(crate::daemon_protocol::Event::Remove { id: "s1".into(), keep_worktree: false })
            .await;
        assert!(state.protocol.read().await.sessions.is_empty());
    }

    #[tokio::test]
    async fn remove_nonexistent_is_noop() {
        let state = AppState::new(test_config());
        let effects = state
            .apply_and_execute(crate::daemon_protocol::Event::Remove { id: "nope".into(), keep_worktree: false })
            .await;
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, crate::daemon_protocol::Effect::RemoveFailed { .. }))
        );
    }

    #[tokio::test]
    async fn remove_remote_session_fails() {
        let state = AppState::new(test_config());
        {
            let mut proto = state.protocol.write().await;
            proto.sessions.insert(
                "remote/s1".into(),
                crate::daemon_protocol::SessionEntry {
                    id: "remote/s1".into(),
                    origin: crate::daemon_protocol::Origin::Remote("remote".into()),
                    ..Default::default()
                },
            );
        }
        let effects = state
            .apply_and_execute(crate::daemon_protocol::Event::Remove {
                id: "remote/s1".into(),
                keep_worktree: false,
            })
            .await;
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, crate::daemon_protocol::Effect::RemoveFailed { .. }))
        );
        assert_eq!(state.protocol.read().await.sessions.len(), 1);
    }

    /// Helper to build a SessionEntry for tests.
    fn test_entry(
        id: &str,
        pane: Option<&str>,
        origin: crate::daemon_protocol::Origin,
        metadata: crate::daemon_protocol::SessionMeta,
    ) -> crate::daemon_protocol::SessionEntry {
        crate::daemon_protocol::SessionEntry {
            id: id.into(),
            pane: pane.map(Into::into),
            origin,
            metadata,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn log_message_caps_at_max() {
        let state = AppState::new(test_config());
        for i in 0..150 {
            state
                .log_message("from".into(), "to".into(), format!("msg {i}"), true, "test")
                .await;
        }
        let log = state.message_log.read().await;
        assert_eq!(log.len(), MAX_LOG);
    }

    #[tokio::test]
    async fn local_session_hash_changes_on_networked_toggle() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;

        let hash_networked = state.local_session_hash().await;

        // Toggle s1 to non-networked
        {
            let mut proto = state.protocol.write().await;
            proto.sessions.get_mut("s1").unwrap().metadata.networked = false;
        }
        let hash_not_networked = state.local_session_hash().await;

        assert_ne!(hash_networked, hash_not_networked);
    }

    #[tokio::test]
    async fn disconnect_node_removes_sessions() {
        let state = AppState::new(test_config());
        // Add a remote session
        {
            let mut proto = state.protocol.write().await;
            proto.sessions.insert(
                "remote/s1".into(),
                test_entry(
                    "remote/s1",
                    None,
                    crate::daemon_protocol::Origin::Remote("npub1remote".into()),
                    crate::daemon_protocol::SessionMeta::default(),
                ),
            );
            proto.sessions.insert(
                "remote/s2".into(),
                test_entry(
                    "remote/s2",
                    None,
                    crate::daemon_protocol::Origin::Remote("npub1remote".into()),
                    crate::daemon_protocol::SessionMeta::default(),
                ),
            );
        }
        // Add node info
        state.nodes.write().await.insert(
            "npub1remote".into(),
            NodeInfo {
                name: "remote".into(),
                daemon_id: "npub1remote".into(),
                connected_at: Utc::now(),
            },
        );
        state.try_add_node("npub1remote", "remote").unwrap();

        let removed = state.disconnect_node("npub1remote").await;
        assert_eq!(removed, 2);
        assert!(state.protocol.read().await.sessions.is_empty());
        assert!(state.nodes.read().await.is_empty());
    }

    #[test]
    fn session_metadata_networked_defaults_true() {
        let meta = SessionMetadata::default();
        assert!(meta.networked);
    }

    #[test]
    fn session_metadata_networked_serde_default() {
        // Old JSON without "networked" field should default to true
        let json = r#"{"vim_mode": false}"#;
        let meta: SessionMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.networked);
    }

    // --- SessionOrigin serde ---

    #[test]
    fn session_origin_human_round_trip() {
        let origin = SessionOrigin::Human("npub1abc".into());
        let json = serde_json::to_string(&origin).unwrap();
        let parsed: SessionOrigin = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SessionOrigin::Human(npub) if npub == "npub1abc"));
    }

    #[test]
    fn session_origin_human_deserializes() {
        let json = r#"{"Human":"npub1xyz"}"#;
        let origin: SessionOrigin = serde_json::from_str(json).unwrap();
        assert!(matches!(origin, SessionOrigin::Human(npub) if npub == "npub1xyz"));
    }

    #[tokio::test]
    async fn update_session_metadata_sets_role() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;

        state
            .apply_and_execute(crate::daemon_protocol::Event::UpdateMetadata {
                id: "s1".into(),
                role: Some("debugging auth".into()),
                bulletin: None,
                project_dir: None,
                networked: None,
            })
            .await;

        let proto = state.protocol.read().await;
        assert_eq!(
            proto.sessions["s1"].metadata.role.as_deref(),
            Some("debugging auth")
        );
    }

    #[tokio::test]
    async fn local_session_hash_changes_on_role_update() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;

        let hash_before = state.local_session_hash().await;

        state
            .apply_and_execute(crate::daemon_protocol::Event::UpdateMetadata {
                id: "s1".into(),
                role: Some("new role".into()),
                bulletin: None,
                project_dir: None,
                networked: None,
            })
            .await;

        let hash_after = state.local_session_hash().await;
        assert_ne!(hash_before, hash_after);
    }

    #[tokio::test]
    async fn update_metadata_sets_bulletin() {
        let state = AppState::new(test_config());
        proto_register(&state, "s1", Some("%1")).await;

        state
            .apply_and_execute(crate::daemon_protocol::Event::UpdateMetadata {
                id: "s1".into(),
                role: None,
                bulletin: Some("offering review".into()),
                project_dir: None,
                networked: None,
            })
            .await;

        let proto = state.protocol.read().await;
        assert_eq!(
            proto.sessions["s1"].metadata.bulletin.as_deref(),
            Some("offering review")
        );
    }

    // --- collect_excess_idle_sessions ---

    #[tokio::test]
    async fn excess_idle_disabled_when_zero() {
        let state = AppState::new(test_config());
        // max_local_sessions defaults to 0 (disabled)
        proto_register(&state, "s1", Some("%1")).await;
        assert!(state.collect_excess_idle_sessions().await.is_empty());
    }

    #[tokio::test]
    async fn excess_idle_no_eviction_at_limit() {
        let state = AppState::new(test_config());
        state.settings.write().await.max_local_sessions = 2;
        proto_register(&state, "s1", Some("%1")).await;
        proto_register(&state, "s2", Some("%2")).await;
        assert!(state.collect_excess_idle_sessions().await.is_empty());
    }

    #[tokio::test]
    async fn excess_idle_evicts_when_over_limit() {
        use crate::daemon_protocol::{Origin, SessionMeta};
        let state = AppState::new(test_config());
        state.settings.write().await.max_local_sessions = 2;

        // Insert 3 local sessions
        {
            let mut proto = state.protocol.write().await;
            for name in &["a", "b", "c"] {
                proto.sessions.insert(
                    name.to_string(),
                    test_entry(name, Some("%1"), Origin::Local, SessionMeta::default()),
                );
            }
        }

        let evicted = state.collect_excess_idle_sessions().await;
        assert_eq!(evicted.len(), 1);
    }

    #[tokio::test]
    async fn excess_idle_ignores_remote_and_human() {
        use crate::daemon_protocol::{Origin, SessionMeta};
        let state = AppState::new(test_config());
        state.settings.write().await.max_local_sessions = 1;

        {
            let mut proto = state.protocol.write().await;
            proto.sessions.insert(
                "local".into(),
                test_entry("local", Some("%1"), Origin::Local, SessionMeta::default()),
            );
            proto.sessions.insert(
                "remote/r1".into(),
                test_entry(
                    "remote/r1",
                    None,
                    Origin::Remote("npub1x".into()),
                    SessionMeta::default(),
                ),
            );
            proto.sessions.insert(
                "human".into(),
                test_entry(
                    "human",
                    None,
                    Origin::Human("npub1h".into()),
                    SessionMeta::default(),
                ),
            );
        }

        assert!(state.collect_excess_idle_sessions().await.is_empty());
    }
}
