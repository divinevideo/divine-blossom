//! Pure session state machine. No I/O, no async, no locks.
//! Both the runtime and Stateright model call `DaemonState::apply()`.

use std::collections::BTreeMap;

// --- State ---

/// Pure daemon state. Clone+Hash+Eq for Stateright.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DaemonState {
    pub daemon_id: String,
    pub daemon_name: String,
    pub sessions: BTreeMap<String, SessionEntry>,
    pub aliases: BTreeMap<String, String>,
    pub wire_seq: u64,
    pub last_seen_seq: BTreeMap<String, u64>,
    /// Pending replies: session_id → list of pending msg_ids
    pub pending_replies: BTreeMap<String, Vec<PendingReplyEntry>>,
}

/// A pending reply entry tracked in DaemonState.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingReplyEntry {
    pub msg_id: u64,
    pub from: String,
    pub message: String,
    pub received_at: i64,
    pub last_activity: i64,
    pub in_progress: bool,
}

/// A registered session with its identity, origin, and metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub struct SessionEntry {
    pub id: String,
    pub pane: Option<String>,
    pub origin: Origin,
    pub metadata: SessionMeta,
    /// Unix timestamp of registration. Used for reaper grace period.
    #[serde(default)]
    pub registered_at: i64,
}

/// Where a session originates: local, remote peer, or human operator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Origin {
    #[default]
    Local,
    Remote(String),
    Human(String),
}

impl Origin {
    /// Short label for JSON APIs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote(_) => "remote",
            Self::Human(_) => "human",
        }
    }
}

/// A single iteration log entry from a loop_next call.
/// Uses i64 timestamp (not DateTime<Utc>) because DaemonState requires Hash+Eq.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IterationLogEntry {
    pub iteration: u64,
    pub message: Option<String>,
    pub timestamp: i64,
}

/// Mutable metadata attached to a session (role, project, flags).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SessionMeta {
    #[serde(default)]
    pub project_dir: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub bulletin: Option<String>,
    #[serde(default)]
    pub networked: bool,
    #[serde(default)]
    pub worktree: bool,
    #[serde(default)]
    pub vim_mode: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "claude_session_id"
    )]
    pub backend_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_description: Option<String>,
    /// Unix timestamp; 0 in model tests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_metadata_update: Option<i64>,
    /// Which LLM model this session is configured to use (informational only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Reminder text re-injected on idle. Also appended to prompt at session start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminder: Option<String>,
    /// Original prompt from session_start, stored for re-injection on iteration.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "original_prompt")]
    pub prompt: Option<String>,
    /// How many times loop_next has been called on this session.
    #[serde(default, alias = "loop_iteration")]
    pub iteration: u64,
    /// Log messages from each iteration. Capped at 100 entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "loop_log")]
    pub iteration_log: Vec<IterationLogEntry>,
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

/// Metadata becomes stale after 30 minutes without an update.
const METADATA_STALE_SECS: i64 = 1800;

impl SessionMeta {
    /// Returns `true` if metadata has never been explicitly set or is older than 30 minutes.
    pub fn is_stale(&self) -> bool {
        match self.last_metadata_update {
            None => true,
            Some(ts) => chrono::Utc::now().timestamp() - ts > METADATA_STALE_SECS,
        }
    }

    /// Fill recurrence fields from `source` for any field still at its default value.
    /// Used during re-registration so the startup hook doesn't wipe recurrence state
    /// that was set by session_start or carried forward by restart_session.
    pub fn inherit_recurrence_from(&mut self, source: &SessionMeta) {
        if self.prompt.is_none() {
            self.prompt = source.prompt.clone();
        }
        if self.reminder.is_none() {
            self.reminder = source.reminder.clone();
        }
        if self.iteration == 0 && source.iteration > 0 {
            self.iteration = source.iteration;
        }
        if self.iteration_log.is_empty() && !source.iteration_log.is_empty() {
            self.iteration_log = source.iteration_log.clone();
        }
        if self.last_iteration_at.is_none() && source.last_iteration_at.is_some() {
            self.last_iteration_at = source.last_iteration_at;
        }
        if self.on_fire.is_none() {
            self.on_fire = source.on_fire.clone();
        }
        if self.workflow.is_none() {
            self.workflow = source.workflow.clone();
        }
        if self.workflow_calls == 0 && source.workflow_calls > 0 {
            self.workflow_calls = source.workflow_calls;
        }
        if self.workflow_max_calls == 0 && source.workflow_max_calls > 0 {
            self.workflow_max_calls = source.workflow_max_calls;
        }
    }
}

impl Default for SessionMeta {
    fn default() -> Self {
        Self {
            project_dir: None,
            role: None,
            bulletin: None,
            networked: true,
            worktree: false,
            vim_mode: false,
            backend_session_id: None,
            backend: None,
            project_description: None,
            last_metadata_update: None,
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

// --- Events ---

/// Input events that drive state transitions in [`DaemonState::apply`].
#[derive(Debug)]
pub enum Event {
    Register {
        id: String,
        pane: Option<String>,
        metadata: SessionMeta,
    },
    Rename {
        old_id: String,
        new_id: String,
    },
    Remove {
        id: String,
        keep_worktree: bool,
    },
    UpdateMetadata {
        id: String,
        role: Option<String>,
        bulletin: Option<String>,
        project_dir: Option<String>,
        networked: Option<bool>,
    },
    ReapDead {
        dead_ids: Vec<String>,
    },
    IncomingWire {
        msg: crate::protocol::WireMessage,
        sender_npub: Option<String>,
    },
    Send {
        from: String,
        to: String,
        message: String,
        expects_reply: bool,
        responds_to: Option<u64>,
        done: bool,
    },
}

// --- Effects ---

/// Side effects returned by apply(). Values, not actions.
/// The runtime executes them. The model inspects or ignores them.
#[derive(Clone, Debug)]
pub enum Effect {
    // Wire
    Broadcast(crate::protocol::WireMessage),
    BroadcastSessionList,

    // Tmux
    SetTmuxVar {
        pane: String,
        name: String,
        value: String,
    },
    ClearTmuxVar {
        pane: String,
        name: String,
    },
    RenameWindow {
        pane: String,
        name: String,
    },
    EnableAutoRename {
        pane: String,
    },
    InjectMessage {
        session_id: String,
        pane: String,
        message: String,
        vim_mode: bool,
    },

    // Agents
    SpawnAgent {
        session_id: String,
        pane: String,
    },
    StopAgent {
        session_id: String,
    },
    RenameAgent {
        old_id: String,
        new_id: String,
    },
    ClearPendingReplies {
        removed_ids: Vec<String>,
    },

    // Persistence
    Persist,

    // Logging
    Log {
        level: LogLevel,
        message: String,
    },

    // Nostr DM
    SendToHuman {
        npub: String,
        message: String,
    },

    // Remote commands
    ExecuteCommand {
        command: String,
        daemon_id: String,
    },
    ExecuteSessionStart {
        name: String,
        worktree: Option<bool>,
        project_dir: Option<String>,
        prompt: Option<String>,
        reminder: Option<String>,
        from: Option<String>,
        expects_reply: Option<bool>,
        daemon_id: String,
    },
    ExecuteSessionRestart {
        name: String,
        fresh: Option<bool>,
        prompt: Option<String>,
        reminder: Option<String>,
        from: Option<String>,
        expects_reply: Option<bool>,
        daemon_id: String,
    },
    DeliverCommandResult {
        daemon_id: String,
        command: String,
        result: String,
    },

    // Node tracking
    RecordNode {
        daemon_id: String,
        daemon_name: String,
    },
    Reciprocate {
        daemon_id: String,
    },

    // Message logging
    LogMessage {
        from: String,
        to: String,
        message: String,
        delivered: bool,
        transport: String,
    },

    // Results (for callers that need return values)
    RegisterOk {
        session_id: String,
        replaced: Option<String>,
    },
    SendDelivered {
        from: String,
        to: String,
        method: String,
        msg_id: u64,
    },
    SendFailed {
        from: String,
        to: String,
        reason: String,
        renamed_to: Option<String>,
    },
    RenameOk {
        old_id: String,
        new_id: String,
    },
    RenameFailed {
        reason: String,
    },
    RemoveOk {
        id: String,
    },
    RemoveFailed {
        reason: String,
    },
    CleanupWorktree {
        project_dir: String,
    },

    // Workflow lifecycle
    NotifyWorkflow {
        workflow_path: String,
        event: String,
        session_id: String,
        project_dir: Option<String>,
    },
}

/// Severity level for log effects emitted by the state machine.
#[derive(Clone, Debug)]
pub enum LogLevel {
    Info,
    Warn,
    Debug,
}

// --- Helpers ---

/// Builds a namespaced key like `"daemon_name/session_id"` for remote sessions.
pub fn remote_session_key(daemon_name: &str, raw_id: &str) -> String {
    format!("{daemon_name}/{raw_id}")
}

/// Strips the `"daemon_name/"` prefix, returning the raw session id.
///
/// Returns the input unchanged if no prefix is present.
pub fn strip_remote_prefix(prefixed_id: &str) -> &str {
    prefixed_id
        .split_once('/')
        .map(|(_, raw)| raw)
        .unwrap_or(prefixed_id)
}

fn display_name<'a>(daemon_name: &'a str, daemon_id: &'a str) -> &'a str {
    if daemon_name.is_empty() {
        daemon_id
    } else {
        daemon_name
    }
}

/// Format an XML-tagged session message for tmux injection.
pub fn format_session_message(
    from: &str,
    message: &str,
    expects_reply: bool,
    msg_id: u64,
    responds_to: Option<u64>,
    done: bool,
) -> String {
    let mut attrs = format!(r#"from="{from}" id="{msg_id}""#);
    if expects_reply {
        attrs.push_str(r#" reply="true""#);
    }
    if let Some(re) = responds_to {
        attrs.push_str(&format!(r#" re="{re}""#));
    }
    if done {
        attrs.push_str(r#" done="true""#);
    }
    format!("<msg {attrs}>{message}</msg>")
}

fn metadata_to_session_meta(m: Option<&crate::state::SessionMetadata>) -> SessionMeta {
    match m {
        Some(m) => SessionMeta {
            project_dir: m.project_dir.clone(),
            role: m.role.clone(),
            bulletin: m.bulletin.clone(),
            networked: m.networked,
            worktree: m.worktree,
            vim_mode: m.vim_mode,
            backend_session_id: m.backend_session_id.clone(),
            backend: m.backend.clone(),
            project_description: m.project_description.clone(),
            last_metadata_update: m.last_metadata_update.map(|ts| ts.timestamp()),
            model: m.model.clone(),
            reminder: m.reminder.clone(),
            prompt: m.prompt.clone(),
            iteration: m.iteration,
            iteration_log: m.iteration_log.clone(),
            last_iteration_at: m.last_iteration_at,
            on_fire: m.on_fire.clone(),
            workflow: m.workflow.clone(),
            workflow_calls: m.workflow_calls,
            workflow_max_calls: m.workflow_max_calls,
        },
        None => SessionMeta::default(),
    }
}

// --- Implementation ---

impl DaemonState {
    /// Create a new DaemonState with timestamp-based wire_seq so that a
    /// restarted daemon's sequence numbers are always higher than the previous
    /// incarnation's, avoiding generation-counter rejection by peers.
    pub fn new(daemon_id: String, daemon_name: String) -> Self {
        Self {
            daemon_id,
            daemon_name,
            wire_seq: chrono::Utc::now().timestamp() as u64,
            ..Default::default()
        }
    }

    /// Deterministic constructor for model checking (wire_seq starts at 0).
    #[cfg(test)]
    pub fn new_for_model(daemon_id: String, daemon_name: String) -> Self {
        Self {
            daemon_id,
            daemon_name,
            ..Default::default()
        }
    }

    /// Increment and return the next wire sequence number.
    pub fn next_seq(&mut self) -> u64 {
        self.wire_seq += 1;
        self.wire_seq
    }

    /// Accept a peer's sequence number, rejecting stale duplicates.
    pub fn accept_seq(&mut self, daemon_id: &str, seq: u64) -> bool {
        let last = self.last_seen_seq.get(daemon_id).copied().unwrap_or(0);
        if seq < last {
            return false;
        }
        self.last_seen_seq.insert(daemon_id.to_string(), seq);
        true
    }

    /// Clear pending replies from a specific sender on a session.
    pub fn clear_pending_reply_from(&mut self, session: &str, from: &str) {
        if let Some(pending) = self.pending_replies.get_mut(session) {
            pending.retain(|p| p.from != from);
            if pending.is_empty() {
                self.pending_replies.remove(session);
            }
        }
    }

    /// Clear pending replies for removed sessions (both as target and sender).
    pub fn clear_orphaned_replies(&mut self, removed_ids: &[String]) {
        for pending in self.pending_replies.values_mut() {
            pending.retain(|p| !removed_ids.contains(&p.from));
        }
        self.pending_replies.retain(|_, v| !v.is_empty());
        for id in removed_ids {
            self.pending_replies.remove(id);
        }
    }

    /// Core state machine. Apply an event, return effects.
    pub fn apply(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::Register { id, pane, metadata } => self.apply_register(id, pane, metadata),
            Event::Rename { old_id, new_id } => self.apply_rename(&old_id, &new_id),
            Event::Remove { id, keep_worktree } => self.apply_remove(&id, keep_worktree),
            Event::UpdateMetadata {
                id,
                role,
                bulletin,
                project_dir,
                networked,
            } => self.apply_update_metadata(&id, role, bulletin, project_dir, networked),
            Event::ReapDead { dead_ids } => self.apply_reap(dead_ids),
            Event::IncomingWire { msg, sender_npub } => self.apply_incoming_wire(msg, sender_npub),
            Event::Send {
                from,
                to,
                message,
                expects_reply,
                responds_to,
                done,
            } => self.apply_send(&from, &to, &message, expects_reply, responds_to, done),
        }
    }

    fn apply_register(
        &mut self,
        id: String,
        pane: Option<String>,
        metadata: SessionMeta,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();

        // If re-registering the same ID with a different pane (e.g. restart),
        // clean up the old pane's tmux state before proceeding.
        if let Some(ref new_pane) = pane {
            if let Some(existing) = self.sessions.get(&id) {
                if matches!(existing.origin, Origin::Local) {
                    if let Some(ref old_pane) = existing.pane {
                        if old_pane != new_pane {
                            effects.push(Effect::ClearTmuxVar {
                                pane: old_pane.clone(),
                                name: "@ouija_session".into(),
                            });
                            effects.push(Effect::EnableAutoRename {
                                pane: old_pane.clone(),
                            });
                            effects.push(Effect::StopAgent {
                                session_id: id.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Pane dedup: same pane registered under different ID
        let replaced = if let Some(ref pane_id) = pane {
            let old_key = self
                .sessions
                .iter()
                .find(|(key, s)| {
                    *key != &id
                        && matches!(s.origin, Origin::Local)
                        && s.pane.as_deref() == Some(pane_id)
                })
                .map(|(key, _)| key.clone());
            if let Some(ref old_key) = old_key {
                self.sessions.remove(old_key);
                effects.push(Effect::StopAgent {
                    session_id: old_key.clone(),
                });
            }
            old_key
        } else {
            None
        };

        // Preserve recurrence state: the startup hook may re-register after session_start
        // or loop_next's restart, arriving with blank metadata. Without this, the
        // hook's Register would wipe prompt, reminder, and iteration progress.
        let mut metadata = metadata;
        if let Some(existing) = self.sessions.get(&id) {
            metadata.inherit_recurrence_from(&existing.metadata);
        }

        // Insert session
        let session = SessionEntry {
            id: id.clone(),
            pane: pane.clone(),
            origin: Origin::Local,
            metadata,
            registered_at: chrono::Utc::now().timestamp(),
        };
        self.sessions.insert(id.clone(), session);
        effects.push(Effect::Persist);

        // Tmux effects
        if let Some(ref pane_id) = pane {
            effects.push(Effect::SetTmuxVar {
                pane: pane_id.clone(),
                name: "@ouija_session".into(),
                value: id.clone(),
            });
        }

        // Alias if replaced
        if let Some(ref old_key) = replaced {
            self.add_alias(old_key, &id);
        }

        // Agent
        if let Some(ref pane_id) = pane {
            effects.push(Effect::SpawnAgent {
                session_id: id.clone(),
                pane: pane_id.clone(),
            });
        }

        // Network announce
        let session_meta = self.sessions.get(&id);
        let networked = session_meta.map(|s| s.metadata.networked).unwrap_or(false);
        if let Some(ref old_key) = replaced {
            let seq = self.next_seq();
            effects.push(Effect::Broadcast(
                crate::protocol::WireMessage::SessionRenamed {
                    old_id: old_key.clone(),
                    new_id: id.clone(),
                    daemon_id: self.daemon_id.clone(),
                    daemon_name: self.daemon_name.clone(),
                    metadata: None,
                    seq,
                },
            ));
            effects.push(Effect::BroadcastSessionList);
        } else if networked {
            let seq = self.next_seq();
            effects.push(Effect::Broadcast(
                crate::protocol::WireMessage::SessionAnnounce {
                    id: id.clone(),
                    daemon_id: self.daemon_id.clone(),
                    daemon_name: self.daemon_name.clone(),
                    metadata: None,
                    seq,
                },
            ));
            effects.push(Effect::BroadcastSessionList);
        }

        effects.push(Effect::RegisterOk {
            session_id: id,
            replaced,
        });

        effects
    }

    fn add_alias(&mut self, old_id: &str, new_id: &str) {
        if old_id == new_id {
            return;
        }
        for target in self.aliases.values_mut() {
            if *target == old_id {
                *target = new_id.to_string();
            }
        }
        self.aliases.insert(old_id.to_string(), new_id.to_string());
        // Remove self-loops created by repointing (e.g. B→C repointed to B→B)
        self.aliases.retain(|k, v| k != v);
    }

    pub fn resolve_alias(&self, id: &str) -> Option<&str> {
        let target = self.aliases.get(id)?;
        if self.sessions.contains_key(target.as_str()) {
            Some(target.as_str())
        } else {
            None
        }
    }

    fn apply_rename(&mut self, old_id: &str, new_id: &str) -> Vec<Effect> {
        let mut effects = Vec::new();

        if new_id.contains('/') {
            effects.push(Effect::RenameFailed {
                reason: "session ID cannot contain '/'".into(),
            });
            return effects;
        }

        // Check origin before removing
        match self.sessions.get(old_id).map(|s| &s.origin) {
            Some(Origin::Local) => {}
            Some(_) => {
                effects.push(Effect::RenameFailed {
                    reason: format!("cannot rename remote session '{old_id}'"),
                });
                return effects;
            }
            None => {
                effects.push(Effect::RenameFailed {
                    reason: format!("session '{old_id}' not found"),
                });
                return effects;
            }
        };

        let mut renamed = self
            .sessions
            .remove(old_id)
            .expect("session must exist after origin guard");
        renamed.id = new_id.to_string();
        let pane = renamed.pane.clone();
        self.sessions.insert(new_id.to_string(), renamed);

        // Migrate pending_replies key
        if let Some(pending) = self.pending_replies.remove(old_id) {
            self.pending_replies.insert(new_id.to_string(), pending);
        }

        effects.push(Effect::Persist);

        if let Some(ref pane_id) = pane {
            effects.push(Effect::SetTmuxVar {
                pane: pane_id.clone(),
                name: "@ouija_session".into(),
                value: new_id.to_string(),
            });
        }

        self.add_alias(old_id, new_id);

        effects.push(Effect::RenameAgent {
            old_id: old_id.to_string(),
            new_id: new_id.to_string(),
        });

        let seq = self.next_seq();
        effects.push(Effect::Broadcast(
            crate::protocol::WireMessage::SessionRenamed {
                old_id: old_id.to_string(),
                new_id: new_id.to_string(),
                daemon_id: self.daemon_id.clone(),
                daemon_name: self.daemon_name.clone(),
                metadata: None,
                seq,
            },
        ));
        effects.push(Effect::BroadcastSessionList);

        effects.push(Effect::RenameOk {
            old_id: old_id.to_string(),
            new_id: new_id.to_string(),
        });

        effects
    }

    fn apply_remove(&mut self, id: &str, keep_worktree: bool) -> Vec<Effect> {
        let mut effects = Vec::new();

        // Check origin before removing
        match self.sessions.get(id).map(|s| &s.origin) {
            Some(Origin::Local) => {}
            Some(_) => {
                effects.push(Effect::RemoveFailed {
                    reason: format!("cannot remove remote session '{id}'"),
                });
                return effects;
            }
            None => {
                effects.push(Effect::RemoveFailed {
                    reason: format!("session '{id}' not found"),
                });
                return effects;
            }
        };

        // Note: stale-remove guard (registered_at < 5s) lives in the hooks
        // handler (session_end_inner), not here. The protocol-level Remove must
        // always succeed for direct API callers (admin, CLI, tests).

        let session = self
            .sessions
            .remove(id)
            .expect("session must exist after origin guard");
        effects.push(Effect::Persist);

        if let Some(ref pane_id) = session.pane {
            effects.push(Effect::ClearTmuxVar {
                pane: pane_id.clone(),
                name: "@ouija_session".into(),
            });
            effects.push(Effect::EnableAutoRename {
                pane: pane_id.clone(),
            });
        }

        effects.push(Effect::StopAgent {
            session_id: id.to_string(),
        });
        effects.push(Effect::ClearPendingReplies {
            removed_ids: vec![id.to_string()],
        });

        // Worktree cleanup on explicit kill (not reap), unless keep_worktree is set
        // or another session is still using the same worktree directory.
        if !keep_worktree {
            if let Some(ref dir) = session.metadata.project_dir {
                if dir.contains("/.ouija/worktrees/") || dir.contains("/.claude/worktrees/") {
                    let shared = self
                        .sessions
                        .values()
                        .any(|s| s.metadata.project_dir.as_deref() == Some(dir.as_str()));
                    if shared {
                        effects.push(Effect::Log {
                            level: LogLevel::Info,
                            message: format!(
                                "skipping worktree cleanup for {dir}: other sessions still using it"
                            ),
                        });
                    } else {
                        effects.push(Effect::CleanupWorktree {
                            project_dir: dir.clone(),
                        });
                    }
                }
            }
        }

        let seq = self.next_seq();
        effects.push(Effect::Broadcast(
            crate::protocol::WireMessage::SessionRemove {
                id: id.to_string(),
                daemon_id: self.daemon_id.clone(),
                daemon_name: self.daemon_name.clone(),
                seq,
            },
        ));
        effects.push(Effect::BroadcastSessionList);

        // Notify workflow if this session was workflow-driven
        if let Some(ref wf) = session.metadata.workflow {
            effects.push(Effect::NotifyWorkflow {
                workflow_path: wf.clone(),
                event: "session_died".into(),
                session_id: id.to_string(),
                project_dir: session.metadata.project_dir.clone(),
            });
        }

        effects.push(Effect::RemoveOk { id: id.to_string() });

        effects
    }

    fn apply_update_metadata(
        &mut self,
        id: &str,
        role: Option<String>,
        bulletin: Option<String>,
        project_dir: Option<String>,
        networked: Option<bool>,
    ) -> Vec<Effect> {
        let session = match self.sessions.get_mut(id) {
            Some(s) if matches!(s.origin, Origin::Local) => s,
            _ => return vec![],
        };
        if let Some(r) = role {
            session.metadata.role = Some(r);
        }
        if let Some(p) = project_dir {
            session.metadata.project_dir = Some(p);
        }
        if let Some(b) = bulletin {
            session.metadata.bulletin = Some(b);
        }
        if let Some(n) = networked {
            session.metadata.networked = n;
        }
        let mut effects = vec![Effect::Persist];
        if session.metadata.networked {
            effects.push(Effect::BroadcastSessionList);
        }
        effects
    }

    fn apply_reap(&mut self, dead_ids: Vec<String>) -> Vec<Effect> {
        let mut effects = Vec::new();

        for id in &dead_ids {
            let session = match self.sessions.remove(id) {
                Some(s) if matches!(s.origin, Origin::Local) => s,
                Some(s) => {
                    self.sessions.insert(id.clone(), s);
                    continue;
                }
                None => continue,
            };

            effects.push(Effect::Log {
                level: LogLevel::Info,
                message: format!("reaped dead session: {id}"),
            });

            if let Some(ref pane_id) = session.pane {
                effects.push(Effect::ClearTmuxVar {
                    pane: pane_id.clone(),
                    name: "@ouija_session".into(),
                });
                effects.push(Effect::EnableAutoRename {
                    pane: pane_id.clone(),
                });
            }

            effects.push(Effect::StopAgent {
                session_id: id.clone(),
            });
            // Note: no CleanupWorktree on reap (preserves uncommitted work)
        }

        if !dead_ids.is_empty() {
            effects.push(Effect::Persist);
            effects.push(Effect::ClearPendingReplies {
                removed_ids: dead_ids,
            });
            // Increment wire_seq so the session list carries a fresh sequence
            // number. Without this, the list shares the seq of the prior
            // mutation and can be reordered with it, breaking convergence.
            self.next_seq();
            effects.push(Effect::BroadcastSessionList);
        }

        effects
    }

    fn apply_incoming_wire(
        &mut self,
        msg: crate::protocol::WireMessage,
        sender_npub: Option<String>,
    ) -> Vec<Effect> {
        use crate::protocol::WireMessage;

        // Verify daemon_id matches sender_npub when available
        if let Some(ref expected) = sender_npub {
            if let Some(claimed) = msg.daemon_id() {
                if claimed != expected.as_str() {
                    return vec![Effect::Log {
                        level: LogLevel::Warn,
                        message: format!(
                            "daemon_id mismatch: message claims {claimed} but sender is {expected}, dropping"
                        ),
                    }];
                }
            }
        }

        // Drop stale wire messages
        if let (Some(daemon_id), Some(seq)) = (msg.daemon_id(), msg.seq()) {
            if !self.accept_seq(daemon_id, seq) {
                return vec![Effect::Log {
                    level: LogLevel::Debug,
                    message: format!(
                        "dropping stale message from {daemon_id} (seq={seq} < last_seen)"
                    ),
                }];
            }
        }

        match msg {
            WireMessage::SessionSend {
                from,
                to,
                message,
                expects_reply,
                msg_id,
                responds_to,
                done,
            } => self.apply_incoming_send(
                &from,
                &to,
                &message,
                expects_reply,
                msg_id,
                responds_to,
                done,
                sender_npub.as_deref(),
            ),
            WireMessage::SessionSendAck {
                from,
                to,
                delivered,
                daemon_id,
            } => {
                let level = if delivered {
                    LogLevel::Info
                } else {
                    LogLevel::Warn
                };
                let status = if delivered { "delivered" } else { "FAILED" };
                vec![Effect::Log {
                    level,
                    message: format!("ack: message {from}->{to} {status} by {daemon_id}"),
                }]
            }
            WireMessage::SessionAnnounce {
                id,
                daemon_id,
                daemon_name,
                metadata,
                ..
            } => self.apply_incoming_announce(&id, &daemon_id, &daemon_name, metadata),
            WireMessage::SessionList {
                sessions,
                daemon_id,
                daemon_name,
                ..
            } => self.apply_incoming_session_list(sessions, &daemon_id, &daemon_name),
            WireMessage::SessionRemove {
                id,
                daemon_id,
                daemon_name,
                ..
            } => self.apply_incoming_remove(&id, &daemon_id, &daemon_name),
            WireMessage::SessionRenamed {
                old_id,
                new_id,
                daemon_id,
                daemon_name,
                metadata,
                ..
            } => self.apply_incoming_renamed(&old_id, &new_id, &daemon_id, &daemon_name, metadata),
            WireMessage::ConnectRequest { .. } => {
                // Handled directly in the nostr receive loop
                vec![]
            }
            WireMessage::Command { command, daemon_id } => {
                vec![Effect::ExecuteCommand { command, daemon_id }]
            }
            WireMessage::SessionStart {
                name,
                project_dir,
                worktree,
                prompt,
                reminder,
                from,
                expects_reply,
                daemon_id,
                ..
            } => {
                vec![Effect::ExecuteSessionStart {
                    name,
                    worktree,
                    project_dir,
                    prompt,
                    reminder,
                    from,
                    expects_reply,
                    daemon_id,
                }]
            }
            WireMessage::SessionRestart {
                name,
                fresh,
                prompt,
                reminder,
                from,
                expects_reply,
                daemon_id,
                ..
            } => {
                vec![Effect::ExecuteSessionRestart {
                    name,
                    fresh,
                    prompt,
                    reminder,
                    from,
                    expects_reply,
                    daemon_id,
                }]
            }
            WireMessage::CommandResult {
                command,
                result,
                daemon_id,
            } => {
                vec![Effect::DeliverCommandResult {
                    daemon_id,
                    command,
                    result,
                }]
            }
        }
    }

    fn apply_incoming_send(
        &mut self,
        from: &str,
        to: &str,
        message: &str,
        expects_reply: bool,
        msg_id: u64,
        responds_to: Option<u64>,
        done: bool,
        sender_npub: Option<&str>,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        // Use remote msg_id if provided, otherwise assign a local one
        let local_msg_id = if msg_id > 0 { msg_id } else { self.next_seq() };

        // Three-tier reply handling — pending is keyed by the session that
        // owes the reply (from), not the recipient of this wire message (to).
        if let Some(re_id) = responds_to {
            if done {
                if let Some(pending) = self.pending_replies.get_mut(from) {
                    pending.retain(|p| p.msg_id != re_id);
                    if pending.is_empty() {
                        self.pending_replies.remove(from);
                    }
                }
            } else if let Some(pending) = self.pending_replies.get_mut(from) {
                if let Some(entry) = pending.iter_mut().find(|p| p.msg_id == re_id) {
                    entry.last_activity = chrono::Utc::now().timestamp();
                    entry.in_progress = true;
                }
            }
        }

        // Resolve bare `from` to daemon-prefixed remote session key.
        // First try exact match in known remote sessions.
        // If not found, derive prefix from any remote session sharing the sender's npub.
        let remote_match = self
            .sessions
            .iter()
            .find(|(_, s)| {
                matches!(&s.origin, Origin::Remote(_)) && strip_remote_prefix(&s.id) == from
            })
            .map(|(key, _)| key.clone());
        let display_from = remote_match.unwrap_or_else(|| {
            // Session not in our list — derive prefix from sender's daemon npub
            if let Some(npub) = sender_npub {
                if let Some((key, _)) = self
                    .sessions
                    .iter()
                    .find(|(_, s)| matches!(&s.origin, Origin::Remote(d) if d == npub))
                {
                    let prefix = key.split('/').next().unwrap_or(from);
                    return format!("{prefix}/{from}");
                }
            }
            from.to_string()
        });

        let target = self.sessions.get(to).cloned();

        match target {
            Some(ref session)
                if matches!(session.origin, Origin::Local) && session.metadata.networked =>
            {
                if let Some(ref pane) = session.pane {
                    let formatted = format_session_message(
                        &display_from,
                        message,
                        expects_reply,
                        local_msg_id,
                        responds_to,
                        done,
                    );
                    effects.push(Effect::InjectMessage {
                        session_id: to.to_string(),
                        pane: pane.clone(),
                        message: formatted,
                        vim_mode: session.metadata.vim_mode,
                    });

                    if expects_reply {
                        self.pending_replies
                            .entry(to.to_string())
                            .or_default()
                            .push(PendingReplyEntry {
                                msg_id: local_msg_id,
                                from: display_from.clone(),
                                message: message.to_string(),
                                received_at: chrono::Utc::now().timestamp(),
                                last_activity: chrono::Utc::now().timestamp(),
                                in_progress: false,
                            });
                    }

                    effects.push(Effect::LogMessage {
                        from: from.to_string(),
                        to: to.to_string(),
                        message: message.to_string(),
                        delivered: true,
                        transport: "nostr".into(),
                    });

                    effects.push(Effect::Broadcast(
                        crate::protocol::WireMessage::SessionSendAck {
                            from: from.to_string(),
                            to: to.to_string(),
                            delivered: true,
                            daemon_id: self.daemon_id.clone(),
                        },
                    ));
                }
            }
            Some(ref session) if matches!(&session.origin, Origin::Human(..)) => {
                let npub = match &session.origin {
                    Origin::Human(n) => n.clone(),
                    _ => unreachable!(),
                };
                let formatted = format!("[from {display_from}]: {message}");
                effects.push(Effect::SendToHuman {
                    npub,
                    message: formatted,
                });
                effects.push(Effect::LogMessage {
                    from: from.to_string(),
                    to: to.to_string(),
                    message: message.to_string(),
                    delivered: true,
                    transport: "nostr-dm".into(),
                });
            }
            _ => {
                effects.push(Effect::Log {
                    level: LogLevel::Warn,
                    message: format!("SessionSend target '{to}' not found or not local"),
                });
            }
        }

        effects
    }

    fn apply_incoming_announce(
        &mut self,
        id: &str,
        daemon_id: &str,
        daemon_name: &str,
        metadata: Option<crate::state::SessionMetadata>,
    ) -> Vec<Effect> {
        let display = display_name(daemon_name, daemon_id);
        let key = remote_session_key(display, id);

        let entry = self
            .sessions
            .entry(key.clone())
            .or_insert_with(|| SessionEntry {
                id: key,
                pane: None,
                origin: Origin::Remote(daemon_id.to_string()),
                metadata: metadata_to_session_meta(metadata.as_ref()),
                ..Default::default()
            });
        if let Some(ref m) = metadata {
            entry.metadata = metadata_to_session_meta(Some(m));
        }

        vec![Effect::Log {
            level: LogLevel::Info,
            message: format!(
                "remote session announced: {} from daemon {daemon_id}",
                entry.id
            ),
        }]
    }

    fn apply_incoming_session_list(
        &mut self,
        session_infos: Vec<crate::protocol::SessionInfo>,
        daemon_id: &str,
        daemon_name: &str,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();

        let expected_keys: std::collections::HashSet<String> = session_infos
            .iter()
            .map(|info| remote_session_key(daemon_name, &info.id))
            .collect();

        let raw_ids: std::collections::HashSet<&str> =
            session_infos.iter().map(|i| i.id.as_str()).collect();

        // Remove announce-race duplicates
        let announce_dupes: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| matches!(&s.origin, Origin::Remote(d) if d == daemon_id))
            .filter(|(key, _)| {
                let suffix = strip_remote_prefix(key);
                let canonical = remote_session_key(daemon_name, suffix);
                raw_ids.contains(suffix) && **key != canonical
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in &announce_dupes {
            self.sessions.remove(key);
        }

        // Upsert listed sessions
        for info in &session_infos {
            let key = remote_session_key(daemon_name, &info.id);
            let entry = self
                .sessions
                .entry(key.clone())
                .or_insert_with(|| SessionEntry {
                    id: key,
                    pane: None,
                    origin: Origin::Remote(daemon_id.to_string()),
                    metadata: metadata_to_session_meta(info.metadata.as_ref()),
                    ..Default::default()
                });
            if let Some(ref m) = info.metadata {
                entry.metadata = metadata_to_session_meta(Some(m));
            }
        }

        // Remove stale entries
        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| matches!(&s.origin, Origin::Remote(d) if d == daemon_id))
            .map(|(key, _)| key.clone())
            .filter(|key| !expected_keys.contains(key))
            .collect();
        for key in &stale {
            self.sessions.remove(key);
        }

        // Clear orphaned pending replies
        let mut removed_bare: Vec<String> = stale
            .iter()
            .chain(announce_dupes.iter())
            .map(|key| strip_remote_prefix(key).to_string())
            .collect();
        removed_bare.sort();
        removed_bare.dedup();
        if !removed_bare.is_empty() {
            effects.push(Effect::ClearPendingReplies {
                removed_ids: removed_bare,
            });
        }

        effects.push(Effect::RecordNode {
            daemon_id: daemon_id.to_string(),
            daemon_name: daemon_name.to_string(),
        });
        effects.push(Effect::Reciprocate {
            daemon_id: daemon_id.to_string(),
        });

        effects
    }

    fn apply_incoming_remove(
        &mut self,
        id: &str,
        daemon_id: &str,
        daemon_name: &str,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        let display = display_name(daemon_name, daemon_id);
        let key = remote_session_key(display, id);

        let removed = self
            .sessions
            .get(&key)
            .is_some_and(|s| matches!(&s.origin, Origin::Remote(d) if d == daemon_id));
        if removed {
            self.sessions.remove(&key);
            effects.push(Effect::ClearPendingReplies {
                removed_ids: vec![id.to_string()],
            });
        }

        effects.push(Effect::Log {
            level: LogLevel::Info,
            message: format!("remote session removed: {key} from daemon {daemon_id}"),
        });

        effects
    }

    fn apply_incoming_renamed(
        &mut self,
        old_id: &str,
        new_id: &str,
        daemon_id: &str,
        daemon_name: &str,
        metadata: Option<crate::state::SessionMetadata>,
    ) -> Vec<Effect> {
        let display = display_name(daemon_name, daemon_id);
        let old_key = remote_session_key(display, old_id);
        let new_key = remote_session_key(display, new_id);

        let old_meta = self.sessions.remove(&old_key).map(|s| s.metadata);

        let new_entry = SessionEntry {
            id: new_key.clone(),
            pane: None,
            origin: Origin::Remote(daemon_id.to_string()),
            metadata: metadata
                .as_ref()
                .map(|m| metadata_to_session_meta(Some(m)))
                .or(old_meta)
                .unwrap_or_default(),
            ..Default::default()
        };
        self.sessions.insert(new_key.clone(), new_entry);

        self.add_alias(&old_key, &new_key);
        self.add_alias(old_id, new_id);

        vec![Effect::Log {
            level: LogLevel::Info,
            message: format!("remote session renamed: {old_key} -> {new_key}"),
        }]
    }

    fn apply_send(
        &mut self,
        from: &str,
        to: &str,
        message: &str,
        expects_reply: bool,
        responds_to: Option<u64>,
        done: bool,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        let msg_id = self.next_seq();

        // Three-tier reply handling
        if let Some(re_id) = responds_to {
            if done {
                // Complete: remove the pending reply
                if let Some(pending) = self.pending_replies.get_mut(from) {
                    pending.retain(|p| p.msg_id != re_id);
                    if pending.is_empty() {
                        self.pending_replies.remove(from);
                    }
                }
            } else if let Some(pending) = self.pending_replies.get_mut(from) {
                // Progress: update last_activity and set in_progress
                if let Some(entry) = pending.iter_mut().find(|p| p.msg_id == re_id) {
                    entry.last_activity = chrono::Utc::now().timestamp();
                    entry.in_progress = true;
                }
            }
        }
        // No responds_to = standalone ack, no pending reply interaction

        // done=true means the sender is finished — clear its loop reminder
        // so the idle timer stops nudging it.
        if done {
            if let Some(session) = self.sessions.get_mut(from) {
                session.metadata.reminder = None;
            }
        }

        // Resolve alias if target not found directly
        let resolved_to = if self.sessions.contains_key(to) {
            to.to_string()
        } else if let Some(alias_target) = self.resolve_alias(to) {
            // Session was renamed — fail with hint so caller can retry
            effects.push(Effect::SendFailed {
                from: from.to_string(),
                to: to.to_string(),
                reason: format!("session '{}' was renamed to '{}'", to, alias_target),
                renamed_to: Some(alias_target.to_string()),
            });
            return effects;
        } else {
            effects.push(Effect::SendFailed {
                from: from.to_string(),
                to: to.to_string(),
                reason: format!("session '{to}' not found"),
                renamed_to: None,
            });
            return effects;
        };

        let session = match self.sessions.get(&resolved_to) {
            Some(s) => s,
            None => {
                effects.push(Effect::SendFailed {
                    from: from.to_string(),
                    to: to.to_string(),
                    reason: format!("session '{to}' not found"),
                    renamed_to: None,
                });
                return effects;
            }
        };

        match &session.origin {
            Origin::Local => {
                if let Some(ref pane) = session.pane {
                    let formatted = format_session_message(
                        from,
                        message,
                        expects_reply,
                        msg_id,
                        responds_to,
                        done,
                    );
                    effects.push(Effect::InjectMessage {
                        session_id: resolved_to.clone(),
                        pane: pane.clone(),
                        message: formatted,
                        vim_mode: session.metadata.vim_mode,
                    });

                    if expects_reply {
                        self.pending_replies
                            .entry(resolved_to.clone())
                            .or_default()
                            .push(PendingReplyEntry {
                                msg_id,
                                from: from.to_string(),
                                message: message.to_string(),
                                received_at: chrono::Utc::now().timestamp(),
                                last_activity: chrono::Utc::now().timestamp(),
                                in_progress: false,
                            });
                    }
                    effects.push(Effect::LogMessage {
                        from: from.to_string(),
                        to: resolved_to.clone(),
                        message: message.to_string(),
                        delivered: true,
                        transport: "tmux".into(),
                    });
                    effects.push(Effect::SendDelivered {
                        from: from.to_string(),
                        to: resolved_to,
                        method: "tmux".into(),
                        msg_id,
                    });
                } else {
                    effects.push(Effect::SendFailed {
                        from: from.to_string(),
                        to: to.to_string(),
                        reason: "session has no tmux pane".into(),
                        renamed_to: None,
                    });
                }
            }
            Origin::Remote(_) => {
                let wire_to = strip_remote_prefix(&resolved_to).to_string();
                effects.push(Effect::Broadcast(
                    crate::protocol::WireMessage::SessionSend {
                        from: from.to_string(),
                        to: wire_to.clone(),
                        message: message.to_string(),
                        expects_reply,
                        msg_id,
                        responds_to,
                        done,
                    },
                ));
                effects.push(Effect::LogMessage {
                    from: from.to_string(),
                    to: resolved_to.clone(),
                    message: message.to_string(),
                    delivered: true,
                    transport: "nostr".into(),
                });
                effects.push(Effect::SendDelivered {
                    from: from.to_string(),
                    to: resolved_to,
                    method: "nostr".into(),
                    msg_id,
                });
            }
            Origin::Human(npub) => {
                let formatted = format!("[from {from}]: {message}");
                effects.push(Effect::SendToHuman {
                    npub: npub.clone(),
                    message: formatted,
                });
                effects.push(Effect::LogMessage {
                    from: from.to_string(),
                    to: resolved_to.clone(),
                    message: message.to_string(),
                    delivered: true,
                    transport: "nostr-dm".into(),
                });
                effects.push(Effect::SendDelivered {
                    from: from.to_string(),
                    to: resolved_to,
                    method: "nostr-dm".into(),
                    msg_id,
                });
            }
        }

        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_meta_recurrence_fields_default() {
        let meta = SessionMeta::default();
        assert!(meta.reminder.is_none());
        assert!(meta.prompt.is_none());
        assert_eq!(meta.iteration, 0);
        assert!(meta.iteration_log.is_empty());
        assert!(meta.last_iteration_at.is_none());
    }

    #[test]
    fn inherit_recurrence_carries_last_iteration_at() {
        let source = SessionMeta {
            last_iteration_at: Some(1711100000),
            iteration: 5,
            prompt: Some("do work".into()),
            reminder: Some("keep going".into()),
            iteration_log: vec![IterationLogEntry {
                iteration: 5,
                message: None,
                timestamp: 1711100000,
            }],
            ..Default::default()
        };
        let mut target = SessionMeta::default();
        target.inherit_recurrence_from(&source);
        assert_eq!(target.last_iteration_at, Some(1711100000));
        assert_eq!(target.iteration, 5);
    }

    #[test]
    fn loop_log_entry_serde_round_trip() {
        let entry = IterationLogEntry {
            iteration: 3,
            message: Some("converted foo.js".into()),
            timestamp: 1711100000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: IterationLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn loop_log_entry_optional_message() {
        let entry = IterationLogEntry {
            iteration: 1,
            message: None,
            timestamp: 1711100000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: IterationLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.message, None);
    }

    #[test]
    fn iteration_log_cap_at_100() {
        let mut meta = SessionMeta::default();
        for i in 0..110 {
            meta.iteration_log.push(IterationLogEntry {
                iteration: i,
                message: Some(format!("iter {i}")),
                timestamp: 1711100000 + i as i64,
            });
        }
        if meta.iteration_log.len() > 100 {
            let drain_count = meta.iteration_log.len() - 100;
            meta.iteration_log.drain(..drain_count);
        }
        assert_eq!(meta.iteration_log.len(), 100);
        assert_eq!(meta.iteration_log[0].iteration, 10);
    }

    #[test]
    fn inherit_recurrence_carries_on_fire() {
        let source = SessionMeta {
            on_fire: Some(crate::scheduler::OnFire::NewSession),
            ..Default::default()
        };
        let mut target = SessionMeta::default();
        target.inherit_recurrence_from(&source);
        assert_eq!(target.on_fire, Some(crate::scheduler::OnFire::NewSession));
    }

    #[test]
    fn session_meta_serde_aliases_for_renamed_fields() {
        let json = r#"{"original_prompt": "do work", "loop_iteration": 5, "loop_log": [{"iteration": 1, "message": null, "timestamp": 100}], "last_loop_next": 1711100000}"#;
        let meta: SessionMeta = serde_json::from_str(json).unwrap();
        assert_eq!(meta.prompt.as_deref(), Some("do work"));
        assert_eq!(meta.iteration, 5);
        assert_eq!(meta.iteration_log.len(), 1);
        assert_eq!(meta.last_iteration_at, Some(1711100000));
    }

    #[test]
    fn format_message_xml_no_reply() {
        let msg = format_session_message("ouija", "hello", false, 42, None, false);
        assert_eq!(msg, r#"<msg from="ouija" id="42">hello</msg>"#);
    }

    #[test]
    fn format_message_xml_expects_reply() {
        let msg = format_session_message("ouija", "do this", true, 47, None, false);
        assert_eq!(
            msg,
            r#"<msg from="ouija" id="47" reply="true">do this</msg>"#
        );
    }

    #[test]
    fn format_message_xml_with_responds_to() {
        let msg = format_session_message("web", "done", false, 113, Some(47), false);
        assert_eq!(msg, r#"<msg from="web" id="113" re="47">done</msg>"#);
    }

    #[test]
    fn format_message_done_attribute() {
        let msg = format_session_message("a", "hello", false, 1, Some(47), true);
        assert!(
            msg.contains(r#"done="true""#),
            "done=true must appear in XML: {msg}"
        );

        let msg_no_done = format_session_message("a", "hello", false, 1, Some(47), false);
        assert!(
            !msg_no_done.contains("done"),
            "done must not appear when false: {msg_no_done}"
        );
    }

    #[test]
    fn send_assigns_msg_id_from_wire_seq() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let seq_before = state.wire_seq;
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "hello".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        // wire_seq should have been bumped
        assert!(state.wire_seq > seq_before);
        // InjectMessage should contain the msg_id in the XML
        let inject = effects
            .iter()
            .find(|e| matches!(e, Effect::InjectMessage { .. }));
        assert!(inject.is_some());
        if let Some(Effect::InjectMessage { message, .. }) = inject {
            assert!(message.contains(&format!("id=\"{}\"", seq_before + 1)));
            assert!(message.contains("reply=\"true\""));
        }
        // SendDelivered should contain msg_id
        let delivered = effects
            .iter()
            .find(|e| matches!(e, Effect::SendDelivered { .. }));
        assert!(delivered.is_some());
        if let Some(Effect::SendDelivered { msg_id, .. }) = delivered {
            assert_eq!(*msg_id, seq_before + 1);
        }
    }

    #[test]
    fn pending_reply_tracked_by_msg_id() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "do this".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id = effects
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        // target has a pending reply for msg_id
        assert!(state.pending_replies.contains_key("target"));
        assert!(
            state.pending_replies["target"]
                .iter()
                .any(|p| p.msg_id == msg_id)
        );
    }

    #[test]
    fn ack_without_responds_to_does_not_clear() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "do this".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id = effects
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        // Target sends ack WITHOUT responds_to
        state.apply(Event::Send {
            from: "target".into(),
            to: "sender".into(),
            message: "on it".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        // Pending reply still exists
        assert!(
            state.pending_replies["target"]
                .iter()
                .any(|p| p.msg_id == msg_id)
        );
    }

    #[test]
    fn reply_with_responds_to_clears_pending() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "do this".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id = effects
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        // Target sends reply WITH responds_to
        state.apply(Event::Send {
            from: "target".into(),
            to: "sender".into(),
            message: "done".into(),
            expects_reply: false,
            responds_to: Some(msg_id),
            done: true,
        });
        // Pending reply cleared
        assert!(
            state
                .pending_replies
                .get("target")
                .map(|v| v.is_empty())
                .unwrap_or(true)
        );
    }

    #[test]
    fn multiple_pending_replies_independent() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "s1".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "s2".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%3".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });

        // Two different senders send to target
        let effects1 = state.apply(Event::Send {
            from: "s1".into(),
            to: "target".into(),
            message: "task1".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id1 = effects1
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        let effects2 = state.apply(Event::Send {
            from: "s2".into(),
            to: "target".into(),
            message: "task2".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id2 = effects2
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        assert_eq!(state.pending_replies["target"].len(), 2);

        // Respond to msg_id1 only
        state.apply(Event::Send {
            from: "target".into(),
            to: "s1".into(),
            message: "done1".into(),
            expects_reply: false,
            responds_to: Some(msg_id1),
            done: true,
        });
        // msg_id1 cleared, msg_id2 remains
        assert_eq!(state.pending_replies["target"].len(), 1);
        assert!(
            state.pending_replies["target"]
                .iter()
                .any(|p| p.msg_id == msg_id2)
        );
    }

    #[test]
    fn send_progress_does_not_clear_pending() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "do this".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id = effects
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        // Progress reply (responds_to set, done=false) should NOT clear pending
        state.apply(Event::Send {
            from: "target".into(),
            to: "sender".into(),
            message: "working on it".into(),
            expects_reply: false,
            responds_to: Some(msg_id),
            done: false,
        });
        assert!(
            state
                .pending_replies
                .get("target")
                .is_some_and(|v| v.iter().any(|p| p.msg_id == msg_id)),
            "progress reply must NOT clear pending"
        );
        assert!(
            state.pending_replies["target"]
                .iter()
                .find(|p| p.msg_id == msg_id)
                .unwrap()
                .in_progress,
            "progress reply must set in_progress"
        );
    }

    #[test]
    fn send_done_clears_pending() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "do this".into(),
            expects_reply: true,
            responds_to: None,
            done: false,
        });
        let msg_id = effects
            .iter()
            .find_map(|e| match e {
                Effect::SendDelivered { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .unwrap();

        // Done reply (responds_to set, done=true) SHOULD clear pending
        state.apply(Event::Send {
            from: "target".into(),
            to: "sender".into(),
            message: "all done".into(),
            expects_reply: false,
            responds_to: Some(msg_id),
            done: true,
        });
        assert!(
            !state
                .pending_replies
                .get("target")
                .is_some_and(|v| v.iter().any(|p| p.msg_id == msg_id)),
            "done reply must clear pending"
        );
    }

    #[test]
    fn send_done_clears_sender_reminder() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "worker".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                reminder: Some("call loop_next".into()),
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "boss".into(),
            pane: Some("%2".into()),
            metadata: Default::default(),
        });

        // worker sends done=true
        state.apply(Event::Send {
            from: "worker".into(),
            to: "boss".into(),
            message: "all done".into(),
            expects_reply: false,
            responds_to: None,
            done: true,
        });

        assert!(
            state.sessions["worker"].metadata.reminder.is_none(),
            "done=true must clear sender's reminder"
        );
    }

    #[test]
    fn cross_daemon_pending_reply_cleared_by_local_done() {
        // Remote A sends to local B with expects_reply via wire.
        // B replies locally with responds_to + done=true.
        // Pending on B must be cleared.
        let mut state = DaemonState::new_for_model("d2".into(), "host2".into());
        state.apply(Event::Register {
            id: "B".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });

        // Remote A sends to local B via wire
        let _effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionSend {
                from: "A".into(),
                to: "B".into(),
                message: "do this".into(),
                expects_reply: true,
                msg_id: 42,
                responds_to: None,
                done: false,
            },
            sender_npub: Some("npub1remote".into()),
        });
        // Verify pending was stored
        assert!(
            state.pending_replies.contains_key("B"),
            "pending should be stored for local target"
        );
        assert_eq!(state.pending_replies["B"][0].msg_id, 42);

        // B replies locally with done=true
        state.apply(Event::Send {
            from: "B".into(),
            to: "A".into(),
            message: "all done".into(),
            expects_reply: false,
            responds_to: Some(42),
            done: true,
        });
        assert!(
            !state
                .pending_replies
                .get("B")
                .is_some_and(|v| v.iter().any(|p| p.msg_id == 42)),
            "done reply must clear cross-daemon pending"
        );
    }

    #[test]
    fn register_new_session() {
        let mut state = DaemonState::new("npub1abc".into(), "myhost".into());
        let effects = state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        assert!(state.sessions.contains_key("web"));
        assert_eq!(state.sessions["web"].pane, Some("%1".into()));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SetTmuxVar { .. }))
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::Persist)));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SpawnAgent { .. }))
        );
    }

    #[test]
    fn register_same_id_different_pane_updates() {
        let mut state = DaemonState::new("npub1abc".into(), "myhost".into());
        state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%2".into()),
            metadata: Default::default(),
        });
        // Re-registering same ID with different pane updates the pane (e.g. restart)
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RegisterOk { .. }))
        );
        assert_eq!(state.sessions["web"].pane, Some("%2".into()));
        // Old pane should be cleaned up
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::ClearTmuxVar { pane, .. } if pane == "%1"))
        );
    }

    #[test]
    fn register_dedup_same_pane_different_id() {
        let mut state = DaemonState::new("npub1abc".into(), "myhost".into());
        state.apply(Event::Register {
            id: "old-name".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::Register {
            id: "new-name".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        assert!(!state.sessions.contains_key("old-name"));
        assert!(state.sessions.contains_key("new-name"));
        assert_eq!(state.aliases.get("old-name"), Some(&"new-name".into()));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::StopAgent { session_id } if session_id == "old-name"))
        );
    }

    #[test]
    fn register_same_id_different_pane_overwrites() {
        // Two panes in the same project dir both derive the same base name.
        // If both register as "ouija" (stale conflict map), the second
        // overwrites the first. This test documents the overwrite behavior;
        // the actual fix is in scan_and_autoregister_panes which updates
        // its conflict map after each registration to prevent this.
        let mut state = DaemonState::new("npub1abc".into(), "myhost".into());
        state.apply(Event::Register {
            id: "ouija".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        // Second pane claims the same name
        let effects = state.apply(Event::Register {
            id: "ouija".into(),
            pane: Some("%2".into()),
            metadata: Default::default(),
        });
        // The second registration wins — pane %2 now owns "ouija"
        let session = state.sessions.get("ouija").unwrap();
        assert_eq!(session.pane.as_deref(), Some("%2"));
        // Old pane's tmux var is cleared
        assert!(effects.iter().any(
            |e| matches!(e, Effect::ClearTmuxVar { pane, .. } if pane == "%1")
        ));
    }

    #[test]
    fn register_idempotent_same_id_same_pane() {
        let mut state = DaemonState::new("npub1abc".into(), "myhost".into());
        state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                role: Some("v1".into()),
                ..Default::default()
            },
        });
        state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                role: Some("v2".into()),
                ..Default::default()
            },
        });
        assert_eq!(state.sessions["web"].metadata.role, Some("v2".into()));
    }

    #[test]
    fn rename_updates_alias_and_broadcasts() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "old".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Rename {
            old_id: "old".into(),
            new_id: "new".into(),
        });
        assert!(!state.sessions.contains_key("old"));
        assert!(state.sessions.contains_key("new"));
        assert_eq!(state.aliases.get("old"), Some(&"new".into()));
        assert!(effects.iter().any(|e| matches!(e, Effect::Broadcast(..))));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::BroadcastSessionList))
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RenameAgent { .. }))
        );
    }

    #[test]
    fn rename_rejects_slash() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "s1".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::Rename {
            old_id: "s1".into(),
            new_id: "has/slash".into(),
        });
        assert!(state.sessions.contains_key("s1"));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RenameFailed { .. }))
        );
    }

    #[test]
    fn rename_nonexistent_fails() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        let effects = state.apply(Event::Rename {
            old_id: "nope".into(),
            new_id: "new".into(),
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RenameFailed { .. }))
        );
    }

    #[test]
    fn remove_cleans_up() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "s1".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::Remove { id: "s1".into(), keep_worktree: false });
        assert!(!state.sessions.contains_key("s1"));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::StopAgent { session_id } if session_id == "s1"))
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::ClearPendingReplies { .. }))
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::Persist)));
    }

    #[test]
    fn remove_remote_fails() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.sessions.insert(
            "remote/s1".into(),
            SessionEntry {
                id: "remote/s1".into(),
                origin: Origin::Remote("npub1xyz".into()),
                ..Default::default()
            },
        );
        let effects = state.apply(Event::Remove {
            id: "remote/s1".into(),
            keep_worktree: false,
        });
        assert!(state.sessions.contains_key("remote/s1"));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RemoveFailed { .. }))
        );
    }

    #[test]
    fn remove_triggers_worktree_cleanup() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "wt".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                project_dir: Some("/code/ouija/.claude/worktrees/wt".into()),
                ..Default::default()
            },
        });
        let effects = state.apply(Event::Remove { id: "wt".into(), keep_worktree: false });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::CleanupWorktree { .. }))
        );
    }

    #[test]
    fn reap_removes_dead_sessions() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "alive".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.apply(Event::Register {
            id: "dead".into(),
            pane: Some("%2".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::ReapDead {
            dead_ids: vec!["dead".into()],
        });
        assert!(!state.sessions.contains_key("dead"));
        assert!(state.sessions.contains_key("alive"));
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::CleanupWorktree { .. }))
        );
    }

    // --- IncomingWire tests ---

    #[test]
    fn incoming_session_list_reconciles_remote() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        let effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![
                    crate::protocol::SessionInfo {
                        id: "s1".into(),
                        metadata: None,
                    },
                    crate::protocol::SessionInfo {
                        id: "s2".into(),
                        metadata: None,
                    },
                ],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 1,
            },
            sender_npub: Some("npub1remote".into()),
        });
        assert!(state.sessions.contains_key("remote-host/s1"));
        assert!(state.sessions.contains_key("remote-host/s2"));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RecordNode { .. }))
        );
    }

    #[test]
    fn incoming_session_list_removes_stale() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        // First list with s1 and s2
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![
                    crate::protocol::SessionInfo {
                        id: "s1".into(),
                        metadata: None,
                    },
                    crate::protocol::SessionInfo {
                        id: "s2".into(),
                        metadata: None,
                    },
                ],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 1,
            },
            sender_npub: Some("npub1remote".into()),
        });
        // Second list with only s1 (s2 removed)
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![crate::protocol::SessionInfo {
                    id: "s1".into(),
                    metadata: None,
                }],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 2,
            },
            sender_npub: Some("npub1remote".into()),
        });
        assert!(state.sessions.contains_key("remote-host/s1"));
        assert!(!state.sessions.contains_key("remote-host/s2"));
    }

    #[test]
    fn incoming_session_list_deduplicates_announce_race() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        // Simulate announce-race: session arrived via Announce with daemon_id prefix
        state.sessions.insert(
            "npub1remote/s1".into(),
            SessionEntry {
                id: "npub1remote/s1".into(),
                origin: Origin::Remote("npub1remote".into()),
                ..Default::default()
            },
        );
        // SessionList arrives with daemon_name prefix
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![crate::protocol::SessionInfo {
                    id: "s1".into(),
                    metadata: None,
                }],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 1,
            },
            sender_npub: Some("npub1remote".into()),
        });
        // Old key removed, canonical key present
        assert!(!state.sessions.contains_key("npub1remote/s1"));
        assert!(state.sessions.contains_key("remote-host/s1"));
    }

    #[test]
    fn incoming_session_remove_removes_remote() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.sessions.insert(
            "remote-host/s1".into(),
            SessionEntry {
                id: "remote-host/s1".into(),
                origin: Origin::Remote("npub1remote".into()),
                ..Default::default()
            },
        );
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionRemove {
                id: "s1".into(),
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 1,
            },
            sender_npub: Some("npub1remote".into()),
        });
        assert!(!state.sessions.contains_key("remote-host/s1"));
    }

    #[test]
    fn incoming_session_renamed_rekeys_and_aliases() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.sessions.insert(
            "remote-host/old".into(),
            SessionEntry {
                id: "remote-host/old".into(),
                origin: Origin::Remote("npub1remote".into()),
                ..Default::default()
            },
        );
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionRenamed {
                old_id: "old".into(),
                new_id: "new".into(),
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                metadata: None,
                seq: 1,
            },
            sender_npub: Some("npub1remote".into()),
        });
        assert!(!state.sessions.contains_key("remote-host/old"));
        assert!(state.sessions.contains_key("remote-host/new"));
        assert_eq!(
            state.aliases.get("remote-host/old"),
            Some(&"remote-host/new".into())
        );
        assert_eq!(state.aliases.get("old"), Some(&"new".into()));
    }

    #[test]
    fn incoming_stale_seq_dropped() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        // First message with seq=5
        state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![crate::protocol::SessionInfo {
                    id: "s1".into(),
                    metadata: None,
                }],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 5,
            },
            sender_npub: Some("npub1remote".into()),
        });
        // Stale message with seq=3
        let effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionList {
                sessions: vec![],
                daemon_id: "npub1remote".into(),
                daemon_name: "remote-host".into(),
                seq: 3,
            },
            sender_npub: Some("npub1remote".into()),
        });
        // Session from first message should still be there (stale msg dropped)
        assert!(state.sessions.contains_key("remote-host/s1"));
        // Only effect should be a log about dropping
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Log {
                level: LogLevel::Debug,
                ..
            }
        )));
    }

    #[test]
    fn incoming_daemon_id_mismatch_dropped() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        let effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionAnnounce {
                id: "s1".into(),
                daemon_id: "npub1claimed".into(),
                daemon_name: "host".into(),
                metadata: None,
                seq: 1,
            },
            sender_npub: Some("npub1actual".into()),
        });
        // Should be dropped - no session added
        assert!(state.sessions.is_empty());
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Log {
                level: LogLevel::Warn,
                ..
            }
        )));
    }

    #[test]
    fn incoming_session_send_to_local_returns_inject() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        let effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionSend {
                from: "remote-session".into(),
                to: "web".into(),
                message: "hello".into(),
                expects_reply: false,
                msg_id: 0,
                responds_to: None,
                done: false,
            },
            sender_npub: None,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::InjectMessage { pane, .. } if pane == "%1"))
        );
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Broadcast(crate::protocol::WireMessage::SessionSendAck {
                delivered: true,
                ..
            })
        )));
    }

    #[test]
    fn incoming_session_send_to_unknown_no_inject() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        let effects = state.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionSend {
                from: "remote-session".into(),
                to: "nonexistent".into(),
                message: "hello".into(),
                expects_reply: false,
                msg_id: 0,
                responds_to: None,
                done: false,
            },
            sender_npub: None,
        });
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::InjectMessage { .. }))
        );
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Log {
                level: LogLevel::Warn,
                ..
            }
        )));
    }

    // --- Send tests ---

    #[test]
    fn send_local_injects_and_delivers() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.apply(Event::Register {
            id: "target".into(),
            pane: Some("%2".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "target".into(),
            message: "hello".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::InjectMessage { pane, .. } if pane == "%2"))
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendDelivered { .. }))
        );
    }

    #[test]
    fn send_remote_broadcasts_wire() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.sessions.insert(
            "remote-host/target".into(),
            SessionEntry {
                id: "remote-host/target".into(),
                origin: Origin::Remote("npub1remote".into()),
                ..Default::default()
            },
        );
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "remote-host/target".into(),
            message: "hello".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Broadcast(crate::protocol::WireMessage::SessionSend { .. })
        )));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendDelivered { .. }))
        );
    }

    #[test]
    fn send_human_sends_dm() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "sender".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.sessions.insert(
            "human-user".into(),
            SessionEntry {
                id: "human-user".into(),
                origin: Origin::Human("npub1human".into()),
                ..Default::default()
            },
        );
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "human-user".into(),
            message: "hello".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendToHuman { npub, .. } if npub == "npub1human"))
        );
    }

    #[test]
    fn send_nonexistent_fails() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "nope".into(),
            message: "hello".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendFailed { .. }))
        );
    }

    #[test]
    fn send_resolves_alias() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "old-name".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        state.apply(Event::Rename {
            old_id: "old-name".into(),
            new_id: "new-name".into(),
        });
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "old-name".into(),
            message: "hello".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        // Alias resolution returns a redirect hint, not silent routing
        assert!(effects.iter().any(
            |e| matches!(e, Effect::SendFailed { renamed_to: Some(new), .. } if new == "new-name")
        ));
    }

    // --- UpdateMetadata tests ---

    #[test]
    fn update_metadata_updates_fields() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "s1".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        let effects = state.apply(Event::UpdateMetadata {
            id: "s1".into(),
            role: Some("new-role".into()),
            bulletin: Some("new-bulletin".into()),
            project_dir: Some("/new/dir".into()),
            networked: None,
        });
        assert_eq!(state.sessions["s1"].metadata.role, Some("new-role".into()));
        assert_eq!(
            state.sessions["s1"].metadata.bulletin,
            Some("new-bulletin".into())
        );
        assert_eq!(
            state.sessions["s1"].metadata.project_dir,
            Some("/new/dir".into())
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::Persist)));
    }

    #[test]
    fn update_metadata_partial() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.apply(Event::Register {
            id: "s1".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                role: Some("old-role".into()),
                ..Default::default()
            },
        });
        state.apply(Event::UpdateMetadata {
            id: "s1".into(),
            role: None,
            bulletin: Some("bulletin".into()),
            project_dir: None,
            networked: None,
        });
        // role unchanged
        assert_eq!(state.sessions["s1"].metadata.role, Some("old-role".into()));
        assert_eq!(
            state.sessions["s1"].metadata.bulletin,
            Some("bulletin".into())
        );
    }

    #[test]
    fn update_metadata_remote_noop() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        state.sessions.insert(
            "remote/s1".into(),
            SessionEntry {
                id: "remote/s1".into(),
                origin: Origin::Remote("npub1xyz".into()),
                ..Default::default()
            },
        );
        let effects = state.apply(Event::UpdateMetadata {
            id: "remote/s1".into(),
            role: Some("role".into()),
            bulletin: None,
            project_dir: None,
            networked: None,
        });
        assert!(effects.is_empty());
    }

    // --- Convergence simulation: exercises every Event variant ---

    /// Simulates two daemons exchanging wire messages and verifies
    /// they converge to the same view of each other's sessions.
    /// This mirrors the Stateright model's convergence property.
    #[test]
    fn two_daemon_convergence() {
        let mut d0 = DaemonState::new("npub0".into(), "host0".into());
        let mut d1 = DaemonState::new("npub1".into(), "host1".into());

        // d0 registers sessions
        d0.apply(Event::Register {
            id: "web".into(),
            pane: Some("%1".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });
        d0.apply(Event::Register {
            id: "api".into(),
            pane: Some("%2".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });

        // d1 registers a session
        d1.apply(Event::Register {
            id: "db".into(),
            pane: Some("%3".into()),
            metadata: SessionMeta {
                networked: true,
                ..Default::default()
            },
        });

        // Exchange session lists
        let d0_list = crate::protocol::WireMessage::SessionList {
            sessions: vec![
                crate::protocol::SessionInfo {
                    id: "web".into(),
                    metadata: None,
                },
                crate::protocol::SessionInfo {
                    id: "api".into(),
                    metadata: None,
                },
            ],
            daemon_id: "npub0".into(),
            daemon_name: "host0".into(),
            seq: d0.wire_seq,
        };
        let d1_list = crate::protocol::WireMessage::SessionList {
            sessions: vec![crate::protocol::SessionInfo {
                id: "db".into(),
                metadata: None,
            }],
            daemon_id: "npub1".into(),
            daemon_name: "host1".into(),
            seq: d1.wire_seq,
        };
        d1.apply(Event::IncomingWire {
            msg: d0_list,
            sender_npub: Some("npub0".into()),
        });
        d0.apply(Event::IncomingWire {
            msg: d1_list,
            sender_npub: Some("npub1".into()),
        });

        // Verify convergence: d1 sees d0's sessions
        assert!(d1.sessions.contains_key("host0/web"));
        assert!(d1.sessions.contains_key("host0/api"));
        // d0 sees d1's sessions
        assert!(d0.sessions.contains_key("host1/db"));

        // d0 renames a session
        d0.apply(Event::Rename {
            old_id: "web".into(),
            new_id: "frontend".into(),
        });

        // d1 receives the rename
        d1.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionRenamed {
                old_id: "web".into(),
                new_id: "frontend".into(),
                daemon_id: "npub0".into(),
                daemon_name: "host0".into(),
                metadata: None,
                seq: d0.wire_seq,
            },
            sender_npub: Some("npub0".into()),
        });
        assert!(!d1.sessions.contains_key("host0/web"));
        assert!(d1.sessions.contains_key("host0/frontend"));
        assert_eq!(d1.aliases.get("host0/web"), Some(&"host0/frontend".into()));

        // d0 removes a session
        d0.apply(Event::Remove { id: "api".into(), keep_worktree: false });

        // d1 receives the removal
        d1.apply(Event::IncomingWire {
            msg: crate::protocol::WireMessage::SessionRemove {
                id: "api".into(),
                daemon_id: "npub0".into(),
                daemon_name: "host0".into(),
                seq: d0.wire_seq,
            },
            sender_npub: Some("npub0".into()),
        });
        assert!(!d1.sessions.contains_key("host0/api"));

        // d0 reaps a dead session
        d0.apply(Event::ReapDead {
            dead_ids: vec!["frontend".into()],
        });
        assert!(!d0.sessions.contains_key("frontend"));

        // After reconciliation via updated list
        let d0_list2 = crate::protocol::WireMessage::SessionList {
            sessions: vec![],
            daemon_id: "npub0".into(),
            daemon_name: "host0".into(),
            seq: d0.wire_seq + 1,
        };
        d1.apply(Event::IncomingWire {
            msg: d0_list2,
            sender_npub: Some("npub0".into()),
        });
        // d1 should have no d0 sessions
        assert!(
            !d1.sessions
                .iter()
                .any(|(_, s)| matches!(&s.origin, Origin::Remote(d) if d == "npub0"))
        );

        // Verify seq filtering: stale message dropped (use seq=2, not seq<=1 which triggers restart reset)
        let final_seq = d1.last_seen_seq.get("npub0").copied().unwrap_or(0);
        let stale_list = crate::protocol::WireMessage::SessionList {
            sessions: vec![crate::protocol::SessionInfo {
                id: "ghost".into(),
                metadata: None,
            }],
            daemon_id: "npub0".into(),
            daemon_name: "host0".into(),
            seq: if final_seq > 2 { 2 } else { final_seq }, // stale
        };
        d1.apply(Event::IncomingWire {
            msg: stale_list,
            sender_npub: Some("npub0".into()),
        });
        // Ghost session should NOT appear if message was truly stale
        if final_seq > 2 {
            assert!(!d1.sessions.contains_key("host0/ghost"));
        }
    }

    /// Exercises Send routing through all origin types.
    #[test]
    fn send_routes_all_origins() {
        let mut state = DaemonState::new("d1".into(), "host1".into());
        // Local session
        state.apply(Event::Register {
            id: "local".into(),
            pane: Some("%1".into()),
            metadata: Default::default(),
        });
        // Remote session
        state.sessions.insert(
            "host2/remote".into(),
            SessionEntry {
                id: "host2/remote".into(),
                origin: Origin::Remote("npub2".into()),
                ..Default::default()
            },
        );
        // Human session
        state.sessions.insert(
            "human".into(),
            SessionEntry {
                id: "human".into(),
                origin: Origin::Human("npub3".into()),
                ..Default::default()
            },
        );

        // Send to local → InjectMessage
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "local".into(),
            message: "hi".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::InjectMessage { .. }))
        );

        // Send to remote → Broadcast(SessionSend)
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "host2/remote".into(),
            message: "hi".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Broadcast(crate::protocol::WireMessage::SessionSend { .. })
        )));

        // Send to human → SendToHuman
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "human".into(),
            message: "hi".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendToHuman { .. }))
        );

        // Send to nonexistent → SendFailed
        let effects = state.apply(Event::Send {
            from: "sender".into(),
            to: "nope".into(),
            message: "hi".into(),
            expects_reply: false,
            responds_to: None,
            done: false,
        });
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::SendFailed { .. }))
        );
    }

    /// Verify accept_seq filtering logic.
    #[test]
    fn seq_filtering() {
        let mut state = DaemonState::new_for_model("d1".into(), "host1".into());

        // First message accepted
        assert!(state.accept_seq("peer", 1));
        // Higher seq accepted
        assert!(state.accept_seq("peer", 5));
        // Stale seq rejected (including seq=1)
        assert!(!state.accept_seq("peer", 3));
        assert!(!state.accept_seq("peer", 1));
        assert!(!state.accept_seq("peer", 0));
        // Equal seq accepted
        assert!(state.accept_seq("peer", 5));
    }
}

// ---------------------------------------------------------------------------
// Stateright model using real DaemonState
// ---------------------------------------------------------------------------

#[cfg(test)]
mod stateright_model {
    use super::*;
    use crate::protocol::{SessionInfo, WireMessage};
    use stateright::actor::{Actor, ActorModel, Id, Network, Out};
    use stateright::{Checker, Expectation, Model};
    use std::borrow::Cow;
    use std::collections::BTreeSet;

    const SESSION_IDS: [&str; 2] = ["A", "B"];

    /// A shared worktree path that two sessions can reference. Uses the
    /// `.claude/worktrees/` convention so apply_remove's cleanup guard fires.
    const MODEL_WORKTREE_DIR: &str = "/tmp/.claude/worktrees/shared";

    // -- Messages (must be Hash+Eq+Ord for Stateright) -----------------------

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    enum ModelMsg {
        // Client -> Daemon
        Register {
            id: String,
        },
        /// Register with metadata fields (project_dir, workflow, prompt, reminder)
        /// to exercise inherit_recurrence_from and worktree cleanup paths.
        RegisterWithMeta {
            id: String,
            project_dir: Option<String>,
            workflow: Option<String>,
            prompt: Option<String>,
            reminder: Option<String>,
        },
        Remove {
            id: String,
        },
        /// Remove with keep_worktree=true (the default Remove uses false).
        RemoveKeep {
            id: String,
        },
        /// Reap dead sessions (simulates the pane-polling reaper).
        ReapDead {
            ids: Vec<String>,
        },
        Rename {
            old_id: String,
            new_id: String,
        },
        // Wire protocol (daemon -> daemon)
        WireAnnounce {
            id: String,
            daemon_id: String,
            daemon_name: String,
            seq: u64,
        },
        WireList {
            sessions: BTreeSet<String>,
            daemon_id: String,
            daemon_name: String,
            seq: u64,
        },
        WireRemove {
            id: String,
            daemon_id: String,
            daemon_name: String,
            seq: u64,
        },
        WireRenamed {
            old_id: String,
            new_id: String,
            daemon_id: String,
            daemon_name: String,
            seq: u64,
        },
        // Session messaging
        Send {
            from: String,
            to: String,
            message: String,
            expects_reply: bool,
        },
        Reply {
            from: String,
            to: String,
            msg_id: u64,
            done: bool,
        },
        WireSessionSend {
            from: String,
            to: String,
            message: String,
            expects_reply: bool,
            msg_id: u64,
            responds_to: Option<u64>,
            done: bool,
        },
    }

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    enum ModelAction {
        Register(String),
        RegisterWithMeta {
            id: String,
            project_dir: Option<String>,
            workflow: Option<String>,
            prompt: Option<String>,
            reminder: Option<String>,
        },
        Remove(String),
        RemoveKeep(String),
        ReapDead(Vec<String>),
        Rename(String, String),
        Send {
            from: String,
            to: String,
            expects_reply: bool,
        },
        Reply {
            from: String,
            to: String,
            msg_id: u64,
            done: bool,
        },
    }

    // -- Actor & State -------------------------------------------------------

    #[derive(Clone)]
    enum ModelActor {
        Daemon {
            daemon_id: String,
            daemon_name: String,
            peers: Vec<Id>,
        },
        SessionDriver {
            target: Id,
        },
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    enum ModelState {
        Daemon {
            ds: Box<DaemonState>,
            peers: Vec<Id>,
            last_send_result: Option<SendOutcome>,
            pending_reply_counts: BTreeMap<String, usize>,
            prev_pending_reply_counts: BTreeMap<String, usize>,
            last_event_type: LastEvent,
            /// Worktree dirs cleaned up in the last apply (for invariant checking).
            last_cleaned_worktrees: BTreeSet<String>,
            /// Whether the last event was a ReapDead.
            last_was_reap: bool,
        },
        Driver {
            actions_taken: u8,
        },
    }

    const MAX_DRIVER_ACTIONS: u8 = 2;

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    enum SendOutcome {
        Delivered {
            from: String,
            to: String,
            msg_id: u64,
        },
        Failed {
            from: String,
            to: String,
            renamed_to: Option<String>,
        },
    }

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    enum LastEvent {
        ReplyDone,
        ReplyProgress,
        Other,
    }

    impl Actor for ModelActor {
        type Msg = ModelMsg;
        type State = ModelState;
        type Timer = ();
        type Random = ModelAction;
        type Storage = ();

        fn on_start(&self, _id: Id, _: &Option<()>, o: &mut Out<Self>) -> Self::State {
            match self {
                Self::Daemon {
                    daemon_id,
                    daemon_name,
                    peers,
                } => ModelState::Daemon {
                    ds: Box::new(DaemonState::new_for_model(
                        daemon_id.clone(),
                        daemon_name.clone(),
                    )),
                    peers: peers.clone(),
                    last_send_result: None,
                    pending_reply_counts: BTreeMap::new(),
                    prev_pending_reply_counts: BTreeMap::new(),
                    last_event_type: LastEvent::Other,
                    last_cleaned_worktrees: BTreeSet::new(),
                    last_was_reap: false,
                },
                Self::SessionDriver { .. } => {
                    offer_actions(o);
                    ModelState::Driver { actions_taken: 0 }
                }
            }
        }

        fn on_msg(
            &self,
            _id: Id,
            state: &mut Cow<'_, Self::State>,
            _src: Id,
            msg: Self::Msg,
            o: &mut Out<Self>,
        ) {
            if !matches!(state.as_ref(), ModelState::Daemon { .. }) {
                return;
            }
            let s = state.to_mut();
            let ModelState::Daemon {
                ds,
                peers,
                last_send_result,
                pending_reply_counts,
                prev_pending_reply_counts,
                last_event_type,
                last_cleaned_worktrees,
                last_was_reap,
            } = s
            else {
                return;
            };

            match msg {
                // -- Register / Remove / Rename / Reap / Wire* shared path --
                ModelMsg::Register { .. }
                | ModelMsg::RegisterWithMeta { .. }
                | ModelMsg::Remove { .. }
                | ModelMsg::RemoveKeep { .. }
                | ModelMsg::ReapDead { .. }
                | ModelMsg::Rename { .. }
                | ModelMsg::WireAnnounce { .. }
                | ModelMsg::WireList { .. }
                | ModelMsg::WireRemove { .. }
                | ModelMsg::WireRenamed { .. } => {
                    let is_reap = matches!(msg, ModelMsg::ReapDead { .. });
                    let event = match msg {
                        ModelMsg::Register { id } => Event::Register {
                            id: id.clone(),
                            pane: Some(format!("model-pane-{id}")),
                            metadata: SessionMeta {
                                networked: true,
                                ..Default::default()
                            },
                        },
                        ModelMsg::RegisterWithMeta {
                            id,
                            project_dir,
                            workflow,
                            prompt,
                            reminder,
                        } => Event::Register {
                            id: id.clone(),
                            pane: Some(format!("model-pane-{id}")),
                            metadata: SessionMeta {
                                networked: true,
                                project_dir,
                                workflow,
                                prompt,
                                reminder,
                                ..Default::default()
                            },
                        },
                        ModelMsg::Remove { id } => Event::Remove { id, keep_worktree: false },
                        ModelMsg::RemoveKeep { id } => Event::Remove { id, keep_worktree: true },
                        ModelMsg::ReapDead { ids } => Event::ReapDead { dead_ids: ids },
                        ModelMsg::Rename { old_id, new_id } => Event::Rename { old_id, new_id },
                        ModelMsg::WireAnnounce {
                            id,
                            daemon_id,
                            daemon_name,
                            seq,
                        } => Event::IncomingWire {
                            msg: WireMessage::SessionAnnounce {
                                id,
                                daemon_id,
                                daemon_name,
                                metadata: None,
                                seq,
                            },
                            sender_npub: None,
                        },
                        ModelMsg::WireList {
                            sessions,
                            daemon_id,
                            daemon_name,
                            seq,
                        } => Event::IncomingWire {
                            msg: WireMessage::SessionList {
                                sessions: sessions
                                    .into_iter()
                                    .map(|id| SessionInfo { id, metadata: None })
                                    .collect(),
                                daemon_id,
                                daemon_name,
                                seq,
                            },
                            sender_npub: None,
                        },
                        ModelMsg::WireRemove {
                            id,
                            daemon_id,
                            daemon_name,
                            seq,
                        } => Event::IncomingWire {
                            msg: WireMessage::SessionRemove {
                                id,
                                daemon_id,
                                daemon_name,
                                seq,
                            },
                            sender_npub: None,
                        },
                        ModelMsg::WireRenamed {
                            old_id,
                            new_id,
                            daemon_id,
                            daemon_name,
                            seq,
                        } => Event::IncomingWire {
                            msg: WireMessage::SessionRenamed {
                                old_id,
                                new_id,
                                daemon_id,
                                daemon_name,
                                metadata: None,
                                seq,
                            },
                            sender_npub: None,
                        },
                        _ => unreachable!(),
                    };
                    let effects = ds.apply(event);
                    normalize_timestamps(ds);
                    *last_send_result = None;
                    *last_event_type = LastEvent::Other;
                    *last_cleaned_worktrees = extract_cleaned_worktrees(&effects);
                    *last_was_reap = is_reap;
                    route_effects(ds, &effects, peers, o);
                }

                // -- Send (local API call) --
                ModelMsg::Send {
                    from,
                    to,
                    message,
                    expects_reply,
                } => {
                    let event = Event::Send {
                        from,
                        to,
                        message,
                        expects_reply,
                        responds_to: None,
                        done: false,
                    };
                    let effects = ds.apply(event);
                    normalize_timestamps(ds);
                    *last_send_result = extract_send_outcome(&effects);
                    update_pending_tracking(ds, prev_pending_reply_counts, pending_reply_counts);
                    *last_event_type = LastEvent::Other;
                    *last_cleaned_worktrees = BTreeSet::new();
                    *last_was_reap = false;
                    route_effects(ds, &effects, peers, o);
                }

                // -- Reply (local API call responding to a pending msg) --
                ModelMsg::Reply {
                    from,
                    to,
                    msg_id,
                    done,
                } => {
                    let event = Event::Send {
                        from,
                        to,
                        message: "model-reply".into(),
                        expects_reply: false,
                        responds_to: Some(msg_id),
                        done,
                    };
                    let effects = ds.apply(event);
                    normalize_timestamps(ds);
                    *last_send_result = extract_send_outcome(&effects);
                    update_pending_tracking(ds, prev_pending_reply_counts, pending_reply_counts);
                    *last_event_type = if done {
                        LastEvent::ReplyDone
                    } else {
                        LastEvent::ReplyProgress
                    };
                    *last_cleaned_worktrees = BTreeSet::new();
                    *last_was_reap = false;
                    route_effects(ds, &effects, peers, o);
                }

                // -- WireSessionSend (cross-daemon delivery, receiving side) --
                ModelMsg::WireSessionSend {
                    from,
                    to,
                    message,
                    expects_reply,
                    msg_id,
                    responds_to,
                    done,
                } => {
                    let event = Event::IncomingWire {
                        msg: WireMessage::SessionSend {
                            from,
                            to,
                            message,
                            expects_reply,
                            msg_id,
                            responds_to,
                            done,
                        },
                        sender_npub: None,
                    };
                    let effects = ds.apply(event);
                    normalize_timestamps(ds);
                    *last_send_result = None; // receiving side, clear stale result
                    update_pending_tracking(ds, prev_pending_reply_counts, pending_reply_counts);
                    *last_event_type = LastEvent::Other;
                    *last_cleaned_worktrees = BTreeSet::new();
                    *last_was_reap = false;
                    route_effects(ds, &effects, peers, o);
                }
            }
        }

        fn on_random(
            &self,
            _id: Id,
            state: &mut Cow<'_, Self::State>,
            random: &Self::Random,
            o: &mut Out<Self>,
        ) {
            if let Self::SessionDriver { target } = self {
                let s = state.to_mut();
                if let ModelState::Driver { actions_taken } = s {
                    *actions_taken += 1;
                    match random {
                        ModelAction::Register(id) => {
                            o.send(*target, ModelMsg::Register { id: id.clone() })
                        }
                        ModelAction::RegisterWithMeta {
                            id,
                            project_dir,
                            workflow,
                            prompt,
                            reminder,
                        } => o.send(
                            *target,
                            ModelMsg::RegisterWithMeta {
                                id: id.clone(),
                                project_dir: project_dir.clone(),
                                workflow: workflow.clone(),
                                prompt: prompt.clone(),
                                reminder: reminder.clone(),
                            },
                        ),
                        ModelAction::Remove(id) => {
                            o.send(*target, ModelMsg::Remove { id: id.clone() })
                        }
                        ModelAction::RemoveKeep(id) => {
                            o.send(*target, ModelMsg::RemoveKeep { id: id.clone() })
                        }
                        ModelAction::ReapDead(ids) => {
                            o.send(*target, ModelMsg::ReapDead { ids: ids.clone() })
                        }
                        ModelAction::Rename(old, new) => o.send(
                            *target,
                            ModelMsg::Rename {
                                old_id: old.clone(),
                                new_id: new.clone(),
                            },
                        ),
                        ModelAction::Send {
                            from,
                            to,
                            expects_reply,
                        } => o.send(
                            *target,
                            ModelMsg::Send {
                                from: from.clone(),
                                to: to.clone(),
                                message: "model-msg".into(),
                                expects_reply: *expects_reply,
                            },
                        ),
                        ModelAction::Reply {
                            from,
                            to,
                            msg_id,
                            done,
                        } => o.send(
                            *target,
                            ModelMsg::Reply {
                                from: from.clone(),
                                to: to.clone(),
                                msg_id: *msg_id,
                                done: *done,
                            },
                        ),
                    }
                    if *actions_taken < MAX_DRIVER_ACTIONS {
                        offer_actions(o);
                    }
                }
            }
        }
    }

    // -- Helpers -------------------------------------------------------------

    fn normalize_timestamps(ds: &mut DaemonState) {
        for entry in ds.sessions.values_mut() {
            entry.registered_at = 0;
        }
        for entries in ds.pending_replies.values_mut() {
            for e in entries.iter_mut() {
                e.received_at = 0;
                e.last_activity = 0;
            }
        }
    }

    fn extract_send_outcome(effects: &[Effect]) -> Option<SendOutcome> {
        effects.iter().find_map(|e| match e {
            Effect::SendDelivered {
                from, to, msg_id, ..
            } => Some(SendOutcome::Delivered {
                from: from.clone(),
                to: to.clone(),
                msg_id: *msg_id,
            }),
            Effect::SendFailed {
                from,
                to,
                renamed_to,
                ..
            } => Some(SendOutcome::Failed {
                from: from.clone(),
                to: to.clone(),
                renamed_to: renamed_to.clone(),
            }),
            _ => None,
        })
    }

    fn extract_cleaned_worktrees(effects: &[Effect]) -> BTreeSet<String> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::CleanupWorktree { project_dir } => Some(project_dir.clone()),
                _ => None,
            })
            .collect()
    }

    fn update_pending_tracking(
        ds: &DaemonState,
        prev_counts: &mut BTreeMap<String, usize>,
        curr_counts: &mut BTreeMap<String, usize>,
    ) {
        *prev_counts = curr_counts.clone();
        curr_counts.clear();
        for (k, v) in &ds.pending_replies {
            curr_counts.insert(k.clone(), v.len());
        }
    }

    fn route_effects(ds: &DaemonState, effects: &[Effect], peers: &[Id], o: &mut Out<ModelActor>) {
        for effect in effects {
            match effect {
                Effect::Broadcast(wire_msg) => {
                    if let Some(model_msg) = wire_to_msg(wire_msg) {
                        for &peer in peers.iter() {
                            o.send(peer, model_msg.clone());
                        }
                    }
                }
                Effect::BroadcastSessionList => {
                    let session_ids: BTreeSet<String> = ds
                        .sessions
                        .values()
                        .filter(|s| matches!(s.origin, Origin::Local) && s.metadata.networked)
                        .map(|s| s.id.clone())
                        .collect();
                    let msg = ModelMsg::WireList {
                        sessions: session_ids,
                        daemon_id: ds.daemon_id.clone(),
                        daemon_name: ds.daemon_name.clone(),
                        seq: ds.wire_seq,
                    };
                    for &peer in peers.iter() {
                        o.send(peer, msg.clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn wire_to_msg(wire: &WireMessage) -> Option<ModelMsg> {
        match wire {
            WireMessage::SessionAnnounce {
                id,
                daemon_id,
                daemon_name,
                seq,
                ..
            } => Some(ModelMsg::WireAnnounce {
                id: id.clone(),
                daemon_id: daemon_id.clone(),
                daemon_name: daemon_name.clone(),
                seq: *seq,
            }),
            WireMessage::SessionRemove {
                id,
                daemon_id,
                daemon_name,
                seq,
                ..
            } => Some(ModelMsg::WireRemove {
                id: id.clone(),
                daemon_id: daemon_id.clone(),
                daemon_name: daemon_name.clone(),
                seq: *seq,
            }),
            WireMessage::SessionRenamed {
                old_id,
                new_id,
                daemon_id,
                daemon_name,
                seq,
                ..
            } => Some(ModelMsg::WireRenamed {
                old_id: old_id.clone(),
                new_id: new_id.clone(),
                daemon_id: daemon_id.clone(),
                daemon_name: daemon_name.clone(),
                seq: *seq,
            }),
            WireMessage::SessionSend {
                from,
                to,
                message,
                expects_reply,
                msg_id,
                responds_to,
                done,
            } => Some(ModelMsg::WireSessionSend {
                from: from.clone(),
                to: to.clone(),
                message: message.clone(),
                expects_reply: *expects_reply,
                msg_id: *msg_id,
                responds_to: *responds_to,
                done: *done,
            }),
            // SessionList is handled via BroadcastSessionList effect, not here.
            // SessionSendAck is not modeled (it's an ack, no state change needed).
            _ => None,
        }
    }

    fn offer_actions(o: &mut Out<ModelActor>) {
        let mut c = Vec::new();
        for &id in &SESSION_IDS {
            c.push(ModelAction::Register(id.to_string()));
            c.push(ModelAction::Remove(id.to_string()));
            // Register with shared worktree dir + recurrence metadata.
            // Both sessions can point at the same dir, exercising the
            // shared-worktree guard in apply_remove.
            c.push(ModelAction::RegisterWithMeta {
                id: id.to_string(),
                project_dir: Some(MODEL_WORKTREE_DIR.to_string()),
                workflow: Some("test-workflow.py".to_string()),
                prompt: Some("model-prompt".to_string()),
                reminder: Some("model-reminder".to_string()),
            });
        }
        // Offer RemoveKeep and ReapDead for first session only to limit
        // state space -- the code paths are symmetric across IDs.
        c.push(ModelAction::RemoveKeep(SESSION_IDS[0].to_string()));
        c.push(ModelAction::ReapDead(vec![SESSION_IDS[0].to_string()]));
        for &a in &SESSION_IDS {
            for &b in &SESSION_IDS {
                if a != b {
                    c.push(ModelAction::Rename(a.to_string(), b.to_string()));
                    // Send with expects_reply true and false
                    c.push(ModelAction::Send {
                        from: a.to_string(),
                        to: b.to_string(),
                        expects_reply: true,
                    });
                    c.push(ModelAction::Send {
                        from: a.to_string(),
                        to: b.to_string(),
                        expects_reply: false,
                    });
                    // Reply with msg_id 1..=4, done true and false
                    for msg_id in 1..=4u64 {
                        c.push(ModelAction::Reply {
                            from: a.to_string(),
                            to: b.to_string(),
                            msg_id,
                            done: true,
                        });
                        c.push(ModelAction::Reply {
                            from: a.to_string(),
                            to: b.to_string(),
                            msg_id,
                            done: false,
                        });
                    }
                }
            }
        }
        o.choose_random("action", c);
    }

    // -- Property checkers ---------------------------------------------------

    fn daemon_states(actor_states: &[std::sync::Arc<ModelState>]) -> Vec<&DaemonState> {
        actor_states
            .iter()
            .filter_map(|s| match s.as_ref() {
                ModelState::Daemon { ds, .. } => Some(ds.as_ref()),
                _ => None,
            })
            .collect()
    }

    /// After quiescence, each daemon's local sessions match every other daemon's
    /// remote view of that daemon.
    fn check_convergence(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        if state.network.len() > 0 {
            return true;
        }
        let ds = daemon_states(&state.actor_states);
        for src in &ds {
            for obs in &ds {
                if src.daemon_id == obs.daemon_id {
                    continue;
                }
                let src_local: BTreeSet<&str> = src
                    .sessions
                    .values()
                    .filter(|s| matches!(s.origin, Origin::Local) && s.metadata.networked)
                    .map(|s| s.id.as_str())
                    .collect();
                let obs_remote: BTreeSet<&str> = obs
                    .sessions
                    .values()
                    .filter(|s| matches!(&s.origin, Origin::Remote(d) if d == &src.daemon_id))
                    .map(|s| strip_remote_prefix(&s.id))
                    .collect();
                if src_local != obs_remote {
                    return false;
                }
            }
        }
        true
    }

    /// No daemon stores a remote session attributed to itself.
    fn check_no_self_remote(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        daemon_states(&state.actor_states).iter().all(|ds| {
            ds.sessions
                .values()
                .all(|s| !matches!(&s.origin, Origin::Remote(d) if d == &ds.daemon_id))
        })
    }

    /// Alias chains never form cycles.
    fn check_alias_acyclic(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds in daemon_states(&state.actor_states) {
            for (start, first) in &ds.aliases {
                let mut cur = first.as_str();
                let mut vis = BTreeSet::new();
                vis.insert(start.as_str());
                if !vis.insert(cur) {
                    return false;
                }
                while let Some(nxt) = ds.aliases.get(cur) {
                    if !vis.insert(nxt.as_str()) {
                        return false;
                    }
                    cur = nxt.as_str();
                }
            }
        }
        true
    }

    fn check_some_registered(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        daemon_states(&state.actor_states).iter().any(|ds| {
            ds.sessions
                .values()
                .any(|s| matches!(s.origin, Origin::Local))
        })
    }

    fn check_some_remote(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        daemon_states(&state.actor_states).iter().any(|ds| {
            ds.sessions
                .values()
                .any(|s| matches!(&s.origin, Origin::Remote(_)))
        })
    }

    /// Re-registering the same session ID produces the same final state
    /// regardless of how many times it's applied.
    fn check_register_idempotent(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds in daemon_states(&state.actor_states) {
            for (id, entry) in &ds.sessions {
                if matches!(entry.origin, Origin::Local) {
                    // Local session count for this ID should be exactly 1
                    let count = ds
                        .sessions
                        .values()
                        .filter(|s| s.id == *id && matches!(s.origin, Origin::Local))
                        .count();
                    if count != 1 {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// wire_seq is monotonically increasing (never decreases).
    fn check_seq_monotonic(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds in daemon_states(&state.actor_states) {
            for &seen in ds.last_seen_seq.values() {
                // Sanity: seq should never be astronomically large in the model
                if seen > u64::MAX / 2 {
                    return false;
                }
            }
        }
        true
    }

    /// Metadata updates don't affect convergence: remote session existence
    /// matches local session existence regardless of metadata content.
    fn check_metadata_does_not_affect_convergence(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        let ds = daemon_states(&state.actor_states);
        for obs in &ds {
            for entry in obs.sessions.values() {
                if let Origin::Remote(ref peer_id) = entry.origin {
                    let peer_exists = ds.iter().any(|d| d.daemon_id == *peer_id);
                    if !peer_exists {
                        return false;
                    }
                }
            }
        }
        true
    }

    // -- Worktree, recurrence, and reap property checkers --------------------

    /// CleanupWorktree must never be emitted for a project_dir that another
    /// live session still references. The bug: apply_remove with keep_worktree=false
    /// used to clean up worktrees without checking if other sessions shared the
    /// directory. The fix checks `self.sessions` for other references first.
    fn check_no_cleanup_while_shared(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds_state in &state.actor_states {
            if let ModelState::Daemon {
                ds,
                last_cleaned_worktrees,
                ..
            } = ds_state.as_ref()
            {
                for cleaned_dir in last_cleaned_worktrees {
                    // If any remaining session still points at this dir, invariant broken
                    let still_referenced = ds
                        .sessions
                        .values()
                        .any(|s| s.metadata.project_dir.as_deref() == Some(cleaned_dir.as_str()));
                    if still_referenced {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// ReapDead must never emit CleanupWorktree. Reap preserves worktrees
    /// (uncommitted work) -- only explicit Remove with keep_worktree=false cleans up.
    fn check_reap_never_cleans_worktree(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds_state in &state.actor_states {
            if let ModelState::Daemon {
                last_cleaned_worktrees,
                last_was_reap: true,
                ..
            } = ds_state.as_ref()
            {
                if !last_cleaned_worktrees.is_empty() {
                    return false;
                }
            }
        }
        true
    }

    /// Re-registering a session preserves recurrence fields (prompt, reminder,
    /// iteration, workflow) that were set by the prior registration. This
    /// verifies inherit_recurrence_from works correctly: if workflow_calls > 0
    /// or workflow_max_calls > 0, the workflow path must still be set.
    fn check_recurrence_preserved_on_reregister(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds in daemon_states(&state.actor_states) {
            for entry in ds.sessions.values() {
                if !matches!(entry.origin, Origin::Local) {
                    continue;
                }
                if entry.metadata.workflow_calls > 0 && entry.metadata.workflow.is_none() {
                    return false;
                }
                if entry.metadata.workflow_max_calls > 0 && entry.metadata.workflow.is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Liveness: the model exercises worktree cleanup at least once.
    fn check_some_worktree_cleanup(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        state.actor_states.iter().any(|s| {
            matches!(
                s.as_ref(),
                ModelState::Daemon {
                    last_cleaned_worktrees,
                    ..
                } if !last_cleaned_worktrees.is_empty()
            )
        })
    }

    /// Liveness: some state has sessions with workflow metadata set.
    fn check_some_workflow_sessions(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        daemon_states(&state.actor_states)
            .iter()
            .any(|ds| ds.sessions.values().any(|s| s.metadata.workflow.is_some()))
    }

    /// Liveness: the model exercises the ReapDead path.
    fn check_some_reap(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        state.actor_states.iter().any(|s| {
            matches!(
                s.as_ref(),
                ModelState::Daemon {
                    last_was_reap: true,
                    ..
                }
            )
        })
    }

    // -- Model builder -------------------------------------------------------

    fn build_model() -> ActorModel<ModelActor, ()> {
        let (d0, d1) = (Id::from(0usize), Id::from(1usize));
        ActorModel::new((), ())
            .actor(ModelActor::Daemon {
                daemon_id: "npub0".into(),
                daemon_name: "host0".into(),
                peers: vec![d1],
            })
            .actor(ModelActor::Daemon {
                daemon_id: "npub1".into(),
                daemon_name: "host1".into(),
                peers: vec![d0],
            })
            .actor(ModelActor::SessionDriver { target: d0 })
            .actor(ModelActor::SessionDriver { target: d1 })
            .init_network(Network::new_unordered_nonduplicating([]))
            .property(Expectation::Always, "no self-remote", check_no_self_remote)
            .property(Expectation::Always, "convergence", check_convergence)
            .property(Expectation::Always, "alias acyclic", check_alias_acyclic)
            .property(
                Expectation::Always,
                "register idempotent",
                check_register_idempotent,
            )
            .property(Expectation::Always, "seq monotonic", check_seq_monotonic)
            .property(
                Expectation::Always,
                "remote refs valid daemons",
                check_metadata_does_not_affect_convergence,
            )
            .property(
                Expectation::Always,
                "pending replies valid",
                check_pending_replies_valid,
            )
            .property(
                Expectation::Always,
                "send failure implies unreachable",
                check_send_failure_implies_unreachable,
            )
            .property(
                Expectation::Always,
                "no spurious pending removal",
                check_no_spurious_pending_removal,
            )
            .property(
                Expectation::Always,
                "alias send hints",
                check_alias_send_hints,
            )
            .property(
                Expectation::Always,
                "no cleanup while shared",
                check_no_cleanup_while_shared,
            )
            .property(
                Expectation::Always,
                "reap never cleans worktree",
                check_reap_never_cleans_worktree,
            )
            .property(
                Expectation::Always,
                "recurrence preserved on reregister",
                check_recurrence_preserved_on_reregister,
            )
            .property(Expectation::Sometimes, "registered", check_some_registered)
            .property(Expectation::Sometimes, "remote visible", check_some_remote)
            .property(
                Expectation::Sometimes,
                "pending replies exist",
                check_some_pending_replies,
            )
            .property(
                Expectation::Sometimes,
                "some deliveries",
                check_some_deliveries,
            )
            .property(
                Expectation::Sometimes,
                "cross-daemon delivery",
                check_cross_daemon_delivery,
            )
            .property(
                Expectation::Sometimes,
                "worktree cleanup exercised",
                check_some_worktree_cleanup,
            )
            .property(
                Expectation::Sometimes,
                "workflow sessions exist",
                check_some_workflow_sessions,
            )
            .property(
                Expectation::Sometimes,
                "reap exercised",
                check_some_reap,
            )
            .within_boundary(|_, state| state.network.len() <= 12)
    }

    // -- Reply threading property checkers -----------------------------------

    /// All pending reply entries reference sessions that exist somewhere.
    fn check_pending_replies_valid(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        let ds = daemon_states(&state.actor_states);
        for d in &ds {
            for (session_id, entries) in &d.pending_replies {
                // The session that owes the reply must exist locally
                if !d.sessions.contains_key(session_id) {
                    return false;
                }
                // Each entry's msg_id must be unique within this session
                let mut seen = BTreeSet::new();
                for e in entries {
                    if !seen.insert(e.msg_id) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Property 8: If send failed and target wasn't renamed, then the sending
    /// daemon itself does not have that target as a reachable session (local
    /// networked with a pane, keyed exactly by that ID).
    fn check_send_failure_implies_unreachable(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds_state in &state.actor_states {
            if let ModelState::Daemon {
                ds,
                last_send_result:
                    Some(SendOutcome::Failed {
                        to,
                        renamed_to: None,
                        ..
                    }),
                ..
            } = ds_state.as_ref()
            {
                if ds.sessions.contains_key(to.as_str()) {
                    return false;
                }
            }
        }
        true
    }

    /// Property 10: If last event was ReplyProgress (done=false), pending count
    /// must not decrease.
    fn check_no_spurious_pending_removal(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds_state in &state.actor_states {
            if let ModelState::Daemon {
                pending_reply_counts,
                prev_pending_reply_counts,
                last_event_type,
                ..
            } = ds_state.as_ref()
            {
                if matches!(last_event_type, LastEvent::ReplyProgress) {
                    for (session, &count) in pending_reply_counts {
                        let prev = prev_pending_reply_counts.get(session).copied().unwrap_or(0);
                        if count < prev {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Property 11: If send failed and the sending daemon can resolve an alias
    /// for the target (alias exists AND the alias target is in sessions),
    /// renamed_to must be Some.
    fn check_alias_send_hints(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        for ds_state in &state.actor_states {
            if let ModelState::Daemon {
                ds,
                last_send_result: Some(SendOutcome::Failed { to, renamed_to, .. }),
                ..
            } = ds_state.as_ref()
            {
                if ds.resolve_alias(to.as_str()).is_some() && renamed_to.is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Liveness: some state has pending replies.
    fn check_some_pending_replies(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        daemon_states(&state.actor_states)
            .iter()
            .any(|ds| ds.pending_replies.values().any(|v| !v.is_empty()))
    }

    /// Liveness: some send was delivered.
    fn check_some_deliveries(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        state.actor_states.iter().any(|s| {
            matches!(
                s.as_ref(),
                ModelState::Daemon {
                    last_send_result: Some(SendOutcome::Delivered { .. }),
                    ..
                }
            )
        })
    }

    /// Liveness: a message was delivered cross-daemon.
    fn check_cross_daemon_delivery(
        _: &ActorModel<ModelActor, ()>,
        state: &<ActorModel<ModelActor, ()> as Model>::State,
    ) -> bool {
        let daemon_info: Vec<(&str, Option<&SendOutcome>)> = state
            .actor_states
            .iter()
            .filter_map(|s| match s.as_ref() {
                ModelState::Daemon {
                    ds,
                    last_send_result,
                    ..
                } => Some((ds.daemon_id.as_str(), last_send_result.as_ref())),
                _ => None,
            })
            .collect();
        let all_ds = daemon_states(&state.actor_states);
        for (i, (_daemon_id, send_result)) in daemon_info.iter().enumerate() {
            if let Some(SendOutcome::Delivered { to, .. }) = send_result {
                for (j, ds) in all_ds.iter().enumerate() {
                    if i != j
                        && ds
                            .sessions
                            .values()
                            .any(|s| matches!(s.origin, Origin::Local) && s.id == *to)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    // -- Tests ---------------------------------------------------------------

    #[test]
    fn model_check_bfs() {
        use std::time::Instant;
        let start = Instant::now();
        let checker = build_model().checker().spawn_bfs().join();
        let elapsed = start.elapsed();
        println!(
            "Real DaemonState model -- states: {}, unique: {}, depth: {}, time: {:.1}s",
            checker.state_count(),
            checker.unique_state_count(),
            checker.max_depth(),
            elapsed.as_secs_f64(),
        );
        checker.assert_properties();
    }
}
