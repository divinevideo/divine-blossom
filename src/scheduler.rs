use std::collections::HashMap;

use chrono::{DateTime, Utc};
use croner::Cron;
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use crate::tmux;

/// How often the scheduler checks for due tasks.
const SCHEDULER_TICK_SECS: u64 = 15;
/// Max time to wait for the backend to start in a revived pane.
const REVIVAL_TIMEOUT_SECS: u64 = 30;
/// Extra time to wait for the backend's TUI prompt after process appears.
const TUI_READY_TIMEOUT_SECS: u64 = 30;
/// Interval between readiness polls during session revival.
const REVIVAL_POLL_SECS: u64 = 2;

/// What happens each time the task fires.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum OnFire {
    /// Inject into live session; revive with --continue if dead.
    #[default]
    ContinueSession,
    /// Start fresh when dead/missing; no-op when alive (reminder handles nudging).
    NewSession,
    /// Named worktree that persists across fires.
    /// `clear_context: true` starts a new conversation each fire.
    /// `clear_context: false` continues/resumes the previous conversation.
    PersistentWorktree {
        #[serde(default)]
        clear_context: bool,
    },
    /// Anonymous worktree, created fresh and cleaned up after each fire.
    /// Always starts a new conversation (context clearing is implicit).
    DisposableWorktree,
}

impl OnFire {
    /// Whether this mode clears conversation context on each fire.
    pub fn clears_context(&self) -> bool {
        match self {
            Self::ContinueSession => false,
            Self::NewSession => true,
            Self::PersistentWorktree { clear_context } => *clear_context,
            Self::DisposableWorktree => true,
        }
    }

    /// Whether this mode uses a worktree.
    pub fn uses_worktree(&self) -> bool {
        matches!(
            self,
            Self::PersistentWorktree { .. } | Self::DisposableWorktree
        )
    }

    /// Whether the worktree is disposable (cleaned up after fire).
    pub fn is_disposable_worktree(&self) -> bool {
        matches!(self, Self::DisposableWorktree)
    }

    /// Whether this mode kills an alive session's process on each fire.
    /// Only worktree modes with context clearing need to kill alive sessions.
    /// ContinueSession and NewSession are no-ops when alive (reminder handles nudging).
    pub fn kills_alive(&self) -> bool {
        match self {
            Self::ContinueSession | Self::NewSession => false,
            Self::PersistentWorktree { clear_context } => *clear_context,
            Self::DisposableWorktree => true,
        }
    }
}

/// A cron-driven task that injects messages into sessions.
///
/// # Design: Trigger + SessionConfig + Runtime
///
/// ScheduledTask = SessionConfig (prompt, reminder, project_dir, on_fire) + Trigger
/// (cron, enabled, next_run). SessionMetadata (state.rs) = SessionConfig + Runtime
/// (iteration, iteration_log). The shared SessionConfig fields (prompt, reminder,
/// project_dir, on_fire) are stamped onto SessionMetadata when the task creates or
/// revives a session — that's the handoff.
///
/// A third trigger type (file watch — see GitHub issue #1) would add
/// Trigger::FileWatch alongside Trigger::Cron and the implicit Trigger::SelfDriven
/// (loop_next). If that happens, extracting a named SessionConfig type would make
/// the trigger→session handoff explicit instead of field-by-field copying.
#[derive(Clone, Debug, Serialize)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    pub cron: String,
    /// Optional: inject into this existing session (ContinueSession only).
    /// When absent or when creating a new session, `name` is used instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session: Option<String>,
    /// Bootstrap: prompt for creating/reviving the target session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Bootstrap: reminder for the target session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminder: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub next_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub last_status: Option<TaskRunStatus>,
    pub run_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    #[serde(default)]
    pub once: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "claude_session_id"
    )]
    pub backend_session_id: Option<String>,
    #[serde(default)]
    pub on_fire: OnFire,
}

impl ScheduledTask {
    /// The ouija session name to look up or create.
    /// For ContinueSession, prefer target_session if set; otherwise use the task name.
    /// For all other OnFire variants, always use the task name.
    pub fn session_name(&self) -> &str {
        if matches!(self.on_fire, OnFire::ContinueSession) {
            self.target_session.as_deref().unwrap_or(&self.name)
        } else {
            &self.name
        }
    }
}

impl<'de> serde::Deserialize<'de> for ScheduledTask {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            id: String,
            name: String,
            cron: String,
            #[serde(default)]
            target_session: Option<String>,
            #[serde(default)]
            prompt: Option<String>,
            #[serde(default)]
            reminder: Option<String>,
            enabled: bool,
            created_at: DateTime<Utc>,
            #[serde(default)]
            next_run: Option<DateTime<Utc>>,
            #[serde(default)]
            last_run: Option<DateTime<Utc>>,
            #[serde(default)]
            last_status: Option<TaskRunStatus>,
            #[serde(default)]
            run_count: u64,
            #[serde(default)]
            project_dir: Option<String>,
            #[serde(default)]
            once: bool,
            #[serde(default, alias = "claude_session_id")]
            backend_session_id: Option<String>,
            #[serde(default)]
            on_fire: Option<OnFire>,
            #[serde(default)]
            fresh: Option<bool>,
            #[serde(default)]
            worktree: Option<bool>,
            #[serde(default)]
            worktree_mode: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let on_fire = raw.on_fire.unwrap_or_else(|| {
            let fresh = raw.fresh.unwrap_or(false);
            let worktree = raw.worktree.unwrap_or(false);
            let worktree_mode = raw.worktree_mode.as_deref();
            match (fresh, worktree, worktree_mode) {
                (_, true, Some("per-fire")) => OnFire::DisposableWorktree,
                (false, true, _) => OnFire::PersistentWorktree {
                    clear_context: false,
                },
                (true, true, _) => OnFire::PersistentWorktree {
                    clear_context: true,
                },
                (true, false, _) => OnFire::NewSession,
                _ => OnFire::ContinueSession,
            }
        });

        Ok(ScheduledTask {
            id: raw.id,
            name: raw.name,
            cron: raw.cron,
            target_session: raw.target_session,
            prompt: raw.prompt,
            reminder: raw.reminder,
            enabled: raw.enabled,
            created_at: raw.created_at,
            next_run: raw.next_run,
            last_run: raw.last_run,
            last_status: raw.last_status,
            run_count: raw.run_count,
            project_dir: raw.project_dir,
            once: raw.once,
            backend_session_id: raw.backend_session_id,
            on_fire,
        })
    }
}

/// Outcome of a single scheduled task execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunStatus {
    Ok,
    Failed,
}

/// Record of a completed task execution with status and context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskRun {
    pub task_id: String,
    pub task_name: String,
    pub timestamp: DateTime<Utc>,
    pub status: TaskRunStatus,
    pub error: Option<String>,
    pub session_name: String,
    pub revived_pane: Option<String>,
}

impl TaskRun {
    /// Create an Ok run for this task.
    fn ok(task: &ScheduledTask, revived_pane: Option<String>) -> Self {
        Self {
            task_id: task.id.clone(),
            task_name: task.name.clone(),
            timestamp: Utc::now(),
            status: TaskRunStatus::Ok,
            error: None,
            session_name: task.session_name().to_string(),
            revived_pane,
        }
    }

    /// Create a Failed run for this task.
    fn failed(task: &ScheduledTask, error: String) -> Self {
        Self {
            task_id: task.id.clone(),
            task_name: task.name.clone(),
            timestamp: Utc::now(),
            status: TaskRunStatus::Failed,
            error: Some(error),
            session_name: task.session_name().to_string(),
            revived_pane: None,
        }
    }
}

/// Validate a cron expression and return a human-readable description.
///
/// # Errors
///
/// Returns the parse error as a `String` if `expr` is not valid cron syntax.
pub fn validate_cron(expr: &str) -> Result<String, String> {
    let cron = expr.parse::<Cron>().map_err(|e| format!("{e}"))?;
    Ok(cron.pattern.to_string())
}

/// Compute the next run time from now for a cron expression.
pub fn compute_next_run(expr: &str) -> Option<DateTime<Utc>> {
    let cron = expr.parse::<Cron>().ok()?;
    cron.find_next_occurrence(&Utc::now(), false).ok()
}

/// Generate an 8-char hex task ID.
pub fn generate_task_id() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// Run the scheduler loop, checking for due tasks every 15 seconds.
pub async fn run_scheduler(state: SharedState) {
    // Recompute next_run for all tasks on startup
    recompute_all_next_runs(&state).await;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(SCHEDULER_TICK_SECS)).await;
        tick(&state).await;
    }
}

/// Recompute `next_run` for all enabled tasks (e.g. after daemon restart).
async fn recompute_all_next_runs(state: &SharedState) {
    let mut tasks = state.scheduled_tasks.write().await;
    let mut changed = false;
    for task in tasks.values_mut() {
        if task.enabled {
            task.next_run = compute_next_run(&task.cron);
            changed = true;
        }
    }
    if changed {
        state.persist_tasks_from(&tasks);
    }
}

/// Single tick: find due tasks and execute them sequentially.
async fn tick(state: &SharedState) {
    let now = Utc::now();

    // Collect due task IDs under a short read lock
    let due_ids: Vec<String> = {
        let tasks = state.scheduled_tasks.read().await;
        tasks
            .values()
            .filter(|t| t.enabled && t.next_run.is_some_and(|nr| nr <= now))
            .map(|t| t.id.clone())
            .collect()
    };

    for id in due_ids {
        execute_task(state, &id).await;
    }
}

/// Execute a single scheduled task by ID.
pub async fn execute_task(state: &SharedState, task_id: &str) {
    // Read the task snapshot
    let task = {
        let tasks = state.scheduled_tasks.read().await;
        match tasks.get(task_id) {
            Some(t) => t.clone(),
            None => return,
        }
    };

    let run = execute_injection(state, &task).await;

    // Update task state
    state
        .update_task(task_id, |t| {
            t.last_run = Some(run.timestamp);
            t.last_status = Some(run.status.clone());
            t.run_count += 1;
            t.next_run = compute_next_run(&t.cron);
        })
        .await;

    state.log_task_run(run).await;

    // Auto-delete one-shot tasks after execution
    if task.once {
        state.remove_task(task_id).await;
    }
}

/// Try to inject into the target session, reviving if needed.
async fn execute_injection(state: &SharedState, task: &ScheduledTask) -> TaskRun {
    let session_name = task.session_name();

    // Look up session
    let session = {
        let proto = state.protocol.read().await;
        proto.sessions.get(session_name).cloned()
    };

    // Session not found — create from scratch if task has enough info
    let Some(session) = session else {
        if task.project_dir.is_some() || task.prompt.is_some() {
            tracing::info!("session '{session_name}' not found, creating from task project_dir",);
            return revive_from_task(state, task, None).await;
        }
        return TaskRun::failed(
            task,
            format!("session '{session_name}' not found and task has no project_dir"),
        );
    };

    // Only handle local sessions
    if !matches!(session.origin, crate::daemon_protocol::Origin::Local) {
        return TaskRun::failed(task, "cannot target remote sessions".into());
    }

    let Some(pane) = &session.pane else {
        // Session exists but has no pane — revive it
        return revive_from_task(state, task, None).await;
    };

    // Check if pane is alive
    let pane_id = pane.clone();
    let names: Vec<String> = state.backends.all_process_names();
    let alive = tokio::task::spawn_blocking(move || {
        let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        tmux::pane_alive(&pane_id, &name_refs)
    })
    .await
    .unwrap_or(false);

    if alive {
        if task.on_fire.kills_alive() {
            let dir = task
                .project_dir
                .as_deref()
                .or(session.metadata.project_dir.as_deref())
                .unwrap_or("/tmp");
            return respawn_and_inject(state, task, pane, dir).await;
        }
        // Verify session still exists — a concurrent kill may have removed it
        // while we were checking pane liveness. If gone, fall through to revival.
        if state.protocol.read().await.sessions.contains_key(session_name) {
            return TaskRun::ok(task, None);
        }
        tracing::info!(
            "session '{session_name}' disappeared during alive check, reviving"
        );
    }

    // Pane is dead — attempt revival, falling back to session's project_dir
    let project_dir = task
        .project_dir
        .as_deref()
        .or(session.metadata.project_dir.as_deref());
    revive_from_task(state, task, project_dir).await
}

/// Respawn the backend in an existing pane (for clears_context on a live session).
async fn respawn_and_inject(
    state: &SharedState,
    task: &ScheduledTask,
    pane: &str,
    dir: &str,
) -> TaskRun {
    let pane_id = pane.to_string();
    let dir = dir.to_string();
    let uses_worktree = task.on_fire.uses_worktree();
    let is_disposable = task.on_fire.is_disposable_worktree();
    let task_name = task.name.clone();

    let backend = state.backend_for_session(task.session_name()).await;
    let claude_cmd = backend.build_start_command(&crate::backend::StartOpts {
        project_dir: dir.to_string(),
        worktree: if uses_worktree {
            if is_disposable {
                Some(crate::backend::WorktreeMode::Disposable)
            } else {
                Some(crate::backend::WorktreeMode::Named(task_name.clone()))
            }
        } else {
            None
        },
    });

    let respawn_result = tokio::task::spawn_blocking({
        let pane_id = pane_id.clone();
        move || -> anyhow::Result<()> {
            let output = std::process::Command::new("tmux")
                .args(["respawn-pane", "-k", "-t", &pane_id, &claude_cmd])
                .output()?;
            if !output.status.success() {
                anyhow::bail!(
                    "respawn-pane failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(())
        }
    })
    .await;

    match respawn_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return TaskRun::failed(task, e.to_string()),
        Err(e) => return TaskRun::failed(task, e.to_string()),
    }

    // Stamp bootstrap metadata and clear backend_session_id since we started fresh
    {
        let mut proto = state.protocol.write().await;
        if let Some(s) = proto.sessions.get_mut(task.session_name()) {
            if s.metadata.prompt.is_none() {
                s.metadata.prompt = task.prompt.clone();
            }
            if s.metadata.reminder.is_none() {
                s.metadata.reminder = task.reminder.clone();
            }
            if s.metadata.on_fire.is_none() {
                s.metadata.on_fire = Some(task.on_fire.clone());
            }
            s.metadata.backend_session_id = None;
        }
    }

    // Wait for the backend process to start, then inject
    let poll_pane = pane_id.clone();
    let process_names: Vec<String> = backend
        .process_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let ready = tokio::task::spawn_blocking(move || {
        let name_refs: Vec<&str> = process_names.iter().map(|s| s.as_str()).collect();
        wait_for_process(&poll_pane, &name_refs, REVIVAL_TIMEOUT_SECS)
    })
    .await
    .unwrap_or(false);

    if !ready {
        tracing::warn!("backend did not start in time after respawn in pane {pane_id}");
    }

    TaskRun::ok(task, None)
}

/// Create or revive a session and inject a message.
///
/// `project_dir_override` falls back to `task.project_dir` if `None`.
async fn revive_from_task(
    state: &SharedState,
    task: &ScheduledTask,
    project_dir_override: Option<&str>,
) -> TaskRun {
    let project_dir = project_dir_override.or(task.project_dir.as_deref());
    match revive_and_inject(state, task, project_dir).await {
        Ok(new_pane) => {
            if task.on_fire.clears_context() {
                let mut proto = state.protocol.write().await;
                if let Some(s) = proto.sessions.get_mut(task.session_name()) {
                    s.metadata.backend_session_id = None;
                }
            }
            TaskRun::ok(task, Some(new_pane))
        }
        Err(e) => TaskRun::failed(task, e.to_string()),
    }
}

/// Revive a dead session: create new tmux window, launch the backend, re-register, inject.
async fn revive_and_inject(
    state: &SharedState,
    task: &ScheduledTask,
    project_dir: Option<&str>,
) -> anyhow::Result<String> {
    let dir = project_dir
        .map(String::from)
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()));

    let clears_context = task.on_fire.clears_context();
    let uses_worktree = task.on_fire.uses_worktree();
    let is_disposable = task.on_fire.is_disposable_worktree();

    // Build the launch command before entering the blocking closure.
    let worktree = if uses_worktree {
        if is_disposable {
            Some(crate::backend::WorktreeMode::Disposable)
        } else {
            Some(crate::backend::WorktreeMode::Named(task.name.clone()))
        }
    } else {
        None
    };
    let backend = state.backend_for_session(task.session_name()).await;
    let launch_cmd = if clears_context {
        backend.build_start_command(&crate::backend::StartOpts {
            project_dir: dir.clone(),
            worktree,
        })
    } else {
        let session_id = task
            .backend_session_id
            .clone()
            .or_else(|| backend.detect_session_id(&dir));
        backend
            .build_resume_command(&crate::backend::ResumeOpts {
                project_dir: dir.clone(),
                session_id,
                worktree,
            })
            .unwrap_or_else(|| {
                backend.build_start_command(&crate::backend::StartOpts {
                    project_dir: dir.clone(),
                    worktree: None,
                })
            })
    };

    // Create named tmux session/window for the revived session.
    // If a tmux session with the target name exists, add a window to it;
    // otherwise create a new tmux session. Both get the ouija session name.
    let new_pane = tokio::task::spawn_blocking({
        let dir = dir.clone();
        let window_name = task.session_name().to_string();
        let tmux_session = crate::tmux::tmux_session_name(&dir);
        move || -> anyhow::Result<String> {
            let tmux_session_exists = std::process::Command::new("tmux")
                .args(["has-session", "-t", &tmux_session])
                .output()
                .is_ok_and(|o| o.status.success());

            let target = format!("{tmux_session}:");
            let output = if tmux_session_exists {
                std::process::Command::new("tmux")
                    .args([
                        "new-window",
                        "-d",
                        "-t",
                        &target,
                        "-n",
                        &window_name,
                        "-P",
                        "-F",
                        "#{pane_id}",
                    ])
                    .output()?
            } else {
                std::process::Command::new("tmux")
                    .args([
                        "new-session",
                        "-d",
                        "-s",
                        &tmux_session,
                        "-n",
                        &window_name,
                        "-P",
                        "-F",
                        "#{pane_id}",
                    ])
                    .output()?
            };
            if !output.status.success() {
                anyhow::bail!(
                    "tmux session/window creation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let pane_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

            // Prevent tmux from overriding the window name
            let _ = std::process::Command::new("tmux")
                .args([
                    "set-window-option",
                    "-t",
                    &pane_id,
                    "automatic-rename",
                    "off",
                ])
                .status();

            // Launch the backend in the project dir
            std::process::Command::new("tmux")
                .args(["send-keys", "-t", &pane_id, &launch_cmd, "Enter"])
                .status()?;

            Ok(pane_id)
        }
    })
    .await??;

    // Phase 1: Wait for the backend process to appear in the pane
    let poll_pane = new_pane.clone();
    let process_names: Vec<String> = backend
        .process_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let backend_name = backend.name().to_string();
    let tui_pattern = backend.tui_ready_pattern().map(String::from);
    let process_ready = tokio::task::spawn_blocking(move || {
        let name_refs: Vec<&str> = process_names.iter().map(|s| s.as_str()).collect();
        wait_for_process(&poll_pane, &name_refs, REVIVAL_TIMEOUT_SECS)
    })
    .await
    .unwrap_or(false);

    if !process_ready {
        anyhow::bail!(
            "{backend_name} did not start within {REVIVAL_TIMEOUT_SECS}s in pane {new_pane}"
        );
    }

    // Phase 2: Wait for the backend's TUI to be ready (prompt indicator appears)
    if let Some(pattern) = tui_pattern {
        let poll_pane = new_pane.clone();
        let tui_ready = tokio::task::spawn_blocking(move || {
            wait_for_tui_ready(&poll_pane, Some(&pattern), TUI_READY_TIMEOUT_SECS)
        })
        .await
        .unwrap_or(false);

        if !tui_ready {
            tracing::warn!(
                "{backend_name} TUI prompt not detected within {TUI_READY_TIMEOUT_SECS}s in pane {new_pane}, proceeding anyway"
            );
        }
    }

    // Re-register session with new pane (same ID, so dedup check won't fire)
    let proto_meta = crate::daemon_protocol::SessionMeta {
        project_dir: project_dir.map(String::from),
        prompt: task.prompt.clone(),
        reminder: task.reminder.clone(),
        on_fire: Some(task.on_fire.clone()),
        ..Default::default()
    };
    state
        .apply_and_execute(crate::daemon_protocol::Event::Register {
            id: task.session_name().to_string(),
            pane: Some(new_pane.clone()),
            metadata: proto_meta,
        })
        .await;

    // Track disposable worktree panes for reaper cleanup
    if task.on_fire.is_disposable_worktree() {
        if let Some(ref dir) = project_dir {
            state
                .perfire_worktree_panes
                .write()
                .await
                .insert(new_pane.clone(), dir.to_string());
        }
    }

    // Inject prompt into the revived session
    if let Some(ref prompt) = task.prompt {
        let full_text = match &task.reminder {
            Some(r) => format!("{prompt}\n\n{r}"),
            None => prompt.clone(),
        };
        crate::nostr_transport::schedule_prompt_injection(state, task.session_name(), new_pane.clone(), full_text);
    }

    Ok(new_pane)
}

/// Poll a pane until one of `names` appears as the current command (blocking).
fn wait_for_process(pane: &str, names: &[&str], timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(REVIVAL_POLL_SECS));
        if let Ok(output) = std::process::Command::new("tmux")
            .args([
                "display-message",
                "-t",
                pane,
                "-p",
                "#{pane_current_command}",
            ])
            .output()
        {
            let current = String::from_utf8_lossy(&output.stdout);
            let current = current.trim();
            if names.contains(&current) {
                return true;
            }
        }
    }
    false
}

/// Poll a pane until the TUI prompt pattern appears (blocking).
/// If `pattern` is `None`, returns `true` immediately (no TUI readiness check).
fn wait_for_tui_ready(pane: &str, pattern: Option<&str>, timeout_secs: u64) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(REVIVAL_POLL_SECS));
        if let Ok(output) = std::process::Command::new("tmux")
            .args(["capture-pane", "-t", pane, "-p", "-S", "-20"])
            .output()
        {
            if String::from_utf8_lossy(&output.stdout).contains(pattern) {
                return true;
            }
        }
    }
    false
}

/// Escape a string for safe use in shell commands.
pub(crate) fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Create a new enabled `ScheduledTask` with computed `next_run`.
///
/// The task is assigned a random hex ID and starts with zero runs.
#[expect(
    clippy::too_many_arguments,
    reason = "flat parameters clearer than a builder for internal API"
)]
pub fn new_task(
    name: String,
    cron: String,
    target_session: Option<String>,
    prompt: Option<String>,
    reminder: Option<String>,
    once: bool,
    backend_session_id: Option<String>,
    on_fire: OnFire,
) -> ScheduledTask {
    let next_run = compute_next_run(&cron);
    ScheduledTask {
        id: generate_task_id(),
        name,
        cron,
        target_session,
        prompt,
        reminder,
        enabled: true,
        created_at: Utc::now(),
        next_run,
        last_run: None,
        last_status: None,
        run_count: 0,
        project_dir: None,
        once,
        backend_session_id,
        on_fire,
    }
}

/// Build a HashMap from a Vec of tasks, keyed by ID.
pub fn tasks_to_map(tasks: Vec<ScheduledTask>) -> HashMap<String, ScheduledTask> {
    tasks.into_iter().map(|t| (t.id.clone(), t)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_cron_valid() {
        let result = validate_cron("*/5 * * * *");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn validate_cron_invalid() {
        let result = validate_cron("not a cron");
        assert!(result.is_err());
    }

    #[test]
    fn compute_next_run_returns_future() {
        let next = compute_next_run("*/1 * * * *");
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }

    #[test]
    fn compute_next_run_invalid_returns_none() {
        assert!(compute_next_run("bad").is_none());
    }

    #[test]
    fn task_id_is_8_hex_chars() {
        let id = generate_task_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn task_serialization_round_trip() {
        let task = ScheduledTask {
            id: "a1b2c3d4".into(),
            name: "test task".into(),
            cron: "*/5 * * * *".into(),
            target_session: Some("web".into()),
            prompt: None,
            reminder: None,
            enabled: true,
            created_at: Utc::now(),
            next_run: Some(Utc::now()),
            last_run: None,
            last_status: None,
            run_count: 0,
            project_dir: Some("/tmp".into()),
            once: false,
            backend_session_id: None,
            on_fire: OnFire::ContinueSession,
        };
        let json = serde_json::to_string(&task).unwrap();
        let decoded: ScheduledTask = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, task.id);
        assert_eq!(decoded.name, task.name);
        assert_eq!(decoded.project_dir, task.project_dir);
    }

    #[test]
    fn shell_escape_basic() {
        assert_eq!(shell_escape("/home/user"), "'/home/user'");
    }

    #[test]
    fn shell_escape_with_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn new_task_has_next_run() {
        let task = new_task(
            "t".into(),
            "*/1 * * * *".into(),
            Some("web".into()),
            None,
            None,
            false,
            None,
            OnFire::ContinueSession,
        );
        assert!(task.next_run.is_some());
        assert!(task.enabled);
        assert_eq!(task.run_count, 0);
    }

    #[test]
    fn task_worktree_serialization() {
        let task = ScheduledTask {
            id: "wt123456".into(),
            name: "wt-task".into(),
            cron: "0 9 * * *".into(),
            target_session: Some("web".into()),
            prompt: None,
            reminder: None,
            enabled: true,
            created_at: Utc::now(),
            next_run: None,
            last_run: None,
            last_status: None,
            run_count: 0,
            project_dir: Some("/tmp/project".into()),
            once: false,
            backend_session_id: None,
            on_fire: OnFire::DisposableWorktree,
        };
        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("\"mode\":\"disposable_worktree\""));
        let decoded: ScheduledTask = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.on_fire, OnFire::DisposableWorktree);
    }

    #[test]
    fn task_worktree_defaults_on_missing_fields() {
        let json = r#"{"id":"x","name":"n","cron":"* * * * *","target_session":"s","enabled":true,"created_at":"2026-01-01T00:00:00Z","run_count":0,"once":false}"#;
        let task: ScheduledTask = serde_json::from_str(json).unwrap();
        assert_eq!(task.on_fire, OnFire::ContinueSession);
    }

    #[test]
    fn on_fire_default_is_continue_session() {
        assert_eq!(OnFire::default(), OnFire::ContinueSession);
    }

    #[test]
    fn on_fire_serialization_round_trip() {
        let variants = vec![
            OnFire::ContinueSession,
            OnFire::NewSession,
            OnFire::PersistentWorktree {
                clear_context: false,
            },
            OnFire::PersistentWorktree {
                clear_context: true,
            },
            OnFire::DisposableWorktree,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: OnFire = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, variant, "round-trip failed for {json}");
        }
    }

    #[test]
    fn on_fire_clear_context_defaults_false() {
        let json = r#"{"mode":"persistent_worktree"}"#;
        let on_fire: OnFire = serde_json::from_str(json).unwrap();
        assert_eq!(
            on_fire,
            OnFire::PersistentWorktree {
                clear_context: false
            }
        );
        assert!(!on_fire.clears_context());
    }

    #[test]
    fn legacy_task_json_migrates_to_on_fire() {
        let json = r#"{"id":"x","name":"n","cron":"* * * * *","target_session":"s","enabled":true,"created_at":"2026-01-01T00:00:00Z","run_count":0,"fresh":true,"worktree":true,"worktree_mode":"per-fire"}"#;
        let task: ScheduledTask = serde_json::from_str(json).unwrap();
        assert_eq!(task.on_fire, OnFire::DisposableWorktree);
    }

    #[test]
    fn legacy_task_fresh_only_migrates() {
        let json = r#"{"id":"x","name":"n","cron":"* * * * *","target_session":"s","enabled":true,"created_at":"2026-01-01T00:00:00Z","run_count":0,"fresh":true}"#;
        let task: ScheduledTask = serde_json::from_str(json).unwrap();
        assert_eq!(task.on_fire, OnFire::NewSession);
    }

    #[test]
    fn legacy_task_no_flags_migrates() {
        let json = r#"{"id":"x","name":"n","cron":"* * * * *","target_session":"s","enabled":true,"created_at":"2026-01-01T00:00:00Z","run_count":0,"fresh":false}"#;
        let task: ScheduledTask = serde_json::from_str(json).unwrap();
        assert_eq!(task.on_fire, OnFire::ContinueSession);
    }

    #[test]
    fn on_fire_kills_alive() {
        assert!(!OnFire::ContinueSession.kills_alive());
        assert!(!OnFire::NewSession.kills_alive());
        assert!(!OnFire::PersistentWorktree { clear_context: false }.kills_alive());
        assert!(OnFire::PersistentWorktree { clear_context: true }.kills_alive());
        assert!(OnFire::DisposableWorktree.kills_alive());
    }

    #[test]
    fn new_task_with_prompt_and_reminder() {
        let task = new_task(
            "test-task".into(),
            "0 0 * * *".into(),
            None,
            Some("do the work".into()),
            Some("call loop_next".into()),
            false,
            None,
            OnFire::NewSession,
        );
        assert_eq!(task.prompt.as_deref(), Some("do the work"));
        assert_eq!(task.reminder.as_deref(), Some("call loop_next"));
    }
}
