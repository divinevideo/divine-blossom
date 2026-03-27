use std::sync::Arc;

use chrono::{DateTime, Utc};
use ractor::concurrency::JoinHandle;
use ractor::{Actor, ActorProcessingErr, ActorRef, MessagingErr};

use crate::daemon_protocol::{IterationLogEntry, PendingReplyEntry};
use crate::state::AppState;

/// Hardcoded stall thresholds.
const MILD_STALL_MULTIPLIER: i64 = 3;
const HARD_STALL_MULTIPLIER: i64 = 10;
/// Absolute cap for hard stall: 30 minutes.
const HARD_STALL_CAP_SECS: u64 = 1800;

/// Compute average interval between consecutive iteration_log timestamps.
/// Returns None if fewer than 3 entries (insufficient data for stall detection).
pub fn compute_average_loop_interval(log: &[IterationLogEntry]) -> Option<i64> {
    if log.len() < 3 {
        return None;
    }
    let intervals: Vec<i64> = log
        .windows(2)
        .map(|w| w[1].timestamp - w[0].timestamp)
        .collect();
    let sum: i64 = intervals.iter().sum();
    Some(sum / intervals.len() as i64)
}

/// Messages the session agent handles.
#[derive(Debug)]
pub enum SessionMsg {
    /// Stop hook fired — reset idle timer.
    Stopped,
    /// User typed (UserPromptSubmit) — cancel idle, mark active.
    Active,
    /// Query: return current pending replies from DaemonState (RPC).
    GetPendingReplies(ractor::RpcReplyPort<Vec<PendingReplyEntry>>),
    /// Session was renamed — update internal session_id.
    Renamed { new_id: String },
    /// Internal: idle timer expired.
    IdleTimeout,
    /// loop_next was called — reset loop stall timer.
    LoopProgress,
    /// Internal: mild stall timer expired (3x average interval).
    LoopMildStall,
    /// Internal: hard stall timer expired (10x average interval or 30min cap).
    LoopHardStall,
    /// MCP tool called: session acknowledged the reminder.
    ClearReminder { clearing_id: u64 },
}

/// Per-session behavioral state owned by the agent.
pub struct SessionAgentState {
    pub session_id: String,
    pub pane: String,
    pub idle: bool,
    pub last_stopped_at: Option<DateTime<Utc>>,
    pub last_active_at: Option<DateTime<Utc>>,
    idle_timer: Option<JoinHandle<Result<(), MessagingErr<SessionMsg>>>>,
    /// Timer for mild loop stall (3x average interval).
    loop_mild_timer: Option<JoinHandle<Result<(), MessagingErr<SessionMsg>>>>,
    /// Timer for hard loop stall (10x average interval or 30min cap).
    loop_hard_timer: Option<JoinHandle<Result<(), MessagingErr<SessionMsg>>>>,
    /// True when the session has acknowledged the current reminder via ouija.clear-reminder.
    pub reminder_cleared: bool,
    /// Monotonic counter for clearing_id stamped on each reminder injection.
    next_clearing_id: u64,
}

impl std::fmt::Debug for SessionAgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAgentState")
            .field("session_id", &self.session_id)
            .field("pane", &self.pane)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

impl SessionAgentState {
    /// Create initial agent state for a session and pane.
    pub fn new(session_id: String, pane: String) -> Self {
        Self {
            session_id,
            pane,
            idle: false,
            last_stopped_at: None,
            last_active_at: None,
            idle_timer: None,
            loop_mild_timer: None,
            loop_hard_timer: None,
            reminder_cleared: false,
            next_clearing_id: 0,
        }
    }
}

/// The actor struct. Holds a reference to shared app state for reading
/// session metadata and performing tmux injection.
#[derive(Debug)]
pub struct SessionAgent {
    pub app_state: Arc<AppState>,
}

/// Arguments passed when spawning the agent.
#[derive(Debug)]
pub struct SessionAgentArgs {
    pub session_id: String,
    pub pane: String,
}

#[ractor::async_trait]
impl Actor for SessionAgent {
    type Msg = SessionMsg;
    type State = SessionAgentState;
    type Arguments = SessionAgentArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        tracing::info!("session agent started: {}", args.session_id);
        Ok(SessionAgentState::new(args.session_id, args.pane))
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SessionMsg::Stopped => {
                state.last_stopped_at = Some(Utc::now());
                if let Some(h) = state.idle_timer.take() {
                    h.abort();
                }
                let timeout = self.app_state.settings.read().await.idle_timeout_secs;
                state.idle_timer = Some(
                    myself.send_after(std::time::Duration::from_secs(timeout), || {
                        SessionMsg::IdleTimeout
                    }),
                );

                // Nudge about pending replies older than idle_timeout
                let cutoff = Utc::now().timestamp() - timeout as i64;
                let pending = self
                    .app_state
                    .protocol
                    .read()
                    .await
                    .pending_replies
                    .get(&state.session_id)
                    .cloned()
                    .unwrap_or_default();
                let overdue: Vec<String> = pending
                    .iter()
                    .filter(|p| p.last_activity < cutoff)
                    .map(|p| p.from.clone())
                    .collect();

                if !overdue.is_empty() {
                    self.send_reminders(&overdue, state).await;
                }
            }
            SessionMsg::Active => {
                state.idle = false;
                state.reminder_cleared = false;
                state.last_active_at = Some(Utc::now());
                if let Some(h) = state.idle_timer.take() {
                    h.abort();
                }
            }
            SessionMsg::GetPendingReplies(reply) => {
                if !reply.is_closed() {
                    let pending = self
                        .app_state
                        .protocol
                        .read()
                        .await
                        .pending_replies
                        .get(&state.session_id)
                        .cloned()
                        .unwrap_or_default();
                    let _ = reply.send(pending);
                }
            }
            SessionMsg::Renamed { new_id } => {
                tracing::info!(
                    old = %state.session_id,
                    new = %new_id,
                    "session agent renamed"
                );
                state.session_id = new_id;
            }
            SessionMsg::LoopProgress => {
                // Cancel existing stall timers
                if let Some(h) = state.loop_mild_timer.take() {
                    h.abort();
                }
                if let Some(h) = state.loop_hard_timer.take() {
                    h.abort();
                }

                // Compute average interval from iteration_log
                let avg = {
                    let proto = self.app_state.protocol.read().await;
                    proto
                        .sessions
                        .get(&state.session_id)
                        .map(|s| compute_average_loop_interval(&s.metadata.iteration_log))
                        .unwrap_or(None)
                };

                // Only activate stall detection with 3+ entries
                if let Some(avg) = avg {
                    let mild_secs = (avg * MILD_STALL_MULTIPLIER) as u64;
                    let hard_secs = ((avg * HARD_STALL_MULTIPLIER) as u64).min(HARD_STALL_CAP_SECS);

                    state.loop_mild_timer = Some(
                        myself.send_after(std::time::Duration::from_secs(mild_secs), || {
                            SessionMsg::LoopMildStall
                        }),
                    );
                    state.loop_hard_timer = Some(
                        myself.send_after(std::time::Duration::from_secs(hard_secs), || {
                            SessionMsg::LoopHardStall
                        }),
                    );

                    tracing::debug!(
                        session = %state.session_id,
                        avg_interval = avg,
                        mild_timeout = mild_secs,
                        hard_timeout = hard_secs,
                        "loop stall timers set"
                    );
                }
            }
            SessionMsg::LoopMildStall => {
                state.loop_mild_timer = None;
                tracing::warn!(
                    session = %state.session_id,
                    "mild loop stall detected (3x average interval)"
                );

                self.handle_mild_stall(state).await;
            }
            SessionMsg::LoopHardStall => {
                state.loop_hard_timer = None;
                state.loop_mild_timer = None; // clear mild too
                tracing::warn!(
                    session = %state.session_id,
                    "hard loop stall detected — forcing clean context restart"
                );

                self.handle_hard_stall(state).await;
            }
            SessionMsg::ClearReminder { clearing_id } => {
                if clearing_id == state.next_clearing_id {
                    state.reminder_cleared = true;
                    tracing::debug!(
                        session = %state.session_id,
                        clearing_id,
                        "reminder cleared by session"
                    );
                }
            }
            SessionMsg::IdleTimeout => {
                state.idle_timer = None;
                state.idle = true;

                if state.reminder_cleared {
                    tracing::debug!(
                        session = %state.session_id,
                        "idle timeout fired but reminder was cleared — skipping injection"
                    );
                } else {
                    state.next_clearing_id += 1;
                    let clearing_id = state.next_clearing_id;

                    // Read session metadata in one lock
                    let (reminder, vim_mode, pending) = {
                        let proto = self.app_state.protocol.read().await;
                        let session = proto.sessions.get(&state.session_id);
                        let reminder = session.and_then(|s| s.metadata.reminder.clone());
                        let vim_mode =
                            session.map(|s| s.metadata.vim_mode).unwrap_or(false);
                        let pending = proto
                            .pending_replies
                            .get(&state.session_id)
                            .cloned()
                            .unwrap_or_default();
                        (reminder, vim_mode, pending)
                    };

                    tracing::debug!(
                        session = %state.session_id,
                        clearing_id,
                        pending = pending.len(),
                        has_reminder = reminder.is_some(),
                        "idle timeout fired"
                    );

                    // Inject reminder text if present, otherwise a default nudge (once)
                    if let Some(ref reminder_text) = reminder {
                        let wrapped = format!(
                            "<ouija-status type=\"reminder\" clearing_id=\"{clearing_id}\">{reminder_text}</ouija-status>"
                        );
                        let _ = crate::tmux::locked_inject(
                            &self.app_state,
                            &state.session_id,
                            &state.pane,
                            &wrapped,
                            vim_mode,
                        )
                        .await;
                    } else {
                        // Default nudge for sessions with no configured reminder.
                        // Auto-clears so it fires exactly once per idle period.
                        // The nudge text teaches the LLM the clearing mechanism (HATEOAS).
                        let nudge = format!(
                            "<ouija-status type=\"idle-check\" clearing_id=\"{clearing_id}\">You appear idle. If you are done, call ouija.clear-reminder({clearing_id}) to confirm completion. If you have pending work, continue — this nudge will not repeat until your next idle period.</ouija-status>"
                        );
                        let _ = crate::tmux::locked_inject(
                            &self.app_state,
                            &state.session_id,
                            &state.pane,
                            &nudge,
                            vim_mode,
                        )
                        .await;
                        state.reminder_cleared = true;
                    }

                    // Append pending reply info with per-message format
                    if !pending.is_empty() {
                        tracing::info!(
                            session = %state.session_id,
                            count = pending.len(),
                            "reminding about unanswered pending replies"
                        );
                        for p in &pending {
                            let msg = format!(
                                "<ouija-status type=\"reminder\" clearing_id=\"{clearing_id}\">Pending reply owed: msg #{} from {}</ouija-status>",
                                p.msg_id, p.from
                            );
                            let _ = crate::tmux::locked_inject(
                                &self.app_state,
                                &state.session_id,
                                &state.pane,
                                &msg,
                                vim_mode,
                            )
                            .await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        tracing::info!("session agent stopped: {}", state.session_id);
        Ok(())
    }
}

impl SessionAgent {
    /// Inject pending-reply reminders into the session's pane.
    async fn send_reminders(&self, senders: &[String], state: &SessionAgentState) {
        let vim_mode = self
            .app_state
            .protocol
            .read()
            .await
            .sessions
            .get(&state.session_id)
            .map(|s| s.metadata.vim_mode)
            .unwrap_or(false);

        for from in senders {
            let reminder = format!(
                "<ouija-status type=\"reminder\">You have an unanswered question from {from} — reply using ouija.send</ouija-status>"
            );
            let _ = crate::tmux::locked_inject(
                &self.app_state,
                &state.session_id,
                &state.pane,
                &reminder,
                vim_mode,
            )
            .await;
        }
    }

    /// Mild stall: inject reminder + notify pending reply originators.
    async fn handle_mild_stall(&self, state: &SessionAgentState) {
        let (reminder, vim_mode, pending) = {
            let proto = self.app_state.protocol.read().await;
            let session = proto.sessions.get(&state.session_id);
            let reminder = session.and_then(|s| s.metadata.reminder.clone());
            let vim_mode = session.map(|s| s.metadata.vim_mode).unwrap_or(false);
            let pending = proto
                .pending_replies
                .get(&state.session_id)
                .cloned()
                .unwrap_or_default();
            (reminder, vim_mode, pending)
        };

        // Inject reminder into the stalled session
        if let Some(ref reminder_text) = reminder {
            let msg = format!(
                "<ouija-status type=\"loop-stall\">Loop stall detected (3x average interval). Reminder: {reminder_text}</ouija-status>"
            );
            let _ = crate::tmux::locked_inject(
                &self.app_state,
                &state.session_id,
                &state.pane,
                &msg,
                vim_mode,
            )
            .await;
        }

        // Notify originators of pending replies about the stall
        for p in &pending {
            let origin_info = {
                let proto = self.app_state.protocol.read().await;
                proto
                    .sessions
                    .get(&p.from)
                    .and_then(|s| s.pane.clone().map(|pane| (pane, s.metadata.vim_mode)))
            };
            if let Some((origin_pane, origin_vim)) = origin_info {
                let notify_msg = format!(
                    "<ouija-status type=\"loop-stall\">session '{}' appears stalled (no progress for 3x its average interval)</ouija-status>",
                    state.session_id
                );
                let _ = crate::tmux::locked_inject(
                    &self.app_state,
                    &p.from,
                    &origin_pane,
                    &notify_msg,
                    origin_vim,
                )
                .await;
            }
        }
    }

    /// Hard stall: force restart with clean context.
    async fn handle_hard_stall(&self, state: &SessionAgentState) {
        let meta = {
            let proto = self.app_state.protocol.read().await;
            proto
                .sessions
                .get(&state.session_id)
                .map(|s| s.metadata.clone())
        };

        let Some(meta) = meta else {
            return;
        };
        let Some(ref prompt) = meta.prompt else {
            return;
        };

        let prompt = prompt.clone();
        let reminder = meta.reminder.clone();
        let app_state = self.app_state.clone();
        let sid = state.session_id.clone();

        // Snapshot loop state before restart
        let stash = meta.clone();

        tokio::spawn(async move {
            crate::nostr_transport::restart_session(
                &app_state,
                &sid,
                true,
                Some(prompt.as_str()),
                None,
                None,
                None,
                None,
                reminder.as_deref(),
            )
            .await;

            // Re-stamp loop fields
            {
                let mut proto = app_state.protocol.write().await;
                if let Some(session) = proto.sessions.get_mut(&sid) {
                    session.metadata.inherit_recurrence_from(&stash);
                }
            }
            let proto = app_state.protocol.read().await;
            app_state.persist_protocol_state(&proto);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ractor::Actor;

    #[test]
    fn agent_state_starts_not_idle() {
        let state = SessionAgentState::new("test-sess".into(), "%1".into());
        assert!(!state.idle);
    }

    #[tokio::test]
    async fn agent_becomes_idle_after_stopped() {
        let state = crate::state::AppState::new_for_test();
        let agent = SessionAgent {
            app_state: state.clone(),
        };
        let args = SessionAgentArgs {
            session_id: "test-idle".into(),
            pane: "%99".into(),
        };

        state.settings.write().await.idle_timeout_secs = 1;

        let (actor, handle) = Actor::spawn(None, agent, args).await.expect("spawn failed");

        actor.cast(SessionMsg::Stopped).expect("send failed");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert!(!handle.is_finished());

        actor.stop(None);
        handle.await.expect("actor failed");
    }

    #[tokio::test]
    async fn agent_active_cancels_idle() {
        let state = crate::state::AppState::new_for_test();
        let agent = SessionAgent {
            app_state: state.clone(),
        };
        let args = SessionAgentArgs {
            session_id: "test-active".into(),
            pane: "%99".into(),
        };
        state.settings.write().await.idle_timeout_secs = 1;

        let (actor, handle) = Actor::spawn(None, agent, args).await.expect("spawn failed");

        actor.cast(SessionMsg::Stopped).expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        actor.cast(SessionMsg::Active).expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert!(!handle.is_finished());

        actor.stop(None);
        handle.await.expect("actor failed");
    }

    #[test]
    fn session_metadata_recurrence_fields_default() {
        let meta = crate::state::SessionMetadata::default();
        assert!(meta.reminder.is_none());
        assert!(meta.prompt.is_none());
        assert_eq!(meta.iteration, 0);
        assert!(meta.iteration_log.is_empty());
        assert!(meta.last_iteration_at.is_none());
    }

    #[test]
    fn compute_average_interval_needs_3_entries() {
        let log: Vec<crate::daemon_protocol::IterationLogEntry> = vec![
            crate::daemon_protocol::IterationLogEntry {
                iteration: 1,
                message: None,
                timestamp: 100,
            },
            crate::daemon_protocol::IterationLogEntry {
                iteration: 2,
                message: None,
                timestamp: 200,
            },
        ];
        assert!(compute_average_loop_interval(&log).is_none());
    }

    #[test]
    fn compute_average_interval_with_3_entries() {
        let log = vec![
            crate::daemon_protocol::IterationLogEntry {
                iteration: 1,
                message: None,
                timestamp: 100,
            },
            crate::daemon_protocol::IterationLogEntry {
                iteration: 2,
                message: None,
                timestamp: 200,
            },
            crate::daemon_protocol::IterationLogEntry {
                iteration: 3,
                message: None,
                timestamp: 400,
            },
        ];
        // intervals: 100, 200 → average = 150
        assert_eq!(compute_average_loop_interval(&log), Some(150));
    }

    #[test]
    fn compute_average_interval_empty() {
        let log: Vec<crate::daemon_protocol::IterationLogEntry> = vec![];
        assert!(compute_average_loop_interval(&log).is_none());
    }

    #[tokio::test]
    async fn agent_injects_reminder_on_idle_without_pending_replies() {
        let state = crate::state::AppState::new_for_test();
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "test-reminder".into(),
                pane: Some("%99".into()),
                metadata: crate::daemon_protocol::SessionMeta {
                    reminder: Some("call loop_next when done".into()),
                    ..Default::default()
                },
            })
            .await;

        let agent = SessionAgent {
            app_state: state.clone(),
        };
        let args = SessionAgentArgs {
            session_id: "test-reminder".into(),
            pane: "%99".into(),
        };
        state.settings.write().await.idle_timeout_secs = 1;

        let (actor, handle) = Actor::spawn(None, agent, args).await.expect("spawn failed");
        actor.cast(SessionMsg::Stopped).expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert!(!handle.is_finished());
        actor.stop(None);
        handle.await.expect("actor failed");
    }

    #[test]
    fn agent_state_starts_reminder_not_cleared() {
        let state = SessionAgentState::new("test-sess".into(), "%1".into());
        assert!(!state.reminder_cleared);
        assert_eq!(state.next_clearing_id, 0);
    }

    #[tokio::test]
    async fn active_resets_reminder_cleared() {
        let state = crate::state::AppState::new_for_test();
        let agent = SessionAgent {
            app_state: state.clone(),
        };
        let args = SessionAgentArgs {
            session_id: "test-clear".into(),
            pane: "%99".into(),
        };
        state.settings.write().await.idle_timeout_secs = 60;

        let (actor, handle) = Actor::spawn(None, agent, args).await.expect("spawn failed");

        actor
            .cast(SessionMsg::ClearReminder { clearing_id: 1 })
            .expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        actor.cast(SessionMsg::Active).expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(!handle.is_finished());

        actor.stop(None);
        handle.await.expect("actor failed");
    }

    #[tokio::test]
    async fn clear_reminder_wrong_id_ignored() {
        let state = crate::state::AppState::new_for_test();
        let agent = SessionAgent {
            app_state: state.clone(),
        };
        let args = SessionAgentArgs {
            session_id: "test-wrong-id".into(),
            pane: "%99".into(),
        };
        state.settings.write().await.idle_timeout_secs = 60;

        let (actor, handle) = Actor::spawn(None, agent, args).await.expect("spawn failed");

        // clearing_id 999 doesn't match next_clearing_id (0), should be ignored
        actor
            .cast(SessionMsg::ClearReminder { clearing_id: 999 })
            .expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(!handle.is_finished());

        actor.stop(None);
        handle.await.expect("actor failed");
    }
}
