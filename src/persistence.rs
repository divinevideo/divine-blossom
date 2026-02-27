use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use serde::de::DeserializeOwned;

use crate::scheduler::{ScheduledTask, TaskRun};
use crate::state::{Session, SessionMetadata, SessionOrigin};

/// Load a JSON file, returning `default` if the file doesn't exist.
fn load_json<T: DeserializeOwned>(path: &Path, default: T) -> Result<T> {
    match std::fs::read_to_string(path) {
        Ok(data) => Ok(serde_json::from_str(&data)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(default),
        Err(e) => Err(e.into()),
    }
}

/// Atomically write JSON to a file (write to .tmp, then rename).
fn save_json<T: Serialize>(path: &Path, value: &T, pretty: bool) -> Result<()> {
    let data = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    atomic_write(path, data.as_bytes())
}

/// On-disk representation of a local session for restart recovery.
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedSession {
    pub id: String,
    pub pane: Option<String>,
    pub registered_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub last_activity_at: DateTime<Utc>,
    pub metadata: SessionMetadata,
}

impl PersistedSession {
    /// Convert a live session to its persisted form (local only).
    pub fn from_session(session: &Session) -> Option<Self> {
        // Only persist Local sessions; Remote and Human are restored differently.
        if !matches!(session.origin, SessionOrigin::Local) {
            return None;
        }
        Some(Self {
            id: session.id.clone(),
            pane: session.pane.clone(),
            registered_at: session.registered_at,
            last_activity_at: session.last_activity_at,
            metadata: session.metadata.clone(),
        })
    }
}

/// On-disk representation of a remote node connection.
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedConnection {
    pub ticket: String,
    pub connected_at: DateTime<Utc>,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default)]
    pub daemon_npub: Option<String>,
}

// --- Sessions ---

/// Load persisted sessions from `sessions.json`.
///
/// # Errors
///
/// Returns an error if the file exists but contains invalid JSON.
pub fn load_sessions(data_dir: &Path) -> Result<Vec<PersistedSession>> {
    load_json(&data_dir.join("sessions.json"), vec![])
}

/// Atomically write sessions to `sessions.json`.
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn save_sessions(data_dir: &Path, sessions: &[PersistedSession]) -> Result<()> {
    save_json(&data_dir.join("sessions.json"), &sessions, false)
}

// --- Connections ---

/// Load persisted connections from `connections.json`.
///
/// # Errors
///
/// Returns an error if the file exists but contains invalid JSON.
pub fn load_connections(data_dir: &Path) -> Result<Vec<PersistedConnection>> {
    load_json(&data_dir.join("connections.json"), vec![])
}

/// Add or update a connection, deduplicating by npub or ticket.
///
/// # Errors
///
/// Returns an error if reading or writing `connections.json` fails.
pub fn add_connection(
    data_dir: &Path,
    ticket: &str,
    node_name: Option<&str>,
    daemon_npub: Option<&str>,
) -> Result<()> {
    let mut conns = load_connections(data_dir).unwrap_or_default();
    // Dedup by npub (preferred) or by ticket string (fallback)
    if let Some(npub) = daemon_npub {
        conns.retain(|c| c.daemon_npub.as_deref() != Some(npub));
    }
    conns.retain(|c| c.ticket != ticket);
    conns.push(PersistedConnection {
        ticket: ticket.to_string(),
        connected_at: Utc::now(),
        node_name: node_name.map(String::from),
        daemon_npub: daemon_npub.map(String::from),
    });
    save_json(&data_dir.join("connections.json"), &conns, false)
}

/// Remove the `connections.json` file, if it exists.
///
/// # Errors
///
/// Returns an error if file removal fails for reasons other than not found.
pub fn clear_connections(data_dir: &Path) -> Result<()> {
    match std::fs::remove_file(data_dir.join("connections.json")) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// --- Settings ---

/// Configuration for a human Nostr user who can interact via DMs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HumanSession {
    pub npub: String,
    pub name: String,
    #[serde(default)]
    pub default_session: Option<String>,
    /// Whether the welcome message has been sent.
    #[serde(default)]
    pub welcomed: bool,
}

/// LLM router configuration for dispatching bare-text human DMs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Explicit API key. If absent, falls back to `ROUTER_API_KEY` or `GEMINI_API_KEY` env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default = "default_router_model")]
    pub model: String,
    #[serde(default = "default_router_base_url")]
    pub base_url: String,
}

fn default_router_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_router_base_url() -> String {
    "https://generativelanguage.googleapis.com/v1beta/openai".to_string()
}

/// User-configurable daemon settings persisted in `settings.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OuijaSettings {
    #[serde(default = "default_true")]
    pub auto_register: bool,
    #[serde(default)]
    pub human_sessions: Vec<HumanSession>,
    /// Base directory for projects (e.g. ~/code). Used by /start to resolve session dirs.
    #[serde(default)]
    pub projects_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<RouterConfig>,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_reaper_interval")]
    pub reaper_interval_secs: u64,
    /// Max local sessions before the most idle are auto-closed. 0 = disabled.
    #[serde(default)]
    pub max_local_sessions: u64,
}

fn default_true() -> bool {
    true
}

/// Default idle timeout before a session is considered stale (seconds).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 180;
/// Default interval between reaper sweeps (seconds).
const DEFAULT_REAPER_INTERVAL_SECS: u64 = 5;

fn default_idle_timeout() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

fn default_reaper_interval() -> u64 {
    DEFAULT_REAPER_INTERVAL_SECS
}

impl Default for OuijaSettings {
    fn default() -> Self {
        Self {
            auto_register: true,
            human_sessions: Vec::new(),
            projects_dir: None,
            router: None,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            reaper_interval_secs: DEFAULT_REAPER_INTERVAL_SECS,
            max_local_sessions: 0,
        }
    }
}

/// Load settings from `settings.json`, using defaults if missing.
///
/// # Errors
///
/// Returns an error if the file exists but contains invalid JSON.
pub fn load_settings(data_dir: &Path) -> Result<OuijaSettings> {
    load_json(&data_dir.join("settings.json"), OuijaSettings::default())
}

/// Atomically write settings to `settings.json` (pretty-printed).
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn save_settings(data_dir: &Path, settings: &OuijaSettings) -> Result<()> {
    save_json(&data_dir.join("settings.json"), settings, true)
}

// --- Scheduled Tasks ---

/// Load scheduled tasks from `tasks.json` into a map keyed by ID.
///
/// # Errors
///
/// Returns an error if the file exists but contains invalid JSON.
pub fn load_tasks(data_dir: &Path) -> Result<HashMap<String, ScheduledTask>> {
    let tasks: Vec<ScheduledTask> = load_json(&data_dir.join("tasks.json"), vec![])?;
    Ok(crate::scheduler::tasks_to_map(tasks))
}

/// Atomically write scheduled tasks to `tasks.json`.
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn save_tasks(data_dir: &Path, tasks: &HashMap<String, ScheduledTask>) -> Result<()> {
    let list: Vec<&ScheduledTask> = tasks.values().collect();
    save_json(&data_dir.join("tasks.json"), &list, false)
}

/// Append a task run record to `task_runs.jsonl`.
///
/// # Errors
///
/// Returns an error if serialization or file I/O fails.
pub fn append_task_run(data_dir: &Path, run: &TaskRun) -> Result<()> {
    let path = data_dir.join("task_runs.jsonl");
    let line = serde_json::to_string(run)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    writeln!(f, "{line}")?;
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Session, SessionMetadata, SessionOrigin};

    fn make_local_session(id: &str, pane: Option<&str>) -> Session {
        Session {
            id: id.to_string(),
            pane: pane.map(|s| s.to_string()),
            origin: SessionOrigin::Local,
            registered_at: Utc::now(),
            last_activity_at: Utc::now(),
            metadata: SessionMetadata::default(),
        }
    }

    fn make_remote_session(id: &str, daemon: &str) -> Session {
        Session {
            id: id.to_string(),
            pane: None,
            origin: SessionOrigin::Remote(daemon.to_string()),
            registered_at: Utc::now(),
            last_activity_at: Utc::now(),
            metadata: SessionMetadata::default(),
        }
    }

    // --- PersistedSession::from_session ---

    #[test]
    fn from_session_local_succeeds() {
        let session = make_local_session("test", Some("%1"));
        let persisted = PersistedSession::from_session(&session);
        assert!(persisted.is_some());
        let p = persisted.unwrap();
        assert_eq!(p.id, "test");
        assert_eq!(p.pane.as_deref(), Some("%1"));
    }

    #[test]
    fn from_session_remote_returns_none() {
        let session = make_remote_session("test", "remote-daemon");
        assert!(PersistedSession::from_session(&session).is_none());
    }

    // --- Sessions ---

    #[test]
    fn sessions_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = vec![
            PersistedSession {
                id: "a".into(),
                pane: Some("%1".into()),
                registered_at: Utc::now(),
                last_activity_at: Utc::now(),
                metadata: SessionMetadata::default(),
            },
            PersistedSession {
                id: "b".into(),
                pane: None,
                registered_at: Utc::now(),
                last_activity_at: Utc::now(),
                metadata: SessionMetadata {
                    vim_mode: true,
                    project_dir: Some("/tmp".into()),
                    role: Some("dev".into()),
                    ..Default::default()
                },
            },
        ];
        save_sessions(dir.path(), &sessions).unwrap();
        let loaded = load_sessions(dir.path()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "a");
        assert_eq!(loaded[1].id, "b");
        assert!(loaded[1].metadata.vim_mode);
        assert_eq!(loaded[1].metadata.project_dir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn load_sessions_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_sessions(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn load_sessions_corrupt_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sessions.json"), "{bad").unwrap();
        assert!(load_sessions(dir.path()).is_err());
    }

    // --- Connections ---

    #[test]
    fn connections_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        add_connection(dir.path(), "ticket-abc", None, None).unwrap();
        add_connection(dir.path(), "ticket-def", Some("remote1"), None).unwrap();
        let loaded = load_connections(dir.path()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].ticket, "ticket-abc");
        assert!(loaded[0].node_name.is_none());
        assert_eq!(loaded[1].ticket, "ticket-def");
        assert_eq!(loaded[1].node_name.as_deref(), Some("remote1"));
    }

    #[test]
    fn add_connection_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        add_connection(dir.path(), "ticket-abc", None, None).unwrap();
        add_connection(dir.path(), "ticket-abc", None, None).unwrap();
        let loaded = load_connections(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn node_name_backward_compat() {
        let dir = tempfile::tempdir().unwrap();
        // Simulate old format without node_name field
        let old_json = r#"[{"ticket":"old-ticket","connected_at":"2025-01-01T00:00:00Z"}]"#;
        std::fs::write(dir.path().join("connections.json"), old_json).unwrap();
        let loaded = load_connections(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].node_name.is_none());
    }

    #[test]
    fn load_connections_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_connections(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn clear_connections_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        add_connection(dir.path(), "ticket-abc", None, None).unwrap();
        assert!(dir.path().join("connections.json").exists());
        clear_connections(dir.path()).unwrap();
        assert!(!dir.path().join("connections.json").exists());
    }

    #[test]
    fn clear_connections_no_file_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        clear_connections(dir.path()).unwrap();
    }

    // --- Settings ---

    #[test]
    fn settings_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let settings = OuijaSettings {
            auto_register: false,
            ..Default::default()
        };
        save_settings(dir.path(), &settings).unwrap();
        let loaded = load_settings(dir.path()).unwrap();
        assert!(!loaded.auto_register);
    }

    #[test]
    fn load_settings_missing_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let settings = load_settings(dir.path()).unwrap();
        assert!(settings.auto_register);
    }

    #[test]
    fn load_settings_empty_object_uses_field_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let settings = load_settings(dir.path()).unwrap();
        assert!(settings.auto_register);
    }

    #[test]
    fn human_sessions_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let settings = OuijaSettings {
            auto_register: true,
            human_sessions: vec![HumanSession {
                npub: "npub1abc".into(),
                name: "daniel".into(),
                default_session: Some("ouija".into()),
                welcomed: false,
            }],
            ..Default::default()
        };
        save_settings(dir.path(), &settings).unwrap();
        let loaded = load_settings(dir.path()).unwrap();
        assert_eq!(loaded.human_sessions.len(), 1);
        assert_eq!(loaded.human_sessions[0].name, "daniel");
        assert_eq!(loaded.human_sessions[0].npub, "npub1abc");
        assert!(!loaded.human_sessions[0].welcomed);
        assert_eq!(
            loaded.human_sessions[0].default_session.as_deref(),
            Some("ouija")
        );
    }

    #[test]
    fn human_sessions_default_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let settings = load_settings(dir.path()).unwrap();
        assert!(settings.human_sessions.is_empty());
    }

    // --- RouterConfig ---

    #[test]
    fn router_config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let settings = OuijaSettings {
            router: Some(RouterConfig {
                api_key: Some("sk-test-123".into()),
                model: "gemini-2.5-flash".into(),
                base_url: "https://generativelanguage.googleapis.com/v1beta/openai".into(),
            }),
            ..Default::default()
        };
        save_settings(dir.path(), &settings).unwrap();
        let loaded = load_settings(dir.path()).unwrap();
        let router = loaded.router.unwrap();
        assert_eq!(router.api_key.as_deref(), Some("sk-test-123"));
        assert_eq!(router.model, "gemini-2.5-flash");
    }

    #[test]
    fn router_none_backward_compat() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let settings = load_settings(dir.path()).unwrap();
        assert!(settings.router.is_none());
    }

    #[test]
    fn router_config_uses_defaults() {
        let json = r#"{"router":{"api_key":"sk-test"}}"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), json).unwrap();
        let settings = load_settings(dir.path()).unwrap();
        let router = settings.router.unwrap();
        assert_eq!(router.api_key.as_deref(), Some("sk-test"));
        assert_eq!(router.model, "gemini-2.5-flash");
        assert_eq!(
            router.base_url,
            "https://generativelanguage.googleapis.com/v1beta/openai"
        );
    }

    // --- Idle Timeout ---

    #[test]
    fn idle_timeout_default() {
        let settings: OuijaSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings.idle_timeout_secs, 180);
    }

    #[test]
    fn idle_timeout_custom() {
        let settings: OuijaSettings = serde_json::from_str(r#"{"idle_timeout_secs":600}"#).unwrap();
        assert_eq!(settings.idle_timeout_secs, 600);
    }

    // --- Scheduled Tasks ---

    #[test]
    fn tasks_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut tasks = HashMap::new();
        let task = ScheduledTask {
            id: "a1b2c3d4".into(),
            name: "test".into(),
            cron: "*/5 * * * *".into(),
            target_session: Some("web".into()),
            prompt: None,
            reminder: None,
            enabled: true,
            created_at: Utc::now(),
            next_run: None,
            last_run: None,
            last_status: None,
            run_count: 0,
            project_dir: None,
            once: false,
            backend_session_id: None,
            on_fire: crate::scheduler::OnFire::ContinueSession,
        };
        tasks.insert(task.id.clone(), task);
        save_tasks(dir.path(), &tasks).unwrap();
        let loaded = load_tasks(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("a1b2c3d4"));
    }

    #[test]
    fn load_tasks_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_tasks(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn append_task_run_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let run = TaskRun {
            task_id: "abc".into(),
            task_name: "test".into(),
            timestamp: Utc::now(),
            status: crate::scheduler::TaskRunStatus::Ok,
            error: None,
            session_name: "web".into(),
            revived_pane: None,
        };
        append_task_run(dir.path(), &run).unwrap();
        assert!(dir.path().join("task_runs.jsonl").exists());
        let content = std::fs::read_to_string(dir.path().join("task_runs.jsonl")).unwrap();
        assert!(content.contains("abc"));
    }
}
