use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

/// Common request body for pane-identified hooks.
/// Accepts either `pane` (tmux pane ID like "%689") or `backend_session_id`
/// (opencode session UUID). At least one must be provided.
#[derive(Debug, Deserialize)]
pub struct PaneBody {
    #[serde(default)]
    pub pane: Option<String>,
    #[serde(default)]
    pub backend_session_id: Option<String>,
}

impl PaneBody {
    /// Stable key for per-caller state (e.g. session diff baselines).
    fn baseline_key(&self) -> &str {
        self.pane
            .as_deref()
            .or(self.backend_session_id.as_deref())
            .unwrap_or("")
    }
}

/// POST /api/hooks/session-end
pub async fn session_end(
    State(state): State<SharedState>,
    Json(body): Json<PaneBody>,
) -> (StatusCode, Json<Value>) {
    let result = session_end_inner(&state, body).await;
    (StatusCode::OK, Json(result))
}

async fn session_end_inner(
    state: &std::sync::Arc<crate::state::AppState>,
    body: PaneBody,
) -> Value {
    let session = {
        let proto = state.protocol.read().await;
        let found = proto
            .sessions
            .values()
            .find(|s| {
                body.pane
                    .as_deref()
                    .is_some_and(|p| s.pane.as_deref() == Some(p))
                    || body
                        .backend_session_id
                        .as_deref()
                        .is_some_and(|b| s.metadata.backend_session_id.as_deref() == Some(b))
            })
            .cloned();
        match found {
            Some(s) => s,
            None => return json!({ "skipped": "no session" }),
        }
    };
    // Reject if recently registered (stale SessionEnd hook from pre-restart Claude)
    let age = chrono::Utc::now().timestamp() - session.registered_at;
    if session.registered_at > 0 && age < 5 {
        return json!({ "skipped": format!("recently registered ({}s ago)", age) });
    }
    let id = session.id.clone();
    state
        .apply_and_execute(crate::daemon_protocol::Event::Remove {
            id: id.clone(),
            keep_worktree: false,
        })
        .await;
    // Clear tmux @ouija_id
    let pane = session.pane.unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let _ = std::process::Command::new("tmux")
            .args(["set-option", "-pu", "-t", &pane, "@ouija_id"])
            .status();
    });
    json!({ "removed": id })
}

/// POST /api/hooks/stop
pub async fn hook_stop(
    State(state): State<SharedState>,
    Json(body): Json<PaneBody>,
) -> (StatusCode, Json<Value>) {
    let result = hook_stop_inner(&state, body).await;
    (StatusCode::OK, Json(result))
}

async fn hook_stop_inner(
    state: &std::sync::Arc<crate::state::AppState>,
    body: PaneBody,
) -> Value {
    if let Some(id) = state
        .find_session_by_pane_or_backend_sid(
            body.pane.as_deref(),
            body.backend_session_id.as_deref(),
        )
        .await
    {
        state
            .notify_agent(&id, crate::session_agent::SessionMsg::Stopped)
            .await;
    }
    json!({ "ok": true })
}

/// POST /api/hooks/prompt-submit
pub async fn prompt_submit(
    State(state): State<SharedState>,
    Json(body): Json<PaneBody>,
) -> (StatusCode, Json<Value>) {
    let result = prompt_submit_inner(&state, body).await;
    (StatusCode::OK, Json(result))
}

async fn prompt_submit_inner(
    state: &std::sync::Arc<crate::state::AppState>,
    body: PaneBody,
) -> Value {
    // Single lock acquisition: build snapshots, find our session, get ID for Active notify
    let baseline_key = body.baseline_key().to_string();
    let (current_snapshots, my_session, my_id) = {
        let proto = state.protocol.read().await;
        let snaps: Vec<crate::state::SessionSnapshot> = proto
            .sessions
            .values()
            .map(|s| crate::state::SessionSnapshot {
                id: s.id.clone(),
                origin: match &s.origin {
                    crate::daemon_protocol::Origin::Local => "local".into(),
                    crate::daemon_protocol::Origin::Remote(_) => "remote".into(),
                    crate::daemon_protocol::Origin::Human(_) => "human".into(),
                },
                role: s.metadata.role.clone(),
                bulletin: s.metadata.bulletin.clone(),
            })
            .collect();
        let me = proto
            .sessions
            .values()
            .find(|s| {
                body.pane.as_deref().is_some_and(|p| s.pane.as_deref() == Some(p))
                    || body.backend_session_id.as_deref().is_some_and(|b| {
                        s.metadata.backend_session_id.as_deref() == Some(b)
                    })
            })
            .cloned();
        let id = me.as_ref().map(|s| s.id.clone());
        (snaps, me, id)
    };

    // Notify agent active (outside lock)
    if let Some(ref id) = my_id {
        state
            .notify_agent(id, crate::session_agent::SessionMsg::Active)
            .await;
    }

    // Compute diff against per-caller baseline
    let previous = {
        let mut baselines = state.session_diff_baselines.lock().unwrap();
        let prev = baselines.get(baseline_key.as_str()).cloned().unwrap_or_default();
        baselines.insert(baseline_key, current_snapshots.clone());
        prev
    };

    let prev_ids: std::collections::HashSet<&str> =
        previous.iter().map(|s| s.id.as_str()).collect();
    let curr_ids: std::collections::HashSet<&str> =
        current_snapshots.iter().map(|s| s.id.as_str()).collect();

    let joined: Vec<&crate::state::SessionSnapshot> = current_snapshots
        .iter()
        .filter(|s| !prev_ids.contains(s.id.as_str()))
        .collect();
    let left: Vec<&str> = previous
        .iter()
        .filter(|s| !curr_ids.contains(s.id.as_str()))
        .map(|s| s.id.as_str())
        .collect();
    let updated: Vec<&crate::state::SessionSnapshot> = current_snapshots
        .iter()
        .filter(|s| {
            prev_ids.contains(s.id.as_str())
                && previous.iter().find(|p| p.id == s.id) != Some(s)
        })
        .collect();

    // Stale check — is_stale() is on SessionMeta in daemon_protocol.rs
    let stale = my_session.as_ref().and_then(|s| {
        if s.metadata.is_stale() {
            Some(json!({
                "id": s.id,
                "role": s.metadata.role,
                "bulletin": s.metadata.bulletin,
            }))
        } else {
            None
        }
    });

    // Format output
    let mut output_parts: Vec<String> = Vec::new();

    if let Some(ref stale_info) = stale {
        let id = stale_info["id"].as_str().unwrap_or("");
        let role = stale_info["role"].as_str().unwrap_or("none");
        let bulletin = stale_info["bulletin"].as_str().unwrap_or("");
        if !bulletin.is_empty() {
            output_parts.push(format!(
                "<ouija-status type=\"stale\">Your metadata is stale. Current: role=\"{role}\" | bulletin=\"{bulletin}\". Update via POST /api/sessions/update with {{\"id\":\"{id}\", \"role\":\"...\", \"bulletin\":\"...\"}} if these are outdated.</ouija-status>"
            ));
        } else {
            output_parts.push(format!(
                "<ouija-status type=\"stale\">Your metadata is stale (role: \"{role}\", no bulletin). Update via POST /api/sessions/update with {{\"id\":\"{id}\", \"role\":\"...\", \"bulletin\":\"...\"}} to stay discoverable.</ouija-status>"
            ));
        }
    }

    if !joined.is_empty() {
        let mut lines = vec!["<ouija-status type=\"mesh-update\">joined:".to_string()];
        for s in &joined {
            let mut line = format!("  - {} ({})", s.id, s.origin);
            if let Some(ref r) = s.role {
                line.push_str(&format!(" — {r}"));
            }
            lines.push(line);
        }
        lines.push("</ouija-status>".into());
        output_parts.push(lines.join("\n"));
    }

    if !left.is_empty() {
        output_parts.push(format!(
            "<ouija-status type=\"mesh-update\">left: {}</ouija-status>",
            left.join(",")
        ));
    }

    if !updated.is_empty() {
        let mut lines = vec!["<ouija-status type=\"mesh-update\">updated:".to_string()];
        for s in &updated {
            let prev_s = previous.iter().find(|p| p.id == s.id);
            let mut details = Vec::new();
            if s.role != prev_s.and_then(|p| p.role.as_ref()).cloned() {
                details.push(format!("role: {}", s.role.as_deref().unwrap_or("<cleared>")));
            }
            if s.bulletin != prev_s.and_then(|p| p.bulletin.as_ref()).cloned() {
                details.push(format!(
                    "bulletin: {}",
                    s.bulletin.as_deref().unwrap_or("<cleared>")
                ));
            }
            lines.push(format!("  - {}: {}", s.id, details.join(", ")));
        }
        lines.push("</ouija-status>".into());
        output_parts.push(lines.join("\n"));
    }

    json!({
        "output": output_parts.join("\n"),
        "diff": {
            "joined": joined,
            "left": left,
            "updated": updated,
        },
        "stale": stale,
    })
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used by Deserialize; will be read when blocking logic is implemented
pub struct PreToolUseBody {
    pub pane: String,
    pub tool_name: String,
}

/// POST /api/hooks/pre-tool-use
pub async fn pre_tool_use(
    State(state): State<SharedState>,
    Json(body): Json<PreToolUseBody>,
) -> (StatusCode, Json<Value>) {
    let result = pre_tool_use_inner(&state, body).await;
    (StatusCode::OK, Json(result))
}

async fn pre_tool_use_inner(
    _state: &std::sync::Arc<crate::state::AppState>,
    _body: PreToolUseBody,
) -> Value {
    // TODO: check injection marker state on the session to decide blocking.
    // Currently a no-op — always allows interactive tools.
    json!({ "block": false })
}

#[derive(Debug, Deserialize)]
pub struct SessionStartBody {
    pub pane: String,
    pub cwd: String,
}

/// POST /api/hooks/session-start
pub async fn session_start(
    State(state): State<SharedState>,
    Json(body): Json<SessionStartBody>,
) -> (StatusCode, Json<Value>) {
    let result = session_start_inner(&state, body).await;
    (StatusCode::OK, Json(result))
}

async fn session_start_inner(
    state: &std::sync::Arc<crate::state::AppState>,
    body: SessionStartBody,
) -> Value {
    // Check auto_register
    if !state.settings.read().await.auto_register {
        return json!({ "skipped": "auto_register disabled", "output": "" });
    }

    // Skip if pane already registered
    if let Some(existing_id) = state.find_session_by_pane(&body.pane).await {
        return json!({ "registered": existing_id, "output": "" });
    }

    // Derive name from cwd
    let project_root = crate::state::resolve_project_root(&body.cwd);
    let basename = std::path::Path::new(project_root)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");
    let base_id = crate::state::sanitize_session_id(basename);
    if base_id.is_empty() {
        return json!({ "error": "could not derive session name", "output": "" });
    }

    // Resolve name conflicts
    let id = {
        let proto = state.protocol.read().await;
        let mut id = base_id.clone();
        let mut suffix = 2u32;
        while proto.sessions.contains_key(&id) {
            if proto.sessions.get(&id).and_then(|s| s.pane.as_deref()) == Some(&body.pane) {
                break;
            }
            id = format!("{base_id}-{suffix}");
            suffix += 1;
            if suffix > 100 {
                break;
            }
        }
        id
    };

    // Register
    let role = format!("working on {basename}");
    let proto_meta = crate::daemon_protocol::SessionMeta {
        project_dir: Some(project_root.to_string()),
        role: Some(role),
        ..Default::default()
    };
    state
        .apply_and_execute(crate::daemon_protocol::Event::Register {
            id: id.clone(),
            pane: Some(body.pane.clone()),
            metadata: proto_meta,
        })
        .await;

    // Set tmux @ouija_id (after registration so name reflects any suffix)
    let pane_clone = body.pane.clone();
    let tmux_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let _ = std::process::Command::new("tmux")
            .args(["set-option", "-p", "-t", &pane_clone, "@ouija_id", &tmux_id])
            .status();
    });

    // Build peer list
    let peers: Vec<Value> = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .filter(|s| s.id != id)
            .map(|s| {
                json!({
                    "id": s.id,
                    "role": s.metadata.role,
                    "bulletin": s.metadata.bulletin,
                })
            })
            .collect()
    };

    // Version check
    let daemon_version = env!("CARGO_PKG_VERSION");
    let plugin_version = std::env::var("HOME")
        .ok()
        .and_then(|home| {
            std::fs::read_dir(format!("{home}/.claude/plugins/cache/ouija/ouija"))
                .ok()
        })
        .and_then(|entries| {
            entries.flatten().find_map(|e| {
                let vf = e.path().join(".version");
                std::fs::read_to_string(vf).ok()
            })
        })
        .map(|v| v.trim().to_string());

    let version_warning = plugin_version
        .as_ref()
        .filter(|pv| pv.as_str() != daemon_version)
        .map(|pv| format!("daemon={daemon_version}, plugin={pv}"));

    // Format output
    let mut output_parts = vec![format!(
        "<ouija-status type=\"registered\">Registered as {id} on the ouija mesh.</ouija-status>"
    )];

    if let Some(ref warn) = version_warning {
        output_parts.push(format!(
            "WARNING: ouija version mismatch — {warn}.\n  To fix: run 'ouija update', then start a new session."
        ));
    }

    if !peers.is_empty() {
        let mut peer_lines =
            vec!["<ouija-status type=\"mesh-update\">Other sessions on the mesh:".to_string()];
        for p in &peers {
            let mut line = format!("  - {}", p["id"].as_str().unwrap_or("?"));
            if let Some(r) = p["role"].as_str() {
                line.push_str(&format!(" | {r}"));
            }
            if let Some(b) = p["bulletin"].as_str() {
                line.push_str(&format!(" | bulletin: {b}"));
            }
            peer_lines.push(line);
        }
        peer_lines.push("</ouija-status>".into());
        output_parts.push(peer_lines.join("\n"));
    } else {
        output_parts.push(
            "<ouija-status type=\"mesh-update\">No other sessions on the mesh.</ouija-status>"
                .into(),
        );
    }

    json!({
        "registered": id,
        "output": output_parts.join("\n"),
        "peers": peers,
        "version_warning": version_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_end_removes_old_session() {
        let state = crate::state::AppState::new_for_test();
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "test-session".into(),
                pane: Some("%99".into()),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;
        assert!(state.find_session_by_pane("%99").await.is_some());

        // Manually set registered_at to 10 seconds ago so the guard doesn't trigger
        {
            let mut proto = state.protocol.write().await;
            if let Some(s) = proto.sessions.get_mut("test-session") {
                s.registered_at = chrono::Utc::now().timestamp() - 10;
            }
        }

        let body = PaneBody { pane: Some("%99".into()), backend_session_id: None };
        let result = session_end_inner(&state, body).await;
        assert!(result.get("removed").is_some());
        assert!(state.find_session_by_pane("%99").await.is_none());
    }

    #[tokio::test]
    async fn session_end_rejects_recently_registered() {
        let state = crate::state::AppState::new_for_test();
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "fresh".into(),
                pane: Some("%99".into()),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;
        // registered_at is now(), so age < 5s — should reject
        let body = PaneBody { pane: Some("%99".into()), backend_session_id: None };
        let result = session_end_inner(&state, body).await;
        assert!(result.get("skipped").is_some());
        // Session still exists
        assert!(state.find_session_by_pane("%99").await.is_some());
    }

    #[tokio::test]
    async fn session_end_no_session() {
        let state = crate::state::AppState::new_for_test();
        let body = PaneBody { pane: Some("%999".into()), backend_session_id: None };
        let result = session_end_inner(&state, body).await;
        assert!(result.get("skipped").is_some());
    }

    #[tokio::test]
    async fn hook_stop_no_session_returns_ok() {
        let state = crate::state::AppState::new_for_test();
        let body = PaneBody { pane: Some("%999".into()), backend_session_id: None };
        let result = hook_stop_inner(&state, body).await;
        assert_eq!(result, json!({ "ok": true }));
    }

    #[tokio::test]
    async fn prompt_submit_returns_empty_for_unknown_pane() {
        let state = crate::state::AppState::new_for_test();
        let body = PaneBody { pane: Some("%999".into()), backend_session_id: None };
        let result = prompt_submit_inner(&state, body).await;
        assert_eq!(result["output"], "");
    }

    #[tokio::test]
    async fn prompt_submit_detects_joined_sessions() {
        let state = crate::state::AppState::new_for_test();
        // Register observer pane
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "observer".into(),
                pane: Some("%10".into()),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;
        // First call: sets baseline
        let _ = prompt_submit_inner(&state, PaneBody { pane: Some("%10".into()), backend_session_id: None }).await;
        // Add newcomer
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "newcomer".into(),
                pane: Some("%11".into()),
                metadata: crate::daemon_protocol::SessionMeta {
                    role: Some("working on newcomer".into()),
                    ..Default::default()
                },
            })
            .await;
        // Second call: should detect newcomer
        let result = prompt_submit_inner(&state, PaneBody { pane: Some("%10".into()), backend_session_id: None }).await;
        let output = result["output"].as_str().unwrap();
        assert!(output.contains("newcomer"), "output should mention newcomer: {output}");
        assert!(output.contains("joined"), "output should contain 'joined': {output}");
    }

    #[tokio::test]
    async fn pre_tool_use_no_session_allows() {
        let state = crate::state::AppState::new_for_test();
        let body = PreToolUseBody {
            pane: "%999".into(),
            tool_name: "AskUserQuestion".into(),
        };
        let result = pre_tool_use_inner(&state, body).await;
        assert_eq!(result["block"], false);
    }

    #[tokio::test]
    async fn session_start_registers_new_session() {
        let state = crate::state::AppState::new_for_test();
        let body = SessionStartBody {
            pane: "%50".into(),
            cwd: "/home/user/code/myproject".into(),
        };
        let result = session_start_inner(&state, body).await;
        assert_eq!(result["registered"], "myproject");
        let output = result["output"].as_str().unwrap();
        assert!(output.contains("ouija-status"), "output: {output}");
    }

    #[tokio::test]
    async fn session_start_skips_already_registered() {
        let state = crate::state::AppState::new_for_test();
        state
            .apply_and_execute(crate::daemon_protocol::Event::Register {
                id: "existing".into(),
                pane: Some("%50".into()),
                metadata: crate::daemon_protocol::SessionMeta::default(),
            })
            .await;
        let body = SessionStartBody {
            pane: "%50".into(),
            cwd: "/home/user/code/existing".into(),
        };
        let result = session_start_inner(&state, body).await;
        assert_eq!(result["registered"], "existing");
        // Verify only one session exists
        let proto = state.protocol.read().await;
        let count = proto.sessions.len();
        assert_eq!(count, 1, "should still have exactly 1 session, got {count}");
    }

    #[tokio::test]
    async fn session_start_resolves_worktree_path() {
        let state = crate::state::AppState::new_for_test();
        let body = SessionStartBody {
            pane: "%50".into(),
            cwd: "/home/user/code/ouija/.ouija/worktrees/feature-x".into(),
        };
        let result = session_start_inner(&state, body).await;
        assert_eq!(result["registered"], "ouija");
    }
}
