use std::path::Path;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Deserialize;
use serde_json::json;

use crate::scheduler;
use crate::state::SharedState;
use crate::tmux;
use crate::transport;

/// Max description length before truncation.
const MAX_DESCRIPTION_LEN: usize = 200;
/// Max characters of npub to display as fallback node name.
const NPUB_DISPLAY_LEN: usize = 16;
/// Timeout for peer connect handshake.
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Max task runs to return in the list endpoint.
const MAX_TASK_RUNS_RETURNED: usize = 50;

/// Extract a short project description from a project directory.
///
/// Tries in order: `Cargo.toml` description field, `package.json` description,
/// first non-heading non-empty line of `README.md` (truncated to 200 chars).
pub(crate) fn extract_project_description(project_dir: &str) -> Option<String> {
    let dir = Path::new(project_dir);

    // Try Cargo.toml
    if let Ok(contents) = std::fs::read_to_string(dir.join("Cargo.toml")) {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("description") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let val = rest.trim().trim_matches('"');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }

    // Try package.json
    if let Ok(contents) = std::fs::read_to_string(dir.join("package.json")) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(desc) = json["description"].as_str() {
                if !desc.is_empty() {
                    return Some(desc.to_string());
                }
            }
        }
    }

    // Try README.md — first non-heading, non-empty line
    if let Ok(contents) = std::fs::read_to_string(dir.join("README.md")) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let truncated = if trimmed.len() > MAX_DESCRIPTION_LEN {
                format!("{}...", &trimmed[..MAX_DESCRIPTION_LEN])
            } else {
                trimmed.to_string()
            };
            return Some(truncated);
        }
    }

    None
}

/// Return status of a single session by name.
pub async fn get_session(
    State(state): State<SharedState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let proto = state.protocol.read().await;
    match proto.sessions.get(&name) {
        Some(s) => {
            let stale = s.metadata.is_stale();
            (
                StatusCode::OK,
                Json(json!({
                    "id": s.id,
                    "pane": s.pane,
                    "origin": s.origin.label(),
                    "vim_mode": s.metadata.vim_mode,
                    "project_dir": s.metadata.project_dir,
                    "role": s.metadata.role,
                    "bulletin": s.metadata.bulletin,
                    "networked": s.metadata.networked,
                    "worktree": s.metadata.worktree,
                    "model": s.metadata.model,
                    "last_metadata_update": s.metadata.last_metadata_update,
                    "stale": stale,
                    "backend_session_id": s.metadata.backend_session_id,
                    "backend": s.metadata.backend,
                    "reminder": s.metadata.reminder,
                    "prompt": s.metadata.prompt,
                    "iteration": s.metadata.iteration,
                    "iteration_log": s.metadata.iteration_log,
                    "last_iteration_at": s.metadata.last_iteration_at,
                    "workflow": s.metadata.workflow,
                    "workflow_calls": s.metadata.workflow_calls,
                    "workflow_max_calls": s.metadata.workflow_max_calls,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("session '{}' not found", name)})),
        ),
    }
}

/// Return daemon status, sessions, nodes, and transport info.
pub async fn status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let proto = state.protocol.read().await;
    let nodes = state.nodes.read().await;
    let transports = state.transports().await;

    let sessions_list: Vec<_> = proto
        .sessions
        .values()
        .map(|s| {
            let stale = s.metadata.is_stale();
            json!({
                "id": s.id,
                "pane": s.pane,
                "origin": s.origin.label(),
                "vim_mode": s.metadata.vim_mode,
                "project_dir": s.metadata.project_dir,
                "role": s.metadata.role,
                "bulletin": s.metadata.bulletin,
                "networked": s.metadata.networked,
                "worktree": s.metadata.worktree,
                "model": s.metadata.model,
                "last_metadata_update": s.metadata.last_metadata_update,
                "stale": stale,
                "backend_session_id": s.metadata.backend_session_id,
                "backend": s.metadata.backend,
                "reminder": s.metadata.reminder,
                "prompt": s.metadata.prompt,
                "iteration": s.metadata.iteration,
                "iteration_log": s.metadata.iteration_log,
                "last_iteration_at": s.metadata.last_iteration_at,
                "workflow": s.metadata.workflow,
                "workflow_calls": s.metadata.workflow_calls,
                "workflow_max_calls": s.metadata.workflow_max_calls,
            })
        })
        .collect();
    drop(proto);

    let nodes_list: Vec<_> = nodes
        .values()
        .map(|p| {
            json!({
                "name": p.name,
                "daemon_id": p.daemon_id,
            })
        })
        .collect();

    let transports_list: Vec<_> = transports
        .values()
        .map(|t| {
            json!({
                "name": t.transport_name(),
                "ready": t.is_ready(),
                "endpoint_id": t.endpoint_id(),
            })
        })
        .collect();

    // Deprecated compat: "transport" = first transport name, "endpoint_id" = first endpoint
    let first_transport = transports.values().next();
    let compat_transport = first_transport.map(|t| t.transport_name());
    let compat_endpoint_id = first_transport.and_then(|t| t.endpoint_id());

    let assistant_panes: Vec<_> = state
        .cached_assistant_panes()
        .await
        .into_iter()
        .map(|p| json!({ "pane_id": p.pane_id, "session": p.session_name }))
        .collect();

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "daemon": state.config.name,
        "daemon_id": state.config.npub,
        "port": state.config.port,
        "transports": transports_list,
        "transport": compat_transport,
        "endpoint_id": compat_endpoint_id,
        "sessions": sessions_list,
        "nodes": nodes_list,
        "assistant_panes": assistant_panes,
    }))
}

#[derive(Debug, Deserialize, Default)]
pub struct TicketQuery {
    /// Relay URLs for nostr transport (?relay=url1&relay=url2 or comma-separated).
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    relay: Vec<String>,
}

/// Accept a single string or a sequence for query params.
///
/// `serde_urlencoded` (used by axum's `Query`) cannot deserialize repeated
/// query keys (`?relay=a&relay=b`) into `Vec<String>`. This deserializer
/// accepts a single string and wraps it in a vec instead of failing.
fn deserialize_string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrSeq;

    impl<'de> de::Visitor<'de> for StringOrSeq {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a string or sequence of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element()? {
                v.push(s);
            }
            Ok(v)
        }
    }

    deserializer.deserialize_any(StringOrSeq)
}

/// Generate a connect ticket for remote peer pairing.
pub async fn ticket(
    State(state): State<SharedState>,
    Query(query): Query<TicketQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let t = if !query.relay.is_empty() {
        match crate::nostr_transport::ensure_active(&state, query.relay).await {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("failed to start nostr transport: {e}");
                tracing::error!("{msg}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": msg })),
                );
            }
        }
    } else {
        let Some(t) = state.transport_by_name("nostr").await else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "nostr transport is not active" })),
            );
        };
        t
    };
    match t.ticket_string().await {
        Some(ticket) => (
            StatusCode::OK,
            Json(json!({
                "ticket": ticket,
                "endpoint_id": t.endpoint_id(),
                "transport": "nostr",
            })),
        ),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "nostr transport not ready" })),
        ),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct RegenerateQuery {
    confirm: Option<bool>,
}

/// Regenerate the connect secret and return a new ticket.
pub async fn regenerate_ticket(
    State(state): State<SharedState>,
    Query(query): Query<RegenerateQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(t) = state.transport_by_name("nostr").await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "nostr transport is not active" })),
        );
    };

    if query.confirm != Some(true) {
        return (
            StatusCode::OK,
            Json(json!({
                "warning": "This will destroy your nostr identity (nsec). All nodes must re-connect. Add ?confirm=true to proceed.",
                "transport": "nostr",
            })),
        );
    }

    match t
        .regenerate(&state.config.config_dir, &state.config.data_dir)
        .await
    {
        Ok(ticket) => (
            StatusCode::OK,
            Json(json!({ "ticket": ticket, "transport": "nostr" })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnectBody {
    ticket: String,
    name: Option<String>,
}

/// Initiate a Nostr connection to a remote peer via ticket.
pub async fn connect(
    State(state): State<SharedState>,
    Json(body): Json<ConnectBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Strip #secret suffix for validation — the nprofile is before the '#'
    let nprofile_part = body
        .ticket
        .split_once('#')
        .map_or(body.ticket.as_str(), |(left, _)| left);
    if !nprofile_part.starts_with("nprofile1") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "ticket must be an nprofile1 string" })),
        );
    }

    tracing::info!(
        "connect request received (ticket len={})",
        body.ticket.len()
    );

    // Check for duplicate connection by npub
    let peer_npub = extract_npub(&body.ticket);
    if let Some(ref npub) = peer_npub {
        let node_name = body
            .name
            .as_deref()
            .unwrap_or(&npub[..NPUB_DISPLAY_LEN.min(npub.len())]);
        if let Err(existing) = state.try_add_node(npub, node_name) {
            let msg = format!("already connected to this daemon as '{existing}'");
            tracing::info!("connect rejected: {msg}");
            return (StatusCode::CONFLICT, Json(json!({ "error": msg })));
        }
    }

    // Lazily activate nostr transport using relays from the nprofile
    let t = if let Some(t) = state.transport_by_name("nostr").await {
        t
    } else {
        let relays = extract_nprofile_relays(&body.ticket);
        match crate::nostr_transport::ensure_active(&state, relays).await {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("failed to start nostr transport: {e}");
                tracing::error!("{msg}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": msg })),
                );
            }
        }
    };

    let connect_fut = t.connect(&body.ticket, state.clone(), true);
    match tokio::time::timeout(
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        connect_fut,
    )
    .await
    {
        Err(_) => {
            tracing::warn!("connect timed out after 10s waiting for peer");
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({ "error": "connect timed out waiting for peer" })),
            );
        }
        Ok(Err(e)) => {
            tracing::error!("connect failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("connect failed: {e}") })),
            );
        }
        Ok(Ok(())) => {}
    }

    if let Err(e) = crate::persistence::add_connection(
        &state.config.data_dir,
        &body.ticket,
        body.name.as_deref(),
        peer_npub.as_deref(),
    ) {
        tracing::warn!("failed to persist connection: {e}");
    }

    // Don't broadcast sessions here — the remote peer may not have processed
    // our ConnectRequest yet, so it would reject the SessionList as unauthorized.
    // Session exchange happens naturally: once the peer authorizes us, it broadcasts
    // its sessions; we process them as a new peer and broadcast ours back.
    // The periodic 5s broadcast in the main loop also provides resilience.
    tracing::info!("node connected successfully via nostr");
    (
        StatusCode::OK,
        Json(json!({ "status": "connected", "transport": "nostr" })),
    )
}

/// Strip the `#secret` suffix from a ticket, returning just the nprofile.
fn strip_ticket_secret(ticket: &str) -> &str {
    ticket.split_once('#').map_or(ticket, |(left, _)| left)
}

/// Extract relay URLs from an nprofile bech32 string.
fn extract_nprofile_relays(ticket: &str) -> Vec<String> {
    use nostr_sdk::prelude::*;
    Nip19Profile::from_bech32(strip_ticket_secret(ticket))
        .map(|p| p.relays.into_iter().map(|r| r.to_string()).collect())
        .unwrap_or_default()
}

/// Extract the daemon npub from an nprofile ticket.
pub fn extract_npub(ticket: &str) -> Option<String> {
    use nostr_sdk::prelude::*;
    Nip19Profile::from_bech32(strip_ticket_secret(ticket))
        .ok()
        .and_then(|p| p.public_key.to_bech32().ok())
}

#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    id: String,
    pane: Option<String>,
    #[serde(default)]
    vim_mode: bool,
    project_dir: Option<String>,
    role: Option<String>,
    bulletin: Option<String>,
    /// Defaults to true if omitted.
    #[serde(default)]
    networked: Option<bool>,
    #[serde(alias = "claude_session_id")]
    backend_session_id: Option<String>,
    /// Which coding assistant backend to use (e.g. "claude-code", "codex").
    #[serde(default)]
    backend: Option<String>,
    /// Reminder text re-injected on idle.
    #[serde(default)]
    reminder: Option<String>,
    /// Path to a workflow executable.
    #[serde(default)]
    workflow: Option<String>,
    /// Maximum workflow calls allowed (daemon-enforced effort budget).
    #[serde(default)]
    workflow_max_calls: Option<u64>,
}

/// Register a new local session with optional metadata.
pub async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    if body.id.contains('/') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "session ID must not contain '/'" })),
        );
    }
    let project_description = body
        .project_dir
        .as_deref()
        .and_then(extract_project_description);
    let metadata = crate::state::SessionMetadata {
        vim_mode: body.vim_mode,
        project_dir: body.project_dir,
        role: body.role,
        bulletin: body.bulletin,
        networked: body.networked.unwrap_or(true),
        backend_session_id: body.backend_session_id,
        backend: body.backend,
        project_description,
        reminder: body.reminder,
        ..Default::default()
    };
    if let Some(ref p) = body.pane {
        let names = state.backends.all_process_names();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        if !crate::tmux::pane_alive(p, &refs) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("pane {p} does not exist") })),
            );
        }
    }
    let proto_meta = crate::daemon_protocol::SessionMeta {
        project_dir: metadata.project_dir.clone(),
        role: metadata.role.clone(),
        bulletin: metadata.bulletin.clone(),
        networked: metadata.networked,
        worktree: metadata.worktree,
        vim_mode: metadata.vim_mode,
        backend: metadata.backend.clone(),
        reminder: metadata.reminder.clone(),
        workflow: body.workflow,
        workflow_max_calls: body.workflow_max_calls.unwrap_or(0),
        ..Default::default()
    };
    let effects = state
        .apply_and_execute(crate::daemon_protocol::Event::Register {
            id: body.id.clone(),
            pane: body.pane.clone(),
            metadata: proto_meta,
        })
        .await;
    let (session_id, _replaced) = match effects.iter().find_map(|e| match e {
        crate::daemon_protocol::Effect::RegisterOk {
            session_id,
            replaced,
        } => Some((session_id.clone(), replaced.clone())),
        _ => None,
    }) {
        Some(ok) => ok,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "unexpected register result" })),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "registered": session_id,
            "pane": body.pane,
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct SendBody {
    from: String,
    to: String,
    message: String,
    #[serde(default)]
    expects_reply: bool,
    #[serde(default)]
    responds_to: Option<u64>,
    #[serde(default)]
    done: bool,
}

/// Send a message from one session to another.
pub async fn send_msg(
    State(state): State<SharedState>,
    Json(body): Json<SendBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    if body.from == body.to {
        let suffix = format!("/{}", body.to);
        let prefix = format!("{}/", body.to);
        let proto = state.protocol.read().await;
        let suggestions: Vec<&str> = proto
            .sessions
            .keys()
            .filter(|k| k.ends_with(&suffix) || k.starts_with(&prefix))
            .map(|k| k.as_str())
            .collect();
        let hint = if suggestions.is_empty() {
            "If you meant a remote session, use the full node-prefixed name (e.g. 'node/session'). GET /api/status to see all available targets.".to_string()
        } else {
            format!(
                "Did you mean one of these remote sessions? {} — GET /api/status to check.",
                suggestions.join(", ")
            )
        };
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("cannot send a message to yourself. {hint}") })),
        );
    }
    let effects = state
        .apply_and_execute(crate::daemon_protocol::Event::Send {
            from: body.from,
            to: body.to,
            message: body.message,
            expects_reply: body.expects_reply,
            responds_to: body.responds_to,
            done: body.done,
        })
        .await;

    if let Some((method, msg_id)) = effects.iter().find_map(|e| match e {
        crate::daemon_protocol::Effect::SendDelivered { method, msg_id, .. } => {
            Some((method.clone(), *msg_id))
        }
        _ => None,
    }) {
        (
            StatusCode::OK,
            Json(json!({
                "status": "delivered",
                "method": method,
                "msg_id": msg_id,
                "hint": format!("To reply to this message, use responds_to={msg_id}")
            })),
        )
    } else if let Some((reason, renamed_to)) = effects.iter().find_map(|e| match e {
        crate::daemon_protocol::Effect::SendFailed {
            reason, renamed_to, ..
        } => Some((reason.clone(), renamed_to.clone())),
        _ => None,
    }) {
        let mut body = json!({ "error": reason });
        if let Some(new_id) = renamed_to {
            body["renamed_to"] = json!(new_id);
        }
        (StatusCode::NOT_FOUND, Json(body))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "unexpected send result" })),
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct RenameBody {
    old_id: String,
    new_id: String,
}

/// Rename an existing session.
pub async fn rename(
    State(state): State<SharedState>,
    Json(body): Json<RenameBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let effects = state
        .apply_and_execute(crate::daemon_protocol::Event::Rename {
            old_id: body.old_id.clone(),
            new_id: body.new_id.clone(),
        })
        .await;
    if effects
        .iter()
        .any(|e| matches!(e, crate::daemon_protocol::Effect::RenameOk { .. }))
    {
        (
            StatusCode::OK,
            Json(json!({ "renamed": body.old_id, "to": body.new_id })),
        )
    } else {
        let reason = effects
            .iter()
            .find_map(|e| match e {
                crate::daemon_protocol::Effect::RenameFailed { reason } => Some(reason.clone()),
                _ => None,
            })
            .unwrap_or_else(|| format!("session '{}' not found", body.old_id));
        (StatusCode::NOT_FOUND, Json(json!({ "error": reason })))
    }
}

#[derive(Debug, Deserialize)]
pub struct RemoveBody {
    id: String,
}

/// Unregister a session by ID.
pub async fn remove(
    State(state): State<SharedState>,
    Json(body): Json<RemoveBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let effects = state
        .apply_and_execute(crate::daemon_protocol::Event::Remove {
            id: body.id.clone(),
            keep_worktree: false,
        })
        .await;
    if effects
        .iter()
        .any(|e| matches!(e, crate::daemon_protocol::Effect::RemoveOk { .. }))
    {
        (StatusCode::OK, Json(json!({ "removed": body.id })))
    } else {
        let reason = effects
            .iter()
            .find_map(|e| match e {
                crate::daemon_protocol::Effect::RemoveFailed { reason } => Some(reason.clone()),
                _ => None,
            })
            .unwrap_or_else(|| format!("session '{}' not found", body.id));
        (StatusCode::NOT_FOUND, Json(json!({ "error": reason })))
    }
}

#[derive(Debug, Deserialize)]
pub struct SessionUpdateBody {
    id: String,
    networked: Option<bool>,
    role: Option<String>,
    project_dir: Option<String>,
    bulletin: Option<String>,
}

/// Update a session's metadata (role, bulletin, project_dir, etc.).
pub async fn update_session(
    State(state): State<SharedState>,
    Json(body): Json<SessionUpdateBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate session exists and is not remote
    {
        let proto = state.protocol.read().await;
        let Some(session) = proto.sessions.get(&body.id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("session '{}' not found", body.id) })),
            );
        };
        if matches!(session.origin, crate::daemon_protocol::Origin::Remote(_)) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "cannot update remote session" })),
            );
        }
    }

    state
        .apply_and_execute(crate::daemon_protocol::Event::UpdateMetadata {
            id: body.id.clone(),
            role: body.role,
            bulletin: body.bulletin,
            project_dir: body.project_dir,
            networked: body.networked,
        })
        .await;

    let proto = state.protocol.read().await;
    let response = if let Some(s) = proto.sessions.get(&body.id) {
        json!({
            "updated": s.id,
            "networked": s.metadata.networked,
            "role": s.metadata.role,
            "bulletin": s.metadata.bulletin,
            "project_dir": s.metadata.project_dir,
        })
    } else {
        json!({ "updated": body.id })
    };

    (StatusCode::OK, Json(response))
}

#[derive(Debug, Deserialize)]
pub struct InjectBody {
    pane: String,
    message: String,
    #[serde(default)]
    vim_mode: bool,
}

/// Inject text into a tmux pane via the queued writer.
pub async fn inject(
    State(state): State<SharedState>,
    Json(body): Json<InjectBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let session_id = {
        let proto = state.protocol.read().await;
        match proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(&body.pane))
            .map(|s| s.id.clone())
        {
            Some(id) => id,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "no session registered for this pane"})),
                );
            }
        }
    };
    match tmux::locked_inject(
        &state,
        &session_id,
        &body.pane,
        &body.message,
        body.vim_mode,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "injected" }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

// --- Nodes ---

/// List connected remote nodes with their sessions.
pub async fn nodes(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let connected = state.nodes.read().await;

    // Self entry first
    let self_entry = json!({
        "name": state.config.name,
        "npub": state.config.npub,
        "status": "self",
        "transport": null,
        "since": null,
    });

    let mut entries: Vec<serde_json::Value> = vec![self_entry];

    for p in connected.values() {
        entries.push(json!({
            "name": p.name,
            "npub": p.daemon_id,
            "status": "connected",
            "transport": null,
            "since": p.connected_at.format("%H:%M:%S").to_string(),
        }));
    }

    // Add saved (persisted) connections that aren't currently connected
    let connected_names: std::collections::HashSet<&str> =
        connected.values().map(|p| p.name.as_str()).collect();

    if let Ok(conns) = crate::persistence::load_connections(&state.config.data_dir) {
        for conn in &conns {
            if let Some(name) = &conn.node_name
                && connected_names.contains(name.as_str())
            {
                continue;
            }
            entries.push(json!({
                "name": conn.node_name,
                "npub": conn.daemon_npub,
                "status": "saved",
                "transport": "nostr",
                "since": conn.connected_at.format("%Y-%m-%d").to_string(),
            }));
        }
    }

    Json(json!({ "nodes": entries }))
}

#[derive(Debug, Deserialize)]
pub struct DisconnectNodeBody {
    daemon_id: String,
}

/// Disconnect a remote node and remove its sessions.
pub async fn disconnect_node(
    State(state): State<SharedState>,
    Json(body): Json<DisconnectNodeBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let removed = state.disconnect_node(&body.daemon_id).await;
    (
        StatusCode::OK,
        Json(json!({
            "disconnected": body.daemon_id,
            "sessions_removed": removed,
        })),
    )
}

// --- Settings ---

/// Return the current daemon settings.
pub async fn get_settings(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let settings = state.settings.read().await;
    Json(json!({
        "auto_register": settings.auto_register,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SettingsUpdateBody {
    auto_register: Option<bool>,
    projects_dir: Option<String>,
    idle_timeout_secs: Option<u64>,
    reaper_interval_secs: Option<u64>,
    max_local_sessions: Option<u64>,
}

/// Patch daemon settings and persist to disk.
pub async fn update_settings(
    State(state): State<SharedState>,
    Json(body): Json<SettingsUpdateBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut settings = state.settings.write().await;
    if let Some(v) = body.auto_register {
        settings.auto_register = v;
    }
    let projects_dir_changed = body.projects_dir.is_some();
    if let Some(v) = body.projects_dir {
        settings.projects_dir = Some(v);
    }
    if let Some(v) = body.idle_timeout_secs {
        settings.idle_timeout_secs = v;
    }
    if let Some(v) = body.reaper_interval_secs {
        settings.reaper_interval_secs = v;
    }
    if let Some(v) = body.max_local_sessions {
        settings.max_local_sessions = v;
    }
    if let Err(e) = crate::persistence::save_settings(&state.config.config_dir, &settings) {
        tracing::warn!("failed to save settings: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to save: {e}") })),
        );
    }
    // Drop the write lock before spawning the refresh
    drop(settings);
    // Rebuild project index when projects_dir changes
    if projects_dir_changed {
        let s = state.clone();
        tokio::spawn(async move {
            crate::project_index::refresh_index(&s).await;
        });
    }
    let settings = state.settings.read().await;
    (
        StatusCode::OK,
        Json(json!({
            "status": "saved",
            "settings": {
                "auto_register": settings.auto_register,
                "projects_dir": settings.projects_dir,
            }
        })),
    )
}

/// Bulk-set `networked` on all local sessions.
pub async fn bulk_update_sessions(
    State(state): State<SharedState>,
    Json(body): Json<BulkSessionUpdateBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut count = 0;
    {
        let mut proto = state.protocol.write().await;
        for session in proto.sessions.values_mut() {
            if matches!(session.origin, crate::daemon_protocol::Origin::Local) {
                if let Some(v) = body.networked {
                    if session.metadata.networked != v {
                        session.metadata.networked = v;
                        count += 1;
                    }
                }
            }
        }
    }
    if count > 0 {
        transport::broadcast_local_sessions(&state).await;
    }
    (StatusCode::OK, Json(json!({ "updated": count })))
}

#[derive(Debug, Deserialize)]
pub struct BulkSessionUpdateBody {
    networked: Option<bool>,
}

/// Return the list of configured Nostr relay URLs.
pub async fn get_relays(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let relays = crate::nostr_transport::load_relays(&state.config.data_dir);
    Json(json!({ "relays": relays }))
}

#[derive(Debug, Deserialize)]
pub struct RelaysUpdateBody {
    relays: Vec<String>,
}

/// Replace the Nostr relay list and persist to disk.
pub async fn update_relays(
    State(state): State<SharedState>,
    Json(body): Json<RelaysUpdateBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate relay URLs
    let relays: Vec<String> = body
        .relays
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    if let Err(e) = crate::nostr_transport::save_relays(&state.config.data_dir, &relays) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to save: {e}") })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "status": "saved", "relays": relays })),
    )
}

// --- Scheduled Tasks ---

/// List all scheduled tasks sorted by creation time.
pub async fn list_tasks(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let tasks = state.scheduled_tasks.read().await;
    let mut list: Vec<&scheduler::ScheduledTask> = tasks.values().collect();
    list.sort_by_key(|t| &t.created_at);
    let entries: Vec<serde_json::Value> = list
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "cron": t.cron,
                "target_session": t.target_session,
                "enabled": t.enabled,
                "next_run": t.next_run,
                "last_run": t.last_run,
                "last_status": t.last_status,
                "run_count": t.run_count,
                "project_dir": t.project_dir,
                "once": t.once,
                "backend_session_id": t.backend_session_id,
                "on_fire": t.on_fire,
            })
        })
        .collect();
    Json(json!({ "tasks": entries }))
}

#[derive(Debug, Deserialize)]
pub struct CreateTaskBody {
    name: String,
    cron: String,
    target_session: Option<String>,
    prompt: Option<String>,
    reminder: Option<String>,
    project_dir: Option<String>,
    #[serde(default)]
    once: Option<bool>,
    #[serde(alias = "claude_session_id")]
    backend_session_id: Option<String>,
    #[serde(default)]
    on_fire: Option<crate::scheduler::OnFire>,
}

/// Create a new scheduled task with a cron expression.
pub async fn create_task(
    State(state): State<SharedState>,
    Json(body): Json<CreateTaskBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = scheduler::validate_cron(&body.cron) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid cron: {e}") })),
        );
    }

    let mut task = scheduler::new_task(
        body.name,
        body.cron,
        body.target_session,
        body.prompt,
        body.reminder,
        body.once.unwrap_or(false),
        body.backend_session_id,
        body.on_fire.unwrap_or_default(),
    );
    task.project_dir = body.project_dir;

    let id = task.id.clone();
    state.add_task(task).await;

    (StatusCode::OK, Json(json!({ "created": id })))
}

#[derive(Debug, Deserialize)]
pub struct TaskIdBody {
    id: String,
}

/// Delete a scheduled task by ID.
pub async fn delete_task(
    State(state): State<SharedState>,
    Json(body): Json<TaskIdBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.remove_task(&body.id).await {
        Some(_) => (StatusCode::OK, Json(json!({ "deleted": body.id }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("task '{}' not found", body.id) })),
        ),
    }
}

/// Enable a disabled scheduled task.
pub async fn enable_task(
    State(state): State<SharedState>,
    Json(body): Json<TaskIdBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tasks = state.scheduled_tasks.read().await;
    if !tasks.contains_key(&body.id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("task '{}' not found", body.id) })),
        );
    }
    drop(tasks);
    state
        .update_task(&body.id, |t| {
            t.enabled = true;
            t.next_run = scheduler::compute_next_run(&t.cron);
        })
        .await;
    (StatusCode::OK, Json(json!({ "enabled": body.id })))
}

/// Disable a scheduled task without deleting it.
pub async fn disable_task(
    State(state): State<SharedState>,
    Json(body): Json<TaskIdBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tasks = state.scheduled_tasks.read().await;
    if !tasks.contains_key(&body.id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("task '{}' not found", body.id) })),
        );
    }
    drop(tasks);
    state
        .update_task(&body.id, |t| {
            t.enabled = false;
            t.next_run = None;
        })
        .await;
    (StatusCode::OK, Json(json!({ "disabled": body.id })))
}

/// Immediately fire a scheduled task, ignoring its cron schedule.
pub async fn trigger_task(
    State(state): State<SharedState>,
    Json(body): Json<TaskIdBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    {
        let tasks = state.scheduled_tasks.read().await;
        if !tasks.contains_key(&body.id) {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("task '{}' not found", body.id) })),
            );
        }
    }
    scheduler::execute_task(&state, &body.id).await;
    (StatusCode::OK, Json(json!({ "triggered": body.id })))
}

#[derive(Debug, Deserialize, Default)]
pub struct TaskRunsQuery {
    task: Option<String>,
}

/// Return recent task execution history, newest first.
pub async fn list_task_runs(
    State(state): State<SharedState>,
    Query(query): Query<TaskRunsQuery>,
) -> Json<serde_json::Value> {
    let runs = state.task_runs.read().await;
    let entries: Vec<serde_json::Value> = runs
        .iter()
        .rev()
        .filter(|r| query.task.as_ref().is_none_or(|id| r.task_id == *id))
        .take(MAX_TASK_RUNS_RETURNED)
        .map(|r| {
            json!({
                "task_id": r.task_id,
                "task_name": r.task_name,
                "timestamp": r.timestamp,
                "status": r.status,
                "error": r.error,
                "session_name": r.session_name,
                "revived_pane": r.revived_pane,
            })
        })
        .collect();
    Json(json!({ "runs": entries }))
}

// --- Human sessions ---

#[derive(Debug, Deserialize)]
pub struct AddHumanBody {
    pub npub: String,
    pub name: String,
    pub default_session: Option<String>,
}

/// Add or update a human Nostr session configuration.
pub async fn add_human(
    State(state): State<SharedState>,
    Json(body): Json<AddHumanBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.contains('/') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid name" })),
        );
    }

    // Reject if name conflicts with an existing non-human session
    {
        let proto = state.protocol.read().await;
        if proto
            .sessions
            .get(&name)
            .is_some_and(|s| !matches!(s.origin, crate::daemon_protocol::Origin::Human(_)))
        {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "name conflicts with existing session" })),
            );
        }
    }

    let mut settings = state.settings.write().await;
    if settings.human_sessions.iter().any(|h| h.name == name) {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "human session already exists" })),
        );
    }

    let human = crate::persistence::HumanSession {
        npub: body.npub.clone(),
        name: name.clone(),
        default_session: body.default_session,
        welcomed: false,
    };
    settings.human_sessions.push(human);

    if let Err(e) = crate::persistence::save_settings(&state.config.config_dir, &settings) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to save: {e}") })),
        );
    }
    drop(settings);

    // Register the human session in protocol state
    {
        let mut proto = state.protocol.write().await;
        proto.sessions.entry(name.clone()).or_insert_with(|| {
            crate::daemon_protocol::SessionEntry {
                id: name.clone(),
                pane: None,
                origin: crate::daemon_protocol::Origin::Human(body.npub.clone()),
                metadata: crate::daemon_protocol::SessionMeta {
                    role: Some("human".to_string()),
                    networked: false,
                    ..Default::default()
                },
                ..Default::default()
            }
        });
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "added", "name": name })),
    )
}

#[derive(Debug, Deserialize)]
pub struct RemoveHumanBody {
    pub name: String,
}

/// Remove a human session configuration by name.
pub async fn remove_human(
    State(state): State<SharedState>,
    Json(body): Json<RemoveHumanBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut settings = state.settings.write().await;
    let before = settings.human_sessions.len();
    settings.human_sessions.retain(|h| h.name != body.name);
    if settings.human_sessions.len() == before {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })));
    }

    if let Err(e) = crate::persistence::save_settings(&state.config.config_dir, &settings) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to save: {e}") })),
        );
    }
    drop(settings);

    // Remove the session from protocol state
    {
        let mut proto = state.protocol.write().await;
        if proto
            .sessions
            .get(&body.name)
            .is_some_and(|s| matches!(s.origin, crate::daemon_protocol::Origin::Human(_)))
        {
            proto.sessions.remove(&body.name);
        }
    }

    (StatusCode::OK, Json(json!({ "status": "removed" })))
}

/// List configured human Nostr sessions.
pub async fn list_humans(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let settings = state.settings.read().await;
    let humans: Vec<serde_json::Value> = settings
        .human_sessions
        .iter()
        .map(|h| {
            json!({
                "name": h.name,
                "npub": h.npub,
                "default_session": h.default_session,
            })
        })
        .collect();
    Json(json!({ "humans": humans }))
}

// --- Session lifecycle ---

#[derive(Debug, Deserialize)]
pub struct SessionNameBody {
    name: String,
    #[serde(default)]
    fresh: Option<bool>,
    #[serde(default)]
    worktree: Option<bool>,
    #[serde(default)]
    project_dir: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    expects_reply: Option<bool>,
    /// Which coding assistant backend to use (e.g. "claude-code", "codex").
    #[serde(default)]
    backend: Option<String>,
    /// Which LLM model to use (informational metadata only).
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    reminder: Option<String>,
    /// Path to a workflow executable.
    #[serde(default)]
    workflow: Option<String>,
    /// JSON params passed to the workflow on registration. Consumed at start, not persisted.
    #[serde(default)]
    workflow_params: Option<serde_json::Value>,
}

/// Kill the coding assistant process in a session's tmux pane.
pub async fn kill_session(
    State(state): State<SharedState>,
    Json(body): Json<SessionNameBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = crate::nostr_transport::kill_session(&state, &body.name).await;
    (StatusCode::OK, Json(json!({ "result": result })))
}

/// Start a new session in a tmux pane, optionally in a worktree.
pub async fn start_session(
    State(state): State<SharedState>,
    Json(body): Json<SessionNameBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Return 202 immediately — all work (registration + boot) happens in background.
    let name = body.name.clone();
    let state2 = state.clone();
    tokio::spawn(async move {
        // Workflow registration (if configured) — must run before exists check
        // because restart also needs the registered prompt/reminder.
        let mut prompt = body.prompt;
        let mut reminder = body.reminder;
        let mut workflow_for_meta = None;
        if let Some(ref wf) = body.workflow {
            match crate::workflow::register_workflow(
                &state2,
                wf,
                &body.name,
                body.workflow_params.as_ref(),
                body.project_dir.as_deref(),
            )
            .await
            {
                Ok(reg) => {
                    let max_calls = reg.max_calls.unwrap_or(0);
                    prompt = Some(match prompt.take() {
                        Some(user_prompt) => format!("{}\n\n{user_prompt}", reg.instructions),
                        None => reg.instructions,
                    });
                    if reminder.is_none() {
                        reminder = reg.inject_on_start;
                    }
                    workflow_for_meta = Some((wf.clone(), max_calls));
                }
                Err(e) => {
                    tracing::warn!("async workflow registration failed for {}: {e}", body.name);
                    return;
                }
            }
        }

        // If session already exists, restart with fresh context instead of failing.
        // Handles re-spawn: reviewer requests changes → workflow spawns worker with same name.
        let exists = state2.protocol.read().await.sessions.contains_key(&body.name);
        if exists {
            tracing::info!("session '{}' exists, restarting with fresh context", body.name);
            let (_result, _msg_id) = crate::nostr_transport::restart_session(
                &state2,
                &body.name,
                true, // fresh
                prompt.as_deref(),
                body.from.as_deref(),
                body.expects_reply,
                body.backend.as_deref(),
                body.model.as_deref(),
                reminder.as_deref(),
            )
            .await;

            // Stamp workflow metadata and reset call counter for new round
            if let Some((wf_path, max_calls)) = workflow_for_meta {
                let mut proto = state2.protocol.write().await;
                if let Some(session) = proto.sessions.get_mut(&body.name) {
                    session.metadata.workflow = Some(wf_path);
                    session.metadata.workflow_max_calls = max_calls;
                    session.metadata.workflow_calls = 0;
                }
                state2.persist_protocol_state(&proto);
            }

            tracing::info!("async session restart complete: {}", body.name);
            return;
        }

        let (result, _prompt_msg_id) = crate::nostr_transport::start_session(
            &state2,
            &body.name,
            body.worktree,
            body.project_dir.as_deref(),
            prompt.as_deref(),
            body.from.as_deref(),
            body.expects_reply,
            body.backend.as_deref(),
            body.model.as_deref(),
            reminder.as_deref(),
        )
        .await;

        // Stamp workflow metadata after session is registered.
        // Also re-stamp after a delay to handle the startup hook race
        // (hook may re-register with blank metadata, wiping workflow).
        if let Some((wf_path, max_calls)) = workflow_for_meta {
            let stamp = |state: &std::sync::Arc<crate::state::AppState>,
                         name: &str,
                         wf: &str,
                         mc: u64| {
                let state = state.clone();
                let name = name.to_string();
                let wf = wf.to_string();
                async move {
                    let mut proto = state.protocol.write().await;
                    if let Some(session) = proto.sessions.get_mut(&name) {
                        session.metadata.workflow = Some(wf);
                        session.metadata.workflow_max_calls = mc;
                    }
                    state.persist_protocol_state(&proto);
                }
            };
            // Stamp now
            stamp(&state2, &body.name, &wf_path, max_calls).await;
            // No re-stamp needed: apply_register's inherit_recurrence_from
            // preserves workflow/prompt/reminder even if the hook re-registers
            // with blank metadata.
        }

        tracing::info!("async session start complete: {}, result: {result}", body.name);
    });

    (StatusCode::ACCEPTED, Json(json!({ "session": name, "status": "starting" })))
}

/// Kill and restart a session, optionally with a fresh conversation.
pub async fn restart_session(
    State(state): State<SharedState>,
    Json(body): Json<SessionNameBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Snapshot metadata before restart (hook re-registration may wipe fields)
    let meta_snapshot = {
        let proto = state.protocol.read().await;
        proto.sessions.get(&body.name).map(|s| {
            (
                s.metadata.workflow.clone(),
                s.metadata.workflow_max_calls,
                s.metadata.prompt.clone(),
                s.metadata.reminder.clone(),
            )
        })
    };

    let fresh = body.fresh.unwrap_or(false);
    let (result, _prompt_msg_id) = crate::nostr_transport::restart_session(
        &state,
        &body.name,
        fresh,
        body.prompt.as_deref(),
        body.from.as_deref(),
        body.expects_reply,
        body.backend.as_deref(),
        body.model.as_deref(),
        body.reminder.as_deref(),
    )
    .await;

    // No re-stamp needed: apply_register's inherit_recurrence_from preserves
    // workflow/prompt/reminder even if the hook re-registers with blank metadata.
    let _ = meta_snapshot;

    (StatusCode::OK, Json(json!({ "result": result })))
}

/// Check if interactive mode is currently blocked.
pub async fn get_block_interactive(
    State(_state): State<SharedState>,
    axum::extract::Path(_pane): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    // block_interactive is no longer tracked in protocol state
    Json(json!({ "block_interactive": false }))
}

/// Clear the interactive block flag (no-op, kept for compat).
pub async fn clear_block_interactive(
    State(_state): State<SharedState>,
    axum::extract::Path(_pane): axum::extract::Path<String>,
) -> StatusCode {
    // block_interactive is no longer tracked in protocol state
    StatusCode::OK
}

/// Return pending reply entries for a session identified by pane.
pub async fn get_pending_replies(
    State(state): State<SharedState>,
    axum::extract::Path(pane): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let pane_id = format!("%{pane}");
    let session_id = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(&pane_id))
            .map(|s| s.id.clone())
    };
    let replies = if let Some(id) = session_id {
        state.query_agent_pending_replies(&id).await
    } else {
        Vec::new()
    };
    let list: Vec<_> = replies
        .iter()
        .map(|r| json!({ "msg_id": r.msg_id, "from": r.from, "message": r.message, "received_at": r.received_at }))
        .collect();
    Json(json!({ "pending_replies": list, "count": list.len() }))
}

/// Clear a pending reply from a specific sender on a pane's session.
pub async fn delete_pending_reply(
    State(state): State<SharedState>,
    axum::extract::Path((pane, from)): axum::extract::Path<(String, String)>,
) -> StatusCode {
    let pane_id = format!("%{pane}");
    let session_id = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(&pane_id))
            .map(|s| s.id.clone())
    };
    if let Some(id) = session_id {
        let mut proto = state.protocol.write().await;
        proto.clear_pending_reply_from(&id, &from);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Notify the session agent that the coding assistant has stopped in a pane.
pub async fn session_stopped(
    State(state): State<SharedState>,
    axum::extract::Path(pane): axum::extract::Path<String>,
) -> StatusCode {
    let pane_id = format!("%{pane}");
    let session_id = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(&pane_id))
            .map(|s| s.id.clone())
    };
    if let Some(id) = session_id {
        state
            .notify_agent(&id, crate::session_agent::SessionMsg::Stopped)
            .await;
    }
    StatusCode::OK
}

/// Notify the session agent that the coding assistant is active in a pane.
pub async fn session_active(
    State(state): State<SharedState>,
    axum::extract::Path(pane): axum::extract::Path<String>,
) -> StatusCode {
    let pane_id = format!("%{pane}");
    let session_id = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.pane.as_deref() == Some(&pane_id))
            .map(|s| s.id.clone())
    };
    if let Some(id) = session_id {
        state
            .notify_agent(&id, crate::session_agent::SessionMsg::Active)
            .await;
    }
    StatusCode::OK
}

/// Deliver a pending prompt for the given session, if one is queued.
fn deliver_pending_prompt(state: &SharedState, session_name: &str) -> bool {
    let pending = state.pending_prompts.lock().unwrap().remove(session_name);
    let Some((pane_id, prompt)) = pending else {
        return false;
    };
    let state = state.clone();
    let sid = session_name.to_string();
    tokio::spawn(async move {
        if let Err(e) = crate::tmux::locked_inject(&state, &sid, &pane_id, &prompt, false).await {
            tracing::warn!("readiness prompt delivery failed for {sid}: {e}");
        } else {
            tracing::info!("delivered queued prompt to {sid} via readiness signal");
        }
    });
    true
}

/// Handle a readiness signal from an HttpApi session's plugin.
pub async fn session_ready(
    State(state): State<SharedState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let delivered = deliver_pending_prompt(&state, &session_id);
    Json(json!({"delivered": delivered}))
}

/// Handle a readiness signal keyed by opencode backend session ID.
/// Resolves the ouija session name internally, avoiding plugin-side race conditions.
pub async fn backend_session_ready(
    State(state): State<SharedState>,
    axum::extract::Path(backend_sid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let session_name = {
        let proto = state.protocol.read().await;
        proto
            .sessions
            .values()
            .find(|s| s.metadata.backend_session_id.as_deref() == Some(&backend_sid))
            .map(|s| s.id.clone())
    };
    let Some(name) = session_name else {
        return Json(
            json!({"delivered": false, "error": "no session with this backend_session_id"}),
        );
    };
    let delivered = deliver_pending_prompt(&state, &name);
    Json(json!({"delivered": delivered, "session": name}))
}

/// Request body for the workflow REST endpoint.
#[derive(Debug, Deserialize)]
pub struct WorkflowCallBody {
    action: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

/// Call a session's workflow actor via REST.
pub async fn call_session_workflow(
    State(state): State<SharedState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    Json(body): Json<WorkflowCallBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let (workflow_path, project_dir) = {
        let mut proto = state.protocol.write().await;
        match proto.sessions.get_mut(&session_id) {
            Some(s) => {
                // Enforce effort budget
                if s.metadata.workflow_max_calls > 0
                    && s.metadata.workflow_calls >= s.metadata.workflow_max_calls
                {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({
                            "error": format!(
                                "workflow call budget exhausted ({} of {} calls used)",
                                s.metadata.workflow_calls, s.metadata.workflow_max_calls
                            )
                        })),
                    );
                }
                s.metadata.workflow_calls += 1;
                let result = (
                    s.metadata.workflow.clone(),
                    s.metadata.project_dir.clone(),
                );
                state.persist_protocol_state(&proto);
                result
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": format!("session '{}' not found", session_id)})),
                );
            }
        }
    };

    let Some(workflow_path) = workflow_path else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session has no workflow configured"})),
        );
    };

    match crate::workflow::call_workflow(
        &state,
        &workflow_path,
        &session_id,
        &body.action,
        body.params.as_ref(),
        project_dir.as_deref(),
    )
    .await
    {
        Ok(message) => (StatusCode::OK, Json(json!({"message": message}))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("workflow error: {e}")})),
        ),
    }
}

/// List indexed projects from the configured projects directory.
pub async fn list_projects(
    State(state): State<SharedState>,
) -> axum::Json<Vec<crate::project_index::ProjectInfo>> {
    let index = state.project_index.read().await;
    let mut projects: Vec<_> = index.values().cloned().collect();
    projects.sort_by(|a, b| a.name.cmp(&b.name));
    axum::Json(projects)
}

// ── Clear reminder (REST equivalent of removed MCP tool) ─────────────

#[derive(Deserialize)]
pub struct ClearReminderBody {
    pub from: String,
    pub clearing_id: u64,
}

pub async fn clear_reminder(
    State(state): State<SharedState>,
    Json(body): Json<ClearReminderBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    state
        .notify_agent(
            &body.from,
            crate::session_agent::SessionMsg::ClearReminder {
                clearing_id: body.clearing_id,
            },
        )
        .await;
    (
        StatusCode::OK,
        Json(json!({
            "cleared": body.clearing_id,
            "session": body.from,
            "hint": "Reminder paused. It will resume after new activity (incoming message, hook fire, etc.)."
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"foo\"\ndescription = \"A test crate\"\n",
        )
        .unwrap();
        let desc = extract_project_description(dir.path().to_str().unwrap());
        assert_eq!(desc.as_deref(), Some("A test crate"));
    }

    #[test]
    fn extract_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"foo","description":"A JS project"}"#,
        )
        .unwrap();
        let desc = extract_project_description(dir.path().to_str().unwrap());
        assert_eq!(desc.as_deref(), Some("A JS project"));
    }

    #[test]
    fn extract_from_readme() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# My Project\n\nThis is a great project.\n",
        )
        .unwrap();
        let desc = extract_project_description(dir.path().to_str().unwrap());
        assert_eq!(desc.as_deref(), Some("This is a great project."));
    }

    #[test]
    fn extract_cargo_toml_preferred_over_readme() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\ndescription = \"From cargo\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "# Title\n\nFrom readme\n").unwrap();
        let desc = extract_project_description(dir.path().to_str().unwrap());
        assert_eq!(desc.as_deref(), Some("From cargo"));
    }

    #[test]
    fn extract_missing_files_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(extract_project_description(dir.path().to_str().unwrap()).is_none());
    }
}
