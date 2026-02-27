use axum::Router;
use axum::routing::{delete, get, post};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio::net::TcpListener;

use crate::mcp::OuijaMcp;
use crate::state::SharedState;
use crate::{admin, api, hooks};

/// Start the HTTP/MCP server on the configured port.
pub async fn run(state: SharedState) -> anyhow::Result<()> {
    let port = state.config.port;
    let name = state.config.name.clone();

    let mcp_state = state.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(OuijaMcp::new(mcp_state.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig {
            stateful_mode: false,
            ..Default::default()
        },
    );

    let app = Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/", get(admin::dashboard))
        .route("/admin", get(admin::dashboard))
        .route("/api/status", get(api::status))
        .route("/api/ticket", get(api::ticket))
        .route("/api/register", post(api::register))
        .route("/api/send", post(api::send_msg))
        .route("/api/inject", post(api::inject))
        .route("/api/rename", post(api::rename))
        .route("/api/remove", post(api::remove))
        .route("/api/sessions/update", post(api::update_session))
        .route("/api/sessions/bulk-update", post(api::bulk_update_sessions))
        .route("/api/connect", post(api::connect))
        .route("/api/nodes", get(api::nodes))
        .route("/api/nodes/disconnect", post(api::disconnect_node))
        .route("/api/regenerate-ticket", post(api::regenerate_ticket))
        .route(
            "/api/settings",
            get(api::get_settings).post(api::update_settings),
        )
        .route("/api/relays", get(api::get_relays).post(api::update_relays))
        .route(
            "/api/tasks",
            get(api::list_tasks)
                .post(api::create_task)
                .delete(api::delete_task),
        )
        .route("/api/tasks/enable", post(api::enable_task))
        .route("/api/tasks/disable", post(api::disable_task))
        .route("/api/tasks/trigger", post(api::trigger_task))
        .route("/api/task-runs", get(api::list_task_runs))
        .route(
            "/api/humans",
            get(api::list_humans)
                .post(api::add_human)
                .delete(api::remove_human),
        )
        .route("/api/sessions/{name}", get(api::get_session))
        .route("/api/sessions/{session_id}/workflow", post(api::call_session_workflow))
        .route("/api/sessions/kill", post(api::kill_session))
        .route("/api/sessions/start", post(api::start_session))
        .route("/api/sessions/restart", post(api::restart_session))
        .route(
            "/api/pane/{pane}/block-interactive",
            get(api::get_block_interactive).delete(api::clear_block_interactive),
        )
        .route(
            "/api/pane/{pane}/pending-replies",
            get(api::get_pending_replies),
        )
        .route(
            "/api/pane/{pane}/pending-replies/{from}",
            delete(api::delete_pending_reply),
        )
        .route("/api/pane/{pane}/stopped", post(api::session_stopped))
        .route("/api/pane/{pane}/active", post(api::session_active))
        .route("/api/session/{id}/ready", post(api::session_ready))
        .route(
            "/api/backend-session/{id}/ready",
            post(api::backend_session_ready),
        )
        .route("/api/projects", get(api::list_projects))
        .route("/api/hooks/session-start", post(hooks::session_start))
        .route("/api/hooks/session-end", post(hooks::session_end))
        .route("/api/hooks/stop", post(hooks::hook_stop))
        .route("/api/hooks/prompt-submit", post(hooks::prompt_submit))
        .route("/api/hooks/pre-tool-use", post(hooks::pre_tool_use))
        .with_state(state);

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    println!("ouija daemon '{name}' listening on http://localhost:{port}");
    tracing::info!("ouija daemon '{name}' listening on {addr}");
    tracing::info!("  MCP: http://localhost:{port}/mcp");
    axum::serve(listener, app).await?;

    Ok(())
}
