use std::path::Path;
use std::sync::Arc;

use crate::protocol::WireMessage;
use crate::state::AppState;

/// P2P transport abstraction.
///
/// Implementations handle connection setup, message broadcasting, and
/// receiving. The receive side is an implementation detail: the transport
/// spawns its own receive loop and calls [`handle_incoming`] when a
/// `WireMessage` arrives.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Downcast to concrete type.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Broadcast a wire message to all connected peers.
    /// Returns `true` if at least one peer was available.
    async fn broadcast(&self, msg: &WireMessage) -> bool;

    /// Connect to a peer using an opaque ticket string.
    /// When `wait` is true, blocks until the peer is reachable.
    async fn connect(&self, ticket: &str, state: Arc<AppState>, wait: bool) -> anyhow::Result<()>;

    /// Generate a ticket string for others to connect to us.
    async fn ticket_string(&self) -> Option<String>;

    /// Regenerate identity/topic, invalidating old tickets.
    async fn regenerate(&self, config_dir: &Path, data_dir: &Path) -> anyhow::Result<String>;

    /// Remove a peer so future messages from it are rejected.
    ///
    /// The `peer_id` is transport-specific (e.g. an npub for Nostr).
    /// Default implementation is a no-op for transports without peer auth.
    async fn deauthorize_peer(&self, _peer_id: &str) {}

    /// Human-readable endpoint identifier for status display.
    fn endpoint_id(&self) -> Option<String>;

    /// Whether the transport is initialized and ready.
    fn is_ready(&self) -> bool;

    /// Short name identifying the transport backend (e.g. "nostr").
    fn transport_name(&self) -> &'static str;
}

/// Route an incoming wire message to the appropriate handler.
///
/// Called by transport implementations when bytes arrive from a peer.
/// Delegates all processing to the protocol state machine via
/// `apply_and_execute(Event::IncomingWire { .. })`.
pub async fn handle_incoming(state: &Arc<AppState>, content: &[u8], sender_npub: Option<&str>) {
    let msg: WireMessage = match serde_json::from_slice(content) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("failed to decode incoming message: {e}");
            return;
        }
    };
    state
        .apply_and_execute(crate::daemon_protocol::Event::IncomingWire {
            msg,
            sender_npub: sender_npub.map(String::from),
        })
        .await;
}

/// Broadcast all local networked sessions to peers for discovery.
pub async fn broadcast_local_sessions(state: &AppState) {
    let proto = state.protocol.read().await;
    let local_infos: Vec<crate::protocol::SessionInfo> = proto
        .sessions
        .values()
        .filter(|s| {
            matches!(s.origin, crate::daemon_protocol::Origin::Local) && s.metadata.networked
        })
        .map(|s| crate::protocol::SessionInfo {
            id: s.id.clone(),
            metadata: None,
        })
        .collect();
    let seq = proto.wire_seq;
    drop(proto);

    let msg = WireMessage::SessionList {
        sessions: local_infos,
        daemon_id: state.config.npub.clone(),
        daemon_name: state.config.name.clone(),
        seq,
    };
    broadcast(state, &msg).await;
}

/// Broadcast a wire message via all active transports.
///
/// Returns `true` if at least one transport successfully sent.
pub async fn broadcast(state: &AppState, msg: &WireMessage) -> bool {
    let transports = state.transports().await;
    let mut any_sent = false;
    for t in transports.values() {
        if t.broadcast(msg).await {
            any_sent = true;
        }
    }
    any_sent
}
