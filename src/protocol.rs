use serde::{Deserialize, Serialize};

use crate::state::SessionMetadata;

/// A session's identity and optional metadata for wire exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    #[serde(default)]
    pub metadata: Option<SessionMetadata>,
}

/// Tagged JSON message exchanged between daemons over Nostr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WireMessage {
    SessionSend {
        from: String,
        to: String,
        message: String,
        #[serde(default)]
        expects_reply: bool,
        #[serde(default)]
        msg_id: u64,
        #[serde(default)]
        responds_to: Option<u64>,
        #[serde(default)]
        done: bool,
    },
    SessionSendAck {
        from: String,
        to: String,
        delivered: bool,
        daemon_id: String,
    },
    SessionAnnounce {
        id: String,
        daemon_id: String,
        #[serde(default)]
        daemon_name: String,
        #[serde(default)]
        metadata: Option<SessionMetadata>,
        #[serde(default)]
        seq: u64,
    },
    SessionList {
        sessions: Vec<SessionInfo>,
        daemon_id: String,
        daemon_name: String,
        #[serde(default)]
        seq: u64,
    },
    SessionRemove {
        id: String,
        daemon_id: String,
        #[serde(default)]
        daemon_name: String,
        #[serde(default)]
        seq: u64,
    },
    SessionRenamed {
        old_id: String,
        new_id: String,
        daemon_id: String,
        #[serde(default)]
        daemon_name: String,
        #[serde(default)]
        metadata: Option<SessionMetadata>,
        #[serde(default)]
        seq: u64,
    },
    ConnectRequest {
        secret: String,
        #[serde(default)]
        relays: Vec<String>,
    },
    Command {
        command: String,
        #[serde(default)]
        daemon_id: String,
    },
    CommandResult {
        command: String,
        result: String,
        daemon_id: String,
    },
    SessionStart {
        name: String,
        #[serde(default)]
        project_dir: Option<String>,
        #[serde(default)]
        worktree: Option<bool>,
        #[serde(default)]
        prompt: Option<String>,
        #[serde(default)]
        reminder: Option<String>,
        #[serde(default)]
        from: Option<String>,
        #[serde(default)]
        expects_reply: Option<bool>,
        daemon_id: String,
        #[serde(default)]
        seq: u64,
    },
    SessionRestart {
        name: String,
        #[serde(default)]
        fresh: Option<bool>,
        #[serde(default)]
        prompt: Option<String>,
        #[serde(default)]
        reminder: Option<String>,
        #[serde(default)]
        from: Option<String>,
        #[serde(default)]
        expects_reply: Option<bool>,
        daemon_id: String,
        #[serde(default)]
        seq: u64,
    },
}

impl WireMessage {
    /// Extract the `daemon_id` field, if present on this variant.
    pub fn daemon_id(&self) -> Option<&str> {
        match self {
            Self::SessionSendAck { daemon_id, .. }
            | Self::SessionAnnounce { daemon_id, .. }
            | Self::SessionList { daemon_id, .. }
            | Self::SessionRemove { daemon_id, .. }
            | Self::SessionRenamed { daemon_id, .. }
            | Self::Command { daemon_id, .. }
            | Self::CommandResult { daemon_id, .. }
            | Self::SessionStart { daemon_id, .. }
            | Self::SessionRestart { daemon_id, .. } => Some(daemon_id),
            Self::SessionSend { .. } | Self::ConnectRequest { .. } => None,
        }
    }

    /// Extract the monotonic sequence counter, if present on this variant.
    pub fn seq(&self) -> Option<u64> {
        match self {
            Self::SessionAnnounce { seq, .. }
            | Self::SessionList { seq, .. }
            | Self::SessionRemove { seq, .. }
            | Self::SessionRenamed { seq, .. }
            | Self::SessionStart { seq, .. }
            | Self::SessionRestart { seq, .. } => Some(*seq),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: &WireMessage) -> WireMessage {
        let json = serde_json::to_string(msg).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn session_send_round_trip() {
        let msg = WireMessage::SessionSend {
            from: "a".into(),
            to: "b".into(),
            message: "hello".into(),
            expects_reply: false,
            msg_id: 0,
            responds_to: None,
            done: false,
        };
        let decoded = round_trip(&msg);
        assert!(
            matches!(decoded, WireMessage::SessionSend { from, to, message, expects_reply, .. }
            if from == "a" && to == "b" && message == "hello" && !expects_reply)
        );
    }

    #[test]
    fn session_send_expects_reply_round_trip() {
        let msg = WireMessage::SessionSend {
            from: "a".into(),
            to: "b".into(),
            message: "hello".into(),
            expects_reply: true,
            msg_id: 0,
            responds_to: None,
            done: false,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(decoded, WireMessage::SessionSend { expects_reply, .. } if expects_reply));
    }

    #[test]
    fn session_send_backward_compat() {
        // Old format without expects_reply should default to false
        let json = r#"{"type":"SessionSend","from":"a","to":"b","message":"hi"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, WireMessage::SessionSend { expects_reply, .. } if !expects_reply));
    }

    #[test]
    fn session_send_ack_round_trip() {
        let msg = WireMessage::SessionSendAck {
            from: "a".into(),
            to: "b".into(),
            delivered: true,
            daemon_id: "d1".into(),
        };
        let decoded = round_trip(&msg);
        assert!(matches!(decoded, WireMessage::SessionSendAck { delivered, .. } if delivered));
    }

    #[test]
    fn session_announce_round_trip() {
        let msg = WireMessage::SessionAnnounce {
            id: "s1".into(),
            daemon_id: "npub1test".into(),
            daemon_name: "host1".into(),
            metadata: Some(SessionMetadata {
                vim_mode: true,
                project_dir: Some("/tmp".into()),
                role: None,
                ..Default::default()
            }),
            seq: 1,
        };
        let decoded = round_trip(&msg);
        assert!(
            matches!(decoded, WireMessage::SessionAnnounce { id, daemon_name, metadata, .. }
            if id == "s1" && daemon_name == "host1" && metadata.clone().unwrap().vim_mode)
        );
    }

    #[test]
    fn session_announce_no_metadata() {
        let msg = WireMessage::SessionAnnounce {
            id: "s1".into(),
            daemon_id: "d1".into(),
            daemon_name: String::new(),
            metadata: None,
            seq: 0,
        };
        let decoded = round_trip(&msg);
        assert!(
            matches!(decoded, WireMessage::SessionAnnounce { metadata, .. } if metadata.is_none())
        );
    }

    #[test]
    fn session_list_round_trip() {
        let msg = WireMessage::SessionList {
            sessions: vec![
                SessionInfo {
                    id: "s1".into(),
                    metadata: None,
                },
                SessionInfo {
                    id: "s2".into(),
                    metadata: Some(SessionMetadata::default()),
                },
            ],
            daemon_id: "d1".into(),
            daemon_name: "host1".into(),
            seq: 1,
        };
        let decoded = round_trip(&msg);
        assert!(
            matches!(decoded, WireMessage::SessionList { sessions, .. } if sessions.len() == 2)
        );
    }

    #[test]
    fn session_remove_round_trip() {
        let msg = WireMessage::SessionRemove {
            id: "s1".into(),
            daemon_id: "d1".into(),
            daemon_name: "host1".into(),
            seq: 1,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(decoded, WireMessage::SessionRemove { id, .. } if id == "s1"));
    }

    #[test]
    fn connect_request_round_trip() {
        let msg = WireMessage::ConnectRequest {
            secret: "a1b2c3d4e5f6".into(),
            relays: vec!["wss://relay.damus.io".into()],
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::ConnectRequest { secret, relays }
            if secret == "a1b2c3d4e5f6" && relays.len() == 1
        ));
    }

    #[test]
    fn connect_request_backward_compat() {
        // Old format without relays field should deserialize with empty relays
        let json = r#"{"type":"ConnectRequest","secret":"abc123"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, WireMessage::ConnectRequest { relays, .. } if relays.is_empty()));
    }

    #[test]
    fn wire_message_uses_type_tag() {
        let msg = WireMessage::SessionSend {
            from: "a".into(),
            to: "b".into(),
            message: "hi".into(),
            expects_reply: false,
            msg_id: 0,
            responds_to: None,
            done: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"SessionSend\""));
    }

    #[test]
    fn command_round_trip() {
        let msg = WireMessage::Command {
            command: "/start foo".into(),
            daemon_id: "npub1abc".into(),
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::Command { command, daemon_id }
            if command == "/start foo" && daemon_id == "npub1abc"
        ));
    }

    #[test]
    fn command_result_round_trip() {
        let msg = WireMessage::CommandResult {
            command: "/start foo".into(),
            result: "started".into(),
            daemon_id: "npub1abc".into(),
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::CommandResult { command, result, daemon_id }
            if command == "/start foo" && result == "started" && daemon_id == "npub1abc"
        ));
    }

    #[test]
    fn session_renamed_round_trip() {
        let msg = WireMessage::SessionRenamed {
            old_id: "old".into(),
            new_id: "new".into(),
            daemon_id: "d1".into(),
            daemon_name: "host1".into(),
            metadata: None,
            seq: 1,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::SessionRenamed { old_id, new_id, daemon_id, .. }
            if old_id == "old" && new_id == "new" && daemon_id == "d1"
        ));
    }

    #[test]
    fn session_renamed_backward_compat() {
        // Minimal format without daemon_name/metadata
        let json = r#"{"type":"SessionRenamed","old_id":"a","new_id":"b","daemon_id":"d1"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(
            msg,
            WireMessage::SessionRenamed { old_id, new_id, .. }
            if old_id == "a" && new_id == "b"
        ));
    }

    #[test]
    fn command_backward_compat() {
        // Old AdminCommand format should still work via serde alias or new name
        let json = r#"{"type":"Command","command":"/start bar"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, WireMessage::Command { command, .. } if command == "/start bar"));
    }

    #[test]
    fn session_start_round_trip() {
        let msg = WireMessage::SessionStart {
            name: "test-session".into(),
            project_dir: Some("/home/user/project".into()),
            worktree: Some(true),
            prompt: Some("do the thing".into()),
            reminder: None,
            from: Some("caller".into()),
            expects_reply: Some(true),
            daemon_id: "npub1abc".into(),
            seq: 42,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::SessionStart {
                name, project_dir, worktree, prompt, from, expects_reply, daemon_id, seq, ..
            }
            if name == "test-session"
                && project_dir.as_deref() == Some("/home/user/project")
                && worktree == Some(true)
                && prompt.as_deref() == Some("do the thing")
                && from.as_deref() == Some("caller")
                && expects_reply == Some(true)
                && daemon_id == "npub1abc"
                && seq == 42
        ));
    }

    #[test]
    fn session_start_minimal() {
        // Only required fields
        let msg = WireMessage::SessionStart {
            name: "foo".into(),
            project_dir: None,
            worktree: None,
            prompt: None,
            reminder: None,
            from: None,
            expects_reply: None,
            daemon_id: "npub1abc".into(),
            seq: 0,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::SessionStart { name, project_dir, worktree, .. }
            if name == "foo" && project_dir.is_none() && worktree.is_none()
        ));
    }

    #[test]
    fn session_start_backward_compat() {
        // Old daemon without optional fields should deserialize with defaults
        let json = r#"{"type":"SessionStart","name":"foo","daemon_id":"npub1abc"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(
            msg,
            WireMessage::SessionStart { name, project_dir, worktree, seq, .. }
            if name == "foo" && project_dir.is_none() && worktree.is_none() && seq == 0
        ));
    }

    #[test]
    fn session_restart_round_trip() {
        let msg = WireMessage::SessionRestart {
            name: "test-session".into(),
            fresh: Some(true),
            prompt: Some("check status".into()),
            reminder: None,
            from: Some("caller".into()),
            expects_reply: Some(false),
            daemon_id: "npub1abc".into(),
            seq: 7,
        };
        let decoded = round_trip(&msg);
        assert!(matches!(
            decoded,
            WireMessage::SessionRestart {
                name, fresh, prompt, from, expects_reply, daemon_id, seq, ..
            }
            if name == "test-session"
                && fresh == Some(true)
                && prompt.as_deref() == Some("check status")
                && from.as_deref() == Some("caller")
                && expects_reply == Some(false)
                && daemon_id == "npub1abc"
                && seq == 7
        ));
    }

    #[test]
    fn session_restart_backward_compat() {
        let json = r#"{"type":"SessionRestart","name":"bar","daemon_id":"npub1xyz"}"#;
        let msg: WireMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(
            msg,
            WireMessage::SessionRestart { name, fresh, seq, .. }
            if name == "bar" && fresh.is_none() && seq == 0
        ));
    }
}
