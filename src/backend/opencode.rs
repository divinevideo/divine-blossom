use std::path::Path;

use super::{CodingAssistant, DeliveryMode, InjectConfig, ResumeOpts, StartOpts};

mod embedded {
    pub const PLUGIN_TS: &str = include_str!("../../opencode-plugin/ouija.ts");
}

#[derive(Debug)]
pub struct OpenCode;

impl CodingAssistant for OpenCode {
    fn name(&self) -> &str {
        "opencode"
    }

    fn cli_name(&self) -> &str {
        "opencode"
    }

    fn process_names(&self) -> &[&str] {
        &["opencode"]
    }

    fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::HttpApi {
            serve_command: "opencode serve".into(),
            attach_command: "opencode attach".into(),
        }
    }

    fn build_start_command(&self, opts: &StartOpts) -> String {
        // Placeholder: HttpApi sessions use the shared serve, so this is
        // only called as a fallback. The actual attach command is built
        // by start_session/restart_session after creating the opencode session.
        let escaped_dir = crate::scheduler::shell_escape(&opts.project_dir);
        format!("cd {escaped_dir} && echo 'waiting for opencode attach...'")
    }

    fn build_resume_command(&self, opts: &ResumeOpts) -> Option<String> {
        // Resume is handled via HTTP API on the shared serve
        let escaped_dir = crate::scheduler::shell_escape(&opts.project_dir);
        Some(format!(
            "cd {escaped_dir} && echo 'waiting for opencode attach...'"
        ))
    }

    fn detect_session_id(&self, _project_dir: &str) -> Option<String> {
        None
    }

    fn tui_ready_pattern(&self) -> Option<&str> {
        None
    }

    fn inject_config(&self) -> InjectConfig {
        // Fallback values if tmux injection is ever used; HttpApi mode bypasses this.
        InjectConfig {
            paste_settle_ms: 100,
            use_inner_bracketed_paste: false,
            startup_inject_delay_secs: 0,
        }
    }

    fn config_dir_name(&self) -> &str {
        ".opencode"
    }

    fn resolve_project_root<'a>(&self, path: &'a str) -> &'a str {
        path
    }

    fn has_project_history(&self, dir: &Path) -> bool {
        dir.join(".opencode").is_dir()
    }

    fn exit_command(&self) -> Option<&str> {
        None
    }

    fn install(&self) -> anyhow::Result<()> {
        let home = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;

        let config_dir = home.join(".config/opencode");
        let config_path = config_dir.join("opencode.json");

        // Write the plugin file
        let plugins_dir = config_dir.join("plugins");
        std::fs::create_dir_all(&plugins_dir)?;
        std::fs::write(plugins_dir.join("ouija.ts"), embedded::PLUGIN_TS)?;

        let mut config: serde_json::Value = match std::fs::read_to_string(&config_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({})),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&config_dir)?;
                serde_json::json!({ "$schema": "https://opencode.ai/config.json" })
            }
            Err(e) => return Err(e.into()),
        };

        let obj = config
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("opencode config is not a JSON object"))?;

        // Add MCP config
        let mcp = obj.entry("mcp").or_insert_with(|| serde_json::json!({}));

        if mcp.get("ouija").is_none() {
            mcp["ouija"] = serde_json::json!({
                "type": "remote",
                "url": "http://localhost:7880/mcp",
                "oauth": false
            });
        }

        // Add plugin to the plugin array (merge, don't overwrite)
        let plugin_file = plugins_dir.join("ouija.ts");
        let plugin_path = format!("file://{}", plugin_file.display());
        let plugins = obj.entry("plugin").or_insert_with(|| serde_json::json!([]));
        if let Some(arr) = plugins.as_array_mut() {
            // Remove old relative-path entry if present
            arr.retain(|v| v.as_str() != Some("./plugins/ouija.ts"));
            if !arr.iter().any(|v| v.as_str() == Some(&plugin_path)) {
                arr.push(serde_json::json!(plugin_path));
            }
        }

        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ResumeOpts, StartOpts};

    fn backend() -> OpenCode {
        OpenCode
    }

    #[test]
    fn start_command_basic() {
        let cmd = backend().build_start_command(&StartOpts {
            project_dir: "/home/user/myproject".to_string(),
            worktree: None,
        });
        // HttpApi backends use shared serve; start command is a placeholder
        assert!(cmd.contains("/home/user/myproject"));
    }

    #[test]
    fn resume_command_returns_some() {
        let cmd = backend().build_resume_command(&ResumeOpts {
            project_dir: "/home/user/myproject".to_string(),
            session_id: None,
            worktree: None,
        });
        assert!(cmd.is_some());
        assert!(cmd.unwrap().contains("/home/user/myproject"));
    }

    #[test]
    fn detect_session_id_always_none() {
        assert_eq!(backend().detect_session_id("/home/user/myproject"), None);
        assert_eq!(backend().detect_session_id("/some/other/path"), None);
    }

    #[test]
    fn has_project_history_with_opencode_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".opencode")).unwrap();
        assert!(backend().has_project_history(tmp.path()));
    }

    #[test]
    fn has_project_history_without_opencode_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!backend().has_project_history(tmp.path()));
    }

    #[test]
    fn resolve_project_root_unchanged() {
        let b = backend();
        assert_eq!(
            b.resolve_project_root("/home/user/myproject"),
            "/home/user/myproject"
        );
        assert_eq!(
            b.resolve_project_root("/home/user/myproject/subdir"),
            "/home/user/myproject/subdir"
        );
    }
}
