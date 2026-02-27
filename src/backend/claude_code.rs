use std::path::Path;

use super::{CodingAssistant, DeliveryMode, InjectConfig, ResumeOpts, StartOpts};

#[derive(Debug)]
pub struct ClaudeCode;

// --- Embedded plugin files ---
// These are compiled into the binary so `ouija start` can bootstrap the Claude
// Code plugin without needing the source repo on disk.

mod embedded {
    pub const HOOKS_JSON: &str = include_str!("../../hooks/hooks.json");
    pub const MCP_JSON: &str = include_str!("../../.mcp.json");

    pub const SCRIPT_BLOCK_INTERACTIVE: &str =
        include_str!("../../scripts/block-interactive-prompts.sh");
    pub const SCRIPT_CHECK_PENDING: &str = include_str!("../../scripts/check-pending-replies.sh");
    pub const SCRIPT_PROMPT_SUBMIT: &str = include_str!("../../scripts/ouija-prompt-submit.sh");
    pub const SCRIPT_REGISTER: &str = include_str!("../../scripts/ouija-register.sh");
    pub const SCRIPT_STATUSLINE: &str = include_str!("../../scripts/ouija-statusline.sh");
    pub const SCRIPT_UNREGISTER: &str = include_str!("../../scripts/ouija-unregister.sh");

    pub const SKILLS_PEER_TRUST: &str = include_str!("../../skills/ouija/SKILL.md");
}

/// Write all embedded plugin files to the given cache directory.
fn write_embedded_plugin_files(cache_dir: &std::path::Path) {
    let files: &[(&str, &str)] = &[
        ("hooks/hooks.json", embedded::HOOKS_JSON),
        (".mcp.json", embedded::MCP_JSON),
        (
            "scripts/block-interactive-prompts.sh",
            embedded::SCRIPT_BLOCK_INTERACTIVE,
        ),
        (
            "scripts/check-pending-replies.sh",
            embedded::SCRIPT_CHECK_PENDING,
        ),
        (
            "scripts/ouija-prompt-submit.sh",
            embedded::SCRIPT_PROMPT_SUBMIT,
        ),
        ("scripts/ouija-register.sh", embedded::SCRIPT_REGISTER),
        ("scripts/ouija-statusline.sh", embedded::SCRIPT_STATUSLINE),
        ("scripts/ouija-unregister.sh", embedded::SCRIPT_UNREGISTER),
        ("skills/ouija/SKILL.md", embedded::SKILLS_PEER_TRUST),
    ];

    for (path, content) in files {
        let dest = cache_dir.join(path);
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&dest, content);
    }

    // Make scripts executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(entries) = std::fs::read_dir(cache_dir.join("scripts")) {
            for entry in entries.flatten() {
                let _ =
                    std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o755));
            }
        }
    }
}

fn sync_dir(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            sync_dir(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Try to sync plugin files from the local source directory. Returns true if
/// a source dir was found and synced.
fn try_sync_from_source(home: &std::path::Path, cache_dir: &std::path::Path) -> bool {
    let settings_path = home.join(".claude/settings.json");
    let settings_str = match std::fs::read_to_string(&settings_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let settings: serde_json::Value = match serde_json::from_str(&settings_str) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let source_dir = match settings
        .pointer("/extraKnownMarketplaces/ouija/source/path")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from)
    {
        Some(d) if d.exists() => d,
        _ => return false,
    };

    for dir in &["scripts", "hooks", "skills"] {
        let src = source_dir.join(dir);
        let dst = cache_dir.join(dir);
        if src.is_dir() {
            if let Err(e) = sync_dir(&src, &dst) {
                eprintln!("warning: failed to sync plugin {dir}: {e}");
            }
        }
    }

    let src = source_dir.join(".mcp.json");
    let dst = cache_dir.join(".mcp.json");
    if src.is_file() {
        let _ = std::fs::copy(&src, &dst);
    }

    let src = source_dir.join(".claude-plugin");
    let dst = cache_dir.join(".claude-plugin");
    if src.is_dir() {
        if let Err(e) = sync_dir(&src, &dst) {
            eprintln!("warning: failed to sync plugin .claude-plugin: {e}");
        }
    }

    true
}

/// Ensure the Claude Code plugin is installed. Called on every `ouija start`.
/// If the plugin cache already exists, just stamps the version. If not, writes
/// all embedded files and registers in installed_plugins.json / settings.json.
fn ensure_plugin_installed() {
    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return,
    };

    let claude_dir = home.join(".claude");
    if !claude_dir.exists() {
        // Claude Code not installed — skip silently
        return;
    }

    let version = env!("CARGO_PKG_VERSION");
    let cache_dir = claude_dir.join("plugins/cache/ouija/ouija/0.1.0");

    let needs_full_install = !cache_dir.exists();
    if needs_full_install {
        println!("installing Claude Code plugin...");
    }

    write_embedded_plugin_files(&cache_dir);

    // Stamp version
    let _ = std::fs::write(cache_dir.join(".version"), version);

    if !needs_full_install {
        return;
    }

    // --- First-time registration ---

    // Update installed_plugins.json
    let plugins_path = claude_dir.join("plugins/installed_plugins.json");
    let mut plugins: serde_json::Value = std::fs::read_to_string(&plugins_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "version": 2,
                "plugins": {}
            })
        });

    if !plugins["plugins"]
        .as_object()
        .is_some_and(|p| p.contains_key("ouija@ouija"))
    {
        let now = chrono::Utc::now().to_rfc3339();
        plugins["plugins"]["ouija@ouija"] = serde_json::json!([{
            "scope": "user",
            "installPath": cache_dir.to_string_lossy(),
            "version": "0.1.0",
            "installedAt": now,
            "lastUpdated": now,
            "isLocal": false
        }]);
        let _ = std::fs::write(
            &plugins_path,
            serde_json::to_string_pretty(&plugins).unwrap(),
        );
    }

    // Update settings.json — enable the plugin
    let settings_path = claude_dir.join("settings.json");
    let mut settings: serde_json::Value = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let mut changed = false;
    if let Some(obj) = settings.as_object_mut() {
        let enabled = obj
            .entry("enabledPlugins")
            .or_insert_with(|| serde_json::json!({}));
        if enabled.get("ouija@ouija").is_none() {
            enabled["ouija@ouija"] = serde_json::Value::Bool(true);
            changed = true;
        }

        // Set statusLine if not already configured
        if obj.get("statusLine").is_none() {
            let script = cache_dir.join("scripts/ouija-statusline.sh");
            obj.insert(
                "statusLine".to_string(),
                serde_json::json!({
                    "type": "command",
                    "command": script.to_string_lossy()
                }),
            );
            changed = true;
        }
    }

    if changed {
        let _ = std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).unwrap(),
        );
    }

    println!("Claude Code plugin installed. Restart Claude Code sessions to activate.");
}

/// Refresh the Claude Code plugin cache from the source directory.
///
/// Tries the source directory first (for local dev), falls back to embedded
/// files (for production installs).
pub fn refresh_plugin_cache(version: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) => std::path::PathBuf::from(h),
        Err(_) => return,
    };

    let cache_base = home.join(".claude/plugins/cache/ouija/ouija");
    let cache_dir = match std::fs::read_dir(&cache_base)
        .ok()
        .and_then(|mut entries| entries.next())
        .and_then(|e| e.ok())
    {
        Some(entry) => entry.path(),
        None => {
            // No cache dir yet — run full install with embedded files
            ensure_plugin_installed();
            return;
        }
    };

    // Try source directory first (local dev workflow)
    let source_synced = try_sync_from_source(&home, &cache_dir);

    if !source_synced {
        // Fall back to embedded files (production install via cargo)
        write_embedded_plugin_files(&cache_dir);
    }

    // Stamp version so hooks can detect plugin/daemon mismatch
    let _ = std::fs::write(cache_dir.join(".version"), version);

    println!("plugin cache refreshed");
}

impl CodingAssistant for ClaudeCode {
    fn name(&self) -> &str {
        "claude-code"
    }

    fn cli_name(&self) -> &str {
        "claude"
    }

    fn process_names(&self) -> &[&str] {
        &["claude"]
    }

    fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::TuiInjection
    }

    fn build_start_command(&self, opts: &StartOpts) -> String {
        let escaped_dir = crate::scheduler::shell_escape(&opts.project_dir);
        match &opts.worktree {
            None => {
                format!("cd {escaped_dir} && claude --dangerously-skip-permissions")
            }
            Some(super::WorktreeMode::Disposable) => {
                format!("cd {escaped_dir} && claude --dangerously-skip-permissions --worktree")
            }
            Some(super::WorktreeMode::Named(name)) => {
                let escaped_name = crate::scheduler::shell_escape(name);
                format!(
                    "cd {escaped_dir} && claude --dangerously-skip-permissions --worktree {escaped_name}"
                )
            }
        }
    }

    fn build_resume_command(&self, opts: &ResumeOpts) -> Option<String> {
        let escaped_dir = crate::scheduler::shell_escape(&opts.project_dir);
        let resume_flag = match &opts.session_id {
            Some(sid) => format!("--resume {}", crate::scheduler::shell_escape(sid)),
            None => "--continue".to_string(),
        };
        let cmd = match &opts.worktree {
            None => {
                format!("cd {escaped_dir} && claude --dangerously-skip-permissions {resume_flag}")
            }
            Some(super::WorktreeMode::Disposable) => {
                format!(
                    "cd {escaped_dir} && claude --dangerously-skip-permissions {resume_flag} --worktree"
                )
            }
            Some(super::WorktreeMode::Named(name)) => {
                let escaped_name = crate::scheduler::shell_escape(name);
                format!(
                    "cd {escaped_dir} && claude --dangerously-skip-permissions {resume_flag} --worktree {escaped_name}"
                )
            }
        };
        Some(cmd)
    }

    fn detect_session_id(&self, project_dir: &str) -> Option<String> {
        let home = std::env::var("HOME").ok()?;
        // Claude encodes project dirs as: absolute path with / replaced by -
        // e.g. /home/daniel/code/ouija -> -home-daniel-code-ouija
        let slug = project_dir.replace('/', "-");
        let sessions_dir = std::path::PathBuf::from(&home)
            .join(".claude")
            .join("projects")
            .join(&slug);
        if !sessions_dir.is_dir() {
            return None;
        }

        // Find the most recently modified .jsonl file
        let mut newest: Option<(std::time::SystemTime, String)> = None;
        let entries = std::fs::read_dir(&sessions_dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            let stem = path.file_stem()?.to_str()?.to_string();
            if newest.as_ref().is_none_or(|(t, _)| modified > *t) {
                newest = Some((modified, stem));
            }
        }

        let (_, session_id) = newest?;
        tracing::debug!(
            "auto-detected claude session {session_id} from {}",
            sessions_dir.display()
        );
        Some(session_id)
    }

    fn tui_ready_pattern(&self) -> Option<&str> {
        Some("\u{276F}")
    }

    fn inject_config(&self) -> InjectConfig {
        InjectConfig {
            paste_settle_ms: 300,
            use_inner_bracketed_paste: true,
            startup_inject_delay_secs: 5,
        }
    }

    fn config_dir_name(&self) -> &str {
        ".claude"
    }

    fn resolve_project_root<'a>(&self, path: &'a str) -> &'a str {
        // Strip /.claude/worktrees/<branch> suffix if present
        if let Some(idx) = path.find("/.claude/worktrees/") {
            &path[..idx]
        } else {
            path
        }
    }

    fn has_project_history(&self, dir: &Path) -> bool {
        dir.join(".claude").is_dir()
    }

    fn exit_command(&self) -> Option<&str> {
        Some("/exit")
    }

    fn install(&self) -> anyhow::Result<()> {
        ensure_plugin_installed();
        Ok(())
    }

    // is_available: uses default impl (runs `self.cli_name() --version`)

    fn description_file_priority(&self) -> &[&str] {
        &["CLAUDE.md", "README.md"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ResumeOpts, StartOpts, WorktreeMode};

    fn backend() -> ClaudeCode {
        ClaudeCode
    }

    #[test]
    fn start_command_no_worktree() {
        let cmd = backend().build_start_command(&StartOpts {
            project_dir: "/home/user/myproject".to_string(),
            worktree: None,
        });
        assert_eq!(
            cmd,
            "cd '/home/user/myproject' && claude --dangerously-skip-permissions"
        );
    }

    #[test]
    fn start_command_named_worktree() {
        let cmd = backend().build_start_command(&StartOpts {
            project_dir: "/home/user/myproject".to_string(),
            worktree: Some(WorktreeMode::Named("feature-x".to_string())),
        });
        assert_eq!(
            cmd,
            "cd '/home/user/myproject' && claude --dangerously-skip-permissions --worktree 'feature-x'"
        );
    }

    #[test]
    fn start_command_disposable_worktree() {
        let cmd = backend().build_start_command(&StartOpts {
            project_dir: "/home/user/myproject".to_string(),
            worktree: Some(WorktreeMode::Disposable),
        });
        assert_eq!(
            cmd,
            "cd '/home/user/myproject' && claude --dangerously-skip-permissions --worktree"
        );
    }

    #[test]
    fn resume_command_no_session_id() {
        let cmd = backend().build_resume_command(&ResumeOpts {
            project_dir: "/home/user/myproject".to_string(),
            session_id: None,
            worktree: None,
        });
        assert_eq!(
            cmd,
            Some(
                "cd '/home/user/myproject' && claude --dangerously-skip-permissions --continue"
                    .to_string()
            )
        );
    }

    #[test]
    fn resume_command_with_session_id() {
        let cmd = backend().build_resume_command(&ResumeOpts {
            project_dir: "/home/user/myproject".to_string(),
            session_id: Some("abc123".to_string()),
            worktree: None,
        });
        assert_eq!(
            cmd,
            Some(
                "cd '/home/user/myproject' && claude --dangerously-skip-permissions --resume 'abc123'"
                    .to_string()
            )
        );
    }

    #[test]
    fn resume_command_with_session_id_and_named_worktree() {
        let cmd = backend().build_resume_command(&ResumeOpts {
            project_dir: "/home/user/myproject".to_string(),
            session_id: Some("abc123".to_string()),
            worktree: Some(WorktreeMode::Named("feature-x".to_string())),
        });
        assert_eq!(
            cmd,
            Some(
                "cd '/home/user/myproject' && claude --dangerously-skip-permissions --resume 'abc123' --worktree 'feature-x'"
                    .to_string()
            )
        );
    }

    #[test]
    fn detect_session_id_nonexistent_dir() {
        let result = backend().detect_session_id("/nonexistent/path/that/does/not/exist");
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_project_root_strips_worktree_suffix() {
        let b = backend();
        assert_eq!(
            b.resolve_project_root("/home/user/myproject/.claude/worktrees/feature-x"),
            "/home/user/myproject"
        );
    }

    #[test]
    fn resolve_project_root_normal_path_unchanged() {
        let b = backend();
        assert_eq!(
            b.resolve_project_root("/home/user/myproject"),
            "/home/user/myproject"
        );
    }
}
