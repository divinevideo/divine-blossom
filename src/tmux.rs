use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};

/// Lines of scrollback to capture for pane content checks.
const CAPTURE_SCROLL_LINES: &str = "-20";
/// Max message prefix length used for injection verification.
const VERIFY_NEEDLE_LEN: usize = 60;
/// Delay for vim mode keypress detection.
const VIM_DETECT_MS: u64 = 100;
/// Delay for vim backspace to settle.
const VIM_BACKSPACE_MS: u64 = 50;
/// Delay before verification capture.
const VERIFY_DELAY_MS: u64 = 100;
/// Max retry attempts for pane injection (pane busy / mid-output).
const MAX_INJECT_RETRIES: u32 = 3;
/// Base delay for exponential backoff between retries (500ms, 1s, 2s).
const RETRY_BASE_MS: u64 = 500;

#[derive(Debug, Clone)]
pub struct TmuxPane {
    pub pane_id: String,
    pub session_name: String,
    pub pane_current_path: Option<String>,
}

/// Parsed process tree snapshot for efficient descendant lookups.
struct ProcessTree {
    children: std::collections::HashMap<u32, Vec<u32>>,
    names: std::collections::HashMap<u32, String>,
}

impl ProcessTree {
    /// Take a snapshot of all processes via `ps`.
    fn snapshot() -> Option<Self> {
        let output = Command::new("ps")
            .args(["-eo", "pid,ppid,comm"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut children: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        let mut names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

        for line in stdout.lines().skip(1) {
            let mut parts = line.split_whitespace();
            let (Some(pid_s), Some(ppid_s), Some(comm)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(pid), Ok(ppid)) = (pid_s.parse::<u32>(), ppid_s.parse::<u32>()) else {
                continue;
            };
            children.entry(ppid).or_default().push(pid);
            names.insert(pid, comm.to_string());
        }

        Some(Self { children, names })
    }

    /// Check if any descendant of `root` matches one of the given `names`.
    fn has_descendant_named(&self, root: u32, names: &[&str]) -> bool {
        let mut stack = vec![root];
        while let Some(pid) = stack.pop() {
            if self
                .names
                .get(&pid)
                .is_some_and(|n| names.iter().any(|&target| n == target))
            {
                return true;
            }
            if let Some(kids) = self.children.get(&pid) {
                stack.extend(kids);
            }
        }
        false
    }
}

/// Find all tmux panes that have a matching assistant process.
///
/// Checks `pane_current_command` first (fast path), then falls back to
/// walking the process tree for panes where the assistant runs under a shell.
/// The process snapshot is taken once and reused for all panes.
pub fn find_assistant_panes(names: &[&str]) -> anyhow::Result<Vec<TmuxPane>> {
    const SEP: &str = "|||";
    let format = format!(
        "#{{pane_id}}{SEP}#{{session_name}}{SEP}#{{pane_pid}}{SEP}#{{pane_current_command}}{SEP}#{{pane_current_path}}"
    );
    let output = Command::new("tmux")
        .args(["list-panes", "-a", "-F", &format])
        .output()
        .context("failed to run tmux")?;

    if !output.status.success() {
        bail!("tmux not running or not available");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Lazily snapshot the process tree only if needed (some pane isn't a direct match)
    let mut proc_tree: Option<ProcessTree> = None;
    let needs_tree = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.split(SEP).collect();
        parts.len() >= 5 && !names.contains(&parts[3])
    });
    if needs_tree {
        proc_tree = ProcessTree::snapshot();
    }

    let panes = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(SEP).collect();
            if parts.len() >= 5 {
                let is_match = names.contains(&parts[3])
                    || parts[2].parse::<u32>().ok().is_some_and(|pid| {
                        proc_tree
                            .as_ref()
                            .is_some_and(|t| t.has_descendant_named(pid, names))
                    });
                if is_match {
                    let path = parts[4].trim();
                    return Some(TmuxPane {
                        pane_id: parts[0].to_string(),
                        session_name: parts[1].to_string(),
                        pane_current_path: if path.is_empty() {
                            None
                        } else {
                            Some(path.to_string())
                        },
                    });
                }
            }
            None
        })
        .collect();

    Ok(panes)
}

/// Check if a tmux pane exists and has a matching process in its tree.
pub fn pane_alive(pane_id: &str, names: &[&str]) -> bool {
    let output = match Command::new("tmux")
        .args(["display-message", "-t", pane_id, "-p", "#{pane_pid}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };

    let pane_pid: u32 = match String::from_utf8_lossy(&output.stdout).trim().parse() {
        Ok(pid) => pid,
        Err(_) => return false,
    };

    ProcessTree::snapshot().is_some_and(|t| t.has_descendant_named(pane_pid, names))
}

/// Log a warning if the pane is not running a known app.
///
/// This is purely informational — injection proceeds regardless, since
/// messages queued in the terminal input buffer are picked up when the
/// app's turn ends.
fn check_known_app(pane: &str, names: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("tmux")
        .args([
            "display-message",
            "-t",
            pane,
            "-p",
            "#{pane_current_command}",
        ])
        .output();

    let cmd = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            tracing::warn!(pane, "could not detect pane command");
            return Ok(());
        }
    };

    if !names.iter().any(|&app| cmd == app) {
        tracing::warn!(
            pane,
            cmd,
            "pane is not running a known app — injecting anyway"
        );
    }
    Ok(())
}

/// Ensure the pane is in INSERT mode for vim-enabled sessions.
///
/// Sends `i` and checks whether it appeared as text on the prompt.
/// If it did, we were already in INSERT mode — backspace removes it.
/// If it didn't, the `i` entered INSERT mode from NORMAL mode.
/// Either way, the pane is in INSERT mode and ready for text.
fn ensure_insert_mode(pane: &str, tui_pattern: &str) -> anyhow::Result<()> {
    let before = prompt_text(pane, tui_pattern)?;

    let _ = Command::new("tmux")
        .args(["send-keys", "-t", pane, "i"])
        .status();
    thread::sleep(Duration::from_millis(VIM_DETECT_MS));

    let after = prompt_text(pane, tui_pattern)?;

    if after.len() > before.len() {
        // `i` appeared as text — was already in INSERT mode, remove it
        let _ = Command::new("tmux")
            .args(["send-keys", "-t", pane, "BSpace"])
            .status();
        thread::sleep(Duration::from_millis(VIM_BACKSPACE_MS));
    }
    // Otherwise `i` was consumed as a vim command — now in INSERT mode

    Ok(())
}

/// Extract the text after a prompt pattern on the last prompt line.
fn prompt_text(pane: &str, pattern: &str) -> anyhow::Result<String> {
    let content = capture_pane(pane)?;
    let text = content
        .lines()
        .rev()
        .find(|l| l.contains(pattern))
        .and_then(|line| line.split(pattern).nth(1))
        .unwrap_or("")
        .to_string();
    Ok(text)
}

/// Inject a message into a tmux pane via paste-buffer.
///
/// Optionally enters vim INSERT mode first, then verifies delivery.
///
/// # Errors
///
/// Returns an error if tmux commands fail or the pane does not exist.
pub fn inject(
    pane: &str,
    message: &str,
    vim_mode: bool,
    config: &crate::backend::InjectConfig,
    tui_pattern: Option<&str>,
) -> anyhow::Result<()> {
    let t0 = Instant::now();
    check_known_app(pane, &[])?;
    let t1 = Instant::now();

    if vim_mode {
        if let Some(pattern) = tui_pattern {
            ensure_insert_mode(pane, pattern)?;
        }
    }
    let t2 = Instant::now();

    inject_text(pane, message, config)?;
    let t3 = Instant::now();

    // Best-effort verification (warns on miss, never fails the delivery)
    thread::sleep(Duration::from_millis(VERIFY_DELAY_MS));
    verify_injected(pane, message);
    let t4 = Instant::now();

    tracing::info!(
        pane,
        msg_len = message.len(),
        check_app_ms = t1.duration_since(t0).as_millis() as u64,
        vim_mode_ms = t2.duration_since(t1).as_millis() as u64,
        inject_ms = t3.duration_since(t2).as_millis() as u64,
        verify_ms = t4.duration_since(t3).as_millis() as u64,
        total_ms = t4.duration_since(t0).as_millis() as u64,
        "inject timing"
    );

    Ok(())
}

fn capture_pane(pane: &str) -> anyhow::Result<String> {
    let output = Command::new("tmux")
        .args(["capture-pane", "-t", pane, "-p", "-S", CAPTURE_SCROLL_LINES])
        .output()
        .context("failed to run tmux capture-pane")?;

    if !output.status.success() {
        bail!(
            "tmux capture-pane failed for pane {pane}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Best-effort verification — warns instead of failing.
///
/// When the target is mid-turn, Claude's output can scroll the injected text
/// off the visible capture window before we check. The message was still
/// delivered (paste-buffer/send-keys are reliable), so a missing needle is
/// not a real failure.
fn verify_injected(pane: &str, message: &str) {
    let content = match capture_pane(pane) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("verify capture failed for pane {pane}: {e}");
            return;
        }
    };

    let needle = if message.len() > VERIFY_NEEDLE_LEN {
        &message[..VERIFY_NEEDLE_LEN]
    } else {
        message
    };

    if !content.contains(needle) {
        tracing::warn!(
            pane,
            "inject verification: text not found in visible area (may have scrolled off)"
        );
    }
}

/// Inject message text via `tmux paste-buffer` then submit with Enter.
///
/// When `config.use_inner_bracketed_paste` is true, wraps the text in
/// bracketed paste sequences (`ESC[200~...ESC[201~`) inside the buffer,
/// then uses `paste-buffer` (which adds its own outer bracket layer).
/// This is necessary for TUIs that intercept individual keystrokes from
/// `send-keys -l`, silently swallowing them. The explicit inner brackets
/// ensure the TUI receives the text as a paste event.
///
/// When inner bracketed paste is disabled, the raw text is loaded into
/// the paste buffer without extra escape sequences.
///
/// Newlines are replaced with spaces to prevent multiline paste behavior.
fn inject_text(
    pane: &str,
    message: &str,
    config: &crate::backend::InjectConfig,
) -> anyhow::Result<()> {
    let sanitized = message.replace('\n', " ");

    let paste_content = if config.use_inner_bracketed_paste {
        // Wrap in bracketed paste sequences so the TUI treats it as pasted text
        format!("\x1b[200~{sanitized}\x1b[201~")
    } else {
        sanitized
    };

    // Load into tmux paste buffer via stdin
    let mut child = Command::new("tmux")
        .args(["load-buffer", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn tmux load-buffer")?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(paste_content.as_bytes())?;
    }

    let status = child.wait().context("tmux load-buffer failed")?;
    if !status.success() {
        bail!("tmux load-buffer failed for pane {pane}");
    }

    // Paste buffer into target pane (tmux adds outer bracket wrapping)
    let status = Command::new("tmux")
        .args(["paste-buffer", "-t", pane])
        .status()
        .context("failed to run tmux paste-buffer")?;

    if !status.success() {
        bail!("tmux paste-buffer failed for pane {pane}");
    }

    // Wait for the TUI to fully process the paste event before submitting.
    thread::sleep(Duration::from_millis(config.paste_settle_ms));

    let status = Command::new("tmux")
        .args(["send-keys", "-t", pane, "Enter"])
        .status()
        .context("failed to run tmux send-keys Enter")?;

    if !status.success() {
        tracing::warn!("tmux send-keys Enter failed for pane {pane}");
    }

    Ok(())
}

/// A queued injection request sent to the per-pane background worker.
#[derive(Debug)]
pub struct InjectRequest {
    pub pane: String,
    pub message: String,
    pub vim_mode: bool,
    pub inject_config: crate::backend::InjectConfig,
    pub tui_pattern: Option<String>,
    pub result_tx: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
}

/// Background worker that drains the FIFO queue for a single pane.
///
/// Messages are processed in order. On failure, retries with exponential
/// backoff before reporting the error back to the caller.
pub async fn pane_inject_loop(mut rx: tokio::sync::mpsc::UnboundedReceiver<InjectRequest>) {
    while let Some(req) = rx.recv().await {
        let mut attempts = 0u32;
        let result = loop {
            let pane = req.pane.clone();
            let message = req.message.clone();
            let vim_mode = req.vim_mode;
            let config = crate::backend::InjectConfig {
                paste_settle_ms: req.inject_config.paste_settle_ms,
                use_inner_bracketed_paste: req.inject_config.use_inner_bracketed_paste,
                startup_inject_delay_secs: req.inject_config.startup_inject_delay_secs,
            };
            let tui_pattern = req.tui_pattern.clone();
            match tokio::task::spawn_blocking(move || {
                inject(&pane, &message, vim_mode, &config, tui_pattern.as_deref())
            })
            .await
            {
                Ok(Ok(())) => break Ok(()),
                Ok(Err(e)) => {
                    attempts += 1;
                    if attempts >= MAX_INJECT_RETRIES {
                        break Err(e);
                    }
                    let delay = RETRY_BASE_MS * 2u64.pow(attempts - 1);
                    tracing::warn!(
                        pane = %req.pane,
                        attempt = attempts,
                        retry_ms = delay,
                        "inject failed, retrying: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                Err(e) => break Err(anyhow::anyhow!("spawn_blocking join error: {e}")),
            }
        };
        let _ = req.result_tx.send(result);
    }
}

/// Enqueue a message for injection into a tmux pane.
///
/// Messages are queued in a per-pane FIFO and processed by a background
/// worker. Ordering is preserved and messages are never lost. On injection
/// failure the worker retries with backoff before returning the error.
pub async fn locked_inject(
    state: &crate::state::AppState,
    session_id: &str,
    pane: &str,
    message: &str,
    vim_mode: bool,
) -> anyhow::Result<()> {
    let backend = state.backend_for_session(session_id).await;

    match backend.delivery_mode() {
        crate::backend::DeliveryMode::HttpApi { .. } => {
            // Read backend_session_id here so deliver_via_http doesn't
            // re-acquire the protocol lock (backend_for_session already
            // dropped its lock).
            let oc_session_id = {
                let proto = state.protocol.read().await;
                proto
                    .sessions
                    .get(session_id)
                    .and_then(|s| s.metadata.backend_session_id.clone())
            };
            let project_dir = {
                let proto = state.protocol.read().await;
                proto
                    .sessions
                    .get(session_id)
                    .and_then(|s| s.metadata.project_dir.clone())
            };
            deliver_via_http(state, oc_session_id, project_dir.as_deref(), message).await
        }
        crate::backend::DeliveryMode::TuiInjection => {
            let config = backend.inject_config();
            let tui_pattern = backend.tui_ready_pattern().map(String::from);

            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let req = InjectRequest {
                pane: pane.to_string(),
                message: message.to_string(),
                vim_mode,
                inject_config: config,
                tui_pattern,
                result_tx,
            };
            state.enqueue_inject(req);
            result_rx
                .await
                .map_err(|_| anyhow::anyhow!("inject queue closed"))?
        }
    }
}

/// Deliver a message to an opencode session via its HTTP API.
///
/// Uses the `prompt_async` endpoint which returns immediately without waiting
/// for the LLM to finish processing.
async fn deliver_via_http(
    state: &crate::state::AppState,
    oc_session_id: Option<String>,
    project_dir: Option<&str>,
    message: &str,
) -> anyhow::Result<()> {
    let port = state.opencode_serve_port();

    let oc_session_id =
        oc_session_id.ok_or_else(|| anyhow::anyhow!("no backend_session_id for session"))?;

    let client = state.http_client.clone();
    let body = serde_json::json!({
        "parts": [{"type": "text", "text": message}]
    });

    // Use prompt_async — returns immediately, LLM processes in background.
    let async_url = format!("http://127.0.0.1:{port}/session/{oc_session_id}/prompt_async");
    let mut req = client
        .post(&async_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10));
    if let Some(dir) = project_dir {
        req = req.header("x-opencode-directory", dir);
    }
    let resp = req.send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!(port, "delivered message via prompt_async");
        }
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            tracing::warn!("prompt_async returned {status}: {text}");
        }
        Err(e) => {
            tracing::warn!("prompt_async request failed: {e}");
        }
    }

    Ok(())
}

/// Rename the tmux window containing a pane and disable automatic-rename.
pub fn rename_window(pane_id: &str, name: &str) {
    let _ = Command::new("tmux")
        .args(["rename-window", "-t", pane_id, name])
        .status();
    let _ = Command::new("tmux")
        .args([
            "set-window-option",
            "-t",
            pane_id,
            "automatic-rename",
            "off",
        ])
        .status();
}

/// Re-enable automatic-rename on the tmux window containing a pane.
pub fn enable_automatic_rename(pane_id: &str) {
    let _ = Command::new("tmux")
        .args(["set-window-option", "-t", pane_id, "automatic-rename", "on"])
        .status();
}

/// Derive a tmux session name from a project directory path.
/// Uses the directory basename with dots replaced by underscores
/// (matching tmux-sessionizer convention).
pub fn tmux_session_name(project_dir: &str) -> String {
    // For ouija-managed worktrees, use the repo root's basename so
    // worktree sessions join the same tmux session as the main project.
    let effective_dir = if let Some(i) = project_dir.find("/.ouija/worktrees/") {
        &project_dir[..i]
    } else if let Some(i) = project_dir.find("/.claude/worktrees/") {
        &project_dir[..i]
    } else {
        project_dir
    };
    let basename = std::path::Path::new(effective_dir)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| effective_dir.to_string());
    basename.replace('.', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmux_session_name_basename() {
        assert_eq!(
            tmux_session_name("/home/user/code/divine-mobile"),
            "divine-mobile"
        );
    }

    #[test]
    fn tmux_session_name_dots_replaced() {
        assert_eq!(
            tmux_session_name("/home/user/code/my.project"),
            "my_project"
        );
    }

    #[test]
    fn tmux_session_name_preserves_hyphens_and_underscores() {
        assert_eq!(tmux_session_name("/tmp/some_repo-name"), "some_repo-name");
    }

    #[test]
    fn tmux_session_name_bare_name() {
        assert_eq!(tmux_session_name("ouija"), "ouija");
    }

    #[test]
    fn rename_window_invalid_pane_no_panic() {
        // Should not panic on non-existent pane
        rename_window("%99999", "test");
    }

    #[test]
    fn enable_automatic_rename_invalid_pane_no_panic() {
        // Should not panic on non-existent pane
        enable_automatic_rename("%99999");
    }
}
