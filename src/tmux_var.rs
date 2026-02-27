use std::process::Command;

const VAR_NAME: &str = "@ouija_session";

/// Set the `@ouija_session` user variable on a tmux pane.
pub fn set(pane: &str, session_id: &str) {
    let _ = Command::new("tmux")
        .args(["set", "-t", pane, "-p", VAR_NAME, session_id])
        .status();
}

/// Clear the `@ouija_session` user variable from a tmux pane.
pub fn clear(pane: &str) {
    let _ = Command::new("tmux")
        .args(["set", "-t", pane, "-pu", VAR_NAME])
        .status();
}
