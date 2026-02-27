use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::state::AppState;

/// Maximum number of bytes to read from a file for description extraction.
const MAX_FILE_PREVIEW_BYTES: usize = 500;
/// Maximum length of a project description line before truncation.
const MAX_DESC_LENGTH: usize = 120;

/// Metadata about a discovered project directory.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectInfo {
    pub name: String,
    pub dir: PathBuf,
    pub description: Option<String>,
    pub has_assistant_history: bool,
}

/// Scan `projects_dir` one level deep and build a project index.
pub fn scan_projects_dir(projects_dir: &Path) -> HashMap<String, ProjectInfo> {
    let mut index = HashMap::new();
    let entries = match std::fs::read_dir(projects_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                "failed to scan projects_dir {}: {e}",
                projects_dir.display()
            );
            return index;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip hidden directories
        if name.starts_with('.') {
            continue;
        }

        // Phase 1: check for .claude directory (Claude Code backend).
        // Phase 2: delegate to backend.has_assistant_history(&path) when per-session backends are supported.
        let has_assistant_history = path.join(".claude").is_dir();
        let description = extract_description(&path);

        index.insert(
            name.to_string(),
            ProjectInfo {
                name: name.to_string(),
                dir: path,
                description,
                has_assistant_history,
            },
        );
    }

    tracing::info!(
        "indexed {} projects from {}",
        index.len(),
        projects_dir.display()
    );
    index
}

/// Extract a short description from a description file or README.md.
///
/// Phase 2: replace the hardcoded list with `backend.description_file_priority()`.
fn extract_description(dir: &Path) -> Option<String> {
    // Try CLAUDE.md first, then README.md
    for filename in &["CLAUDE.md", "README.md"] {
        let path = dir.join(filename);
        if let Ok(content) = std::fs::read_to_string(&path) {
            // Take first ~500 bytes to avoid reading huge files
            let content = &content[..content.len().min(MAX_FILE_PREVIEW_BYTES)];
            if let Some(line) = first_meaningful_line(content) {
                return Some(line);
            }
        }
    }
    None
}

/// Return the first non-empty, non-heading line from markdown content.
fn first_meaningful_line(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip markdown headings
        if trimmed.starts_with('#') {
            continue;
        }
        // Skip horizontal rules
        if trimmed.starts_with("---") || trimmed.starts_with("===") {
            continue;
        }
        // Skip HTML comments and tags
        if trimmed.starts_with("<!--") || trimmed.starts_with('<') {
            continue;
        }
        // Skip badge/image markdown
        if trimmed.starts_with("[![") || trimmed.starts_with("![") {
            continue;
        }
        // Truncate long lines
        let desc = if trimmed.len() > MAX_DESC_LENGTH {
            format!("{}...", &trimmed[..MAX_DESC_LENGTH - 3])
        } else {
            trimmed.to_string()
        };
        return Some(desc);
    }
    None
}

/// Resolve `projects_dir` from settings, expanding `~/`.
pub fn resolve_projects_dir(projects_dir: &Option<String>) -> Option<PathBuf> {
    let dir = projects_dir.as_ref()?;
    let expanded = PathBuf::from(crate::state::expand_tilde(dir));
    if expanded.is_dir() {
        Some(expanded)
    } else {
        None
    }
}

/// Refresh the project index on AppState from the configured projects_dir.
pub async fn refresh_index(state: &Arc<AppState>) {
    let projects_dir = {
        let settings = state.settings.read().await;
        resolve_projects_dir(&settings.projects_dir)
    };
    let Some(projects_dir) = projects_dir else {
        return;
    };
    let index = tokio::task::spawn_blocking(move || scan_projects_dir(&projects_dir))
        .await
        .unwrap_or_default();
    *state.project_index.write().await = index;
}

/// Find projects matching a query (exact, then substring).
pub async fn suggest_projects(state: &Arc<AppState>, query: &str) -> Vec<ProjectInfo> {
    let index = state.project_index.read().await;
    let query_lower = query.to_lowercase();

    // Exact match
    if let Some(info) = index.get(query) {
        return vec![info.clone()];
    }

    // Substring match
    index
        .values()
        .filter(|p| p.name.to_lowercase().contains(&query_lower))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn first_meaningful_line_skips_headings() {
        let content = "# My Project\n\nA cool Rust library for things.";
        assert_eq!(
            first_meaningful_line(content),
            Some("A cool Rust library for things.".into())
        );
    }

    #[test]
    fn first_meaningful_line_returns_none_for_empty() {
        assert_eq!(first_meaningful_line(""), None);
        assert_eq!(first_meaningful_line("# Just a heading\n---"), None);
    }

    #[test]
    fn first_meaningful_line_truncates_long() {
        let long = "x".repeat(200);
        let result = first_meaningful_line(&long).unwrap();
        assert!(result.ends_with("..."));
        assert!(result.len() <= 121);
    }

    #[test]
    fn scan_finds_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let proj_a = tmp.path().join("project-a");
        let proj_b = tmp.path().join("project-b");
        fs::create_dir(&proj_a).unwrap();
        fs::create_dir(&proj_b).unwrap();
        fs::create_dir(proj_a.join(".claude")).unwrap();
        fs::write(proj_b.join("README.md"), "# Hello\n\nA web app.\n").unwrap();
        // Hidden dirs should be skipped
        fs::create_dir(tmp.path().join(".hidden")).unwrap();

        let index = scan_projects_dir(tmp.path());
        assert_eq!(index.len(), 2);
        assert!(index["project-a"].has_assistant_history);
        assert!(!index["project-b"].has_assistant_history);
        assert_eq!(
            index["project-b"].description.as_deref(),
            Some("A web app.")
        );
        assert!(!index.contains_key(".hidden"));
    }

    #[test]
    fn resolve_projects_dir_none() {
        assert!(resolve_projects_dir(&None).is_none());
    }

    #[test]
    fn resolve_projects_dir_nonexistent() {
        assert!(resolve_projects_dir(&Some("/nonexistent/path/xyz".into())).is_none());
    }
}
