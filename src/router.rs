use crate::daemon_protocol::Origin;
use crate::persistence::RouterConfig;
use crate::state::{AppState, LogEntry};

/// Timeout for LLM router API requests.
const ROUTER_API_TIMEOUT_SECS: u64 = 30;
/// Max inter-session messages to include in the router prompt.
const MAX_INTER_SESSION_MESSAGES: usize = 10;
/// Max message length before truncation in router context.
const MAX_MESSAGE_PREVIEW_LEN: usize = 200;

/// LLM-produced routing action for an inbound human message.
#[derive(Debug, PartialEq)]
pub enum RouterDecision {
    Route { targets: Vec<String> },
    Command(String),
    DirectAnswer(String),
}

/// Lightweight view of a session for the router prompt.
#[derive(Debug)]
pub struct SessionSnapshot {
    pub id: String,
    pub origin: String,
    pub role: Option<String>,
    pub project_dir: Option<String>,
    pub project_description: Option<String>,
    pub bulletin: Option<String>,
}

/// Truncated message record included in the router prompt.
#[derive(Debug)]
pub struct MessageSnapshot {
    pub timestamp: String,
    pub from: String,
    pub to: String,
    pub message: String,
}

/// Classify a human's bare text message using an LLM.
///
/// Returns `Ok(Some(decision))` on success, `Ok(None)` if the LLM response
/// couldn't be parsed, or `Err` if the API call itself failed.
pub async fn classify(
    config: &RouterConfig,
    message: &str,
    sessions: &[SessionSnapshot],
    messages: &[MessageSnapshot],
    human_name: &str,
) -> Result<Option<RouterDecision>, String> {
    let system_prompt = build_system_prompt(sessions, messages, human_name);
    let response = call_api(config, &system_prompt, message)
        .await
        .map_err(|e| e.to_string())?;
    tracing::debug!("router LLM response: {response}");
    Ok(parse_response(&response))
}

fn build_system_prompt(
    sessions: &[SessionSnapshot],
    messages: &[MessageSnapshot],
    human_name: &str,
) -> String {
    let mut prompt = String::from(
        "<role>\n\
         You are the message router for ouija, a cross-machine AI session daemon.\n\
         ouija manages multiple coding sessions running across different machines and projects.\n\
         Each session is an AI agent working in a tmux pane on a specific codebase.\n\
         Sessions communicate via the ouija daemon using Nostr (a decentralized messaging protocol).\n\
         The human sends messages via Nostr DMs to the daemon. Your job is to read those messages,\n\
         understand intent and context, and route them to the right session(s).\n\
         </role>\n\n\
         <context>\n\
         When you route a message, the daemon delivers the human's original message verbatim to\n\
         the target session(s) via tmux injection. The session then sees it as `<msg from=\"<human>\" ...>message</msg>`\n\
         and can respond. You do not need to rewrite or summarize the message — just pick the target(s).\n\n\
         Use the session list to understand what each session is working on (role, project directory,\n\
         project description). Use the message log to understand conversation context — who has been\n\
         talking to whom, what topics are active, what the human was last discussing and with which session.\n\
         This context is crucial for routing ambiguous messages like \"continue with that\" or\n\
         \"tell them about the fix\".\n\n\
         <sessions>\n",
    );

    if sessions.is_empty() {
        prompt.push_str("(none)\n");
    } else {
        for s in sessions {
            let role = s.role.as_deref().unwrap_or("idle");
            let dir = s
                .project_dir
                .as_deref()
                .map(|d| format!(" [dir: {d}]"))
                .unwrap_or_default();
            let desc = s
                .project_description
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default();
            let bulletin = s
                .bulletin
                .as_deref()
                .map(|b| format!(" | bulletin: {b}"))
                .unwrap_or_default();
            prompt.push_str(&format!(
                "- {} ({}) — {role}{dir}{desc}{bulletin}\n",
                s.id, s.origin
            ));
        }
    }
    prompt.push_str("</sessions>\n");

    // Split messages: human conversation vs inter-session chatter
    let human_msgs: Vec<&MessageSnapshot> = messages
        .iter()
        .filter(|m| m.from == human_name || m.to == human_name)
        .collect();
    let session_msgs: Vec<&MessageSnapshot> = messages
        .iter()
        .filter(|m| m.from != human_name && m.to != human_name)
        .collect();

    prompt.push_str("\n<conversation_history>\n");
    if human_msgs.is_empty() {
        prompt.push_str("(no recent messages)\n");
    } else {
        for m in &human_msgs {
            prompt.push_str(&format!(
                "[{}] {} -> {}: {}\n",
                m.timestamp, m.from, m.to, m.message
            ));
        }
    }
    prompt.push_str("</conversation_history>\n");

    if !session_msgs.is_empty() {
        // Only include a small tail of inter-session traffic
        prompt.push_str("\n<inter_session_messages>\n");
        for m in session_msgs
            .iter()
            .rev()
            .take(MAX_INTER_SESSION_MESSAGES)
            .rev()
        {
            prompt.push_str(&format!(
                "[{}] {} -> {}: {}\n",
                m.timestamp, m.from, m.to, m.message
            ));
        }
        prompt.push_str("</inter_session_messages>\n");
    }
    prompt.push_str("</context>\n");

    prompt.push_str(
        "\n<commands>\n\
         The human can also issue commands via natural language. If their message matches \
         a command intent, respond with COMMAND <slash_command>.\n\n\
         /help              — show help message\n\
         /list              — show sessions\n\
         /default <id>      — set default session\n\
         /status            — daemon status\n\
         /kill <session>    — kill a session\n\
         /start <name>      — start new session\n\
         /restart <name>    — restart a session\n\
         /connect <ticket>  — connect to peer\n\
         /nodes             — list connected nodes\n\
         /task list         — list scheduled tasks\n\
         /task trigger <id> — trigger a task\n\
         </commands>\n",
    );

    prompt.push_str(&format!(
        "\n<instructions>\n\
         The human's name is \"{human_name}\".\n\
         Read the human's message, understand their intent using the session list and \
         conversation history, and decide where to send it.\n\n\
         Respond with exactly one of these formats (no extra text):\n\n\
         ROUTE <session_id> [session_id2 ...]\n\
         COMMAND <slash_command>\n\
         ANSWER: <response>\n\n\
         ROUTE sends the human's message (verbatim, handled by the system) to one or more sessions.\n\
         COMMAND executes a daemon command on behalf of the human.\n\
         ANSWER lets you reply directly — use sparingly, only when no session is relevant.\n\
         </instructions>\n"
    ));

    prompt
}

/// Resolve the API key from config or environment.
fn resolve_api_key(config: &RouterConfig) -> Option<String> {
    config
        .api_key
        .clone()
        .or_else(|| std::env::var("ROUTER_API_KEY").ok())
        .or_else(|| std::env::var("GEMINI_API_KEY").ok())
}

/// Call an OpenAI-compatible chat completions endpoint.
async fn call_api(
    config: &RouterConfig,
    system_prompt: &str,
    user_message: &str,
) -> anyhow::Result<String> {
    let api_key = resolve_api_key(config).ok_or_else(|| {
        anyhow::anyhow!("no API key configured or in ROUTER_API_KEY / GEMINI_API_KEY")
    })?;

    static CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            .build()
            .expect("failed to build HTTP client")
    });
    let client = &*CLIENT;
    // TODO: switch to native Gemini API with thinkingBudget:0 to avoid 10-15s
    // thinking overhead on gemini-2.5-flash. OpenAI compat doesn't support it.
    // Native endpoint: POST /v1beta/models/{model}:generateContent
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(ROUTER_API_TIMEOUT_SECS))
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API returned {status}: {text}");
    }

    let json: serde_json::Value = resp.json().await?;

    // OpenAI chat completions format: choices[0].message.content
    json["choices"]
        .as_array()
        .and_then(|choices| choices.first())
        .and_then(|choice| choice["message"]["content"].as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("no text in API response"))
}

/// Parse an LLM response into a [`RouterDecision`].
///
/// Returns `None` if the text does not match any expected format.
pub fn parse_response(text: &str) -> Option<RouterDecision> {
    let text = text.trim();

    // ROUTE target1 [target2 ...]
    // Original message is passed through by the caller, not echoed by the LLM.
    if let Some(rest) = text.strip_prefix("ROUTE ") {
        // Strip optional trailing colon/message (LLM may still include one)
        let targets_part = rest.split_once(':').map_or(rest, |(t, _)| t);
        let targets: Vec<String> = targets_part
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if targets.is_empty() {
            return None;
        }
        return Some(RouterDecision::Route { targets });
    }

    // COMMAND /something
    if let Some(rest) = text.strip_prefix("COMMAND ") {
        let cmd = rest.trim().to_string();
        if !cmd.is_empty() {
            return Some(RouterDecision::Command(cmd));
        }
        return None;
    }

    // ANSWER: text
    if let Some(rest) = text.strip_prefix("ANSWER:") {
        let answer = rest.trim().to_string();
        if !answer.is_empty() {
            return Some(RouterDecision::DirectAnswer(answer));
        }
        return None;
    }

    None
}

/// Gather session and message snapshots for the router prompt.
pub async fn gather_context(
    state: &AppState,
    human_name: &str,
) -> (Vec<SessionSnapshot>, Vec<MessageSnapshot>) {
    let proto = state.protocol.read().await;
    let session_snapshots: Vec<SessionSnapshot> = proto
        .sessions
        .values()
        .filter(|s| s.id != human_name)
        .map(|s| SessionSnapshot {
            id: s.id.clone(),
            origin: origin_label(&s.origin),
            role: s.metadata.role.clone(),
            project_dir: s.metadata.project_dir.clone(),
            project_description: s.metadata.project_description.clone(),
            bulletin: s.metadata.bulletin.clone(),
        })
        .collect();
    drop(proto);

    let log = state.message_log.read().await;
    let message_snapshots: Vec<MessageSnapshot> = log
        .iter()
        .map(|e: &LogEntry| MessageSnapshot {
            timestamp: e.timestamp.format("%H:%M").to_string(),
            from: e.from.clone(),
            to: e.to.clone(),
            message: truncate(&e.message, MAX_MESSAGE_PREVIEW_LEN),
        })
        .collect();

    (session_snapshots, message_snapshots)
}

fn origin_label(origin: &Origin) -> String {
    match origin {
        Origin::Remote(d) => format!("remote/{d}"),
        other => other.label().to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_response ---

    #[test]
    fn parse_route_single_target() {
        let r = parse_response("ROUTE ouija");
        assert_eq!(
            r,
            Some(RouterDecision::Route {
                targets: vec!["ouija".into()],
            })
        );
    }

    #[test]
    fn parse_route_single_target_with_trailing_message() {
        // LLM may still include a message after colon — we ignore it
        let r = parse_response("ROUTE ouija: hello world");
        assert_eq!(
            r,
            Some(RouterDecision::Route {
                targets: vec!["ouija".into()],
            })
        );
    }

    #[test]
    fn parse_route_multiple_targets() {
        let r = parse_response("ROUTE web api");
        assert_eq!(
            r,
            Some(RouterDecision::Route {
                targets: vec!["web".into(), "api".into()],
            })
        );
    }

    #[test]
    fn parse_command() {
        let r = parse_response("COMMAND /list");
        assert_eq!(r, Some(RouterDecision::Command("/list".into())));
    }

    #[test]
    fn parse_answer() {
        let r = parse_response("ANSWER: It's 3pm UTC");
        assert_eq!(r, Some(RouterDecision::DirectAnswer("It's 3pm UTC".into())));
    }

    #[test]
    fn parse_empty_returns_none() {
        assert_eq!(parse_response(""), None);
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert_eq!(parse_response("I think you should send it to ouija"), None);
    }

    #[test]
    fn parse_route_no_targets_returns_none() {
        assert_eq!(parse_response("ROUTE : hello"), None);
    }

    #[test]
    fn parse_answer_empty_returns_none() {
        assert_eq!(parse_response("ANSWER:"), None);
        assert_eq!(parse_response("ANSWER:   "), None);
    }

    #[test]
    fn parse_with_surrounding_whitespace() {
        let r = parse_response("  ROUTE ouija  ");
        assert_eq!(
            r,
            Some(RouterDecision::Route {
                targets: vec!["ouija".into()],
            })
        );
    }

    // --- build_system_prompt ---

    #[test]
    fn prompt_includes_sessions() {
        let sessions = vec![SessionSnapshot {
            id: "web".into(),
            origin: "local".into(),
            role: Some("building frontend".into()),
            project_dir: Some("~/code/web".into()),
            project_description: Some("A web app".into()),
            bulletin: None,
        }];
        let prompt = build_system_prompt(&sessions, &[], "daniel");
        assert!(prompt.contains("web (local)"));
        assert!(prompt.contains("building frontend"));
        assert!(prompt.contains("~/code/web"));
        assert!(prompt.contains("A web app"));
        assert!(prompt.contains("daniel"));
    }

    #[test]
    fn prompt_handles_empty() {
        let prompt = build_system_prompt(&[], &[], "daniel");
        assert!(prompt.contains("(none)"));
        assert!(prompt.contains("(no recent messages)"));
    }

    #[test]
    fn prompt_includes_human_messages() {
        let messages = vec![
            MessageSnapshot {
                timestamp: "10:30".into(),
                from: "daniel".into(),
                to: "ouija".into(),
                message: "hello".into(),
            },
            MessageSnapshot {
                timestamp: "10:31".into(),
                from: "web".into(),
                to: "api".into(),
                message: "inter-session noise".into(),
            },
        ];
        let prompt = build_system_prompt(&[], &messages, "daniel");
        assert!(prompt.contains("<conversation_history>"));
        assert!(prompt.contains("[10:30] daniel -> ouija: hello"));
        assert!(prompt.contains("<inter_session_messages>"));
        assert!(prompt.contains("inter-session noise"));
    }

    #[test]
    fn prompt_includes_all_commands() {
        let prompt = build_system_prompt(&[], &[], "daniel");
        assert!(prompt.contains("/help"));
        assert!(prompt.contains("/list"));
        assert!(prompt.contains("COMMAND"));
        assert!(prompt.contains("/kill"));
        assert!(prompt.contains("/start"));
        assert!(prompt.contains("/restart"));
        assert!(prompt.contains("/nodes"));
    }
}
