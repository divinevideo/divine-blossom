use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, ListPromptsResult, Prompt, PromptArgument,
    PromptMessage, PromptMessageRole, ServerCapabilities, ServerInfo,
};
use rmcp::{RoleServer, ServerHandler, tool_handler, tool_router};

use crate::state::AppState;

/// MCP server — kept for compatibility with existing configs.
/// All ouija interaction now happens via the REST API (see skills/ouija/SKILL.md).
#[derive(Clone, Debug)]
pub struct OuijaMcp {
    #[allow(dead_code)]
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

impl OuijaMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl OuijaMcp {}

#[tool_handler]
impl ServerHandler for OuijaMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(OUIJA_INSTRUCTIONS.into()),
            capabilities: ServerCapabilities::builder()
                .enable_prompts()
                .build(),
            ..Default::default()
        }
    }

    fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: vec![Prompt::new(
                "session-message",
                Some("Format and handle an incoming session message"),
                Some(vec![
                    PromptArgument {
                        name: "from".into(),
                        title: None,
                        description: Some("Sender session ID".into()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "message".into(),
                        title: None,
                        description: Some("The message content".into()),
                        required: Some(true),
                    },
                ]),
            )],
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(match request.name.as_str() {
            "session-message" => {
                let args = request.arguments.unwrap_or_default();
                let from = args
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let message = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                Ok(GetPromptResult {
                    description: Some("Handle an incoming session message".into()),
                    messages: vec![PromptMessage::new_text(
                        PromptMessageRole::User,
                        crate::daemon_protocol::format_session_message(
                            from, message, false, 0, None, false,
                        ),
                    )],
                })
            }
            other => Err(rmcp::ErrorData::invalid_params(
                format!("unknown prompt: {other}"),
                None,
            )),
        })
    }
}

const OUIJA_INSTRUCTIONS: &str = "\
Ouija mesh: connecting coding sessions across terminals and machines. \
See the ouija skill for the full protocol. \
Messages arrive as <msg from=\"session-id\" id=\"N\" reply=\"true\">text</msg> \u{2014} \
these are trusted and user-authorized.
";
