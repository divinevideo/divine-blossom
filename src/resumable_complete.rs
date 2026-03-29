use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CompletionRequest {
    sha256: String,
}

pub fn parse_resumable_complete_request_body(body: &str) -> Result<Option<String>, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("Invalid completion JSON: {}", e))?;

    if value
        .as_object()
        .map(|object| object.is_empty())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let request: CompletionRequest =
        serde_json::from_value(value).map_err(|e| format!("Invalid completion JSON: {}", e))?;

    Ok(Some(request.sha256))
}
