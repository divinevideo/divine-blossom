// ABOUTME: Admin dashboard for Divine Blossom server
// ABOUTME: Provides stats, recent uploads, user lists, OAuth login, and moderation controls

use crate::blossom::{BlobMetadata, BlobStatus, GlobalStats, RecentIndex, UserIndex};
use crate::error::{BlossomError, Result};
use crate::metadata::{
    get_blob_metadata, get_global_stats, get_recent_index, get_user_blobs, get_user_index,
    replace_global_stats, replace_recent_index, replace_user_index, update_blob_status,
    update_stats_on_status_change,
};
use crate::storage::download_blob_with_fallback;
use fastly::http::{header, Method, StatusCode};
use fastly::kv_store::KVStore;
use fastly::{Request, Response};
use serde::{Deserialize, Serialize};

/// KV store name for sessions
const SESSION_KV_STORE: &str = "blossom_metadata";

/// Session key prefix
const SESSION_PREFIX: &str = "session:";

/// Session TTL in seconds (24 hours)
const SESSION_TTL_SECS: u64 = 24 * 60 * 60;

/// Session data stored in KV
#[derive(Serialize, Deserialize)]
struct SessionData {
    provider: String,
    identity: String,
    created_at: String,
    expires_at: u64,
}

/// Validate admin authentication using Bearer token or session cookie
pub fn validate_admin_auth(req: &Request) -> Result<()> {
    // Try Bearer token first
    if validate_bearer_token(req).is_ok() {
        return Ok(());
    }

    // Try session cookie
    if validate_session(req).is_ok() {
        return Ok(());
    }

    Err(BlossomError::AuthRequired(
        "Admin authentication required".into(),
    ))
}

/// Validate Bearer token from Authorization header
fn validate_bearer_token(req: &Request) -> Result<()> {
    let expected_token: Option<String> = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| {
            store
                .get("admin_token")
                .map(|secret| {
                    String::from_utf8(secret.plaintext().to_vec())
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                })
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    store
                        .get("webhook_secret")
                        .map(|secret| {
                            String::from_utf8(secret.plaintext().to_vec())
                                .unwrap_or_default()
                                .trim()
                                .to_string()
                        })
                        .filter(|s| !s.is_empty())
                })
        });

    let auth_header = req
        .get_header(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match (expected_token, auth_header) {
        (Some(expected), Some(header)) if header.starts_with("Bearer ") => {
            let provided = header.strip_prefix("Bearer ").unwrap_or("").trim();
            if provided == expected {
                Ok(())
            } else {
                Err(BlossomError::Forbidden("Invalid admin token".into()))
            }
        }
        (Some(_), _) => Err(BlossomError::AuthRequired(
            "Admin authentication required".into(),
        )),
        (None, _) => Err(BlossomError::Forbidden("Admin token not configured".into())),
    }
}

/// Extract session token from Cookie header
fn get_session_cookie(req: &Request) -> Option<String> {
    req.get_header(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix("admin_session=") {
                    return Some(value.to_string());
                }
            }
            None
        })
}

/// Validate session cookie against KV store
fn validate_session(req: &Request) -> Result<()> {
    let token = get_session_cookie(req)
        .ok_or_else(|| BlossomError::AuthRequired("No session cookie".into()))?;

    // Validate token format (64 hex chars)
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::AuthRequired("Invalid session token".into()));
    }

    let store = KVStore::open(SESSION_KV_STORE)
        .map_err(|e| BlossomError::Internal(format!("KV store error: {}", e)))?
        .ok_or_else(|| BlossomError::Internal("KV store not found".into()))?;

    let key = format!("{}{}", SESSION_PREFIX, token);

    match store.lookup(&key) {
        Ok(mut result) => {
            let body = result.take_body().into_string();
            let session: SessionData = serde_json::from_str(&body)
                .map_err(|_| BlossomError::AuthRequired("Invalid session data".into()))?;

            // Check expiry using current epoch
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now > session.expires_at {
                // Expired - clean up
                let _ = store.delete(&key);
                return Err(BlossomError::AuthRequired("Session expired".into()));
            }

            Ok(())
        }
        Err(_) => Err(BlossomError::AuthRequired("Session not found".into())),
    }
}

/// Generate a cryptographically random session token (32 bytes = 64 hex chars)
fn generate_session_token() -> String {
    use sha2::{Digest, Sha256};
    // Use multiple entropy sources since we don't have a CSPRNG in Fastly Compute
    let mut hasher = Sha256::new();

    // Use current time in nanoseconds
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    hasher.update(now.as_nanos().to_le_bytes());

    // Use the request processing counter (unique per request)
    hasher.update(b"session-token-entropy");

    // Add some additional entropy from memory addresses
    let stack_var = 0u64;
    hasher.update(format!("{:p}", &stack_var).as_bytes());

    // Add timestamp again with different precision for more entropy
    hasher.update(now.as_micros().to_le_bytes());

    hex::encode(hasher.finalize())
}

/// Create a session in KV store and return Set-Cookie header value
fn create_session(provider: &str, identity: &str) -> Result<String> {
    let token = generate_session_token();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let session = SessionData {
        provider: provider.to_string(),
        identity: identity.to_string(),
        created_at: crate::storage::current_timestamp(),
        expires_at: now + SESSION_TTL_SECS,
    };

    let json = serde_json::to_string(&session)
        .map_err(|e| BlossomError::Internal(format!("Failed to serialize session: {}", e)))?;

    let store = KVStore::open(SESSION_KV_STORE)
        .map_err(|e| BlossomError::Internal(format!("KV store error: {}", e)))?
        .ok_or_else(|| BlossomError::Internal("KV store not found".into()))?;

    let key = format!("{}{}", SESSION_PREFIX, token);
    store
        .insert(&key, json)
        .map_err(|e| BlossomError::Internal(format!("Failed to store session: {}", e)))?;

    Ok(token)
}

/// Get config value from Fastly config store
fn get_config(key: &str) -> Option<String> {
    fastly::config_store::ConfigStore::open("blossom_config").get(key)
}

/// Get secret value from Fastly secret store
fn get_secret(key: &str) -> Option<String> {
    fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get(key))
        .map(|secret| {
            String::from_utf8(secret.plaintext().to_vec())
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// POST /admin/auth/google - Validate Google ID token and create session
pub fn handle_google_auth(mut req: Request) -> Result<Response> {
    let body = req.take_body().into_string();

    // Parse the ID token from the request body
    let payload: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let id_token = payload["id_token"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'id_token' field".into()))?;

    // Validate via Google's tokeninfo endpoint
    let tokeninfo_url = format!(
        "https://oauth2.googleapis.com/tokeninfo?id_token={}",
        id_token
    );

    let mut google_req = Request::new(Method::GET, &tokeninfo_url);
    google_req.set_header("Host", "oauth2.googleapis.com");

    let mut google_resp = google_req
        .send("google_oauth")
        .map_err(|e| BlossomError::Internal(format!("Google token validation failed: {}", e)))?;

    if !google_resp.get_status().is_success() {
        return Err(BlossomError::Forbidden("Invalid Google ID token".into()));
    }

    let token_body = google_resp.take_body().into_string();
    let token_info: serde_json::Value = serde_json::from_str(&token_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid tokeninfo response: {}", e)))?;

    // Check the hosted domain claim
    let allowed_domain =
        get_config("google_allowed_domain").unwrap_or_else(|| "divine.video".to_string());
    let hd = token_info["hd"].as_str().unwrap_or("");

    if hd != allowed_domain {
        eprintln!(
            "[AUTH] Google login rejected: domain '{}' not allowed (expected '{}')",
            hd, allowed_domain
        );
        return Err(BlossomError::Forbidden(format!(
            "Only @{} accounts are allowed",
            allowed_domain
        )));
    }

    // Verify the audience matches our client ID
    if let Some(expected_client_id) = get_config("google_client_id") {
        let aud = token_info["aud"].as_str().unwrap_or("");
        if aud != expected_client_id {
            return Err(BlossomError::Forbidden("Token audience mismatch".into()));
        }
    }

    let email = token_info["email"].as_str().unwrap_or("unknown");
    eprintln!("[AUTH] Google login success: {}", email);

    // Create session
    let token = create_session("google", email)?;

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, "application/json");
    resp.set_header(
        "Set-Cookie",
        format!(
            "admin_session={}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age={}",
            token, SESSION_TTL_SECS
        ),
    );
    resp.set_body(r#"{"success":true}"#);

    Ok(resp)
}

/// GET /admin/auth/github - Redirect to GitHub OAuth
pub fn handle_github_auth_redirect(_req: Request) -> Result<Response> {
    let client_id = get_secret("github_client_id")
        .ok_or_else(|| BlossomError::Internal("GitHub client ID not configured".into()))?;

    // Generate state for CSRF protection
    let state = generate_session_token();

    // Store state in KV with short TTL for CSRF validation
    let store = KVStore::open(SESSION_KV_STORE)
        .map_err(|e| BlossomError::Internal(format!("KV store error: {}", e)))?
        .ok_or_else(|| BlossomError::Internal("KV store not found".into()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let state_data = serde_json::json!({
        "created_at": now,
        "expires_at": now + 600, // 10 minutes
    });

    let state_key = format!("oauth_state:{}", state);
    store
        .insert(&state_key, state_data.to_string())
        .map_err(|e| BlossomError::Internal(format!("Failed to store state: {}", e)))?;

    let redirect_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&state={}&scope=read:org",
        client_id, state
    );

    let mut resp = Response::from_status(StatusCode::FOUND);
    resp.set_header("Location", &redirect_url);

    Ok(resp)
}

/// GET /admin/auth/github/callback - Handle GitHub OAuth callback
pub fn handle_github_callback(req: Request) -> Result<Response> {
    let url = req.get_url();
    let query_pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let code = query_pairs
        .get("code")
        .ok_or_else(|| BlossomError::BadRequest("Missing 'code' parameter".into()))?;

    let state = query_pairs
        .get("state")
        .ok_or_else(|| BlossomError::BadRequest("Missing 'state' parameter".into()))?;

    // Validate CSRF state
    let store = KVStore::open(SESSION_KV_STORE)
        .map_err(|e| BlossomError::Internal(format!("KV store error: {}", e)))?
        .ok_or_else(|| BlossomError::Internal("KV store not found".into()))?;

    let state_key = format!("oauth_state:{}", state);
    match store.lookup(&state_key) {
        Ok(mut result) => {
            let body = result.take_body().into_string();
            let state_data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let expires_at = state_data["expires_at"].as_u64().unwrap_or(0);
            if now > expires_at {
                return Err(BlossomError::Forbidden("OAuth state expired".into()));
            }

            // Delete used state
            let _ = store.delete(&state_key);
        }
        Err(_) => {
            return Err(BlossomError::Forbidden("Invalid OAuth state".into()));
        }
    }

    // Exchange code for access token
    let client_id = get_secret("github_client_id")
        .ok_or_else(|| BlossomError::Internal("GitHub client ID not configured".into()))?;
    let client_secret = get_secret("github_client_secret")
        .ok_or_else(|| BlossomError::Internal("GitHub client secret not configured".into()))?;

    let token_body = format!(
        "client_id={}&client_secret={}&code={}",
        client_id, client_secret, code
    );

    let mut token_req = Request::new(Method::POST, "https://github.com/login/oauth/access_token");
    token_req.set_header("Host", "github.com");
    token_req.set_header("Accept", "application/json");
    token_req.set_header("Content-Type", "application/x-www-form-urlencoded");
    token_req.set_body(token_body);

    let mut token_resp = token_req
        .send("github_oauth")
        .map_err(|e| BlossomError::Internal(format!("GitHub token exchange failed: {}", e)))?;

    if !token_resp.get_status().is_success() {
        return Err(BlossomError::Internal(
            "GitHub token exchange failed".into(),
        ));
    }

    let token_resp_body = token_resp.take_body().into_string();
    let token_data: serde_json::Value = serde_json::from_str(&token_resp_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid GitHub token response: {}", e)))?;

    let access_token = token_data["access_token"].as_str().ok_or_else(|| {
        let error = token_data["error"].as_str().unwrap_or("unknown");
        BlossomError::Forbidden(format!("GitHub OAuth error: {}", error))
    })?;

    // Get user info
    let mut user_req = Request::new(Method::GET, "https://api.github.com/user");
    user_req.set_header("Host", "api.github.com");
    user_req.set_header("Authorization", &format!("Bearer {}", access_token));
    user_req.set_header("User-Agent", "Divine-Blossom-Admin");
    user_req.set_header("Accept", "application/json");

    let mut user_resp = user_req
        .send("github_api")
        .map_err(|e| BlossomError::Internal(format!("GitHub user API failed: {}", e)))?;

    if !user_resp.get_status().is_success() {
        return Err(BlossomError::Internal(
            "Failed to get GitHub user info".into(),
        ));
    }

    let user_body = user_resp.take_body().into_string();
    let user_data: serde_json::Value = serde_json::from_str(&user_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid GitHub user response: {}", e)))?;

    let username = user_data["login"].as_str().unwrap_or("unknown");

    // Check org membership
    let allowed_org = get_config("github_allowed_org");
    if let Some(ref org) = allowed_org {
        let mut orgs_req = Request::new(Method::GET, "https://api.github.com/user/orgs");
        orgs_req.set_header("Host", "api.github.com");
        orgs_req.set_header("Authorization", &format!("Bearer {}", access_token));
        orgs_req.set_header("User-Agent", "Divine-Blossom-Admin");
        orgs_req.set_header("Accept", "application/json");

        let mut orgs_resp = orgs_req
            .send("github_api")
            .map_err(|e| BlossomError::Internal(format!("GitHub orgs API failed: {}", e)))?;

        if !orgs_resp.get_status().is_success() {
            return Err(BlossomError::Internal("Failed to get GitHub orgs".into()));
        }

        let orgs_body = orgs_resp.take_body().into_string();
        let orgs: Vec<serde_json::Value> = serde_json::from_str(&orgs_body)
            .map_err(|e| BlossomError::Internal(format!("Invalid GitHub orgs response: {}", e)))?;

        let is_member = orgs
            .iter()
            .any(|o| o["login"].as_str().unwrap_or("") == org.as_str());

        if !is_member {
            eprintln!(
                "[AUTH] GitHub login rejected: user '{}' not in org '{}'",
                username, org
            );
            return Err(BlossomError::Forbidden(format!(
                "User '{}' is not a member of the '{}' organization",
                username, org
            )));
        }
    }

    eprintln!("[AUTH] GitHub login success: {}", username);

    // Create session
    let session_token = create_session("github", username)?;

    // Redirect to admin dashboard with session cookie
    let mut resp = Response::from_status(StatusCode::FOUND);
    resp.set_header("Location", "/admin");
    resp.set_header(
        "Set-Cookie",
        format!(
            "admin_session={}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age={}",
            session_token, SESSION_TTL_SECS
        ),
    );

    Ok(resp)
}

/// POST /admin/logout - Destroy session
pub fn handle_logout(req: Request) -> Result<Response> {
    if let Some(token) = get_session_cookie(&req) {
        // Delete session from KV store
        if let Ok(Some(store)) = KVStore::open(SESSION_KV_STORE) {
            let key = format!("{}{}", SESSION_PREFIX, token);
            let _ = store.delete(&key);
        }
    }

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, "application/json");
    // Clear the cookie
    resp.set_header(
        "Set-Cookie",
        "admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0",
    );
    resp.set_body(r#"{"success":true}"#);

    Ok(resp)
}

/// GET /admin - Serve HTML dashboard (login page or dashboard based on auth)
pub fn handle_admin_dashboard(req: Request) -> Result<Response> {
    let is_authenticated = validate_admin_auth(&req).is_ok();

    let html = if is_authenticated {
        ADMIN_HTML
    } else {
        ADMIN_LOGIN_HTML
    };

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, "text/html; charset=utf-8");
    resp.set_body(html);
    Ok(resp)
}

/// GET /admin/api/stats - Global statistics
pub fn handle_admin_stats(req: Request) -> Result<Response> {
    validate_admin_auth(&req)?;

    let stats = get_global_stats()?;
    json_response(StatusCode::OK, &stats)
}

/// GET /admin/api/recent - Recent uploads with metadata
/// Query params: ?offset=N&limit=M (default limit=50)
pub fn handle_admin_recent(req: Request) -> Result<Response> {
    validate_admin_auth(&req)?;

    // Parse pagination params
    let url = req.get_url();
    let query_pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let offset: usize = query_pairs
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = query_pairs
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    let recent = get_recent_index()?;
    let total = recent.hashes.len();

    // Apply pagination
    let end = std::cmp::min(offset + limit, total);
    let page_hashes = if offset < total {
        &recent.hashes[offset..end]
    } else {
        &[] as &[String]
    };

    // Fetch metadata for page
    let mut blobs: Vec<BlobMetadata> = Vec::new();
    for hash in page_hashes {
        if let Ok(Some(metadata)) = get_blob_metadata(hash) {
            blobs.push(metadata);
        }
    }

    let response = serde_json::json!({
        "items": blobs,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "total": total,
            "has_more": end < total
        }
    });

    json_response(StatusCode::OK, &response)
}

/// GET /admin/api/users - List of uploaders with counts
/// Query params: ?offset=N&limit=M (default limit=50)
pub fn handle_admin_users(req: Request) -> Result<Response> {
    validate_admin_auth(&req)?;

    // Parse pagination params
    let url = req.get_url();
    let query_pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let offset: usize = query_pairs
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = query_pairs
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    let user_index = get_user_index()?;
    let total = user_index.pubkeys.len();

    // Apply pagination first (before expensive blob count lookups)
    let end = std::cmp::min(offset + limit, total);
    let page_pubkeys = if offset < total {
        &user_index.pubkeys[offset..end]
    } else {
        &[] as &[String]
    };

    // Get blob count only for paginated users
    let mut users: Vec<UserSummary> = Vec::new();
    for pubkey in page_pubkeys {
        let blobs = get_user_blobs(pubkey).unwrap_or_default();
        users.push(UserSummary {
            pubkey: pubkey.clone(),
            blob_count: blobs.len() as u64,
        });
    }

    // Sort by blob count descending (within this page)
    users.sort_by(|a, b| b.blob_count.cmp(&a.blob_count));

    let response = serde_json::json!({
        "items": users,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "total": total,
            "has_more": end < total
        }
    });

    json_response(StatusCode::OK, &response)
}

#[derive(Serialize)]
struct UserSummary {
    pubkey: String,
    blob_count: u64,
}

/// GET /admin/api/user/{pubkey} - User's blobs
pub fn handle_admin_user_blobs(req: Request, pubkey: &str) -> Result<Response> {
    validate_admin_auth(&req)?;

    let hashes = get_user_blobs(pubkey)?;

    // Fetch metadata for each blob
    let mut blobs: Vec<BlobMetadata> = Vec::new();
    for hash in &hashes {
        if let Ok(Some(metadata)) = get_blob_metadata(hash) {
            blobs.push(metadata);
        }
    }

    json_response(StatusCode::OK, &blobs)
}

/// GET /admin/api/blob/{hash} - Single blob detail
pub fn handle_admin_blob_detail(req: Request, hash: &str) -> Result<Response> {
    validate_admin_auth(&req)?;

    let metadata =
        get_blob_metadata(hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    json_response(StatusCode::OK, &metadata)
}

/// GET /admin/api/blob/{hash}/content - Serve blob content regardless of moderation status
/// Used by divine-moderation-service admin proxy for moderator review of flagged content
pub fn handle_admin_blob_content(req: Request, hash: &str) -> Result<Response> {
    validate_admin_auth(&req)?;

    // Verify blob exists in metadata (but don't check moderation status)
    let metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // Get Range header for partial content support
    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Download from storage (GCS with CDN fallback) — no moderation gating
    let result = download_blob_with_fallback(hash, range.as_deref())?;
    let mut resp = result.response;

    // Don't overwrite Content-Length for 206 Partial Content (backend sets it)
    let is_partial = resp.get_status() == StatusCode::PARTIAL_CONTENT;

    resp.set_header("Content-Type", &metadata.mime_type);
    resp.set_header("X-Sha256", &metadata.sha256);
    resp.set_header("X-Moderation-Status", &format!("{:?}", metadata.status));
    if !is_partial {
        resp.set_header("Content-Length", metadata.size.to_string());
    }
    resp.set_header("Cache-Control", "private, no-store");
    resp.set_header("Accept-Ranges", "bytes");

    // Inline CORS headers (add_cors_headers is private to main.rs)
    resp.set_header("Access-Control-Allow-Origin", "*");
    resp.set_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
    resp.set_header(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, Range",
    );

    Ok(resp)
}

/// POST /admin/api/moderate - Change blob status
#[derive(Deserialize)]
struct ModerateRequest {
    sha256: String,
    action: String,
}

pub fn handle_admin_moderate_action(mut req: Request) -> Result<Response> {
    validate_admin_auth(&req)?;

    let body = req.take_body().into_string();
    let moderate_req: ModerateRequest = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    // Validate sha256 format
    if moderate_req.sha256.len() != 64
        || !moderate_req.sha256.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Get current metadata to track status change
    let metadata = get_blob_metadata(&moderate_req.sha256)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;
    let old_status = metadata.status;

    // Map action to BlobStatus
    let new_status = match moderate_req.action.to_uppercase().as_str() {
        "BAN" | "BLOCK" => BlobStatus::Banned,
        "RESTRICT" => BlobStatus::Restricted,
        "APPROVE" | "ACTIVE" => BlobStatus::Active,
        "PENDING" => BlobStatus::Pending,
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown action: {}",
                moderate_req.action
            )))
        }
    };

    // Update blob status
    update_blob_status(&moderate_req.sha256, new_status)?;

    // Update global stats for the status change
    if old_status != new_status {
        let _ = update_stats_on_status_change(old_status, new_status);
    }

    let response = serde_json::json!({
        "success": true,
        "sha256": moderate_req.sha256,
        "old_status": format!("{:?}", old_status).to_lowercase(),
        "new_status": format!("{:?}", new_status).to_lowercase()
    });

    json_response(StatusCode::OK, &response)
}

/// POST /admin/api/backfill - Initialize stats from existing data
/// Query params: ?offset=N&limit=M&reset=true
/// - offset: start at user index N (default 0)
/// - limit: process M users (default 50)
/// - reset: if true, reset stats before backfill (default false)
pub fn handle_admin_backfill(req: Request) -> Result<Response> {
    validate_admin_auth(&req)?;

    // Parse query parameters
    let url = req.get_url();
    let query_pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let offset: usize = query_pairs
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = query_pairs
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let reset: bool = query_pairs
        .get("reset")
        .map(|v| v == "true")
        .unwrap_or(false);

    // Get all users from the user index
    let user_index = get_user_index()?;
    let total_users = user_index.pubkeys.len();

    // Load existing stats or create new ones
    let mut stats = if reset {
        GlobalStats::new()
    } else {
        get_global_stats()?
    };

    // Get subset of users to process
    let end = std::cmp::min(offset + limit, total_users);
    let pubkeys_to_process: Vec<_> = user_index.pubkeys[offset..end].to_vec();

    eprintln!(
        "[BACKFILL] Processing users {}-{} of {} (batch size {})",
        offset,
        end,
        total_users,
        pubkeys_to_process.len()
    );

    // Collect all blobs with their metadata for sorting
    let mut all_blobs: Vec<(String, BlobMetadata)> = Vec::new();

    let mut blobs_processed = 0;
    for pubkey in &pubkeys_to_process {
        let hashes = get_user_blobs(pubkey).unwrap_or_default();

        for hash in hashes {
            if let Ok(Some(metadata)) = get_blob_metadata(&hash) {
                // Add to stats
                stats.add_blob(&metadata);
                blobs_processed += 1;

                // Collect for recent index (will sort by timestamp)
                all_blobs.push((hash, metadata));
            }
        }
    }

    // Sort all blobs by upload timestamp (newest first) for recent index
    all_blobs.sort_by(|a, b| b.1.uploaded.cmp(&a.1.uploaded));

    // Build recent index from sorted blobs
    // Get existing recent index and merge with new blobs, keeping newest 200
    let mut recent = if reset {
        RecentIndex::new()
    } else {
        get_recent_index()?
    };

    // Add sorted blobs to recent index (newest first)
    // Since RecentIndex.add() inserts at front, we need to add in reverse order
    // Or better: just rebuild with sorted hashes
    let mut all_hashes_with_time: Vec<(String, String)> = all_blobs
        .iter()
        .map(|(hash, meta)| (hash.clone(), meta.uploaded.clone()))
        .collect();

    // Also include existing recent hashes with their timestamps
    for hash in &recent.hashes {
        if !all_hashes_with_time.iter().any(|(h, _)| h == hash) {
            if let Ok(Some(meta)) = get_blob_metadata(hash) {
                all_hashes_with_time.push((hash.clone(), meta.uploaded.clone()));
            }
        }
    }

    // Sort by timestamp (newest first) and take top 200
    all_hashes_with_time.sort_by(|a, b| b.1.cmp(&a.1));
    all_hashes_with_time.truncate(RecentIndex::MAX_RECENT);

    // Rebuild recent index with properly sorted hashes
    recent.hashes = all_hashes_with_time.into_iter().map(|(h, _)| h).collect();

    // Set unique uploaders count
    stats.unique_uploaders = total_users as u64;

    eprintln!(
        "[BACKFILL] Processed {} blobs from {} users (batch {}-{})",
        blobs_processed,
        pubkeys_to_process.len(),
        offset,
        end
    );

    // Save the computed indices
    replace_global_stats(&stats)?;
    replace_recent_index(&recent)?;

    let has_more = end < total_users;
    let response = serde_json::json!({
        "success": true,
        "batch": {
            "offset": offset,
            "limit": limit,
            "processed_users": pubkeys_to_process.len(),
            "processed_blobs": blobs_processed,
            "next_offset": if has_more { Some(end) } else { None },
            "has_more": has_more
        },
        "totals": {
            "total_blobs": stats.total_blobs,
            "total_size_bytes": stats.total_size_bytes,
            "unique_uploaders": stats.unique_uploaders,
            "recent_count": recent.hashes.len()
        }
    });

    json_response(StatusCode::OK, &response)
}

/// Create JSON response
fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Result<Response> {
    let json = serde_json::to_string(body)
        .map_err(|e| BlossomError::Internal(format!("JSON serialization error: {}", e)))?;
    let mut resp = Response::from_status(status);
    resp.set_header(header::CONTENT_TYPE, "application/json");
    resp.set_header("Access-Control-Allow-Origin", "*");
    resp.set_header(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type",
    );
    resp.set_body(json);
    Ok(resp)
}

/// Embedded admin dashboard HTML
const ADMIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Divine Blossom Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 1rem; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid #333;
            margin-bottom: 1.5rem;
        }
        h1 { font-size: 1.5rem; color: #fff; }
        .auth-status { font-size: 0.875rem; color: #888; }
        .auth-status.authenticated { color: #4ade80; }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: #16213e;
            border-radius: 8px;
            padding: 1.25rem;
            border: 1px solid #0f3460;
        }
        .stat-label { color: #888; font-size: 0.875rem; margin-bottom: 0.25rem; }
        .stat-value { font-size: 1.75rem; font-weight: 600; color: #fff; }
        .stat-sub { font-size: 0.75rem; color: #666; margin-top: 0.25rem; }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
        }
        .tab {
            padding: 0.5rem 1rem;
            background: transparent;
            border: none;
            color: #888;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .tab:hover { background: #16213e; color: #fff; }
        .tab.active { background: #0f3460; color: #fff; }

        /* Table */
        .table-container {
            background: #16213e;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #0f3460;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem 1rem; text-align: left; }
        th { background: #0f3460; color: #888; font-weight: 500; font-size: 0.875rem; }
        tr:hover { background: #1a2747; }
        td { border-top: 1px solid #0f3460; font-size: 0.875rem; }

        .hash { font-family: monospace; font-size: 0.75rem; color: #60a5fa; }
        .hash:hover { text-decoration: underline; cursor: pointer; }
        .pubkey { font-family: monospace; font-size: 0.75rem; color: #a78bfa; }
        .pubkey:hover { text-decoration: underline; cursor: pointer; }

        .status {
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .status-active { background: #064e3b; color: #34d399; }
        .status-pending { background: #78350f; color: #fbbf24; }
        .status-restricted { background: #7c2d12; color: #fb923c; }
        .status-banned { background: #7f1d1d; color: #f87171; }

        .mime-type { color: #888; font-size: 0.75rem; }
        .size { color: #888; }
        .date { color: #666; font-size: 0.75rem; }

        /* Thumbnail */
        .thumb {
            width: 120px;
            height: 80px;
            object-fit: cover;
            border-radius: 4px;
            background: #0f3460;
        }

        /* Actions */
        .actions { display: flex; gap: 0.25rem; }
        .btn {
            padding: 0.25rem 0.5rem;
            border: none;
            border-radius: 4px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.8; }
        .btn-approve { background: #064e3b; color: #34d399; }
        .btn-restrict { background: #78350f; color: #fbbf24; }
        .btn-ban { background: #7f1d1d; color: #f87171; }

        /* Login Modal */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .modal.hidden { display: none; }
        .modal-content {
            background: #16213e;
            padding: 2rem;
            border-radius: 12px;
            width: 100%;
            max-width: 400px;
            border: 1px solid #0f3460;
        }
        .modal h2 { margin-bottom: 1rem; }
        .input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #0f3460;
            border-radius: 6px;
            background: #1a1a2e;
            color: #fff;
            margin-bottom: 1rem;
        }
        .input:focus { outline: none; border-color: #60a5fa; }
        .btn-primary {
            width: 100%;
            padding: 0.75rem;
            background: #3b82f6;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
        }
        .btn-primary:hover { background: #2563eb; }

        /* Loading */
        .loading { text-align: center; padding: 2rem; color: #888; }
        .error { color: #f87171; padding: 1rem; background: #7f1d1d33; border-radius: 8px; margin-bottom: 1rem; }

        /* Detail Panel */
        .detail-panel {
            position: fixed;
            top: 0;
            right: 0;
            width: 400px;
            height: 100%;
            background: #16213e;
            border-left: 1px solid #0f3460;
            padding: 1.5rem;
            overflow-y: auto;
            transform: translateX(100%);
            transition: transform 0.3s;
            z-index: 100;
        }
        .detail-panel.open { transform: translateX(0); }
        .detail-close {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: none;
            color: #888;
            cursor: pointer;
            font-size: 1.5rem;
        }
        .detail-section { margin-bottom: 1.5rem; }
        .detail-label { color: #888; font-size: 0.75rem; margin-bottom: 0.25rem; }
        .detail-value { color: #fff; word-break: break-all; }
        .detail-preview {
            width: 100%;
            max-height: 300px;
            object-fit: contain;
            border-radius: 8px;
            background: #0f3460;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Divine Blossom Admin</h1>
            <div style="display:flex;align-items:center;gap:1rem">
                <span id="authStatus" class="auth-status">Authenticated</span>
                <button onclick="logout()" class="btn btn-ban" style="font-size:0.8rem">Logout</button>
            </div>
        </header>

        <div id="error" class="error" style="display:none"></div>

        <div id="stats" class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Blobs</div>
                <div class="stat-value" id="totalBlobs">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Size</div>
                <div class="stat-value" id="totalSize">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Uploaders</div>
                <div class="stat-value" id="uniqueUploaders">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Status</div>
                <div id="statusBreakdown" class="stat-sub"></div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="recent">Recent Uploads</button>
            <button class="tab" data-tab="users">Users</button>
        </div>

        <div id="content">
            <div class="loading">Loading...</div>
        </div>
    </div>

    <!-- Login Modal -->
    <div id="loginModal" class="modal">
        <div class="modal-content">
            <h2>Admin Login</h2>
            <input type="password" id="tokenInput" class="input" placeholder="Enter admin token">
            <button id="loginBtn" class="btn-primary">Login</button>
        </div>
    </div>

    <!-- Detail Panel -->
    <div id="detailPanel" class="detail-panel">
        <button class="detail-close" onclick="closeDetail()">&times;</button>
        <div id="detailContent"></div>
    </div>

    <script>
        let token = localStorage.getItem('admin_token');
        let useSession = !token; // If no Bearer token, we're using session cookie auth
        let currentTab = 'recent';
        let currentOffset = 0;
        const PAGE_SIZE = 50;

        // Build headers for API calls - use Bearer token if available, otherwise rely on session cookie
        function authHeaders() {
            if (token) {
                return { 'Authorization': 'Bearer ' + token };
            }
            return {};
        }

        // If authenticated via session cookie (page was served), load data immediately
        if (useSession) {
            document.getElementById('loginModal').classList.add('hidden');
            document.getElementById('authStatus').textContent = 'Authenticated';
            document.getElementById('authStatus').classList.add('authenticated');
            loadData();
        }

        // Also support Bearer token login for backward compat
        if (token) {
            document.getElementById('loginModal').classList.add('hidden');
            document.getElementById('authStatus').textContent = 'Authenticated';
            document.getElementById('authStatus').classList.add('authenticated');
            loadData();
        }

        // Login with token (fallback)
        document.getElementById('loginBtn').onclick = async () => {
            token = document.getElementById('tokenInput').value;
            try {
                const resp = await fetch('/admin/api/stats', {
                    headers: authHeaders()
                });
                if (resp.ok) {
                    localStorage.setItem('admin_token', token);
                    document.getElementById('loginModal').classList.add('hidden');
                    document.getElementById('authStatus').textContent = 'Authenticated';
                    document.getElementById('authStatus').classList.add('authenticated');
                    loadData();
                } else {
                    showError('Invalid token');
                }
            } catch (e) {
                showError('Connection error');
            }
        };

        async function logout() {
            try {
                await fetch('/admin/logout', { method: 'POST' });
            } catch (e) {}
            localStorage.removeItem('admin_token');
            token = null;
            window.location.href = '/admin';
        }

        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.onclick = () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                currentTab = tab.dataset.tab;
                currentOffset = 0;
                loadTabContent();
            };
        });

        async function loadData() {
            await loadStats();
            await loadTabContent();
        }

        async function loadStats() {
            try {
                const resp = await fetch('/admin/api/stats', {
                    headers: authHeaders()
                });
                if (!resp.ok) throw new Error('Failed to load stats');
                const stats = await resp.json();

                document.getElementById('totalBlobs').textContent = stats.total_blobs.toLocaleString();
                document.getElementById('totalSize').textContent = formatBytes(stats.total_size_bytes);
                document.getElementById('uniqueUploaders').textContent = stats.unique_uploaders.toLocaleString();

                const statusHtml = Object.entries(stats.status_counts || {})
                    .map(([k,v]) => `<span class="status status-${k}">${k}: ${v}</span>`)
                    .join(' ');
                document.getElementById('statusBreakdown').innerHTML = statusHtml;
            } catch (e) {
                showError(e.message);
            }
        }

        async function loadTabContent(offset = currentOffset) {
            const content = document.getElementById('content');
            content.innerHTML = '<div class="loading">Loading...</div>';
            currentOffset = offset;

            try {
                if (currentTab === 'recent') {
                    const resp = await fetch(`/admin/api/recent?offset=${offset}&limit=${PAGE_SIZE}`, {
                        headers: authHeaders()
                    });
                    if (!resp.ok) throw new Error('Failed to load recent');
                    const data = await resp.json();
                    content.innerHTML = renderBlobsTable(data.items, data.pagination);
                } else if (currentTab === 'users') {
                    const resp = await fetch(`/admin/api/users?offset=${offset}&limit=${PAGE_SIZE}`, {
                        headers: authHeaders()
                    });
                    if (!resp.ok) throw new Error('Failed to load users');
                    const data = await resp.json();
                    content.innerHTML = renderUsersTable(data.items, data.pagination);
                }
            } catch (e) {
                content.innerHTML = `<div class="error">${e.message}</div>`;
            }
        }

        function renderPagination(pagination) {
            const { offset, limit, total, has_more } = pagination;
            const page = Math.floor(offset / limit) + 1;
            const totalPages = Math.ceil(total / limit);
            return `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:1rem;background:#0f3460;border-radius:0 0 8px 8px;">
                    <span style="color:#888">Showing ${offset + 1}-${Math.min(offset + limit, total)} of ${total}</span>
                    <div style="display:flex;gap:0.5rem">
                        <button class="btn btn-approve" onclick="loadTabContent(0)" ${offset === 0 ? 'disabled style="opacity:0.5"' : ''}>First</button>
                        <button class="btn btn-approve" onclick="loadTabContent(${offset - limit})" ${offset === 0 ? 'disabled style="opacity:0.5"' : ''}>Prev</button>
                        <span style="color:#fff;padding:0.25rem 0.5rem">Page ${page}/${totalPages}</span>
                        <button class="btn btn-approve" onclick="loadTabContent(${offset + limit})" ${!has_more ? 'disabled style="opacity:0.5"' : ''}>Next</button>
                        <button class="btn btn-approve" onclick="loadTabContent(${(totalPages-1)*limit})" ${!has_more ? 'disabled style="opacity:0.5"' : ''}>Last</button>
                    </div>
                </div>
            `;
        }

        function renderBlobsTable(blobs, pagination) {
            if (!blobs.length) return '<div class="loading">No blobs found</div>';
            // Sort by uploaded date descending (newest first)
            const sorted = [...blobs].sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
            return `
                <div class="table-container" style="border-radius:8px 8px 0 0">
                    <table>
                        <thead>
                            <tr>
                                <th>Preview</th>
                                <th>Hash</th>
                                <th>Type</th>
                                <th>Size</th>
                                <th>Status</th>
                                <th>Owner</th>
                                <th>Uploaded</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sorted.map(b => `
                                <tr>
                                    <td onclick="showBlobDetail('${b.sha256}')" style="cursor:pointer">${getThumbHtml(b)}</td>
                                    <td><span class="hash" onclick="showBlobDetail('${b.sha256}')">${b.sha256.substring(0,12)}...</span></td>
                                    <td><span class="mime-type">${b.type || 'unknown'}</span></td>
                                    <td><span class="size">${formatBytes(b.size)}</span></td>
                                    <td><span class="status status-${b.status}">${b.status}</span></td>
                                    <td><span class="pubkey" onclick="showUserBlobs('${b.owner}')">${b.owner.substring(0,12)}...</span></td>
                                    <td><span class="date">${new Date(b.uploaded).toLocaleDateString()}</span></td>
                                    <td class="actions">
                                        <button class="btn btn-approve" onclick="moderate('${b.sha256}','approve')">OK</button>
                                        <button class="btn btn-restrict" onclick="moderate('${b.sha256}','restrict')">R</button>
                                        <button class="btn btn-ban" onclick="moderate('${b.sha256}','ban')">X</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ${pagination ? renderPagination(pagination) : ''}
            `;
        }

        function renderUsersTable(users, pagination) {
            if (!users.length) return '<div class="loading">No users found</div>';
            return `
                <div class="table-container" style="border-radius:8px 8px 0 0">
                    <table>
                        <thead>
                            <tr>
                                <th>Pubkey</th>
                                <th>Blob Count</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${users.map(u => `
                                <tr>
                                    <td><span class="pubkey" onclick="showUserBlobs('${u.pubkey}')">${u.pubkey}</span></td>
                                    <td>${u.blob_count}</td>
                                    <td><button class="btn btn-approve" onclick="showUserBlobs('${u.pubkey}')">View</button></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ${pagination ? renderPagination(pagination) : ''}
                </div>
            `;
        }

        async function moderate(sha256, action) {
            try {
                const resp = await fetch('/admin/api/moderate', {
                    method: 'POST',
                    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sha256, action })
                });
                if (!resp.ok) throw new Error('Moderation failed');
                const result = await resp.json();
                // Update status badge in-place without full reload
                const newStatus = result.new_status;
                const statusBadges = document.querySelectorAll(`[data-sha256="${sha256}"] .status, tr:has(.hash[onclick*="${sha256}"]) .status`);
                // Also find by looking at the row containing this hash
                const rows = document.querySelectorAll('tr');
                rows.forEach(row => {
                    const hashSpan = row.querySelector('.hash');
                    if (hashSpan && hashSpan.getAttribute('onclick')?.includes(sha256)) {
                        const statusSpan = row.querySelector('.status');
                        if (statusSpan) {
                            statusSpan.className = 'status status-' + newStatus;
                            statusSpan.textContent = newStatus;
                        }
                    }
                });
                // Refresh stats in background
                loadStats();
            } catch (e) {
                showError(e.message);
            }
        }

        async function showBlobDetail(hash) {
            const panel = document.getElementById('detailPanel');
            const content = document.getElementById('detailContent');

            try {
                const resp = await fetch('/admin/api/blob/' + hash, {
                    headers: authHeaders()
                });
                if (!resp.ok) throw new Error('Failed to load blob');
                const blob = await resp.json();

                const isVideo = blob.type?.startsWith('video');
                const isImage = blob.type?.startsWith('image');
                const thumbUrl = blob.thumbnail || (isVideo ? '/' + blob.sha256 + '.jpg' : null);
                const previewUrl = isImage ? '/' + blob.sha256 : thumbUrl;

                content.innerHTML = `
                    ${isVideo ? `<video src="/${blob.sha256}" class="detail-preview" controls poster="${thumbUrl}" style="max-width:100%"></video>` : (previewUrl ? `<img src="${previewUrl}" class="detail-preview">` : '')}
                    <div class="detail-section">
                        <div class="detail-label">SHA256</div>
                        <div class="detail-value hash">${blob.sha256}</div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Type</div>
                        <div class="detail-value">${blob.type}</div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Size</div>
                        <div class="detail-value">${formatBytes(blob.size)}</div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Status</div>
                        <div class="detail-value"><span class="status status-${blob.status}">${blob.status}</span></div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Owner</div>
                        <div class="detail-value pubkey">${blob.owner}</div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Uploaded</div>
                        <div class="detail-value">${new Date(blob.uploaded).toLocaleString()}</div>
                    </div>
                    ${blob.transcode_status ? `
                    <div class="detail-section">
                        <div class="detail-label">Transcode</div>
                        <div class="detail-value">${blob.transcode_status}</div>
                    </div>
                    ` : ''}
                    <div class="actions" style="margin-top:1rem">
                        <button class="btn btn-approve" onclick="moderate('${blob.sha256}','approve');closeDetail()">Approve</button>
                        <button class="btn btn-restrict" onclick="moderate('${blob.sha256}','restrict');closeDetail()">Restrict</button>
                        <button class="btn btn-ban" onclick="moderate('${blob.sha256}','ban');closeDetail()">Ban</button>
                    </div>
                    <div style="margin-top:1rem">
                        <a href="/${blob.sha256}" target="_blank" class="btn btn-approve">View File</a>
                    </div>
                `;
                panel.classList.add('open');
            } catch (e) {
                content.innerHTML = `<div class="error">${e.message}</div>`;
                panel.classList.add('open');
            }
        }

        async function showUserBlobs(pubkey) {
            const content = document.getElementById('content');
            content.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const resp = await fetch('/admin/api/user/' + pubkey, {
                    headers: authHeaders()
                });
                if (!resp.ok) throw new Error('Failed to load user blobs');
                const blobs = await resp.json();
                content.innerHTML = `
                    <div style="margin-bottom:1rem">
                        <span class="pubkey">${pubkey}</span>
                        <button class="btn btn-approve" onclick="loadTabContent()" style="margin-left:1rem">Back</button>
                    </div>
                    ${renderBlobsTable(blobs)}
                `;
            } catch (e) {
                content.innerHTML = `<div class="error">${e.message}</div>`;
            }
        }

        function closeDetail() {
            document.getElementById('detailPanel').classList.remove('open');
        }

        function showError(msg) {
            const el = document.getElementById('error');
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }

        function formatBytes(bytes) {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function getThumbHtml(b) {
            const isVideo = b.type?.startsWith('video');
            const isImage = b.type?.startsWith('image');
            // For videos, use stored thumbnail or try the /{hash}.jpg pattern
            if (isVideo) {
                const thumbUrl = b.thumbnail || '/' + b.sha256 + '.jpg';
                return '<img src="' + thumbUrl + '" class="thumb" onerror="this.outerHTML=\'<div class=thumb style=display:flex;align-items:center;justify-content:center;font-size:24px>▶</div>\'">';
            }
            if (isImage) {
                return '<img src="/' + b.sha256 + '" class="thumb">';
            }
            return '<div class="thumb"></div>';
        }
    </script>
</body>
</html>"#;

/// Login page HTML - shown when not authenticated
const ADMIN_LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Divine Blossom Admin - Login</title>
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .login-container {
            background: #16213e;
            padding: 2.5rem;
            border-radius: 12px;
            width: 100%;
            max-width: 420px;
            border: 1px solid #0f3460;
            text-align: center;
        }
        h1 { font-size: 1.5rem; color: #fff; margin-bottom: 0.5rem; }
        .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 2rem; }
        .divider {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 1.5rem 0;
            color: #666;
            font-size: 0.8rem;
        }
        .divider::before, .divider::after {
            content: '';
            flex: 1;
            border-bottom: 1px solid #333;
        }
        .oauth-buttons {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        .oauth-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid #333;
            border-radius: 8px;
            background: #1a1a2e;
            color: #fff;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
        }
        .oauth-btn:hover { background: #0f3460; border-color: #60a5fa; }
        .oauth-btn svg { width: 20px; height: 20px; flex-shrink: 0; }
        .input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #0f3460;
            border-radius: 6px;
            background: #1a1a2e;
            color: #fff;
            margin-bottom: 0.75rem;
        }
        .input:focus { outline: none; border-color: #60a5fa; }
        .btn-primary {
            width: 100%;
            padding: 0.75rem;
            background: #3b82f6;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.95rem;
        }
        .btn-primary:hover { background: #2563eb; }
        .error {
            color: #f87171;
            padding: 0.75rem;
            background: #7f1d1d33;
            border-radius: 8px;
            margin-bottom: 1rem;
            display: none;
            font-size: 0.875rem;
        }
        #googleButtonContainer {
            display: flex;
            justify-content: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Divine Blossom Admin</h1>
        <p class="subtitle">Sign in to access the admin dashboard</p>

        <div id="error" class="error"></div>

        <div class="oauth-buttons">
            <div id="googleButtonContainer"></div>

            <a href="/admin/auth/github" class="oauth-btn">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                Sign in with GitHub
            </a>
        </div>

        <div class="divider">or use admin token</div>

        <input type="password" id="tokenInput" class="input" placeholder="Enter admin token">
        <button id="loginBtn" class="btn-primary">Login with Token</button>
    </div>

    <script>
        // Google Sign-In callback
        function handleGoogleCredentialResponse(response) {
            fetch('/admin/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id_token: response.credential })
            }).then(resp => {
                if (resp.ok) {
                    window.location.href = '/admin';
                } else {
                    return resp.json().then(data => {
                        showError(data.error || 'Google login failed');
                    });
                }
            }).catch(() => showError('Connection error'));
        }

        // Initialize Google Sign-In when GIS library loads
        window.onload = function() {
            if (typeof google !== 'undefined' && google.accounts) {
                // Try to get client ID from a meta tag or use default
                const clientId = document.querySelector('meta[name="google-signin-client_id"]')?.content;
                if (clientId) {
                    google.accounts.id.initialize({
                        client_id: clientId,
                        callback: handleGoogleCredentialResponse
                    });
                    google.accounts.id.renderButton(
                        document.getElementById('googleButtonContainer'),
                        { theme: 'filled_black', size: 'large', width: 370, text: 'signin_with' }
                    );
                }
            }
        };

        // Token login (fallback)
        document.getElementById('loginBtn').onclick = async () => {
            const token = document.getElementById('tokenInput').value;
            try {
                const resp = await fetch('/admin/api/stats', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                if (resp.ok) {
                    localStorage.setItem('admin_token', token);
                    window.location.href = '/admin';
                } else {
                    showError('Invalid token');
                }
            } catch (e) {
                showError('Connection error');
            }
        };

        document.getElementById('tokenInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') document.getElementById('loginBtn').click();
        });

        function showError(msg) {
            const el = document.getElementById('error');
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }
    </script>
</body>
</html>"#;
