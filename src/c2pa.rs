// ABOUTME: C2PA content credentials validation and policy enforcement
// ABOUTME: Validates C2PA manifests against trusted signers and claim generators

use serde::{Deserialize, Serialize};

/// C2PA validation result stored in blob metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paValidation {
    /// Whether a valid C2PA manifest was found
    pub has_manifest: bool,
    /// Claim generator string (e.g. "ProofMode/1.4.2")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator: Option<String>,
    /// Certificate issuer / signer common name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Signing certificate serial number or fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<String>,
    /// Signing timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// Whether the signer is in our trusted list
    pub trusted_signer: bool,
    /// Whether the claim generator is in our allowed list
    pub trusted_generator: bool,
    /// Validation errors if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<Vec<String>>,
    /// When validation was performed (ISO 8601)
    pub validated_at: String,
}

/// Reduced C2PA info for public API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paPublicInfo {
    /// Whether a valid C2PA manifest was found
    pub has_manifest: bool,
    /// Claim generator string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator: Option<String>,
    /// Certificate issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Whether the signer is trusted
    pub trusted_signer: bool,
    /// Whether the claim generator is trusted
    pub trusted_generator: bool,
}

impl C2paValidation {
    /// Convert to public-facing info (strips internal details)
    pub fn to_public(&self) -> C2paPublicInfo {
        C2paPublicInfo {
            has_manifest: self.has_manifest,
            claim_generator: self.claim_generator.clone(),
            issuer: self.issuer.clone(),
            trusted_signer: self.trusted_signer,
            trusted_generator: self.trusted_generator,
        }
    }
}

// ============================================================================
// C2PA Policy Configuration
// ============================================================================

/// C2PA enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C2paMode {
    /// Skip all C2PA checks
    Off,
    /// Validate and store results but don't reject uploads
    Log,
    /// Reject uploads without valid C2PA from trusted sources
    Enforce,
}

impl C2paMode {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "enforce" => C2paMode::Enforce,
            "log" => C2paMode::Log,
            _ => C2paMode::Off,
        }
    }
}

/// Policy evaluation result
pub struct PolicyResult {
    /// Whether the upload should be rejected
    pub reject: bool,
    /// Reason for rejection (if any)
    pub reason: String,
}

/// Load C2PA enforcement mode from config store
pub fn get_c2pa_mode() -> C2paMode {
    let config = fastly::ConfigStore::open("blossom_config");
    match config.get("c2pa_mode") {
        Some(mode) => C2paMode::from_str(&mode),
        None => C2paMode::Off,
    }
}

/// Load trusted certificate issuers from config store
/// Config value is a JSON array of strings, e.g. ["ProofMode CA", "Guardian Project"]
pub fn get_trusted_issuers() -> Vec<String> {
    let config = fastly::ConfigStore::open("blossom_config");
    match config.get("c2pa_trusted_issuers") {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Load trusted claim generators from config store
/// Config value is a JSON array of strings, e.g. ["ProofMode", "eyeWitness"]
/// Matching is case-insensitive prefix match (e.g. "ProofMode" matches "ProofMode/1.4.2")
pub fn get_trusted_generators() -> Vec<String> {
    let config = fastly::ConfigStore::open("blossom_config");
    match config.get("c2pa_trusted_generators") {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Check whether C2PA is required for video uploads
pub fn is_c2pa_required_for_video() -> bool {
    let config = fastly::ConfigStore::open("blossom_config");
    match config.get("c2pa_require_for_video") {
        Some(val) => val.trim().to_lowercase() == "true",
        None => false,
    }
}

// ============================================================================
// Policy Evaluation
// ============================================================================

/// Evaluate C2PA validation results against policy
/// Returns a PolicyResult indicating whether the upload should be rejected
pub fn evaluate_c2pa_policy(
    c2pa: &C2paValidation,
    mime_type: &str,
    mode: C2paMode,
) -> PolicyResult {
    // Off mode: never reject
    if mode == C2paMode::Off {
        return PolicyResult {
            reject: false,
            reason: String::new(),
        };
    }

    let should_reject = mode == C2paMode::Enforce;

    // Check if C2PA is required for this content type
    let is_video = crate::blossom::is_video_mime_type(mime_type);
    let require_for_video = is_c2pa_required_for_video();

    // No manifest found
    if !c2pa.has_manifest {
        if is_video && require_for_video {
            let reason = "Video uploads require C2PA content credentials".to_string();
            eprintln!("[C2PA POLICY] REJECT: {}", reason);
            return PolicyResult {
                reject: should_reject,
                reason,
            };
        }
        // No manifest and not required — pass
        return PolicyResult {
            reject: false,
            reason: String::new(),
        };
    }

    // Manifest found — check trust
    if !c2pa.trusted_signer {
        let issuer = c2pa.issuer.as_deref().unwrap_or("unknown");
        let reason = format!(
            "C2PA manifest signed by untrusted issuer: {}",
            issuer
        );
        eprintln!("[C2PA POLICY] WARN: {}", reason);
        return PolicyResult {
            reject: should_reject,
            reason,
        };
    }

    if !c2pa.trusted_generator {
        let generator = c2pa.claim_generator.as_deref().unwrap_or("unknown");
        let reason = format!(
            "C2PA manifest from untrusted claim generator: {}",
            generator
        );
        eprintln!("[C2PA POLICY] WARN: {}", reason);
        return PolicyResult {
            reject: should_reject,
            reason,
        };
    }

    // Has validation errors
    if let Some(errors) = &c2pa.validation_errors {
        if !errors.is_empty() {
            let reason = format!(
                "C2PA manifest has validation errors: {}",
                errors.join(", ")
            );
            eprintln!("[C2PA POLICY] WARN: {}", reason);
            return PolicyResult {
                reject: should_reject,
                reason,
            };
        }
    }

    // All checks passed
    eprintln!(
        "[C2PA POLICY] PASS: issuer={} generator={}",
        c2pa.issuer.as_deref().unwrap_or("unknown"),
        c2pa.claim_generator.as_deref().unwrap_or("unknown")
    );
    PolicyResult {
        reject: false,
        reason: String::new(),
    }
}

// ============================================================================
// Cloud Run Response Parsing
// ============================================================================

/// Parse C2PA validation data from Cloud Run upload response
/// Cloud Run returns a "c2pa" object in its JSON response when C2PA data is found
pub fn parse_cloud_run_c2pa(
    c2pa_json: &serde_json::Value,
    validated_at: &str,
) -> Option<C2paValidation> {
    if c2pa_json.is_null() {
        return None;
    }

    let has_manifest = c2pa_json["has_manifest"].as_bool().unwrap_or(false);
    let claim_generator = c2pa_json["claim_generator"].as_str().map(|s| s.to_string());
    let issuer = c2pa_json["issuer"].as_str().map(|s| s.to_string());
    let cert_serial = c2pa_json["cert_serial"].as_str().map(|s| s.to_string());
    let signed_at = c2pa_json["signed_at"].as_str().map(|s| s.to_string());
    let validation_errors: Option<Vec<String>> = c2pa_json["validation_errors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    // Check against trusted lists
    let trusted_issuers = get_trusted_issuers();
    let trusted_generators = get_trusted_generators();

    let trusted_signer = if let Some(ref iss) = issuer {
        trusted_issuers.iter().any(|trusted| {
            iss.to_lowercase().contains(&trusted.to_lowercase())
        })
    } else {
        false
    };

    let trusted_generator = if let Some(ref gen) = claim_generator {
        let gen_lower = gen.to_lowercase();
        trusted_generators.iter().any(|trusted| {
            gen_lower.starts_with(&trusted.to_lowercase())
        })
    } else {
        false
    };

    Some(C2paValidation {
        has_manifest,
        claim_generator,
        issuer,
        cert_serial,
        signed_at,
        trusted_signer,
        trusted_generator,
        validation_errors,
        validated_at: validated_at.to_string(),
    })
}

/// Create a C2paValidation for content with no C2PA manifest
pub fn no_manifest(validated_at: &str) -> C2paValidation {
    C2paValidation {
        has_manifest: false,
        claim_generator: None,
        issuer: None,
        cert_serial: None,
        signed_at: None,
        trusted_signer: false,
        trusted_generator: false,
        validation_errors: None,
        validated_at: validated_at.to_string(),
    }
}
