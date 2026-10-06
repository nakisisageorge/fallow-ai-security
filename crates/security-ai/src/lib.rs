//! AI-powered security finding verification for fallow.
//!
//! This crate provides optional AI-assisted verification of security findings
//! to reduce false positives and provide remediation guidance.

use fallow_types::results::SecurityFinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use thiserror::Error;

pub mod cache;
pub mod provider;

pub use cache::{VerificationCache, VerificationCacheEntry};
pub use provider::{LlmProvider, LlmProviderKind, LlmRequest, LlmResponse};

/// Configuration for AI security verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVerificationConfig {
    /// Whether AI verification is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// LLM provider to use.
    #[serde(default = "default_provider")]
    pub provider: LlmProviderKind,
    /// Model name/identifier.
    #[serde(default = "default_model")]
    pub model: String,
    /// API endpoint (for custom/Ollama providers).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// API key environment variable name.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    /// Maximum tokens for response.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Temperature for LLM calls.
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Cache directory for verification results.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    /// Rate limit (requests per minute).
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
    /// Whether to redact secrets before sending to LLM.
    #[serde(default = "default_true")]
    pub redact_secrets: bool,
    /// System prompt for verification.
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,
    /// Timeout for LLM requests in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_provider() -> LlmProviderKind {
    LlmProviderKind::Ollama
}
fn default_model() -> String {
    "llama3.1".to_string()
}
fn default_api_key_env() -> String {
    "FALLOW_AI_API_KEY".to_string()
}
fn default_max_tokens() -> u32 {
    2048
}
fn default_temperature() -> f32 {
    0.1
}
fn default_cache_dir() -> String {
    ".fallow/ai-cache".to_string()
}
fn default_rate_limit() -> u32 {
    60
}
fn default_true() -> bool {
    true
}
fn default_system_prompt() -> String {
    r#"You are a security expert reviewing static analysis findings for TypeScript/JavaScript code.
Your task is to classify each finding as:
- TRUE_POSITIVE: The finding represents a real security vulnerability
- FALSE_POSITIVE: The finding is a false alarm (sanitized, safe pattern, etc.)
- UNCERTAIN: Cannot determine without more context

Provide a confidence score (0-100) and a brief remediation suggestion.
Respond in JSON format only."#
        .to_string()
}
fn default_timeout() -> u64 {
    30
}

impl Default for AiVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_provider(),
            model: default_model(),
            endpoint: None,
            api_key_env: default_api_key_env(),
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
            cache_dir: default_cache_dir(),
            rate_limit: default_rate_limit(),
            redact_secrets: default_true(),
            system_prompt: default_system_prompt(),
            timeout_secs: default_timeout(),
        }
    }
}

/// Errors that can occur during AI verification.
#[derive(Debug, Error)]
pub enum AiVerificationError {
    #[error("AI verification is not enabled")]
    NotEnabled,
    #[error("Provider error: {0}")]
    Provider(#[from] provider::ProviderError),
    #[error("Cache error: {0}")]
    Cache(#[from] cache::CacheError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Timeout")]
    Timeout,
    #[error("Redaction error: {0}")]
    Redaction(String),
}

/// Result of AI verification for a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVerificationResult {
    /// Classification of the finding.
    pub classification: VerificationClassification,
    /// Confidence score (0-100).
    pub confidence: u8,
    /// Remediation suggestion.
    pub remediation: String,
    /// Reasoning for the classification.
    pub reasoning: String,
    /// Model used for verification.
    pub model: String,
    /// Provider used.
    pub provider: LlmProviderKind,
    /// Timestamp of verification.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Content hash of the finding (for cache invalidation).
    pub content_hash: String,
}

/// Classification of a security finding after AI verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationClassification {
    TruePositive,
    FalsePositive,
    Uncertain,
}

impl VerificationClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationClassification::TruePositive => "true_positive",
            VerificationClassification::FalsePositive => "false_positive",
            VerificationClassification::Uncertain => "uncertain",
        }
    }
}

/// Extended security finding with AI verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSecurityFinding {
    /// The original finding.
    #[serde(flatten)]
    pub finding: SecurityFinding,
    /// AI verification result, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_verification: Option<AiVerificationResult>,
}

/// Global verifier instance (placeholder for future async implementation).
static GLOBAL_VERIFIER: OnceLock<()> = OnceLock::new();

/// Initialize the global AI verifier (placeholder).
pub fn init_global_verifier(_config: AiVerificationConfig) -> Result<(), AiVerificationError> {
    GLOBAL_VERIFIER
        .set(())
        .map_err(|_| AiVerificationError::Config("Global verifier already initialized".to_string()))
}

/// Get the global verifier instance (placeholder).
pub fn global_verifier() -> Option<()> {
    GLOBAL_VERIFIER.get().cloned()
}

/// Compute a content hash for a finding for cache key generation.
pub fn finding_content_hash(finding: &SecurityFinding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.finding_id.as_bytes());
    hasher.update(finding.evidence.as_bytes());
    hasher.update(finding.path.to_string_lossy().as_bytes());
    hasher.update(finding.line.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Redact potential secrets from a string before sending to LLM.
pub fn redact_secrets(text: &str) -> String {
    let mut result = text.to_string();
    
    // Redact common secret patterns
    let secret_patterns = [
        (r#"(?i)(api[_-]?key|secret|token|password|credential)["\s]*[:=]["\s]*[a-zA-Z0-9_\-]{20,}"#, "[REDACTED]"),
        (r#"(?i)(bearer|authorization)["\s]*[:=]["\s]*[a-zA-Z0-9_\-\.]{20,}"#, "[REDACTED]"),
        (r#"sk-[a-zA-Z0-9]{20,}"#, "[REDACTED]"),
        (r#"gh[ps]_[a-zA-Z0-9]{20,}"#, "[REDACTED]"),
        (r#"[a-zA-Z0-9+/]{40,}={0,2}"#, "[REDACTED]"), // Base64-like
    ];
    
    for (pattern, replacement) in secret_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            result = re.replace_all(&result, replacement).to_string();
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_redact_secrets() {
        let input = "const api_key = 'sk-1234567890abcdef1234';";
        let output = redact_secrets(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("sk-1234567890abcdef1234"));
    }
    
    #[test]
    fn test_finding_content_hash() {
        let finding = SecurityFinding {
            finding_id: "test-123".to_string(),
            kind: fallow_types::results::SecurityFindingKind::TaintedSink,
            category: Some("test".to_string()),
            cwe: Some(79),
            path: "test.ts".into(),
            line: 10,
            col: 5,
            evidence: "test evidence".to_string(),
            source_backed: false,
            source_read: None,
            severity: fallow_types::results::SecuritySeverity::Medium,
            trace: vec![],
            actions: vec![],
            dead_code: None,
            reachability: None,
            candidate: fallow_types::results::SecurityCandidate::default(),
            taint_flow: None,
            runtime: None,
            attack_surface: None,
        };
        
        let hash1 = finding_content_hash(&finding);
        let hash2 = finding_content_hash(&finding);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex
    }
}