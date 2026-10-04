//! LLM provider abstraction for AI security verification (simplified).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Not implemented")]
    NotImplemented,
}

/// LLM provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProviderKind {
    OpenAI,
    Anthropic,
    Ollama,
    Custom,
}

/// Request to an LLM provider.
#[derive(Debug, Clone, Serialize)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub system: Option<String>,
}

/// Message in an LLM conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String,
    pub content: String,
}

/// Response from an LLM provider.
#[derive(Debug, Clone, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<LlmUsage>,
}

/// Token usage information.
#[derive(Debug, Clone, Deserialize)]
pub struct LlmUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Trait for LLM providers (simplified synchronous version).
pub trait LlmProvider: Send + Sync {
    /// Get the provider kind.
    fn kind(&self) -> LlmProviderKind;
    
    /// Get the model name.
    fn model(&self) -> &str;
}

/// Placeholder provider that returns an error (for compilation).
pub struct PlaceholderProvider {
    kind: LlmProviderKind,
    model: String,
}

impl PlaceholderProvider {
    pub fn new(kind: LlmProviderKind, model: String) -> Self {
        Self { kind, model }
    }
}

impl LlmProvider for PlaceholderProvider {
    fn kind(&self) -> LlmProviderKind {
        self.kind
    }
    
    fn model(&self) -> &str {
        &self.model
    }
}

/// Create a provider from configuration (placeholder).
pub fn create_provider(
    kind: LlmProviderKind,
    model: String,
    _api_key: Option<String>,
    _endpoint: Option<String>,
    _timeout_secs: u64,
) -> Result<Box<dyn LlmProvider>, ProviderError> {
    Ok(Box::new(PlaceholderProvider::new(kind, model)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_provider_kind_serialization() {
        let kind = LlmProviderKind::OpenAI;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"openai\"");
        
        let kind: LlmProviderKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, LlmProviderKind::OpenAI);
    }
}