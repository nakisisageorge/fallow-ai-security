# fallow-ai-security

Enhanced and independently developed implementation inspired by [fallow](https://github.com/fallow-rs/fallow), adding AI/LLM-specific security analysis, compliance reporting, and an AI-powered verification framework.

## Overview

This project extends fallow's security analysis capabilities with specialized rules for AI/LLM applications, automated compliance reporting against major security frameworks, and an optional AI-assisted verification layer to reduce false positives.

## Why This Project Exists

As AI/LLM integration becomes ubiquitous in software systems, traditional static analysis tools lack awareness of AI-specific attack vectors. This project addresses that gap by:

1. **AI/LLM Security Rules** — Detecting prompt injection, agent tool misuse, data exfiltration to models, RAG poisoning, insecure agent state, MCP tool injection, system prompt override, and output parsing injection
2. **Compliance Reporting** — Mapping security findings to OWASP Top 10, CWE Top 25, SOC 2, and ISO 27001 control frameworks
3. **AI Verification Framework** — Optional AI-assisted triage of security findings to reduce false positives and provide remediation guidance

## Original Project

- **Original repository:** https://github.com/fallow-rs/fallow
- **Original authors:** fallow-rs contributors
- **License:** MIT
- **Attribution:** This project builds upon fallow's security analysis engine and data-driven matcher catalogue. All original copyright notices and licenses are preserved.

## What Was Improved

| Area | Original | Improved |
|------|----------|----------|
| Security Rules | 48 catalogue categories | 56 categories (+8 AI/LLM-specific) |
| Compliance | None | OWASP Top 10, CWE Top 25, SOC 2, ISO 27001 |
| Verification | Manual review | AI-assisted verification framework |
| AI Awareness | None | Dedicated AI/LLM threat model coverage |

### New AI/LLM Security Rules

| Rule ID | CWE | Title | Description |
|---------|-----|-------|-------------|
| `llm-call-injection` | 1427 | Untrusted input reaches an LLM call | Detects attacker-controlled input flowing into LLM prompt/messages |
| `agent-tool-misuse` | 1427 | Untrusted input controls agent tool call | Catches untrusted input controlling tool selection or arguments |
| `llm-data-exfiltration` | 201 | Secret or PII reaches LLM call | Flags secrets/PII from env vars or request input sent to models |
| `rag-poisoning` | 1336 | Untrusted data in RAG retrieval context | Detects untrusted content in vector store writes and context assembly |
| `insecure-agent-state` | 922 | Untrusted input writes agent state/memory | Catches attacker-controlled writes to agent memory/history |
| `mcp-tool-injection` | 94 | Untrusted input reaches MCP tool call | Detects untrusted input controlling MCP tool invocation |
| `llm-system-prompt-override` | 1427 | Untrusted input reaches LLM system prompt | Flags attacker input reaching high-authority system prompts |
| `agent-output-parsing-injection` | 1427 | Unvalidated LLM output parsed as structured data | Catches unsafe parsing of LLM output without validation |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    fallow-ai-security                       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ fallow-core  │  │ fallow-sec   │  │ fallow-security  │  │
│  │ (analysis)   │──│ (matchers)   │──│ (tainted-sink)   │  │
│  └──────────────┘  └──────────────┘  └────────┬─────────┘  │
│                                                │            │
│  ┌──────────────────┐  ┌──────────────────┐  │            │
│  │ fallow-security  │  │ fallow-compliance│  │            │
│  │     -ai          │  │                  │  │            │
│  │ (AI verification)│──│ (report gen)     │  │            │
│  └──────────────────┘  └──────────────────┘  │            │
│         │                    │                │            │
│         └────────────────────┴────────────────┘            │
│                          │                                  │
│  ┌───────────────────────▼─────────────────────────────┐   │
│  │              fallow-api (programmatic facade)       │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│  ┌───────────────────────▼─────────────────────────────┐   │
│  │              fallow-cli (terminal interface)        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Component Overview

- **fallow-security** — Extended data-driven security matcher catalogue with 8 new AI/LLM categories
- **fallow-security-ai** — AI verification framework with provider abstraction, caching, secret redaction, and configurable prompts
- **fallow-compliance** — Standalone compliance report generator (OWASP, CWE Top 25, SOC 2, ISO 27001)
- **fallow-api** — Programmatic facade exposing security analysis, compliance, and AI verification
- **fallow-cli** — CLI commands for `security`, `compliance`, and `ai-verify`

## Technology Stack

- **Language:** Rust 2024 edition
- **Parser:** Oxc (syntactic analysis without TypeScript compiler)
- **Async Runtime:** Tokio
- **HTTP Client:** reqwest (for LLM providers)
- **Serialization:** serde, serde_json
- **Testing:** cargo test, insta (snapshot testing)
- **Compliance:** tabled (markdown tables), clap (CLI)

## Project Structure

```
fallow-ai-security/
├── crates/
│   ├── security/              # Extended security matcher catalogue
│   │   └── data/
│   │       └── security_matchers.toml   # 56 matcher categories (8 new AI/LLM)
│   ├── security-ai/           # AI verification framework
│   │   ├── src/
│   │   │   ├── lib.rs         # Config, verification types, redaction
│   │   │   ├── provider.rs    # LLM provider abstraction
│   │   │   └── cache.rs       # Verification result caching
│   │   └── Cargo.toml
│   ├── compliance/            # Compliance report generator
│   │   ├── src/
│   │   │   └── main.rs        # OWASP, CWE, SOC2, ISO 27001 reports
│   │   └── Cargo.toml
│   ├── api/                   # Programmatic facade
│   │   └── src/
│   │       └── explain.rs     # Updated with AI/LLM rule explanations
│   └── cli/                   # CLI commands
├── Cargo.toml                 # Workspace configuration
├── CONTRIBUTING.md            # Updated with new crates
├── LICENSE                    # MIT
└── README.md                  # This file
```

## Installation

```bash
# From source
git clone https://github.com/nakisisageorge/fallow-ai-security
cd fallow-ai-security
cargo build --release --workspace

# Binaries:
# - target/release/fallow           (main CLI with security command)
# - target/release/fallow-compliance (compliance report generator)
```

## Configuration

### AI Verification (Optional)

Create a `.fallowrc.json` with AI verification config:

```json
{
  "security": {
    "categories": {
      "include": ["llm-call-injection", "agent-tool-misuse", "llm-data-exfiltration", "rag-poisoning", "insecure-agent-state", "mcp-tool-injection", "llm-system-prompt-override", "agent-output-parsing-injection"]
    }
  },
  "aiVerification": {
    "enabled": true,
    "provider": "ollama",
    "model": "llama3.1",
    "apiKeyEnv": "FALLOW_AI_API_KEY",
    "maxTokens": 2048,
    "temperature": 0.1,
    "cacheDir": ".fallow/ai-cache",
    "rateLimit": 60,
    "redactSecrets": true,
    "timeoutSecs": 30
  }
}
```

Supported providers: `openai`, `anthropic`, `ollama`, `custom`

### Environment Variables

- `FALLOW_AI_API_KEY` — API key for LLM provider (when using OpenAI/Anthropic/Custom)
- `FALLOW_AI_ENDPOINT` — Custom endpoint URL (for Ollama/Custom providers)

## Usage

### Security Analysis with AI/LLM Rules

```bash
# Run security analysis (includes new AI/LLM rules by default)
fallow security

# Run with specific AI categories
fallow security --include llm-call-injection,agent-tool-misuse,llm-data-exfiltration

# Output as JSON for programmatic use
fallow security --format json > security-findings.json
```

### Compliance Reporting

```bash
# Generate OWASP Top 10 report from fallow security output
fallow-compliance --input security-findings.json --report-type owasp --format markdown

# Generate CWE Top 25 report
fallow-compliance --input security-findings.json --report-type cwe-top25 --format markdown

# Generate SOC 2 report
fallow-compliance --input security-findings.json --report-type soc2 --format markdown

# Generate ISO 27001 report
fallow-compliance --input security-findings.json --report-type iso27001 --format markdown

# JSON output for integration
fallow-compliance --input security-findings.json --report-type owasp --format json
```

### AI Verification (When Enabled)

```bash
# Verify security findings with AI (requires config and API key)
fallow ai-verify --input security-findings.json --format json

# Note: AI verification is opt-in and requires:
# 1. aiVerification.enabled = true in config
# 2. Valid API key in environment variable
# 3. Accessible LLM provider endpoint
```

## API Documentation

### Programmatic Security Analysis

```rust
use fallow_api::{Fallow, SecurityConfig};

let fallow = Fallow::new();
let config = SecurityConfig::default()
    .include_categories(vec!["llm-call-injection", "agent-tool-misuse"]);
let result = fallow.security(&config).await?;
```

### Compliance Reporting

```rust
use fallow_compliance::{ComplianceReport, ReportType, OutputFormat};

let report = ComplianceReport::generate(
    &security_findings,
    ReportType::Owasp,
    OutputFormat::Markdown
)?;
```

### AI Verification

```rust
use fallow_security_ai::{AiVerificationConfig, LlmProviderKind, verify_findings};

let config = AiVerificationConfig {
    enabled: true,
    provider: LlmProviderKind::Ollama,
    model: "llama3.1".to_string(),
    ..Default::default()
};

let verified = verify_findings(&findings, &config).await?;
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p fallow-security-ai
cargo test -p fallow-compliance
cargo test -p fallow-api explain::tests
```

## Deployment

The compliance tool is a standalone binary suitable for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run fallow security
  run: npx fallow security --format json > security-findings.json

- name: Generate OWASP compliance report
  run: |
    cargo install --path crates/compliance
    fallow-compliance --input security-findings.json --report-type owasp --format markdown > owasp-report.md

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: owasp-compliance-report
    path: owasp-report.md
```

## Security

- **Secret Redaction:** The AI verification framework automatically redacts secrets (API keys, tokens, passwords, Base64 blobs) before sending findings to LLM providers
- **Local Processing:** Core security analysis runs locally with no network calls
- **Opt-in AI:** AI verification is disabled by default and requires explicit configuration
- **No Telemetry:** No usage data is collected

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Roadmap

- [ ] Implement OpenAI and Anthropic provider clients in fallow-security-ai
- [ ] Add streaming verification for large finding sets
- [ ] Integrate AI verification directly into `fallow security` command
- [ ] Add more compliance frameworks (PCI DSS, HIPAA, NIST CSF)
- [ ] Create VS Code extension integration for AI verification results
- [ ] Add SARIF output for compliance reports

## Attribution

This project is an independent enhancement fork of [fallow](https://github.com/fallow-rs/fallow) by the fallow-rs team. The original MIT license applies to all fallow-derived code. New code in `crates/security-ai`, `crates/compliance`, and AI/LLM matcher extensions is also licensed under MIT.

## Author

**George Nakisisa**  
Senior Software Engineer · AI Engineer · Cybersecurity  
GICT Africa Technologies  
https://gictafrica.com  
nakisisageorge@gmail.com

## Company

GICT Africa Technologies  
https://gictafrica.com  
Kampala, Uganda 🇺🇬