# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.31.x  | ✅        |
| < 3.31  | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in fallow-ai-security, please report it responsibly:

1. **Do not** open a public issue
2. Email: **nakisisageorge@gmail.com** with subject "SECURITY: fallow-ai-security"
3. Include: description, reproduction steps, impact assessment
4. We will acknowledge within 48 hours and provide a timeline for fix

## Security Features

### Core Analysis
- **Local-first**: All syntactic analysis runs offline with no network calls
- **No Telemetry**: No usage data, metrics, or error reports are collected
- **Deterministic**: Same input always produces same output

### AI Verification (Opt-In)
- **Disabled by Default**: Requires explicit `aiVerification.enabled: true` in config
- **Secret Redaction**: Automatic regex-based redaction of API keys, tokens, passwords, Base64 blobs before any LLM call
- **Provider Choice**: Local (Ollama) or cloud (OpenAI, Anthropic, Custom) — you control data flow
- **Content-Hash Cache**: Findings cached by SHA-256 of content; cache invalidates on finding changes
- **Rate Limiting**: Configurable requests/minute to respect provider limits

### Compliance Reporting
- **Standalone Binary**: `fallow-compliance` has no AI dependencies
- **No Network Calls**: Pure local transformation of fallow security JSON output
- **CI/CD Safe**: Suitable for air-gapped environments

## Threat Model

| Component | Threats | Mitigations |
|-----------|---------|-------------|
| Security Analyzer | False negatives (missed vulns) | Data-driven matchers; source-model precision; opt-in categories for noisy rules |
| AI Verifier | Secret leakage to LLM | Always-on redaction; local provider option; opt-in only |
| AI Verifier | Prompt injection in verification | Structured output format; low temperature; system prompt hardening |
| Compliance Reporter | Incorrect mapping | Unit tests for each framework mapping; snapshot testing |
| Configuration | Misconfiguration | Schema validation; documented defaults; fail-secure defaults |

## Secure Configuration Checklist

- [ ] `aiVerification.enabled: false` (default) unless explicitly needed
- [ ] `aiVerification.redactSecrets: true` (default) — never disable
- [ ] Use `Ollama` provider for air-gapped / sensitive environments
- [ ] Store API keys in environment variables (`FALLOW_AI_API_KEY`), never in config files
- [ ] Review `security.categories.include` — only enable categories you need
- [ ] Run `fallow security` in CI with `--format json` for audit trail

## Vulnerability Disclosure Timeline

1. **Day 0**: Report received, acknowledged
2. **Day 1-3**: Triage, impact assessment, reproduction
3. **Day 3-14**: Fix development and testing
4. **Day 14-21**: Coordinated disclosure, patch release
5. **Day 21+**: Public advisory (CVE if applicable)

## Attribution

This project extends [fallow](https://github.com/fallow-rs/fallow) which has its own [security policy](https://github.com/fallow-rs/fallow/blob/main/SECURITY.md). Both projects follow responsible disclosure practices.

---

**Contact**: nakisisageorge@gmail.com  
**GPG Key**: Available on request  
**Company**: GICT Africa Technologies