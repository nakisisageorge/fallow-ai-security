# Design Document — fallow-ai-security

## 1. Original Architecture

Fallow is a Rust-based static analysis tool for TypeScript/JavaScript that uses Oxc for syntactic analysis (no TypeScript compiler required). The security analysis pipeline follows:

```
config → discovery → extract → resolve → graph → analyze → output
```

The security component (`fallow-security`) uses a data-driven catalogue in `security_matchers.toml` where each `[[matcher]]` row defines a syntactic sink pattern mapped to a CWE. Findings are candidates for verification, not proven vulnerabilities.

Key architectural invariants:
- Syntactic analysis only (no inter-procedural taint tracking)
- False negatives preferred over false positives
- Data-driven matchers (TOML) — no Rust enum churn for new categories
- Source model raises precision but doesn't gate findings

## 2. Problems Identified

### 2.1 Missing AI/LLM Threat Coverage
The original security catalogue covered traditional web/app vulnerabilities (XSS, SQLi, SSRF, path traversal, etc.) but had **zero coverage** for AI/LLM-specific attack vectors:
- Prompt injection (CWE-1427)
- Agent tool/function calling misuse
- Data exfiltration to LLM providers
- RAG/knowledge base poisoning
- Insecure agent state/memory manipulation
- MCP (Model Context Protocol) tool injection
- System prompt override
- Unvalidated LLM output parsing

### 2.2 No Compliance Reporting
Security findings existed in isolation with no mapping to compliance frameworks required by enterprise customers:
- OWASP Top 10 2021
- CWE Top 25
- SOC 2 (Common Criteria)
- ISO 27001 Annex A

### 2.3 No Automated Verification
All findings required manual review. No framework existed for AI-assisted triage to:
- Classify findings (true positive / false positive / uncertain)
- Provide confidence scores
- Suggest remediation
- Cache results for consistency

## 3. Proposed Architecture

### 3.1 Extended Security Catalogue
Add 8 new `[[matcher]]` rows to `security_matchers.toml` covering AI/LLM threat vectors. Each follows the existing pattern:
- `requires_source = true` for taint-gated detection
- Specific `callee_patterns` for major LLM SDKs (OpenAI, Anthropic, Google, Vercel AI SDK)
- Appropriate CWE mappings (1427, 201, 1336, 922, 94)

### 3.2 Compliance Report Generator (`fallow-compliance`)
New standalone crate consuming fallow's JSON security output:
- Maps CWE IDs to compliance framework controls
- Generates Markdown and JSON reports
- Filters findings by relevance to each framework
- Usable in CI/CD pipelines

### 3.3 AI Verification Framework (`fallow-security-ai`)
New crate providing optional AI-assisted verification:
- **Config:** `AiVerificationConfig` with provider, model, cache, rate limits
- **Providers:** Trait-based abstraction (OpenAI, Anthropic, Ollama, Custom)
- **Cache:** Two-tier (memory + disk) with content-hash keys
- **Redaction:** Automatic secret/PII redaction before LLM calls
- **Integration:** Designed for future CLI integration via `fallow ai-verify`

## 4. New Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                        fallow-ai-security                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐   │
│  │   Source    │    │   Security       │    │   Compliance    │   │
│  │   Code      │───▶│   Analysis       │───▶│   Reporter      │   │
│  │  (TS/JS)    │    │  (fallow-sec)    │    │ (fallow-compl)  │   │
│  └─────────────┘    │  + AI/LLM rules  │    └────────┬────────┘   │
│                     └────────┬─────────┘             │            │
│                              │                       │            │
│                     ┌────────▼─────────┐    ┌────────▼────────┐   │
│                     │  Security        │    │  OWASP / CWE    │   │
│                     │  Findings (JSON) │    │  SOC2 / ISO     │   │
│                     └────────┬─────────┘    │  Reports (MD)   │   │
│                              │              └─────────────────┘   │
│                              │                                      │
│                     ┌────────▼─────────┐                            │
│                     │  AI Verification │                            │
│                     │ (fallow-sec-ai)  │                            │
│                     │  - Provider      │                            │
│                     │  - Cache         │                            │
│                     │  - Redaction     │                            │
│                     └──────────────────┘                            │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Source Code** → Parsed by Oxc → **Module Graph**
2. **Module Graph** → Security Analyzer → **Sink Candidates** (with CWE metadata)
3. **Sink Candidates** → Source Model → **Taint-Enriched Findings** (source-backed = higher confidence)
4. **Findings (JSON)** → Compliance Reporter → **Framework Reports** (Markdown/JSON)
5. **Findings (JSON)** → AI Verifier (optional) → **Verified Findings** (classification + remediation)

## 5. Why Changes Were Made

| Change | Rationale |
|--------|-----------|
| Data-driven matchers (TOML) | Consistency with existing fallow architecture; no Rust recompilation for new rules |
| `requires_source = true` for AI rules | Maintains "prefer false negatives" principle; taint gate controls FP rate |
| Specific SDK callee patterns | Precision: only known LLM SDK calls trigger, not generic `.invoke()`/`.call()` |
| Separate compliance crate | Separation of concerns; standalone binary for CI/CD; no runtime deps in core |
| AI verification as separate crate | Optional feature; heavy deps (reqwest, tokio) isolated; opt-in via config |
| Provider abstraction | Flexibility: local (Ollama), cloud (OpenAI/Anthropic), custom endpoints |
| Secret redaction | Security-first: never send credentials to external LLMs |
| Two-tier cache | Performance: memory for hot lookups, disk for persistence across runs |

## 6. Technology Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Language | Rust 2024 | Consistency with fallow workspace |
| Parser | Oxc | fallow's existing choice; fast, no TS compiler |
| LLM HTTP | reqwest + rustls | Mature, async, TLS by default |
| Caching | bitcode + filesystem | Binary serialization; no DB dependency |
| Redaction | regex patterns | Simple, effective for common secret formats |
| Compliance output | tabled + markdown | Human-readable + machine-parseable |
| Testing | cargo test + insta | fallow's existing patterns |

## 7. Security Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| AI verification opt-in | Disabled by default | No surprise network calls; explicit consent |
| Secret redaction | Always on (configurable) | Defense in depth; prevents accidental leakage |
| Local-first analysis | Core runs offline | Air-gapped environments supported |
| Provider trait | Abstract interface | Enables testing with mocks; future-proof |
| Content-hash cache keys | SHA-256 of finding | Deterministic; invalidates on finding change |

## 8. Performance Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Memory + disk cache | Two-tier | Hot findings in memory; persistence across runs |
| Rate limiting | Configurable (req/min) | Respects provider limits; prevents abuse |
| Async verification | Tokio + reqwest | Non-blocking; concurrent request handling |
| Batch processing | Future work | Current: sequential; planned: concurrent with semaphore |

## 9. Scalability Considerations

- **Large codebases:** Security analysis scales with fallow's O(n) syntactic analysis
- **Many findings:** AI verification processes findings sequentially; batch support planned
- **Cache growth:** LRU eviction in memory; disk cache unbounded (manual clear)
- **Compliance reports:** Streaming output; constant memory regardless of finding count

## 10. Deployment Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   CI/CD     │────▶│ fallow sec   │────▶│ fallow-compl    │
│  Pipeline   │     │ --format json│     │ --report owasp  │
└─────────────┘     └──────────────┘     └────────┬────────┘
                                                   │
                                          ┌────────▼────────┐
                                          │  Artifact Store │
                                          │  (reports.md)   │
                                          └─────────────────┘
                                                   │
                                          ┌────────▼────────┐
                                          │  Policy Gate    │
                                          │  (fail on crit) │
                                          └─────────────────┘
```

Optional AI verification step:
```
Security Findings ──▶ fallow ai-verify ──▶ Verified Findings ──▶ Policy Gate
```

## 11. Testing Strategy

| Layer | Approach |
|-------|----------|
| Unit | Rust `#[test]` for redaction, hashing, provider serialization |
| Integration | Fallback CLI tests with fixture projects |
| Snapshot | `insta` for compliance report output stability |
| Property | `proptest` for matcher parsing (existing fallow patterns) |
| E2E | Test project with known AI/LLM patterns |

## 12. Future Improvements

### Short-term
- [ ] Implement OpenAI/Anthropic provider clients
- [ ] Add `fallow ai-verify` CLI command
- [ ] Streaming/batch verification with concurrency control
- [ ] SARIF output for compliance reports

### Medium-term
- [ ] Additional compliance frameworks (PCI DSS, HIPAA, NIST CSF)
- [ ] VS Code extension integration for AI verification results
- [ ] Custom matcher DSL for organization-specific AI patterns
- [ ] Baseline tracking for AI findings (like fallow's audit baseline)

### Long-term
- [ ] Inter-procedural taint analysis for higher precision
- [ ] ML-based finding prioritization (local model)
- [ ] Integration with fallow's MCP server for agent-driven remediation
- [ ] Automated PR comments with AI verification results

---

*Document version: 1.0*  
*Date: 2026-10-06*  
*Author: George Nakisisa, GICT Africa Technologies*