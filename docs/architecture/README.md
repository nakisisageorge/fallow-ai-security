# Architecture Visualization

## System Overview

```mermaid
flowchart TB
    subgraph "Input"
        SC[Source Code\nTypeScript/JavaScript]
    end

    subgraph "Analysis Pipeline"
        PARSE[Oxc Parser\nSyntactic Analysis]
        GRAPH[Module Graph\nImports, Exports, Dependencies]
        SEC[Security Analyzer\nExtended Catalogue]
        SRC[Source Model\nTaint Tracking]
    end

    subgraph "Security Findings"
        SF[Security Findings JSON\nCWE + Trace + Evidence]
    end

    subgraph "Output Processors"
        COMP[Compliance Reporter\nfallow-compliance]
        AIV[AI Verifier\nfallow-security-ai]
        EXIST[Existing Outputs\nSARIF, CodeClimate, LSP]
    end

    subgraph "Compliance Reports"
        OWASP[OWASP Top 10]
        CWE[CWE Top 25]
        SOC2[SOC 2]
        ISO[ISO 27001]
    end

    subgraph "AI Verification"
        PROV[Provider Abstraction\nOpenAI, Anthropic, Ollama]
        CACHE[Two-Tier Cache\nMemory + Disk]
        REDACT[Secret Redaction\nRegex Patterns]
        RESULT[Verified Findings\nClassification + Remediation]
    end

    SC --> PARSE
    PARSE --> GRAPH
    GRAPH --> SEC
    SEC --> SRC
    SRC --> SF

    SF --> COMP
    SF --> AIV
    SF --> EXIST

    COMP --> OWASP
    COMP --> CWE
    COMP --> SOC2
    COMP --> ISO

    AIV --> PROV
    AIV --> CACHE
    AIV --> REDACT
    AIV --> RESULT

    style SF fill:#f9f,stroke:#333
    style COMP fill:#bbf,stroke:#333
    style AIV fill:#bfb,stroke:#333
    style OWASP fill:#ff9,stroke:#333
    style CWE fill:#ff9,stroke:#333
    style SOC2 fill:#ff9,stroke:#333
    style ISO fill:#ff9,stroke:#333
```

## Security Matcher Catalogue

```mermaid
flowchart LR
    subgraph "Traditional Categories (48)"
        XSS[CWE-79: XSS\nHTML sinks]
        SQLI[CWE-89: SQL Injection]
        CMDI[CWE-78: Command Injection]
        SSRF[CWE-918: SSRF]
        PATH[CWE-22: Path Traversal]
        XXE[CWE-611: XXE]
        PROTO[CWE-1321: Prototype Pollution]
        CRYPTO[CWE-327: Weak Crypto]
        -- -- -- --
        OTHER[41 more categories]
    end

    subgraph "AI/LLM Categories (8 NEW)"
        LLM1[CWE-1427: Prompt Injection\nllm-call-injection]
        LLM2[CWE-1427: Agent Tool Misuse\nagent-tool-misuse]
        LLM3[CWE-201: Data Exfiltration\nllm-data-exfiltration]
        LLM4[CWE-1336: RAG Poisoning\nrag-poisoning]
        LLM5[CWE-922: Insecure Agent State\ninsecure-agent-state]
        LLM6[CWE-94: MCP Tool Injection\nmcp-tool-injection]
        LLM7[CWE-1427: System Prompt Override\nllm-system-prompt-override]
        LLM8[CWE-1427: Output Parsing Injection\nagent-output-parsing-injection]
    end

    style LLM1 fill:#f96,stroke:#333
    style LLM2 fill:#f96,stroke:#333
    style LLM3 fill:#f96,stroke:#333
    style LLM4 fill:#f96,stroke:#333
    style LLM5 fill:#f96,stroke:#333
    style LLM6 fill:#f96,stroke:#333
    style LLM7 fill:#f96,stroke:#333
    style LLM8 fill:#f96,stroke:#333
```

## Compliance Mapping

```mermaid
flowchart TB
    subgraph "Findings"
        F1[Finding\nCWE-1427]
        F2[Finding\nCWE-89]
        F3[Finding\nCWE-79]
        F4[Finding\nCWE-201]
    end

    subgraph "Mapping Engine"
        MAP[CWE → Framework Mapper]
    end

    subgraph "OWASP Top 10"
        O1[A03: Injection]
        O2[A01: Broken Access Control]
        O3[A04: Insecure Design]
    end

    subgraph "CWE Top 25"
        C1[CWE-1427: Prompt Injection]
        C2[CWE-89: SQL Injection]
        C3[CWE-79: XSS]
    end

    subgraph "SOC 2"
        S1[CC6.1: Logical Access]
        S2[CC6.7: Data Transmission]
    end

    subgraph "ISO 27001"
        I1[A.14.2: Security in Dev]
        I2[A.8.2: Info Classification]
    end

    F1 --> MAP
    F2 --> MAP
    F3 --> MAP
    F4 --> MAP

    MAP --> O1
    MAP --> O2
    MAP --> O3
    MAP --> C1
    MAP --> C2
    MAP --> C3
    MAP --> S1
    MAP --> S2
    MAP --> I1
    MAP --> I2

    style MAP fill:#f9f,stroke:#333
```

## AI Verification Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as fallow CLI
    participant SEC as Security Analyzer
    participant AIV as AI Verifier
    participant CACHE as Cache
    participant LLM as LLM Provider

    User->>CLI: fallow security --format json
    CLI->>SEC: Analyze codebase
    SEC-->>CLI: Security findings (JSON)
    CLI->>User: findings.json

    User->>CLI: fallow ai-verify --input findings.json
    CLI->>AIV: Verify findings
    AIV->>CACHE: Check cache (content hash)
    alt Cache Hit
        CACHE-->>AIV: Cached result
    else Cache Miss
        AIV->>REDACT: Redact secrets
        REDACT-->>AIV: Sanitized findings
        AIV->>LLM: Send verification prompt
        LLM-->>AIV: Classification + remediation
        AIV->>CACHE: Store result
    end
    AIV-->>CLI: Verified findings
    CLI-->>User: Verified findings (JSON)
```

## Crate Dependency Graph

```mermaid
flowchart TB
    subgraph "Foundation"
        TYPES[fallow-types\nContracts, Envelopes]
        CONFIG[fallow-config\nConfiguration]
        PROCESS[fallow-process\nProcess Management]
    end

    subgraph "Analysis Core"
        EXTRACT[fallow-extract\nParser Facts]
        GRAPH[fallow-graph\nModule Graph]
        SECURITY[fallow-security\nMatcher Catalogue]
        CORE[fallow-core\nDetector Backend]
        ENGINE[fallow-engine\nOrchestration]
    end

    subgraph "Output & Contracts"
        OUTPUT[fallow-output\nFormatters, SARIF]
        API[fallow-api\nProgrammatic Facade]
    end

    subgraph "Protocol Adapters"
        CLI[fallow-cli\nTerminal]
        LSP[fallow-lsp\nLanguage Server]
        MCP[fallow-mcp\nModel Context Protocol]
        NAPI[fallow-napi\nNode.js Bindings]
    end

    subgraph "New Extensions"
        SEC_AI[fallow-security-ai\nAI Verification]
        COMP[fallow-compliance\nCompliance Reports]
    end

    TYPES --> EXTRACT
    TYPES --> GRAPH
    TYPES --> SECURITY
    TYPES --> OUTPUT
    CONFIG --> ENGINE
    PROCESS --> ENGINE
    EXTRACT --> GRAPH
    GRAPH --> ENGINE
    SECURITY --> ENGINE
    CORE --> ENGINE
    ENGINE --> OUTPUT
    ENGINE --> API
    API --> CLI
    API --> LSP
    API --> MCP
    API --> NAPI
    API --> SEC_AI
    SECURITY --> COMP
    OUTPUT --> COMP
    API --> SEC_AI
    SEC_AI --> COMP

    style SEC_AI fill:#f96,stroke:#333
    style COMP fill:#f96,stroke:#333
```

## Interactive Documentation Tree

```mermaid
flowchart TD
    ROOT[fallow-ai-security] --> CLI[CLI Commands]
    ROOT --> API[Programmatic API]
    ROOT --> ARCH[Architecture]
    ROOT --> SEC[Security Rules]
    ROOT --> COMP[Compliance]
    ROOT --> AIV[AI Verification]

    CLI --> SEC_CMD[fallow security]
    CLI --> COMP_CMD[fallow-compliance]
    CLI --> AIV_CMD[fallow ai-verify]

    SEC_CMD --> MATCHERS[Matcher Catalogue]
    SEC_CMD --> SOURCES[Source Model]
    SEC_CMD --> OUTPUT[Output Formats]

    COMP_CMD --> OWASP[OWASP Top 10]
    COMP_CMD --> CWETOP[CWE Top 25]
    COMP_CMD --> SOC2[SOC 2]
    COMP_CMD --> ISO[ISO 27001]

    AIV_CMD --> PROVIDERS[LLM Providers]
    AIV_CMD --> CACHE[Caching]
    AIV_CMD --> REDACT[Redaction]

    SEC --> TRAD[Traditional 48]
    SEC --> AI[AI/LLM 8]

    API --> FACADE[Fallow Facade]
    API --> WORKFLOWS[Workflows]
    API --> ATTRIBUTION[Attribution]

    style ROOT fill:#f9f,stroke:#333,stroke-width:3px
    style AI fill:#f96,stroke:#333
    style COMP_CMD fill:#bbf,stroke:#333
    style AIV_CMD fill:#bfb,stroke:#333
```

## Deployment Architecture

```mermaid
flowchart LR
    subgraph "Development"
        DEV[Developer Machine]
        IDE[IDE / Editor]
    end

    subgraph "CI/CD Pipeline"
        GHA[GitHub Actions]
        SEC_STEP[fallow security]
        COMP_STEP[fallow-compliance]
        GATE[Policy Gate]
    end

    subgraph "Artifacts"
        SARIF[SARIF Upload]
        REPORTS[Compliance Reports]
        BADGE[Health Badge]
    end

    subgraph "Production"
        PROD[Production Systems]
        MON[Monitoring]
    end

    DEV --> GHA
    IDE -.-> LSP[fallow-lsp]
    GHA --> SEC_STEP
    SEC_STEP --> COMP_STEP
    COMP_STEP --> GATE
    SEC_STEP --> SARIF
    COMP_STEP --> REPORTS
    GATE --> PROD
    PROD --> MON

    style GHA fill:#bbf,stroke:#333
    style GATE fill:#f96,stroke:#333
    style SARIF fill:#bfb,stroke:#333
```

---

*Generated as part of fallow-ai-security documentation*  
*View interactive version at: https://github.com/nakisisageorge/fallow-ai-security/tree/main/docs/architecture*