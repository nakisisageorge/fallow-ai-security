use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use fallow_types::results::SecurityFinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tabled::{Table, Tabled};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the fallow security JSON output file
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// The compliance report to generate
    #[arg(short, long, value_name = "REPORT_TYPE", default_value = "owasp")]
    report_type: ReportType,

    /// Output format
    #[arg(short, long, value_name = "FORMAT", default_value = "markdown")]
    format: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
enum ReportType {
    Owasp,
    CweTop25,
    Soc2,
    Iso27001,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
enum OutputFormat {
    Markdown,
    Json,
}

#[derive(Debug, Serialize, Tabled)]
struct ComplianceFinding {
    id: String,
    title: String,
    cwe: u32,
    file: String,
    line: u32,
    #[tabled(skip)]
    owasp_category: Option<String>,
    #[tabled(skip)]
    cwe_top25_category: Option<String>,
}

#[derive(Debug, Serialize)]
struct ComplianceReport {
    report_type: ReportType,
    findings: Vec<ComplianceFinding>,
    summary: HashMap<String, usize>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let input_content = fs::read_to_string(&args.input)
        .with_context(|| format!("Could not read input file {}", args.input.display()))?;

    let json: Value = serde_json::from_str(&input_content)
        .with_context(|| "Could not parse fallow security JSON output")?;

    let security_findings = json
        .get("security_findings")
        .and_then(|v| v.as_array())
        .with_context(|| "JSON output does not contain 'security_findings' array")?;

    let mut compliance_findings = Vec::new();
    let mut owasp_summary: HashMap<String, usize> = HashMap::new();
    let mut cwe_top25_summary: HashMap<String, usize> = HashMap::new();
    let mut soc2_summary: HashMap<String, usize> = HashMap::new();
    let mut iso27001_summary: HashMap<String, usize> = HashMap::new();

    for finding_value in security_findings {
        let finding: SecurityFinding = serde_json::from_value(finding_value.clone())
            .with_context(|| "Could not deserialize security finding")?;

        if let Some(cwe) = finding.cwe {
            let owasp_category = map_cwe_to_owasp(cwe);
            let cwe_top25_category = map_cwe_to_cwe_top25(cwe);
            let soc2_category = map_cwe_to_soc2(cwe);
            let iso27001_category = map_cwe_to_iso27001(cwe);

            if let Some(cat) = &owasp_category {
                *owasp_summary.entry(cat.clone()).or_insert(0) += 1;
            }
            if let Some(cat) = &cwe_top25_category {
                *cwe_top25_summary.entry(cat.clone()).or_insert(0) += 1;
            }
            if let Some(cat) = &soc2_category {
                *soc2_summary.entry(cat.clone()).or_insert(0) += 1;
            }
            if let Some(cat) = &iso27001_category {
                *iso27001_summary.entry(cat.clone()).or_insert(0) += 1;
            }

            // Use category id or CWE-based title
            let title = finding
                .category
                .as_deref()
                .unwrap_or(&format!("CWE-{}", cwe))
                .to_string();

            compliance_findings.push(ComplianceFinding {
                id: finding.finding_id,
                title,
                cwe,
                file: finding.path.display().to_string(),
                line: finding.line,
                owasp_category,
                cwe_top25_category,
            });
        }
    }

    match args.report_type {
        ReportType::Owasp => {
            let filtered_findings: Vec<_> = compliance_findings
                .into_iter()
                .filter(|f| f.owasp_category.is_some())
                .collect();
            let report = ComplianceReport {
                report_type: ReportType::Owasp,
                findings: filtered_findings,
                summary: owasp_summary,
            };
            render_report(report, args.format)?;
        }
        ReportType::CweTop25 => {
            let filtered_findings: Vec<_> = compliance_findings
                .into_iter()
                .filter(|f| f.cwe_top25_category.is_some())
                .collect();
            let report = ComplianceReport {
                report_type: ReportType::CweTop25,
                findings: filtered_findings,
                summary: cwe_top25_summary,
            };
            render_report(report, args.format)?;
        }
        ReportType::Soc2 => {
            let filtered_findings: Vec<_> = compliance_findings
                .into_iter()
                .filter(|f| map_cwe_to_soc2(f.cwe).is_some())
                .collect();
            let report = ComplianceReport {
                report_type: ReportType::Soc2,
                findings: filtered_findings,
                summary: soc2_summary,
            };
            render_report(report, args.format)?;
        }
        ReportType::Iso27001 => {
            let filtered_findings: Vec<_> = compliance_findings
                .into_iter()
                .filter(|f| map_cwe_to_iso27001(f.cwe).is_some())
                .collect();
            let report = ComplianceReport {
                report_type: ReportType::Iso27001,
                findings: filtered_findings,
                summary: iso27001_summary,
            };
            render_report(report, args.format)?;
        }
    }

    Ok(())
}

fn map_cwe_to_owasp(cwe: u32) -> Option<String> {
    match cwe {
        79 => Some(String::from("A03:2021-Injection")), // XSS
        89 => Some(String::from("A03:2021-Injection")), // SQL Injection
        78 => Some(String::from("A03:2021-Injection")), // OS Command Injection
        94 => Some(String::from("A03:2021-Injection")), // Code Injection, Agent Tool Misuse, MCP Tool Injection
        611 => Some(String::from("A05:2021-Security Misconfiguration")), // XXE
        918 => Some(String::from("A10:2021-Server-Side Request Forgery (SSRF)")), // SSRF
        22 => Some(String::from("A01:2021-Broken Access Control")), // Path Traversal
        113 => Some(String::from("A03:2021-Injection")), // HTTP Response Splitting
        601 => Some(String::from("A03:2021-Injection")), // Open Redirect
        201 => Some(String::from("A04:2021-Insecure Design")), // Sensitive Data Exposure (Secrets to network exfil, LLM Data Exfiltration)
        1321 => Some(String::from("A03:2021-Injection")), // Prototype Pollution
        1336 => Some(String::from("A03:2021-Injection")), // SSTI, RAG Poisoning
        1427 => Some(String::from("A03:2021-Injection")), // Prompt Injection, LLM System Prompt Override, Agent Output Parsing Injection
        532 => Some(String::from("A04:2021-Insecure Design")), // Sensitive Data Exposure (Secret/PII in logs)
        922 => Some(String::from("A04:2021-Insecure Design")), // Insecure Agent State / Memory Handling
        _ => None,
    }
}

fn map_cwe_to_cwe_top25(cwe: u32) -> Option<String> {
    match cwe {
        79 => Some(String::from("CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")),
        89 => Some(String::from("CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")),
        78 => Some(String::from("CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")),
        94 => Some(String::from("CWE-94: Improper Control of Generation of Code ('Code Injection')")), // Code Injection, Agent Tool Misuse, MCP Tool Injection
        611 => Some(String::from("CWE-611: Improper Restriction of XML External Entity Reference")),
        918 => Some(String::from("CWE-918: Server-Side Request Forgery (SSRF)")),
        22 => Some(String::from("CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')")),
        113 => Some(String::from("CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')")),
        601 => Some(String::from("CWE-601: URL Redirection to Untrusted Site ('Open Redirect')")),
        201 => Some(String::from("CWE-201: Information Exposure Through Sent Data")), // Secrets to network exfil, LLM Data Exfiltration
        1321 => Some(String::from("CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')")),
        1336 => Some(String::from("CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine")), // SSTI, RAG Poisoning
        1427 => Some(String::from("CWE-1427: Improper Neutralization of Special Elements Used in an LLM Prompt ('Prompt Injection')")), // Prompt Injection, LLM System Prompt Override, Agent Output Parsing Injection
        532 => Some(String::from("CWE-532: Insertion of Sensitive Information into Log File")),
        922 => Some(String::from("CWE-922: Improper Neutralization of Input in an Agent Memory/State")),
        _ => None,
    }
}

fn map_cwe_to_soc2(cwe: u32) -> Option<String> {
    match cwe {
        79 => Some(String::from("CC6.1: Logical Access Security Measures")), // XSS
        89 => Some(String::from("CC6.1: Logical Access Security Measures")), // SQL Injection
        78 => Some(String::from("CC6.1: Logical Access Security Measures")), // OS Command Injection
        94 => Some(String::from("CC6.1: Logical Access Security Measures")), // Code Injection
        611 => Some(String::from("CC6.7: Data Transmission and Disposal")), // XXE
        918 => Some(String::from("CC6.1: Logical Access Security Measures")), // SSRF
        22 => Some(String::from("CC6.1: Logical Access Security Measures")), // Path Traversal
        113 => Some(String::from("CC6.1: Logical Access Security Measures")), // HTTP Response Splitting
        601 => Some(String::from("CC6.1: Logical Access Security Measures")), // Open Redirect
        201 => Some(String::from("CC6.7: Data Transmission and Disposal")), // Sensitive Data Exposure
        1321 => Some(String::from("CC6.1: Logical Access Security Measures")), // Prototype Pollution
        1336 => Some(String::from("CC6.1: Logical Access Security Measures")), // SSTI, RAG Poisoning
        1427 => Some(String::from("CC6.1: Logical Access Security Measures")), // Prompt Injection
        532 => Some(String::from("CC7.1: System Monitoring")), // Sensitive Data in Logs
        922 => Some(String::from("CC6.1: Logical Access Security Measures")), // Insecure Agent State
        _ => None,
    }
}

fn map_cwe_to_iso27001(cwe: u32) -> Option<String> {
    match cwe {
        79 => Some(String::from("A.8.2: Information Classification / A.14.2: Security in Development")), // XSS
        89 => Some(String::from("A.14.2: Security in Development / A.12.2: Protection from Malware")), // SQL Injection
        78 => Some(String::from("A.14.2: Security in Development")), // OS Command Injection
        94 => Some(String::from("A.14.2: Security in Development")), // Code Injection
        611 => Some(String::from("A.14.2: Security in Development")), // XXE
        918 => Some(String::from("A.14.2: Security in Development / A.13.1: Network Controls")), // SSRF
        22 => Some(String::from("A.9.1: Access Control / A.14.2: Security in Development")), // Path Traversal
        113 => Some(String::from("A.14.2: Security in Development")), // HTTP Response Splitting
        601 => Some(String::from("A.14.2: Security in Development")), // Open Redirect
        201 => Some(String::from("A.8.2: Information Classification / A.13.1: Network Controls")), // Data Exposure
        1321 => Some(String::from("A.14.2: Security in Development")), // Prototype Pollution
        1336 => Some(String::from("A.14.2: Security in Development")), // SSTI, RAG Poisoning
        1427 => Some(String::from("A.14.2: Security in Development")), // Prompt Injection
        532 => Some(String::from("A.12.2: Protection from Malware / A.12.4: Logging")), // Logs
        922 => Some(String::from("A.14.2: Security in Development")), // Insecure Agent State
        _ => None,
    }
}

fn render_report(report: ComplianceReport, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Markdown => {
            println!("# Fallow Security Compliance Report ({:?})\n", report.report_type);
            println!("## Summary\n");
            for (category, count) in report.summary {
                println!("- {}: {}", category, count);
            }
            println!("\n## Findings\n");
            if report.findings.is_empty() {
                println!("No findings relevant to this report type.\n");
            } else {
                let table = Table::new(&report.findings).to_string();
                println!("{}\n", table);
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}