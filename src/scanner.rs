//! Passive security scanner.
//!
//! Makes a single non-intrusive HTTP request and analyzes response headers,
//! cookies, CSP directives, CORS policy and technology fingerprints.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::{Client, header::HeaderMap};

use crate::detectors::{check_security_headers, check_cors_headers, detect_tech, evaluate_csp};
use crate::error::{Error, Result};
use crate::types::{Finding, Rule, ScanReport, Severity};

/// Performs a passive scan of the given URL.
///
/// Fetches the target once with a carefully crafted client that identifies
/// itself as the Web Shield scanner. No active payloads or vulnerability
/// probing is performed. Returns a `ScanReport` containing all findings,
/// technology fingerprint, risk score (0-100) and the raw headers.
pub async fn scan(url: &str, rules: Option<&[Rule]>) -> Result<ScanReport> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Web-Shield/0.1 (+https://github.com/web-shield/web-shield)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(Error::from)?;

    let res = client.get(url).send().await?;

    let headers = res.headers().clone();
    let tech = detect_tech(&res);

    let mut findings = check_security_headers(&headers);

    if let Some(csp) = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
    {
        findings.extend(evaluate_csp(csp));
    } else {
        findings.push(Finding {
            id: "csp-missing".to_string(),
            severity: Severity::High,
            title: "Content-Security-Policy header is missing".to_string(),
            description: "Without a CSP the browser has no mechanism to prevent XSS, data injection, and clickjacking.".to_string(),
            recommendation: "Add a strong CSP. For Nginx:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\"; always;".to_string(),
        });
    }

    findings.extend(check_cors_headers(&headers));

    if let Some(rules) = rules {
        findings.extend(apply_rules(rules, &headers, &tech));
    }

    let raw_headers: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("<non-utf8-value>").to_string(),
            )
        })
        .collect();

    let score = calculate_score(&findings);

    Ok(ScanReport {
        url: url.to_string(),
        findings,
        tech,
        score,
        raw_headers,
    })
}

fn calculate_score(findings: &[Finding]) -> u8 {
    let mut score = 100u8;

    for finding in findings {
        let deduction = match finding.severity {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 12,
            Severity::Low => 5,
            Severity::Info => 0,
        };
        score = score.saturating_sub(deduction);
    }

    score.max(15)
}

fn apply_rules(rules: &[Rule], headers: &HeaderMap, _tech: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        let triggered = if let Some(ref header_name) = rule.header {
            headers.contains_key(header_name.as_str())
        } else {
            true
        };

        if triggered {
            findings.push(Finding {
                id: rule.id.clone(),
                severity: rule.severity.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                recommendation: rule.recommendation.clone(),
            });
        }
    }

    findings
}
