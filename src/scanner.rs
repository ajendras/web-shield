use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use regex::Regex;
use reqwest::{Client, header::HeaderMap};
use tokio::sync::Semaphore;

use crate::detectors::{check_security_headers, check_cors_headers, detect_tech, evaluate_csp};
use crate::error::{Error, Result};
use crate::types::{Finding, Rule, ScanReport, Severity};

/// Resolves a target which can be:
/// - a direct URL,
/// - a local sitemap.xml or remote sitemap URL (parsed for <loc> tags),
/// - or a local plain-text list (one URL per line, # comments ignored).
///
/// Returns deduplicated URLs in discovery order. Used by the CLI and exposed
/// for library users who want to feed sitemaps or URL lists into scan_multiple.
pub async fn resolve_urls(target: &str) -> Result<Vec<String>> {
    let target = target.trim();
    if target.is_empty() {
        return Err(Error::InvalidInput("Empty target".to_string()));
    }

    if target.starts_with("http://") || target.starts_with("https://") {
        if target.ends_with(".xml")
            || target.to_lowercase().contains("sitemap")
        {
            let content = fetch_sitemap(target).await?;
            Ok(parse_sitemap(&content))
        } else {
            Ok(vec![target.to_string()])
        }
    } else {
        let path = std::path::Path::new(target);
        if !path.exists() {
            return Err(Error::InvalidInput(format!(
                "Path does not exist: {}",
                target
            )));
        }
        let content = std::fs::read_to_string(path).map_err(Error::Io)?;
        if target.ends_with(".xml")
            || target.to_lowercase().contains("sitemap")
        {
            Ok(parse_sitemap(&content))
        } else {
            Ok(read_url_list(&content))
        }
    }
}

async fn fetch_sitemap(sitemap_url: &str) -> Result<String> {
    let client = create_client()?;
    let resp = client.get(sitemap_url).send().await?;
    resp.text().await.map_err(Error::from)
}

/// Performs a passive scan of the given URL.
///
/// Fetches the target once with a carefully crafted client that identifies
/// itself as the Web Shield scanner. No active payloads or vulnerability
/// probing is performed. Returns a `ScanReport` containing all findings,
/// technology fingerprint, risk score (0-100) and the raw headers.
pub async fn scan(url: &str, rules: Option<&[Rule]>) -> Result<ScanReport> {
    let client = create_client()?;

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

/// Performs parallel passive scans of multiple URLs with a shared rate limiter
/// (tokio::sync::Semaphore). The semaphore limits concurrent HTTP requests to
/// `max_concurrent`. Each scan runs independently; LLM analysis happens
/// sequentially after all fetches complete. Order of results matches input.
pub async fn scan_multiple(
    urls: &[String],
    rules: Option<&[Rule]>,
    max_concurrent: usize,
) -> Result<Vec<ScanReport>> {
    if urls.is_empty() {
        return Ok(vec![]);
    }
    if max_concurrent < 1 {
        return Err(Error::InvalidInput(
            "max_concurrent must be at least 1".to_string(),
        ));
    }

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::with_capacity(urls.len());

    for url in urls {
        let semaphore = Arc::clone(&semaphore);
        let url = url.clone();
        let rules_clone = rules.map(|r| r.to_vec());

        let handle = tokio::spawn(async move {
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|e| Error::InvalidInput(format!("Rate limiter semaphore closed: {}", e)))?;

            scan(&url, rules_clone.as_deref()).await
        });
        handles.push(handle);
    }

    let mut reports = Vec::with_capacity(handles.len());
    for handle in handles {
        let report = handle
            .await
            .map_err(|e| Error::InvalidInput(format!("Join error in parallel scan: {}", e)))??;
        reports.push(report);
    }

    Ok(reports)
}

fn create_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Web-Shield/0.1 (+https://github.com/web-shield/web-shield)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(Error::from)
}

fn parse_sitemap(content: &str) -> Vec<String> {
    let re = sitemap_regex();
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    for cap in re.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let url = m.as_str().trim().to_string();
            if (url.starts_with("http://") || url.starts_with("https://"))
                && seen.insert(url.clone())
            {
                urls.push(url);
            }
        }
    }
    urls
}

fn read_url_list(content: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with("http://") || line.starts_with("https://") {
            urls.push(line.to_string());
        }
    }
    urls
}

fn sitemap_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"<loc[^>]*>(?:\s*<!\[CDATA\[)?\s*(https?://[^\s<"]+)"#).unwrap()
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

pub fn calculate_score_for_test(findings: &[Finding]) -> u8 {
    calculate_score(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sitemap() {
        let xml = r#"
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/</loc>
  </url>
  <url>
    <loc>https://example.com/about</loc>
  </url>
  <url>
    <loc>https://example.com/blog</loc>
  </url>
  <url>
    <loc><![CDATA[https://example.com/cdata-page]]></loc>
  </url>
</urlset>
        "#;
        let urls = parse_sitemap(xml);
        assert_eq!(
            urls,
            vec![
                "https://example.com/".to_string(),
                "https://example.com/about".to_string(),
                "https://example.com/blog".to_string(),
                "https://example.com/cdata-page".to_string(),
            ]
        );
    }

    #[test]
    fn test_read_url_list() {
        let list = r#"
https://example.com
# this is a comment
https://test.com

https://example.com/about
// another comment
https://staging.example.com
        "#;
        let urls = read_url_list(list);
        assert_eq!(
            urls,
            vec![
                "https://example.com".to_string(),
                "https://test.com".to_string(),
                "https://example.com/about".to_string(),
                "https://staging.example.com".to_string(),
            ]
        );
    }
}
