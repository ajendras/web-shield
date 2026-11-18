//! Integration tests for the passive scanner.
//!
//! Uses the `mockito` crate to simulate HTTP servers with carefully chosen
//! headers that trigger every major detector. Asserts correct findings,
//! severity, technology fingerprint, and risk scoring.

use mockito::{Matcher, Server};
use web_shield::{
    detectors::{check_security_headers, evaluate_csp},
    scanner,
    types::{Finding, ScanReport, Severity},
};

#[tokio::test]
async fn test_scanner_missing_hsts_csp_and_tech() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("server", "nginx/1.21.6")
        .with_header("x-powered-by", "PHP/8.1")
        .with_header("set-cookie", "sess=abc123; Path=/")
        .with_header("content-type", "text/html")
        // deliberately missing: Strict-Transport-Security, X-Frame-Options, CSP
        .with_body("<html><body>test</body></html>")
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let report: ScanReport = scanner::scan(&url, None).await.expect("scan must succeed");

    assert_eq!(report.url, url);
    assert!(!report.findings.is_empty());

    let ids: Vec<String> = report.findings.iter().map(|f| f.id.clone()).collect();

    // Core header detectors
    assert!(ids.contains(&"missing-strict-transport-security".to_string()));
    assert!(ids.contains(&"missing-x-frame-options".to_string()));
    assert!(ids.contains(&"missing-x-content-type-options".to_string()));
    assert!(ids.contains(&"csp-missing".to_string()));

    // Cookie flag detectors
    assert!(ids.contains(&"cookie-missing-secure".to_string()));
    assert!(ids.contains(&"cookie-missing-httponly".to_string()));

    // Technology fingerprint
    assert!(report.tech.iter().any(|t| t.to_lowercase().contains("nginx")));
    assert!(report.tech.iter().any(|t| t.contains("PHP")));

    // Score should reflect the missing critical headers
    assert!(report.score < 60, "score was {}", report.score);

    // Server header disclosure finding
    assert!(ids.contains(&"server-header-disclosure".to_string()));
}

#[tokio::test]
async fn test_evaluate_csp_unsafe_inline_and_eval() {
    let csp = "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' 'self';";

    let findings = evaluate_csp(csp);

    assert_eq!(findings.len(), 3);

    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"csp-unsafe-inline"));
    assert!(ids.contains(&"csp-unsafe-eval"));
    assert!(ids.contains(&"csp-missing-object-base"));

    let unsafe_inline = findings
        .iter()
        .find(|f| f.id == "csp-unsafe-inline")
        .unwrap();
    assert_eq!(unsafe_inline.severity, Severity::Medium);
}

#[tokio::test]
async fn test_check_security_headers_cookie_flags() {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("session=xyz; Path=/; SameSite=None"),
    );
    // missing Secure on SameSite=None should trigger high-severity finding

    let findings = check_security_headers(&headers);

    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"cookie-missing-secure"));
    assert!(ids.contains(&"cookie-missing-httponly"));
    assert!(ids.contains(&"cookie-samesite-none-no-secure"));

    let high = findings
        .iter()
        .find(|f| f.id == "cookie-samesite-none-no-secure")
        .unwrap();
    assert_eq!(high.severity, Severity::High);
}

#[tokio::test]
async fn test_scanner_with_custom_rules() {
    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("x-custom-header", "bad-value")
        .with_body("ok")
        .create_async()
        .await;

    // Minimal rule that should always trigger because it has no header filter
    let rules = vec![web_shield::types::Rule {
        id: "test-rule".to_string(),
        header: None,
        severity: Severity::Medium,
        title: "Test custom rule".to_string(),
        description: "This rule should always fire".to_string(),
        recommendation: "Fix it".to_string(),
    }];

    let url = server.url();
    let report = scanner::scan(&url, Some(&rules)).await.unwrap();

    let custom = report
        .findings
        .iter()
        .find(|f| f.id == "test-rule");
    assert!(custom.is_some(), "custom rule was not applied");
}

#[tokio::test]
async fn test_calculate_score_boundaries() {
    // All findings are Low → score should be high but not 100
    let low_findings = vec![Finding {
        id: "low-1".into(),
        severity: Severity::Low,
        title: "Low".into(),
        description: "desc".into(),
        recommendation: "rec".into(),
    }];

    let score = web_shield::scanner::calculate_score_for_test(&low_findings); // internal helper exposed only for test
    assert!(score >= 90);

    // One Critical finding should tank the score
    let critical = vec![Finding {
        id: "crit".into(),
        severity: Severity::Critical,
        title: "Critical".into(),
        description: "desc".into(),
        recommendation: "rec".into(),
    }];
    let score = web_shield::scanner::calculate_score_for_test(&critical);
    assert!(score <= 70);
}
