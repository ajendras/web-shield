//! Integration tests for the scanner and detectors using mock HTTP responses.

use reqwest;
use web_shield::detectors::{check_cors_headers, check_security_headers, detect_tech, evaluate_csp};
use web_shield::scanner::calculate_score_for_test as calculate_score;
use web_shield::types::{Finding, Severity};

#[tokio::test]
async fn test_check_security_headers() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("server", "Apache/2.4")
        .with_header(
            "set-cookie",
            "session=abc123; Path=/; Domain=example.com",
        ) // missing secure, httponly, samesite
        .with_header(
            "set-cookie",
            "csrf=def456; Path=/; Secure; SameSite=Strict; HttpOnly",
        ) // good cookie
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.url()).send().await.unwrap();
    let findings = check_security_headers(resp.headers());

    // Missing headers + server disclosure + cookie attribute issues
    assert!(findings.iter().any(|f| f.id.starts_with("missing-")));
    assert!(findings.iter().any(|f| f.id == "server-header-disclosure"));
    assert!(findings.iter().any(|f| f.id == "cookie-missing-secure"));
    assert!(findings.iter().any(|f| f.id == "cookie-missing-httponly"));
    // Good cookie prevents SameSite=None issue from firing
    assert!(!findings.iter().any(|f| f.id == "cookie-samesite-none-no-secure"));

    let score = calculate_score(&findings);
    assert!(score < 100);
}

#[tokio::test]
async fn test_cookie_samesite_none_no_secure() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/")
        .with_status(200)
        .with_header(
            "set-cookie",
            "crosssite=val; SameSite=None; Path=/",
        )
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.url()).send().await.unwrap();
    let findings = check_security_headers(resp.headers());

    assert!(findings.iter().any(|f| f.id == "cookie-samesite-none-no-secure"));
    assert!(findings.iter().any(|f| f.severity == Severity::High));
}

#[tokio::test]
async fn test_evaluate_csp() {
    let findings = evaluate_csp("default-src 'self'; script-src 'unsafe-inline'");
    assert!(findings.iter().any(|f| f.id == "csp-unsafe-inline"));

    let findings2 = evaluate_csp("");
    assert!(findings2.iter().any(|f| f.id == "csp-empty"));

    let findings3 = evaluate_csp("default-src 'self'; object-src 'none'; base-uri 'self';");
    assert!(!findings3.iter().any(|f| f.id == "csp-no-default-src"));
    assert!(!findings3.iter().any(|f| f.id == "csp-missing-object-base"));
}

#[tokio::test]
async fn test_check_cors_headers() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("access-control-allow-origin", "*".parse().unwrap());
    headers.insert("access-control-allow-credentials", "true".parse().unwrap());

    let findings = check_cors_headers(&headers);
    assert!(findings.iter().any(|f| f.id == "cors-wildcard-with-credentials"));
}

#[tokio::test]
async fn test_detect_tech() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/")
        .with_header("server", "nginx/1.21")
        .with_header("x-powered-by", "Express")
        .with_header("content-type", "text/html; charset=utf-8")
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.url()).send().await.unwrap();
    let tech = detect_tech(&resp);

    assert!(tech.contains(&"nginx".to_string()));
    assert!(tech.contains(&"Express".to_string()));
}

#[test]
fn test_calculate_score() {
    let findings = vec![
        Finding {
            id: "test-high".to_string(),
            severity: Severity::High,
            title: "High".to_string(),
            description: "".to_string(),
            recommendation: "".to_string(),
        },
        Finding {
            id: "test-medium".to_string(),
            severity: Severity::Medium,
            title: "Medium".to_string(),
            description: "".to_string(),
            recommendation: "".to_string(),
        },
        Finding {
            id: "test-low".to_string(),
            severity: Severity::Low,
            title: "Low".to_string(),
            description: "".to_string(),
            recommendation: "".to_string(),
        },
    ];

    let score = calculate_score(&findings);
    // 100 - 25 (High) - 12 (Medium) - 5 (Low) = 58
    assert_eq!(score, 58);
}

#[tokio::test]
async fn test_no_cookie_findings_when_all_secure() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/")
        .with_status(200)
        .with_header(
            "set-cookie",
            "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
        )
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(server.url()).send().await.unwrap();
    let findings = check_security_headers(resp.headers());

    assert!(!findings.iter().any(|f| f.id.starts_with("cookie-")));
}
