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
    assert!(ids.contains(&"missing-referrer-policy".to_string()));
    assert!(ids.contains(&"csp-missing".to_string()));
    assert!(ids.contains(&"server-header-disclosure".to_string()));
    assert!(ids.contains(&"cookie-missing-secure".to_string()));
    assert!(ids.contains(&"cookie-missing-httponly".to_string()));

    // Tech fingerprint
    let tech_lower: Vec<String> = report.tech.iter().map(|t| t.to_lowercase()).collect();
    assert!(tech_lower.iter().any(|t| t.contains("nginx")));
    assert!(tech_lower.iter().any(|t| t.contains("php")));

    // Score reflects the high number of findings
    assert!(report.score < 60);
}

#[tokio::test]
async fn test_calculate_score() {
    let findings = vec![
        Finding {
            id: "high".to_string(),
            severity: Severity::High,
            title: "High".to_string(),
            description: "".to_string(),
            recommendation: "".to_string(),
        },
        Finding {
            id: "medium".to_string(),
            severity: Severity::Medium,
            title: "Medium".to_string(),
            description: "".to_string(),
            recommendation: "".to_string(),
        },
    ];
    let score = scanner::calculate_score_for_test(&findings);
    assert_eq!(score, 63); // 100 - 25 - 12
}

#[tokio::test]
async fn test_parallel_scan_with_rate_limiter() {
    let mut server1 = Server::new_async().await;
    let mut server2 = Server::new_async().await;

    let _mock1 = server1
        .mock("GET", "/")
        .with_status(200)
        .with_header("server", "nginx/1.21")
        .with_header("strict-transport-security", "max-age=31536000")
        .with_body("ok")
        .create_async()
        .await;

    let _mock2 = server2
        .mock("GET", "/")
        .with_status(200)
        .with_header("server", "Apache/2.4")
        .with_header("x-frame-options", "DENY")
        .with_body("ok")
        .create_async()
        .await;

    let urls = vec![format!("{}/", server1.url()), format!("{}/", server2.url())];
    let reports = scanner::scan_multiple(&urls, None, 2)
        .await
        .expect("parallel scan must succeed");

    assert_eq!(reports.len(), 2);

    let techs: Vec<String> = reports.iter().flat_map(|r| r.tech.clone()).collect();
    let tech_lower: Vec<String> = techs.iter().map(|t| t.to_lowercase()).collect();
    assert!(tech_lower.iter().any(|t| t.contains("nginx")));
    assert!(tech_lower.iter().any(|t| t.contains("apache")));

    for report in &reports {
        let ids: Vec<String> = report.findings.iter().map(|f| f.id.clone()).collect();
        // The first server should have fewer findings because of HSTS
        if report.url.contains(&server1.url()) {
            assert!(!ids.contains(&"missing-strict-transport-security".to_string()));
        }
        assert!(report.score > 40);
    }
}
