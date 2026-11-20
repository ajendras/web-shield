use mockito::Server;
use web_shield::{
    config,
    scanner,
    types::{Finding, Severity},
};

#[tokio::test]
async fn test_passive_scan() {
    let mut server = Server::new();
    let _mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("strict-transport-security", "max-age=31536000")
        .with_header("x-frame-options", "DENY")
        .with_header("content-security-policy", "default-src 'self'")
        .with_header("server", "nginx")
        .with_body("<html>ok</html>")
        .create();

    let rules = config::load_rules(None).expect("rules load");
    let report = scanner::scan(&server.url(), Some(&rules))
        .await
        .expect("scan succeeds");

    assert_eq!(report.url, server.url());
    assert!(!report.tech.is_empty());
    assert!(report.score < 100);
    assert!(report.findings.iter().any(|f| f.id.contains("server-header")));
    assert!(!report.findings.is_empty());
}

#[test]
fn test_calculate_score_for_test() {
    let findings = vec![
        Finding {
            id: "high1".into(),
            severity: Severity::High,
            title: "High".into(),
            description: "desc".into(),
            recommendation: "rec".into(),
        },
        Finding {
            id: "med1".into(),
            severity: Severity::Medium,
            title: "Med".into(),
            description: "desc".into(),
            recommendation: "rec".into(),
        },
    ];

    let score = scanner::calculate_score_for_test(&findings);
    assert_eq!(score, 63);
}

#[tokio::test]
async fn test_scan_multiple() {
    let urls = vec![
        "https://example.com".to_string(),
        "https://httpbin.org".to_string(),
    ];
    let rules = config::load_rules(None).ok();
    let reports = scanner::scan_multiple(&urls, rules.as_deref(), 2)
        .await
        .expect("multi scan");

    assert_eq!(reports.len(), 2);
    for report in reports {
        assert!(report.score <= 100);
        assert!(!report.url.is_empty());
    }
}
