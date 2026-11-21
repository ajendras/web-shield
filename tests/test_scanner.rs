use mockito;
use web_shield::{
    scanner,
    types::{Finding, Severity},
};

#[test]
fn test_calculate_score_for_test() {
    // No findings should give a perfect score.
    let findings: Vec<Finding> = vec![];
    assert_eq!(scanner::calculate_score_for_test(&findings), 100);

    // A single High severity finding deducts 25 points.
    let findings = vec![Finding {
        id: "missing-hsts".to_string(),
        severity: Severity::High,
        title: "Missing HSTS".to_string(),
        description: "test desc".to_string(),
        recommendation: "test rec".to_string(),
    }];
    assert_eq!(scanner::calculate_score_for_test(&findings), 75);

    // Critical + High should deduct 65 points (capped at minimum 15 by the implementation).
    let findings = vec![
        Finding {
            id: "crit".to_string(),
            severity: Severity::Critical,
            title: "Critical issue".to_string(),
            description: "test".to_string(),
            recommendation: "test".to_string(),
        },
        Finding {
            id: "high".to_string(),
            severity: Severity::High,
            title: "High issue".to_string(),
            description: "test".to_string(),
            recommendation: "test".to_string(),
        },
    ];
    assert_eq!(scanner::calculate_score_for_test(&findings), 35);
}

#[tokio::test]
async fn test_passive_scan() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("server", "Apache/2.4.41 (Unix)")
        .with_header("set-cookie", "session=abc123")
        .with_header("content-type", "text/html; charset=utf-8")
        .create();

    let url = server.url();
    let report = scanner::scan(&url, None).await.unwrap();

    assert_eq!(report.url, url);
    assert!(!report.findings.is_empty());

    let finding_ids: Vec<String> = report.findings.iter().map(|f| f.id.clone()).collect();
    assert!(finding_ids.contains(&"server-header-disclosure".to_string()));
    assert!(finding_ids.contains(&"cookie-missing-secure".to_string()));
    assert!(finding_ids.contains(&"cookie-missing-httponly".to_string()));
    assert!(finding_ids.contains(&"csp-missing".to_string()));

    assert!(report
        .tech
        .iter()
        .any(|t| t.contains("apache") || t.contains("Apache")));

    // Multiple missing headers and cookie issues reduce the score.
    assert!(report.score < 80);

    mock.assert();
}

#[tokio::test]
async fn test_scan_multiple() {
    let mut server1 = mockito::Server::new();
    let mut server2 = mockito::Server::new();

    let _m1 = server1.mock("GET", "/").with_status(200).create();
    let _m2 = server2.mock("GET", "/").with_status(200).create();

    let urls = vec![server1.url(), server2.url()];
    let reports = scanner::scan_multiple(&urls, None, 2).await.unwrap();

    assert_eq!(reports.len(), 2);

    let reported_urls: Vec<&String> = reports.iter().map(|r| &r.url).collect();
    assert!(reported_urls.contains(&&urls[0]));
    assert!(reported_urls.contains(&&urls[1]));
}
