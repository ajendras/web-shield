//! Security header and technology detectors.
//!
//! Pure functions that analyze HTTP response data and return findings or
//! technology identifiers. No network activity.

use std::collections::HashSet;

use reqwest::header::HeaderMap;
use reqwest::Response;

use crate::types::{Finding, Severity};

/// Checks for common security headers and returns a list of findings for any
/// that are missing or misconfigured. Also inspects Set-Cookie headers.
pub fn check_security_headers(headers: &HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    let header_checks: Vec<(&str, &str, Severity, &str, &str)> = vec![
        (
            "strict-transport-security",
            "Missing HSTS",
            Severity::High,
            "Site is vulnerable to SSL stripping and man-in-the-middle attacks.",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ),
        (
            "x-frame-options",
            "Missing X-Frame-Options",
            Severity::Medium,
            "Clickjacking attacks are possible because the site can be iframed.",
            "Add X-Frame-Options: DENY (or SAMEORIGIN for specific use-cases)",
        ),
        (
            "x-content-type-options",
            "Missing X-Content-Type-Options",
            Severity::Medium,
            "MIME-type sniffing may allow malicious files to be executed differently than declared.",
            "Add X-Content-Type-Options: nosniff",
        ),
        (
            "referrer-policy",
            "Missing Referrer-Policy",
            Severity::Low,
            "Full URLs may be leaked to third-party origins in cross-origin requests.",
            "Add Referrer-Policy: strict-origin-when-cross-origin",
        ),
        (
            "permissions-policy",
            "Missing Permissions-Policy",
            Severity::Low,
            "Browser features (camera, microphone, geolocation) are not restricted.",
            "Add Permissions-Policy header with desired feature controls.",
        ),
    ];

    for (name, title, severity, description, recommendation) in header_checks {
        if !headers.contains_key(name) {
            findings.push(Finding {
                id: format!("missing-{}", name.replace('-', "_")),
                severity,
                title: title.to_string(),
                description: description.to_string(),
                recommendation: recommendation.to_string(),
            });
        }
    }

    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        findings.push(Finding {
            id: "server-header-disclosure".to_string(),
            severity: Severity::Low,
            title: "Server header discloses technology".to_string(),
            description: format!("The Server response header reveals backend information: '{}'.", server),
            recommendation: "Remove or genericise the Server header (e.g. via server_tokens off; in Nginx).".to_string(),
        });
    }

    for cookie_hdr in headers.get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            let lower = cookie_str.to_lowercase();
            if !lower.contains("secure") {
                findings.push(Finding {
                    id: "cookie-missing-secure".to_string(),
                    severity: Severity::Medium,
                    title: "Cookie missing Secure flag".to_string(),
                    description: "Cookies can be transmitted over unencrypted HTTP connections.".to_string(),
                    recommendation: "Add the Secure attribute to every Set-Cookie header.".to_string(),
                });
            }
            if !lower.contains("httponly") {
                findings.push(Finding {
                    id: "cookie-missing-httponly".to_string(),
                    severity: Severity::Medium,
                    title: "Cookie missing HttpOnly flag".to_string(),
                    description: "JavaScript can read this cookie (session cookies are especially sensitive).".to_string(),
                    recommendation: "Add the HttpOnly attribute.".to_string(),
                });
            }
            if lower.contains("samesite=none") && !lower.contains("secure") {
                findings.push(Finding {
                    id: "cookie-samesite-none-no-secure".to_string(),
                    severity: Severity::High,
                    title: "SameSite=None without Secure flag".to_string(),
                    description: "SameSite=None cookies must be marked Secure.".to_string(),
                    recommendation: "Add Secure when SameSite=None is used.".to_string(),
                });
            }
        }
    }

    findings
}

/// Detects technology stack based on response headers (Server, X-Powered-By, etc).
pub fn detect_tech(res: &Response) -> Vec<String> {
    let mut tech = HashSet::new();
    let headers = res.headers();

    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let s = server.to_lowercase();
        tech.insert(server.to_string());
        if s.contains("nginx") {
            tech.insert("nginx".to_string());
        }
        if s.contains("apache") {
            tech.insert("apache".to_string());
        }
        if s.contains("express") {
            tech.insert("express".to_string());
        }
        if s.contains("cloudflare") {
            tech.insert("cloudflare".to_string());
        }
    }

    if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        tech.insert(powered.to_string());
    }

    if let Some(aspnet) = headers.get("x-aspnet-version").and_then(|v| v.to_str().ok()) {
        tech.insert(format!("ASP.NET ({})", aspnet));
    }

    if let Some(runtime) = headers.get("x-runtime").and_then(|v| v.to_str().ok()) {
        tech.insert(format!("Ruby on Rails ({})", runtime));
    }

    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        let ctl = ct.to_lowercase();
        if ctl.contains("php") {
            tech.insert("php".to_string());
        }
        if ctl.contains("python") || ctl.contains("wsgi") {
            tech.insert("python".to_string());
        }
        if ctl.contains("django") {
            tech.insert("django".to_string());
        }
    }

    let mut tech_vec: Vec<_> = tech.into_iter().collect();
    tech_vec.sort();
    tech_vec
}

/// Evaluates a Content-Security-Policy header value for dangerous or missing directives.
pub fn evaluate_csp(csp: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lower = csp.to_ascii_lowercase();

    if lower.contains("'unsafe-inline'") {
        findings.push(Finding {
            id: "csp-unsafe-inline".to_string(),
            severity: Severity::Medium,
            title: "CSP contains 'unsafe-inline'".to_string(),
            description: "'unsafe-inline' disables most of CSP's XSS protection by allowing inline scripts and styles.".to_string(),
            recommendation: "Replace with nonces or hashes: script-src 'self' 'nonce-xyz123';".to_string(),
        });
    }

    if lower.contains("'unsafe-eval'") {
        findings.push(Finding {
            id: "csp-unsafe-eval".to_string(),
            severity: Severity::Medium,
            title: "CSP contains 'unsafe-eval'".to_string(),
            description: "eval() and similar dynamic code execution is allowed, expanding the attack surface.".to_string(),
            recommendation: "Remove unsafe-eval and refactor code that depends on it.".to_string(),
        });
    }

    if !lower.contains("default-src") {
        findings.push(Finding {
            id: "csp-no-default-src".to_string(),
            severity: Severity::Low,
            title: "CSP does not define default-src".to_string(),
            description: "Missing default-src can lead to overly permissive fallback behavior.".to_string(),
            recommendation: "Add default-src 'self'; to the policy.".to_string(),
        });
    }

    if !lower.contains("object-src") && !lower.contains("base-uri") {
        findings.push(Finding {
            id: "csp-missing-object-base".to_string(),
            severity: Severity::Low,
            title: "CSP should restrict object-src and base-uri".to_string(),
            description: "Plugins and base URI are not restricted, opening vectors for injection.".to_string(),
            recommendation: "Add object-src 'none'; base-uri 'self';".to_string(),
        });
    }

    if csp.trim().is_empty() {
        findings.push(Finding {
            id: "csp-empty".to_string(),
            severity: Severity::High,
            title: "CSP header is present but empty".to_string(),
            description: "An empty CSP header grants no protection.".to_string(),
            recommendation: "Replace with a functional policy.".to_string(),
        });
    }

    findings
}

/// Checks for dangerous CORS header combinations.
pub fn check_cors_headers(headers: &HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    let origin = headers.get("access-control-allow-origin");
    let credentials = headers.get("access-control-allow-credentials");

    if let (Some(o), Some(c)) = (origin, credentials) {
        if o.to_str().unwrap_or_default() == "*" && c.to_str().unwrap_or_default().to_lowercase() == "true" {
            findings.push(Finding {
                id: "cors-wildcard-with-credentials".to_string(),
                severity: Severity::High,
                title: "CORS wildcard origin with credentials enabled".to_string(),
                description: "Access-Control-Allow-Origin: * combined with credentials=true is invalid and can expose sensitive data.".to_string(),
                recommendation: "Specify an explicit origin instead of '*' or disable credentials.".to_string(),
            });
        }
    }

    findings
}
