//! Core data types for scan results, findings, severity levels and custom rules.
//!
//! These types are shared across the scanner, detectors, LLM analyst, reporting
//! and configuration modules. `ScanReport` is serializable for JSON/SARIF output
//! and deserializable for the `analyze` subcommand.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Severity of a security finding. Used for scoring, coloring, and SARIF levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A concrete security observation or violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier (e.g. "missing-hsts", "csp-unsafe-inline")
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

/// Complete passive scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub url: String,
    pub findings: Vec<Finding>,
    pub tech: Vec<String>,
    pub score: u8,
    pub raw_headers: HashMap<String, String>,
}

/// Custom rule definition loaded from YAML (or embedded defaults).
///
/// Rules can be header-triggered or always-on. They extend the built-in
/// detectors with organization-specific policies.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub header: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

/// A chat message exchanged with the LLM in the interactive UI.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}
