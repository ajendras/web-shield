//! Loads organization-specific rules from YAML. Falls back to embedded
//! default rules when no file is supplied. Rules extend the built-in
//! detectors via the `Rule` trait-compatible struct.

use std::path::Path;

use crate::error::{Error, Result};
use crate::types::Rule;

/// Embedded default rule set. The file is maintained alongside the binary
/// and provides sensible baseline policies for common web frameworks and
/// header configurations.
const DEFAULT_RULES: &str = include_str!("../rules/default.yaml");

/// Loads rules from a user-provided YAML file or the embedded defaults.
///
/// The YAML must deserialize to a sequence of `Rule` objects. Helpful
/// validation and error messages are provided for missing files or
/// malformed YAML.
pub fn load_rules(path: Option<&Path>) -> Result<Vec<Rule>> {
    let content = if let Some(p) = path {
        if !p.exists() {
            return Err(Error::InvalidInput(format!(
                "Rules file not found: {}. Provide a valid path or omit --rules to use defaults.",
                p.display()
            )));
        }
        std::fs::read_to_string(p).map_err(Error::Io)?
    } else {
        DEFAULT_RULES.to_string()
    };

    let rules: Vec<Rule> = serde_yaml::from_str(&content).map_err(|e| {
        Error::InvalidInput(format!(
            "Failed to parse rules YAML: {}. Check syntax and that it is a list of rules.",
            e
        ))
    })?;

    // Validate that every rule has non-empty fields (production guard)
    for rule in &rules {
        if rule.id.trim().is_empty()
            || rule.title.trim().is_empty()
            || rule.description.trim().is_empty()
        {
            return Err(Error::InvalidInput(
                "One or more rules contain empty id/title/description fields".to_string(),
            ));
        }
    }

    Ok(rules)
}
