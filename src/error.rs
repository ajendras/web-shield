//! Custom error types for the Web Shield scanner.
//!
//! Centralised error handling with rich variants for all failure modes
//! (network, IO, parsing, LLM communication). Uses `thiserror` for
//! ergonomic `?` propagation and user-friendly messages.

use std::fmt;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Any IO error (reading rules file, writing reports, etc).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Errors from the HTTP client (timeouts, connection failures, TLS issues).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// User-provided input that failed validation (bad URL, missing rules file, etc).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Failures talking to the local Ollama instance (not running, model not found,
    /// malformed JSON response, etc).
    #[error("LLM error: {0}")]
    Llm(String),

    /// JSON (de)serialisation errors for reports.
    #[error("JSON error: {0}")]
    Json(String),

    /// YAML parsing errors for custom rule files.
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err.to_string())
    }
}

/// Convenient alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
