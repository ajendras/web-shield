//! Web Shield library.
//!
//! Provides the core scanner, detectors, types, LLM integration, reporting
//! and configuration primitives. The crate can be used both as a binary
//! (via src/main.rs) and as a library for embedding passive web security
//! scans in other Rust projects.
//!
//! ## Parallel multi-URL scanning
//!
//! ```no_run
//! use web_shield::{config, error::Result, scanner};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let rules = config::load_rules(None)?;
//!     let urls = vec!["https://example.com".to_string(), "https://test.com".to_string()];
//!     let reports = scanner::scan_multiple(&urls, Some(&rules), 4).await?;
//!     println!("Scanned {} sites", reports.len());
//!     Ok(())
//! }
//! ```
//!
//! ## Loading URLs from sitemap or list (new)
//!
//! ```no_run
//! use web_shield::{config, error::Result, scanner};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let rules = config::load_rules(None)?;
//!     let urls = scanner::resolve_urls("sitemap.xml").await?;
//!     let reports = scanner::scan_multiple(&urls, Some(&rules), 10).await?;
//!     println!("Scanned {} sites from sitemap", reports.len());
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod detectors;
pub mod error;
pub mod llm;
pub mod report;
pub mod scanner;
pub mod types;
pub mod ui;
