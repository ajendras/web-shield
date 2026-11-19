//! Web Shield library.
//!
//! Provides the core scanner, detectors, types, LLM integration, reporting
//! and configuration primitives. The crate can be used both as a binary
//! (via src/main.rs) and as a library for embedding passive web security
//! scans in other Rust projects.

pub mod config;
pub mod detectors;
pub mod error;
pub mod llm;
pub mod report;
pub mod scanner;
pub mod types;
pub mod ui;
