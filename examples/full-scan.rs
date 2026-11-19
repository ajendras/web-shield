//! Full scan example for Web Shield.
//!
//! This runnable example demonstrates a complete end-to-end workflow:
//! 1. Loading embedded default rules
//! 2. Performing a passive scan (headers, cookies, CSP, CORS, tech fingerprint)
//! 3. Printing the retro terminal report
//! 4. Obtaining an LLM-generated plain-English explanation via Ollama
//! 5. Writing a rich Markdown report with copy-paste remediation snippets
//!
//! Run with: cargo run --example full-scan
//! (Ollama must be running with the requested model for the LLM step;
//! the example gracefully falls back if Ollama is unavailable.)

use web_shield::{
    config,
    error::Result,
    llm::LlmClient,
    report,
    scanner,
};

#[tokio::main]
async fn main() -> Result<()> {
    let url = "https://example.com";

    println!("\x1b[0;32m┌──────────────────────────────────────────────────────────────┐");
    println!("\x1b[0;32m│               WEB SHIELD — FULL SCAN EXAMPLE                 │");
    println!("\x1b[0;32m└──────────────────────────────────────────────────────────────┘\x1b[0m");
    println!("Target URL : {}", url);
    println!("Model      : llama3.2 (local Ollama)\n");

    // Load default rules (embedded in binary)
    let rules = config::load_rules(None)?;
    println!("\x1b[0;32m[+]\x1b[0m Loaded {} default security rules", rules.len());

    // Passive scan — single GET, no malicious payloads
    let report = scanner::scan(
        url,
        if rules.is_empty() { None } else { Some(&rules) },
    ).await?;
    println!(
        "\x1b[0;32m[+]\x1b[0m Scan complete — score: {}/100 ({} findings)",
        report.score,
        report.findings.len()
    );

    // Print retro terminal report
    report::print_terminal(&report);

    // Get LLM explanation (graceful fallback if Ollama not available)
    let llm = LlmClient::new();
    let explanation = match llm.explain(&report, "llama3.2").await {
        Ok(text) => text,
        Err(e) => {
            eprintln!("\x1b[0;33m[!] LLM unavailable: {}. Using placeholder.\x1b[0m", e);
            "# LLM Analysis Skipped\n\nOllama is not running or the model is not pulled.\n\nRun:\n  ollama pull llama3.2\n  ollama run llama3.2".to_string()
        }
    };

    // Generate and write markdown report
    let markdown = report::to_markdown(&report, &explanation);
    let output_path = "web-shield-full-report.md";
    std::fs::write(output_path, markdown)?;

    println!("\x1b[0;32m[+] Full report with LLM analysis written to {}\x1b[0m", output_path);
    println!("\x1b[0;32m[+] Example completed successfully!\x1b[0m");

    Ok(())
}
