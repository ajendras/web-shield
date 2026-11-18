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

use std::path::Path;

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
    )
    .await?;
    println!(
        "\x1b[0;32m[+]\x1b[0m Scan completed — Risk score: {}/100 ({} findings)\n",
        report.score,
        report.findings.len()
    );

    // Retro terminal report (phosphor-green ASCII boxes)
    report::print_terminal(&report);

    // LLM analysis (plain English + concrete fix snippets)
    println!("\x1b[0;32m[LLM] Querying Ollama for risk explanation...\x1b[0m");
    let llm = LlmClient::new();
    let explanation = match llm.explain(&report, "llama3.2").await {
        Ok(text) => {
            println!("\x1b[0;32m[LLM] Explanation received ({} chars)\x1b[0m", text.len());
            text
        }
        Err(e) => {
            let msg = format!(
                "LLM analysis unavailable: {}.\n\n\
                 Make sure Ollama is running (`ollama serve`) and the model is pulled:\n\
                 $ ollama pull llama3.2",
                e
            );
            println!("\x1b[0;33m[LLM] {}\x1b[0m", msg.split('\n').next().unwrap());
            msg
        }
    };

    // Markdown report with embedded LLM insights and ready-to-use config snippets
    let markdown = report::to_markdown(&report, &explanation);
    let output_path = "web-shield-full-report.md";
    std::fs::write(output_path, markdown).map_err(web_shield::error::Error::from)?;

    println!("\n\x1b[0;32m┌──────────────────────────────────────────────────────────────┐");
    println!("│ Report files written                                         │");
    println!("├──────────────────────────────────────────────────────────────┤");
    println!("│ • Retro terminal summary above                               │");
    println!("│ • Full Markdown report with LLM analysis → {} │", output_path);
    println!("└──────────────────────────────────────────────────────────────┘\x1b[0m");

    println!("\n\x1b[0;32mExample completed. Run `web-shield scan {}` for the full CLI experience.\x1b[0m", url);

    Ok(())
}
