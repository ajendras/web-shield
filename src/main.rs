//! Web Shield — Passive web security scanner with local LLM analysis.
//!
//! Scans headers, cookies, CSP, and tech stack without sending malicious payloads,
//! then uses Ollama to generate plain-English risk summaries and concrete fixes.
//! Supports terminal UI, markdown/SARIF reports, custom rules, and CI mode.

use std::path::Path;
use std::process;

use clap::Parser;

mod cli;
mod config;
mod error;
mod llm;
mod report;
mod scanner;
mod types;
mod ui;

use cli::{Args, Commands};
use error::Result;

#[tokio::main]
async fn main() {
    let exit_code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("\x1b[0;31m[!] {}\x1b[0m", e);
            1
        }
    };
    process::exit(exit_code);
}

async fn run() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Scan(cmd) => scan_command(cmd).await,
        Commands::Analyze(cmd) => analyze_command(cmd).await,
        Commands::Interactive(cmd) => interactive_command(cmd).await,
    }
}

async fn scan_command(cmd: cli::ScanCmd) -> Result<()> {
    // Validate URL (extra safety beyond clap parser)
    if !cmd.url.starts_with("http://") && !cmd.url.starts_with("https://") {
        return Err(error::Error::InvalidInput(
            "URL must start with http:// or https://".to_string(),
        ));
    }

    let rules = config::load_rules(cmd.rules.as_deref())?;
    let report = scanner::scan(&cmd.url, if rules.is_empty() { None } else { Some(&rules) }).await?;

    let model = cmd.model.unwrap_or_else(|| "llama3.2".to_string());
    let llm = llm::LlmClient::new();
    let explanation = llm.explain(&report, &model).await?;

    if let Some(output) = cmd.output {
        let content = if output.ends_with(".json") {
            serde_json::to_string_pretty(&report)
                .map_err(|e| error::Error::Json(e.to_string()))?
        } else if output.ends_with(".sarif") {
            report::to_sarif(&report)
        } else {
            report::to_markdown(&report, &explanation)
        };
        std::fs::write(&output, content).map_err(error::Error::Io)?;
        println!("\x1b[0;32m[+] Report written to {}\x1b[0m", output);
    } else if cmd.ci {
        println!("{}", report::to_sarif(&report));
    } else {
        report::print_terminal(&report);
        println!("\n\x1b[0;32m=== LLM Analysis ({} ) ===\x1b[0m\n{}", model, explanation);
    }

    // Proper CI exit codes based on risk score (0 = clean, 1 = warnings, 2 = high risk)
    if report.score < 50 {
        process::exit(2);
    } else if report.score < 75 {
        process::exit(1);
    }

    Ok(())
}

async fn analyze_command(cmd: cli::AnalyzeCmd) -> Result<()> {
    let json = std::fs::read_to_string(&cmd.report).map_err(error::Error::Io)?;
    let report: types::ScanReport =
        serde_json::from_str(&json).map_err(|e| error::Error::Json(e.to_string()))?;

    let llm = llm::LlmClient::new();
    let explanation = llm.explain(&report, &cmd.model).await?;

    let markdown = report::to_markdown(&report, &explanation);
    std::fs::write(&cmd.output, markdown).map_err(error::Error::Io)?;

    println!(
        "\x1b[0;32m[+] Analysis complete. Markdown report saved to {}\x1b[0m",
        cmd.output.display()
    );
    Ok(())
}

async fn interactive_command(cmd: cli::InteractiveCmd) -> Result<()> {
    let report = if let Some(url) = cmd.url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(error::Error::InvalidInput(
                "URL must start with http:// or https://".to_string(),
            ));
        }
        let rules = config::load_rules(None)?;
        scanner::scan(&url, if rules.is_empty() { None } else { Some(&rules) }).await?
    } else {
        // Demo report for immediate UI demonstration when no URL is given
        types::ScanReport {
            url: "https://demo.example.com".to_string(),
            findings: vec![],
            tech: vec!["nginx".to_string(), "react".to_string()],
            score: 72,
            raw_headers: std::collections::HashMap::new(),
        }
    };

    ui::run_interactive(report)?;
    Ok(())
}
