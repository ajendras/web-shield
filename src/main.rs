use std::collections::HashSet;
use std::process;

use clap::Parser;

mod cli;

use web_shield::{config, error::{self, Result}, llm, report, scanner, types, ui};
use cli::{Args, Commands};

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
    let rules = config::load_rules(cmd.rules.as_deref())?;
    let rules_ref = if rules.is_empty() { None } else { Some(rules.as_slice()) };

    let mut all_urls = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    for target in &cmd.urls {
        let resolved = scanner::resolve_urls(target).await?;
        for u in resolved {
            if seen.insert(u.clone()) {
                all_urls.push(u);
            }
        }
    }

    if all_urls.is_empty() {
        return Err(error::Error::InvalidInput(
            "No valid URLs to scan".to_string(),
        ));
    }

    let reports = if all_urls.len() == 1 {
        vec![scanner::scan(&all_urls[0], rules_ref).await?]
    } else {
        scanner::scan_multiple(&all_urls, rules_ref, cmd.max_concurrent).await?
    };

    let model = cmd.model.unwrap_or_else(|| "llama3.2".to_string());
    let llm = llm::LlmClient::new();
    let mut explanations = Vec::with_capacity(reports.len());
    for report in &reports {
        let explanation = llm.explain(report, &model).await?;
        explanations.push(explanation);
    }

    if let Some(output) = cmd.output {
        let content = if output.ends_with(".json") {
            if reports.len() == 1 {
                serde_json::to_string_pretty(&reports[0])
                    .map_err(|e| error::Error::Json(e.to_string()))?
            } else {
                serde_json::to_string_pretty(&reports)
                    .map_err(|e| error::Error::Json(e.to_string()))?
            }
        } else if output.ends_with(".sarif") {
            if reports.len() == 1 {
                report::to_sarif(&reports[0])
            } else {
                report::to_sarif_multiple(&reports)
            }
        } else if reports.len() == 1 {
            report::to_markdown(&reports[0], &explanations[0])
        } else {
            report::to_markdown_multiple(&reports, &explanations, &model)
        };
        std::fs::write(&output, content).map_err(error::Error::Io)?;
        println!("\x1b[0;32m[+] Report written to {}\x1b[0m", output);
    } else if cmd.ci {
        let sarif = if reports.len() == 1 {
            report::to_sarif(&reports[0])
        } else {
            report::to_sarif_multiple(&reports)
        };
        println!("{}", sarif);
    } else if reports.len() == 1 {
        report::print_terminal(&reports[0]);
        println!("\n\x1b[0;32m=== LLM Analysis ({} ) ===\x1b[0m\n{}", model, explanations[0]);
    } else {
        report::print_terminal_multiple(&reports, &explanations, &model);
    }

    let min_score = reports.iter().map(|r| r.score).min().unwrap_or(100);
    if min_score < 50 {
        process::exit(2);
    } else if min_score < 75 {
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

    ui::run_interactive(report, cmd.model)?;
    Ok(())
}
