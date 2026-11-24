//! Local LLM integration via Ollama.
//!
//! Uses the Ollama HTTP API (/api/chat) to turn technical scan results into
//! plain-English risk summaries and concrete, copy-pasteable fixes.

use reqwest;
use serde::Deserialize;
use serde_json::json;

use crate::error::{Error, Result};
use crate::types::{Finding, ScanReport, Severity};

/// Client for communicating with a locally running Ollama instance.
///
/// No persistent state is kept; each call is independent.
pub struct LlmClient;

impl LlmClient {
    /// Returns a new LLM client. Ollama must be running on http://localhost:11434.
    pub fn new() -> Self {
        LlmClient
    }

    /// Sends the scan report to Ollama and returns a markdown explanation with
    /// prioritized risks and ready-to-use configuration snippets.
    pub async fn explain(&self, report: &ScanReport, model: &str) -> Result<String> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Llm(format!("Failed to create HTTP client for Ollama: {}", e)))?;

        let findings_text: Vec<String> = report
            .findings
            .iter()
            .map(|f| {
                format!(
                    "* [{}] {} — {}\n  Recommendation: {}",
                    severity_label(&f.severity),
                    f.title,
                    f.description,
                    f.recommendation.replace('\n', " ")
                )
            })
            .collect();

        let user_prompt = format!(
            "URL: {}\nScore: {}/100\nTechnologies: {}\n\nFindings:\n{}",
            report.url,
            report.score,
            if report.tech.is_empty() {
                "unknown".to_string()
            } else {
                report.tech.join(", ")
            },
            findings_text.join("\n")
        );

        let payload = json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are Web Shield Analyst, a concise DevSecOps expert. Translate technical findings into plain English for developers. Always give exact configuration snippets for the detected stack.\nIf 'Next.js' is listed in technologies, include a next.config.js (or headers() function) example.\nIf 'Django' is listed, include settings.py and/or middleware examples.\nIf 'Ruby on Rails' is listed, include config/application.rb or initializer examples.\nAlways include appropriate Nginx/Apache/CSP snippets as well.\nStructure answers with markdown headings. Be practical, never vague."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            "stream": false,
            "options": {
                "temperature": 0.25,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        });

        let resp = http_client
            .post("http://localhost:11434/api/chat")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                Error::Llm(format!(
                    "Could not connect to Ollama (is it running and is model '{}' pulled?). Error: {}",
                    model, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
            return Err(Error::Llm(format!(
                "Ollama returned HTTP {}: {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct OllamaResponse {
            message: OllamaMessage,
        }

        #[derive(Deserialize)]
        struct OllamaMessage {
            content: String,
        }

        let parsed: OllamaResponse = resp
            .json()
            .await
            .map_err(|e| Error::Llm(format!("Failed to deserialize Ollama JSON: {}", e)))?;

        let mut text = parsed.message.content.trim().to_string();
        if text.is_empty() {
            text = "(Ollama returned empty response. Try a different model or check Ollama logs.)".to_string();
        }

        Ok(text)
    }

    /// Synchronous version used by the interactive TUI (blocking HTTP).
    pub fn explain_sync(&self, report: &ScanReport, model: &str) -> Result<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Llm(format!("Failed to create blocking client: {}", e)))?;

        let findings_text: Vec<String> = report
            .findings
            .iter()
            .map(|f| {
                format!(
                    "* [{}] {} — {}\n  Recommendation: {}",
                    severity_label(&f.severity),
                    f.title,
                    f.description,
                    f.recommendation.replace('\n', " ")
                )
            })
            .collect();

        let user_prompt = format!(
            "URL: {}\nScore: {}/100\nTechnologies: {}\n\nFindings:\n{}",
            report.url,
            report.score,
            if report.tech.is_empty() {
                "unknown".to_string()
            } else {
                report.tech.join(", ")
            },
            findings_text.join("\n")
        );

        let payload = json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are Web Shield Analyst, a concise DevSecOps expert. Translate technical findings into plain English for developers. Always give exact configuration snippets for the detected stack.\nIf 'Next.js' is listed in technologies, include a next.config.js (or headers() function) example.\nIf 'Django' is listed, include settings.py and/or middleware examples.\nIf 'Ruby on Rails' is listed, include config/application.rb or initializer examples.\nAlways include appropriate Nginx/Apache/CSP snippets as well.\nStructure answers with markdown headings. Be practical, never vague."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            "stream": false,
            "options": {
                "temperature": 0.25,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        });

        let resp = client
            .post("http://localhost:11434/api/chat")
            .json(&payload)
            .send()
            .map_err(|e| {
                Error::Llm(format!(
                    "Could not connect to Ollama (is it running and is model '{}' pulled?). Error: {}",
                    model, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Error::Llm(format!(
                "Ollama returned HTTP {}: {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct OllamaResponse {
            message: OllamaMessage,
        }

        #[derive(Deserialize)]
        struct OllamaMessage {
            content: String,
        }

        let parsed: OllamaResponse = resp
            .json()
            .map_err(|e| Error::Llm(format!("Failed to deserialize Ollama JSON: {}", e)))?;

        let mut text = parsed.message.content.trim().to_string();
        if text.is_empty() {
            text = "(Ollama returned empty response. Try a different model or check Ollama logs.)".to_string();
        }

        Ok(text)
    }

    /// Interactive follow-up chat about a specific finding. Maintains conversation
    /// context across multiple questions.
    pub fn chat_about(
        &self,
        report: &ScanReport,
        finding: &Finding,
        previous_context: Option<&str>,
        question: &str,
        model: &str,
    ) -> Result<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Llm(format!("Failed to create blocking client: {}", e)))?;

        let finding_text = format!(
            "[{}] {} — {}\nRecommendation: {}",
            severity_label(&finding.severity),
            finding.title,
            finding.description,
            finding.recommendation.replace('\n', " ")
        );

        let context = previous_context.unwrap_or("No previous conversation.");

        let user_prompt = format!(
            "URL: {}\nTechnologies: {}\nRisk Score: {}/100\n\nSelected Finding:\n{}\n\nPrevious conversation:\n{}\n\nUser question: {}",
            report.url,
            if report.tech.is_empty() { "unknown" } else { &report.tech.join(", ") },
            report.score,
            finding_text,
            context,
            question
        );

        let payload = json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful Web Shield security assistant. Answer follow-up questions about a specific finding. Provide concrete, actionable advice tailored to the detected technologies. Use markdown, code blocks for config examples, and stay concise."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            "stream": false,
            "options": {
                "temperature": 0.3,
                "top_p": 0.85,
                "num_ctx": 8192
            }
        });

        let resp = client
            .post("http://localhost:11434/api/chat")
            .json(&payload)
            .send()
            .map_err(|e| {
                Error::Llm(format!(
                    "Could not connect to Ollama (is it running and is model '{}' pulled?). Error: {}",
                    model, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Error::Llm(format!(
                "Ollama returned HTTP {}: {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct OllamaResponse {
            message: OllamaMessage,
        }

        #[derive(Deserialize)]
        struct OllamaMessage {
            content: String,
        }

        let parsed: OllamaResponse = resp
            .json()
            .map_err(|e| Error::Llm(format!("Failed to deserialize Ollama JSON: {}", e)))?;

        let mut text = parsed.message.content.trim().to_string();
        if text.is_empty() {
            text = "(Ollama returned empty response. Try a different model or check Ollama logs.)".to_string();
        }

        Ok(text)
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}
