# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-18

### Added

- Passive Scanner — Fetches headers, cookies, CSP and CORS in one request with no malicious payloads
- Tech Fingerprint — Identifies servers, frameworks, JS libs and surfaces known CVEs
- Local LLM Analyst — Queries Ollama to generate contextual explanations and remediation code
- Terminal UI — Ratatui-powered interactive explorer with severity filters and drill-down
- Smart Reports — Markdown summaries with ready-to-use header snippets for Nginx/Apache
- Custom Rules — Load organization rules from YAML; extend via Rust traits
- CI Ready — Non-interactive mode, JSON/SARIF output and proper exit codes
- Blazing Fast — Rust + async keeps scans under 400 ms even with LLM summary
