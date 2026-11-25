//! Interactive Ratatui-powered terminal UI for exploring scan results.
//!
//! Provides keyboard-driven navigation, tabbed interface (Summary / Findings / Chat),
//! severity-colored output matching the retro phosphor-green CRT aesthetic, and
//! live LLM chat about any selected finding using the same LlmClient used elsewhere.

use std::io;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};

use crate::error::Result;
use crate::llm::LlmClient;
use crate::types::{Finding, ScanReport, Severity};

#[derive(Default)]
struct App {
    report: ScanReport,
    model: String,
    current_tab: usize,
    selected_finding: usize,
    chat_history: Vec<String>,
    input_buffer: String,
    show_help: bool,
}

pub fn run_interactive(report: ScanReport, model: String) -> Result<()> {
    let mut app = App {
        report,
        model,
        chat_history: vec!["Web Shield LLM Chat ready. Select a finding in the Findings tab and press 'c' to begin.".to_string()],
        ..Default::default()
    };

    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    KeyCode::Tab | KeyCode::Char('l') | KeyCode::Right => {
                        app.current_tab = (app.current_tab + 1) % 3;
                    }
                    KeyCode::Char('h') | KeyCode::Left => {
                        app.current_tab = if app.current_tab == 0 { 2 } else { app.current_tab - 1 };
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        if app.current_tab == 1 && !app.report.findings.is_empty() {
                            app.selected_finding =
                                (app.selected_finding + 1) % app.report.findings.len();
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if app.current_tab == 1 && !app.report.findings.is_empty() {
                            app.selected_finding = if app.selected_finding == 0 {
                                app.report.findings.len() - 1
                            } else {
                                app.selected_finding.saturating_sub(1)
                            };
                        }
                    }
                    KeyCode::Char('c') => {
                        if app.current_tab == 1 && !app.report.findings.is_empty() {
                            app.current_tab = 2;
                            let finding = &app.report.findings[app.selected_finding];
                            app.chat_history.push(format!(
                                "→ Asking about: [{}] {}",
                                severity_label(&finding.severity),
                                finding.title
                            ));
                        }
                    }
                    KeyCode::Enter => {
                        if app.current_tab == 2 && !app.input_buffer.trim().is_empty() {
                            let question = app.input_buffer.clone();
                            app.chat_history.push(format!("You: {}", question));

                            let llm = LlmClient::new();
                            if let Some(finding) = app.report.findings.get(app.selected_finding) {
                                match llm.chat_about(
                                    &app.report,
                                    finding,
                                    None,
                                    &question,
                                    &app.model,
                                ) {
                                    Ok(resp) => app.chat_history.push(format!("Assistant: {}", resp)),
                                    Err(e) => app.chat_history.push(format!("Error: {}", e)),
                                }
                            }
                            app.input_buffer.clear();
                        }
                    }
                    KeyCode::Char(c) => {
                        if app.current_tab == 2 {
                            app.input_buffer.push(c);
                        }
                    }
                    KeyCode::Backspace => {
                        if app.current_tab == 2 && !app.input_buffer.is_empty() {
                            app.input_buffer.pop();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut Frame, app: &mut App) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // tabs
            Constraint::Min(10),    // main content
            Constraint::Length(1),  // footer
        ])
        .split(size);

    let tab_titles = vec![" Summary ", " Findings ", " Chat "];
    let tabs = Tabs::new(tab_titles)
        .select(app.current_tab)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Web Shield Explorer")
                .border_style(Style::default().fg(Color::Green)),
        )
        .style(Style::default().fg(Color::Green))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    f.render_widget(tabs, chunks[0]);

    match app.current_tab {
        0 => draw_summary_tab(f, app, chunks[1]),
        1 => draw_findings_tab(f, app, chunks[1]),
        2 => draw_chat_tab(f, app, chunks[1]),
        _ => {}
    }

    let footer = Paragraph::new(
        " q:quit  ?:help  Tab/h/l: tabs  j/k: navigate  c:chat about finding ",
    )
    .style(Style::default().fg(Color::Green));
    f.render_widget(footer, chunks[2]);

    if app.show_help {
        let help_area = centered_rect(60, 70, size);
        let help = Paragraph::new(
            "Interactive Controls:\n\n\
             • Tab / h / l / arrows : cycle tabs (Summary, Findings, Chat)\n\
             • j / k or arrows      : navigate findings list\n\
             • c                    : open chat about selected finding\n\
             • type + Enter         : send question to local LLM\n\
             • ?                    : toggle this help overlay\n\
             • q or Esc             : quit\n\n\
             All LLM calls stay on your machine via Ollama.\n\
             Press any key to close help."
        )
        .block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .style(Style::default().fg(Color::White));
        f.render_widget(help, help_area);
    }
}

fn draw_summary_tab(f: &mut Frame, app: &App, area: Rect) {
    let score_color = match app.report.score {
        s if s >= 75 => Color::Green,
        s if s >= 50 => Color::Yellow,
        _ => Color::Red,
    };

    let tech = if app.report.tech.is_empty() {
        "none detected".to_string()
    } else {
        app.report.tech.join(", ")
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("URL: ", Style::default().fg(Color::Green)),
            Span::raw(&app.report.url),
        ]),
        Line::from(vec![
            Span::styled("Risk Score: ", Style::default().fg(Color::Green)),
            Span::styled(
                format!("{}/100", app.report.score),
                Style::default().fg(score_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("Technologies: ", Style::default().fg(Color::Green)),
            Span::raw(tech),
        ]),
        Line::from(vec![
            Span::styled("Findings: ", Style::default().fg(Color::Green)),
            Span::raw(app.report.findings.len().to_string()),
        ]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Scan Summary")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(paragraph, area);
}

fn draw_findings_tab(f: &mut Frame, app: &App, area: Rect) {
    if app.report.findings.is_empty() {
        let p = Paragraph::new("No findings detected.\n\nSite appears secure from a passive scan.")
            .block(
                Block::default()
                    .title("Findings")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)),
            );
        f.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = app
        .report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_style = match f.severity {
                Severity::Critical | Severity::High => Style::default().fg(Color::Red),
                Severity::Medium => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::Green),
            };
            let selected = i == app.selected_finding;
            let prefix = if selected { "▶ " } else { "  " };

            let mut content = vec![Line::from(vec![Span::styled(
                format!("{}{} [{}] {}", prefix, severity_label(&f.severity), f.title, if selected { " (press c to chat)" } else { "" }),
                if selected {
                    sev_style.add_modifier(Modifier::BOLD | Modifier::REVERSED)
                } else {
                    sev_style
                },
            )])];

            content.push(Line::from(Span::raw(format!("    ID: {}", f.id))));
            content.push(Line::from(Span::raw(format!("    {}", f.description))));

            ListItem::new(content)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Findings ({} total) — use j/k to navigate",
                    app.report.findings.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(list, area);
}

fn draw_chat_tab(f: &mut Frame, app: &App, area: Rect) {
    let chat_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(3)])
        .split(area);

    let history: Vec<Line> = app
        .chat_history
        .iter()
        .map(|msg| Line::from(Span::raw(msg.clone())))
        .collect();

    let chat = Paragraph::new(history)
        .block(
            Block::default()
                .title("LLM Chat (local Ollama)")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::White));

    let input = Paragraph::new(app.input_buffer.as_str())
        .block(
            Block::default()
                .title("Type question and press Enter")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );

    f.render_widget(chat, chat_area[0]);
    f.render_widget(input, chat_area[1]);
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

/// Helper to create a centered rectangle for overlays (e.g. help).
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
