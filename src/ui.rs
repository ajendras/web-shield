//! Ratatui-powered interactive terminal explorer.
//!
//! Provides a tabbed, keyboard-driven interface with retro-CRT aesthetics:
//! phosphor-green text (#39ff14) on near-black (#0c0c0c), ASCII box-drawing
//! borders, bold headings, severity-coloured findings, and Vim-style key bindings.
//! Blinking cursor is emulated via the terminal; scanline effect is left to
//! the user's terminal emulator.

use std::io;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};

use crate::error::Result;
use crate::llm::LlmClient;
use crate::types::{ChatMessage, ScanReport, Severity};

const PHOSPHOR_GREEN: Color = Color::Rgb(0x39, 0xff, 0x14);
const AMBER: Color = Color::Rgb(0xff, 0xb0, 0x00);
const DARK_BG: Color = Color::Rgb(0x0c, 0x0c, 0x0c);
const DIM: Color = Color::Rgb(0x44, 0x44, 0x44);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Summary,
    Findings,
    Headers,
    Tech,
    Chat,
}

struct App {
    report: ScanReport,
    active_tab: ActiveTab,
    findings_state: ListState,
    chat_history: Vec<ChatMessage>,
    input: String,
    model: String,
    show_help: bool,
    selected_finding_idx: Option<usize>,
    should_quit: bool,
}

impl App {
    fn new(report: ScanReport, model: String) -> Self {
        let mut findings_state = ListState::default();
        if !report.findings.is_empty() {
            findings_state.select(Some(0));
        }
        Self {
            report,
            active_tab: ActiveTab::Summary,
            findings_state,
            chat_history: vec![],
            input: String::new(),
            model,
            show_help: false,
            selected_finding_idx: None,
            should_quit: false,
        }
    }

    fn next_finding(&mut self) {
        let len = self.report.findings.len();
        if len == 0 {
            return;
        }
        let i = match self.findings_state.selected() {
            Some(i) => (i + 1) % len,
            None => 0,
        };
        self.findings_state.select(Some(i));
        self.selected_finding_idx = Some(i);
    }

    fn previous_finding(&mut self) {
        let len = self.report.findings.len();
        if len == 0 {
            return;
        }
        let i = match self.findings_state.selected() {
            Some(i) => {
                if i == 0 {
                    len - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.findings_state.select(Some(i));
        self.selected_finding_idx = Some(i);
    }

    fn switch_tab(&mut self, tab: ActiveTab) {
        self.active_tab = tab;
        if tab == ActiveTab::Findings && self.selected_finding_idx.is_none() && !self.report.findings.is_empty() {
            self.selected_finding_idx = Some(0);
            self.findings_state.select(Some(0));
        }
    }

    fn open_chat_for_selected(&mut self) {
        if let Some(idx) = self.selected_finding_idx {
            if idx < self.report.findings.len() {
                self.active_tab = ActiveTab::Chat;
                self.chat_history.clear();
                let finding = &self.report.findings[idx];
                self.chat_history.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: format!("Ask me anything about this finding:\n\n[{}] {}\n\n{}", 
                        match finding.severity {
                            Severity::Critical | Severity::High => "HIGH",
                            Severity::Medium => "MEDIUM",
                            _ => "LOW",
                        },
                        finding.title,
                        finding.description
                    ),
                });
            }
        }
    }

    fn send_message(&mut self) {
        if self.input.trim().is_empty() || self.selected_finding_idx.is_none() {
            return;
        }

        let question = self.input.trim().to_string();
        self.chat_history.push(ChatMessage {
            role: "user".to_string(),
            content: question.clone(),
        });

        let idx = self.selected_finding_idx.unwrap();
        let finding = &self.report.findings[idx];

        let context = self.chat_history
            .iter()
            .map(|m| format!("{}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");

        let llm = LlmClient::new();
        match llm.chat_about(
            &self.report,
            finding,
            Some(&context),
            &question,
            &self.model,
        ) {
            Ok(response) => {
                self.chat_history.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: response,
                });
            }
            Err(e) => {
                self.chat_history.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: format!("Error communicating with Ollama: {}", e),
                });
            }
        }

        self.input.clear();
    }

    fn on_key(&mut self, code: KeyCode) {
        if self.show_help {
            if code == KeyCode::Char('?') || code == KeyCode::Esc {
                self.show_help = false;
            }
            return;
        }

        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Tab => self.cycle_tab_forward(),
            KeyCode::Char('h') => self.cycle_tab_backward(),
            KeyCode::Char('l') => self.cycle_tab_forward(),
            KeyCode::Char('j') | KeyCode::Down => {
                if self.active_tab == ActiveTab::Findings {
                    self.next_finding();
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.active_tab == ActiveTab::Findings {
                    self.previous_finding();
                }
            }
            KeyCode::Char('c') => {
                if self.active_tab == ActiveTab::Findings {
                    self.open_chat_for_selected();
                }
            }
            KeyCode::Enter => {
                if self.active_tab == ActiveTab::Chat {
                    self.send_message();
                }
            }
            KeyCode::Char(c) => {
                if self.active_tab == ActiveTab::Chat {
                    self.input.push(c);
                }
            }
            KeyCode::Backspace => {
                if self.active_tab == ActiveTab::Chat && !self.input.is_empty() {
                    self.input.pop();
                }
            }
            _ => {}
        }
    }

    fn cycle_tab_forward(&mut self) {
        self.active_tab = match self.active_tab {
            ActiveTab::Summary => ActiveTab::Findings,
            ActiveTab::Findings => ActiveTab::Headers,
            ActiveTab::Headers => ActiveTab::Tech,
            ActiveTab::Tech => ActiveTab::Chat,
            ActiveTab::Chat => ActiveTab::Summary,
        };
    }

    fn cycle_tab_backward(&mut self) {
        self.active_tab = match self.active_tab {
            ActiveTab::Summary => ActiveTab::Chat,
            ActiveTab::Findings => ActiveTab::Summary,
            ActiveTab::Headers => ActiveTab::Findings,
            ActiveTab::Tech => ActiveTab::Headers,
            ActiveTab::Chat => ActiveTab::Tech,
        };
    }
}

pub fn run_interactive(report: ScanReport, model: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(report, model);

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.on_key(key.code);
                if app.should_quit {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    let area = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Min(10),   // content
            Constraint::Length(3), // footer / input
        ])
        .split(area);

    let tabs = vec![" SUMMARY ", " FINDINGS ", " HEADERS ", " TECH ", " CHAT "];
    let tab_titles: Vec<Line> = tabs
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(PHOSPHOR_GREEN))))
        .collect();

    let selected = match app.active_tab {
        ActiveTab::Summary => 0,
        ActiveTab::Findings => 1,
        ActiveTab::Headers => 2,
        ActiveTab::Tech => 3,
        ActiveTab::Chat => 4,
    };

    let tabs_widget = Tabs::new(tab_titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title("Web Shield Explorer"))
        .style(Style::default().fg(DIM))
        .highlight_style(Style::default().fg(PHOSPHOR_GREEN).add_modifier(Modifier::BOLD));

    f.render_widget(tabs_widget, chunks[0]);

    match app.active_tab {
        ActiveTab::Summary => render_summary(f, app, chunks[1]),
        ActiveTab::Findings => render_findings(f, app, chunks[1]),
        ActiveTab::Headers => render_headers(f, app, chunks[1]),
        ActiveTab::Tech => render_tech(f, app, chunks[1]),
        ActiveTab::Chat => render_chat(f, app, chunks[1]),
    }

    let footer = if app.show_help {
        Paragraph::new("j/k: navigate • c: chat about finding • Enter: send • Tab/h/l: tabs • q: quit • ?: close help")
            .block(Block::default().borders(Borders::ALL).title("Help").style(Style::default().fg(AMBER)))
    } else if app.active_tab == ActiveTab::Chat {
        let input = format!("Ask follow-up > {}", app.input);
        Paragraph::new(input)
            .block(Block::default().borders(Borders::ALL).title("Chat with LLM").style(Style::default().fg(PHOSPHOR_GREEN)))
            .style(Style::default().fg(PHOSPHOR_GREEN))
    } else {
        Paragraph::new("Press ? for help • c on a finding to start chatting")
            .block(Block::default().borders(Borders::ALL).title("Controls"))
            .style(Style::default().fg(DIM))
    };
    f.render_widget(footer, chunks[2]);
}

fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let score_color = if app.report.score >= 75 {
        PHOSPHOR_GREEN
    } else if app.report.score >= 50 {
        AMBER
    } else {
        Color::Red
    };

    let text = vec![
        Line::from(Span::styled(format!("URL: {}", app.report.url), Style::default().fg(PHOSPHOR_GREEN))),
        Line::from(Span::styled(
            format!("Risk Score: {}/100", app.report.score),
            Style::default().fg(score_color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Technologies: {}", if app.report.tech.is_empty() { "none detected" } else { &app.report.tech.join(", ") }),
            Style::default().fg(PHOSPHOR_GREEN),
        )),
        Line::from(""),
        Line::from(Span::styled(
            if app.report.findings.is_empty() {
                "No security issues found — site looks solid!".to_string()
            } else {
                format!("{} findings detected. Switch to FINDINGS tab or press 'c' on a finding to chat with the LLM.", app.report.findings.len())
            },
            Style::default().fg(if app.report.findings.is_empty() { PHOSPHOR_GREEN } else { AMBER }),
        )),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Scan Summary"))
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn render_findings(f: &mut Frame, app: &App, area: Rect) {
    if app.report.findings.is_empty() {
        let p = Paragraph::new("No findings.").block(Block::default().borders(Borders::ALL).title("Findings"));
        f.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = app.report.findings.iter().enumerate().map(|(i, fnd)| {
        let severity_style = match fnd.severity {
            Severity::Critical | Severity::High => Style::default().fg(Color::Red),
            Severity::Medium => Style::default().fg(AMBER),
            _ => Style::default().fg(PHOSPHOR_GREEN),
        };
        let label = format!("[{}] {}", severity_label(&fnd.severity), fnd.title);
        ListItem::new(vec![
            Line::from(Span::styled(label, severity_style)),
            Line::from(Span::styled(format!("   ID: {}", fnd.id), Style::default().fg(DIM))),
        ])
    }).collect();

    let findings_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Findings (j/k to move, c to chat)"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED).fg(PHOSPHOR_GREEN))
        .highlight_symbol(">> ");

    f.render_stateful_widget(findings_list, area, &mut app.findings_state.clone());
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn render_headers(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![];
    for (k, v) in &app.report.raw_headers {
        lines.push(Line::from(format!("{}: {}", k, v)));
    }
    if lines.is_empty() {
        lines.push(Line::from("No headers captured."));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Raw Response Headers"))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn render_tech(f: &mut Frame, app: &App, area: Rect) {
    let tech_list = if app.report.tech.is_empty() {
        vec![Line::from("No technologies fingerprinted.")]
    } else {
        app.report.tech.iter().map(|t| Line::from(format!("• {}", t))).collect()
    };

    let p = Paragraph::new(tech_list)
        .block(Block::default().borders(Borders::ALL).title("Technology Fingerprint"))
        .style(Style::default().fg(PHOSPHOR_GREEN));
    f.render_widget(p, area);
}

fn render_chat(f: &mut Frame, app: &App, area: Rect) {
    if app.chat_history.is_empty() {
        let help = Paragraph::new("Select a finding in the Findings tab and press 'c' to start a conversation with the local LLM.\n\nYou can ask follow-up questions about risks, fixes, or how the issue affects your stack.")
            .block(Block::default().borders(Borders::ALL).title("LLM Chat"))
            .style(Style::default().fg(DIM));
        f.render_widget(help, area);
        return;
    }

    let mut chat_lines = vec![];
    for msg in &app.chat_history {
        let role_style = if msg.role == "user" {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(PHOSPHOR_GREEN)
        };
        let prefix = if msg.role == "user" { "You: " } else { "Analyst: " };
        chat_lines.push(Line::from(Span::styled(prefix, role_style)));
        for line in msg.content.lines() {
            chat_lines.push(Line::from(line.to_string()));
        }
        chat_lines.push(Line::from(""));
    }

    let p = Paragraph::new(chat_lines)
        .block(Block::default().borders(Borders::ALL).title("Conversation with LLM"))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}
