use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Tabs};
use ratatui::{Frame, Terminal};

use crate::error::Result;
use crate::llm::LlmClient;
use crate::types::{Finding, ScanReport, Severity};

#[derive(Debug)]
pub struct App {
    pub report: ScanReport,
    pub model: String,
    current_tab: usize,
    selected_finding: usize,
    show_chat: bool,
    chat_input: String,
    chat_history: Vec<String>,
}

impl App {
    pub fn new(report: ScanReport, model: String) -> Self {
        Self {
            report,
            model,
            current_tab: 0,
            selected_finding: 0,
            show_chat: false,
            chat_input: String::new(),
            chat_history: vec![],
        }
    }

    fn next_tab(&mut self) {
        self.current_tab = (self.current_tab + 1) % 3;
    }

    fn select_next(&mut self) {
        if !self.report.findings.is_empty() {
            self.selected_finding = (self.selected_finding + 1) % self.report.findings.len();
        }
    }

    fn select_previous(&mut self) {
        if !self.report.findings.is_empty() {
            self.selected_finding = (self.selected_finding + self.report.findings.len() - 1) % self.report.findings.len();
        }
    }
}

pub fn run_interactive(report: ScanReport, model: String) -> Result<()> {
    enable_raw_mode().map_err(crate::error::Error::Io)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(crate::error::Error::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(crate::error::Error::Io)?;

    let mut app = App::new(report, model);

    loop {
        terminal
            .draw(|f| draw(f, &app))
            .map_err(crate::error::Error::Io)?;

        if let Event::Key(key) = event::read().map_err(crate::error::Error::Io)? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab | KeyCode::Char('l') => app.next_tab(),
                    KeyCode::Char('h') => app.current_tab = if app.current_tab == 0 { 2 } else { app.current_tab - 1 },
                    KeyCode::Char('j') | KeyCode::Down => app.select_next(),
                    KeyCode::Char('k') | KeyCode::Up => app.select_previous(),
                    KeyCode::Char('c') if app.current_tab == 1 => app.show_chat = !app.show_chat,
                    KeyCode::Enter if app.show_chat => handle_chat_input(&mut app),
                    KeyCode::Char(c) if app.show_chat => app.chat_input.push(c),
                    KeyCode::Backspace if app.show_chat => {
                        let _ = app.chat_input.pop();
                    }
                    KeyCode::Char('?') => {
                        // help is always available as tab 2
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode().map_err(crate::error::Error::Io)?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(crate::error::Error::Io)?;

    Ok(())
}

fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(if app.show_chat { 12 } else { 0 }),
        ])
        .split(f.size());

    let tab_titles = vec![" Overview ", " Findings ", " Help "];
    let tabs = Tabs::new(tab_titles)
        .select(app.current_tab)
        .block(Block::default().borders(Borders::ALL).title("Web Shield Explorer"))
        .style(Style::default().fg(Color::Green))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    f.render_widget(tabs, chunks[0]);

    match app.current_tab {
        0 => draw_overview(f, app, chunks[1]),
        1 => draw_findings(f, app, chunks[1]),
        2 => draw_help(f, chunks[1]),
        _ => {}
    }

    if app.show_chat {
        draw_chat(f, app, chunks[2]);
    }
}

fn draw_overview(f: &mut Frame, app: &App, area: Rect) {
    let technologies = format!(
        "Technologies: {}", 
        if app.report.tech.is_empty() { "none detected".to_string() } else { app.report.tech.join(", ") }
    );
    let text = vec![
        Line::from(vec![
            Span::styled("URL: ", Style::default().fg(Color::Green)),
            Span::raw(&app.report.url),
        ]),
        Line::from(vec![
            Span::styled("Risk Score: ", Style::default().fg(Color::Green)),
            Span::raw(format!("{}/100", app.report.score)),
        ]),
        Line::from(technologies),
        Line::from(vec![
            Span::styled("Findings: ", Style::default().fg(Color::Green)),
            Span::raw(app.report.findings.len().to_string()),
        ]),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Scan Overview").style(Style::default().fg(Color::Green)));
    f.render_widget(paragraph, area);
}

fn draw_findings(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.report.findings.iter().enumerate().map(|(_i, fnd)| {
        let color = match fnd.severity {
            Severity::Critical | Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            _ => Color::Green,
        };
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] {}", severity_label(&fnd.severity), fnd.title),
                Style::default().fg(color),
            ),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Findings (j/k navigate, c to chat)").style(Style::default().fg(Color::Green)))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let help_text = "Keyboard Controls:\n\n  Tab/h/l : Switch tabs\n  j/k or arrows : Navigate findings\n  c : Toggle LLM chat for selected finding\n  Enter : Send message when in chat mode\n  q/Esc : Quit\n\nPhosphor-green retro CRT aesthetics. All analysis runs locally with Ollama.";
    let paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Help").style(Style::default().fg(Color::Green)));
    f.render_widget(paragraph, area);
}

fn draw_chat(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = app.chat_history.iter().map(|s| Line::from(s.as_str())).collect();
    lines.push(Line::from(format!("> {}", app.chat_input)));

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(format!("LLM Chat (model: {})", app.model)).style(Style::default().fg(Color::Green)));
    f.render_widget(paragraph, area);
}

fn handle_chat_input(app: &mut App) {
    let question = app.chat_input.trim().to_string();
    if question.is_empty() {
        return;
    }
    let llm = LlmClient::new();
    if let Some(fnd) = app.report.findings.get(app.selected_finding) {
        match llm.chat_about(&app.report, fnd, None, &question, &app.model) {
            Ok(resp) => {
                app.chat_history.push(format!("Q: {}", question));
                app.chat_history.push(format!("A: {}", resp));
            }
            Err(e) => app.chat_history.push(format!("Error: {}", e)),
        }
    }
    app.chat_input.clear();
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
