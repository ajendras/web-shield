//! Ratatui-powered interactive terminal explorer.
//!
//! Provides a tabbed, keyboard-driven interface with retro-CRT aesthetics:
//! phosphor-green text (#39ff14) on near-black (#0c0c0c), ASCII box-drawing
//! borders, bold headings, severity-coloured findings, and Vim-like key bindings.
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
use crate::types::{ScanReport, Severity};

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
}

impl ActiveTab {
    fn as_index(&self) -> usize {
        match self {
            ActiveTab::Summary => 0,
            ActiveTab::Findings => 1,
            ActiveTab::Headers => 2,
            ActiveTab::Tech => 3,
        }
    }

    fn from_index(i: usize) -> Self {
        match i % 4 {
            0 => ActiveTab::Summary,
            1 => ActiveTab::Findings,
            2 => ActiveTab::Headers,
            _ => ActiveTab::Tech,
        }
    }
}

struct App {
    report: ScanReport,
    tab: ActiveTab,
    findings_state: ListState,
    show_help: bool,
}

impl App {
    fn new(report: ScanReport) -> Self {
        let mut findings_state = ListState::default();
        if !report.findings.is_empty() {
            findings_state.select(Some(0));
        }

        Self {
            report,
            tab: ActiveTab::Summary,
            findings_state,
            show_help: false,
        }
    }

    fn next_tab(&mut self) {
        let i = self.tab.as_index();
        self.tab = ActiveTab::from_index(i + 1);
    }

    fn prev_tab(&mut self) {
        let i = self.tab.as_index();
        self.tab = ActiveTab::from_index(i + 3); // +3 ≡ -1 mod 4
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
    }

    fn prev_finding(&mut self) {
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
    }
}

/// Runs the interactive retro terminal UI.
///
/// Sets up an alternate screen, raw mode, and an event loop that respects
/// the project's phosphor-green/ASCII-box aesthetic. Returns control to the
/// terminal on `q` or Esc. All errors are propagated through the crate's
/// `Result` type.
pub fn run_interactive(report: ScanReport) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(report);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => app.next_tab(),
                KeyCode::Left | KeyCode::Char('h') => app.prev_tab(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if matches!(app.tab, ActiveTab::Findings) {
                        app.next_finding();
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if matches!(app.tab, ActiveTab::Findings) {
                        app.prev_finding();
                    }
                }
                KeyCode::Char('?') => app.show_help = !app.show_help,
                _ => {}
            }
        }
    }

    // Clean shutdown
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // tabs + title
            Constraint::Min(12),    // content
            Constraint::Length(3),  // status bar
        ])
        .split(area);

    draw_tabs(f, app, chunks[0]);
    match app.tab {
        ActiveTab::Summary => draw_summary(f, app, chunks[1]),
        ActiveTab::Findings => draw_findings(f, app, chunks[1]),
        ActiveTab::Headers => draw_headers(f, app, chunks[1]),
        ActiveTab::Tech => draw_tech(f, app, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles = vec![" SUMMARY ", " FINDINGS ", " HEADERS ", " TECH "];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR_GREEN))
                .title(Span::styled(
                    " WEB SHIELD INTERACTIVE v0.1.0 ",
                    Style::default()
                        .fg(PHOSPHOR_GREEN)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(
            Style::default()
                .fg(AMBER)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        )
        .select(app.tab.as_index());

    f.render_widget(tabs, area);
}

fn draw_summary(f: &mut Frame, app: &App, area: Rect) {
    let score_style = match app.report.score {
        85..=100 => Style::default().fg(PHOSPHOR_GREEN).add_modifier(Modifier::BOLD),
        60..=84 => Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    };

    let tech = if app.report.tech.is_empty() {
        "none detected".to_string()
    } else {
        app.report.tech.join(", ")
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("URL  ", Style::default().fg(PHOSPHOR_GREEN)),
            Span::raw(&app.report.url),
        ]),
        Line::from(vec![
            Span::styled("SCORE", Style::default().fg(PHOSPHOR_GREEN)),
            Span::raw("  "),
            Span::styled(
                format!("{:>3}/100", app.report.score),
                score_style,
            ),
        ]),
        Line::from(vec![
            Span::styled("TECH ", Style::default().fg(PHOSPHOR_GREEN)),
            Span::raw(tech),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "PASSIVE SCAN — NO MALICIOUS PAYLOADS SENT",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "Findings are derived from headers, cookies, CSP and Server banners.",
            Style::default().fg(DIM),
        )),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR_GREEN))
                .title("SCAN SUMMARY"),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_findings(f: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PHOSPHOR_GREEN))
        .title(format!("FINDINGS ({})", app.report.findings.len()));

    if app.report.findings.is_empty() {
        let para = Paragraph::new("No security findings detected.\n\nSite appears secure from a passive scan.")
            .block(block)
            .style(Style::default().fg(PHOSPHOR_GREEN));
        f.render_widget(para, area);
        return;
    }

    let items: Vec<ListItem> = app
        .report
        .findings
        .iter()
        .map(|finding| {
            let sev_style = severity_style(&finding.severity);
            let label = format!(
                "[{:>7}] {}",
                severity_label(&finding.severity),
                finding.title
            );
            ListItem::new(vec![
                Line::from(Span::styled(label, sev_style)),
                Line::from(Span::styled(
                    format!("    {}", finding.id),
                    Style::default().fg(DIM),
                )),
            ])
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(0x11, 0x33, 0x11))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.findings_state);
}

fn draw_headers(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        "RAW HTTP RESPONSE HEADERS",
        Style::default()
            .fg(PHOSPHOR_GREEN)
            .add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::from(""));

    for (name, value) in &app.report.raw_headers {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<28}", name),
                Style::default().fg(PHOSPHOR_GREEN),
            ),
            Span::raw(" : "),
            Span::raw(value),
        ]));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR_GREEN))
                .title("HEADERS"),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_tech(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        "TECHNOLOGY FINGERPRINT",
        Style::default()
            .fg(PHOSPHOR_GREEN)
            .add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::from(""));

    if app.report.tech.is_empty() {
        lines.push(Line::from(Span::styled(
            "No server or framework signatures detected.",
            Style::default().fg(DIM),
        )));
    } else {
        for tech in &app.report.tech {
            lines.push(Line::from(Span::styled(
                format!("  • {}", tech),
                Style::default().fg(AMBER),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Known CVEs for detected technologies would be listed here.",
        Style::default().fg(DIM),
    )));

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR_GREEN))
                .title("TECH"),
        );

    f.render_widget(paragraph, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let help = if app.show_help {
        " q/Esc:quit  ←→/hl: tabs  ↑↓/jk: findings  ?: hide help "
    } else {
        " ? for help • RETRO TERMINAL • local-only • no data leaves machine "
    };

    let footer = Paragraph::new(help)
        .style(
            Style::default()
                .fg(PHOSPHOR_GREEN)
                .bg(DARK_BG),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR_GREEN)),
        )
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(footer, area);
}

fn severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Critical | Severity::High => {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        }
        Severity::Medium => Style::default().fg(AMBER),
        _ => Style::default().fg(PHOSPHOR_GREEN),
    }
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}
