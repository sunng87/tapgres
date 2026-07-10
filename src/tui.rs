//! Interactive TUI (`--tui`).
//!
//! An orthogonal presentation layer over the existing traffic sources: the
//! pcap capture or the mitm proxy runs in a background thread and feeds decoded
//! lines onto a channel; the TUI drains them on the main thread and renders a
//! scrollable view with [ratatui].
//!
//! First-cut controls:
//! - `q` / `Ctrl-C` — quit
//! - `j`/`k`, arrows, `PgUp`/`PgDn`, `g`/`G` — scroll
//! - `f` — toggle follow (auto-tail)
//! - `w` — toggle line wrap
//! - `c` — clear

use crossbeam_channel::Receiver;
use std::error::Error;
use std::io;
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::capture::PcapOpts;
use crate::decode::{self, Output};
use crate::proxy::ProxyOpts;

/// Cap on retained lines in the TUI's own buffer.
const HISTORY_CAP: usize = 50_000;

/// TUI over the passive pcap capture.
pub fn run_pcap(opts: PcapOpts) -> Result<(), Box<dyn Error>> {
    run(
        Box::new(move || {
            if let Err(e) = crate::capture::run(opts) {
                decode::status(format!("⚠ pcap source error: {e}"));
            }
        }),
        "pcap",
    )
}

/// TUI over the TLS-terminating mitm proxy.
pub fn run_mitm(opts: ProxyOpts) -> Result<(), Box<dyn Error>> {
    run(
        Box::new(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    decode::status(format!("⚠ failed to start mitm runtime: {e}"));
                    return;
                }
            };
            if let Err(e) = rt.block_on(crate::proxy::serve(opts)) {
                decode::status(format!("⚠ mitm source error: {e}"));
            }
        }),
        "mitm",
    )
}

/// Install a shared sink, start `source` in a background thread, run the TUI on
/// this (main) thread, and always restore the terminal before returning.
fn run(
    source: Box<dyn FnOnce() + Send + 'static>,
    mode: &'static str,
) -> Result<(), Box<dyn Error>> {
    // One channel: the source (background thread) produces via decode::out,
    // the TUI (this thread) consumes.
    let (tx, rx) = crossbeam_channel::unbounded();
    decode::set_output(tx);

    // The source runs until the process exits; no graceful shutdown here.
    let _source_thread = std::thread::Builder::new()
        .name("tapgres-source".into())
        .spawn(source)?;

    let mut terminal = ratatui::try_init()?;
    let result = app_loop(&mut terminal, App::new(rx, mode));
    // Restore the terminal even on error. try_init installs a panic hook that
    // also restores, so panics are covered too.
    let _ = ratatui::try_restore();
    result.map_err(Into::into)
}

struct App {
    rx: Receiver<Output>,
    events: Vec<String>,
    /// Index of the top visible line into the event buffer.
    scroll: usize,
    /// Auto-tail new output.
    follow: bool,
    /// Wrap long lines to the viewport width.
    wrap: bool,
    mode: &'static str,
}

impl App {
    fn new(rx: Receiver<Output>, mode: &'static str) -> Self {
        Self {
            rx,
            events: Vec::new(),
            scroll: 0,
            follow: true,
            wrap: false,
            mode,
        }
    }
}

fn app_loop(terminal: &mut ratatui::DefaultTerminal, mut app: App) -> io::Result<()> {
    loop {
        while let Ok(record) = app.rx.try_recv() {
            let line = match record {
                Output::Line(s) | Output::Status(s) => s,
            };
            app.events.push(line);
        }
        if app.events.len() > HISTORY_CAP {
            let drop_n = app.events.len() - HISTORY_CAP;
            app.events.drain(..drop_n);
        }

        // 3 (title) + 3 (footer) + 2 (log block borders) rows of chrome.
        let term_h = terminal.size()?.height as usize;
        let log_h = term_h.saturating_sub(8).max(1);

        // With wrap on, each event may occupy several rows, so allow scrolling
        // all the way to the last event. Otherwise rows are separated by a blank
        // line for readability, so a full viewport shows about half as many
        // events.
        let max_scroll = if app.wrap {
            app.events.len().saturating_sub(1)
        } else {
            app.events.len().saturating_sub(log_h.div_ceil(2))
        };
        if app.follow {
            app.scroll = max_scroll;
        }
        app.scroll = app.scroll.min(max_scroll);

        terminal.draw(|frame| draw(frame, &app, log_h))?;

        if event::poll(Duration::from_millis(100))? {
            // Drain all currently-ready events without blocking on read().
            loop {
                match event::read()? {
                    Event::Key(key)
                        if key.kind == KeyEventKind::Press && handle_key(&mut app, log_h, key) =>
                    {
                        return Ok(());
                    }
                    // Resize / focus / mouse etc. — just trigger a redraw next loop.
                    _ => {}
                }
                if !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }
}

/// Handle one key. Returns `true` to quit.
fn handle_key(app: &mut App, log_h: usize, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('c') if ctrl => return true,
        KeyCode::Char('q') => return true,
        KeyCode::Char('j') | KeyCode::Down => {
            app.follow = false;
            app.scroll = app.scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.follow = false;
            app.scroll = app.scroll.saturating_sub(1);
        }
        KeyCode::PageDown => {
            app.follow = false;
            app.scroll = app.scroll.saturating_add(log_h);
        }
        KeyCode::PageUp => {
            app.follow = false;
            app.scroll = app.scroll.saturating_sub(log_h);
        }
        KeyCode::Char('G') | KeyCode::End => app.follow = true,
        KeyCode::Char('g') | KeyCode::Home => {
            app.follow = false;
            app.scroll = 0;
        }
        KeyCode::Char('f') => app.follow = !app.follow,
        KeyCode::Char('w') => app.wrap = !app.wrap,
        KeyCode::Char('c') => app.events.clear(),
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, app: &App, log_h: usize) {
    let [title_area, log_area, foot_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    // --- title bar ---
    let follow_tag = if app.follow { " · following" } else { "" };
    let wrap_tag = if app.wrap { " · wrap" } else { "" };
    let title = format!(
        " tapgres — {} mode · {} events{}{} ",
        app.mode,
        app.events.len(),
        follow_tag,
        wrap_tag,
    );
    frame.render_widget(Block::bordered().title_top(Line::raw(title)), title_area);

    // --- packet view ---
    let log_block = Block::bordered()
        .title_top(Line::raw(" packets "))
        .border_style(Style::default().fg(Color::Green));
    let start = app.scroll;
    if app.wrap {
        // Wrap mode: dense — a per-row blank separator isn't feasible without
        // per-line height info, so just wrap into the viewport.
        let end = (start + log_h).min(app.events.len());
        let lines: Vec<Line> = app.events[start..end]
            .iter()
            .map(|l| build_line(l.as_str()))
            .collect();
        let para = Paragraph::new(Text::from(lines))
            .block(log_block)
            .wrap(Wrap { trim: false });
        frame.render_widget(para, log_area);
    } else {
        // A blank line between rows for readability; each event then occupies
        // two rows, so show half the viewport's worth of events.
        let win = log_h.div_ceil(2);
        let end = (start + win).min(app.events.len());
        let mut lines: Vec<Line> = Vec::new();
        for (i, line) in app.events[start..end].iter().enumerate() {
            if i > 0 {
                lines.push(Line::raw(""));
            }
            lines.push(build_line(line.as_str()));
        }
        frame.render_widget(Paragraph::new(Text::from(lines)).block(log_block), log_area);
    }

    // --- footer ---
    frame.render_widget(
        Paragraph::new(Text::raw(
            " q quit · j/k ↑↓ · PgUp/PgDn · g/G top/bottom · f follow · w wrap · c clear ",
        ))
        .block(Block::bordered()),
        foot_area,
    );
}

/// Render a line with the direction symbol (`[F→B]`/`[B→F]`) highlighted in a
/// high-contrast colour (F→B cyan, B→F magenta, bold) and the packet name
/// (e.g. `Query`, `DataRow`) bold; all other text stays the default colour for
/// easy reading. Warnings stay red and connection notices yellow.
fn build_line(line: &str) -> Line<'_> {
    if line.contains('⚠') {
        return Line::styled(line, Style::default().fg(Color::Red));
    }
    if line.contains("===") {
        return Line::styled(line, Style::default().fg(Color::Yellow));
    }
    let Some((color, start, end)) = direction_split(line) else {
        return Line::styled(line, Style::default());
    };
    // "[ts] [F→B] KIND: text" -> prefix | symbol | gap | kind | rest.
    // Skip the single space after the symbol closing bracket.
    let kind_start = (end + 1).min(line.len());
    let kind_end = line[kind_start..]
        .find(": ")
        .map(|p| kind_start + p)
        .unwrap_or(line.len());
    Line::from(vec![
        Span::raw(&line[..start]),
        Span::raw(&line[start..end]).fg(color).bold(),
        Span::raw(&line[end..kind_start]),
        Span::raw(&line[kind_start..kind_end]).bold(),
        Span::raw(&line[kind_end..]),
    ])
}

/// If `line` carries a direction tag, return `(colour, byte start, byte end)`
/// of the tag. F→B is cyan, B→F is magenta — high contrast against each other.
fn direction_split(line: &str) -> Option<(Color, usize, usize)> {
    for (tag, color) in [("[F→B]", Color::Cyan), ("[B→F]", Color::Magenta)] {
        if let Some(start) = line.find(tag) {
            return Some((color, start, start + tag.len()));
        }
    }
    None
}
