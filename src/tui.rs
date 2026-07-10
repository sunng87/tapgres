//! Interactive TUI (`--tui`).
//!
//! An orthogonal presentation layer over the existing traffic sources: the
//! pcap capture or the mitm proxy runs in a background thread and feeds decoded
//! lines onto a channel; the TUI drains them on the main
//! thread and renders a scrollable, filterable view with [ratatui].
//!
//! First-cut controls:
//! - `q` / `Ctrl-C` — quit
//! - `j`/`k`, arrows, `PgUp`/`PgDn`, `g`/`G` — scroll
//! - `f` — toggle follow (auto-tail)
//! - `/` — filter by substring (`Enter` applies, `Esc` cancels)
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
use ratatui::widgets::{Block, Paragraph};

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
    /// Active substring filter (empty = none), case-insensitive.
    filter: String,
    /// Buffer being typed while in filter mode.
    filter_buf: String,
    filtering: bool,
    /// Index of the top visible line into the filtered view.
    scroll: usize,
    /// Auto-tail new output.
    follow: bool,
    mode: &'static str,
}

impl App {
    fn new(rx: Receiver<Output>, mode: &'static str) -> Self {
        Self {
            rx,
            events: Vec::new(),
            filter: String::new(),
            filter_buf: String::new(),
            filtering: false,
            scroll: 0,
            follow: true,
            mode,
        }
    }
}

/// Lines passing `filter` (empty = all). A free function (not a method) so the
/// returned borrows are tied only to `events`, leaving `App`'s other fields
/// (e.g. `scroll`) free to mutate while the view is live.
fn filtered<'a>(events: &'a [String], filter: &str) -> Vec<&'a String> {
    if filter.is_empty() {
        return events.iter().collect();
    }
    let needle = filter.to_lowercase();
    events
        .iter()
        .filter(|l| l.to_lowercase().contains(&needle))
        .collect()
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

        let view = filtered(&app.events, &app.filter);
        let max_scroll = view.len().saturating_sub(log_h);
        if app.follow {
            app.scroll = max_scroll;
        }
        app.scroll = app.scroll.min(max_scroll);

        terminal.draw(|frame| draw(frame, &app, &view, log_h))?;

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
    if app.filtering {
        match key.code {
            KeyCode::Esc => {
                app.filtering = false;
                app.filter_buf.clear();
            }
            KeyCode::Enter => {
                app.filter = std::mem::take(&mut app.filter_buf);
                app.filtering = false;
                app.follow = true;
            }
            KeyCode::Backspace => {
                app.filter_buf.pop();
            }
            KeyCode::Char(c) if !c.is_control() => app.filter_buf.push(c),
            _ => {}
        }
        return false;
    }

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
        KeyCode::Char('c') => app.events.clear(),
        KeyCode::Char('/') => {
            app.filtering = true;
            app.filter_buf.clear();
        }
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, app: &App, view: &[&String], log_h: usize) {
    let [title_area, log_area, foot_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    // --- title bar ---
    let filter_tag = if app.filter.is_empty() {
        String::new()
    } else {
        format!(" · filter {:?} ", app.filter)
    };
    let follow_tag = if app.follow { " · following" } else { "" };
    let title = format!(
        " tapgres — {} mode · {} events ({} shown){}{} ",
        app.mode,
        app.events.len(),
        view.len(),
        filter_tag,
        follow_tag,
    );
    frame.render_widget(Block::bordered().title_top(Line::raw(title)), title_area);

    // --- log ---
    let start = app.scroll;
    let end = (start + log_h).min(view.len());
    let lines: Vec<Line> = view[start..end]
        .iter()
        .map(|l| build_line(l.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(lines)).block(Block::bordered().title_top(Line::raw(" events "))),
        log_area,
    );

    // --- footer ---
    if app.filtering {
        let prefix = " filter: ";
        frame.render_widget(
            Paragraph::new(Text::raw(format!("{prefix}{}", app.filter_buf)))
                .block(Block::bordered().title_top(Line::raw(" / "))),
            foot_area,
        );
        let cx = foot_area.x + 1 + prefix.len() as u16 + app.filter_buf.len() as u16;
        let cy = foot_area.y + 1;
        frame.set_cursor_position((cx.min(foot_area.right().saturating_sub(1)), cy));
    } else {
        frame.render_widget(
            Paragraph::new(Text::raw(
                " q quit · j/k ↑↓ · PgUp/PgDn · g/G top/bottom · f follow · / filter · c clear ",
            ))
            .block(Block::bordered()),
            foot_area,
        );
    }
}

/// Render a line with only the direction symbol (`[F→B]`/`[B→F]`) highlighted;
/// everything else stays the default colour for easy reading. The two symbols
/// use high-contrast colours (F→B cyan, B→F magenta) so direction is obvious at
/// a glance. Warnings stay red and connection notices yellow.
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
    // "[ts] [F→B] KIND: text" -> prefix | symbol | suffix
    Line::from(vec![
        Span::raw(&line[..start]),
        Span::raw(&line[start..end]).fg(color).bold(),
        Span::raw(&line[end..]),
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
