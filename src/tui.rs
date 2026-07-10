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
use ratatui::layout::{Constraint, Layout, Margin, Rect};
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
    // Probe the terminal's default background (best-effort) so zebra striping
    // picks a shade that reads on dark vs light themes.
    let theme = detect_bg_theme();
    let result = app_loop(&mut terminal, App::new(rx, mode, theme));
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
    /// Terminal background theme — chooses the zebra-stripe shade.
    theme: BgTheme,
    mode: &'static str,
}

impl App {
    fn new(rx: Receiver<Output>, mode: &'static str, theme: BgTheme) -> Self {
        Self {
            rx,
            events: Vec::new(),
            scroll: 0,
            follow: true,
            wrap: false,
            theme,
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
        // all the way to the last event; otherwise keep the viewport full.
        let max_scroll = if app.wrap {
            app.events.len().saturating_sub(1)
        } else {
            app.events.len().saturating_sub(log_h)
        };
        if app.follow {
            app.scroll = max_scroll;
        }
        app.scroll = app.scroll.min(max_scroll);

        terminal.draw(|frame| draw(frame, &app))?;

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

fn draw(frame: &mut Frame, app: &App) {
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
    // Render the bordered block, then each row as its own widget so the zebra
    // background fills the whole line width (a Block fills its area with its
    // style; a Paragraph alone only colours the cells under the text).
    frame.render_widget(
        Block::bordered()
            .title_top(Line::raw(" packets "))
            .border_style(Style::default().fg(Color::Green)),
        log_area,
    );
    let inner = log_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });
    let bottom = inner.bottom();
    let stripe = app.theme.stripe_color();
    let mut y = inner.y;
    for (vis, idx) in (app.scroll..app.events.len()).enumerate() {
        if y >= bottom {
            break;
        }
        let avail = bottom - y;
        let mut para = Paragraph::new(build_line(app.events[idx].as_str()));
        if app.wrap {
            para = para.wrap(Wrap { trim: false });
        }
        // With wrap on an event may occupy several rows; otherwise one.
        let h = if app.wrap {
            (para.line_count(inner.width).max(1) as u16).min(avail)
        } else {
            1
        };
        let row = Rect::new(inner.x, y, inner.width, h);
        // Odd visible rows get a full-width background; the text goes on top.
        if vis % 2 == 1 {
            frame.render_widget(Block::new().style(Style::default().bg(stripe)), row);
        }
        frame.render_widget(para, row);
        y += h;
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
/// easy reading. Warnings stay red and connection notices yellow. Row/zebra
/// background is applied by the per-row widget in [`draw`].
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

// ---------------------------------------------------------------------------
// Terminal background detection — picks a zebra-stripe shade that reads on the
// user's theme. Tries OSC 11 (the terminal's default bg) first, then the
// `COLORFGBG` env var, then assumes dark.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum BgTheme {
    Dark,
    Light,
}

impl BgTheme {
    /// A subtle background for zebra striping: dark grey on dark themes,
    /// light grey on light themes.
    fn stripe_color(self) -> Color {
        match self {
            BgTheme::Dark => Color::DarkGray,
            BgTheme::Light => Color::Gray,
        }
    }
}

fn detect_bg_theme() -> BgTheme {
    if let Some((r, g, b)) = query_default_bg() {
        // Rec. 709 luma; below the midpoint reads as a dark background.
        let lum = 0.299 * f32::from(r) + 0.587 * f32::from(g) + 0.114 * f32::from(b);
        return if lum < 128.0 {
            BgTheme::Dark
        } else {
            BgTheme::Light
        };
    }
    if let Some(theme) = parse_colorfgbg() {
        return theme;
    }
    BgTheme::Dark
}

#[cfg(unix)]
fn query_default_bg() -> Option<(u8, u8, u8)> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    // Ask the terminal for its default background (OSC 11, ST-terminated).
    {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b]11;?\x1b\\");
        let _ = out.flush();
    }

    // Read the reply non-blocking so we can't hang on terminals that ignore it.
    let fd = std::io::stdin().as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return None;
    }
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    struct RestoreFlags(i32, i32);
    impl Drop for RestoreFlags {
        fn drop(&mut self) {
            unsafe { libc::fcntl(self.0, libc::F_SETFL, self.1) };
        }
    }
    let _restore = RestoreFlags(fd, flags); // always restore blocking mode

    let mut got: Vec<u8> = Vec::with_capacity(64);
    let mut buf = [0u8; 64];
    let deadline = std::time::Instant::now() + Duration::from_millis(100);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match std::io::stdin().lock().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                // Done once we see the ST (ESC \) or BEL terminator.
                if got.ends_with(b"\x07") || got.windows(2).any(|w| w == b"\x1b\\") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(4));
                continue;
            }
            Err(_) => break,
        }
    }
    parse_osc_rgb(&got)
}

#[cfg(not(unix))]
fn query_default_bg() -> Option<(u8, u8, u8)> {
    None
}

/// Parse an OSC color reply of the form `...rgb:rrrr/gggg/bbbb...` (or
/// `rgba:...`) into an 8-bit-per-channel triple.
fn parse_osc_rgb(bytes: &[u8]) -> Option<(u8, u8, u8)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let rgb = s.find("rgb")?;
    let rest = &s[rgb..];
    let colon = rest.find(':')?;
    let mut parts = rest[colon + 1..].split('/');
    let r = parse_hex_channel(parts.next()?)?;
    let g = parse_hex_channel(parts.next()?)?;
    let b = parse_hex_channel(parts.next()?)?;
    Some((r, g, b))
}

/// Decode one OSC color channel (1–4 hex digits) into a u8.
fn parse_hex_channel(group: &str) -> Option<u8> {
    let hex: String = group
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    let normalized = if hex.len() >= 2 {
        hex[..2].to_string()
    } else {
        format!("{hex}{hex}")
    };
    u8::from_str_radix(&normalized, 16).ok()
}

/// Fall back to the legacy `COLORFGBG="fg;bg"` env var (set by some terminals).
fn parse_colorfgbg() -> Option<BgTheme> {
    let val = std::env::var("COLORFGBG").ok()?;
    let bg: u8 = val.split(';').nth(1)?.trim().parse().ok()?;
    // 0–6 and 8 are dark; 7 and 9–15 are light.
    Some(if bg <= 6 || bg == 8 {
        BgTheme::Dark
    } else {
        BgTheme::Light
    })
}
