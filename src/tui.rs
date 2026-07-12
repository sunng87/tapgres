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
use std::sync::Arc;
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, RenderDirection, Sparkline, Wrap};

use crate::capture::PcapOpts;
use crate::decode::{self, Output};
use crate::proxy::ProxyOpts;
use crate::state::Metrics;

/// Cap on retained lines in the TUI's own buffer.
const HISTORY_CAP: usize = 50_000;

/// TUI over the passive pcap capture.
pub fn run_pcap(opts: PcapOpts, metrics: Arc<Metrics>) -> Result<(), Box<dyn Error>> {
    let source_metrics = metrics.clone();
    run(
        Box::new(move || {
            if let Err(e) = crate::capture::run(opts, source_metrics) {
                decode::status(format!("⚠ pcap source error: {e}"));
            }
        }),
        "pcap",
        metrics,
    )
}

/// TUI over the TLS-terminating mitm proxy.
pub fn run_mitm(opts: ProxyOpts, metrics: Arc<Metrics>) -> Result<(), Box<dyn Error>> {
    let source_metrics = metrics.clone();
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
            if let Err(e) = rt.block_on(crate::proxy::serve(opts, source_metrics)) {
                decode::status(format!("⚠ mitm source error: {e}"));
            }
        }),
        "mitm",
        metrics,
    )
}

/// Install a shared sink, start `source` in a background thread, run the TUI on
/// this (main) thread, and always restore the terminal before returning.
fn run(
    source: Box<dyn FnOnce() + Send + 'static>,
    mode: &'static str,
    metrics: Arc<Metrics>,
) -> Result<(), Box<dyn Error>> {
    // One channel: the source (background thread) produces via decode::out,
    // the TUI (this thread) consumes.
    let (tx, rx) = crossbeam_channel::unbounded();
    decode::set_output(tx);

    // The source runs until the process exits; no graceful shutdown here.
    let _source_thread = std::thread::Builder::new()
        .name("tapgres-source".into())
        .spawn(source)?;
    let _rate_sampler = metrics.spawn_rate_sampler()?;

    let mut terminal = ratatui::try_init()?;
    let result = app_loop(&mut terminal, App::new(rx, mode, metrics));
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
    metrics: Arc<Metrics>,
    /// All-time peak messages/sec seen this session, per direction. Used as a
    /// fixed sparkline scale so bars don't rescale as the rate window slides;
    /// the value only ever grows.
    peak_msgs_in: u64,
    peak_msgs_out: u64,
}

impl App {
    fn new(rx: Receiver<Output>, mode: &'static str, metrics: Arc<Metrics>) -> Self {
        Self {
            rx,
            events: Vec::new(),
            scroll: 0,
            follow: true,
            wrap: false,
            mode,
            metrics,
            peak_msgs_in: 0,
            peak_msgs_out: 0,
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

        // 6 (metrics) + 3 (footer) + 2 (log block borders) rows of chrome.
        let term_h = terminal.size()?.height as usize;
        let log_h = term_h.saturating_sub(11).max(1);

        // In wrap mode an event may span several rows, so the viewport holds
        // fewer than `log_h` events; allow scrolling up to the last event.
        // Otherwise the viewport shows `log_h` events.
        let max_scroll = if app.wrap {
            app.events.len().saturating_sub(1)
        } else {
            app.events.len().saturating_sub(log_h)
        };
        if app.follow {
            app.scroll = max_scroll;
        }
        app.scroll = app.scroll.min(max_scroll);

        // Fixed sparkline scale: track the all-time peak messages/sec per
        // direction so the bars keep a stable scale instead of rescaling to
        // the current window's max as samples expire or arrive.
        {
            let summary = app.metrics.summary();
            app.peak_msgs_in = app
                .peak_msgs_in
                .max(summary.rates.iter().map(|r| r.msgs_in).max().unwrap_or(0));
            app.peak_msgs_out = app
                .peak_msgs_out
                .max(summary.rates.iter().map(|r| r.msgs_out).max().unwrap_or(0));
        }

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
        Constraint::Length(6),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    // --- title bar: rich metrics header ---
    let heading = format!(
        " tapgres — {} mode · {} events ",
        app.mode,
        app.events.len()
    );
    let metrics = app.metrics.summary();
    let current = metrics.rates.last().copied().unwrap_or_default();

    // Messages-per-second series over the rate window. In is cyan and out is
    // magenta to match the [F→B]/[B→F] colour scheme used in the message view.
    let msgs_in: Vec<u64> = metrics.rates.iter().map(|r| r.msgs_in).collect();
    let msgs_out: Vec<u64> = metrics.rates.iter().map(|r| r.msgs_out).collect();
    let combined: Vec<u64> = metrics
        .rates
        .iter()
        .map(|r| r.msgs_in.saturating_add(r.msgs_out))
        .collect();
    let avg = combined.iter().copied().sum::<u64>() / combined.len().max(1) as u64;
    let peak = combined.iter().copied().max().unwrap_or(0);
    let now = current.msgs_in.saturating_add(current.msgs_out);

    let header_block = Block::bordered().title_top(Line::raw(heading));
    let header_inner = header_block.inner(title_area);
    frame.render_widget(header_block, title_area);

    // Active | total in | total out | messages-per-second — four equal columns.
    let [active_area, in_area, out_area, chart_area] =
        Layout::horizontal([Constraint::Fill(1); 4]).areas(header_inner);

    frame.render_widget(
        stat_text(
            "ACTIVE",
            metrics.conns_live.to_string(),
            Color::Reset,
            format!("opened {}", metrics.conns_opened),
            String::new(),
        ),
        active_area,
    );
    frame.render_widget(
        stat_text(
            "TOTAL IN",
            human(metrics.bytes_in),
            Color::Cyan,
            format!("{} msgs", with_commas(metrics.msgs_in)),
            format!("{}/s", human(current.bytes_in)),
        ),
        in_area,
    );
    frame.render_widget(
        stat_text(
            "TOTAL OUT",
            human(metrics.bytes_out),
            Color::Magenta,
            format!("{} msgs", with_commas(metrics.msgs_out)),
            format!("{}/s", human(current.bytes_out)),
        ),
        out_area,
    );

    // Right column: two stacked sparklines (in cyan, out magenta) + caption.
    let [chart_label, chart_in, chart_out, chart_cap] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(chart_area);
    frame.render_widget(
        Paragraph::new(Text::styled(
            "MESSAGES/SEC",
            Style::default().fg(Color::DarkGray),
        )),
        chart_label,
    );
    let [in_tag, in_spark] =
        Layout::horizontal([Constraint::Length(5), Constraint::Fill(1)]).areas(chart_in);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("in ", Style::default().fg(Color::Cyan)),
            Span::styled("→", Style::default().fg(Color::Cyan).bold()),
        ])),
        in_tag,
    );
    // Right-to-left with the series reversed: the newest sample pins to the
    // right edge and older samples scroll left, like a live-activity chart.
    frame.render_widget(
        Sparkline::default()
            .direction(RenderDirection::RightToLeft)
            .data(msgs_in.iter().rev())
            .max(app.peak_msgs_in.max(1))
            .style(Style::default().fg(Color::Cyan)),
        in_spark,
    );
    let [out_tag, out_spark] =
        Layout::horizontal([Constraint::Length(5), Constraint::Fill(1)]).areas(chart_out);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("out ", Style::default().fg(Color::Magenta)),
            Span::styled("←", Style::default().fg(Color::Magenta).bold()),
        ])),
        out_tag,
    );
    frame.render_widget(
        Sparkline::default()
            .direction(RenderDirection::RightToLeft)
            .data(msgs_out.iter().rev())
            .max(app.peak_msgs_out.max(1))
            .style(Style::default().fg(Color::Magenta)),
        out_spark,
    );
    frame.render_widget(
        Paragraph::new(Text::styled(
            format!(
                "now {} avg {} peak {}",
                with_commas(now),
                with_commas(avg),
                with_commas(peak)
            ),
            Style::default().fg(Color::Gray),
        )),
        chart_cap,
    );

    // --- message view ---
    let log_block = Block::bordered()
        .title_top(Line::raw(" messages "))
        .border_style(Style::default().fg(Color::Green));
    let inner_w = log_area.width.saturating_sub(2) as usize;
    // Size the window by display rows so every shown item is fully visible (no
    // mid-item clipping): follow fills backward from the newest event, else
    // forward from the scroll anchor. Without wrap each item is one row.
    let (start, end) = if app.wrap {
        wrap_window(&app.events, app.scroll, app.follow, log_h, inner_w)
    } else {
        let s = app.scroll;
        (s, (s + log_h).min(app.events.len()))
    };
    let lines: Vec<Line> = app.events[start..end]
        .iter()
        .map(|l| build_line(l.as_str()))
        .collect();
    let mut para = Paragraph::new(Text::from(lines)).block(log_block);
    if app.wrap {
        para = para.wrap(Wrap { trim: false });
    }
    frame.render_widget(para, log_area);

    // --- footer: follow/wrap state shown by colour (green = on) ---
    let on = Style::default().fg(Color::Green);
    let off = Style::default();
    let footer = Line::from(vec![
        Span::raw(" q quit · j/k ↑↓ · PgUp/PgDn · g/G top/bottom · f "),
        Span::styled("follow", if app.follow { on } else { off }),
        Span::raw(" · w "),
        Span::styled("wrap", if app.wrap { on } else { off }),
        Span::raw(" · c clear "),
    ]);
    frame.render_widget(Paragraph::new(footer).block(Block::bordered()), foot_area);
}

fn human(value: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}{}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// Group a number with thousands separators: `8521` -> `8,521`.
fn with_commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i != 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// A four-line stat column for the metrics header: label / big value / sub
/// value / rate. Content is owned so the returned `Text` is `'static`.
fn stat_text(
    label: &str,
    big: String,
    big_color: Color,
    sub: String,
    rate: String,
) -> Text<'static> {
    Text::from(vec![
        Line::styled(label.to_string(), Style::default().fg(Color::DarkGray)),
        Line::styled(format!(" {big}"), Style::default().fg(big_color).bold()),
        Line::styled(format!(" {sub}"), Style::default().fg(Color::Gray).bold()),
        Line::styled(format!(" {rate}"), Style::default().fg(Color::Gray).bold()),
    ])
}

/// In wrap mode, pick the slice `[start, end)` of events to render so the
/// viewport is filled with whole items (no row clipped mid-item): follow fills
/// backward from the newest event; otherwise fill forward from the `scroll`
/// anchor. `width` is the inner (post-border) column count.
fn wrap_window(
    events: &[String],
    scroll: usize,
    follow: bool,
    log_h: usize,
    width: usize,
) -> (usize, usize) {
    let n = events.len();
    if n == 0 {
        return (0, 0);
    }
    let height = |s: &str| {
        Paragraph::new(build_line(s))
            .wrap(Wrap { trim: false })
            .line_count(width as u16)
            .max(1)
    };
    let mut rows = 0usize;
    if follow {
        let mut start = n;
        for (i, evt) in events.iter().enumerate().rev() {
            let h = height(evt.as_str());
            if rows != 0 && rows + h > log_h {
                break;
            }
            rows += h;
            start = i;
            if rows >= log_h {
                break;
            }
        }
        (start, n)
    } else {
        let mut end = scroll;
        for (i, evt) in events.iter().enumerate().skip(scroll) {
            let h = height(evt.as_str());
            if rows != 0 && rows + h > log_h {
                break;
            }
            rows += h;
            end = i + 1;
            if rows >= log_h {
                break;
            }
        }
        (scroll, end)
    }
}

/// Render a line with the direction symbol (`[F→B]`/`[B→F]`) highlighted in a
/// high-contrast colour (F→B cyan, B→F magenta, bold) and the message name
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
        Span::raw(&line[..start]).fg(Color::DarkGray),
        Span::raw(&line[start..end]).fg(color).bold(),
        Span::raw(&line[end..kind_start]),
        Span::raw(&line[kind_start..kind_end]).fg(color).bold(),
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
