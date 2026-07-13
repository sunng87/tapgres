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
pub fn run_pcap(
    opts: PcapOpts,
    metrics: Arc<Metrics>,
    rich: bool,
) -> Result<(), Box<dyn Error>> {
    let source_metrics = metrics.clone();
    run(
        Box::new(move || {
            if let Err(e) = crate::capture::run(opts, source_metrics) {
                decode::status(format!("⚠ pcap source error: {e}"));
            }
        }),
        "pcap",
        metrics,
        rich,
    )
}

/// TUI over the TLS-terminating mitm proxy.
pub fn run_mitm(
    opts: ProxyOpts,
    metrics: Arc<Metrics>,
    rich: bool,
) -> Result<(), Box<dyn Error>> {
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
        rich,
    )
}

/// Install a shared sink, start `source` in a background thread, run the TUI on
/// this (main) thread, and always restore the terminal before returning.
fn run(
    source: Box<dyn FnOnce() + Send + 'static>,
    mode: &'static str,
    metrics: Arc<Metrics>,
    rich: bool,
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
    let result = app_loop(&mut terminal, App::new(rx, mode, metrics, rich));
    // Restore the terminal even on error. try_init installs a panic hook that
    // also restores, so panics are covered too.
    let _ = ratatui::try_restore();
    result.map_err(Into::into)
}

/// One retained decoded record: the line-view text plus, optionally, the
/// structured detail the rich view renders instead of that text.
struct Entry {
    text: String,
    detail: Option<decode::EventDetail>,
}

/// Rich-mode rendering options bundled together so the draw/window functions
/// stay readable as more toggles accumulate.
#[derive(Clone, Copy)]
struct View {
    rich: bool,
    wrap: bool,
}

struct App {
    rx: Receiver<Output>,
    events: Vec<Entry>,
    /// Index of the top visible line into the event buffer.
    scroll: usize,
    /// Auto-tail new output.
    follow: bool,
    /// Wrap long lines to the viewport width.
    wrap: bool,
    /// Rich display mode: draw `DataRow` as a per-message key/value table and
    /// `RowDescription` as a typed column list, instead of the flat line. Type
    /// names are shown with an icon-font (Nerd Font) glyph.
    rich: bool,
    mode: &'static str,
    metrics: Arc<Metrics>,
    /// All-time peak messages/sec seen this session, per direction. Used as a
    /// fixed sparkline scale so bars don't rescale as the rate window slides;
    /// the value only ever grows.
    peak_msgs_in: u64,
    peak_msgs_out: u64,
}

impl App {
    fn new(rx: Receiver<Output>, mode: &'static str, metrics: Arc<Metrics>, rich: bool) -> Self {
        Self {
            rx,
            events: Vec::new(),
            scroll: 0,
            follow: true,
            wrap: false,
            rich,
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
            let evt = match record {
                Output::Line(s) | Output::Status(s) => Entry { text: s, detail: None },
                Output::Rich { text, detail } => Entry { text, detail: Some(detail) },
            };
            app.events.push(evt);
        }
        if app.events.len() > HISTORY_CAP {
            let drop_n = app.events.len() - HISTORY_CAP;
            app.events.drain(..drop_n);
        }

        // 5 (metrics) + 3 (footer) + 2 (log block borders) rows of chrome.
        let term_h = terminal.size()?.height as usize;
        let log_h = term_h.saturating_sub(10).max(1);

        // In wrap mode an event may span several rows, so the viewport holds
        // fewer than `log_h` events; allow scrolling up to the last event.
        // Otherwise the viewport shows `log_h` events.
        // Wrap mode and rich mode both let a single event span several rows
        // (wrapped lines, or a key/value table), so scrolling is indexed by
        // event and may reach the last one. In the plain one-row-per-event
        // view, cap so the window stays full instead of stranding the last
        // event at the top with empty space below.
        let max_scroll = if app.wrap || app.rich {
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
        KeyCode::Char('r') => app.rich = !app.rich,
        KeyCode::Char('c') => app.events.clear(),
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, app: &App, log_h: usize) {
    let [title_area, log_area, foot_area] = Layout::vertical([
        Constraint::Length(5),
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
    let [chart_in, chart_out, chart_cap] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(chart_area);
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
    let view = View {
        rich: app.rich,
        wrap: app.wrap,
    };
    // Size the window by display rows so every shown item is fully visible (no
    // mid-item clipping): follow fills backward from the newest event, else
    // forward from the scroll anchor. Wrap mode and rich mode both need this —
    // an event may span many rows (wrapped text, or a key/value table) — so
    // they share the row-counted window; the plain one-row view stays on the
    // cheap fixed-slice path.
    let (start, end) = if app.wrap || app.rich {
        view_window(&app.events, app.scroll, app.follow, log_h, inner_w, view)
    } else {
        let s = app.scroll;
        (s, (s + log_h).min(app.events.len()))
    };
    let mut lines: Vec<Line> = Vec::new();
    for evt in &app.events[start..end] {
        lines.extend(event_lines(evt, view));
    }
    let mut para = Paragraph::new(Text::from(lines)).block(log_block);
    if app.wrap {
        para = para.wrap(Wrap { trim: false });
    }
    frame.render_widget(para, log_area);

    // --- footer: follow/wrap/rich state shown by colour (green = on) ---
    let on = Style::default().fg(Color::Green);
    let off = Style::default();
    let footer = Line::from(vec![
        Span::raw(" q quit · j/k ↑↓ · PgUp/PgDn · g/G top/bottom · f "),
        Span::styled("follow", if app.follow { on } else { off }),
        Span::raw(" · w "),
        Span::styled("wrap", if app.wrap { on } else { off }),
        Span::raw(" · r "),
        Span::styled("rich", if app.rich { on } else { off }),
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

/// A three-line stat column for the metrics header: the label sits inline
/// with the big value, followed by the sub value and the rate. Content is
/// owned so the returned `Text` is `'static`.
fn stat_text(
    label: &str,
    big: String,
    big_color: Color,
    sub: String,
    rate: String,
) -> Text<'static> {
    Text::from(vec![
        Line::from(vec![
            Span::styled(format!("{label} "), Style::default().fg(Color::DarkGray)),
            Span::styled(big, Style::default().fg(big_color).bold()),
        ]),
        Line::styled(sub, Style::default().fg(Color::Gray).bold()),
        Line::styled(rate, Style::default().fg(Color::Gray).bold()),
    ])
}

/// Pick the slice `[start, end)` of events to render so the viewport is filled
/// with whole items (no row clipped mid-item): follow fills backward from the
/// newest event; otherwise fill forward from the `scroll` anchor. `width` is
/// the inner (post-border) column count. Shared by the wrapped line view and
/// the multi-row rich tables — both key event height off [`event_height`] —
/// so an item that spans several rows is never cut in half.
fn view_window(
    events: &[Entry],
    scroll: usize,
    follow: bool,
    log_h: usize,
    width: usize,
    view: View,
) -> (usize, usize) {
    let n = events.len();
    if n == 0 {
        return (0, 0);
    }
    let mut rows = 0usize;
    if follow {
        let mut start = n;
        for (i, evt) in events.iter().enumerate().rev() {
            let h = event_height(evt, width, view);
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
            let h = event_height(evt, width, view);
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

/// Display rows an event occupies: the flat line view is one row (or its
/// wrapped height in wrap mode); a rich `DataRow`/`RowDescription` is one
/// header row plus one row per column. In wrap mode any of those lines may
/// further reflow, so defer to ratatui's `Paragraph::line_count`.
fn event_height(evt: &Entry, width: usize, view: View) -> usize {
    if view.wrap {
        return Paragraph::new(Text::from(event_lines(evt, view)))
            .wrap(Wrap { trim: false })
            .line_count(width as u16)
            .max(1);
    }
    if view.rich {
        match &evt.detail {
            Some(decode::EventDetail::DataRow(cols)) => 1 + cols.len(),
            Some(decode::EventDetail::RowDescription(fields)) => 1 + fields.len(),
            None => 1,
        }
    } else {
        1
    }
}

/// The lines an event renders as: the flat line view, or — in rich mode, when
/// structured detail is available — a header line followed by a key/value (or
/// typed column) breakdown.
fn event_lines<'a>(evt: &'a Entry, view: View) -> Vec<Line<'a>> {
    if view.rich {
        if let Some(detail) = &evt.detail {
            return render_rich(&evt.text, detail);
        }
    }
    vec![build_line(&evt.text)]
}

/// Render a structured event for rich mode: the kind header (no line-view
/// content), then one row per field. A `DataRow` becomes a `name = value`
/// list; a `RowDescription` becomes a `name  type` list. Field names are blue
/// to read as a header and stay distinct from the cyan/magenta direction
/// colours; each type is shown as an icon-font glyph (when enabled) plus its
/// textual name.
fn render_rich<'a>(text: &'a str, detail: &'a decode::EventDetail) -> Vec<Line<'a>> {
    let key = Style::default().fg(Color::Blue).bold();
    // The structured rows below ARE the content, so the header carries only the
    // timestamp/direction/kind — not the line-view summary text, which would
    // just duplicate the table.
    let mut lines = vec![build_header_line(text)];
    match detail {
        decode::EventDetail::DataRow(cols) => {
            for c in cols {
                let mut row: Vec<Span<'static>> = vec![
                    Span::raw("   "),
                    Span::styled(c.name.clone(), key),
                    Span::raw(" = "),
                    Span::raw(c.value.clone()),
                    Span::raw("  "),
                ];
                row.extend(type_spans(c.type_oid));
                lines.push(Line::from(row));
            }
        }
        decode::EventDetail::RowDescription(fields) => {
            for f in fields {
                let mut row: Vec<Span<'static>> = vec![
                    Span::raw("   "),
                    Span::styled(f.name.clone(), key),
                    Span::raw("  "),
                ];
                row.extend(type_spans(f.type_oid));
                lines.push(Line::from(row));
            }
        }
    }
    lines
}

/// Human-friendly type name for common PostgreSQL OIDs, falling back to the
/// numeric OID. This is the safe textual fallback issue #15 asks for — no
/// glyph/font assumptions — and is always shown alongside any glyph so a
/// terminal without the Nerd Font never loses the type.
fn type_label(oid: u32) -> String {
    let name = match oid {
        16 => "bool",
        17 => "bytea",
        18 => "char",
        19 => "name",
        20 => "int8",
        21 => "int2",
        23 => "int4",
        25 => "text",
        114 => "json",
        700 => "float4",
        701 => "float8",
        1043 => "varchar",
        1082 => "date",
        1114 => "timestamp",
        1184 => "timestamptz",
        1186 => "interval",
        1700 => "numeric",
        2950 => "uuid",
        3802 => "jsonb",
        _ => return format!("oid={oid}"),
    };
    name.to_string()
}

/// Icon-font glyph for a column type, keyed on the PostgreSQL OID, plus a
/// category colour. The codepoints are Font Awesome solid (preserved verbatim
/// by Nerd Fonts v3) and require a Nerd Font in the terminal; the textual
/// [`type_label`] is always shown alongside, so the type is never ambiguous.
/// Returns `None` for unknown OIDs, which then render with the name only.
fn type_icon(oid: u32) -> Option<(char, Color)> {
    Some(match oid {
        16 => ('\u{f00c}', Color::Green), // bool -> check
        20 | 21 | 23 => ('\u{f292}', Color::Yellow), // int8/int2/int4 -> hashtag
        700 | 701 | 1700 => ('\u{f1ec}', Color::Yellow), // float4/float8/numeric -> calculator
        18 | 19 | 25 | 1042 | 1043 => ('\u{f031}', Color::Cyan), // char/name/text/bpchar/varchar -> font
        114 | 3802 => ('\u{f121}', Color::Magenta), // json/jsonb -> code
        2950 => ('\u{f577}', Color::Magenta), // uuid -> fingerprint
        17 => ('\u{f1c0}', Color::Green), // bytea -> database
        1082 => ('\u{f073}', Color::Cyan), // date -> calendar
        1083 | 1114 | 1184 | 1186 | 1266 => ('\u{f017}', Color::Cyan), // time/timestamp*/interval -> clock
        _ => return None,
    })
}

/// Styled spans for a column's type: an icon-font glyph (when known) followed
/// by the textual type name. Rich mode always shows the glyph.
fn type_spans(oid: u32) -> Vec<Span<'static>> {
    let mut spans = Vec::with_capacity(3);
    if let Some((g, color)) = type_icon(oid) {
        spans.push(Span::styled(g.to_string(), Style::default().fg(color)));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        type_label(oid),
        Style::default().fg(Color::DarkGray),
    ));
    spans
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
    let Some(p) = parse_line(line) else {
        return Line::styled(line, Style::default());
    };
    Line::from(vec![
        Span::raw(&line[..p.prefix_end]).fg(Color::DarkGray),
        Span::raw(&line[p.prefix_end..p.tag_end]).fg(p.color).bold(),
        Span::raw(&line[p.tag_end..p.kind_start]),
        Span::raw(&line[p.kind_start..p.kind_end]).fg(p.color).bold(),
        Span::raw(&line[p.kind_end..]),
    ])
}

/// Like [`build_line`] but stops after the message kind, dropping the trailing
/// content. Used as the header of a rich table, where that content is rendered
/// as the structured rows below instead of being duplicated in the header.
fn build_header_line(line: &str) -> Line<'_> {
    let Some(p) = parse_line(line) else {
        return Line::styled(line, Style::default());
    };
    Line::from(vec![
        Span::raw(&line[..p.prefix_end]).fg(Color::DarkGray),
        Span::raw(&line[p.prefix_end..p.tag_end]).fg(p.color).bold(),
        Span::raw(&line[p.tag_end..p.kind_start]),
        Span::raw(&line[p.kind_start..p.kind_end]).fg(p.color).bold(),
    ])
}

/// The coloured segments of a decoded line `[ts] [F→B] Kind[: rest]`.
/// [`direction_split`] supplies the tag colour and bounds; the rest is computed
/// here so [`build_line`] (full line) and [`build_header_line`] (kind only)
/// share a single parser and never drift apart.
struct LineParts {
    color: Color,
    prefix_end: usize,
    tag_end: usize,
    kind_start: usize,
    kind_end: usize,
}

fn parse_line(line: &str) -> Option<LineParts> {
    let (color, prefix_end, tag_end) = direction_split(line)?;
    // Skip the single space after the tag's closing bracket.
    let kind_start = (tag_end + 1).min(line.len());
    let kind_end = line[kind_start..]
        .find(": ")
        .map(|p| kind_start + p)
        .unwrap_or(line.len());
    Some(LineParts {
        color,
        prefix_end,
        tag_end,
        kind_start,
        kind_end,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{DataColumn, EventDetail};

    fn data_row_detail(n: usize) -> EventDetail {
        EventDetail::DataRow(
            (0..n)
                .map(|i| DataColumn {
                    name: format!("c{i}"),
                    type_oid: 25,
                    value: "'v'".into(),
                })
                .collect(),
        )
    }

    fn view(rich: bool) -> View {
        View {
            rich,
            wrap: false,
        }
    }

    #[test]
    fn type_label_maps_common_oids_and_falls_back() {
        assert_eq!(type_label(23), "int4");
        assert_eq!(type_label(25), "text");
        assert_eq!(type_label(2950), "uuid");
        assert_eq!(type_label(9999), "oid=9999");
    }

    #[test]
    fn type_icon_maps_common_oids_and_none_for_unknown() {
        // Known OIDs yield a glyph; the textual name stays authoritative.
        assert_eq!(type_icon(16).map(|(c, _)| c), Some('\u{f00c}')); // bool
        assert_eq!(type_icon(23).map(|(c, _)| c), Some('\u{f292}')); // int4
        assert_eq!(type_icon(25).map(|(c, _)| c), Some('\u{f031}')); // text
        assert!(type_icon(9999).is_none());
    }

    #[test]
    fn type_spans_render_glyph_for_known_and_name_only_for_unknown() {
        // Known OID -> glyph + space + label.
        let known = type_spans(23);
        assert_eq!(known.len(), 3);
        assert_eq!(known[0].content.as_ref(), "\u{f292}");
        assert_eq!(known[2].content.as_ref(), "int4");
        // Unknown OID -> name only, no glyph.
        let unknown = type_spans(9999);
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].content.as_ref(), "oid=9999");
    }

    #[test]
    fn event_height_counts_header_plus_each_field() {
        let entry = Entry {
            text: "x".into(),
            detail: Some(data_row_detail(3)),
        };
        // 1 header row + 3 columns, non-wrap rich mode.
        assert_eq!(event_height(&entry, 80, view(true)), 4);
    }

    #[test]
    fn event_height_plain_line_is_one_row() {
        let entry = Entry { text: "x".into(), detail: None };
        assert_eq!(event_height(&entry, 80, view(false)), 1);
        // Rich mode with no structured detail still renders the flat line.
        assert_eq!(event_height(&entry, 80, view(true)), 1);
    }

    #[test]
    fn view_window_does_not_clip_multirow_items() {
        // Two rich DataRows, 3 columns each -> 4 rows each. A 5-row viewport in
        // follow mode must show only the last item fully (4 rows) rather than
        // start the first and clip it mid-table.
        let events: Vec<Entry> = (0..2)
            .map(|_| Entry {
                text: "x".into(),
                detail: Some(data_row_detail(3)),
            })
            .collect();
        let (start, end) = view_window(&events, 0, true, 5, 80, view(true));
        assert_eq!((start, end), (1, 2));
    }

    #[test]
    fn rich_header_omits_line_view_content() {
        // The line-view text carries the row content; rich mode must not repeat
        // it in the header, since the table body below already shows it.
        let text = "[00:00:00.000] [B→F] DataRow: { name='alice' }";
        let detail = EventDetail::DataRow(vec![DataColumn {
            name: "name".into(),
            type_oid: 25,
            value: "'alice'".into(),
        }]);
        let rendered = render_rich(text, &detail);
        let header: String = rendered[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(header.contains("DataRow"), "header: {header}");
        assert!(
            !header.contains("alice"),
            "header must not repeat row content: {header}"
        );
        let body: String = rendered[1].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(body.contains("alice"), "body should carry the value: {body}");
    }

    #[test]
    fn rich_type_row_carries_glyph_and_name() {
        // Rich mode always renders the glyph (nerd font assumed) plus the name.
        let text = "[00:00:00.000] [B→F] DataRow";
        let detail = EventDetail::DataRow(vec![DataColumn {
            name: "id".into(),
            type_oid: 23,
            value: "1".into(),
        }]);
        let body: String = render_rich(text, &detail)[1]
            .spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(body.contains('\u{f292}'), "int4 glyph should render: {body:?}");
        assert!(body.contains("int4"), "type name should render: {body:?}");
    }
}
