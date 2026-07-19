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
//! - `r` — toggle rich message rendering
//! - `c` — clear
//! - `y` — edit the display filter
//! - `/` — search the message text; `n`/`N` — next/previous match
//! - `:` — open the command bar (`:save FILE`, `:open FILE`)

use crossbeam_channel::Receiver;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, RenderDirection, Sparkline, Wrap};

use crate::capture::PcapOpts;
use crate::decode::{self, Output};
use crate::filter::DisplayFilter;
use crate::proxy::ProxyOpts;
use crate::session::{self, SessionWriter};
use crate::state::{Metrics, MetricsSummary};

/// Cap on retained lines in the TUI's own buffer.
const HISTORY_CAP: usize = 50_000;
/// Trim in chunks during fast replay so a producer cannot grow the TUI buffer
/// without bound while avoiding an O(n) front-drain for every single record.
const HISTORY_TRIM_CHUNK: usize = 1_024;
/// How many recent status/warning lines to retain for the startup splash.
const STATUS_TAIL_CAP: usize = 8;

/// tapgres ASCII-art banner. Shown by the CLI (`--help` via `before_help`) and
/// as the heading of the TUI startup splash.
pub const BANNER: &str = "
████████╗ █████╗ ██████╗  ██████╗ ██████╗ ███████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ██╔══██╗██╔════╝██╔════╝
   ██║   ███████║██████╔╝██║  ███╗██████╔╝█████╗  ███████╗
   ██║   ██╔══██║██╔═══╝ ██║   ██║██╔══██╗██╔══╝  ╚════██║
   ██║   ██║  ██║██║     ╚██████╔╝██║  ██║███████╗███████║
   ╚═╝   ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
";

/// TUI over the passive pcap capture.
pub fn run_pcap(
    opts: PcapOpts,
    metrics: Arc<Metrics>,
    rich: bool,
    filter: DisplayFilter,
    save: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let splash_lines = pcap_splash_lines(&opts);
    let source_metrics = metrics.clone();
    run(
        Box::new(move || {
            crate::capture::run(opts, source_metrics).map_err(|e| format!("pcap source error: {e}"))
        }),
        "pcap",
        metrics,
        rich,
        filter,
        splash_lines,
        save,
        None,
    )
}

/// Connection/capture info shown on the pcap splash: which interface is being
/// sniffed and which PostgreSQL port is watched.
fn pcap_splash_lines(opts: &PcapOpts) -> Vec<String> {
    let iface = match &opts.interface {
        Some(name) => name.clone(),
        None => "lo (loopback, default)".to_string(),
    };
    vec![
        format!("capturing interface:  {iface}"),
        format!("monitoring port:      {}", opts.port),
        "cleartext connections only".to_string(),
    ]
}

/// TUI over the TLS-terminating mitm proxy.
pub fn run_mitm(
    opts: ProxyOpts,
    metrics: Arc<Metrics>,
    rich: bool,
    filter: DisplayFilter,
    save: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let splash_lines = mitm_splash_lines(&opts);
    let source_metrics = metrics.clone();
    run(
        Box::new(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start mitm runtime: {e}"))?;
            rt.block_on(crate::proxy::serve(opts, source_metrics))
                .map_err(|e| format!("mitm source error: {e}"))
        }),
        "mitm",
        metrics,
        rich,
        filter,
        splash_lines,
        save,
        None,
    )
}

/// TUI over a saved JSONL session. Records are loaded at full speed through
/// the same channel and rendering path as live capture.
pub fn run_replay(
    path: PathBuf,
    metrics: Arc<Metrics>,
    rich: bool,
    filter: DisplayFilter,
    save: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let source_path = path.clone();
    run(
        Box::new(move || {
            let (outputs, dropped) = session::read_tail(&source_path, HISTORY_CAP)
                .map_err(|error| format!("replay source error: {error}"))?;
            if dropped > 0 {
                decode::status(format!(
                    "replay: showing the newest {HISTORY_CAP} records; {dropped} earlier records are outside TUI history"
                ));
            }
            outputs.into_iter().for_each(decode::replay);
            decode::close_output();
            Ok(())
        }),
        "replay",
        metrics,
        rich,
        filter,
        Vec::new(),
        save,
        Some(path),
    )
}

/// Connection info shown on the mitm splash: where to point the client, the
/// upstream it forwards to, and the TLS configuration on each leg.
fn mitm_splash_lines(opts: &ProxyOpts) -> Vec<String> {
    let client_tls = if opts.tls_cert.is_some() {
        "client TLS:  user-supplied certificate".to_string()
    } else {
        format!("client TLS:  auto CA in {}", opts.tls_dir.display())
    };
    let upstream_tls = if opts.no_upstream_tls {
        "upstream:     cleartext".to_string()
    } else {
        "upstream:     TLS auto-negotiate".to_string()
    };
    vec![
        format!("point your client at:  {}", opts.listen),
        format!("forwarding to:         {}", opts.upstream),
        client_tls,
        upstream_tls,
    ]
}

/// The traffic source thread's body. Returns a human-readable error string on a
/// fatal source failure (capture permission, bind failure, replay read error).
type Source = Box<dyn FnOnce() -> Result<(), String> + Send + 'static>;

/// Install a shared sink, start `source` in a background thread, run the TUI on
/// this (main) thread, and always restore the terminal before returning.
#[allow(clippy::too_many_arguments)]
fn run(
    source: Source,
    mode: &'static str,
    metrics: Arc<Metrics>,
    rich: bool,
    filter: DisplayFilter,
    splash_lines: Vec<String>,
    save: Option<PathBuf>,
    replay_source: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // One channel: the source (background thread) produces via decode::out,
    // the TUI (this thread) consumes. Bounded so a stalled UI sheds records
    // rather than growing memory without limit (see decode::channel).
    let (tx, rx) = decode::channel();
    decode::set_output(tx);

    // Validate/create the save destination before starting a live source.
    let recorder = save.map(SessionWriter::create).transpose()?;

    // Shared slot the source thread writes a fatal error into, so the TUI can
    // surface it (instead of "waiting for traffic…" forever) and exit non-zero.
    let source_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slot = source_error.clone();
    // The source runs until the process exits; no graceful shutdown here. Its
    // body is caught so a panic in the capture/decode path becomes a visible
    // status line rather than firing ratatui's restore hook on this background
    // thread while the main thread keeps drawing.
    let _source_thread = std::thread::Builder::new()
        .name("tapgres-source".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(source));
            let error = match outcome {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e),
                Err(_) => Some("capture/decode thread panicked".to_string()),
            };
            if let Some(e) = error {
                *slot.lock().unwrap() = Some(e.clone());
                decode::status(format!("⚠ {e}"));
            }
        })?;
    let _rate_sampler = metrics.spawn_rate_sampler()?;

    let mut app = App::new(rx, mode, metrics, rich, filter, splash_lines);
    app.recorder = recorder;
    app.source_error = source_error;
    app.replay_source = replay_source;
    let mut terminal = ratatui::try_init()?;
    let result = app_loop(&mut terminal, app);
    // Restore the terminal even on error. try_init installs a panic hook that
    // also restores, so panics are covered too.
    let _ = ratatui::try_restore();
    result.map_err(Into::into)
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
    /// Complete retained history; filtering never removes entries from here.
    events: Vec<Output>,
    /// Indices into `events` that match the current display filter.
    visible: Vec<usize>,
    /// Index into `visible` of the topmost shown row (the scroll anchor).
    scroll: usize,
    /// Auto-tail new output.
    follow: bool,
    /// Wrap long lines to the viewport width.
    wrap: bool,
    /// Rich display mode: draw `DataRow` as a per-message key/value table and
    /// `RowDescription` as a typed column list, instead of the flat line. Type
    /// names are shown with an icon-font (Nerd Font) glyph.
    rich: bool,
    mode: String,
    metrics: Arc<Metrics>,
    /// All-time peak messages/sec seen this session, per direction. Used as a
    /// fixed sparkline scale so bars don't rescale as the rate window slides;
    /// the value only ever grows.
    peak_msgs_in: u64,
    peak_msgs_out: u64,
    filter: DisplayFilter,
    filter_text: String,
    filter_error: Option<String>,
    filter_editing: bool,
    /// Applied filter text captured when the editor opens, so Esc can cancel an
    /// in-progress edit and restore it instead of wiping the filter.
    filter_snapshot: String,
    /// Incremental text search over the message view (`/`). Non-empty while a
    /// search is active; `n`/`N` jump between matches and matches are highlighted.
    search_editing: bool,
    search_text: String,
    command_editing: bool,
    command_text: String,
    command_notice: Option<(String, bool)>,
    /// Recent status/warning lines, surfaced on the startup splash so a fatal
    /// source error (e.g. missing capture privileges) is visible immediately.
    status_tail: Vec<String>,
    /// Set by the source thread on a fatal failure; drives a non-zero exit and
    /// leaves the splash so the error is shown.
    source_error: Arc<Mutex<Option<String>>>,
    /// Path of the file being replayed, if any, so `:save` refuses to overwrite
    /// the input the source thread is still reading.
    replay_source: Option<PathBuf>,
    /// False after `:open`: the loaded replay replaces the live view for the
    /// rest of this TUI session, while the source channel is drained safely.
    accept_source_records: bool,
    /// Number of events removed by the bounded TUI history before `:save`.
    dropped_events: usize,
    /// Mode-specific connection/capture info lines for the startup splash.
    splash_lines: Vec<String>,
    /// Whether the startup splash is still showing. Flips off once a real
    /// connection is detected (see `app_loop`).
    show_splash: bool,
    /// Optional continuous JSONL recorder. It receives records before the TUI
    /// history cap or display filter can hide them.
    recorder: Option<SessionWriter>,
}

impl App {
    fn new(
        rx: Receiver<Output>,
        mode: &'static str,
        metrics: Arc<Metrics>,
        rich: bool,
        filter: DisplayFilter,
        splash_lines: Vec<String>,
    ) -> Self {
        let filter_text = filter.expression().to_string();
        // No splash content (e.g. unit tests) means no splash screen.
        let show_splash = !splash_lines.is_empty();
        Self {
            rx,
            events: Vec::new(),
            visible: Vec::new(),
            scroll: 0,
            follow: true,
            wrap: false,
            rich,
            mode: mode.to_string(),
            metrics,
            peak_msgs_in: 0,
            peak_msgs_out: 0,
            filter,
            filter_text,
            filter_error: None,
            filter_editing: false,
            filter_snapshot: String::new(),
            search_editing: false,
            search_text: String::new(),
            command_editing: false,
            command_text: String::new(),
            command_notice: None,
            status_tail: Vec::new(),
            source_error: Arc::new(Mutex::new(None)),
            replay_source: None,
            accept_source_records: true,
            dropped_events: 0,
            splash_lines,
            show_splash,
            recorder: None,
        }
    }

    fn matches(&self, output: &Output) -> bool {
        output.matches_filter(&self.filter)
    }

    fn push_output(&mut self, output: Output) {
        let write_error = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.write(&output).err());
        if let Some(error) = write_error {
            self.recorder = None;
            self.command_notice = Some((format!("recording stopped: {error}"), true));
        }
        // Keep the tail of status/warning lines so the splash can show them.
        if let Output::Status(line) = &output {
            self.status_tail.push(line.clone());
            let len = self.status_tail.len();
            if len > STATUS_TAIL_CAP {
                self.status_tail.drain(..len - STATUS_TAIL_CAP);
            }
        }
        let index = self.events.len();
        if self.matches(&output) {
            self.visible.push(index);
        }
        self.events.push(output);
        if self.events.len() >= HISTORY_CAP + HISTORY_TRIM_CHUNK {
            self.trim_history();
        }
    }

    /// Evict the oldest events back down to the cap. Rebases the visible indices
    /// and the scroll anchor onto the shifted buffer instead of rebuilding from
    /// scratch, so scrollback doesn't jump to the top at steady state (and no
    /// O(n) re-filter runs on every trim).
    fn trim_history(&mut self) {
        if self.events.len() <= HISTORY_CAP {
            return;
        }
        let drop_n = self.events.len() - HISTORY_CAP;
        self.events.drain(..drop_n);
        self.dropped_events = self.dropped_events.saturating_add(drop_n);
        // `visible` is ascending, so evicted entries are a prefix.
        let removed_visible = self.visible.iter().take_while(|&&i| i < drop_n).count();
        self.visible.retain(|&i| i >= drop_n);
        for index in &mut self.visible {
            *index -= drop_n;
        }
        self.scroll = self.scroll.saturating_sub(removed_visible);
    }

    fn rebuild_visible(&mut self) {
        self.visible = self
            .events
            .iter()
            .enumerate()
            .filter_map(|(index, output)| self.matches(output).then_some(index))
            .collect();
        self.scroll = 0;
    }

    fn update_filter(&mut self) {
        if self.filter_text.trim().is_empty() {
            self.filter = DisplayFilter::default();
            self.filter_error = None;
            self.rebuild_visible();
            return;
        }
        match DisplayFilter::parse(&self.filter_text) {
            Ok(filter) => {
                self.filter = filter;
                self.filter_error = None;
                self.rebuild_visible();
            }
            Err(error) => self.filter_error = Some(error.to_string()),
        }
    }

    fn clear_filter(&mut self) {
        self.filter_text.clear();
        self.filter = DisplayFilter::default();
        self.filter_error = None;
        self.rebuild_visible();
    }

    /// Parse the in-progress filter text for error feedback only, without
    /// re-running it over the whole history — that (expensive) reapplication
    /// happens on Enter via [`App::update_filter`]. Keeps the editor responsive
    /// on a full buffer.
    fn parse_filter_preview(&mut self) {
        self.filter_error = if self.filter_text.trim().is_empty() {
            None
        } else {
            DisplayFilter::parse(&self.filter_text)
                .err()
                .map(|error| error.to_string())
        };
    }

    /// Positions into `visible` whose rendered text contains the search term
    /// (case-insensitive). Empty when no search is active.
    fn search_matches(&self) -> Vec<usize> {
        if self.search_text.is_empty() {
            return Vec::new();
        }
        let needle = self.search_text.to_lowercase();
        self.visible
            .iter()
            .enumerate()
            .filter(|(_, event_index)| {
                self.events[**event_index]
                    .rendered()
                    .to_lowercase()
                    .contains(&needle)
            })
            .map(|(position, _)| position)
            .collect()
    }

    /// Jump to the next (`forward`) or previous match relative to the current
    /// scroll anchor, wrapping around. `include_current` lets the initial jump
    /// land on a match already at the anchor.
    fn jump_to_match(&mut self, forward: bool, include_current: bool) {
        let matches = self.search_matches();
        let Some(&first) = matches.first() else {
            return;
        };
        self.follow = false;
        let anchor = self.scroll;
        let target = if forward {
            matches
                .iter()
                .copied()
                .find(|&p| {
                    if include_current {
                        p >= anchor
                    } else {
                        p > anchor
                    }
                })
                .unwrap_or(first)
        } else {
            matches
                .iter()
                .rev()
                .copied()
                .find(|&p| p < anchor)
                .unwrap_or_else(|| *matches.last().unwrap())
        };
        self.scroll = target;
    }

    fn execute_command(&mut self) {
        let command_text = self.command_text.clone();
        let input = command_text.trim().trim_start_matches([':', '/']).trim();
        let (name, argument) = input
            .split_once(char::is_whitespace)
            .map(|(name, argument)| (name, argument.trim()))
            .unwrap_or((input, ""));

        let result = match name {
            "w" | "write" | "save" => self.start_recording(argument),
            "o" | "open" => self.open_session(argument),
            "" => Err("command is empty".to_string()),
            _ => Err(format!("unknown command: {name}")),
        };
        self.command_notice = Some(match result {
            Ok(message) => (message, false),
            Err(message) => (message, true),
        });
        self.command_editing = false;
    }

    fn start_recording(&mut self, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err("usage: :save FILE".into());
        }
        let path = expand_tilde(argument);
        // Never truncate the file the replay source thread is still reading.
        if let Some(source) = &self.replay_source {
            if same_path(source, &path) {
                return Err("refusing to overwrite the replayed input file".into());
            }
        }
        let mut recorder = SessionWriter::create(&path).map_err(|error| error.to_string())?;
        for output in &self.events {
            recorder.write(output).map_err(|error| error.to_string())?;
        }
        recorder.flush().map_err(|error| error.to_string())?;
        let retained = self.events.len();
        self.recorder = Some(recorder);
        let action = if self.accept_source_records {
            format!("recording {retained} retained events + future traffic")
        } else {
            format!("saved {retained} retained replay events")
        };
        if self.dropped_events == 0 {
            Ok(format!("{action} to {}", path.display()))
        } else {
            Ok(format!(
                "{action} to {}; {} earlier events were outside history",
                path.display(),
                self.dropped_events
            ))
        }
    }

    fn open_session(&mut self, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err("usage: :open FILE".into());
        }
        let path = expand_tilde(argument);
        // Flush the active recorder before reading so a concurrent `:save` to the
        // same file is on disk, not truncated out from under this read. Keep it
        // until the read succeeds so a failed `:open` doesn't stop recording.
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.flush().map_err(|error| error.to_string())?;
        }
        let (outputs, dropped) =
            session::read_tail(&path, HISTORY_CAP).map_err(|error| error.to_string())?;
        let count = outputs.len();
        // Switching to replay: stop recording live traffic.
        self.recorder = None;
        self.events = outputs;
        self.visible.clear();
        self.rebuild_visible();
        self.follow = true;
        self.mode = "replay".into();
        self.metrics = Arc::new(Metrics::new());
        self.peak_msgs_in = 0;
        self.peak_msgs_out = 0;
        self.show_splash = false;
        self.accept_source_records = false;
        self.dropped_events = dropped;
        if dropped == 0 {
            Ok(format!("opened {count} events from {}", path.display()))
        } else {
            Ok(format!(
                "opened newest {count} events from {}; {dropped} earlier events are outside history",
                path.display()
            ))
        }
    }

    /// Leave the splash once a real connection has been detected, or a fatal
    /// source error has arrived (so it isn't hidden behind "waiting for
    /// traffic…"). Startup status lines arrive before any traffic but do not
    /// open a connection, so they alone do not trigger this transition.
    fn leave_splash_if_traffic(&mut self, conns_opened: u64) {
        if self.show_splash && (conns_opened > 0 || self.source_failed()) {
            self.show_splash = false;
        }
    }

    /// Whether the source thread reported a fatal error.
    fn source_failed(&self) -> bool {
        self.source_error.lock().unwrap().is_some()
    }
}

/// Expand a leading `~/` (or bare `~`) to the user's home directory so `:save`
/// / `:open` accept the paths users naturally type.
fn expand_tilde(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    } else if input == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(input)
}

/// Whether two paths point at the same file, tolerant of one not yet existing
/// (compares canonicalized parents so a not-yet-created `:save` target is still
/// caught against the replay input).
fn same_path(a: &Path, b: &Path) -> bool {
    fn resolve(p: &Path) -> Option<PathBuf> {
        if let Ok(canonical) = std::fs::canonicalize(p) {
            return Some(canonical);
        }
        let parent = p.parent().filter(|parent| !parent.as_os_str().is_empty());
        let name = p.file_name()?;
        Some(
            std::fs::canonicalize(parent.unwrap_or_else(|| Path::new(".")))
                .ok()?
                .join(name),
        )
    }
    match (resolve(a), resolve(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

fn app_loop(terminal: &mut ratatui::DefaultTerminal, mut app: App) -> io::Result<()> {
    loop {
        while let Ok(record) = app.rx.try_recv() {
            if app.accept_source_records {
                app.push_output(record);
            }
        }
        // One metrics snapshot per frame, shared by the splash transition, the
        // peak-tracking below, and the header render — instead of three clones.
        let summary = app.metrics.summary();
        // Leave the splash once a real connection is detected (or the source
        // failed). Startup status lines arrive before any traffic but do not
        // open a connection, so they don't trigger this transition.
        app.leave_splash_if_traffic(summary.conns_opened);
        // History trimming happens in push_output as records arrive; no need to
        // re-trim (and re-filter) every frame here.

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
            app.visible.len().saturating_sub(1)
        } else {
            app.visible.len().saturating_sub(log_h)
        };
        if app.follow {
            app.scroll = max_scroll;
        }
        app.scroll = app.scroll.min(max_scroll);

        // Fixed sparkline scale: track the all-time peak messages/sec per
        // direction so the bars keep a stable scale instead of rescaling to
        // the current window's max as samples expire or arrive.
        app.peak_msgs_in = app
            .peak_msgs_in
            .max(summary.rates.iter().map(|r| r.msgs_in).max().unwrap_or(0));
        app.peak_msgs_out = app
            .peak_msgs_out
            .max(summary.rates.iter().map(|r| r.msgs_out).max().unwrap_or(0));

        terminal.draw(|frame| {
            if app.show_splash {
                draw_splash(frame, &app);
                if app.command_editing {
                    let [_, command_area] =
                        Layout::vertical([Constraint::Fill(1), Constraint::Length(3)])
                            .areas(frame.area());
                    draw_command_bar(frame, &app, command_area);
                }
            } else {
                draw(frame, &app, log_h, &summary);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            // Drain all currently-ready events without blocking on read().
            loop {
                match event::read()? {
                    Event::Key(key)
                        if key.kind == KeyEventKind::Press && handle_key(&mut app, log_h, key) =>
                    {
                        // Propagate a fatal source error as a non-zero exit, so
                        // `--tui` matches the documented exit status of the
                        // line-oriented path.
                        return match app.source_error.lock().unwrap().take() {
                            Some(e) => Err(io::Error::other(e)),
                            None => Ok(()),
                        };
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
    // Ctrl-C quits — but while editing an input it cancels that input instead of
    // killing the whole app (handled inside each editing branch below).
    let editing = app.command_editing || app.filter_editing || app.search_editing;
    if key.code == KeyCode::Char('c') && ctrl && !editing {
        return true;
    }
    if app.command_editing {
        match key.code {
            KeyCode::Esc => {
                app.command_editing = false;
                app.command_text.clear();
            }
            KeyCode::Char('c') if ctrl => {
                app.command_editing = false;
                app.command_text.clear();
            }
            KeyCode::Enter => app.execute_command(),
            KeyCode::Backspace => {
                app.command_text.pop();
            }
            KeyCode::Char(ch) if !ctrl => app.command_text.push(ch),
            _ => {}
        }
        return false;
    }
    if app.search_editing {
        match key.code {
            // Cancel the search entirely (Esc or Ctrl-C).
            KeyCode::Esc => {
                app.search_editing = false;
                app.search_text.clear();
            }
            KeyCode::Char('c') if ctrl => {
                app.search_editing = false;
                app.search_text.clear();
            }
            KeyCode::Enter => {
                app.search_editing = false;
                app.jump_to_match(true, true);
            }
            KeyCode::Backspace => {
                app.search_text.pop();
            }
            KeyCode::Char(ch) if !ctrl => app.search_text.push(ch),
            _ => {}
        }
        return false;
    }
    // Keep the command bar available before the first connection so a saved
    // session can be opened directly from the startup splash.
    if app.show_splash {
        return match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Char('/') | KeyCode::Char(':') => {
                app.command_editing = true;
                app.command_text.clear();
                app.command_notice = None;
                false
            }
            _ => false,
        };
    }
    if app.filter_editing {
        match key.code {
            // Cancel the edit and restore the filter that was applied when the
            // editor opened, rather than wiping it.
            KeyCode::Esc => {
                app.filter_text = std::mem::take(&mut app.filter_snapshot);
                app.filter_error = None;
                app.filter_editing = false;
            }
            KeyCode::Char('c') if ctrl => {
                app.filter_text = std::mem::take(&mut app.filter_snapshot);
                app.filter_error = None;
                app.filter_editing = false;
            }
            // Apply on Enter (the expensive reapplication), not per keystroke.
            KeyCode::Enter if app.filter_error.is_none() => {
                app.update_filter();
                app.filter_editing = false;
            }
            KeyCode::Backspace => {
                app.filter_text.pop();
                app.parse_filter_preview();
            }
            KeyCode::Char(ch) if !ctrl => {
                app.filter_text.push(ch);
                app.parse_filter_preview();
            }
            _ => {}
        }
        return false;
    }
    // A key in normal mode dismisses a lingering command notice so the footer
    // key hints return.
    app.command_notice = None;
    match key.code {
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
        KeyCode::Char('n') => app.jump_to_match(true, false),
        KeyCode::Char('N') => app.jump_to_match(false, false),
        KeyCode::Char('c') => {
            // Cleared events can no longer be saved; count them so `:save`'s
            // omission note stays accurate.
            app.dropped_events = app.dropped_events.saturating_add(app.events.len());
            app.events.clear();
            app.visible.clear();
            app.scroll = 0;
        }
        KeyCode::Char('y') => {
            app.filter_snapshot = app.filter_text.clone();
            app.filter_editing = true;
        }
        KeyCode::Char('/') => {
            app.search_editing = true;
            app.search_text.clear();
        }
        KeyCode::Char(':') => {
            app.command_editing = true;
            app.command_text.clear();
            app.command_notice = None;
        }
        // Esc clears an active search first, then the display filter.
        KeyCode::Esc if !app.search_text.is_empty() => app.search_text.clear(),
        KeyCode::Esc if !app.filter.is_empty() => app.clear_filter(),
        _ => {}
    }
    false
}

/// Startup splash: the banner plus mode-specific connection/capture info,
/// shown until the first real connection is detected. Centred on screen.
fn draw_splash(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let banner = Style::default().fg(Color::Cyan);
    let dim = Style::default().fg(Color::DarkGray);

    let mut lines: Vec<Line> = Vec::new();
    for art in BANNER.lines() {
        lines.push(if art.is_empty() {
            Line::raw("")
        } else {
            Line::styled(art.to_string(), banner)
        });
    }
    lines.push(Line::raw(""));
    for line in &app.splash_lines {
        lines.push(Line::raw(format!("  {line}")));
    }
    // Surface recent status/warning lines so a fatal source error (e.g. missing
    // capture privileges) is visible instead of an endless "waiting…".
    if !app.status_tail.is_empty() {
        lines.push(Line::raw(""));
        for status in &app.status_tail {
            let style = if status.contains('⚠') {
                Style::default().fg(Color::Red)
            } else {
                dim
            };
            lines.push(Line::styled(format!("  {status}"), style));
        }
    }
    if let Some((notice, is_error)) = &app.command_notice {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("  {notice}"),
            Style::default().fg(if *is_error { Color::Red } else { Color::Green }),
        ));
    }
    lines.push(Line::raw(""));
    let waiting = if app.source_failed() {
        "  source failed — see above · press q to quit"
    } else {
        "  waiting for traffic…  press : for commands · q to quit"
    };
    lines.push(Line::styled(waiting, dim));

    // Vertically centre the splash block; horizontally centre each line.
    let height = lines.len() as u16;
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(Text::from(lines)).alignment(Alignment::Center),
        mid,
    );
}

fn draw(frame: &mut Frame, app: &App, log_h: usize, metrics: &MetricsSummary) {
    let [title_area, log_area, foot_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .areas(frame.area());

    // --- title bar: rich metrics header ---
    let heading = if app.filter.is_empty() {
        format!(
            " tapgres — {} mode · {} events ",
            app.mode,
            app.events.len()
        )
    } else {
        format!(
            " tapgres — {} mode · {}/{} matching ",
            app.mode,
            app.visible.len(),
            app.events.len()
        )
    };
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
    let filter_title = if app.filter_text.is_empty() {
        " messages ".to_string()
    } else {
        format!(" messages · display filter: {} ", app.filter_text)
    };
    let filter_color = if app.filter_error.is_some() {
        Color::Red
    } else if !app.filter.is_empty() {
        Color::Yellow
    } else {
        Color::Green
    };
    let log_block = Block::bordered()
        .title_top(Line::raw(filter_title))
        .border_style(Style::default().fg(filter_color));
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
        view_window(
            &app.events,
            &app.visible,
            app.scroll,
            app.follow,
            log_h,
            inner_w,
            view,
        )
    } else {
        let s = app.scroll;
        (s, (s + log_h).min(app.visible.len()))
    };
    let needle = app.search_text.to_lowercase();
    let mut lines: Vec<Line> = Vec::new();
    for &event_index in &app.visible[start..end] {
        let mut event_lines = event_lines(&app.events[event_index], view);
        // Highlight lines of events matching the active search.
        if !needle.is_empty()
            && app.events[event_index]
                .rendered()
                .to_lowercase()
                .contains(&needle)
        {
            for line in &mut event_lines {
                line.style = line.style.bg(Color::Rgb(80, 70, 0));
            }
        }
        lines.extend(event_lines);
    }
    let mut para = Paragraph::new(Text::from(lines)).block(log_block);
    if app.wrap {
        para = para.wrap(Wrap { trim: false });
    }
    frame.render_widget(para, log_area);

    // --- footer: follow/wrap/rich state shown by colour (green = on) ---
    let on = Style::default().fg(Color::Green);
    let off = Style::default();
    if app.command_editing {
        draw_command_bar(frame, app, foot_area);
    } else if app.search_editing {
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                format!(" search › {}█", app.search_text),
                Style::default().fg(Color::Yellow),
            )]))
            .block(Block::bordered().title_top(" search · Enter next · Esc cancel ")),
            foot_area,
        );
    } else if app.filter_editing {
        let style = if app.filter_error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Yellow)
        };
        let detail = app
            .filter_error
            .as_deref()
            .map(|error| format!("  ⚠ {error}"))
            .unwrap_or_default();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" display filter › {}█", app.filter_text), style),
                Span::styled(detail, Style::default().fg(Color::Red)),
            ]))
            .block(Block::bordered().title_top(" display filter · Enter apply · Esc cancel ")),
            foot_area,
        );
    } else if !app.search_text.is_empty() {
        // An active search: show the term and match count with n/N hint.
        let count = app.search_matches().len();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!(" search: {} ", app.search_text),
                    Style::default().fg(Color::Yellow).bold(),
                ),
                Span::raw(format!("· {count} matches · n/N next/prev · Esc clear")),
            ]))
            .block(Block::bordered()),
            foot_area,
        );
    } else if let Some((notice, is_error)) = &app.command_notice {
        frame.render_widget(
            Paragraph::new(Line::styled(
                format!(" {notice}"),
                Style::default().fg(if *is_error { Color::Red } else { Color::Green }),
            ))
            .block(Block::bordered().title_top(" status · : command ")),
            foot_area,
        );
    } else {
        let footer = vec![
            Span::raw(" q quit · j/k ↑↓ · PgUp/PgDn · g/G top/bottom · f "),
            Span::styled("follow", if app.follow { on } else { off }),
            Span::raw(" · w "),
            Span::styled("wrap", if app.wrap { on } else { off }),
            Span::raw(" · r "),
            Span::styled("rich", if app.rich { on } else { off }),
            Span::raw(" · y "),
            Span::styled(
                "display filter",
                if app.filter.is_empty() { off } else { on },
            ),
            Span::raw(" · / search · : command · c clear "),
        ];
        frame.render_widget(
            Paragraph::new(Line::from(footer)).block(Block::bordered()),
            foot_area,
        );
    }
}

fn draw_command_bar(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" :", Style::default().fg(Color::Cyan).bold()),
            Span::raw(&app.command_text),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]))
        .block(Block::bordered().title_top(" command · :save FILE · :open FILE · Esc cancel ")),
        area,
    );
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
    events: &[Output],
    visible: &[usize],
    scroll: usize,
    follow: bool,
    log_h: usize,
    width: usize,
    view: View,
) -> (usize, usize) {
    let n = visible.len();
    if n == 0 {
        return (0, 0);
    }
    let mut rows = 0usize;
    if follow {
        let mut start = n;
        for (i, &event_index) in visible.iter().enumerate().rev() {
            let h = event_height(&events[event_index], width, view);
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
        // Forward-fill from the anchor.
        let mut end = scroll;
        for (i, &event_index) in visible.iter().enumerate().skip(scroll) {
            let h = event_height(&events[event_index], width, view);
            if rows != 0 && rows + h > log_h {
                break;
            }
            rows += h;
            end = i + 1;
            if rows >= log_h {
                break;
            }
        }
        // If the forward fill hit the end without filling the viewport, back-fill
        // so the window stays full. Without this, leaving follow near the bottom
        // (a single tall rich/wrapped item as the anchor) collapses the view to a
        // couple of rows with blank space below.
        let mut start = scroll;
        if end == n && rows < log_h {
            for (i, &event_index) in visible.iter().take(scroll).enumerate().rev() {
                let h = event_height(&events[event_index], width, view);
                if rows + h > log_h {
                    break;
                }
                rows += h;
                start = i;
            }
        }
        (start, end)
    }
}

/// Display rows an event occupies: the flat line view is one row (or its
/// wrapped height in wrap mode); a rich `DataRow`/`RowDescription` is one
/// header row plus one row per column. In wrap mode any of those lines may
/// further reflow, so defer to ratatui's `Paragraph::line_count`.
fn event_height(evt: &Output, width: usize, view: View) -> usize {
    if view.wrap {
        return Paragraph::new(Text::from(event_lines(evt, view)))
            .wrap(Wrap { trim: false })
            .line_count(width as u16)
            .max(1);
    }
    if view.rich {
        match evt.detail() {
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
fn event_lines(evt: &Output, view: View) -> Vec<Line<'_>> {
    if view.rich {
        if let Some(detail) = evt.detail() {
            return render_rich(evt.rendered(), detail);
        }
    }
    vec![build_line(evt.rendered())]
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
        16 => ('\u{f00c}', Color::Green),                // bool -> check
        20 | 21 | 23 => ('\u{f292}', Color::Yellow),     // int8/int2/int4 -> hashtag
        700 | 701 | 1700 => ('\u{f1ec}', Color::Yellow), // float4/float8/numeric -> calculator
        18 | 19 | 25 | 1042 | 1043 => ('\u{f031}', Color::Cyan), // char/name/text/bpchar/varchar -> font
        114 | 3802 => ('\u{f121}', Color::Magenta),              // json/jsonb -> code
        2950 => ('\u{f577}', Color::Magenta),                    // uuid -> fingerprint
        17 => ('\u{f1c0}', Color::Green),                        // bytea -> database
        1082 => ('\u{f073}', Color::Cyan),                       // date -> calendar
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
        Span::raw(&line[p.kind_start..p.kind_end])
            .fg(p.color)
            .bold(),
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
        Span::raw(&line[p.kind_start..p.kind_end])
            .fg(p.color)
            .bold(),
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
    use crate::filter::{DisplayMessage, MessageDirection};

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
        View { rich, wrap: false }
    }

    fn message_with_detail(
        kind: &str,
        text: &str,
        port: u16,
        detail: Option<EventDetail>,
    ) -> Output {
        Output::Message {
            message: DisplayMessage {
                timestamp: "2026-07-17T12:34:56.789+01:00".into(),
                rendered: format!("[{kind}] {text}"),
                client: format!("127.0.0.1:{port}").parse().unwrap(),
                direction: MessageDirection::FrontendToBackend,
                kind: kind.into(),
                text: text.into(),
            },
            detail,
        }
    }

    fn message(kind: &str, text: &str, port: u16) -> Output {
        message_with_detail(kind, text, port, None)
    }

    fn app() -> App {
        let (_tx, rx) = crossbeam_channel::unbounded();
        App::new(
            rx,
            "test",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::default(),
            Vec::new(),
        )
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
        let entry = message_with_detail("DataRow", "x", 40005, Some(data_row_detail(3)));
        // 1 header row + 3 columns, non-wrap rich mode.
        assert_eq!(event_height(&entry, 80, view(true)), 4);
    }

    #[test]
    fn event_height_plain_line_is_one_row() {
        let entry = message("Query", "x", 40005);
        assert_eq!(event_height(&entry, 80, view(false)), 1);
        // Rich mode with no structured detail still renders the flat line.
        assert_eq!(event_height(&entry, 80, view(true)), 1);
    }

    #[test]
    fn view_window_does_not_clip_multirow_items() {
        // Two rich DataRows, 3 columns each -> 4 rows each. A 5-row viewport in
        // follow mode must show only the last item fully (4 rows) rather than
        // start the first and clip it mid-table.
        let events: Vec<Output> = (0..2)
            .map(|_| message_with_detail("DataRow", "x", 40005, Some(data_row_detail(3))))
            .collect();
        let visible = vec![0, 1];
        let (start, end) = view_window(&events, &visible, 0, true, 5, 80, view(true));
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
        let header: String = rendered[0]
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(header.contains("DataRow"), "header: {header}");
        assert!(
            !header.contains("alice"),
            "header must not repeat row content: {header}"
        );
        let body: String = rendered[1]
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            body.contains("alice"),
            "body should carry the value: {body}"
        );
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
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            body.contains('\u{f292}'),
            "int4 glyph should render: {body:?}"
        );
        assert!(body.contains("int4"), "type name should render: {body:?}");
    }

    #[test]
    fn changing_filter_reapplies_to_retained_events() {
        let mut app = app();
        app.push_output(message("Query", "SELECT * FROM orders", 40005));
        app.push_output(message("DataRow", "{ id=1 }", 40005));
        app.push_output(message("Query", "SELECT * FROM users", 40006));
        app.push_output(Output::Status("capture active".into()));
        assert_eq!(app.events.len(), 4);
        assert_eq!(app.visible, vec![0, 1, 2, 3]);

        app.filter_text = "client.port == 40005 and message.type == \"Query\" and message.text contains \"orders\"".into();
        app.update_filter();
        assert_eq!(app.events.len(), 4);
        assert_eq!(app.visible, vec![0, 3]);

        app.clear_filter();
        assert_eq!(app.events.len(), 4);
        assert_eq!(app.visible, vec![0, 1, 2, 3]);
    }

    #[test]
    fn filtering_preserves_rich_message_detail() {
        let mut app = app();
        app.push_output(message_with_detail(
            "DataRow",
            "{ id=1 }",
            40005,
            Some(data_row_detail(3)),
        ));

        app.filter_text = "message.type == \"DataRow\"".into();
        app.update_filter();

        assert_eq!(app.visible, vec![0]);
        assert_eq!(event_height(&app.events[0], 80, view(true)), 4);
    }

    #[test]
    fn invalid_live_edit_preserves_last_valid_filter() {
        let mut app = app();
        app.push_output(message("Query", "SELECT 1", 40005));
        app.push_output(message("DataRow", "{ id=1 }", 40005));

        app.filter_text = "message.type == \"Query\"".into();
        app.update_filter();
        assert_eq!(app.visible, vec![0]);

        app.filter_text = "message.type == \"Query\" and unknown == \"value\"".into();
        app.update_filter();
        assert!(app.filter_error.is_some());
        assert_eq!(app.visible, vec![0]);
        assert_eq!(app.filter.expression(), "message.type == \"Query\"");
    }

    #[test]
    fn y_opens_editor_and_escape_cancels_edit_restoring_filter() {
        let (_tx, rx) = crossbeam_channel::unbounded();
        let mut app = App::new(
            rx,
            "test",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::parse("message.type == \"Query\"").unwrap(),
            Vec::new(),
        );
        app.push_output(message("Query", "SELECT 1", 40005));
        app.push_output(message("DataRow", "{ id=1 }", 40005));
        assert_eq!(app.visible, vec![0]);

        // Open the editor, type a partial edit, then Esc: the edit is abandoned
        // and the previously-applied filter is restored (not wiped).
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
        );
        assert!(app.filter_editing);
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        );
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );

        assert!(!app.filter_editing);
        assert!(
            !app.filter.is_empty(),
            "Esc must not wipe the applied filter"
        );
        assert_eq!(app.filter_text, "message.type == \"Query\"");
        assert_eq!(app.visible, vec![0]);

        // A second Esc in normal mode clears the applied filter (documented).
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(app.filter.is_empty());
        assert_eq!(app.visible, vec![0, 1]);
    }

    #[test]
    fn filter_applies_on_enter_not_per_keystroke() {
        let mut app = app();
        app.push_output(message("Query", "SELECT 1", 40005));
        app.push_output(message("DataRow", "{ id=1 }", 40005));

        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
        );
        for ch in "message.type == \"Query\"".chars() {
            handle_key(
                &mut app,
                10,
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            );
        }
        // Still unapplied while typing (both events visible).
        assert_eq!(app.visible, vec![0, 1]);
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert!(!app.filter_editing);
        assert_eq!(app.visible, vec![0]);
    }

    #[test]
    fn clear_counts_dropped_and_resets_scroll() {
        let mut app = app();
        app.push_output(message("Query", "SELECT 1", 40005));
        app.push_output(message("Query", "SELECT 2", 40005));
        app.scroll = 1;
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
        );
        assert!(app.events.is_empty());
        assert_eq!(app.scroll, 0);
        assert_eq!(
            app.dropped_events, 2,
            "cleared events are counted as dropped"
        );
    }

    #[test]
    fn trim_history_preserves_scroll_position() {
        let mut app = app();
        for i in 0..(HISTORY_CAP + HISTORY_TRIM_CHUNK) {
            app.push_output(message("Query", &format!("q{i}"), 40005));
        }
        // Sitting partway up the (now trimmed) buffer, not at the top.
        app.follow = false;
        app.scroll = 100;
        let before = app.scroll;
        app.push_output(message("Query", "trigger-trim", 40005));
        app.trim_history();
        // Scroll shifted with the evicted prefix, not reset to 0.
        assert!(
            app.scroll < before && app.scroll > 0,
            "scroll: {}",
            app.scroll
        );
    }

    #[test]
    fn colon_opens_command_bar_and_slash_opens_search() {
        let (_tx, rx) = crossbeam_channel::unbounded();
        let mut app = App::new(
            rx,
            "test",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::default(),
            Vec::new(),
        );

        // ':' opens the command bar (not the display filter editor).
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE),
        );
        assert!(!app.filter_editing);
        assert!(app.command_editing);
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );

        // '/' opens text search, not the command bar.
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        );
        assert!(app.search_editing);
        assert!(!app.command_editing);
    }

    #[test]
    fn search_jumps_to_and_navigates_matches() {
        let mut app = app();
        app.push_output(message("Query", "SELECT * FROM users", 40005)); // 0
        app.push_output(message("Query", "SELECT * FROM orders", 40005)); // 1
        app.push_output(message("Query", "SELECT * FROM users2", 40005)); // 2
        app.follow = false;
        app.scroll = 0;

        // '/' opens search; type "orders" and Enter: jump to the match at pos 1.
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        );
        assert!(app.search_editing);
        for ch in "orders".chars() {
            handle_key(
                &mut app,
                10,
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert!(!app.search_editing);
        assert_eq!(app.scroll, 1);

        // Search "users" -> matches positions 0 and 2; n/N cycle between them.
        app.search_text = "users".into();
        app.scroll = 0;
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_eq!(app.scroll, 2, "n goes to next match after anchor 0");
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_eq!(app.scroll, 0, "n wraps to the first match");
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('N'), KeyModifiers::NONE),
        );
        assert_eq!(app.scroll, 2, "N wraps back to the last match");

        // Esc clears the active search.
        handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(app.search_text.is_empty());
    }

    #[test]
    fn save_command_writes_retained_and_future_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saved session.jsonl");
        let mut app = app();
        app.push_output(message("Query", "SELECT 1", 40005));
        app.push_output(message("DataRow", "{ id=1 }", 40005));
        app.filter_text = "message.type == \"Query\"".into();
        app.update_filter();

        app.command_text = format!("save {}", path.display());
        app.execute_command();
        app.push_output(message("ReadyForQuery", "txn=idle", 40005));
        app.recorder.as_mut().unwrap().flush().unwrap();

        let saved = session::read_all(&path).unwrap();
        assert_eq!(saved.len(), 3, "display filtering must not affect saving");
        assert!(
            app.command_notice
                .as_ref()
                .is_some_and(|(message, error)| !error && message.contains("recording"))
        );
    }

    #[test]
    fn open_command_atomically_replaces_view_and_preserves_rich_detail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.jsonl");
        let replayed = message_with_detail("DataRow", "{ id=1 }", 40005, Some(data_row_detail(2)));
        let mut writer = SessionWriter::create(&path).unwrap();
        writer.write(&replayed).unwrap();
        writer.flush().unwrap();

        let mut app = app();
        app.push_output(message("Query", "old", 40005));
        app.command_text = format!("open {}", path.display());
        app.execute_command();

        assert_eq!(app.mode, "replay");
        assert!(!app.accept_source_records);
        assert_eq!(app.events.len(), 1);
        assert!(matches!(
            app.events[0].detail(),
            Some(EventDetail::DataRow(columns)) if columns.len() == 2
        ));
    }

    #[test]
    fn failed_open_keeps_the_existing_view() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.jsonl");
        std::fs::write(&path, "not json\n").unwrap();
        let mut app = app();
        app.push_output(message("Query", "SELECT 1", 40005));

        app.command_text = format!("open {}", path.display());
        app.execute_command();

        assert_eq!(app.mode, "test");
        assert!(app.accept_source_records);
        assert_eq!(app.events.len(), 1);
        assert!(
            app.command_notice
                .as_ref()
                .is_some_and(|(message, error)| *error && message.contains("invalid JSONL"))
        );
    }

    #[test]
    fn splash_shown_only_when_there_are_lines() {
        // No splash content (unit tests, plain helpers) -> never show splash.
        let (_tx, rx) = crossbeam_channel::unbounded();
        let app = App::new(
            rx,
            "test",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::default(),
            Vec::new(),
        );
        assert!(!app.show_splash);

        // Real splash content -> show until traffic arrives.
        let (_tx, rx) = crossbeam_channel::unbounded();
        let mut app = App::new(
            rx,
            "pcap",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::default(),
            vec!["capturing interface: lo".into()],
        );
        assert!(app.show_splash);
        // Startup status lines do not count as traffic.
        app.push_output(Output::Status("tapgres: capturing on 'lo'".into()));
        app.leave_splash_if_traffic(0);
        assert!(app.show_splash, "status lines must not leave the splash");
    }

    #[test]
    fn splash_leaves_once_a_connection_opens() {
        let metrics = Arc::new(Metrics::new());
        let (_tx, rx) = crossbeam_channel::unbounded();
        let mut app = App::new(
            rx,
            "pcap",
            metrics.clone(),
            false,
            DisplayFilter::default(),
            vec!["capturing interface: lo".into()],
        );
        assert!(app.show_splash);

        // A real connection is recorded on the metrics registry.
        metrics.open_connection(
            "127.0.0.1:40005".parse().unwrap(),
            "127.0.0.1:5432".parse().unwrap(),
            false,
        );
        let opened = app.metrics.summary().conns_opened;
        app.leave_splash_if_traffic(opened);
        assert!(
            !app.show_splash,
            "an opened connection must leave the splash"
        );
    }

    #[test]
    fn splash_honours_quit_and_command_bar() {
        let (_tx, rx) = crossbeam_channel::unbounded();
        let mut app = App::new(
            rx,
            "pcap",
            Arc::new(Metrics::new()),
            false,
            DisplayFilter::default(),
            vec!["capturing interface: lo".into()],
        );
        // `y` is a no-op on the splash: it must not open the filter editor.
        assert!(!handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
        ));
        assert!(!app.filter_editing);
        // Commands remain available so a replay can be opened before live
        // traffic arrives.
        assert!(!handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        ));
        assert!(app.command_editing);
        app.command_editing = false;
        // `q` quits even from the splash.
        assert!(handle_key(
            &mut app,
            10,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        ));
    }

    #[test]
    fn pcap_splash_shows_interface_and_port() {
        let lines = pcap_splash_lines(&PcapOpts {
            port: 5433,
            interface: Some("any".into()),
            no_promisc: false,
            snaplen: 65535,
        });
        let joined = lines.join("\n");
        assert!(joined.contains("any"), "named interface shown: {joined}");
        assert!(joined.contains("5433"), "port shown: {joined}");

        // Default interface is described as loopback.
        let lines = pcap_splash_lines(&PcapOpts {
            port: 5432,
            interface: None,
            no_promisc: false,
            snaplen: 65535,
        });
        let joined = lines.join("\n");
        assert!(
            joined.contains("loopback"),
            "default interface noted: {joined}"
        );
    }

    #[test]
    fn mitm_splash_shows_listen_upstream_and_tls() {
        let lines = mitm_splash_lines(&ProxyOpts {
            listen: "127.0.0.1:15432".into(),
            upstream: "127.0.0.1:5432".into(),
            tls_dir: std::path::PathBuf::from("/tmp/tapgres"),
            tls_cert: None,
            tls_key: None,
            no_upstream_tls: false,
        });
        let joined = lines.join("\n");
        assert!(joined.contains("127.0.0.1:15432"), "listen shown: {joined}");
        assert!(
            joined.contains("127.0.0.1:5432"),
            "upstream shown: {joined}"
        );
        assert!(joined.contains("auto CA"), "auto CA noted: {joined}");
        assert!(
            joined.contains("TLS auto-negotiate"),
            "upstream TLS noted: {joined}"
        );

        // A user-supplied cert and disabled upstream TLS are reflected.
        let lines = mitm_splash_lines(&ProxyOpts {
            listen: "127.0.0.1:15432".into(),
            upstream: "127.0.0.1:5432".into(),
            tls_dir: std::path::PathBuf::from("/tmp/tapgres"),
            tls_cert: Some(std::path::PathBuf::from("cert.pem")),
            tls_key: Some(std::path::PathBuf::from("key.pem")),
            no_upstream_tls: true,
        });
        let joined = lines.join("\n");
        assert!(
            joined.contains("user-supplied"),
            "user cert noted: {joined}"
        );
        assert!(
            joined.contains("cleartext"),
            "upstream cleartext noted: {joined}"
        );
    }
}
