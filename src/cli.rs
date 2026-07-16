//! Command-line interface.
//!
//! The `Args`/`Mode` definitions live here (rather than in the binary) so that
//! the binary, the tests, and the manpage generator
//! (`cargo run --example gen_manpage`) all share a single source of truth for
//! every option. `command()` returns the built [`clap::Command`] used to render
//! the manual page.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, ValueEnum};

use crate::filter::DisplayFilter;
use crate::state;

pub(crate) const BANNER: &str = "
████████╗ █████╗ ██████╗  ██████╗ ██████╗ ███████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ██╔══██╗██╔════╝██╔════╝
   ██║   ███████║██████╔╝██║  ███╗██████╔╝█████╗  ███████╗
   ██║   ██╔══██║██╔═══╝ ██║   ██║██╔══██╗██╔══╝  ╚════██║
   ██║   ██║  ██║██║     ╚██████╔╝██║  ██║███████╗███████║
   ╚═╝   ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
";

#[derive(Parser, Debug)]
#[command(
    name = "tapgres",
    version,
    about = "Tap a local PostgreSQL port and decode its wire traffic to stdout",
    before_help = BANNER
)]
pub struct Args {
    /// Traffic source.
    #[arg(long, value_enum, default_value_t = Mode::Pcap)]
    pub mode: Mode,

    /// Interactive TUI instead of line-oriented stdout (works with any --mode).
    #[arg(long, default_value_t = false)]
    pub tui: bool,

    /// [tui] Start with rich display mode on: per-message key/value tables for
    /// `DataRow` and typed column lists for `RowDescription`, instead of the
    /// flat line view. Toggle at runtime with `r`.
    #[arg(long, default_value_t = false)]
    pub tui_rich: bool,

    /// Display only decoded messages matching this expression.
    /// Example: message.type == "Query" and message.text contains "orders"
    #[arg(short = 'Y', long = "display-filter")]
    pub display_filter: Option<DisplayFilter>,

    /// Maximum retained open + recently-closed connection records.
    /// Open connections are never evicted.
    #[arg(long, default_value_t = state::DEFAULT_CONNECTION_CAP)]
    pub conn_history: usize,

    /// Number of one-second aggregate rate samples retained for the TUI.
    #[arg(long, default_value_t = state::DEFAULT_RATE_HISTORY)]
    pub rate_history: usize,

    // --- pcap mode ---------------------------------------------------------
    /// [pcap] PostgreSQL TCP port to monitor.
    #[arg(short, long, default_value_t = 5432)]
    pub port: u16,

    /// [pcap] Capture interface. Defaults to loopback; pass "any" for all.
    #[arg(short, long)]
    pub interface: Option<String>,

    /// [pcap] Do not put the interface in promiscuous mode.
    #[arg(long, default_value_t = false)]
    pub no_promisc: bool,

    /// [pcap] Maximum bytes captured per packet (snaplen).
    #[arg(long, default_value_t = 65535)]
    pub snaplen: i32,

    // --- mitm mode ---------------------------------------------------------
    /// [mitm] Address to listen on for client connections.
    #[arg(long, default_value = "127.0.0.1:15432")]
    pub listen: String,

    /// [mitm] Upstream PostgreSQL server to forward to.
    #[arg(long, default_value = "127.0.0.1:5432")]
    pub upstream: String,

    /// [mitm] Directory for the auto-generated CA + server cert.
    /// Defaults to `$XDG_CONFIG_HOME/tapgres` or `~/.config/tapgres`.
    #[arg(long)]
    pub tls_dir: Option<PathBuf>,

    /// [mitm] PEM server cert to present to clients (overrides auto-generation).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// [mitm] PEM private key for --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// [mitm] Disable TLS on the upstream leg (talk cleartext to the server).
    #[arg(long, default_value_t = false)]
    pub no_upstream_tls: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Mode {
    /// Passive libpcap capture (cleartext only).
    Pcap,
    /// Local TLS-terminating proxy.
    Mitm,
}

/// The built [`clap::Command`] for tapgres. Shared by the binary and the
/// manpage generator so every option is documented from one place.
pub fn command() -> clap::Command {
    Args::command()
}
