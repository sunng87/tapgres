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

#[derive(Parser, Debug)]
#[command(
    name = "tapgres",
    version,
    about = "Tap a local PostgreSQL port and decode its wire traffic to stdout",
    long_about = "tapgres reassembles each PostgreSQL connection and decodes its wire traffic \
                  with the pgwire protocol layer. Use --mode pcap (the default) to passively \
                  capture a local port with libpcap (cleartext only), or --mode mitm to run a \
                  local TLS-terminating proxy that decrypts encrypted sessions. Add --tui to \
                  either source for an interactive, scrollable, filterable view. Use --save to \
                  record versioned JSONL or --replay to open a saved session without capture.",
    before_help = crate::tui::BANNER
)]
pub struct Args {
    /// Traffic source.
    #[arg(long, value_enum, default_value_t = Mode::Pcap)]
    pub mode: Mode,

    /// Interactive TUI instead of line-oriented stdout (works with live or replay sources).
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

    /// Save every live or replayed output record as versioned JSONL while
    /// continuing to render normally. Recording happens before display
    /// filtering and before the TUI history cap is applied. An existing file
    /// is replaced.
    #[arg(long, value_name = "FILE")]
    pub save: Option<PathBuf>,

    /// Read a saved JSONL session instead of starting pcap or mitm capture.
    /// Replay is loaded at full speed and preserves original timestamps.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = [
            "mode",
            "port",
            "interface",
            "no_promisc",
            "snaplen",
            "listen",
            "upstream",
            "tls_dir",
            "tls_cert",
            "tls_key",
            "no_upstream_tls"
        ]
    )]
    pub replay: Option<PathBuf>,

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
    ///
    /// Defaults to `$XDG_CONFIG_HOME/tapgres` or `~/.config/tapgres`. tapgres
    /// writes `ca.crt`, `ca.key`, `server.crt`, and `server.key` here;
    /// distribute `ca.crt` to clients that must trust the proxy.
    #[arg(long)]
    pub tls_dir: Option<PathBuf>,

    /// [mitm] PEM server cert to present to clients (overrides auto-generation).
    ///
    /// When unset, tapgres uses an auto-generated leaf valid for `localhost`,
    /// `127.0.0.1`, and `::1`.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// [mitm] PEM private key for `--tls-cert`.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// [mitm] Disable TLS on the upstream leg (talk cleartext to the server).
    ///
    /// By default the upstream leg auto-negotiates TLS (sends an `SSLRequest`
    /// and honors the server's reply); the upstream certificate is not verified.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_save_and_replay_as_file_source_options() {
        let args = Args::try_parse_from([
            "tapgres",
            "--replay",
            "capture.jsonl",
            "--save",
            "copy.jsonl",
            "--tui",
        ])
        .unwrap();

        assert_eq!(args.replay, Some(PathBuf::from("capture.jsonl")));
        assert_eq!(args.save, Some(PathBuf::from("copy.jsonl")));
        assert!(args.tui);
    }

    #[test]
    fn replay_rejects_live_source_options() {
        let error =
            Args::try_parse_from(["tapgres", "--replay", "capture.jsonl", "--mode", "mitm"])
                .unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
