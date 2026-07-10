//! tapgres — PostgreSQL wire-protocol monitor.
//!
//! Traffic sources, selected with `--mode`:
//!
//! - `pcap` (default): passively captures TCP traffic on a local PostgreSQL
//!   port with libpcap, reassembles each connection's two byte streams, and
//!   decodes them with the `pgwire` protocol layer into human-readable stdout.
//!   Cleartext connections only. Requires capture privileges (`CAP_NET_RAW` or
//!   root).
//! - `mitm`: runs a local TLS-terminating proxy. Point your client at the proxy
//!   instead of the server; the proxy decrypts the client leg, decodes the
//!   traffic in the middle, and forwards it to the real server. See
//!   [`tapgres::proxy`].
//!
//! Add `--tui` to either mode for an interactive, scrollable, filterable view
//! instead of line-oriented stdout. See [`tapgres::tui`].

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use tapgres::{capture, decode, proxy, tui};

#[derive(Parser, Debug)]
#[command(
    name = "tapgres",
    version,
    about = "Tap a local PostgreSQL port and decode its wire traffic to stdout"
)]
struct Args {
    /// Traffic source.
    #[arg(long, value_enum, default_value_t = Mode::Pcap)]
    mode: Mode,

    /// Interactive TUI instead of line-oriented stdout (works with any --mode).
    #[arg(long, default_value_t = false)]
    tui: bool,

    // --- pcap mode ---------------------------------------------------------
    /// [pcap] PostgreSQL TCP port to monitor.
    #[arg(short, long, default_value_t = 5432)]
    port: u16,

    /// [pcap] Capture interface. Defaults to loopback; pass "any" for all.
    #[arg(short, long)]
    interface: Option<String>,

    /// [pcap] Do not put the interface in promiscuous mode.
    #[arg(long, default_value_t = false)]
    no_promisc: bool,

    /// [pcap] Maximum bytes captured per packet (snaplen).
    #[arg(long, default_value_t = 65535)]
    snaplen: i32,

    // --- mitm mode ---------------------------------------------------------
    /// [mitm] Address to listen on for client connections.
    #[arg(long, default_value = "127.0.0.1:15432")]
    listen: String,

    /// [mitm] Upstream PostgreSQL server to forward to.
    #[arg(long, default_value = "127.0.0.1:5432")]
    upstream: String,

    /// [mitm] Directory for the auto-generated CA + server cert.
    /// Defaults to `$XDG_CONFIG_HOME/tapgres` or `~/.config/tapgres`.
    #[arg(long)]
    tls_dir: Option<PathBuf>,

    /// [mitm] PEM server cert to present to clients (overrides auto-generation).
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// [mitm] PEM private key for --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// [mitm] Disable TLS on the upstream leg (talk cleartext to the server).
    #[arg(long, default_value_t = false)]
    no_upstream_tls: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    /// Passive libpcap capture (cleartext only).
    Pcap,
    /// Local TLS-terminating proxy.
    Mitm,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    match args.mode {
        Mode::Pcap => {
            let opts = capture::PcapOpts {
                port: args.port,
                interface: args.interface,
                no_promisc: args.no_promisc,
                snaplen: args.snaplen,
            };
            if args.tui {
                tui::run_pcap(opts)
            } else {
                run_stdout(move || capture::run(opts))
            }
        }
        Mode::Mitm => {
            let opts = proxy::ProxyOpts {
                listen: args.listen,
                upstream: args.upstream,
                tls_dir: args.tls_dir.unwrap_or_else(default_tls_dir),
                tls_cert: args.tls_cert,
                tls_key: args.tls_key,
                no_upstream_tls: args.no_upstream_tls,
            };
            if args.tui {
                tui::run_mitm(opts)
            } else {
                run_stdout(move || proxy::run(opts))
            }
        }
    }
}

/// Run `source` with its decoded output funneled through a single consumer
/// thread: decoded lines to stdout, status to stderr. When `source` returns,
/// close the channel and join the consumer so nothing is left unflushed.
fn run_stdout<F>(source: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let (tx, rx) = crossbeam_channel::unbounded();
    decode::set_output(tx);
    let printer = std::thread::Builder::new()
        .name("tapgres-out".into())
        .spawn(move || {
            let mut stdout = std::io::stdout().lock();
            let mut stderr = std::io::stderr().lock();
            while let Ok(record) = rx.recv() {
                match record {
                    decode::Output::Line(s) => {
                        let _ = writeln!(stdout, "{s}");
                    }
                    decode::Output::Status(s) => {
                        let _ = writeln!(stderr, "{s}");
                    }
                }
            }
            let _ = stdout.flush();
            let _ = stderr.flush();
        })?;
    let result = source();
    decode::close_output();
    let _ = printer.join();
    result
}

/// Default on-disk location for the auto-generated CA + server cert.
fn default_tls_dir() -> PathBuf {
    if let Ok(d) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(d).join("tapgres");
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config").join("tapgres");
    }
    PathBuf::from(".tapgres")
}
