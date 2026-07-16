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
use std::sync::Arc;

use clap::Parser;

use tapgres::cli::{Args, Mode};
use tapgres::{capture, decode, filter::DisplayFilter, proxy, state, tui};

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let filter = args.display_filter.unwrap_or_default();
    let metrics = Arc::new(state::Metrics::with_limits(
        args.conn_history,
        args.rate_history,
    ));
    match args.mode {
        Mode::Pcap => {
            let opts = capture::PcapOpts {
                port: args.port,
                interface: args.interface,
                no_promisc: args.no_promisc,
                snaplen: args.snaplen,
            };
            if args.tui {
                tui::run_pcap(opts, metrics, args.tui_rich, filter)
            } else {
                run_stdout(filter, move || capture::run(opts, metrics))
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
                tui::run_mitm(opts, metrics, args.tui_rich, filter)
            } else {
                run_stdout(filter, move || proxy::run(opts, metrics))
            }
        }
    }
}

/// Run `source` with its decoded output funneled through a single consumer
/// thread: decoded lines to stdout, status to stderr. When `source` returns,
/// close the channel and join the consumer so nothing is left unflushed.
fn run_stdout<F>(filter: DisplayFilter, source: F) -> Result<(), Box<dyn Error>>
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
                if !record.matches_filter(&filter) {
                    continue;
                }
                match record {
                    decode::Output::Message { message, .. } => {
                        let _ = writeln!(stdout, "{}", message.rendered);
                    }
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
