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
//! - `--replay FILE`: opens a versioned JSONL session instead of capturing and
//!   feeds its decoded records through the same stdout or TUI renderer.
//!
//! Add `--tui` to either mode for an interactive, scrollable, filterable view
//! instead of line-oriented stdout. See [`tapgres::tui`].

use std::error::Error;
use std::fs;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use tapgres::cli::{Args, Mode};
use tapgres::{capture, decode, filter::DisplayFilter, proxy, session, state, tui};

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let filter = args.display_filter.unwrap_or_default();
    let metrics = Arc::new(state::Metrics::with_limits(
        args.conn_history,
        args.rate_history,
    ));
    if let Some(replay) = args.replay {
        if let Some(save) = &args.save {
            ensure_distinct_files(&replay, save)?;
        }
        return if args.tui {
            tui::run_replay(replay, metrics, args.tui_rich, filter, args.save)
        } else {
            run_stdout(filter, args.save, move || {
                session::read_with(replay, decode::replay).map_err(Into::into)
            })
        };
    }
    match args.mode {
        Mode::Pcap => {
            let opts = capture::PcapOpts {
                port: args.port,
                interface: args.interface,
                no_promisc: args.no_promisc,
                snaplen: args.snaplen,
            };
            if args.tui {
                tui::run_pcap(opts, metrics, args.tui_rich, filter, args.save)
            } else {
                run_stdout(filter, args.save, move || capture::run(opts, metrics))
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
                tui::run_mitm(opts, metrics, args.tui_rich, filter, args.save)
            } else {
                run_stdout(filter, args.save, move || proxy::run(opts, metrics))
            }
        }
    }
}

/// Run `source` with its decoded output funneled through a single consumer
/// thread: decoded lines to stdout, status to stderr. When `source` returns,
/// close the channel and join the consumer so nothing is left unflushed.
fn run_stdout<F>(
    filter: DisplayFilter,
    save: Option<PathBuf>,
    source: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let (tx, rx) = decode::channel();
    decode::set_output(tx);
    let mut recorder = save.map(session::SessionWriter::create).transpose()?;
    let printer = std::thread::Builder::new()
        .name("tapgres-out".into())
        .spawn(move || -> io::Result<()> {
            let mut stdout = std::io::stdout().lock();
            let mut stderr = std::io::stderr().lock();
            let mut recorder_error = None;
            while let Ok(record) = rx.recv() {
                if let Some(writer) = recorder.as_mut() {
                    if let Err(error) = writer.write(&record) {
                        let message = format!("tapgres: recording stopped: {error}");
                        let _ = writeln!(stderr, "{message}");
                        recorder_error = Some(io::Error::other(message));
                        recorder = None;
                    }
                }
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
            if let Some(writer) = recorder.as_mut() {
                writer.flush().map_err(io::Error::other)?;
            }
            let _ = stdout.flush();
            let _ = stderr.flush();
            if let Some(error) = recorder_error {
                return Err(error);
            }
            Ok(())
        })?;
    let result = source();
    decode::close_output();
    let consumer_result = printer
        .join()
        .map_err(|_| io::Error::other("output consumer thread panicked"))?;
    result?;
    consumer_result?;
    let dropped = decode::dropped_count();
    if dropped > 0 {
        eprintln!("tapgres: dropped {dropped} output records (consumer could not keep up)");
    }
    Ok(())
}

/// Prevent `--replay FILE --save FILE` from truncating the input before it is
/// read. Canonicalising the existing input and the output's parent also catches
/// equivalent relative paths and symlinked directories.
fn ensure_distinct_files(input: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let input = fs::canonicalize(input)?;
    let output_exists = output.exists();
    let output = if output_exists {
        fs::canonicalize(output)?
    } else {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = output
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid --save path"))?;
        fs::canonicalize(parent)?.join(name)
    };
    if input == output || (output_exists && files_share_identity(&input, &output)?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--save must not overwrite the --replay input file",
        )
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn files_share_identity(left: &Path, right: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = fs::metadata(left)?;
    let right = fs::metadata(right)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn files_share_identity(_left: &Path, _right: &Path) -> io::Result<bool> {
    Ok(false)
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
