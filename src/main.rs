//! tapgres — PostgreSQL wire-protocol monitor.
//!
//! Two operating modes, selected with `--mode`:
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

use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use pcap::{Capture, Device};

use tapgres::{flow, net, proxy};

#[derive(Parser, Debug)]
#[command(
    name = "tapgres",
    version,
    about = "Tap a local PostgreSQL port and decode its wire traffic to stdout"
)]
struct Args {
    /// Operating mode.
    #[arg(long, value_enum, default_value_t = Mode::Pcap)]
    mode: Mode,

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
        Mode::Pcap => run_pcap(args),
        Mode::Mitm => {
            let opts = proxy::ProxyOpts {
                listen: args.listen,
                upstream: args.upstream,
                tls_dir: args.tls_dir.unwrap_or_else(default_tls_dir),
                tls_cert: args.tls_cert,
                tls_key: args.tls_key,
                no_upstream_tls: args.no_upstream_tls,
            };
            proxy::run(opts)
        }
    }
}

/// Passive capture + decode loop (the original tapgres behaviour).
fn run_pcap(args: Args) -> Result<(), Box<dyn Error>> {
    let device = resolve_device(args.interface.as_deref())?;

    eprintln!(
        "tapgres: capturing on '{}'  (filter: tcp port {})",
        device.name, args.port
    );
    eprintln!(
        "tapgres: note — only cleartext connections are decoded; run as root / grant CAP_NET_RAW."
    );

    let mut cap = Capture::from_device(device)?
        .promisc(!args.no_promisc)
        .snaplen(args.snaplen)
        .timeout(1000)
        .open()?;
    cap.filter(&format!("tcp port {}", args.port), true)?;

    let dlt = cap.get_datalink().0;
    eprintln!("tapgres: datalink type = {} ({})", dlt, datalink_name(dlt));

    let mut table = flow::ConnTable::new();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(seg) = net::parse_frame(packet.data, dlt) {
                    table.handle(&seg, args.port);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
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

/// Resolve which capture device to use.
///
/// - `None` (the default): the loopback interface, found by its pcap loopback
///   flag so it works regardless of OS naming (`lo` on Linux, `lo0` on
///   macOS/BSD, ...).
/// - `Some(name)`: a name matched against the enumerated interfaces. Falls back
///   to a bare-name device so special targets like `any` (Linux's
///   all-interfaces pseudo-device) keep working even though libpcap doesn't
///   list them.
fn resolve_device(interface: Option<&str>) -> Result<Device, String> {
    let devices = Device::list().map_err(|e| format!("listing interfaces: {e}"))?;
    match interface {
        None => devices
            .iter()
            .find(|d| d.flags.is_loopback())
            .cloned()
            .ok_or_else(|| {
                let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
                format!(
                    "no loopback interface found; pass --interface (available: {})",
                    names.join(", ")
                )
            }),
        Some(name) => Ok(devices
            .iter()
            .find(|d| d.name == name)
            .cloned()
            .unwrap_or_else(|| Device::from(name))),
    }
}

fn datalink_name(dlt: i32) -> &'static str {
    match dlt {
        0 => "NULL (BSD loopback)",
        1 => "EN10MB (Ethernet)",
        12 | 101 => "RAW (raw IP)",
        113 => "LINUX_SLL (cooked)",
        276 => "LINUX_SLL2 (cooked v2)",
        228 => "IPV4",
        229 => "IPV6",
        _ => "unknown",
    }
}
