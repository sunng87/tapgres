//! tapgres — passive PostgreSQL wire-protocol monitor.
//!
//! Captures TCP traffic on a user-specified local PostgreSQL port using
//! libpcap, reassembles each connection's two byte streams, and decodes them
//! with the `pgwire` protocol layer into human-readable stdout output.
//!
//! Cleartext connections only. Requires privileges to capture (`CAP_NET_RAW` or
//! root): run as root, grant the binary the capability, or capture on an
//! interface you have capture rights to.

use std::error::Error;

use clap::Parser;
use pcap::{Capture, Device};

use tapgres::{flow, net};

#[derive(Parser, Debug)]
#[command(
    name = "tapgres",
    version,
    about = "Passively tap a local PostgreSQL port and decode its wire traffic to stdout"
)]
struct Args {
    /// PostgreSQL TCP port to monitor.
    #[arg(short, long, default_value_t = 5432)]
    port: u16,

    /// Capture interface. Defaults to the loopback interface; pass "any" to
    /// capture on all interfaces.
    #[arg(short, long)]
    interface: Option<String>,

    /// Do not put the interface in promiscuous mode.
    #[arg(long, default_value_t = false)]
    no_promisc: bool,

    /// Maximum bytes captured per packet (snaplen).
    #[arg(long, default_value_t = 65535)]
    snaplen: i32,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

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
