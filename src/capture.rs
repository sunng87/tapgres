//! Passive libpcap capture + decode loop (`--mode pcap`).
//!
//! Resolves a capture device, opens it with a `tcp port <n>` BPF filter, and
//! feeds each reassembled TCP segment through [`crate::flow`]'s connection
//! table, which decodes with [`crate::decode`]. Output goes through
//! [`decode::out`] (stdout, or the shared sink in TUI mode).
//!
//! Captured from the binary in pcap mode and spawned in a background thread by
//! the TUI.

use std::error::Error;

use pcap::{Capture, Device};

use crate::decode;
use crate::flow;
use crate::net;

/// Options for a passive capture. Cheap to clone so the TUI can move a copy
/// into a background thread.
#[derive(Clone)]
pub struct PcapOpts {
    /// PostgreSQL TCP port to monitor.
    pub port: u16,
    /// Capture interface; `None` means the loopback interface.
    pub interface: Option<String>,
    /// Disable promiscuous mode.
    pub no_promisc: bool,
    /// Snaplen (max bytes captured per packet).
    pub snaplen: i32,
}

/// Run the capture + decode loop until the capture ends or errors.
pub fn run(opts: PcapOpts) -> Result<(), Box<dyn Error>> {
    let device = resolve_device(opts.interface.as_deref())?;

    decode::status(format!(
        "tapgres: capturing on '{}'  (filter: tcp port {})",
        device.name, opts.port
    ));
    decode::status(
        "tapgres: note — only cleartext connections are decoded; run as root / grant CAP_NET_RAW."
            .into(),
    );

    let mut cap = Capture::from_device(device)?
        .promisc(!opts.no_promisc)
        .snaplen(opts.snaplen)
        .timeout(1000)
        .open()?;
    cap.filter(&format!("tcp port {}", opts.port), true)?;

    let dlt = cap.get_datalink().0;
    decode::status(format!(
        "tapgres: datalink type = {} ({})",
        dlt,
        datalink_name(dlt)
    ));

    let mut table = flow::ConnTable::new();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(seg) = net::parse_frame(packet.data, dlt) {
                    table.handle(&seg, opts.port);
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
