//! Raw frame → TCP segment parsing.
//!
//! `libpcap` hands us whole captured frames. We strip the link-layer header
//! (chosen by the capture's datalink type) and parse the IP + TCP headers to
//! extract the connection 4-tuple, sequence number and TCP flags together with
//! the reassembled-direction payload bytes. Actual TCP stream reassembly lives
//! in [`crate::flow`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single captured TCP segment (one direction of one packet).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TcpSegment {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: Vec<u8>,
}

/// Datalink type constants we handle. These mirror `pcap::Linktype`.
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_RAW_OLD: i32 = 12;
const DLT_RAW: i32 = 101;
const DLT_LINUX_SLL: i32 = 113;
const DLT_LINUX_SLL2: i32 = 276;
const DLT_IPV4: i32 = 228;
const DLT_IPV6: i32 = 229;

/// Parse a captured frame into a [`TcpSegment`], based on the datalink type.
///
/// Returns `None` for non-IPv4/IPv6 frames, non-TCP packets, or anything too
/// short / malformed.
pub fn parse_frame(data: &[u8], dlt: i32) -> Option<TcpSegment> {
    let ip = strip_link(data, dlt)?;
    parse_ip(ip)
}

fn strip_link(data: &[u8], dlt: i32) -> Option<&[u8]> {
    match dlt {
        DLT_EN10MB => {
            if data.len() < 14 {
                return None;
            }
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            let mut payload = &data[14..];
            // skip 802.1Q (and stacked) VLAN tags
            while ethertype == 0x8100 && payload.len() >= 4 {
                ethertype = u16::from_be_bytes([payload[0], payload[1]]);
                payload = &payload[4..];
            }
            match ethertype {
                0x0800 | 0x86DD => Some(payload),
                _ => None,
            }
        }
        DLT_RAW | DLT_RAW_OLD | DLT_IPV4 | DLT_IPV6 => Some(data),
        DLT_NULL => {
            // BSD loopback: a 4-byte address-family field, then the IP packet.
            if data.len() < 4 {
                return None;
            }
            Some(&data[4..])
        }
        DLT_LINUX_SLL => {
            // 16-byte cooked header: pkttype(2) arphrd(2) addrlen(2) addr(8) protocol(2)
            if data.len() < 16 {
                return None;
            }
            Some(&data[16..])
        }
        DLT_LINUX_SLL2 => {
            // 20-byte cooked header: protocol(2) reserved(2) ifindex(4) arphrd(2)
            //                       pkttype(2) addrlen(1) addr(8)
            if data.len() < 20 {
                return None;
            }
            Some(&data[20..])
        }
        _ => None,
    }
}

fn parse_ip(b: &[u8]) -> Option<TcpSegment> {
    if b.is_empty() {
        return None;
    }
    match b[0] >> 4 {
        4 => parse_ipv4(b),
        6 => parse_ipv6(b),
        _ => None,
    }
}

fn parse_ipv4(b: &[u8]) -> Option<TcpSegment> {
    if b.len() < 20 {
        return None;
    }
    let ihl = (b[0] & 0x0f) as usize * 4;
    if ihl < 20 || b.len() < ihl {
        return None;
    }
    let proto = b[9];
    if proto != 6 {
        return None; // not TCP
    }
    let total_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let end = total_len.min(b.len());
    if end < ihl {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
    parse_tcp(&b[ihl..end], src, dst)
}

fn parse_ipv6(b: &[u8]) -> Option<TcpSegment> {
    if b.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([b[4], b[5]]) as usize;
    let mut next_header = b[6];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap()));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap()));

    let mut off = 40;
    let body_end = 40usize.saturating_add(payload_len).min(b.len());
    // Walk extension headers (best-effort). Stop at TCP, or bail on anything
    // we don't model (e.g. ESP).
    while is_extension_header(next_header) && off + 8 <= body_end {
        let ext_next = b[off];
        let ext_len = extension_header_len(next_header, &b[off..body_end])?;
        next_header = ext_next;
        off += ext_len;
        if off > body_end {
            return None;
        }
    }
    if next_header != 6 {
        return None;
    }
    parse_tcp(&b[off..body_end], src, dst)
}

fn is_extension_header(nh: u8) -> bool {
    matches!(nh, 0 | 43 | 44 | 51 | 60)
}

fn extension_header_len(nh: u8, ext: &[u8]) -> Option<usize> {
    match nh {
        44 => Some(8), // fragment header is fixed-size
        51 => {
            // AH: length in 4-byte units + 2, but stored as (units-1)... use the
            // standard formula `(len+2)*4`.
            if ext.len() < 2 {
                return None;
            }
            Some(((ext[1] as usize).saturating_add(2)) * 4)
        }
        _ => {
            // hop-by-hop / routing / dest-opts: length in 8-byte units + 8.
            if ext.len() < 2 {
                return None;
            }
            Some(((ext[1] as usize).saturating_add(1)) * 8)
        }
    }
}

fn parse_tcp(l4: &[u8], src: IpAddr, dst: IpAddr) -> Option<TcpSegment> {
    if l4.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
    let data_offset = ((l4[12] >> 4) as usize) * 4;
    let flags = l4[13];
    if data_offset < 20 || l4.len() < data_offset {
        return None;
    }
    let payload = if l4.len() > data_offset {
        l4[data_offset..].to_vec()
    } else {
        Vec::new()
    };
    Some(TcpSegment {
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        syn: flags & 0x02 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload,
    })
}
