//! TCP stream reassembly and per-connection pgwire decode state.
//!
//! libpcap gives us individual, possibly reordered / retransmitted packets.
//! [`ConnTable`] tracks connections by their 4-tuple, reassembles each
//! direction in order, and feeds the resulting byte stream into the pgwire
//! message decoder.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::BytesMut;
use pgwire::messages::DecodeContext;

use crate::decode::{self, FieldSummary};
use crate::net::TcpSegment;
use crate::state::{ConnStats, Metrics, TrafficDirection};

/// (ip, port)
pub type Endpoint = (IpAddr, u16);

/// Which side of the connection a direction belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The PostgreSQL client: sends [`PgWireFrontendMessage`]s.
    Client,
    /// The PostgreSQL server: sends [`PgWireBackendMessage`]s.
    Server,
}

/// A connection, normalised so both directions collapse to the same key.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct ConnKey {
    pub client: Endpoint,
    pub server: Endpoint,
}

/// One direction of a connection: its TCP reassembly state plus the pgwire
/// decode buffer/context for that direction.
pub struct Direction {
    pub role: Role,
    /// Client endpoint attached to every decoded message from this connection.
    pub client: SocketAddr,
    /// Next sequence number we want to deliver (absolute, wrapping). `None`
    /// until we observe a SYN (or, if SYN was missed, until first data).
    next_seq: Option<u32>,
    /// Segments received ahead of `next_seq`, keyed by their start sequence.
    ooo: BTreeMap<u32, Vec<u8>>,
    /// Reassembled, in-order bytes awaiting decode.
    pub rxbuf: BytesMut,
    pub ctx: DecodeContext,
    /// Most recently seen `RowDescription` (server side), used to label
    /// `DataRow`s with column names and to pick text/binary rendering.
    pub row_desc: Option<Vec<FieldSummary>>,
}

impl Direction {
    fn new(role: Role, client: SocketAddr) -> Self {
        Self {
            role,
            client,
            next_seq: None,
            ooo: BTreeMap::new(),
            rxbuf: BytesMut::with_capacity(8 * 1024),
            ctx: DecodeContext::default(),
            row_desc: None,
        }
    }

    /// Decode-only constructor: no TCP reassembly state is exercised. Used by
    /// the MITM proxy, which already has clean, in-order plaintext bytes from
    /// the (possibly TLS-terminated) socket and feeds them straight into
    /// [`Direction::rxbuf`].
    ///
    /// The proxy terminates TLS at the socket layer, so the first plaintext
    /// bytes are a `Startup` message — never the SSL/GSS negotiation the pcap
    /// path expects. We clear the SSL-awaiting flag accordingly.
    pub fn for_decoding(role: Role, client: SocketAddr) -> Self {
        let mut d = Direction::new(role, client);
        d.ctx.awaiting_frontend_ssl = false;
        d
    }

    /// Feed a TCP segment's payload into this direction's reassembly buffer.
    /// SYN consumes one sequence number; data is delivered in order, with
    /// retransmissions de-duplicated and out-of-order segments buffered.
    pub fn feed(&mut self, seq: u32, syn: bool, data: &[u8]) {
        if syn {
            // SYN occupies a sequence number; first data byte is seq+1.
            self.next_seq = Some(seq.wrapping_add(1));
        }
        if data.is_empty() {
            return;
        }

        let next = match self.next_seq {
            Some(n) => n,
            // SYN missed (capture started mid-connection): anchor here.
            None => {
                self.next_seq = Some(seq);
                seq
            }
        };

        // Signed distance from `next` to `seq` in wrapping 32-bit space.
        let diff = seq.wrapping_sub(next) as i32;
        if diff > 0 {
            // Gap: this segment is ahead of what we can deliver yet.
            self.ooo.insert(seq, data.to_vec());
            return;
        }

        let (mut cur, mut chunk) = (seq, data);
        if diff < 0 {
            // Overlapping / retransmitted: drop the bytes we've already seen.
            let skip = (-diff) as usize;
            if skip >= chunk.len() {
                return; // entirely already delivered
            }
            chunk = &chunk[skip..];
            cur = cur.wrapping_add(skip as u32);
        }

        // cur == next: append in-order bytes.
        self.rxbuf.extend_from_slice(chunk);
        let mut adv = cur.wrapping_add(chunk.len() as u32);

        // Drain any buffered segments that now fit contiguously.
        while let Some(b) = self.ooo.remove(&adv) {
            self.rxbuf.extend_from_slice(&b);
            adv = adv.wrapping_add(b.len() as u32);
        }
        self.next_seq = Some(adv);
    }
}

/// A single PostgreSQL connection (client + server directions).
pub struct Connection {
    client: Direction,
    server: Direction,
    /// Set when the client negotiated SSL/GSS — the stream is then encrypted
    /// and we can no longer decode it.
    encrypted: bool,
    /// Metrics close on the first FIN, while the flow entry remains to absorb
    /// the rest of the TCP close handshake.
    metrics_closed: bool,
    stats: Arc<ConnStats>,
}

impl Connection {
    fn new(stats: Arc<ConnStats>) -> Self {
        let client = stats.client();
        Self {
            client: Direction::new(Role::Client, client),
            server: Direction::new(Role::Server, client),
            encrypted: false,
            metrics_closed: false,
            stats,
        }
    }

    fn handle(&mut self, seg: &TcpSegment, pg_port: u16, metrics: &Metrics) {
        if self.encrypted {
            return;
        }
        let is_client_dir = seg.dst_port == pg_port;
        if is_client_dir {
            self.client.feed(seg.seq, seg.syn, &seg.payload);
        } else {
            self.server.feed(seg.seq, seg.syn, &seg.payload);
        }

        let mut outcome = decode::DrainOutcome::default();
        if is_client_dir {
            decode::drain_direction(&mut self.client, &mut outcome);
            // The frontend's SSL/GSS request tells the *server* direction to
            // expect a 1-byte reply next; arm it so pgwire decodes that byte
            // as SslResponse/GssEncResponse rather than a typed message.
            match outcome.server_negotiation_wait {
                decode::ServerNegotiationWait::Ssl => {
                    self.server.ctx.awaiting_backend_ssl_response = true;
                }
                decode::ServerNegotiationWait::Gss => {
                    self.server.ctx.awaiting_backend_gss_response = true;
                }
                decode::ServerNegotiationWait::None => {}
            }
        } else {
            decode::drain_direction(&mut self.server, &mut outcome);
        }
        if outcome.encrypted {
            self.encrypted = true;
            metrics.set_encrypted(&self.stats, true);
        }
        // Count decoded pgwire messages, not TCP segments: one segment may
        // complete zero, one, or many buffered messages (or none, once the
        // stream has gone encrypted and we stopped draining).
        if outcome.msgs > 0 {
            metrics.record_messages(
                &self.stats,
                if is_client_dir {
                    TrafficDirection::In
                } else {
                    TrafficDirection::Out
                },
                outcome.msgs,
                outcome.bytes,
            );
        }
    }
}

/// The table of all active connections seen on the wire.
pub struct ConnTable {
    map: HashMap<ConnKey, Connection>,
    metrics: Arc<Metrics>,
}

impl Default for ConnTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTable {
    /// Construct an isolated table with an internal metrics store. Production
    /// sources use [`ConnTable::with_metrics`]; this convenience is primarily
    /// useful for decode/reassembly tests.
    pub fn new() -> Self {
        Self::with_metrics(Arc::new(Metrics::new()))
    }

    pub fn with_metrics(metrics: Arc<Metrics>) -> Self {
        Self {
            map: HashMap::new(),
            metrics,
        }
    }

    /// Ingest one captured TCP segment.
    pub fn handle(&mut self, seg: &TcpSegment, pg_port: u16) {
        // Classify direction by which endpoint owns the watched port.
        let (client, server) = if seg.dst_port == pg_port {
            ((seg.src, seg.src_port), (seg.dst, seg.dst_port))
        } else if seg.src_port == pg_port {
            ((seg.dst, seg.dst_port), (seg.src, seg.src_port))
        } else {
            return;
        };

        let key = ConnKey { client, server };

        // A closed entry stays in the map after FIN to absorb the trailing
        // ACK/FIN/ACK packets. A later SYN on the same 4-tuple is a genuine
        // reuse and starts fresh decode and metrics state.
        let should_open = self
            .map
            .get(&key)
            .is_none_or(|conn| seg.syn && conn.metrics_closed);
        if should_open {
            decode::out(format!(
                "[{}] === new connection  {}:{}  ->  {}:{}  (port {}) ===",
                decode::ts(),
                client.0,
                client.1,
                server.0,
                server.1,
                pg_port,
            ));
            let stats = self.metrics.open_connection(
                SocketAddr::new(client.0, client.1),
                SocketAddr::new(server.0, server.1),
                false,
            );
            self.map.insert(key, Connection::new(stats));
        }

        if seg.rst {
            if let Some(conn) = self.map.get_mut(&key) {
                conn.handle(seg, pg_port, &self.metrics);
            }
            decode::out(format!("[{}] === connection reset (RST) ===", decode::ts()));
            if let Some(conn) = self.map.remove(&key) {
                self.metrics.close_connection(&conn.stats);
            }
            return;
        }

        if let Some(conn) = self.map.get_mut(&key) {
            conn.handle(seg, pg_port, &self.metrics);
            if seg.fin && !conn.metrics_closed {
                conn.metrics_closed = true;
                decode::out(format!(
                    "[{}] === connection closed (FIN) ===",
                    decode::ts()
                ));
                self.metrics.close_connection(&conn.stats);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ConnectionLifecycle;
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT_PORT: u16 = 40_000;
    const PG_PORT: u16 = 5432;

    fn segment(client_to_server: bool, syn: bool, fin: bool, payload: &[u8]) -> TcpSegment {
        let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (src_port, dst_port) = if client_to_server {
            (CLIENT_PORT, PG_PORT)
        } else {
            (PG_PORT, CLIENT_PORT)
        };
        TcpSegment {
            src: host,
            dst: host,
            src_port,
            dst_port,
            seq: 1,
            ack: 0,
            syn,
            fin,
            rst: false,
            payload: payload.to_vec(),
        }
    }

    fn clean_close(table: &mut ConnTable) {
        table.handle(&segment(true, true, false, &[]), PG_PORT); // SYN
        table.handle(&segment(false, true, false, &[]), PG_PORT); // SYN/ACK
        table.handle(&segment(true, false, false, &[]), PG_PORT); // ACK
        table.handle(&segment(true, false, true, &[]), PG_PORT); // FIN
        table.handle(&segment(false, false, false, &[]), PG_PORT); // ACK
        table.handle(&segment(false, false, true, &[]), PG_PORT); // FIN
        table.handle(&segment(true, false, false, &[]), PG_PORT); // ACK
    }

    #[test]
    fn full_close_handshake_does_not_create_phantom_connections() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        clean_close(&mut table);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conns_opened, 1);
        assert_eq!(snapshot.conns_live, 0);
        // A bare TCP close handshake carries no pgwire messages.
        assert_eq!(snapshot.msgs_in, 0);
        assert_eq!(snapshot.msgs_out, 0);
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(table.map.len(), 1);
        assert!(matches!(
            snapshot.connections[0].lifecycle,
            ConnectionLifecycle::Closed { .. }
        ));
    }

    #[test]
    fn mid_capture_connection_still_opens_without_syn() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        table.handle(&segment(true, false, false, &[1, 2, 3]), PG_PORT);
        table.handle(&segment(false, false, true, &[]), PG_PORT);
        table.handle(&segment(true, false, false, &[]), PG_PORT);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conns_opened, 1);
        assert_eq!(snapshot.conns_live, 0);
        assert_eq!(snapshot.connections.len(), 1);
        // Partial bytes that never form a complete message are not counted.
        assert_eq!(snapshot.connections[0].bytes_in, 0);
    }

    #[test]
    fn syn_reopens_a_closed_four_tuple() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        clean_close(&mut table);
        table.handle(&segment(true, true, false, &[]), PG_PORT);

        let open = metrics.snapshot();
        assert_eq!(open.conns_opened, 2);
        assert_eq!(open.conns_live, 1);
        assert_eq!(open.connections.len(), 2);

        table.handle(&segment(true, false, true, &[]), PG_PORT);
        let closed = metrics.snapshot();
        assert_eq!(closed.conns_opened, 2);
        assert_eq!(closed.conns_live, 0);
        assert_eq!(closed.connections.len(), 2);
    }
}
