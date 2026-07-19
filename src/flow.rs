//! TCP stream reassembly and per-connection pgwire decode state.
//!
//! libpcap gives us individual, possibly reordered / retransmitted packets.
//! [`ConnTable`] tracks connections by their 4-tuple, reassembles each
//! direction in order, and feeds the resulting byte stream into the pgwire
//! message decoder.

use std::collections::btree_map::Entry;
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

/// Cap on out-of-order bytes buffered per direction. Normal reordering settles
/// within a handful of segments; passing this means a segment the kernel
/// dropped before we saw it will never arrive, so we resync past the hole
/// rather than stall and grow without bound.
const OOO_BYTES_CAP: usize = 256 * 1024;

/// A closed connection is kept this many segments (of subsequent global
/// activity) so trailing close-handshake packets and retransmits land on it
/// instead of spawning a phantom new connection, then it is swept.
const CLOSE_GRACE_SEGMENTS: u64 = 256;

/// How often, in handled segments, to sweep the table for evictable entries.
const SWEEP_INTERVAL: u64 = 512;

/// Backstop bound on retained connections. Closed ones are swept promptly via
/// the grace period; this caps the pathological case of many connections whose
/// FIN/RST we never observed (client crash, capture started late, NAT rebind).
const MAX_CONNECTIONS: usize = 16_384;

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
    /// Total bytes held in `ooo`, kept in step with it so the buffering cap is
    /// an O(1) check.
    ooo_bytes: usize,
    /// Reassembled, in-order bytes awaiting decode.
    pub rxbuf: BytesMut,
    pub ctx: DecodeContext,
    /// Most recently seen `RowDescription` (server side), used to label
    /// `DataRow`s with column names and to pick text/binary rendering.
    pub row_desc: Option<Vec<FieldSummary>>,
    /// Extended-protocol prepared statements (name → SQL) seen on this
    /// direction's `Parse` messages, so `Bind`/`Execute` can be annotated with
    /// the actual query instead of an opaque statement name.
    pub prepared: HashMap<String, String>,
    /// Portal name → statement name, from `Bind`, so an `Execute` on a portal
    /// resolves back to its prepared SQL.
    pub portals: HashMap<String, String>,
    /// Consecutive decode failures; reset on any successful decode. Used to
    /// stop decoding a hopelessly desynced direction rather than spam.
    pub decode_failures: u32,
    /// Set once a direction is given up as unrecoverably desynced; decoding
    /// stops (relaying, in mitm mode, continues regardless).
    pub dead: bool,
}

impl Direction {
    fn new(role: Role, client: SocketAddr) -> Self {
        Self {
            role,
            client,
            next_seq: None,
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            rxbuf: BytesMut::with_capacity(8 * 1024),
            ctx: DecodeContext::default(),
            row_desc: None,
            prepared: HashMap::new(),
            portals: HashMap::new(),
            decode_failures: 0,
            dead: false,
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
        // A SYN carrying data (TCP Fast Open) numbers that data from seq+1, not
        // seq, since the SYN itself consumed the ISN.
        let data_seq = if syn { seq.wrapping_add(1) } else { seq };

        let next = match self.next_seq {
            Some(n) => n,
            // SYN missed (capture started mid-connection): anchor here.
            None => {
                self.next_seq = Some(data_seq);
                data_seq
            }
        };

        // Signed distance from `next` to `data_seq` in wrapping 32-bit space.
        let diff = data_seq.wrapping_sub(next) as i32;
        if diff > 0 {
            // Gap: this segment is ahead of what we can deliver yet.
            self.buffer_ooo(data_seq, data);
            if self.ooo_bytes > OOO_BYTES_CAP {
                self.resync_after_gap();
            }
            return;
        }

        let (mut cur, mut chunk) = (data_seq, data);
        if diff < 0 {
            // Overlapping / retransmitted: drop the bytes we've already seen.
            let skip = (-diff) as usize;
            if skip >= chunk.len() {
                return; // entirely already delivered
            }
            chunk = &chunk[skip..];
            cur = cur.wrapping_add(skip as u32);
        }

        // cur == next: append in-order bytes, then pull in any buffered
        // segments that overlap or abut the new position.
        self.rxbuf.extend_from_slice(chunk);
        let adv = cur.wrapping_add(chunk.len() as u32);
        self.next_seq = Some(self.drain_ooo(adv));
    }

    /// Buffer an out-of-order segment, keeping the longer of any two segments
    /// that start at the same sequence — a shorter retransmit must not clobber
    /// data we already hold.
    fn buffer_ooo(&mut self, seq: u32, data: &[u8]) {
        match self.ooo.entry(seq) {
            Entry::Occupied(mut e) => {
                if data.len() > e.get().len() {
                    self.ooo_bytes += data.len() - e.get().len();
                    e.insert(data.to_vec());
                }
            }
            Entry::Vacant(e) => {
                self.ooo_bytes += data.len();
                e.insert(data.to_vec());
            }
        }
    }

    /// Deliver every buffered segment that overlaps or abuts `adv`, returning
    /// the new in-order position. Correctly handles re-segmented retransmissions
    /// where a buffered segment starts before `adv` but extends past it, and
    /// drops segments that are now fully behind `adv`.
    ///
    /// Assumes sequence numbers do not wrap within the buffered set; the
    /// `OOO_BYTES_CAP` resync bounds that set well under the 4 GiB wrap window.
    fn drain_ooo(&mut self, mut adv: u32) -> u32 {
        while let Some((&start, _)) = self.ooo.range(..=adv).next_back() {
            let buf = self.ooo.remove(&start).unwrap();
            self.ooo_bytes -= buf.len();
            let end = start.wrapping_add(buf.len() as u32);
            if (end.wrapping_sub(adv) as i32) <= 0 {
                continue; // entirely already delivered
            }
            let already = adv.wrapping_sub(start) as usize;
            self.rxbuf.extend_from_slice(&buf[already..]);
            adv = end;
        }
        adv
    }

    /// A capture gap has grown past the buffering cap, so a dropped segment will
    /// never arrive. Skip the hole: drop the un-decodable prefix, jump to the
    /// lowest buffered segment, and drain from there so decoding recovers
    /// instead of stalling forever.
    fn resync_after_gap(&mut self) {
        let Some((&lo, _)) = self.ooo.iter().next() else {
            return;
        };
        let lost = self.next_seq.map(|n| lo.wrapping_sub(n)).unwrap_or(0);
        decode::warn(
            self.role,
            self.client,
            &format!("reassembly gap: ~{lost} bytes lost (capture drop?), resyncing stream"),
        );
        // Pre-gap bytes end at the old `next_seq`; splicing them onto the
        // post-gap bytes would forge a bogus message boundary, so drop them.
        self.rxbuf.clear();
        self.next_seq = Some(self.drain_ooo(lo));
    }
}

/// A single PostgreSQL connection (client + server directions).
pub struct Connection {
    client: Direction,
    server: Direction,
    /// Set when the client negotiated SSL/GSS — the stream is then encrypted
    /// and we can no longer decode it.
    encrypted: bool,
    /// Table clock at which metrics closed (first FIN/RST). `Some` marks the
    /// entry a tombstone: it lingers to absorb the rest of the close handshake,
    /// then the sweep removes it after [`CLOSE_GRACE_SEGMENTS`].
    closed_at: Option<u64>,
    /// Table clock of the most recent segment on this connection, for LRU
    /// eviction of connections whose close we never saw.
    last_seen: u64,
    stats: Arc<ConnStats>,
}

impl Connection {
    fn new(stats: Arc<ConnStats>, now: u64) -> Self {
        let client = stats.client();
        Self {
            client: Direction::new(Role::Client, client),
            server: Direction::new(Role::Server, client),
            encrypted: false,
            closed_at: None,
            last_seen: now,
            stats,
        }
    }

    /// Whether a client SYN's ISN matches the handshake we already track (a
    /// retransmitted SYN) rather than a fresh connection reusing the 4-tuple.
    fn is_same_client_syn(&self, seq: u32) -> bool {
        self.client.next_seq == Some(seq.wrapping_add(1))
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
    /// Monotonic count of handled segments, used as a logical clock for the
    /// close-grace and idle/LRU eviction that keep `map` bounded.
    clock: u64,
    /// Clock value at which to run the next sweep.
    next_sweep: u64,
    /// Retained-connection cap; a field so tests can shrink it.
    max_connections: usize,
    /// One-shot guard for the both-ports-are-the-monitored-port warning.
    warned_same_port: bool,
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
            clock: 0,
            next_sweep: SWEEP_INTERVAL,
            max_connections: MAX_CONNECTIONS,
            warned_same_port: false,
        }
    }

    /// Ingest one captured TCP segment.
    pub fn handle(&mut self, seg: &TcpSegment, pg_port: u16) {
        self.clock = self.clock.wrapping_add(1);
        self.maybe_sweep();

        // Both endpoints on the watched port (server-to-server): direction can't
        // be classified, so both sides would collide in one decode buffer. Skip.
        if seg.src_port == pg_port && seg.dst_port == pg_port {
            if !self.warned_same_port {
                self.warned_same_port = true;
                decode::status(
                    "tapgres: ignoring traffic where both endpoints use the monitored port; \
                     direction cannot be classified"
                        .into(),
                );
            }
            return;
        }

        // Classify direction by which endpoint owns the watched port.
        let (client, server) = if seg.dst_port == pg_port {
            ((seg.src, seg.src_port), (seg.dst, seg.dst_port))
        } else if seg.src_port == pg_port {
            ((seg.dst, seg.dst_port), (seg.src, seg.src_port))
        } else {
            return;
        };

        let key = ConnKey { client, server };

        // A client's initial SYN (travelling toward the monitored port).
        let client_syn = seg.syn && seg.dst_port == pg_port;
        let should_open = match self.map.get(&key) {
            // A bare ACK/FIN/RST on an unknown 4-tuple (trailing close packets
            // after eviction, a port-scan RST) must not spawn a phantom
            // connection — only a SYN or a payload-bearing segment does.
            None => seg.syn || !seg.payload.is_empty(),
            // Reuse of the 4-tuple: reopen when a closed (tombstoned) entry sees
            // any SYN, or when a live entry sees a *new* client handshake (its
            // previous close was missed by the capture).
            Some(conn) => {
                (seg.syn && conn.closed_at.is_some())
                    || (client_syn && !conn.is_same_client_syn(seg.seq))
            }
        };
        if should_open {
            // Retire any stale entry we're replacing before opening afresh.
            if let Some(old) = self.map.remove(&key) {
                if old.closed_at.is_none() {
                    self.metrics.close_connection(&old.stats);
                }
            }
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
            self.map.insert(key, Connection::new(stats, self.clock));
        }

        let Some(conn) = self.map.get_mut(&key) else {
            return;
        };
        conn.last_seen = self.clock;
        conn.handle(seg, pg_port, &self.metrics);

        if seg.rst {
            // Tombstone rather than remove: a duplicate/retransmitted RST or a
            // trailing segment then lands on the closed entry instead of
            // recreating a phantom connection. The sweep removes it later.
            if conn.closed_at.is_none() {
                conn.closed_at = Some(self.clock);
                self.metrics.close_connection(&conn.stats);
                decode::out(format!("[{}] === connection reset (RST) ===", decode::ts()));
            }
        } else if seg.fin && conn.closed_at.is_none() {
            conn.closed_at = Some(self.clock);
            decode::out(format!(
                "[{}] === connection closed (FIN) ===",
                decode::ts()
            ));
            self.metrics.close_connection(&conn.stats);
        }
    }

    /// Periodically evict connections that can no longer receive useful data:
    /// tombstoned ones past their close grace, and — as a backstop — the
    /// least-recently-seen live ones once the table exceeds its cap.
    fn maybe_sweep(&mut self) {
        if self.clock < self.next_sweep {
            return;
        }
        self.next_sweep = self.clock.wrapping_add(SWEEP_INTERVAL);
        let clock = self.clock;
        self.map.retain(|_, conn| {
            conn.closed_at
                .is_none_or(|c| clock.wrapping_sub(c) <= CLOSE_GRACE_SEGMENTS)
        });
        if self.map.len() > self.max_connections {
            self.evict_lru(self.map.len() - self.max_connections);
        }
    }

    /// Remove the `n` least-recently-seen connections, closing any that were
    /// still live in the metrics registry so its lifecycle stays consistent.
    fn evict_lru(&mut self, n: usize) {
        let mut by_age: Vec<(u64, ConnKey)> =
            self.map.iter().map(|(k, c)| (c.last_seen, *k)).collect();
        by_age.sort_unstable_by_key(|(seen, _)| *seen);
        for (_, key) in by_age.into_iter().take(n) {
            if let Some(conn) = self.map.remove(&key) {
                if conn.closed_at.is_none() {
                    self.metrics.close_connection(&conn.stats);
                }
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

    fn client_dir() -> Direction {
        Direction::new(Role::Client, "127.0.0.1:40000".parse().unwrap())
    }

    #[test]
    fn syn_with_data_keeps_the_first_byte() {
        // TCP Fast Open: the SYN carries payload numbered from seq+1.
        let mut d = client_dir();
        d.feed(100, true, b"AB");
        assert_eq!(&d.rxbuf[..], b"AB");
        d.feed(103, false, b"C");
        assert_eq!(&d.rxbuf[..], b"ABC");
    }

    #[test]
    fn overlapping_retransmit_delivers_every_byte() {
        // Anchor at 100, buffer an early [150,250) segment, then receive an
        // in-order [100,200) segment that overlaps it. All of [100,250) must
        // arrive contiguously — the classic stranded-suffix reassembly bug.
        let mut d = client_dir();
        d.feed(99, true, b""); // SYN: next_seq = 100
        let early: Vec<u8> = (50u8..150).collect(); // seq 150..250 -> value seq-100
        d.feed(150, false, &early);
        assert!(
            d.rxbuf.is_empty(),
            "early segment must be buffered, not delivered"
        );
        let inorder: Vec<u8> = (0u8..100).collect(); // seq 100..200 -> value seq-100
        d.feed(100, false, &inorder);
        let expected: Vec<u8> = (0u8..150).collect();
        assert_eq!(&d.rxbuf[..], &expected[..]);
        assert_eq!(d.ooo_bytes, 0);
    }

    #[test]
    fn shorter_retransmit_does_not_clobber_a_buffered_segment() {
        let mut d = client_dir();
        d.feed(99, true, b""); // next_seq = 100
        d.feed(200, false, b"LONGSEGMENT"); // buffered at 200
        d.feed(200, false, b"SHORT"); // same start, shorter: must be ignored
        d.feed(100, false, &[b'.'; 100]); // fills the gap to 200
        assert_eq!(&d.rxbuf[100..], b"LONGSEGMENT");
    }

    #[test]
    fn oversized_gap_resyncs_instead_of_stalling() {
        decode::start_capture();
        let mut d = client_dir();
        d.feed(999, true, b""); // next_seq = 1000
        // A far-ahead segment larger than the buffering cap: the [1000, far)
        // gap will never fill, so feed() must skip it and resync.
        let big = vec![0xabu8; OOO_BYTES_CAP + 1];
        d.feed(5000, false, &big);
        assert_eq!(
            d.rxbuf.len(),
            big.len(),
            "resync should deliver the buffered segment"
        );
        assert_eq!(d.ooo_bytes, 0);
        assert_eq!(d.next_seq, Some(5000u32.wrapping_add(big.len() as u32)));
        let out = decode::take_output_capture();
        assert!(
            out.iter().any(|o| matches!(o, decode::Output::Message { message, .. } if message.kind == "Warning")),
            "resync should emit an attributed warning"
        );
    }

    fn noise() -> TcpSegment {
        // Traffic on neither the client nor the monitored port: advances the
        // table clock without creating a connection.
        TcpSegment {
            src: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 1234,
            dst_port: 2345,
            seq: 1,
            ack: 0,
            syn: false,
            fin: false,
            rst: false,
            payload: vec![],
        }
    }

    #[test]
    fn closed_connections_are_swept_after_the_grace_period() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        clean_close(&mut table);
        assert_eq!(table.map.len(), 1, "tombstone retained right after close");

        // Advance the clock well past the close grace, then sweep.
        for _ in 0..(CLOSE_GRACE_SEGMENTS + 4) {
            table.handle(&noise(), PG_PORT);
        }
        table.next_sweep = table.clock;
        table.maybe_sweep();
        assert_eq!(table.map.len(), 0, "tombstone swept after grace");
        assert_eq!(metrics.snapshot().conns_live, 0);
    }

    fn client_syn(src_port: u16) -> TcpSegment {
        TcpSegment {
            src: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port,
            dst_port: PG_PORT,
            seq: 1000,
            ack: 0,
            syn: true,
            fin: false,
            rst: false,
            payload: vec![],
        }
    }

    #[test]
    fn lru_eviction_bounds_live_connections() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        table.max_connections = 2;
        // Four never-closed connections (missed FIN/RST); oldest two evicted.
        for port in 40_001..=40_004 {
            table.handle(&client_syn(port), PG_PORT);
        }
        assert_eq!(table.map.len(), 4);
        table.next_sweep = table.clock;
        table.maybe_sweep();
        assert_eq!(table.map.len(), 2, "capped to max_connections");
        // Evicting live connections closes them in the registry.
        assert_eq!(metrics.snapshot().conns_live, 2);
    }

    #[test]
    fn both_endpoints_on_monitored_port_are_ignored() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        let mut seg = client_syn(40_010);
        seg.src_port = PG_PORT; // both ends on PG_PORT
        table.handle(&seg, PG_PORT);
        assert_eq!(table.map.len(), 0);
        assert_eq!(metrics.snapshot().conns_opened, 0);
    }

    #[test]
    fn bare_ack_on_unknown_tuple_creates_no_connection() {
        let metrics = Arc::new(Metrics::new());
        let mut table = ConnTable::with_metrics(metrics.clone());
        // A stray payload-less ACK/RST arriving for a 4-tuple we never opened.
        table.handle(&segment(true, false, false, &[]), PG_PORT);
        assert_eq!(table.map.len(), 0);
        assert_eq!(metrics.snapshot().conns_opened, 0);
    }
}
