//! TCP stream reassembly and per-connection pgwire decode state.
//!
//! libpcap gives us individual, possibly reordered / retransmitted packets.
//! [`ConnTable`] tracks connections by their 4-tuple, reassembles each
//! direction in order, and feeds the resulting byte stream into the pgwire
//! message decoder.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use bytes::BytesMut;
use pgwire::messages::DecodeContext;

use crate::decode::{self, FieldSummary};
use crate::net::TcpSegment;

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
    fn new(role: Role) -> Self {
        Self {
            role,
            next_seq: None,
            ooo: BTreeMap::new(),
            rxbuf: BytesMut::with_capacity(8 * 1024),
            ctx: DecodeContext::default(),
            row_desc: None,
        }
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
}

impl Connection {
    fn new() -> Self {
        Self {
            client: Direction::new(Role::Client),
            server: Direction::new(Role::Server),
            encrypted: false,
        }
    }

    fn handle(&mut self, seg: &TcpSegment, pg_port: u16) {
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
        }
    }
}

/// The table of all active connections seen on the wire.
pub struct ConnTable {
    map: HashMap<ConnKey, Connection>,
}

impl Default for ConnTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
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

        let is_new = !self.map.contains_key(&key);
        if is_new {
            decode::out(format!(
                "[{}] === new connection  {}:{}  ->  {}:{}  (port {}) ===",
                decode::ts(),
                client.0,
                client.1,
                server.0,
                server.1,
                pg_port,
            ));
            self.map.insert(key, Connection::new());
        }

        if seg.rst {
            decode::out(format!("[{}] === connection reset (RST) ===", decode::ts()));
            self.map.remove(&key);
            return;
        }

        if let Some(conn) = self.map.get_mut(&key) {
            conn.handle(seg, pg_port);
        }
    }
}
