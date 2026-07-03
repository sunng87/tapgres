//! Offline end-to-end test: encode real pgwire messages, split them into
//! synthetic TCP segments (including out-of-order delivery and a
//! retransmission), feed the connection tracker, and assert the decoded output.
//!
//! This validates the whole pipeline — link parsing aside — without needing
//! packet-capture privileges.

use std::net::{IpAddr, Ipv4Addr};

use bytes::{BufMut, BytesMut};

use pgwire::messages::PgWireBackendMessage as Bm;
use pgwire::messages::PgWireFrontendMessage as Fm;
use pgwire::messages::SslNegotiationMetaMessage;
use pgwire::messages::data::{DataRow, FORMAT_CODE_TEXT, FieldDescription, RowDescription};
use pgwire::messages::response::{
    CommandComplete, GssEncResponse, ReadyForQuery, SslResponse, TransactionStatus,
};
use pgwire::messages::simplequery::Query;
use pgwire::messages::startup::{
    Authentication, BackendKeyData, GssEncRequest, ParameterStatus, SecretKey, SslRequest, Startup,
};

use pgwiretap::decode;
use pgwiretap::flow::ConnTable;
use pgwiretap::net::TcpSegment;

const CLI: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const SRV: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const PG_PORT: u16 = 55432;

fn seg(
    src: IpAddr,
    sp: u16,
    dst: IpAddr,
    dp: u16,
    seq: u32,
    syn: bool,
    payload: &[u8],
) -> TcpSegment {
    TcpSegment {
        src,
        dst,
        src_port: sp,
        dst_port: dp,
        seq,
        ack: 0,
        syn,
        fin: false,
        rst: false,
        payload: payload.to_vec(),
    }
}

#[test]
fn replay_cleartext_simple_query_session() {
    // ---- build the client→server byte stream from real pgwire messages ----
    let mut fb = BytesMut::new();
    let mut startup = Startup::new();
    startup.parameters.insert("user".into(), "pgtest".into());
    startup
        .parameters
        .insert("database".into(), "postgres".into());
    startup
        .parameters
        .insert("client_encoding".into(), "UTF8".into());
    Fm::Startup(startup).encode(&mut fb).unwrap();
    Fm::Query(Query::new("SELECT 1 AS a, 'two' AS b".into()))
        .encode(&mut fb)
        .unwrap();
    Fm::Terminate(Default::default()).encode(&mut fb).unwrap();

    // ---- build the server→client byte stream ----
    let mut bb = BytesMut::new();
    Bm::Authentication(Authentication::Ok)
        .encode(&mut bb)
        .unwrap();
    Bm::ParameterStatus(ParameterStatus::new("server_version".into(), "18.4".into()))
        .encode(&mut bb)
        .unwrap();
    Bm::ParameterStatus(ParameterStatus::new(
        "client_encoding".into(),
        "UTF8".into(),
    ))
    .encode(&mut bb)
    .unwrap();
    Bm::BackendKeyData(BackendKeyData::new(42, SecretKey::I32(99)))
        .encode(&mut bb)
        .unwrap();
    Bm::ReadyForQuery(ReadyForQuery::new(TransactionStatus::Idle))
        .encode(&mut bb)
        .unwrap();

    let mut row_desc = RowDescription::new(vec![
        FieldDescription::new("a".into(), 0, 0, 23, 4, -1, FORMAT_CODE_TEXT),
        FieldDescription::new("b".into(), 0, 0, 25, -1, -1, FORMAT_CODE_TEXT),
    ]);
    let _ = &mut row_desc; // silence unused_mut if it ever becomes unused
    Bm::RowDescription(row_desc).encode(&mut bb).unwrap();

    let mut row = BytesMut::new();
    row.put_i32(1);
    row.put_slice(b"1");
    row.put_i32(3);
    row.put_slice(b"two");
    Bm::DataRow(DataRow::new(row, 2)).encode(&mut bb).unwrap();
    Bm::CommandComplete(CommandComplete::new("SELECT 1".into()))
        .encode(&mut bb)
        .unwrap();
    Bm::ReadyForQuery(ReadyForQuery::new(TransactionStatus::Idle))
        .encode(&mut bb)
        .unwrap();

    // ---- split each stream into two chunks (to exercise reassembly) ----
    let fa = fb.len() / 2;
    let (c_a, c_b) = fb.split_at(fa); // c_a: first half, c_b: second half

    let sa = bb.len() / 2;
    let (s_a, s_b) = bb.split_at(sa);

    let isn_c: u32 = 1_000;
    let isn_s: u32 = 2_000;

    decode::start_capture();
    let mut table = ConnTable::new();

    // TCP handshake.
    table.handle(&seg(CLI, 40001, SRV, PG_PORT, isn_c, true, &[]), PG_PORT);
    table.handle(&seg(SRV, PG_PORT, CLI, 40001, isn_s, true, &[]), PG_PORT);

    // Client data delivered OUT OF ORDER: the later chunk arrives first.
    table.handle(
        &seg(
            CLI,
            40001,
            SRV,
            PG_PORT,
            isn_c.wrapping_add(1).wrapping_add(c_a.len() as u32),
            false,
            c_b,
        ),
        PG_PORT,
    );
    // Server data arrives in order.
    table.handle(
        &seg(SRV, PG_PORT, CLI, 40001, isn_s + 1, false, s_a),
        PG_PORT,
    );
    // Now the client's first chunk arrives and flushes the buffered one.
    table.handle(
        &seg(CLI, 40001, SRV, PG_PORT, isn_c + 1, false, c_a),
        PG_PORT,
    );
    // Server's second chunk.
    table.handle(
        &seg(
            SRV,
            PG_PORT,
            CLI,
            40001,
            isn_s + 1 + s_a.len() as u32,
            false,
            s_b,
        ),
        PG_PORT,
    );
    // A pure retransmission of the client's first chunk — must be ignored.
    table.handle(
        &seg(CLI, 40001, SRV, PG_PORT, isn_c + 1, false, c_a),
        PG_PORT,
    );

    let lines = decode::take_capture();
    let joined = lines.join("\n");

    println!("---- decoded output ----\n{joined}\n----");

    assert_contains(&joined, "new connection");
    assert_contains(&joined, "Startup");
    assert_contains(&joined, "user=pgtest");
    assert_contains(&joined, "database=postgres");
    assert_contains(&joined, "Query: SELECT 1 AS a, 'two' AS b");
    assert_contains(&joined, "Authentication: Ok");
    assert_contains(&joined, "ParameterStatus: server_version=18.4");
    assert_contains(&joined, "BackendKeyData: pid=42");
    assert_contains(&joined, "RowDescription");
    assert_contains(&joined, "a(oid=23, text)");
    assert_contains(&joined, "b(oid=25, text)");
    assert_contains(&joined, "DataRow");
    assert_contains(&joined, "a='1'");
    assert_contains(&joined, "b='two'");
    assert_contains(&joined, "CommandComplete: SELECT 1");
    assert_contains(&joined, "ReadyForQuery: txn=idle");
    assert_contains(&joined, "Terminate");

    assert!(
        !joined.contains("decode error"),
        "no decode errors expected, got: {joined}"
    );
}

/// Feeds an in-order sequence of payloads for one direction, tracking
/// sequence numbers (including the SYN's consumed sequence) so each segment
/// lands exactly where the reassembler expects it.
struct Feeder {
    seq: u32,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
}
impl Feeder {
    fn client(isn: u32, sport: u16) -> Self {
        Self {
            seq: isn,
            src: CLI,
            sport,
            dst: SRV,
            dport: PG_PORT,
        }
    }
    fn server(isn: u32, sport: u16) -> Self {
        Self {
            seq: isn,
            src: SRV,
            sport: PG_PORT,
            dst: CLI,
            dport: sport,
        }
    }
    fn syn(&mut self, table: &mut ConnTable) {
        table.handle(
            &seg(
                self.src,
                self.sport,
                self.dst,
                self.dport,
                self.seq,
                true,
                &[],
            ),
            PG_PORT,
        );
        self.seq = self.seq.wrapping_add(1); // SYN consumes a sequence number
    }
    fn data(&mut self, table: &mut ConnTable, payload: &[u8]) {
        let len = payload.len() as u32;
        table.handle(
            &seg(
                self.src, self.sport, self.dst, self.dport, self.seq, false, payload,
            ),
            PG_PORT,
        );
        self.seq = self.seq.wrapping_add(len);
    }
}

/// The real-world case this project exists to handle: the client sends
/// SSLRequest first (as psql and most drivers do by default), the server
/// refuses with a single 'N' byte, and the connection then proceeds in
/// cleartext — which we must decode end to end.
#[test]
fn replay_ssl_refused_then_cleartext() {
    // client→server: SSLRequest, Startup, Query, Terminate
    let mut fb = BytesMut::new();
    Fm::SslNegotiation(SslNegotiationMetaMessage::PostgresSsl(SslRequest::new()))
        .encode(&mut fb)
        .unwrap();
    let mut startup = Startup::new();
    startup.parameters.insert("user".into(), "pgtest".into());
    Fm::Startup(startup).encode(&mut fb).unwrap();
    Fm::Query(Query::new("SELECT 42".into()))
        .encode(&mut fb)
        .unwrap();
    Fm::Terminate(Default::default()).encode(&mut fb).unwrap();

    // server→client: 'N' (refuse SSL), then the normal cleartext startup flow
    let mut bb = BytesMut::new();
    Bm::SslResponse(SslResponse::Refuse)
        .encode(&mut bb)
        .unwrap();
    Bm::Authentication(Authentication::Ok)
        .encode(&mut bb)
        .unwrap();
    Bm::ReadyForQuery(ReadyForQuery::new(TransactionStatus::Idle))
        .encode(&mut bb)
        .unwrap();
    Bm::CommandComplete(CommandComplete::new("SELECT 1".into()))
        .encode(&mut bb)
        .unwrap();

    decode::start_capture();
    let mut table = ConnTable::new();
    let mut c = Feeder::client(7_000, 40005);
    let mut s = Feeder::server(8_000, 40005);

    c.syn(&mut table);
    s.syn(&mut table);
    // client: SSLRequest (arms the server direction for the 1-byte reply)
    let (ssl_req, rest_c) = fb.split_at(8);
    c.data(&mut table, ssl_req);
    // server: refuse byte
    let (refuse, rest_s) = bb.split_at(1);
    s.data(&mut table, refuse);
    // client: rest (Startup + Query + Terminate)
    c.data(&mut table, rest_c);
    // server: rest (Auth Ok, ReadyForQuery, CommandComplete)
    s.data(&mut table, rest_s);

    let joined = decode::take_capture().join("\n");
    println!("---- ssl-refused output ----\n{joined}\n----");

    assert_contains(&joined, "SSLRequest");
    assert_contains(&joined, "SslResponse: refuse (continuing in cleartext)");
    assert_contains(&joined, "Startup");
    assert_contains(&joined, "Query: SELECT 42");
    assert_contains(&joined, "Authentication: Ok");
    assert_contains(&joined, "CommandComplete: SELECT 1");
    assert_contains(&joined, "Terminate");
    assert!(
        !joined.contains("encrypted"),
        "refused SSL must NOT mark the connection encrypted: {joined}"
    );
    assert!(
        !joined.contains("decode error"),
        "no decode errors expected: {joined}"
    );
}

/// Opposite case: the server accepts SSL. The stream then goes opaque, so we
/// emit the request + an "encrypted" notice and must NOT try to decode the
/// subsequent TLS handshake bytes.
#[test]
fn replay_ssl_accepted_stops_decoding() {
    let mut fb = BytesMut::new();
    Fm::SslNegotiation(SslNegotiationMetaMessage::PostgresSsl(SslRequest::new()))
        .encode(&mut fb)
        .unwrap();
    // Fake TLS ClientHello bytes that follow the accept — these must be
    // ignored, not decoded as pgwire.
    fb.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00]);
    // A stray "Startup"-ish payload that must never be decoded.
    fb.extend_from_slice(b"garbage-not-a-real-startup-message");

    let mut bb = BytesMut::new();
    Bm::SslResponse(SslResponse::Accept)
        .encode(&mut bb)
        .unwrap();
    bb.extend_from_slice(&[0x16, 0x03, 0x03]); // TLS ServerHello

    decode::start_capture();
    let mut table = ConnTable::new();
    let mut c = Feeder::client(9_000, 40006);
    let mut s = Feeder::server(9_500, 40006);

    c.syn(&mut table);
    s.syn(&mut table);

    let (ssl_req, tls_c) = fb.split_at(8);
    c.data(&mut table, ssl_req);
    let (accept, tls_s) = bb.split_at(1);
    s.data(&mut table, accept);
    // Subsequent opaque bytes on both sides — must be ignored after encryption.
    c.data(&mut table, tls_c);
    s.data(&mut table, tls_s);

    let joined = decode::take_capture().join("\n");
    println!("---- ssl-accepted output ----\n{joined}\n----");

    assert_contains(&joined, "SSLRequest");
    assert_contains(&joined, "SSL accepted");
    assert!(
        !joined.contains("Startup"),
        "must not decode TLS bytes as Startup: {joined}"
    );
    assert!(
        !joined.contains("Query"),
        "must not decode anything after accept: {joined}"
    );
    assert!(
        !joined.contains("decode error"),
        "must not even attempt to decode opaque TLS bytes: {joined}"
    );
}

/// Same idea for GSS, which shares the 1-byte refuse path.
#[test]
fn replay_gss_refused_then_cleartext() {
    let mut fb = BytesMut::new();
    Fm::SslNegotiation(SslNegotiationMetaMessage::PostgresGss(GssEncRequest::new()))
        .encode(&mut fb)
        .unwrap();
    let mut startup = Startup::new();
    startup.parameters.insert("user".into(), "pgtest".into());
    Fm::Startup(startup).encode(&mut fb).unwrap();

    let mut bb = BytesMut::new();
    Bm::GssEncResponse(GssEncResponse::Refuse)
        .encode(&mut bb)
        .unwrap();
    Bm::Authentication(Authentication::Ok)
        .encode(&mut bb)
        .unwrap();

    decode::start_capture();
    let mut table = ConnTable::new();
    let mut c = Feeder::client(10_000, 40007);
    let mut s = Feeder::server(11_000, 40007);
    c.syn(&mut table);
    s.syn(&mut table);
    let (gss_req, rest_c) = fb.split_at(8);
    c.data(&mut table, gss_req);
    let (refuse, rest_s) = bb.split_at(1);
    s.data(&mut table, refuse);
    c.data(&mut table, rest_c);
    s.data(&mut table, rest_s);

    let joined = decode::take_capture().join("\n");
    assert_contains(&joined, "GssEncRequest");
    assert_contains(&joined, "GssEncResponse: refuse (continuing in cleartext)");
    assert_contains(&joined, "Startup");
    assert_contains(&joined, "Authentication: Ok");
    assert!(!joined.contains("encrypted"));
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected decoded output to contain {needle:?}\n--- output ---\n{haystack}"
    );
}
