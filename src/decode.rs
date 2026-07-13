//! pgwire message decoding and human-readable rendering.
//!
//! Each [`crate::flow::Direction`] owns a byte buffer; [`drain_direction`]
//! repeatedly asks the pgwire protocol layer to decode the next message and
//! prints a one-line, human-readable summary. The frontend direction also
//! advances the SSL / startup state machine (see `DecodeContext`).

use std::cell::RefCell;
use std::fmt::Write as _;
use std::sync::Mutex;

use crossbeam_channel::Sender;

use bytes::{Buf, Bytes};
use chrono::Local;

use crate::flow::{Direction, Role};

// Pull in only the protocol-layer message definitions.
use pgwire::messages::data::{DataRow, FORMAT_CODE_BINARY, FORMAT_CODE_TEXT, FieldDescription};
use pgwire::messages::extendedquery::{Bind, Execute, Parse};
use pgwire::messages::response::{GssEncResponse, SslResponse, TransactionStatus};
use pgwire::messages::simplequery::Query;
use pgwire::messages::startup::{
    Authentication, BackendKeyData, NegotiateProtocolVersion, PasswordMessageFamily, SecretKey,
    Startup,
};
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage, SslNegotiationMetaMessage};

/// A stripped-down description of one result column, kept so that `DataRow`s
/// can be labelled and rendered with the right (text/binary) format.
#[derive(Clone, Debug)]
pub struct FieldSummary {
    pub name: String,
    pub type_oid: u32,
    pub format_code: i16,
}

impl From<&FieldDescription> for FieldSummary {
    fn from(f: &FieldDescription) -> Self {
        FieldSummary {
            name: f.name.clone(),
            type_oid: f.type_id,
            format_code: f.format_code,
        }
    }
}

/// Structured rendering detail for a decoded message, consumed by the TUI's
/// *rich* display mode. The flat line-view text is always produced as well,
/// so non-TUI consumers and the line view are unaffected; this just lets the
/// TUI draw certain messages (a `DataRow` as a key/value table, a
/// `RowDescription` as a typed column list) instead of that flat line.
#[derive(Clone, Debug)]
pub enum EventDetail {
    /// A `RowDescription`: the result columns' names, type OIDs and format.
    RowDescription(Vec<FieldSummary>),
    /// A `DataRow`: each value paired with its column name and type OID. The
    /// names/types come from the connection's cached `RowDescription`, so
    /// this is only emitted while one is cached (otherwise the flat line view
    /// is used, since there is nothing to key the table on).
    DataRow(Vec<DataColumn>),
}

/// One decoded cell of a `DataRow`, labelled with its column metadata and
/// pre-formatted for display (text values quoted, binary values hex-encoded).
#[derive(Clone, Debug)]
pub struct DataColumn {
    pub name: String,
    pub type_oid: u32,
    pub value: String,
}

/// Current wall-clock time, for log line prefixes.
pub fn ts() -> String {
    Local::now().format("%H:%M:%S%.3f").to_string()
}

// --- output routing -------------------------------------------------------
//
// The decoder never decides *where* its output goes. `out`/`status` push onto
// a single multi-producer channel (`OUTPUT_TX`); a consumer chosen at startup
// owns the receiver — a stdout-printer thread for the line-oriented path, or
// the TUI app loop for `--tui`. So the decoder is fully sink-agnostic, and the
// stdout/stderr split (`Line`→stdout, `Status`→stderr) is preserved by the
// consumer rather than baked into the decoder.
//
// Thread-local `CAPTURE` is a higher-priority short-circuit so the integration
// tests can assert decoded output without spinning up a consumer.
thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// What kind of output a record is, so the consumer can route it (decoded lines
/// to stdout, status to stderr) without re-parsing the text.
#[derive(Debug, Clone)]
pub enum Output {
    /// A decoded protocol line.
    Line(String),
    /// A status/informational line.
    Status(String),
    /// A decoded protocol line plus structured `detail` the TUI may render in
    /// rich mode. `text` is the same line-view string the other variants
    /// carry; stdout consumers just print `text` and ignore `detail`.
    Rich { text: String, detail: EventDetail },
}

/// The global producer handle. `None` (the default) means no consumer is wired
/// and `out`/`status` print directly to stdout/stderr.
static OUTPUT_TX: Mutex<Option<Sender<Output>>> = Mutex::new(None);

/// Install the channel producers write to. The matching receiver is owned by
/// whichever consumer is active (stdout-printer thread, or the TUI).
pub fn set_output(tx: Sender<Output>) {
    *OUTPUT_TX.lock().unwrap() = Some(tx);
}

/// Drop the producer handle so the consumer observes end-of-stream and can
/// flush/drain.
pub fn close_output() {
    *OUTPUT_TX.lock().unwrap() = None;
}

fn deliver(record: Output) {
    // Tests capture decoded lines locally (no consumer thread / channel).
    let buffered = CAPTURE.with(|c| c.borrow().is_some());
    if buffered {
        // The line-view text is what tests assert on; `Rich` carries that same
        // text, so capture it like a `Line` and drop the structured detail.
        match record {
            Output::Line(s) | Output::Rich { text: s, .. } => {
                CAPTURE.with(|c| c.borrow_mut().as_mut().unwrap().push(s));
            }
            Output::Status(_) => {}
        }
        return;
    }
    if let Some(tx) = &*OUTPUT_TX.lock().unwrap() {
        let _ = tx.send(record); // unbounded channel: never blocks
        return;
    }
    // No consumer wired: fall back to direct terminal output.
    match record {
        Output::Line(s) | Output::Rich { text: s, .. } => println!("{s}"),
        Output::Status(s) => eprintln!("{s}"),
    }
}

/// Emit one decoded protocol line. Routed to the output consumer, or stdout if
/// none is wired.
pub fn out(line: String) {
    deliver(Output::Line(line));
}

/// Emit a decoded protocol line with structured `detail` for the TUI's rich
/// mode. `line` is exactly the text the line view would show; stdout consumers
/// print it unchanged.
pub fn out_rich(line: String, detail: EventDetail) {
    deliver(Output::Rich { text: line, detail });
}

/// Emit a status/informational line. On the stdout path it goes to stderr; under
/// `--tui` it appears in the list alongside decoded lines.
pub fn status(msg: String) {
    deliver(Output::Status(msg));
}

/// Begin capturing decoded output into a buffer (for tests).
pub fn start_capture() {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

/// Finish capturing and return the buffered lines.
pub fn take_capture() -> Vec<String> {
    CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default())
}

fn dir_tag(role: Role) -> &'static str {
    if role == Role::Client {
        "F→B"
    } else {
        "B→F"
    }
}

fn emit(role: Role, kind: &str, text: &str) {
    if text.is_empty() {
        out(format!("[{}] [{}] {}", ts(), dir_tag(role), kind));
    } else {
        out(format!("[{}] [{}] {}: {}", ts(), dir_tag(role), kind, text));
    }
}

/// Like [`emit`] but attaches structured `detail` for rich-mode rendering.
/// The line text is built identically to [`emit`].
fn emit_rich(role: Role, kind: &str, text: &str, detail: EventDetail) {
    let line = if text.is_empty() {
        format!("[{}] [{}] {}", ts(), dir_tag(role), kind)
    } else {
        format!("[{}] [{}] {}: {}", ts(), dir_tag(role), kind, text)
    };
    out_rich(line, detail);
}

fn warn(role: Role, msg: &str) {
    out(format!("[{}] [{}] ⚠ {}", ts(), dir_tag(role), msg));
}

/// Signal that the *server* side should now expect a 1-byte SSL or GSS
/// response, because the frontend just sent the matching request.
///
/// This is the crux of cleartext support: an SSLRequest from the client does
/// *not* mean the stream is encrypted — the server answers with one byte,
/// `'S'`/`'G'` (accept, then the connection goes opaque) or `'N'` (refuse,
/// connection stays cleartext). Only on accept do we give up.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerNegotiationWait {
    /// No pending negotiation response.
    #[default]
    None,
    /// Frontend sent SSLRequest; await the server's 1-byte SSL response.
    Ssl,
    /// Frontend sent GssEncRequest; await the server's 1-byte GSS response.
    Gss,
}

/// Result of draining one direction's buffer.
#[derive(Default)]
pub struct DrainOutcome {
    /// Set by the client direction when it just emitted an SSL/GSS request.
    pub server_negotiation_wait: ServerNegotiationWait,
    /// Set by the server direction when it observed an accepted SSL/GSS
    /// response — the connection is now encrypted.
    pub encrypted: bool,
    /// Number of pgwire messages decoded this drain (for the drained
    /// direction). The no-consume SSL/GSS "None" peek is excluded.
    pub msgs: u64,
    /// Wire bytes consumed by those decoded messages.
    pub bytes: u64,
}

/// Repeatedly decode messages from `dir`'s buffer until it runs dry.
///
/// See [`ServerNegotiationWait`] and [`DrainOutcome`] for how the caller learns
/// about the SSL/GSS negotiation handoff and encryption.
pub fn drain_direction(dir: &mut Direction, outcome: &mut DrainOutcome) {
    if outcome.encrypted {
        return;
    }
    if dir.role == Role::Client {
        loop {
            let before = dir.rxbuf.len();
            match PgWireFrontendMessage::decode(&mut dir.rxbuf, &dir.ctx) {
                Ok(None) => return,
                Ok(Some(msg)) => {
                    let consumed = before.saturating_sub(dir.rxbuf.len()) as u64;
                    if !handle_frontend(dir, msg, outcome, consumed) {
                        return;
                    }
                }
                Err(e) => {
                    decode_error(Role::Client, &e, &mut dir.rxbuf);
                    return;
                }
            }
        }
    } else {
        loop {
            let before = dir.rxbuf.len();
            match PgWireBackendMessage::decode(&mut dir.rxbuf, &dir.ctx) {
                Ok(None) => return,
                Ok(Some(msg)) => {
                    let consumed = before.saturating_sub(dir.rxbuf.len()) as u64;
                    handle_backend(dir, msg, outcome, consumed);
                }
                Err(e) => {
                    decode_error(Role::Server, &e, &mut dir.rxbuf);
                    return;
                }
            }
        }
    }
}

fn decode_error(role: Role, e: &pgwire::error::PgWireError, buf: &mut bytes::BytesMut) {
    // The buffer is out of sync with the protocol; rather than crash, report and
    // drop the remainder so a later, well-formed message can still be seen.
    out(format!(
        "[{}] [{}] ⚠ decode error ({} lost bytes): {}",
        role_dbg(role),
        dir_tag(role),
        buf.len(),
        e
    ));
    buf.clear();
}

fn role_dbg(role: Role) -> &'static str {
    if role == Role::Client {
        "client"
    } else {
        "server"
    }
}

/// Handle one frontend message. Returns `false` to stop draining.
///
/// `consumed` is the wire bytes the message took from the buffer; it is added
/// to the outcome counters for every real message. The SSL/GSS "None" variant
/// is a no-consume peek (the bytes stay for the next Startup decode) and is
/// not counted.
fn handle_frontend(
    dir: &mut Direction,
    msg: PgWireFrontendMessage,
    outcome: &mut DrainOutcome,
    consumed: u64,
) -> bool {
    let is_peek = matches!(
        msg,
        PgWireFrontendMessage::SslNegotiation(SslNegotiationMetaMessage::None)
    );
    if !is_peek {
        outcome.msgs += 1;
        outcome.bytes += consumed;
    }
    match msg {
        PgWireFrontendMessage::SslNegotiation(meta) => match meta {
            // Neither SSL nor GSS requested: clear the SSL-awaiting flag so the
            // next iteration decodes the Startup message. Nothing to print.
            SslNegotiationMetaMessage::None => {
                dir.ctx.awaiting_frontend_ssl = false;
            }
            // The client asked for SSL/GSS. This does NOT mean the connection
            // is encrypted yet — we must wait for the server's 1-byte reply.
            // Stop draining the client now (it blocks until the server answers)
            // and ask the caller to arm the server direction for the response.
            SslNegotiationMetaMessage::PostgresSsl(_) => {
                dir.ctx.awaiting_frontend_ssl = false;
                outcome.server_negotiation_wait = ServerNegotiationWait::Ssl;
                emit(Role::Client, "SSLRequest", "(awaiting server reply)");
                return false;
            }
            SslNegotiationMetaMessage::PostgresGss(_) => {
                dir.ctx.awaiting_frontend_ssl = false;
                outcome.server_negotiation_wait = ServerNegotiationWait::Gss;
                emit(Role::Client, "GssEncRequest", "(awaiting server reply)");
                return false;
            }
        },
        PgWireFrontendMessage::Startup(s) => {
            // Startup consumed: from now on bytes are typed frontend messages.
            dir.ctx.awaiting_frontend_startup = false;
            emit(Role::Client, "Startup", &format_startup(&s));
        }
        PgWireFrontendMessage::CancelRequest(_) => {
            emit(Role::Client, "CancelRequest", "");
        }
        PgWireFrontendMessage::Query(q) => {
            emit(Role::Client, "Query", &query_text(&q));
        }
        PgWireFrontendMessage::Parse(p) => emit(Role::Client, "Parse", &format_parse(&p)),
        PgWireFrontendMessage::Bind(b) => emit(Role::Client, "Bind", &format_bind(&b)),
        PgWireFrontendMessage::Describe(d) => emit(
            Role::Client,
            "Describe",
            &format_describe_close(d.target_type, &d.name),
        ),
        PgWireFrontendMessage::Execute(e) => emit(Role::Client, "Execute", &format_execute(&e)),
        PgWireFrontendMessage::Close(c) => emit(
            Role::Client,
            "Close",
            &format_describe_close(c.target_type, &c.name),
        ),
        PgWireFrontendMessage::Sync(_) => emit(Role::Client, "Sync", ""),
        PgWireFrontendMessage::Flush(_) => emit(Role::Client, "Flush", ""),
        PgWireFrontendMessage::Terminate(_) => emit(Role::Client, "Terminate", ""),
        PgWireFrontendMessage::PasswordMessageFamily(pmf) => {
            emit(Role::Client, "AuthData", &format_pmf(&pmf))
        }
        PgWireFrontendMessage::CopyData(c) => {
            emit(Role::Client, "CopyData", &format_bytes(&c.data))
        }
        PgWireFrontendMessage::CopyFail(f) => emit(Role::Client, "CopyFail", &f.message),
        PgWireFrontendMessage::CopyDone(_) => emit(Role::Client, "CopyDone", ""),
        PgWireFrontendMessage::PortalSuspended(_) => emit(Role::Client, "PortalSuspended", ""),
    }
    true
}

/// Handle one backend message. Every backend message is a real, emitted
/// protocol event, so all of them are counted.
fn handle_backend(
    dir: &mut Direction,
    msg: PgWireBackendMessage,
    outcome: &mut DrainOutcome,
    consumed: u64,
) {
    outcome.msgs += 1;
    outcome.bytes += consumed;
    match msg {
        PgWireBackendMessage::Authentication(a) => {
            emit(Role::Server, "Authentication", &format_auth(&a))
        }
        PgWireBackendMessage::ParameterStatus(p) => emit(
            Role::Server,
            "ParameterStatus",
            &format!("{}={}", p.name, p.value),
        ),
        PgWireBackendMessage::BackendKeyData(b) => {
            emit(Role::Server, "BackendKeyData", &format_bkd(&b))
        }
        PgWireBackendMessage::NegotiateProtocolVersion(n) => emit(
            Role::Server,
            "NegotiateProtocolVersion",
            &format_negotiate(&n),
        ),
        PgWireBackendMessage::ReadyForQuery(r) => emit(
            Role::Server,
            "ReadyForQuery",
            &format!("txn={}", txn_status(r.status)),
        ),
        PgWireBackendMessage::CommandComplete(c) => emit(Role::Server, "CommandComplete", &c.tag),
        PgWireBackendMessage::EmptyQueryResponse(_) => emit(Role::Server, "EmptyQueryResponse", ""),
        PgWireBackendMessage::ErrorResponse(e) => {
            emit(Role::Server, "ERROR", &format_error_fields(&e.fields))
        }
        PgWireBackendMessage::NoticeResponse(n) => {
            emit(Role::Server, "NOTICE", &format_error_fields(&n.fields))
        }
        PgWireBackendMessage::NotificationResponse(n) => emit(
            Role::Server,
            "NOTIFY",
            &format!("channel={:?} payload={:?}", n.channel, n.payload),
        ),
        PgWireBackendMessage::RowDescription(r) => {
            let summary: Vec<FieldSummary> = r.fields.iter().map(FieldSummary::from).collect();
            emit_rich(
                Role::Server,
                "RowDescription",
                &format_row_desc(&summary),
                EventDetail::RowDescription(summary.clone()),
            );
            // Cache for subsequent `DataRow`s. NOT cleared at `ReadyForQuery`:
            // in the extended protocol a statement/portal is described once but
            // may be executed across many ReadyForQuery cycles, so the columns
            // must outlive a single command cycle.
            dir.row_desc = Some(summary);
        }
        PgWireBackendMessage::NoData(_) => {
            dir.row_desc = None;
            emit(Role::Server, "NoData", "");
        }
        PgWireBackendMessage::DataRow(r) => {
            // Pair the row with the cached description up front so we both
            // format the line-view text and build the structured columns from a
            // single pass over the payload.
            let desc = dir.row_desc.as_deref();
            let columns = data_row_columns(&r, desc);
            let text = format_columns(&columns, desc.is_some());
            if desc.is_some() {
                emit_rich(
                    Role::Server,
                    "DataRow",
                    &text,
                    EventDetail::DataRow(columns),
                );
            } else {
                // No cached description -> nothing to key a table on; emit the
                // flat line view only.
                emit(Role::Server, "DataRow", &text);
            }
        }
        PgWireBackendMessage::ParameterDescription(p) => {
            emit(Role::Server, "ParameterDescription", &format_oids(&p.types))
        }
        PgWireBackendMessage::ParseComplete(_) => emit(Role::Server, "ParseComplete", ""),
        PgWireBackendMessage::BindComplete(_) => emit(Role::Server, "BindComplete", ""),
        PgWireBackendMessage::CloseComplete(_) => emit(Role::Server, "CloseComplete", ""),
        PgWireBackendMessage::PortalSuspended(_) => emit(Role::Server, "PortalSuspended", ""),
        PgWireBackendMessage::SslResponse(s) => {
            // Consume the 1-byte response: this is one-shot, so clear the flag
            // regardless of the answer so normal messages decode afterwards.
            dir.ctx.awaiting_backend_ssl_response = false;
            match s {
                SslResponse::Accept => {
                    warn(
                        Role::Server,
                        "SSL accepted — connection is now encrypted, decoding stops here",
                    );
                    outcome.encrypted = true;
                }
                SslResponse::Refuse => {
                    emit(
                        Role::Server,
                        "SslResponse",
                        "refuse (continuing in cleartext)",
                    );
                }
                _ => {
                    emit(Role::Server, "SslResponse", "unknown");
                }
            }
        }
        PgWireBackendMessage::GssEncResponse(s) => {
            dir.ctx.awaiting_backend_gss_response = false;
            match s {
                GssEncResponse::Accept => {
                    warn(
                        Role::Server,
                        "GSS accepted — connection is now encrypted, decoding stops here",
                    );
                    outcome.encrypted = true;
                }
                GssEncResponse::Refuse => {
                    emit(
                        Role::Server,
                        "GssEncResponse",
                        "refuse (continuing in cleartext)",
                    );
                }
                _ => {
                    emit(Role::Server, "GssEncResponse", "unknown");
                }
            }
        }
        PgWireBackendMessage::CopyInResponse(c) => emit(
            Role::Server,
            "CopyInResponse",
            &format_copy_response("in", &c.columns),
        ),
        PgWireBackendMessage::CopyOutResponse(c) => emit(
            Role::Server,
            "CopyOutResponse",
            &format_copy_response("out", &c.columns),
        ),
        PgWireBackendMessage::CopyBothResponse(c) => emit(
            Role::Server,
            "CopyBothResponse",
            &format_copy_response("both", &c.columns),
        ),
        PgWireBackendMessage::CopyData(cd) => {
            emit(Role::Server, "CopyData", &format_bytes(&cd.data))
        }
        PgWireBackendMessage::CopyFail(f) => emit(Role::Server, "CopyFail", &f.message),
        PgWireBackendMessage::CopyDone(_) => emit(Role::Server, "CopyDone", ""),
    }
}

// ---------------------------------------------------------------------------
// Per-message formatting helpers
// ---------------------------------------------------------------------------

fn format_startup(s: &Startup) -> String {
    let mut out = format!(
        "protocol {}.{}",
        s.protocol_number_major, s.protocol_number_minor
    );
    if !s.parameters.is_empty() {
        out.push_str("  ");
        let kv: Vec<String> = s
            .parameters
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        out.push_str(&kv.join(", "));
    }
    out
}

fn query_text(q: &Query) -> String {
    q.query.clone()
}

fn format_parse(p: &Parse) -> String {
    let name = p.name.as_deref().unwrap_or("<unnamed>");
    let types = format_oids(&p.type_oids);
    format!("{}  [param types: {}]  {}", name, types, p.query)
}

fn format_bind(b: &Bind) -> String {
    let portal = b.portal_name.as_deref().unwrap_or("<unnamed>");
    let stmt = b.statement_name.as_deref().unwrap_or("<unnamed>");
    let all_text = b
        .parameter_format_codes
        .iter()
        .all(|&c| c == FORMAT_CODE_TEXT)
        || b.parameter_format_codes.is_empty();
    let all_binary = b
        .parameter_format_codes
        .iter()
        .all(|&c| c == FORMAT_CODE_BINARY);
    let params: Vec<String> = b
        .parameters
        .iter()
        .map(|p| match p {
            None => "NULL".to_string(),
            Some(bytes) => {
                if all_binary {
                    hex_preview(bytes)
                } else if all_text || is_printable(bytes) {
                    quote(bytes)
                } else {
                    hex_preview(bytes)
                }
            }
        })
        .collect();
    format!(
        "{}  <-  {}  params: [{}]  result: {}",
        portal,
        stmt,
        params.join(", "),
        format_format_codes(&b.result_column_format_codes),
    )
}

/// Render format codes (text=0, binary=1) compactly: `text`, `binary`, or a
/// per-column `[text, binary, ...]`.
fn format_format_codes(codes: &[i16]) -> String {
    if codes.is_empty() || codes.iter().all(|&c| c == FORMAT_CODE_TEXT) {
        "text".to_string()
    } else if codes.iter().all(|&c| c == FORMAT_CODE_BINARY) {
        "binary".to_string()
    } else {
        let parts: Vec<&str> = codes
            .iter()
            .map(|&c| {
                if c == FORMAT_CODE_BINARY {
                    "binary"
                } else {
                    "text"
                }
            })
            .collect();
        format!("[{}]", parts.join(", "))
    }
}

fn format_describe_close(target_type: u8, name: &Option<String>) -> String {
    let kind = match target_type {
        b'S' => "statement",
        b'P' => "portal",
        _ => "?",
    };
    format!("{} {}", kind, name.as_deref().unwrap_or("<unnamed>"))
}

fn format_execute(e: &Execute) -> String {
    let name = e.name.as_deref().unwrap_or("<unnamed>");
    if e.max_rows == 0 {
        name.to_string()
    } else {
        format!("{} (limit {})", name, e.max_rows)
    }
}

fn format_auth(a: &Authentication) -> String {
    match a {
        Authentication::Ok => "Ok".into(),
        Authentication::CleartextPassword => "CleartextPassword".into(),
        Authentication::KerberosV5 => "KerberosV5".into(),
        Authentication::MD5Password(_) => "MD5Password".into(),
        Authentication::SASL(methods) => format!("SASL [{}]", methods.join(", ")),
        Authentication::SASLContinue(_) => "SASLContinue".into(),
        Authentication::SASLFinal(_) => "SASLFinal".into(),
        _ => "Authentication".into(),
    }
}

fn format_bkd(b: &BackendKeyData) -> String {
    let key = match &b.secret_key {
        SecretKey::I32(i) => i.to_string(),
        SecretKey::Bytes(bs) => hex_preview(bs),
    };
    format!("pid={} key={}", b.pid, key)
}

fn format_negotiate(n: &NegotiateProtocolVersion) -> String {
    if n.unsupported_options.is_empty() {
        format!("negotiated minor protocol {}", n.newest_minor_protocol)
    } else {
        format!(
            "negotiated minor protocol {}; unsupported: [{}]",
            n.newest_minor_protocol,
            n.unsupported_options.join(", ")
        )
    }
}

fn txn_status(s: TransactionStatus) -> &'static str {
    match s {
        TransactionStatus::Idle => "idle",
        TransactionStatus::Transaction => "in-transaction",
        TransactionStatus::Error => "failed-transaction",
    }
}

fn format_error_fields(fields: &[(u8, String)]) -> String {
    let severity = field(fields, b'S')
        .or_else(|| field(fields, b'V'))
        .unwrap_or("ERROR");
    let code = field(fields, b'C').unwrap_or("");
    let message = field(fields, b'M').unwrap_or("");
    let mut out = format!("{}: {} [{}]", severity, message, code);
    if let Some(detail) = field(fields, b'D') {
        let _ = write!(out, "  detail: {}", detail);
    }
    if let Some(hint) = field(fields, b'H') {
        let _ = write!(out, "  hint: {}", hint);
    }
    out
}

fn format_pmf(pmf: &PasswordMessageFamily) -> String {
    match pmf {
        PasswordMessageFamily::Password(p) => format!("password (len={})", p.password.len()),
        PasswordMessageFamily::SASLInitialResponse(s) => format!(
            "SASL initial  mech={}  data-len={}",
            s.auth_method,
            s.data.as_ref().map(Bytes::len).unwrap_or(0)
        ),
        PasswordMessageFamily::SASLResponse(s) => format!("SASL continue (len={})", s.data.len()),
        PasswordMessageFamily::Raw(b) => format!("raw password-family message (len={})", b.len()),
        _ => "auth message".into(),
    }
}

fn format_row_desc(fields: &[FieldSummary]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|f| {
            let fmt = match f.format_code {
                FORMAT_CODE_TEXT => "text",
                FORMAT_CODE_BINARY => "binary",
                _ => "?",
            };
            format!("{}(oid={}, {})", f.name, f.type_oid, fmt)
        })
        .collect();
    parts.join(", ")
}

/// One field's worth of bytes read from a `DataRow` payload, or a marker that
/// the row ran out mid-field (so the remaining fields are unknown).
enum FieldRead<'a> {
    /// A SQL NULL (`-1` length).
    Null,
    /// `len` bytes of column data.
    Bytes(&'a [u8]),
    /// The payload was shorter than expected; no more fields can be read.
    Truncated,
}

/// Read one field from a `DataRow` payload. Returns the value and whether more
/// fields may follow (`false` once the payload is exhausted mid-field).
fn read_field<'a>(b: &mut &'a [u8]) -> (FieldRead<'a>, bool) {
    if b.remaining() < 4 {
        return (FieldRead::Truncated, false);
    }
    let len = b.get_i32();
    if len < 0 {
        return (FieldRead::Null, true);
    }
    let len = len as usize;
    if b.remaining() < len {
        return (FieldRead::Truncated, false);
    }
    let bytes = &b[..len];
    b.advance(len);
    (FieldRead::Bytes(bytes), true)
}

/// Decode a `DataRow` into one [`DataColumn`] per field, using `desc` for the
/// column name/type OID and to pick text-vs-binary rendering. On a truncated
/// payload the offending field becomes `<?>` and later fields are dropped,
/// matching the historical line formatter.
fn data_row_columns(r: &DataRow, desc: Option<&[FieldSummary]>) -> Vec<DataColumn> {
    let mut b: &[u8] = &r.data;
    let mut cols: Vec<DataColumn> = Vec::with_capacity(r.field_count.max(0) as usize);

    for i in 0..r.field_count.max(0) {
        let field = desc.and_then(|d| d.get(i as usize));
        let (read, more) = read_field(&mut b);
        let value = match read {
            FieldRead::Null => "NULL".to_string(),
            FieldRead::Truncated => "<?>".to_string(),
            FieldRead::Bytes(bytes) => {
                let binary = field
                    .map(|f| f.format_code == FORMAT_CODE_BINARY)
                    .unwrap_or(false);
                if binary {
                    hex_preview(bytes)
                } else {
                    quote(bytes)
                }
            }
        };
        cols.push(DataColumn {
            name: field
                .map(|f| f.name.clone())
                .unwrap_or_else(|| "?".to_string()),
            type_oid: field.map(|f| f.type_oid).unwrap_or(0),
            value,
        });
        if !more {
            break;
        }
    }
    cols
}

/// Render decoded columns as the line-view text. `labelled` selects the
/// `{ name=v, ... }` form (used when a `RowDescription` is cached) over the
/// nameless `[v, ...]` form. Kept byte-for-byte compatible with the original
/// inline formatter so existing assertions still hold.
fn format_columns(cols: &[DataColumn], labelled: bool) -> String {
    if labelled {
        let parts: Vec<String> = cols
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        format!("{{ {} }}", parts.join(", "))
    } else {
        let parts: Vec<String> = cols.iter().map(|c| c.value.clone()).collect();
        format!("[{}]", parts.join(", "))
    }
}

fn format_oids(oids: &[u32]) -> String {
    let parts: Vec<String> = oids.iter().map(|o| o.to_string()).collect();
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(", ")
    }
}

fn format_copy_response(dir: &str, columns: &i16) -> String {
    format!("copy {} ({} columns)", dir, columns)
}

// --- byte helpers ----------------------------------------------------------

fn field(fields: &[(u8, String)], ty: u8) -> Option<&str> {
    fields
        .iter()
        .find(|(k, _)| *k == ty)
        .map(|(_, v)| v.as_str())
}

fn is_printable(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| (32..127).contains(&c) || c == b'\t' || c == b'\n')
}

fn quote(b: &[u8]) -> String {
    if is_printable(b) {
        format!("'{}'", String::from_utf8_lossy(b))
    } else {
        hex_preview(b)
    }
}

fn hex_preview(b: &[u8]) -> String {
    const MAX: usize = 48;
    let n = b.len().min(MAX);
    let mut s = String::with_capacity(n * 2);
    for byte in &b[..n] {
        let _ = write!(s, "{:02x}", byte);
    }
    if b.len() > MAX {
        let _ = write!(s, "… ({} bytes)", b.len());
    }
    s
}

fn format_bytes(b: &Bytes) -> String {
    if is_printable(b) {
        String::from_utf8_lossy(b).into_owned()
    } else {
        hex_preview(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    fn field(name: &str, oid: u32, fmt: i16) -> FieldSummary {
        FieldSummary {
            name: name.into(),
            type_oid: oid,
            format_code: fmt,
        }
    }

    /// Build a `DataRow` payload from optional field bytes (`None` = SQL NULL).
    fn row_from(fields: &[Option<&[u8]>]) -> DataRow {
        let mut buf = BytesMut::new();
        for f in fields {
            match f {
                None => buf.put_i32(-1),
                Some(bytes) => {
                    buf.put_i32(bytes.len() as i32);
                    buf.put_slice(bytes);
                }
            }
        }
        DataRow::new(buf, fields.len() as i16)
    }

    #[test]
    fn data_row_columns_label_text_and_binary() {
        let desc = vec![
            field("id", 23, FORMAT_CODE_TEXT),
            field("blob", 17, FORMAT_CODE_BINARY),
        ];
        let row = row_from(&[Some(b"1"), Some(&[0x00, 0xff])]);
        let cols = data_row_columns(&row, Some(&desc));
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].name, "id");
        assert_eq!(cols[0].type_oid, 23);
        assert_eq!(cols[0].value, "'1'");
        assert_eq!(cols[1].name, "blob");
        assert_eq!(cols[1].type_oid, 17);
        assert_eq!(cols[1].value, "00ff"); // binary -> hex
    }

    #[test]
    fn data_row_columns_null_field() {
        let desc = vec![field("a", 23, FORMAT_CODE_TEXT)];
        let row = row_from(&[None]);
        let cols = data_row_columns(&row, Some(&desc));
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].value, "NULL");
    }

    #[test]
    fn data_row_columns_truncated_field_terminates_the_row() {
        // field_count claims 2, but the payload only holds one full field plus
        // a length prefix that promises bytes that never arrive.
        let desc = vec![
            field("a", 23, FORMAT_CODE_TEXT),
            field("b", 25, FORMAT_CODE_TEXT),
        ];
        let mut buf = BytesMut::new();
        buf.put_i32(1);
        buf.put_slice(b"1"); // field 0 complete
        buf.put_i32(99); // field 1 claims 99 bytes, but none follow
        let row = DataRow::new(buf, 2);
        let cols = data_row_columns(&row, Some(&desc));
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].value, "'1'");
        assert_eq!(cols[1].value, "<?>");
    }

    #[test]
    fn format_columns_labelled_and_plain_match_line_view() {
        let cols = vec![
            DataColumn {
                name: "a".into(),
                type_oid: 23,
                value: "'1'".into(),
            },
            DataColumn {
                name: "b".into(),
                type_oid: 25,
                value: "'two'".into(),
            },
        ];
        assert_eq!(format_columns(&cols, true), "{ a='1', b='two' }");
        assert_eq!(format_columns(&cols, false), "['1', 'two']");
    }

    #[test]
    fn data_row_columns_without_desc_use_placeholder_names() {
        let row = row_from(&[Some(b"x"), Some(b"y")]);
        let cols = data_row_columns(&row, None);
        assert_eq!(cols[0].name, "?");
        assert_eq!(cols[1].name, "?");
        assert_eq!(cols[0].value, "'x'");
        assert_eq!(cols[1].value, "'y'");
        assert_eq!(format_columns(&cols, false), "['x', 'y']");
    }
}
