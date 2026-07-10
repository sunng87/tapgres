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
#[derive(Clone)]
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
        if let Output::Line(s) = record {
            CAPTURE.with(|c| c.borrow_mut().as_mut().unwrap().push(s));
        }
        return;
    }
    if let Some(tx) = &*OUTPUT_TX.lock().unwrap() {
        let _ = tx.send(record); // unbounded channel: never blocks
        return;
    }
    // No consumer wired: fall back to direct terminal output.
    match record {
        Output::Line(s) => println!("{s}"),
        Output::Status(s) => eprintln!("{s}"),
    }
}

/// Emit one decoded protocol line. Routed to the output consumer, or stdout if
/// none is wired.
pub fn out(line: String) {
    deliver(Output::Line(line));
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
            match PgWireFrontendMessage::decode(&mut dir.rxbuf, &dir.ctx) {
                Ok(None) => return,
                Ok(Some(msg)) => {
                    if !handle_frontend(dir, msg, outcome) {
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
            match PgWireBackendMessage::decode(&mut dir.rxbuf, &dir.ctx) {
                Ok(None) => return,
                Ok(Some(msg)) => handle_backend(dir, msg, outcome),
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
fn handle_frontend(
    dir: &mut Direction,
    msg: PgWireFrontendMessage,
    outcome: &mut DrainOutcome,
) -> bool {
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

/// Handle one backend message.
fn handle_backend(dir: &mut Direction, msg: PgWireBackendMessage, outcome: &mut DrainOutcome) {
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
            emit(Role::Server, "RowDescription", &format_row_desc(&summary));
            dir.row_desc = Some(summary);
        }
        PgWireBackendMessage::NoData(_) => {
            dir.row_desc = None;
            emit(Role::Server, "NoData", "");
        }
        PgWireBackendMessage::DataRow(r) => emit(
            Role::Server,
            "DataRow",
            &format_data_row(&r, dir.row_desc.as_deref()),
        ),
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
    format!("{}  <-  {}  params: [{}]", portal, stmt, params.join(", "))
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

fn format_data_row(r: &DataRow, desc: Option<&[FieldSummary]>) -> String {
    let mut b: &[u8] = &r.data;
    let mut values: Vec<String> = Vec::with_capacity(r.field_count.max(0) as usize);

    for i in 0..r.field_count.max(0) {
        if b.remaining() < 4 {
            values.push("<?>".into());
            break;
        }
        let len = b.get_i32();
        if len < 0 {
            values.push("NULL".into());
            continue;
        }
        let len = len as usize;
        if b.remaining() < len {
            values.push("<?>".into());
            break;
        }
        let bytes = &b[..len];
        b.advance(len);
        let binary = desc
            .and_then(|d| d.get(i as usize))
            .map(|f| f.format_code == FORMAT_CODE_BINARY)
            .unwrap_or(false);
        values.push(if binary {
            hex_preview(bytes)
        } else {
            quote(bytes)
        });
    }

    if let Some(d) = desc {
        let labelled: Vec<String> = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let name = d.get(i).map(|f| f.name.as_str()).unwrap_or("?");
                format!("{}={}", name, v)
            })
            .collect();
        format!("{{ {} }}", labelled.join(", "))
    } else {
        format!("[{}]", values.join(", "))
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
