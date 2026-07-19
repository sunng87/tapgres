//! Versioned JSONL persistence for decoded tapgres sessions.
//!
//! Each line is an independent record with a schema version, capture
//! timestamp, record kind, and the structured fields needed by display
//! filters and rich TUI rendering. Replayed records are converted back into
//! [`crate::decode::Output`] so live and file sources share the same renderer.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, LineWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chrono::{Local, SecondsFormat};
use serde::{Deserialize, Serialize};

use crate::decode::{DataColumn, EventDetail, FieldSummary, Output};
use crate::filter::{DisplayMessage, MessageDirection};

/// Current on-disk JSONL schema. Readers refuse every other version so a
/// future incompatible shape cannot be silently misinterpreted.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub enum SessionError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    InvalidRecord {
        path: PathBuf,
        line: usize,
        message: String,
    },
    UnsupportedSchema {
        path: PathBuf,
        line: usize,
        found: u32,
    },
    Encode {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::InvalidRecord {
                path,
                line,
                message,
            } => write!(
                f,
                "{}: invalid JSONL record at line {line}: {message}",
                path.display()
            ),
            Self::UnsupportedSchema { path, line, found } => write!(
                f,
                "{}: unsupported schema version {found} at line {line} (supported: {SCHEMA_VERSION})",
                path.display()
            ),
            Self::Encode { path, source } => {
                write!(
                    f,
                    "{}: could not encode JSONL record: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Encode { source, .. } => Some(source),
            Self::InvalidRecord { .. } | Self::UnsupportedSchema { .. } => None,
        }
    }
}

/// A streaming JSONL writer. It owns the file so a live consumer can record
/// every event before display filtering or in-memory history eviction.
pub struct SessionWriter {
    path: PathBuf,
    writer: LineWriter<File>,
}

impl SessionWriter {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, SessionError> {
        let path = path.as_ref().to_path_buf();
        let file = File::create(&path).map_err(|source| SessionError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Self {
            path,
            // Flush on every completed JSONL line. Recording is opt-in, and
            // this prevents the final buffered events from disappearing when
            // a long-running CLI capture is stopped with Ctrl-C.
            writer: LineWriter::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&mut self, output: &Output) -> Result<(), SessionError> {
        let record = StoredRecord::from_output(output);
        serde_json::to_writer(&mut self.writer, &record).map_err(|source| {
            SessionError::Encode {
                path: self.path.clone(),
                source,
            }
        })?;
        self.writer
            .write_all(b"\n")
            .map_err(|source| SessionError::Io {
                path: self.path.clone(),
                source,
            })
    }

    pub fn flush(&mut self) -> Result<(), SessionError> {
        self.writer.flush().map_err(|source| SessionError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

impl Drop for SessionWriter {
    fn drop(&mut self) {
        let _ = self.writer.flush();
    }
}

/// Load a complete saved session. The TUI uses this for `:open`, where the
/// current retained view is replaced atomically only after all lines validate.
pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<Output>, SessionError> {
    let mut outputs = Vec::new();
    read_with(path, |output| outputs.push(output))?;
    Ok(outputs)
}

/// Validate a complete session while retaining only its newest `cap` records.
/// The TUI uses this to keep replay memory bounded without exposing a partial
/// file if a later line is malformed.
pub fn read_tail(path: impl AsRef<Path>, cap: usize) -> Result<(Vec<Output>, usize), SessionError> {
    let mut outputs = VecDeque::with_capacity(cap.min(4_096));
    let mut dropped = 0usize;
    read_with(path, |output| {
        if cap == 0 {
            dropped = dropped.saturating_add(1);
            return;
        }
        if outputs.len() == cap {
            outputs.pop_front();
            dropped = dropped.saturating_add(1);
        }
        outputs.push_back(output);
    })?;
    Ok((outputs.into(), dropped))
}

/// Stream a session into a consumer without first retaining the entire file.
/// This is the CLI replay path and keeps large transcripts bounded.
pub fn read_with(
    path: impl AsRef<Path>,
    mut consume: impl FnMut(Output),
) -> Result<(), SessionError> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(|source| SessionError::Io {
        path: path.clone(),
        source,
    })?;
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| SessionError::Io {
            path: path.clone(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|source| SessionError::InvalidRecord {
                path: path.clone(),
                line: line_number,
                message: source.to_string(),
            })?;
        let found = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(|| SessionError::InvalidRecord {
                path: path.clone(),
                line: line_number,
                message: "schema_version must be an unsigned 32-bit integer".into(),
            })?;
        if found != SCHEMA_VERSION {
            return Err(SessionError::UnsupportedSchema {
                path,
                line: line_number,
                found,
            });
        }
        let record: StoredRecord =
            serde_json::from_value(value).map_err(|source| SessionError::InvalidRecord {
                path: path.clone(),
                line: line_number,
                message: source.to_string(),
            })?;
        consume(record.into_output(&path, line_number)?);
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRecord {
    schema_version: u32,
    timestamp: String,
    #[serde(flatten)]
    payload: StoredPayload,
}

impl StoredRecord {
    fn from_output(output: &Output) -> Self {
        let (timestamp, payload) = match output {
            Output::Message { message, detail } => (
                message.timestamp.clone(),
                StoredPayload::Message {
                    direction: StoredDirection::from(message.direction),
                    message_type: message.kind.clone(),
                    text: message.text.clone(),
                    rendered: message.rendered.clone(),
                    client: message.client.to_string(),
                    detail: detail.as_ref().map(StoredDetail::from),
                },
            ),
            Output::Line(text) => (now_timestamp(), StoredPayload::Line { text: text.clone() }),
            Output::Status(text) => (
                now_timestamp(),
                StoredPayload::Status { text: text.clone() },
            ),
        };
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp,
            payload,
        }
    }

    fn into_output(self, path: &Path, line: usize) -> Result<Output, SessionError> {
        chrono::DateTime::parse_from_rfc3339(&self.timestamp).map_err(|error| {
            SessionError::InvalidRecord {
                path: path.to_path_buf(),
                line,
                message: format!("timestamp must be RFC 3339: {error}"),
            }
        })?;
        match self.payload {
            StoredPayload::Message {
                direction,
                message_type,
                text,
                rendered,
                client,
                detail,
            } => {
                let client =
                    client
                        .parse::<SocketAddr>()
                        .map_err(|error| SessionError::InvalidRecord {
                            path: path.to_path_buf(),
                            line,
                            message: format!("invalid client address {client:?}: {error}"),
                        })?;
                Ok(Output::Message {
                    message: DisplayMessage {
                        timestamp: self.timestamp,
                        rendered,
                        client,
                        direction: direction.into(),
                        kind: message_type,
                        text,
                    },
                    detail: detail.map(Into::into),
                })
            }
            StoredPayload::Line { text } => Ok(Output::Line(text)),
            StoredPayload::Status { text } => Ok(Output::Status(text)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum StoredPayload {
    Message {
        direction: StoredDirection,
        message_type: String,
        text: String,
        rendered: String,
        client: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<StoredDetail>,
    },
    Line {
        text: String,
    },
    Status {
        text: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StoredDirection {
    F2b,
    B2f,
}

impl From<MessageDirection> for StoredDirection {
    fn from(value: MessageDirection) -> Self {
        match value {
            MessageDirection::FrontendToBackend => Self::F2b,
            MessageDirection::BackendToFrontend => Self::B2f,
        }
    }
}

impl From<StoredDirection> for MessageDirection {
    fn from(value: StoredDirection) -> Self {
        match value {
            StoredDirection::F2b => Self::FrontendToBackend,
            StoredDirection::B2f => Self::BackendToFrontend,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "detail_type", rename_all = "snake_case")]
enum StoredDetail {
    RowDescription { columns: Vec<StoredFieldSummary> },
    DataRow { columns: Vec<StoredDataColumn> },
}

impl From<&EventDetail> for StoredDetail {
    fn from(value: &EventDetail) -> Self {
        match value {
            EventDetail::RowDescription(columns) => Self::RowDescription {
                columns: columns.iter().map(StoredFieldSummary::from).collect(),
            },
            EventDetail::DataRow(columns) => Self::DataRow {
                columns: columns.iter().map(StoredDataColumn::from).collect(),
            },
        }
    }
}

impl From<StoredDetail> for EventDetail {
    fn from(value: StoredDetail) -> Self {
        match value {
            StoredDetail::RowDescription { columns } => {
                Self::RowDescription(columns.into_iter().map(Into::into).collect())
            }
            StoredDetail::DataRow { columns } => {
                Self::DataRow(columns.into_iter().map(Into::into).collect())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredFieldSummary {
    name: String,
    type_oid: u32,
    format_code: i16,
}

impl From<&FieldSummary> for StoredFieldSummary {
    fn from(value: &FieldSummary) -> Self {
        Self {
            name: value.name.clone(),
            type_oid: value.type_oid,
            format_code: value.format_code,
        }
    }
}

impl From<StoredFieldSummary> for FieldSummary {
    fn from(value: StoredFieldSummary) -> Self {
        Self {
            name: value.name,
            type_oid: value.type_oid,
            format_code: value.format_code,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredDataColumn {
    name: String,
    type_oid: u32,
    value: String,
}

impl From<&DataColumn> for StoredDataColumn {
    fn from(value: &DataColumn) -> Self {
        Self {
            name: value.name.clone(),
            type_oid: value.type_oid,
            value: value.value.clone(),
        }
    }
}

impl From<StoredDataColumn> for DataColumn {
    fn from(value: StoredDataColumn) -> Self {
        Self {
            name: value.name,
            type_oid: value.type_oid,
            value: value.value,
        }
    }
}

fn now_timestamp() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn message_output() -> Output {
        Output::Message {
            message: DisplayMessage {
                timestamp: "2026-07-17T12:34:56.789+01:00".into(),
                rendered: "[12:34:56.789] [B→F] DataRow: { id='1' }".into(),
                client: "127.0.0.1:40005".parse().unwrap(),
                direction: MessageDirection::BackendToFrontend,
                kind: "DataRow".into(),
                text: "{ id='1' }".into(),
            },
            detail: Some(EventDetail::DataRow(vec![DataColumn {
                name: "id".into(),
                type_oid: 23,
                value: "'1'".into(),
            }])),
        }
    }

    #[test]
    fn jsonl_round_trip_preserves_filter_and_rich_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.jsonl");
        let records = vec![
            Output::Status("capture active".into()),
            message_output(),
            Output::Line("=== connection closed ===".into()),
        ];
        {
            let mut writer = SessionWriter::create(&path).unwrap();
            for record in &records {
                writer.write(record).unwrap();
            }
            writer.flush().unwrap();
        }

        let raw = fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 3);
        assert!(raw.contains("\"schema_version\":1"));
        assert!(raw.contains("\"record_type\":\"message\""));
        assert!(raw.contains("\"detail_type\":\"data_row\""));

        let loaded = read_all(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        match &loaded[1] {
            Output::Message { message, detail } => {
                assert_eq!(message.timestamp, "2026-07-17T12:34:56.789+01:00");
                assert_eq!(message.client.port(), 40005);
                assert_eq!(message.kind, "DataRow");
                match detail {
                    Some(EventDetail::DataRow(columns)) => {
                        assert_eq!(columns[0].name, "id");
                        assert_eq!(columns[0].type_oid, 23);
                        assert_eq!(columns[0].value, "'1'");
                    }
                    other => panic!("expected DataRow detail, got {other:?}"),
                }
            }
            other => panic!("expected message, got {other:?}"),
        }
    }

    #[test]
    fn refuses_unknown_schema_without_partial_tui_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.jsonl");
        fs::write(
            &path,
            r#"{"schema_version":99,"timestamp":"now","record_type":"line","text":"future"}
"#,
        )
        .unwrap();

        let error = read_all(&path).unwrap_err().to_string();
        assert!(error.contains("unsupported schema version 99"));
        assert!(error.contains("line 1"));
    }

    #[test]
    fn reports_malformed_json_with_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"schema_version\":1,\"timestamp\":\"2026-07-17T12:34:56.789+01:00\",\"record_type\":\"line\",\"text\":\"valid\"}\n",
                "not json\n"
            ),
        )
        .unwrap();

        let error = read_all(&path).unwrap_err().to_string();
        assert!(error.contains("line 2"));
    }

    #[test]
    fn rejects_non_rfc3339_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-time.jsonl");
        fs::write(
            &path,
            r#"{"schema_version":1,"timestamp":"12:34","record_type":"line","text":"bad"}
"#,
        )
        .unwrap();

        let error = read_all(&path).unwrap_err().to_string();
        assert!(error.contains("timestamp must be RFC 3339"));
        assert!(error.contains("line 1"));
    }

    #[test]
    fn tail_reader_validates_all_records_while_bounding_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("many.jsonl");
        let mut writer = SessionWriter::create(&path).unwrap();
        for index in 0..5 {
            writer
                .write(&Output::Line(format!("line {index}")))
                .unwrap();
        }
        writer.flush().unwrap();

        let (tail, dropped) = read_tail(&path, 2).unwrap();
        assert_eq!(dropped, 3);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].rendered(), "line 3");
        assert_eq!(tail[1].rendered(), "line 4");
    }

    #[test]
    fn reads_the_committed_v1_compatibility_fixture() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session-v1.jsonl");
        let records = read_all(path).unwrap();

        assert_eq!(records.len(), 4);
        assert!(matches!(
            records[2].detail(),
            Some(EventDetail::RowDescription(columns)) if columns[0].name == "id"
        ));
        assert!(matches!(
            records[3].detail(),
            Some(EventDetail::DataRow(columns)) if columns[0].value == "'1'"
        ));
    }
}
