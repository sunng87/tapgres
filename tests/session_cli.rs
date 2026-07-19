//! CLI integration coverage for the durable JSONL session source.

use std::process::Command;

use tapgres::decode::{EventDetail, FieldSummary, Output};
use tapgres::filter::{DisplayMessage, MessageDirection};
use tapgres::session::{self, SessionWriter};

fn message(kind: &str, text: &str, direction: MessageDirection) -> Output {
    let tag = match direction {
        MessageDirection::FrontendToBackend => "F→B",
        MessageDirection::BackendToFrontend => "B→F",
    };
    Output::Message {
        message: DisplayMessage {
            timestamp: "2026-07-17T12:34:56.789+01:00".into(),
            rendered: format!("[12:34:56.789] [{tag}] {kind}: {text}"),
            client: "127.0.0.1:40005".parse().unwrap(),
            direction,
            kind: kind.into(),
            text: text.into(),
        },
        detail: (kind == "RowDescription").then(|| {
            EventDetail::RowDescription(vec![FieldSummary {
                name: "id".into(),
                type_oid: 23,
                format_code: 0,
            }])
        }),
    }
}

fn write_fixture(path: &std::path::Path) {
    let mut writer = SessionWriter::create(path).unwrap();
    writer
        .write(&Output::Status("saved session".into()))
        .unwrap();
    writer
        .write(&message(
            "Query",
            "SELECT * FROM orders",
            MessageDirection::FrontendToBackend,
        ))
        .unwrap();
    writer
        .write(&message(
            "RowDescription",
            "id(oid=23, text)",
            MessageDirection::BackendToFrontend,
        ))
        .unwrap();
    writer.flush().unwrap();
}

#[test]
fn replay_uses_the_normal_stdout_filter_path() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.jsonl");
    write_fixture(&input);

    let result = Command::new(env!("CARGO_BIN_EXE_tapgres"))
        .args([
            "--replay",
            input.to_str().unwrap(),
            "--display-filter",
            "message.type == \"Query\"",
        ])
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stdout.contains("Query: SELECT * FROM orders"));
    assert!(!stdout.contains("RowDescription"));
    assert!(stderr.contains("saved session"));
}

#[test]
fn save_records_unfiltered_replay_stream() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.jsonl");
    let output = dir.path().join("copy.jsonl");
    write_fixture(&input);

    let result = Command::new(env!("CARGO_BIN_EXE_tapgres"))
        .args([
            "--replay",
            input.to_str().unwrap(),
            "--save",
            output.to_str().unwrap(),
            "-Y",
            "message.type == \"Query\"",
        ])
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let saved = session::read_all(&output).unwrap();
    assert_eq!(saved.len(), 3);
    assert!(saved.iter().any(|record| matches!(
        record,
        Output::Message {
            message,
            detail: Some(EventDetail::RowDescription(columns)),
        } if message.kind == "RowDescription" && columns[0].type_oid == 23
    )));
}

#[test]
fn replay_refuses_to_overwrite_its_input() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.jsonl");
    write_fixture(&input);

    let result = Command::new(env!("CARGO_BIN_EXE_tapgres"))
        .args([
            "--replay",
            input.to_str().unwrap(),
            "--save",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("must not overwrite"));
    assert_eq!(session::read_all(&input).unwrap().len(), 3);
}

#[test]
fn replay_and_save_accept_relative_paths() {
    let dir = tempfile::tempdir().unwrap();
    write_fixture(&dir.path().join("capture.jsonl"));

    let result = Command::new(env!("CARGO_BIN_EXE_tapgres"))
        .current_dir(dir.path())
        .args(["--replay", "capture.jsonl", "--save", "copy.jsonl"])
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        session::read_all(dir.path().join("copy.jsonl"))
            .unwrap()
            .len(),
        3
    );
}

#[cfg(unix)]
#[test]
fn replay_refuses_hard_link_alias_as_save_target() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.jsonl");
    let alias = dir.path().join("same-file.jsonl");
    write_fixture(&input);
    std::fs::hard_link(&input, &alias).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_tapgres"))
        .args([
            "--replay",
            input.to_str().unwrap(),
            "--save",
            alias.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("must not overwrite"));
    assert_eq!(session::read_all(&input).unwrap().len(), 3);
}
