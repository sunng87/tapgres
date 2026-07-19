# Tapgres saved-session format

Tapgres saves sessions as UTF-8 JSON Lines (JSONL): one complete JSON object per
line. Version 1 is designed to round-trip every `decode::Output` variant through
the same display-filter and rendering pipeline used by live capture.

The format is local and stream-oriented. `--save` and `:save` replace an
existing destination, then record events before display filtering or TUI
history eviction. Files may contain sensitive SQL, credentials, errors, and
returned row values and should be protected accordingly.

## Common fields

Every line contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | unsigned integer | Version of this record shape; currently `1`. |
| `timestamp` | RFC 3339 string | Original message capture time, or record time for operational lines/status. |
| `record_type` | string | `message`, `line`, or `status`. |

Blank lines are ignored. A malformed record aborts replay with the file path and
line number.

## Message records

A decoded PostgreSQL message contains the structured values required by display
filters and rich rendering:

```json
{"schema_version":1,"timestamp":"2026-07-17T12:34:56.789+01:00","record_type":"message","direction":"f2b","message_type":"Query","text":"SELECT * FROM orders","rendered":"[12:34:56.789] [F→B] Query: SELECT * FROM orders","client":"127.0.0.1:40005"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `direction` | string | `f2b` for frontend/client to backend/server, or `b2f` for the reverse. |
| `message_type` | string | Decoded pgwire message name, such as `Query` or `DataRow`. |
| `text` | string | Decoded message body used by `message.text` filters. |
| `rendered` | string | Stable flat terminal representation, including the original display timestamp. |
| `client` | socket-address string | Owning connection's client IP and port. |
| `detail` | object, optional | Structured rich-rendering payload described below. |

### Rich detail

`RowDescription` preserves field names, PostgreSQL type OIDs, and format codes:

```json
{"detail_type":"row_description","columns":[{"name":"id","type_oid":23,"format_code":0}]}
```

`DataRow` preserves its already-decoded display value alongside the cached
column name and type OID:

```json
{"detail_type":"data_row","columns":[{"name":"id","type_oid":23,"value":"'1'"}]}
```

The detail object is nested under the message record's `detail` field. Keeping
both forms allows replay to reproduce rich tables without re-decoding pgwire
bytes while retaining the stable flat transcript.

## Operational records

Connection/capture lines and status records retain their original text:

```json
{"schema_version":1,"timestamp":"2026-07-17T12:34:56.789+01:00","record_type":"line","text":"=== new connection 127.0.0.1:40005 -> 127.0.0.1:5432 ==="}
{"schema_version":1,"timestamp":"2026-07-17T12:34:56.790+01:00","record_type":"status","text":"tapgres: capturing on 'lo'"}
```

They remain outside display filtering, matching live behavior.

## Compatibility policy

- Tapgres writes only the current schema version.
- Version 1 readers require `schema_version: 1` on every non-blank line.
- Unknown older or newer versions are refused; there is no silent best-effort
  conversion.
- A future incompatible shape must increment `schema_version` and provide an
  explicit migration path if backward compatibility is desired.
- Replay preserves recorded `rendered` output rather than reformatting it, while
  filters and rich mode use the structured fields.
