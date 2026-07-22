# SAVED SESSIONS

`--save FILE` continuously writes every output record as versioned JSONL while
normal stdout or TUI rendering continues. Recording occurs before display
filtering and before the TUI history cap, so hidden and evicted live records
remain in the saved session. Operational line/status records are saved along
with decoded PostgreSQL messages. An existing destination file is replaced.

`--replay FILE` reads a saved session instead of starting pcap or mitm. Records
are replayed immediately through the same stdout/TUI renderer and display
filter as live traffic. Original capture timestamps, client address, direction,
message type/text, and rich RowDescription/DataRow details are preserved. A
replay can be copied to another file with `--save`; the input and output paths
must differ.

The TUI command bar opens with `/` or `:`. `:save FILE` (`:w FILE`) writes the
currently retained history and continuously records future events. If earlier
events have left the 50,000-record TUI history, a footer warning reports the
omission. `:open FILE` (`:o FILE`) validates the complete file before replacing
the view, retains its newest 50,000 records, switches the UI to replay mode, and
closes any active recorder. Subsequent live-source display records are discarded
so timelines do not mix.

The current on-disk schema version is 1. Each JSONL record carries its own
`schema_version` and RFC 3339 timestamp. Unknown versions and malformed records
are refused with the file path and line number; tapgres does not guess at an
incompatible shape. The full format is documented in `docs/session-format.md`
in the source repository.

# DISPLAY FILTER EXPRESSIONS

The `-Y` / `--display-filter` option limits decoded PostgreSQL messages in
line-oriented output and supplies the initial display filter in `--tui` mode.
The `-Y` shorthand mirrors Wireshark's display filters. Its value is parsed
once at startup; a parse error is fatal for stdout mode and is reported in the
TUI footer (the last valid filter stays active).

The expression language is a small, typed subset of Wireshark display-filter
syntax: named fields are compared with operators and combined with boolean
connectives. Capture errors and connection lifecycle notices are operational
context, not decoded protocol messages, so they are never filtered out.

## Fields

`client.ip`
: IP address. Example: `client.ip == 127.0.0.1`

`client.port`
: integer. Example: `client.port in {40005, 40006}`

`message.type`
: string. Example: `message.type == "Query"`. A decoded pgwire message type,
  e.g. Query, Parse, Bind, DataRow, RowDescription, ReadyForQuery.

`message.text`
: string. Example: `message.text contains "orders"`. The text payload: the SQL
  statement for Query, the cached column value for a single-column DataRow, etc.

`message.direction`
: `"f2b"` or `"b2f"`. Example: `message.direction == "b2f"`. f2b is client
  (frontend) to server (backend); b2f is the reverse.

## Operators

`==`, `!=`
: Equality and inequality. Valid for every field. String and direction
  comparisons are case-sensitive.

`in {value, ...}`
: Set membership. Values must match the field's type; a quoted-string set for
  string/direction fields, a bare-integer or IP set for numeric/address fields.

`contains`
: Case-sensitive substring test. Valid only for the string fields
  `message.type` and `message.text`.

`matches`
: Case-insensitive, unanchored regular-expression match. Valid only for the
  string fields. Use a raw string such as `r"orders\s+WHERE"` so backslashes
  reach the regex engine unescaped.

## Combining predicates

Combine predicates with `and` / `&&`, `or` / `||`, and `not` / `!`, grouped
with parentheses. Precedence, highest to lowest: `not`, then `and`, then `or`.
String values must be double-quoted; backslash escapes (`\n`, `\r`, `\t`,
`\"`, `\\`) are honoured in ordinary strings.

## In the TUI

Press `y` to edit the display filter. A valid edit is applied immediately to
the full retained message buffer, so previously hidden messages reappear when
the filter changes. An empty filter (or `Esc`) clears it. The message-view
border is green normally, yellow while a filter is active, and red while the
input is invalid.

# EXAMPLES

Monitor port 5432 on loopback (the defaults):

    tapgres

Capture on a specific interface:

    tapgres -p 5432 -i eth0

Run the local TLS-terminating proxy against an upstream server:

    tapgres --mode mitm --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432

Interactive view with an initial display filter:

    tapgres --tui -Y 'message.type in {"Query", "DataRow"} and message.text contains "orders"'

Show only server-to-client errors and notices:

    tapgres -Y 'message.direction == "b2f" and message.type matches "^Error|Notice$"'

Tee every decoded record to a versioned JSONL session while still capturing
live. Recording happens before display filtering and the TUI history cap:

    tapgres --save session.jsonl

Reopen a saved session in the TUI without starting capture:

    tapgres --replay session.jsonl --tui

Replay recorded traffic through a display filter, exactly as with a live tap:

    tapgres --replay session.jsonl -Y 'message.type == "Query"'

Grant capture privileges without running as root (pcap mode):

    sudo setcap cap_net_raw+ep $(which tapgres)

# EXIT STATUS

tapgres exits 0 on a clean shutdown. A fatal capture/proxy error or an invalid
`--display-filter` expression is reported on stderr and exits non-zero.

# SEE ALSO

psql(1), pg_dump(1). Project home and full documentation:
<https://github.com/sunng87/tapgres>
