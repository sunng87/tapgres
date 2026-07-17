# tapgres

Tap a local PostgreSQL connection and decode its wire traffic.

![tapgres TUI](screenshots/screenshot-splash.png)

`tapgres` reassembles each PostgreSQL connection and decodes it with the
[`pgwire`](https://crates.io/crates/pgwire) protocol layer into readable
stdout or an interactive TUI. It has two traffic sources, selected with
`--mode`:

- **`pcap`** (default) — passively captures a local port with libpcap.
  Cleartext only.
- **`mitm`** — a local TLS-terminating proxy, so you can decode **encrypted**
  sessions too. Point your client at it; it decrypts and forwards to the real
  server.

Add `--tui` to either source for a full-screen, scrollable, filterable view.
Display filters, live connection metrics, and a Wireshark-style `-Y` filter
work across both.

## Quick start

```sh
tapgres                                  # monitor loopback :5432 (the defaults)
tapgres -p 5432 -i eth0                  # capture a specific interface
tapgres --mode mitm \                    # decode an encrypted session via the proxy
  --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432
tapgres --tui -Y 'message.type == "Query"'   # interactive view, filtered
tapgres --save session.jsonl                  # capture and tee every record to disk
tapgres --replay session.jsonl --tui          # reopen it without live capture
```

For making a client trust the mitm proxy's auto-generated CA, see
`man tapgres`. A sample of the decoded output (`F→B` is client→server,
`B→F` the reverse):

```
[F→B] Query: SELECT id, name FROM users
[B→F] RowDescription: id(oid=23), name(oid=25)
[B→F] DataRow: { id=1, name='alice' }
[B→F] ReadyForQuery: txn=idle
```

pcap mode needs capture privileges — grant them once instead of running as
root:

```sh
sudo setcap cap_net_raw+ep $(which tapgres)
```

## Interactive TUI (`--tui`)

![tapgres TUI: live connection metrics, rate sparkline, and decoded PostgreSQL traffic](screenshots/screenshot-tui.png)

| Key | Action |
| --- | ------ |
| `q` / `Ctrl-C` | quit |
| `j`/`k`, arrows, `PgUp`/`PgDn` | scroll |
| `g` / `G` | top / bottom |
| `f` | follow (auto-tail) |
| `w` / `r` | wrap / rich display |
| `c` | clear |
| `y` | edit the display filter |
| `/` / `:` | command bar (`:save FILE`, `:open FILE`) |
| `Esc` | clear the display filter |

Display filters (`-Y` / `--display-filter`) use a small typed expression
language with fields like `message.type`, `message.text`, `client.ip`, and
`client.port`. See `man tapgres` for the full field and operator reference.

## Save and replay

`--save FILE` continuously writes every output record to versioned JSONL while
stdout or the TUI continues normally. Recording happens before display
filtering and before the TUI's 50,000-record history cap, so hidden or evicted
live records are still saved. An existing destination is replaced.

`--replay FILE` uses a saved session instead of pcap/mitm capture. Replay is
instant, preserves the original timestamps and structured rich-view data, and
passes through the same display filters and renderers as live traffic:

```sh
tapgres --replay session.jsonl
tapgres --replay session.jsonl --tui --tui-rich
tapgres --replay session.jsonl -Y 'message.type == "Query"'
```

In the TUI, `/` or `:` opens the command bar. `:save FILE` (also `:w`) writes
the currently retained events and then continuously records future traffic.
If older events have already left the TUI history, the footer reports the
omission. `:open FILE` (also `:o`) validates the complete file, replaces the
current view with its newest 50,000 records, and switches the session to replay
mode. It closes any active recorder, and subsequent live-source records are
discarded so live and replayed timelines never mix.

Schema version 1 and its compatibility rules are defined in
[`docs/session-format.md`](docs/session-format.md). Unsupported schema versions
and malformed records are refused with a file and line-numbered error.

## Installation

**Prebuilt binary** (Linux x86_64, from
[releases](https://github.com/sunng87/tapgres/releases)):

```sh
curl -L -o tapgres https://github.com/sunng87/tapgres/releases/latest/download/tapgres-linux-x86_64
chmod +x tapgres && sudo mv tapgres /usr/local/bin/
```

Built with Nix; on a non-Nix Linux it needs `libpcap.so.1` on the library path.

**Arch Linux (AUR):**

```sh
paru -S tapgres-bin
```

**Nix (flake):**

```sh
nix run github:sunng87/tapgres -- --help      # try it without installing
nix profile install github:sunng87/tapgres    # or install it
```

**Build from source** (libpcap required — `libpcap-dev` on Debian/Ubuntu):

```sh
cargo install --path .
```

A manual page is included in the Nix and Arch packages (`man tapgres`).

## Develop

```sh
nix develop   # Rust toolchain + libpcap + PostgreSQL 18
cargo test
```

The manpage's options come from the clap CLI definition, and the rest of its
prose lives in `man/sections.md` (Markdown). Regenerate it after any change —
it needs `pandoc`, which the Nix shell above provides:

```sh
cargo run --example gen_manpage > man/tapgres.1
```

## License

MIT. See [LICENSE](LICENSE).
