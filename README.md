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
| `/`, `n` / `N` | search message text, next / previous match |
| `:` | command bar (`:save FILE`, `:open FILE`) |
| `Esc` | clear the search, then the display filter |

Display filters (`-Y` / `--display-filter`) use a small typed expression
language with fields like `message.type`, `message.text`, `client.ip`, and
`client.port` (with `==`, `!=`, ordered `<`/`>` on the port, `in`, `contains`,
and `matches`). See `man tapgres` for the full field and operator reference.

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

> **Sensitive data.** Captures and saved sessions are cleartext: they contain
> query text, returned row values, connection parameters, and error messages
> exactly as they crossed the wire. Treat `--save` / `:save` files as sensitive
> and protect them accordingly. See [SECURITY.md](SECURITY.md).

## Installation

**Prebuilt binaries** (from
[releases](https://github.com/sunng87/tapgres/releases):
`tapgres-linux-x86_64`, `tapgres-linux-aarch64`, `tapgres-macos-x86_64`,
`tapgres-macos-arm64`; a `SHA256SUMS` file in each release covers all of
them):

```sh
curl -L -o tapgres https://github.com/sunng87/tapgres/releases/latest/download/tapgres-linux-x86_64
chmod +x tapgres && sudo mv tapgres /usr/local/bin/
```

The linux-x86_64 binary is built with Nix; on a non-Nix Linux it needs
`libpcap.so.1` on the library path (see
[Troubleshooting](#troubleshooting)).

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

## Troubleshooting

**"Permission denied" opening the capture (Linux).** pcap mode needs
`CAP_NET_RAW`. Grant it once instead of running as root:

```sh
sudo setcap cap_net_raw+ep $(which tapgres)
```

**"Permission denied" opening the capture (macOS).** macOS captures packets
through the BPF devices (`/dev/bpf0`, `/dev/bpf1`, …), which are root-only by
default — and `setcap` is a Linux mechanism that does not exist on macOS.
Either run `sudo tapgres`, or install Wireshark's **ChmodBPF** helper
(bundled with the Wireshark installer, or standalone via
`brew install --cask wireshark-chmodbpf`). ChmodBPF installs a launch daemon
that makes `/dev/bpf*` readable by the `access_bpf` group at every boot; make
sure your user is in that group. Note that this grants every group member
capture access to *all* interfaces, not just loopback.

**macOS refuses to run a downloaded binary** ("cannot be opened because the
developer cannot be verified", or the process is killed immediately). The
release binaries are not code-signed; if your download path added the
quarantine attribute, remove it:

```sh
xattr -d com.apple.quarantine ./tapgres
```

**No traffic appears.**

- `psql` and many other clients connect over a **Unix domain socket** when no
  host is given — invisible to pcap. Force TCP with `-h 127.0.0.1`.
- tapgres captures the **loopback** interface by default (`lo` on Linux,
  `lo0` on macOS). For a server on another machine, pick the right interface
  with `-i eth0`. libpcap's `any` pseudo-device (`-i any`) captures every
  interface at once but is **Linux-only**.
- If the client negotiated **TLS** (`sslmode=require`, …), pcap mode can
  observe the SSL negotiation but not the encrypted stream that follows. Use
  `--mode mitm` to decode encrypted sessions.

**Clients reject the mitm proxy's certificate.** In `--mode mitm`, tapgres
terminates TLS with an auto-generated CA written to `--tls-dir` (default
`~/.config/tapgres`). Point each client at that CA: copy `ca.crt` to the client
and connect with `sslrootcert=…/ca.crt` and `sslmode=verify-ca`, for example

```sh
psql "host=127.0.0.1 port=15432 dbname=postgres sslrootcert=ca.crt sslmode=verify-ca"
```

Distribute only `ca.crt`; `ca.key` is the CA's private key and must stay local.

**`libpcap.so.1: cannot open shared object file`** when running a prebuilt
Linux binary: install your distribution's libpcap runtime package
(`libpcap0.8` on Debian/Ubuntu, `libpcap` on Arch and Fedora).

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
