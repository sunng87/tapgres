# Contributing to tapgres

Thanks for taking the time to help. tapgres is a small Rust CLI; the loop below
is all you need.

## Build and test

The supported toolchain is a Nix dev shell that pins the Rust toolchain,
`libpcap`, `pandoc`, and a local PostgreSQL 18 to point the tap at:

```sh
nix develop        # Rust toolchain + libpcap + PostgreSQL 18 + pandoc
cargo build
cargo test         # runs the unit and integration tests
```

Without Nix you need a Rust toolchain (edition 2024, so Rust >= 1.85 — the
`rust-version` in `Cargo.toml`) and libpcap's development headers
(`libpcap-dev` on Debian/Ubuntu, `libpcap` on Arch/Fedora):

```sh
cargo build
cargo test
```

Match CI before opening a PR:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## Regenerate the manpage

The manpage's options come from the clap CLI definition (`src/cli.rs`, the
single source of truth) and the prose in `man/sections.md`. It is generated,
never hand-edited, and needs `pandoc` (provided by the Nix shell). Regenerate it
after any change to the CLI or `man/sections.md`:

```sh
cargo run --example gen_manpage > man/tapgres.1
```

## Code layout

The reusable pieces live in the library crate (`src/lib.rs`); `src/main.rs`
wires them together with libpcap, and `tests/` exercises them directly.

| Module | Responsibility |
| --- | --- |
| `cli.rs` | clap CLI definition — the single source of truth for options and the manpage. |
| `net.rs` | Link-layer / TCP segment parsing (`TcpSegment`). |
| `flow.rs` | Per-connection tracking and TCP reassembly (`ConnTable`, `Direction`, `Role`). |
| `decode.rs` | pgwire message decoding and human-readable rendering (`Output`, `EventDetail`). |
| `filter.rs` | The `-Y` display-filter expression language (`DisplayFilter`, `DisplayMessage`). |
| `capture.rs` | The libpcap capture loop (`--mode pcap`). |
| `proxy.rs` | The TLS-terminating MITM proxy (`--mode mitm`). |
| `session.rs` | Versioned JSONL save/replay (`--save` / `--replay`); format in [`docs/session-format.md`](docs/session-format.md). |
| `state.rs` | Live connection/throughput metrics. |
| `tui.rs` | The ratatui full-screen view (`--tui`). |

## Pull requests

- Keep `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --all` green.
- Preserve the stated MSRV (`rust-version` in `Cargo.toml`); CI has an MSRV job.
- Regenerate the manpage if you touched `src/cli.rs` or `man/sections.md`.
- Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for any
  user-visible change.
- If you change the saved-session on-disk shape, bump `SCHEMA_VERSION` and
  update `docs/session-format.md` and the `tests/fixtures/session-v1.jsonl`
  expectations — the format is versioned deliberately.
- Report security-sensitive issues privately (see [`SECURITY.md`](SECURITY.md)),
  not in a public PR or issue.
