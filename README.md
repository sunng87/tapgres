# pgwiretap

Passively monitor a local PostgreSQL port and decode its wire traffic to stdout.

`pgwiretap` captures TCP traffic with libpcap, reassembles each connection, and
decodes it with the [`pgwire`](https://crates.io/crates/pgwire) protocol layer.

> Cleartext connections only. If SSL/GSS is negotiated and accepted, the stream
> goes opaque and decoding stops. A refused negotiation (common — most clients
> ask for SSL by default) keeps decoding in cleartext.

## Example

```
=== new connection  127.0.0.1:40005 -> 127.0.0.1:55432 (port 55432) ===
[F→B] SSLRequest: (awaiting server reply)
[B→F] SslResponse: refuse (continuing in cleartext)
[F→B] Startup: protocol 3.0  user=pgtest, database=postgres
[F→B] Query: SELECT id, name FROM users
[B→F] RowDescription: id(oid=23, text), name(oid=25, text)
[B→F] DataRow: { id=1, name='alice' }
[B→F] CommandComplete: SELECT 1
[B→F] ReadyForQuery: txn=idle
```

`F→B` is the client (frontend) → server (backend); `B→F` is the reverse.

## Usage

```
pgwiretap -p 5432                 # monitor port 5432 on loopback (default)
pgwiretap -p 5432 -i eth0         # capture on a specific interface
pgwiretap -p 5432 -i any          # capture on all interfaces
pgwiretap --help                  # all options
```

Capturing requires privileges (`CAP_NET_RAW` or root):

```sh
sudo setcap cap_net_raw+ep $(which pgwiretap)
```

## Install

```sh
# Nix
nix build && ./result/bin/pgwiretap -p 5432

# Cargo (libpcap must be installed, e.g. libpcap-dev on Debian/Ubuntu)
cargo install --path .
```

## Develop

```sh
nix develop   # Rust toolchain + libpcap
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
