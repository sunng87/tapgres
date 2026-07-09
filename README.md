# tapgres

Tap a local PostgreSQL connection and decode its wire traffic to stdout.

`tapgres` reassembles each connection and decodes it with the
[`pgwire`](https://crates.io/crates/pgwire) protocol layer. It has two modes:

- **`pcap`** (default): passively captures traffic on a port with libpcap.
  Cleartext only — if SSL/GSS is negotiated and accepted the stream goes opaque
  and decoding stops. A refused negotiation keeps decoding in cleartext.
- **`mitm`**: runs a local TLS-terminating proxy so you can decode **encrypted**
  sessions too. Point your client at the proxy; it decrypts the client leg,
  decodes in the middle, and forwards to the real server.

`F→B` is the client (frontend) → server (backend); `B→F` is the reverse.

## pcap mode (default)

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

```
tapgres -p 5432                 # monitor port 5432 on loopback (default)
tapgres -p 5432 -i eth0         # capture on a specific interface
tapgres -p 5432 -i any          # capture on all interfaces
```

Capturing requires privileges (`CAP_NET_RAW` or root):

```sh
sudo setcap cap_net_raw+ep $(which tapgres)
```

## mitm mode (`--mode mitm`)

The proxy terminates TLS on the **client** leg and re-encrypts (or goes
cleartext) on the **upstream** leg. The decoded output is identical to pcap
mode, but it works against clients that require SSL (`sslmode=require`).

```
            TLS (client trusts tapgres CA)        TLS or cleartext
  psql  ───────────────────────────────►  tapgres  ──────────────────►  postgres
                                          ▲ decodes here ▲
```

1. Start the proxy against your server:

   ```
   tapgres --mode mitm --listen 127.0.0.1:15432 --upstream 127.0.0.1:5432
   ```

   On first run it generates a CA + server certificate (under
   `$XDG_CONFIG_HOME/tapgres`, or `~/.config/tapgres`) and prints where to find
   the CA. Bring your own cert with `--tls-cert`/`--tls-key` if you prefer.

2. Make the client trust the CA and point it at the proxy. For libpq/psql:

   ```sh
   cp ~/.config/tapgres/ca.crt ~/.postgresql/root.crt
   psql "host=127.0.0.1 port=15432 user=… sslmode=require sslrootcert=~/.postgresql/root.crt"
   ```

   The auto-generated leaf is valid for `localhost`, `127.0.0.1` and `::1`.

The upstream leg auto-negotiates TLS (it sends an `SSLRequest` and honors the
server's reply), so it works whether the server is cleartext or TLS. Pass
`--no-upstream-tls` to force a cleartext upstream. The proxy does **not** verify
the upstream certificate — it assumes a local, operator-controlled server.

> GSS encryption is refused (the client falls back); cancel requests are
> relayed verbatim.

## Install

```sh
# Nix
nix build && ./result/bin/tapgres --help

# Cargo (libpcap must be installed, e.g. libpcap-dev on Debian/Ubuntu)
cargo install --path .
```

## Develop

```sh
nix develop   # Rust toolchain + libpcap + PostgreSQL 18
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
