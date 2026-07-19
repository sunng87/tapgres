# Security Policy

## Scope and threat model

tapgres is a **local debugging tool**. It inspects PostgreSQL wire traffic on a
machine you control, either by passively capturing a port with libpcap
(`--mode pcap`) or by running a TLS-terminating man-in-the-middle proxy
(`--mode mitm`). It is not an authentication boundary, a production monitoring
agent, or a tool for intercepting traffic you do not own. Please only point it
at your own databases and connections.

Because of what it does, running tapgres has inherent, expected consequences —
these are not vulnerabilities in the tool:

- **Captures and saved sessions are cleartext.** Decoded output and any
  `--save` / `:save` JSONL file contain query text, returned row values,
  connection parameters, error messages, and other potentially sensitive
  application data in the clear. Treat capture output and saved `.jsonl`
  sessions as sensitive and protect them accordingly.
- **The MITM proxy writes a CA private key to disk.** In `--mode mitm` with
  auto-generated certificates, tapgres writes `ca.crt`, `ca.key`, `server.crt`,
  and `server.key` to `--tls-dir` (default `$XDG_CONFIG_HOME/tapgres`, i.e.
  `~/.config/tapgres`). Any client you configure to trust `ca.crt` will accept
  certificates minted by that CA, so `ca.key` is a sensitive secret: keep it
  local, never distribute it, and distribute only `ca.crt` to the specific
  clients that must trust the proxy. Remove the directory when you are done.
- **pcap mode needs elevated capture privileges** (`CAP_NET_RAW` on Linux, BPF
  device access on macOS). Grant them narrowly rather than running as root
  where possible.

## Reporting a vulnerability

If you find a security issue in tapgres itself — for example, a way it exposes
data or credentials beyond the expected behavior above, or a memory-safety or
input-handling bug reachable from captured/replayed data — please report it
**privately**.

Email the maintainer directly: **sunng@pm.me**

Please do not open a public GitHub issue or pull request for security reports.
Include the tapgres version, your OS, a description of the impact, and steps to
reproduce if you have them. You will get an acknowledgement, and a fix or
mitigation will be coordinated before any public disclosure.
