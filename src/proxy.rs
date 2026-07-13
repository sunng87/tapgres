//! MITM proxy mode (`--mode mitm`).
//!
//! Listens on a local port, accepts PostgreSQL client connections, terminates
//! TLS on the client leg (presenting an auto-generated or user-supplied
//! certificate), optionally re-encrypts on the upstream leg, and decodes the
//! cleartext in the middle — the same [`crate::decode`] pipeline the pcap path
//! uses, just fed from a socket instead of a capture.
//!
//! Because a TLS connection is single-owner, each connection is handled by a
//! tokio task that runs both relay directions under a `tokio::io::split`
//! bi-lock (correctness over raw throughput, which is fine for a tap).

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ServerConfig;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::decode::{self, DrainOutcome};
use crate::flow::{Direction, Role};
use crate::state::{ConnStats, Metrics, TrafficDirection};

/// Postgres protocol negotiation magics (the 4 bytes after the 8-byte length).
const SSL_MAGIC: [u8; 4] = [0x04, 0xd2, 0x16, 0x2f]; // 80877103 SSLRequest
const GSS_MAGIC: [u8; 4] = [0x04, 0xd2, 0x16, 0x30]; // 80877104 GssEncRequest
const CANCEL_MAGIC: [u8; 4] = [0x04, 0xd2, 0x16, 0x2e]; // 80877102 CancelRequest
/// A full SSLRequest message body, sent to the upstream to probe for TLS.
const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

/// Configuration for the MITM proxy.
#[derive(Clone)]
pub struct ProxyOpts {
    /// Address to listen on for client connections.
    pub listen: String,
    /// Upstream PostgreSQL server address.
    pub upstream: String,
    /// Directory holding the auto-generated CA + server cert/key.
    pub tls_dir: PathBuf,
    /// If set, use this PEM server cert instead of the auto-generated one.
    pub tls_cert: Option<PathBuf>,
    /// Key for [`ProxyOpts::tls_cert`] (PEM).
    pub tls_key: Option<PathBuf>,
    /// Skip TLS on the upstream leg (talk cleartext to the server).
    pub no_upstream_tls: bool,
}

/// Bundled TLS material: client-facing server config + an upstream client
/// config that trusts everything (we tap a local, user-controlled server).
struct TlsMaterial {
    server_config: Arc<ServerConfig>,
    upstream_client_config: Arc<ClientConfig>,
    /// Path of the CA cert the user should install, when auto-generated.
    ca_cert_path: Option<PathBuf>,
}

/// Ensures accepted connections are closed in the registry on every return
/// path, including handshake and upstream-connect failures.
struct ConnectionGuard {
    metrics: Arc<Metrics>,
    stats: Arc<ConnStats>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.close_connection(&self.stats);
    }
}

/// Entry point for `--mode mitm`. Builds a multi-thread tokio runtime and runs
/// the proxy until interrupted.
pub fn run(opts: ProxyOpts, metrics: Arc<Metrics>) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(opts, metrics))
}

pub async fn serve(opts: ProxyOpts, metrics: Arc<Metrics>) -> Result<(), Box<dyn Error>> {
    let tls = Arc::new(materialize_tls(&opts)?);

    match &tls.ca_cert_path {
        Some(ca) => {
            decode::status(format!("tapgres: generated/loaded CA at {}", ca.display()));
            decode::status(
                "tapgres: for clients to trust this proxy, install the CA, e.g. for libpq/psql:"
                    .into(),
            );
            decode::status(format!("  cp {} ~/.postgresql/root.crt", ca.display()));
        }
        None if opts.tls_cert.is_some() => {
            decode::status("tapgres: using user-supplied TLS certificate".into());
        }
        _ => {}
    }

    let listener = TcpListener::bind(&opts.listen).await?;
    decode::status(format!(
        "tapgres: mitm proxy  {}  ->  {}  (client TLS termination{})",
        opts.listen,
        opts.upstream,
        if opts.no_upstream_tls {
            ", upstream cleartext"
        } else {
            ", upstream TLS auto-negotiate"
        }
    ));

    let opts = Arc::new(opts);
    loop {
        let (client, peer) = listener.accept().await?;
        let opts = opts.clone();
        let tls = tls.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, opts, tls, metrics).await {
                decode::status(format!("tapgres: connection from {peer}: {e}"));
            }
        });
    }
}

/// Handle one client connection end to end.
async fn handle_connection(
    mut client: TcpStream,
    opts: Arc<ProxyOpts>,
    tls: Arc<TlsMaterial>,
    metrics: Arc<Metrics>,
) -> io::Result<()> {
    let client_endpoint = client.peer_addr()?;
    let proxy_endpoint = client.local_addr()?;
    // `encrypted` means opaque to tapgres. MITM transport encryption is
    // terminated here, so successfully relayed traffic remains decodable.
    let stats = metrics.open_connection(client_endpoint, proxy_endpoint, false);
    let _connection_guard = ConnectionGuard {
        metrics: metrics.clone(),
        stats: stats.clone(),
    };
    // Read the first 8 bytes: 4-byte length + 4-byte magic/protocol.
    let mut head = [0u8; 8];
    if client.read_exact(&mut head).await.is_err() {
        return Ok(()); // client sent < 8 bytes (or nothing); nothing to tap
    }
    let body = &head[4..8];

    // Cancel requests are one-shot, raw, and must reach the server verbatim on
    // their own connection — relay them untouched, no TLS, no decoding.
    if body == CANCEL_MAGIC {
        let mut server = TcpStream::connect(opts.upstream.as_str()).await?;
        server.write_all(&head).await?;
        return raw_relay(client, server).await;
    }

    // --- Decide the client-facing transport ---
    let client_tls = body == SSL_MAGIC;
    let initial: Vec<u8> = if client_tls {
        client.write_all(b"S").await?; // accept SSL locally
        Vec::new()
    } else if body == GSS_MAGIC {
        // We don't speak GSS; refuse so the client falls back to cleartext.
        client.write_all(b"N").await?;
        Vec::new()
    } else {
        // Cleartext Startup (or anything else): these 8 bytes begin it.
        head.to_vec()
    };
    // The cleartext Startup's first 8 bytes (read above to detect
    // SSL/GSS/cancel) are forwarded upstream below and also fed back into the
    // client decoder by the pump, so they no longer need ad-hoc counting here.

    let client_stream: ProxyStream = if client_tls {
        let acceptor = TlsAcceptor::from(tls.server_config.clone());
        let s = acceptor.accept(client).await?;
        ProxyStream::Tls(Box::new(s.into()))
    } else {
        ProxyStream::Plain(client)
    };

    // --- Upstream transport ---
    let mut server = TcpStream::connect(opts.upstream.as_str()).await?;
    let server_stream: ProxyStream = if opts.no_upstream_tls {
        ProxyStream::Plain(server)
    } else {
        server.write_all(&SSL_REQUEST).await?; // probe the server for TLS
        let mut reply = [0u8; 1];
        match server.read_exact(&mut reply).await {
            Ok(_) if reply[0] == b'S' => {
                let connector = TlsConnector::from(tls.upstream_client_config.clone());
                let name = ServerName::try_from("localhost".to_string())
                    .map_err(|e| io::Error::other(format!("invalid upstream name: {e}")))?;
                let s = connector.connect(name, server).await?;
                ProxyStream::Tls(Box::new(s.into()))
            }
            _ => ProxyStream::Plain(server), // 'N' or EOF: stay cleartext upstream
        }
    };

    // Forward the client's initial bytes (the Startup) upstream.
    let mut server_stream = server_stream;
    if !initial.is_empty() {
        server_stream.write_all(&initial).await?;
    }

    // Bidirectional decode + relay.
    let (client_rd, client_wr) = tokio::io::split(client_stream);
    let (server_rd, server_wr) = tokio::io::split(server_stream);
    let mut to_client = tokio::spawn(pump(
        server_rd,
        client_wr,
        Role::Server,
        metrics.clone(),
        stats.clone(),
        Vec::new(),
    ));
    let mut to_server = tokio::spawn(pump(
        client_rd,
        server_wr,
        Role::Client,
        metrics.clone(),
        stats.clone(),
        initial,
    ));
    // Finish as soon as either side closes; abort the other half.
    tokio::select! {
        _ = &mut to_client => {
            to_server.abort();
            let _ = to_server.await;
        }
        _ = &mut to_server => {
            to_client.abort();
            let _ = to_client.await;
        }
    }
    Ok(())
}

/// Copy bytes one way without decoding (used for cancel-request connections).
async fn raw_relay(client: TcpStream, server: TcpStream) -> io::Result<()> {
    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let (mut s_rd, mut s_wr) = tokio::io::split(server);
    let _ = tokio::try_join!(
        async { tokio::io::copy(&mut c_rd, &mut s_wr).await },
        async { tokio::io::copy(&mut s_rd, &mut c_wr).await },
    )?;
    Ok(())
}

/// Read plaintext from `from`, decode it as pgwire, and forward it to `to`.
///
/// `prefix` carries bytes the caller already peeled off the stream (the
/// cleartext Startup's length+protocol on the client leg) so the decoder sees
/// a complete message stream; those bytes were already forwarded to `to`
/// separately, so they are decoded here but not re-written.
async fn pump(
    mut from: tokio::io::ReadHalf<ProxyStream>,
    mut to: tokio::io::WriteHalf<ProxyStream>,
    role: Role,
    metrics: Arc<Metrics>,
    stats: Arc<ConnStats>,
    prefix: Vec<u8>,
) -> io::Result<()> {
    let mut dir = Direction::for_decoding(role, stats.client());
    let direction = if role == Role::Client {
        TrafficDirection::In
    } else {
        TrafficDirection::Out
    };
    if !prefix.is_empty() {
        dir.rxbuf.extend_from_slice(&prefix);
    }
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        // Decode the freshly arrived plaintext (the decoder buffers partial
        // messages across reads), count the decoded pgwire messages, then
        // forward the bytes untouched. Bytes hidden inside TLS are
        // intentionally outside these application-edge counters.
        dir.rxbuf.extend_from_slice(&buf[..n]);
        let mut outcome = DrainOutcome::default();
        decode::drain_direction(&mut dir, &mut outcome);
        if outcome.msgs > 0 {
            metrics.record_messages(&stats, direction, outcome.msgs, outcome.bytes);
        }
        to.write_all(&buf[..n]).await?;
    }
}

/// Either a raw TCP stream or a TLS stream over TCP. Implements the tokio
/// async I/O traits by delegation; `split` then yields independent halves.
enum ProxyStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::TlsStream<TcpStream>>),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ProxyStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ProxyStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ProxyStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Plain(s) => Pin::new(s).poll_flush(cx),
            ProxyStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ProxyStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS material: load user-supplied certs, or auto-generate a CA + leaf.
// ---------------------------------------------------------------------------

fn materialize_tls(opts: &ProxyOpts) -> Result<TlsMaterial, Box<dyn Error>> {
    let (certs, key, ca_cert_path) = match (&opts.tls_cert, &opts.tls_key) {
        (Some(cert), Some(key)) => {
            let certs = load_pem_certs(cert)?;
            let key = load_pem_key(key)?;
            (certs, key, None)
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("--tls-cert and --tls-key must be given together".into());
        }
        (None, None) => {
            let dir = &opts.tls_dir;
            let ca = dir.join("ca.crt");
            let leaf = dir.join("server.crt");
            let leaf_key = dir.join("server.key");
            if !(ca.exists() && leaf.exists() && leaf_key.exists()) {
                fs::create_dir_all(dir)?;
                generate_ca_and_leaf(dir)?;
                decode::status(format!(
                    "tapgres: generated CA + server certificate in {}",
                    dir.display()
                ));
            }
            (load_pem_certs(&leaf)?, load_pem_key(&leaf_key)?, Some(ca))
        }
    };

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // The upstream leg talks to a local, user-controlled server, so we don't
    // verify its certificate — only that the handshake completes.
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    Ok(TlsMaterial {
        server_config: Arc::new(server_config),
        upstream_client_config: Arc::new(client_config),
        ca_cert_path,
    })
}

/// Generate a self-signed CA and a localhost leaf signed by it, written as PEM.
fn generate_ca_and_leaf(dir: &Path) -> Result<(), Box<dyn Error>> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

    // --- CA ---
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "tapgres CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    fs::write(dir.join("ca.crt"), ca_cert.pem())?;
    fs::write(dir.join("ca.key"), ca_key.serialize_pem())?;

    // --- leaf (localhost + loopback) ---
    let mut leaf_params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "tapgres");
    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;
    fs::write(dir.join("server.crt"), leaf_cert.pem())?;
    fs::write(dir.join("server.key"), leaf_key.serialize_pem())?;
    Ok(())
}

fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let mut rd = io::BufReader::new(fs::File::open(path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_pem_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    let mut rd = io::BufReader::new(fs::File::open(path)?);
    let key = rustls_pemfile::private_key(&mut rd)?
        .ok_or_else(|| format!("no private key found in {}", path.display()))?;
    Ok(key)
}

/// A `ServerCertVerifier` that accepts anything. Only safe because the upstream
/// is a local server the operator already controls.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
