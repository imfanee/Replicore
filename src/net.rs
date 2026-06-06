//! net.rs — QUIC transport (E5, FR-501). Built on quinn so we never hand-roll a
//! UDP reliability/congestion layer (NFR-C2).
//!
//! M0 security note: the client uses an accept-any certificate verifier. This is
//! SPIKE-ONLY and INSECURE. Phase 1/2 replaces it with mutual TLS and a pinned
//! peer-certificate allowlist (FR-1001/FR-1002). The marker below is the single
//! place that hardening lands.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::apply::apply;
use crate::proto::{FileMsg, ALPN};

// ---------------------------------------------------------------------------
// SINK: listen, accept connections, apply each incoming file atomically.
// ---------------------------------------------------------------------------

pub async fn run_sink(listen: SocketAddr, dir: PathBuf) -> Result<()> {
    let server_cfg = server_config()?;
    let endpoint = quinn::Endpoint::server(server_cfg, listen).context("bind QUIC server")?;
    eprintln!("[sink] listening on {} -> {}", listen, dir.display());

    while let Some(connecting) = endpoint.accept().await {
        let dir = dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(connecting, dir).await {
                eprintln!("[sink] connection ended: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_conn(connecting: quinn::Connecting, dir: PathBuf) -> Result<()> {
    let conn = connecting.await.context("accept handshake")?;
    eprintln!("[sink] peer connected: {}", conn.remote_address());
    loop {
        match conn.accept_uni().await {
            Ok(mut recv) => {
                // 64 MiB cap for the spike; Phase 2 streams chunks instead.
                let buf = recv
                    .read_to_end(64 * 1024 * 1024)
                    .await
                    .context("read stream")?;
                let msg: FileMsg = bincode::deserialize(&buf).context("decode FileMsg")?;
                if let Err(e) = apply(&dir, &msg) {
                    eprintln!("[sink] apply failed: {e:#}");
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
            Err(e) => return Err(e).context("accept_uni"),
        }
    }
}

fn server_config() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generate self-signed cert")?;
    let cert_der = rustls::Certificate(cert.serialize_der().context("serialize cert")?);
    let key_der = rustls::PrivateKey(cert.serialize_private_key_der());

    let mut tls = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("rustls server config")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    Ok(quinn::ServerConfig::with_crypto(Arc::new(tls)))
}

// ---------------------------------------------------------------------------
// SOURCE: connect to a peer, then send each file produced by the watcher.
// ---------------------------------------------------------------------------

pub async fn run_source(
    peer: SocketAddr,
    dir: PathBuf,
    mut rx: tokio::sync::mpsc::Receiver<PathBuf>,
) -> Result<()> {
    let endpoint = client_endpoint()?;
    let conn = endpoint
        .connect(peer, "localhost")
        .context("start connect")?
        .await
        .context("connect handshake")?;
    eprintln!("[source] connected to {peer}");

    while let Some(path) = rx.recv().await {
        if let Err(e) = send_file(&conn, &dir, &path).await {
            eprintln!("[source] send {} failed: {e:#}", path.display());
        }
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

async fn send_file(conn: &quinn::Connection, root: &Path, path: &Path) -> Result<()> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[source] skip {} ({e})", path.display());
            return Ok(());
        }
    };
    let mode = std::fs::metadata(path)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode()
        })
        .unwrap_or(0o644);

    let rel = path.strip_prefix(root).unwrap_or(path);
    let msg = FileMsg {
        rel_path: rel.to_string_lossy().replace('\\', "/"),
        mode,
        hash: *blake3::hash(&data).as_bytes(),
        data,
    };

    let buf = bincode::serialize(&msg).context("encode FileMsg")?;
    let mut send = conn.open_uni().await.context("open_uni")?;
    send.write_all(&buf).await.context("write")?;
    send.finish().await.context("finish stream")?;
    eprintln!("[source] sent {} ({} bytes)", msg.rel_path, msg.data.len());
    Ok(())
}

fn client_endpoint() -> Result<quinn::Endpoint> {
    let mut tls = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptAny)) // SPIKE-ONLY: replace with pinned mTLS (FR-1001/1002)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let client_cfg = quinn::ClientConfig::new(Arc::new(tls));
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).context("bind QUIC client")?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// INSECURE certificate verifier — accepts any server cert. Spike only.
struct AcceptAny;

impl rustls::client::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
