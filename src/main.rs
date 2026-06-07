//! main.rs — `replicored` entrypoint (anyhow boundary).
//!
//!   replicored gen-cert --out-dir DIR --name NAME
//!       Generate a self-signed node identity (NAME.cert.pem / NAME.key.pem,
//!       key mode 0600) and print the SHA-256 fingerprint to pin in peers'
//!       config allowlists (FR-1002).
//!
//!   replicored gen-admin-key --out FILE
//!       Generate the cluster admin Ed25519 keypair: the secret PKCS#8 doc is
//!       written to FILE (mode 0600) and the public key is printed for the
//!       intent file's `[trust] admin_pubkey`. The daemon never reads the
//!       secret — only `replicorectl member add/remove` does, to sign roster
//!       entries client-side (FR-1305).
//!
//!   replicored run --config FILE
//!       Run the replication daemon: store thread, fanotify watcher
//!       (best-effort), authoritative periodic scanner, ingest pipeline, and
//!       the mTLS QUIC engine (listener + one subscription per peer).
//!
//! The M0 spike's one-way `sink`/`source` modes are gone along with the
//! SPIKE-ONLY accept-anything certificate verifier they depended on.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use replicore::config::Config;
use replicore::ingest::{Ingest, LocalEvent};
use replicore::net::Engine;
use replicore::oplog::Store;
use replicore::suppress::Suppressor;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("gen-cert") => gen_cert(args),
        Some("gen-admin-key") => gen_admin_key(args),
        Some("run") => run(args).await,
        _ => {
            eprintln!(
                "usage:\n  replicored gen-cert --out-dir DIR --name NAME\n  replicored gen-admin-key --out FILE\n  replicored run --config FILE"
            );
            Ok(())
        }
    }
}

async fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.next().context("--config needs a value")?,
                ))
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let config_path = config_path.context("run needs --config FILE")?;
    let cfg = Config::load(&config_path)
        .with_context(|| format!("load config {}", config_path.display()))?;
    if cfg.peers.is_empty() {
        tracing::warn!("no [[peers]] configured; running standalone (nothing will replicate)");
    }

    if let Some(parent) = cfg.db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create db dir {}", parent.display()))?;
    }
    let store = Store::open(&cfg.db_path, cfg.node_id).context("open state store")?;
    let suppress = Suppressor::new();
    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<LocalEvent>(1024);
    // Clone kept only so /healthz can gauge the queue depth.
    let events_tx_gauge = events_tx.clone();

    // Remove staging temps orphaned by a previous kill -9, BEFORE anything
    // that could stage a new one is running (the sweep must never race a
    // live staging file). Same rule for the CAS insert temps.
    let swept = replicore::scanner::sweep_orphan_temps(&cfg.share_dir)
        .context("sweep orphaned staging temps")?;
    if swept > 0 {
        tracing::info!(count = swept, "removed orphaned staging temps");
    }
    let cas = replicore::chunk::Cas::open(&cfg.cas_dir).context("open chunk store")?;
    let swept = cas
        .sweep_orphan_temps()
        .context("sweep orphaned CAS temps")?;
    if swept > 0 {
        tracing::info!(count = swept, "removed orphaned CAS insert temps");
    }

    // FR-104: fanotify overflow → targeted rescan, instead of silent loss.
    let rescan = std::sync::Arc::new(tokio::sync::Notify::new());

    // Fanotify watcher: the low-latency write path. Best-effort by doctrine —
    // if it cannot start (no CAP_SYS_ADMIN), the scanner still guarantees
    // correctness, so we degrade loudly instead of dying.
    {
        let dir = cfg.share_dir.clone();
        let tx = events_tx.clone();
        let rescan = rescan.clone();
        std::thread::Builder::new()
            .name("replicore-watch".into())
            .spawn(move || {
                if let Err(e) = replicore::watch::run(&dir, tx, rescan) {
                    tracing::warn!(
                        error = format!("{e:#}"),
                        "fanotify watcher unavailable; relying on periodic rescan only"
                    );
                }
            })
            .context("spawn watcher thread")?;
    }

    // Scanner: FR-103 baseline immediately, then the authoritative rescan.
    tokio::spawn(replicore::scanner::run(
        cfg.clone(),
        store.clone(),
        events_tx,
        rescan,
    ));

    // Ingest: events -> ops (debounce, suppression, no-op filter), chunking
    // local writes into the CAS as it hashes them.
    tokio::spawn(
        Ingest::new(
            cfg.clone(),
            store.clone(),
            suppress.clone(),
            cas.clone(),
            events_rx,
        )
        .run(),
    );

    // Transport: listener + one subscription per configured peer. Runs until
    // the process is killed.
    tracing::info!(
        node = %hex::encode(cfg.node_id),
        share = %cfg.share_dir.display(),
        peers = cfg.peers.len(),
        "replicored starting"
    );
    let engine = Engine::new(cfg.clone(), store.clone(), suppress, cas.clone());

    // Health endpoint (FR-1102), if configured.
    if let Some(addr) = cfg.health_listen {
        let ctx = replicore::health::HealthCtx {
            node_id: cfg.node_id,
            stats: engine.stats(),
            peers: engine.peer_registry(),
            conns: engine.conn_registry(),
            cas,
            store,
            configured_peers: cfg.peers.iter().map(|p| p.node_id).collect(),
            events_tx: events_tx_gauge,
        };
        tokio::spawn(async move {
            if let Err(e) = replicore::health::serve(addr, ctx).await {
                tracing::error!(error = %e, "health endpoint died");
            }
        });
    }

    engine.run().await.context("transport engine")
}

fn gen_cert(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut out_dir: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--out-dir" => {
                out_dir = Some(PathBuf::from(
                    args.next().context("--out-dir needs a value")?,
                ))
            }
            "--name" => name = Some(args.next().context("--name needs a value")?),
            other => bail!("unknown argument: {other}"),
        }
    }
    let out_dir = out_dir.context("gen-cert needs --out-dir DIR")?;
    let name = name.context("gen-cert needs --name NAME")?;
    std::fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let ident = replicore::net::generate_identity().context("generate identity")?;
    let cert_path = out_dir.join(format!("{name}.cert.pem"));
    let key_path = out_dir.join(format!("{name}.key.pem"));
    std::fs::write(&cert_path, &ident.cert_pem)
        .with_context(|| format!("write {}", cert_path.display()))?;
    write_private(&key_path, ident.key_pem.as_bytes())
        .with_context(|| format!("write {}", key_path.display()))?;

    println!("cert:        {}", cert_path.display());
    println!("key:         {} (mode 0600)", key_path.display());
    println!("fingerprint: {}", hex::encode(ident.fingerprint));
    println!();
    println!("Pin this fingerprint in each peer's [[peers]] entry.");
    Ok(())
}

fn gen_admin_key(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut out: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a value")?)),
            other => bail!("unknown argument: {other}"),
        }
    }
    let out = out.context("gen-admin-key needs --out FILE")?;
    if out.exists() {
        bail!(
            "{} already exists; refusing to overwrite an admin key",
            out.display()
        );
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let (doc, pubkey) = replicore::admin::generate_admin_key().context("generate admin key")?;
    write_private(&out, &doc).with_context(|| format!("write {}", out.display()))?;

    println!("admin secret: {} (mode 0600 — keep offline)", out.display());
    println!("admin pubkey: {}", pubkey.to_hex());
    println!();
    println!("Put this in every node's intent file:");
    println!("  [trust]");
    println!("  admin_pubkey = \"{}\"", pubkey.to_hex());
    Ok(())
}

/// Write the key with owner-only permissions from the start (no chmod window).
fn write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents)
}
