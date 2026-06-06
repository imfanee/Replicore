//! main.rs — Replicore M0 spike entrypoint.
//!
//! Two modes prove the M0 exit criterion (a file written on the source appears,
//! intact and atomically, on the sink over QUIC):
//!
//!   replicored sink   --listen 0.0.0.0:7000 --dir /srv/replicore/in
//!   replicored source --peer 10.0.0.2:7000  --dir /srv/replicore/out
//!
//! This is one-directional by design for M0. Phase 1 makes it bidirectional with
//! the op-log, version vectors, and apply-suppression (FR-201/301/902).

use anyhow::{bail, Context, Result};
use replicore::{net, watch};
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();

    // Tiny hand-rolled flag parser (no clap dependency for the spike).
    let mut listen: Option<SocketAddr> = None;
    let mut peer: Option<SocketAddr> = None;
    let mut dir: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--listen" => listen = Some(parse_addr(args.next())?),
            "--peer" => peer = Some(parse_addr(args.next())?),
            "--dir" => dir = Some(PathBuf::from(args.next().context("--dir needs a value")?)),
            other => bail!("unknown argument: {other}"),
        }
    }

    match mode.as_str() {
        "sink" => {
            let listen = listen.context("sink needs --listen HOST:PORT")?;
            let dir = dir.context("sink needs --dir PATH")?;
            std::fs::create_dir_all(&dir).ok();
            net::run_sink(listen, dir).await
        }
        "source" => {
            let peer = peer.context("source needs --peer HOST:PORT")?;
            let dir = dir.context("source needs --dir PATH")?;
            let dir = dir.canonicalize().context("--dir must exist for source")?;

            // Watcher (blocking, fanotify) -> bounded channel -> async sender.
            let (tx, rx) = tokio::sync::mpsc::channel::<PathBuf>(1024);
            let watch_dir = dir.clone();
            std::thread::spawn(move || {
                if let Err(e) = watch::run(&watch_dir, tx) {
                    eprintln!("[watch] fatal: {e:#}");
                    std::process::exit(1);
                }
            });

            net::run_source(peer, dir, rx).await
        }
        "" => {
            eprintln!("usage:\n  replicored sink   --listen HOST:PORT --dir PATH\n  replicored source --peer HOST:PORT --dir PATH");
            Ok(())
        }
        other => bail!("unknown mode '{other}' (expected 'sink' or 'source')"),
    }
}

fn parse_addr(v: Option<String>) -> Result<SocketAddr> {
    v.context("expected HOST:PORT")?
        .parse()
        .context("invalid HOST:PORT")
}
