//! main.rs — `replicored` entrypoint (anyhow boundary).
//!
//!   replicored gen-cert --out-dir DIR --name NAME
//!       Generate a self-signed node identity (NAME.cert.pem / NAME.key.pem,
//!       key mode 0600) and print the SHA-256 fingerprint to pin in peers'
//!       config allowlists (FR-1002).
//!
//!   replicored run --config FILE
//!       Run the replication daemon. Lands with the daemon wiring commit.
//!
//! The M0 spike's one-way `sink`/`source` modes are gone along with the
//! SPIKE-ONLY accept-anything certificate verifier they depended on.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("gen-cert") => gen_cert(args),
        Some("run") => {
            bail!("`run` is not wired yet — the daemon assembly lands in the next commits")
        }
        _ => {
            eprintln!(
                "usage:\n  replicored gen-cert --out-dir DIR --name NAME\n  replicored run --config FILE"
            );
            Ok(())
        }
    }
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
