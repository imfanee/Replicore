//! apply.rs — atomic, verified apply (E8, FR-801/FR-803).
//!
//! Stage into a temp file in the destination directory (same filesystem so the
//! rename is atomic), fsync, verify the BLAKE3 hash, then rename into place and
//! fsync the parent directory. A consumer never observes a partial file.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::proto::FileMsg;
use crate::TMP_SUFFIX;

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn apply(root: &Path, msg: &FileMsg) -> Result<()> {
    // Verify integrity before touching the filesystem.
    let got = blake3::hash(&msg.data);
    if got.as_bytes() != &msg.hash {
        bail!("hash mismatch for {} (corrupt transfer)", msg.rel_path);
    }

    // Resolve destination, refusing path escapes.
    let rel = Path::new(&msg.rel_path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("unsafe relative path: {}", msg.rel_path);
    }
    let dest = root.join(rel);
    let parent = dest.parent().context("destination has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;

    // Stage in the same directory as the destination.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}{}.{}.{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        TMP_SUFFIX,
        std::process::id(),
        seq
    ));

    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(&msg.data).context("write staged data")?;
        f.flush().ok();
        f.sync_all().context("fsync staged file")?; // durability before rename
        let perms = std::fs::Permissions::from_mode(msg.mode & 0o7777);
        f.set_permissions(perms).context("set mode")?;
    }

    // Atomic publish.
    std::fs::rename(&tmp, &dest)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;

    // Persist the rename by fsyncing the parent directory.
    if let Ok(dirf) = std::fs::File::open(parent) {
        let _ = dirf.sync_all();
    }

    eprintln!("[apply] {} ({} bytes)", msg.rel_path, msg.data.len());
    Ok(())
}
