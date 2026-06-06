//! apply.rs — atomic, verified, suppressed apply (FR-803, FR-802, FR-902).
//!
//! Stage into a temp file in the destination directory (same filesystem so the
//! rename is atomic), fsync, re-read and verify the BLAKE3 hash of what is on
//! disk, then rename into place and fsync the parent directory. A consumer
//! never observes a partial file, and no code path writes the destination
//! directly.
//!
//! Suppression contract: the matching entry is registered **before** the first
//! filesystem mutation, so a scanner walk racing the apply (between rename and
//! the store commit) swallows its own observation instead of emitting a
//! spurious outbound op. Re-running an apply with the same bytes is idempotent:
//! the rename replaces identical content.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::suppress::Suppressor;
use crate::TMP_SUFFIX;

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(thiserror::Error, Debug)]
pub enum ApplyError {
    #[error("hash mismatch for {0} (corrupt transfer or torn write)")]
    HashMismatch(String),
    #[error("unsafe relative path: {0}")]
    UnsafePath(String),
    #[error("{ctx} {path}: {source}")]
    Io {
        ctx: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_err<'p>(ctx: &'static str, path: &'p Path) -> impl FnOnce(std::io::Error) -> ApplyError + 'p {
    move |source| ApplyError::Io {
        ctx,
        path: path.to_path_buf(),
        source,
    }
}

/// Resolve `rel` under `root`, refusing absolute paths and `..` escapes
/// (never trust network input).
fn safe_dest(root: &Path, rel: &str) -> Result<PathBuf, ApplyError> {
    let rel_path = Path::new(rel);
    if rel.is_empty()
        || rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(ApplyError::UnsafePath(rel.to_string()));
    }
    Ok(root.join(rel_path))
}

/// Atomically publish `data` (whose BLAKE3 must equal `hash`) at `root/rel`.
pub fn apply_write(
    root: &Path,
    rel: &str,
    mode: u32,
    hash: &[u8; 32],
    data: &[u8],
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    // Verify integrity before touching the filesystem.
    if blake3::hash(data).as_bytes() != hash {
        return Err(ApplyError::HashMismatch(rel.to_string()));
    }

    let dest = safe_dest(root, rel)?;
    let parent = dest
        .parent()
        .ok_or_else(|| ApplyError::UnsafePath(rel.to_string()))?;
    std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;

    // Bytes verified, destination resolved: register suppression BEFORE the
    // first mutation (FR-902). If anything below fails, the orphan entry is
    // TTL-swept and can at worst swallow one identical-content local event,
    // which the no-op filter would drop anyway.
    suppress.register_write(rel, *hash);

    // Stage in the same directory as the destination (same fs => atomic rename).
    let stage_seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}{}.{}.{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        TMP_SUFFIX,
        std::process::id(),
        stage_seq
    ));

    let stage = || -> Result<(), ApplyError> {
        {
            let mut f = std::fs::File::create(&tmp).map_err(io_err("create", &tmp))?;
            f.write_all(data).map_err(io_err("write", &tmp))?;
            f.sync_all().map_err(io_err("fsync", &tmp))?; // durable before rename
            let perms = std::fs::Permissions::from_mode(mode & 0o7777);
            f.set_permissions(perms).map_err(io_err("chmod", &tmp))?;
        }

        // Verify what actually landed on disk (FR-803: stage → fsync →
        // verify → rename). Catches torn writes the in-memory check cannot.
        let mut staged = std::fs::File::open(&tmp).map_err(io_err("reopen", &tmp))?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = staged.read(&mut buf).map_err(io_err("readback", &tmp))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        if hasher.finalize().as_bytes() != hash {
            return Err(ApplyError::HashMismatch(rel.to_string()));
        }

        // Atomic publish, then persist the rename itself.
        std::fs::rename(&tmp, &dest).map_err(io_err("rename", &dest))?;
        if let Ok(dirf) = std::fs::File::open(parent) {
            let _ = dirf.sync_all();
        }
        Ok(())
    };

    stage().inspect_err(|_| {
        // Never leave a staged temp behind on failure.
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Unlink `root/rel` for a remote delete (tombstone). A missing file is
/// success — the delete already happened from the fs point of view.
pub fn apply_delete(root: &Path, rel: &str, suppress: &Suppressor) -> Result<(), ApplyError> {
    let dest = safe_dest(root, rel)?;

    // Before the unlink, so a racing scanner swallows the disappearance.
    suppress.register_delete(rel);

    match std::fs::remove_file(&dest) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("unlink", &dest)(e)),
    }
    // Empty parent directories are left in place — directory ops are an M2+
    // concern. // SEAM(M2): dir lifecycle
    if let Some(parent) = dest.parent() {
        if let Ok(dirf) = std::fs::File::open(parent) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    #[test]
    fn write_publishes_atomically_with_mode() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let data = b"hello replicore";
        apply_write(dir.path(), "sub/dir/f.txt", 0o640, &hash_of(data), data, &s).unwrap();

        let dest = dir.path().join("sub/dir/f.txt");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        // No staged temp left anywhere.
        assert!(!walk_has_tmp(dir.path()));
        // Suppression entry was registered for the watcher/scanner.
        assert!(s.check_write("sub/dir/f.txt", &hash_of(data)));
    }

    #[test]
    fn overwrite_with_same_bytes_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let data = b"same";
        for _ in 0..2 {
            apply_write(dir.path(), "f", 0o644, &hash_of(data), data, &s).unwrap();
        }
        assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), data);
    }

    #[test]
    fn rejects_path_escapes_before_any_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let data = b"x";
        for bad in ["../evil", "/abs/path", "a/../../evil", ""] {
            let err = apply_write(dir.path(), bad, 0o644, &hash_of(data), data, &s).unwrap_err();
            assert!(matches!(err, ApplyError::UnsafePath(_)), "{bad}");
        }
        assert!(s.is_empty()); // rejected before suppression registration
        assert!(apply_delete(dir.path(), "../evil", &s).is_err());
    }

    #[test]
    fn rejects_hash_mismatch_without_touching_fs() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let err = apply_write(dir.path(), "f", 0o644, &[0u8; 32], b"data", &s).unwrap_err();
        assert!(matches!(err, ApplyError::HashMismatch(_)));
        assert!(!dir.path().join("f").exists());
        assert!(s.is_empty()); // verified before registration
    }

    #[test]
    fn delete_is_idempotent_and_registers_suppression() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        apply_delete(dir.path(), "f", &s).unwrap();
        assert!(!dir.path().join("f").exists());
        assert!(s.check_delete("f"));
        // Already gone: still success (redelivered delete op).
        apply_delete(dir.path(), "f", &s).unwrap();
    }

    fn walk_has_tmp(root: &Path) -> bool {
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let entry = entry.unwrap();
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.to_string_lossy().contains(TMP_SUFFIX) {
                    return true;
                }
            }
        }
        false
    }
}
