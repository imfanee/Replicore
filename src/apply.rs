//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
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
//!
//! Metadata (FR-804): applied to the STAGED temp, after the content is fully
//! written and verified, BEFORE the publishing rename — metadata travels with
//! the inode through the rename, so a consumer never observes content with
//! stale metadata or metadata without its content. The order inside the
//! metadata step lives in `metadata::apply_meta`.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::metadata::{self, Meta, OwnerPolicy};
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
    #[error("chunk store: {0}")]
    Cas(#[from] crate::chunk::CasError),
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
#[allow(clippy::too_many_arguments)]
pub fn apply_write(
    root: &Path,
    rel: &str,
    mode: u32,
    hash: &[u8; 32],
    data: &[u8],
    meta: Option<&Meta>,
    policy: OwnerPolicy,
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
        verify_on_disk(&tmp, hash, rel)?;

        // Metadata on the staged temp, after content, before publish
        // (FR-804) — it travels with the inode through the rename.
        if let Some(m) = meta {
            metadata::apply_meta(&tmp, m, policy).map_err(io_err("meta", &tmp))?;
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

/// Atomically publish a file assembled from CAS chunks at `root/rel`
/// (FR-803 extended to the chunked data plane). Stages a temp in the
/// destination directory, streams each (re-verified) chunk into it while
/// accumulating the whole-file BLAKE3, fsyncs, REQUIRES the streamed hash to
/// equal `whole_hash` before the rename, then re-reads the staged file as an
/// independent torn-write check — exactly M1's discipline, minus the
/// in-memory `data` buffer (files can exceed RAM). Suppression is registered
/// before the first mutation; failures clean up the temp. Blocking — call in
/// spawn_blocking.
#[allow(clippy::too_many_arguments)]
pub fn apply_assembled(
    root: &Path,
    rel: &str,
    mode: u32,
    whole_hash: &[u8; 32],
    manifest: &crate::chunk::Manifest,
    cas: &crate::chunk::Cas,
    meta: Option<&Meta>,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    // Structure sanity before any fs work: the manifest must claim to
    // reconstruct exactly the content the op promised.
    if &manifest.content_hash != whole_hash {
        return Err(ApplyError::HashMismatch(rel.to_string()));
    }

    let dest = safe_dest(root, rel)?;
    let parent = dest
        .parent()
        .ok_or_else(|| ApplyError::UnsafePath(rel.to_string()))?;
    std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;

    // Before the first mutation (FR-902), as with apply_write.
    suppress.register_write(rel, *whole_hash);

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
            // Streams chunks (each re-verified by Cas::read) and returns the
            // whole-file hash of what was actually written.
            let written = crate::chunk::assemble_from_cas(manifest, cas, &mut f)?;
            // THE whole-file verify, before anything is published (reviewer
            // gate: assembled files verified whole-file before the rename).
            if &written != whole_hash {
                return Err(ApplyError::HashMismatch(rel.to_string()));
            }
            f.sync_all().map_err(io_err("fsync", &tmp))?;
            let perms = std::fs::Permissions::from_mode(mode & 0o7777);
            f.set_permissions(perms).map_err(io_err("chmod", &tmp))?;
        }

        // Independent readback (torn-write check), as in apply_write.
        verify_on_disk(&tmp, whole_hash, rel)?;

        // Metadata after content, before publish (FR-804).
        if let Some(m) = meta {
            metadata::apply_meta(&tmp, m, policy).map_err(io_err("meta", &tmp))?;
        }

        std::fs::rename(&tmp, &dest).map_err(io_err("rename", &dest))?;
        if let Ok(dirf) = std::fs::File::open(parent) {
            let _ = dirf.sync_all();
        }
        Ok(())
    };

    stage().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Re-read a staged file and require its BLAKE3 to equal `hash`.
fn verify_on_disk(path: &Path, hash: &[u8; 32], rel: &str) -> Result<(), ApplyError> {
    let mut staged = std::fs::File::open(path).map_err(io_err("reopen", path))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = staged.read(&mut buf).map_err(io_err("readback", path))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    if hasher.finalize().as_bytes() != hash {
        return Err(ApplyError::HashMismatch(rel.to_string()));
    }
    Ok(())
}

/// Identity-preserving move for a remote rename (FR-205): `root/old_rel` →
/// `root/new_rel` via `rename(2)`, taken ONLY when the source file already
/// holds exactly `hash` (verified by readback first) — the no-retransfer fast
/// path. Returns `Ok(false)` with the fs untouched when the source is missing
/// or holds other bytes; the caller falls back to assemble-at-target.
/// Suppression is registered for BOTH path events before the mutation.
#[allow(clippy::too_many_arguments)]
pub fn apply_rename(
    root: &Path,
    old_rel: &str,
    new_rel: &str,
    mode: u32,
    hash: &[u8; 32],
    meta: Option<&Meta>,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<bool, ApplyError> {
    let src = safe_dest(root, old_rel)?;
    let dest = safe_dest(root, new_rel)?;
    let parent = dest
        .parent()
        .ok_or_else(|| ApplyError::UnsafePath(new_rel.to_string()))?;
    match verify_on_disk(&src, hash, old_rel) {
        Ok(()) => {}
        // Source gone or different content: not a fast-path candidate.
        Err(ApplyError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false)
        }
        Err(ApplyError::HashMismatch(_)) => return Ok(false),
        Err(e) => return Err(e),
    }
    std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;

    // Both halves of the move are self-inflicted events (FR-902).
    suppress.register_delete(old_rel);
    suppress.register_write(new_rel, *hash);

    std::fs::rename(&src, &dest).map_err(io_err("rename", &dest))?;
    let perms = std::fs::Permissions::from_mode(mode & 0o7777);
    std::fs::set_permissions(&dest, perms).map_err(io_err("chmod", &dest))?;
    // The op's metadata snapshot rides the move (it IS the file's, captured
    // at the origin's rename).
    if let Some(m) = meta {
        metadata::apply_meta(&dest, m, policy).map_err(io_err("meta", &dest))?;
    }
    // Persist the namespace change in both directories.
    if let Ok(dirf) = std::fs::File::open(parent) {
        let _ = dirf.sync_all();
    }
    if let Some(old_parent) = src.parent() {
        if let Ok(dirf) = std::fs::File::open(old_parent) {
            let _ = dirf.sync_all();
        }
    }
    Ok(true)
}

/// Atomically publish a symlink at `root/rel` (FR-106). The target rides in
/// `meta`; `hash` is BLAKE3 of the raw target bytes (the op's content hash).
/// Staged under a temp name and renamed — same discipline, no following.
pub fn apply_symlink(
    root: &Path,
    rel: &str,
    hash: &[u8; 32],
    meta: &Meta,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    let Some(target) = meta.symlink_target.as_deref() else {
        return Err(ApplyError::HashMismatch(rel.to_string()));
    };
    if blake3::hash(target).as_bytes() != hash {
        return Err(ApplyError::HashMismatch(rel.to_string()));
    }
    let dest = safe_dest(root, rel)?;
    let parent = dest
        .parent()
        .ok_or_else(|| ApplyError::UnsafePath(rel.to_string()))?;
    std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;
    suppress.register_write(rel, *hash);

    let stage_seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}{}.{}.{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("l"),
        TMP_SUFFIX,
        std::process::id(),
        stage_seq
    ));
    let stage = || -> Result<(), ApplyError> {
        use std::os::unix::ffi::OsStrExt;
        let target_os = std::ffi::OsStr::from_bytes(target);
        std::os::unix::fs::symlink(target_os, &tmp).map_err(io_err("symlink", &tmp))?;
        metadata::apply_meta(&tmp, meta, policy).map_err(io_err("meta", &tmp))?;
        std::fs::rename(&tmp, &dest).map_err(io_err("rename", &dest))?;
        if let Ok(dirf) = std::fs::File::open(parent) {
            let _ = dirf.sync_all();
        }
        Ok(())
    };
    stage().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Atomically publish a special node (FIFO / device) at `root/rel` (FR-106).
/// Devices need CAP_MKNOD; the caller degrades on PermissionDenied.
pub fn apply_special(
    root: &Path,
    rel: &str,
    meta: &Meta,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    let dest = safe_dest(root, rel)?;
    let parent = dest
        .parent()
        .ok_or_else(|| ApplyError::UnsafePath(rel.to_string()))?;
    std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;
    // Special ops carry no content hash; the delete-shaped suppression entry
    // covers the node's appearance for the scanner.
    suppress.register_write(rel, [0u8; 32]);

    let stage_seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}{}.{}.{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("s"),
        TMP_SUFFIX,
        std::process::id(),
        stage_seq
    ));
    let stage = || -> Result<(), ApplyError> {
        metadata::create_special(&tmp, meta).map_err(io_err("mknod", &tmp))?;
        metadata::apply_meta(&tmp, meta, policy).map_err(io_err("meta", &tmp))?;
        std::fs::rename(&tmp, &dest).map_err(io_err("rename", &dest))?;
        if let Ok(dirf) = std::fs::File::open(parent) {
            let _ = dirf.sync_all();
        }
        Ok(())
    };
    stage().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Publish one VERSION (content hash + metadata) at `root/rel`, dispatching
/// on the metadata kind: regular files assemble from the CAS manifest;
/// symlinks and special nodes build from the metadata itself (they have no
/// chunk plane). The single materialization entry every receive path uses.
#[allow(clippy::too_many_arguments)]
pub fn apply_version(
    root: &Path,
    rel: &str,
    mode: u32,
    hash: Option<&[u8; 32]>,
    manifest: Option<&crate::chunk::Manifest>,
    cas: &crate::chunk::Cas,
    meta: Option<&Meta>,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    use crate::metadata::FileKind;
    match meta.map(|m| m.kind) {
        Some(FileKind::Symlink) => {
            let (h, m) = (hash, meta);
            match (h, m) {
                (Some(h), Some(m)) => apply_symlink(root, rel, h, m, policy, suppress),
                _ => Err(ApplyError::HashMismatch(rel.to_string())),
            }
        }
        Some(FileKind::Fifo) | Some(FileKind::CharDev) | Some(FileKind::BlockDev) => match meta {
            Some(m) => apply_special(root, rel, m, policy, suppress),
            None => Err(ApplyError::HashMismatch(rel.to_string())),
        },
        _ => match (hash, manifest) {
            (Some(h), Some(man)) => {
                apply_assembled(root, rel, mode, h, man, cas, meta, policy, suppress)
            }
            _ => Err(ApplyError::HashMismatch(rel.to_string())),
        },
    }
}

/// Apply ONLY metadata to an already-current destination (a meta-only op:
/// same bytes, new xattrs/mode/owner/mtime). The content was verified in
/// place by the caller's `have` check; suppression covers the attribute
/// events the change fires.
pub fn apply_meta_only(
    root: &Path,
    rel: &str,
    hash: Option<&[u8; 32]>,
    meta: &Meta,
    policy: OwnerPolicy,
    suppress: &Suppressor,
) -> Result<(), ApplyError> {
    let dest = safe_dest(root, rel)?;
    suppress.register_write(rel, hash.copied().unwrap_or([0u8; 32]));
    metadata::apply_meta(&dest, meta, policy).map_err(io_err("meta", &dest))?;
    Ok(())
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
        apply_write(
            dir.path(),
            "sub/dir/f.txt",
            0o640,
            &hash_of(data),
            data,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap();

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
            apply_write(
                dir.path(),
                "f",
                0o644,
                &hash_of(data),
                data,
                None,
                OwnerPolicy::Skip,
                &s,
            )
            .unwrap();
        }
        assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), data);
    }

    #[test]
    fn rejects_path_escapes_before_any_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let data = b"x";
        for bad in ["../evil", "/abs/path", "a/../../evil", ""] {
            let err = apply_write(
                dir.path(),
                bad,
                0o644,
                &hash_of(data),
                data,
                None,
                OwnerPolicy::Skip,
                &s,
            )
            .unwrap_err();
            assert!(matches!(err, ApplyError::UnsafePath(_)), "{bad}");
        }
        assert!(s.is_empty()); // rejected before suppression registration
        assert!(apply_delete(dir.path(), "../evil", &s).is_err());
    }

    #[test]
    fn rejects_hash_mismatch_without_touching_fs() {
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        let err = apply_write(
            dir.path(),
            "f",
            0o644,
            &[0u8; 32],
            b"data",
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::HashMismatch(_)));
        assert!(!dir.path().join("f").exists());
        assert!(s.is_empty()); // verified before registration
    }

    /// Build a CAS + manifest for `data` split into fixed test chunks.
    fn cas_with(
        data: &[u8],
        chunk_size: usize,
    ) -> (tempfile::TempDir, crate::chunk::Cas, crate::chunk::Manifest) {
        let dir = tempfile::tempdir().unwrap();
        let cas = crate::chunk::Cas::open(&dir.path().join("cas")).unwrap();
        let mut chunks = Vec::new();
        for piece in data.chunks(chunk_size.max(1)) {
            let h = *blake3::hash(piece).as_bytes();
            cas.put_verified(&h, piece).unwrap();
            chunks.push(crate::proto::ChunkEntry {
                hash: h,
                len: piece.len() as u32,
            });
        }
        let manifest = crate::chunk::Manifest {
            content_hash: *blake3::hash(data).as_bytes(),
            chunks,
        };
        (dir, cas, manifest)
    }

    #[test]
    fn assembled_publish_round_trips_with_mode() {
        let data: Vec<u8> = (0u32..40_000).map(|i| (i % 251) as u8).collect();
        let (dir, cas, manifest) = cas_with(&data, 7000);
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let s = Suppressor::new();

        apply_assembled(
            &share,
            "a/big.bin",
            0o640,
            &manifest.content_hash,
            &manifest,
            &cas,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap();
        let dest = share.join("a/big.bin");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert!(s.check_write("a/big.bin", &manifest.content_hash));
        // Idempotent re-assembly (the crash-redelivery path).
        apply_assembled(
            &share,
            "a/big.bin",
            0o640,
            &manifest.content_hash,
            &manifest,
            &cas,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn assembled_whole_file_mismatch_publishes_nothing() {
        let data = b"some data".to_vec();
        let (dir, cas, mut manifest) = cas_with(&data, 4);
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let s = Suppressor::new();

        // Manifest lies about the whole-file hash: rejected BEFORE any fs work.
        manifest.content_hash = [0xee; 32];
        let err = apply_assembled(
            &share,
            "f",
            0o644,
            &[0xee; 32],
            &manifest,
            &cas,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::HashMismatch(_)));
        assert!(!share.join("f").exists());
        assert!(!walk_has_tmp(&share));
    }

    #[test]
    fn assembled_missing_chunk_cleans_up_temp() {
        let data: Vec<u8> = vec![7; 10_000];
        let (dir, cas, manifest) = cas_with(&data, 3000);
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let s = Suppressor::new();

        // Lose a chunk from the CAS (simulates an interrupted fetch).
        std::fs::remove_file(cas.path_for(&manifest.chunks[1].hash)).unwrap();
        let err = apply_assembled(
            &share,
            "g",
            0o644,
            &manifest.content_hash,
            &manifest,
            &cas,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Cas(_)), "{err:?}");
        assert!(!share.join("g").exists());
        assert!(!walk_has_tmp(&share)); // staged temp removed on failure
    }

    #[test]
    fn dir_squatting_the_path_fails_with_a_directory_error_kind() {
        // Review finding S6: a LOCAL directory occupying a replicated file's
        // path must surface as a directory-shaped io error — the receive
        // paths classify those PERMANENT (quarantine) instead of retrying
        // the same poison op forever.
        let dir = tempfile::tempdir().unwrap();
        let s = Suppressor::new();
        std::fs::create_dir_all(dir.path().join("x")).unwrap();

        // Write onto the dir: the publish rename hits EISDIR.
        let data = b"file content";
        let err = apply_write(
            dir.path(),
            "x",
            0o644,
            &hash_of(data),
            data,
            None,
            OwnerPolicy::Skip,
            &s,
        )
        .unwrap_err();
        match &err {
            ApplyError::Io { source, .. } => assert!(
                matches!(
                    source.kind(),
                    std::io::ErrorKind::IsADirectory | std::io::ErrorKind::DirectoryNotEmpty
                ),
                "unexpected kind: {source:?}"
            ),
            other => panic!("expected Io, got {other:?}"),
        }
        // No staged temp left behind.
        assert!(!walk_has_tmp(dir.path()));

        // Delete of the dir path: unlink hits EISDIR too.
        let err = apply_delete(dir.path(), "x", &s).unwrap_err();
        match &err {
            ApplyError::Io { source, .. } => assert!(
                matches!(source.kind(), std::io::ErrorKind::IsADirectory),
                "unexpected kind: {source:?}"
            ),
            other => panic!("expected Io, got {other:?}"),
        }
        // The directory survives untouched either way.
        assert!(dir.path().join("x").is_dir());
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
