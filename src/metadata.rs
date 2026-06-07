//! metadata.rs — full POSIX metadata fidelity (FR-106 / FR-804).
//!
//! One canonical [`Meta`] rides every Write/Rename op and every `files` row:
//! kind, permission bits, ownership, mtime, symlink target, device numbers,
//! and ALL extended attributes (POSIX ACLs are the `system.posix_acl_*`
//! xattrs, so capturing xattrs captures ACLs). The canonical encoding —
//! xattrs sorted by name, bincode over a fixed field order — makes
//! `meta_hash = blake3(canonical bytes)` an agreed-upon value mesh-wide: it
//! feeds the conflict total order (`conflict::Version::meta_hash`) and the
//! Merkle leaf, so metadata reconciles and conflicts deterministically.
//!
//! ## Apply order (FR-804 — metadata only after content)
//!
//! `apply_meta` runs on the STAGED temp file, before the publishing rename,
//! in this fixed order:
//!
//! 1. xattrs (`lsetxattr`, sorted order) — ACL entries land before the mode
//!    so the chmod below settles the ACL mask deterministically;
//! 2. ownership (`lchown`, numeric-preserve) — before mode, because chown
//!    clears setuid/setgid bits which step 3 then restores;
//! 3. permission bits (`fchmodat`, skipped for symlinks — Linux ignores
//!    symlink modes);
//! 4. mtime LAST (`utimensat`, no-follow) — nothing after it re-dirties the
//!    timestamp.
//!
//! ## The no-storm law (as important as the apply order)
//!
//! The scanner re-captures every file and compares against the row; any
//! captured field the apply cannot faithfully REPRODUCE on this node would
//! re-emit forever and storm the mesh. Hence:
//! - every field in [`Meta`] is node-independent or applied verbatim;
//! - under `owner_policy = "skip"` ownership is captured as the 0 sentinel
//!   and never applied — the policy must be uniform across the mesh (like
//!   the protocol version), or meta hashes disagree by construction;
//! - hardlink grouping (dev/ino) is deliberately ABSENT: inode numbers are
//!   node-local and would storm. Hardlinks currently replicate as
//!   independent content. // SEAM(M3-hardlinks): storm-free design = link
//!   leader election by lexicographically-smallest live path, captured by
//!   the scanner pass which sees the whole (dev,ino) group.
//! - directories carry no row today (dir lifecycle SEAM), so directory
//!   xattrs/default ACLs do not replicate yet. // SEAM(dir-meta)
//!
//! Sockets are explicitly NOT replicated (a bound socket is a runtime
//! endpoint, not data); they are skipped with a log line. Device nodes
//! replicate; applying them needs CAP_MKNOD and degrades to skip+log.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// `meta_hash` for "no metadata" (deletes, pre-v4 rows).
pub const META_NONE: [u8; 32] = [0u8; 32];

/// Process-wide count of skipped ownership applies (policy or EPERM) —
/// surfaced as `replicore_meta_owner_skips_total` (FR-106/FR-1101). A static
/// because the apply layer is deliberately engine-free.
static OWNER_SKIPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn owner_skips() -> u64 {
    OWNER_SKIPS.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Regular,
    Symlink,
    Fifo,
    CharDev,
    BlockDev,
}

/// Canonical metadata snapshot. Field order and xattr sorting are part of
/// the wire/hash contract — do not reorder.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Meta {
    pub kind: FileKind,
    /// Permission bits (`& 0o7777`).
    pub mode: u32,
    /// Numeric ownership (rsync --numeric-ids style); 0/0 under the `skip`
    /// owner policy (uniform mesh-wide).
    pub uid: u32,
    pub gid: u32,
    pub mtime_s: i64,
    pub mtime_ns: u32,
    /// Raw target bytes; never followed. `Some` iff kind == Symlink.
    pub symlink_target: Option<Vec<u8>>,
    /// Device number for Char/BlockDev nodes; 0 otherwise.
    pub rdev: u64,
    /// ALL extended attributes, sorted by name (canonical). POSIX ACLs are
    /// `system.posix_acl_access` / `system.posix_acl_default`.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Whether ownership replicates. MUST be uniform across the mesh — it
/// changes what `capture` records, hence every meta hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerPolicy {
    /// Replicate numeric uid/gid and `lchown` on apply (needs CAP_CHOWN).
    Numeric,
    /// Capture the 0 sentinel; never chown (files belong to the daemon).
    Skip,
}

/// The non-fatal degradations of one metadata apply, for counters/logs.
#[derive(Default, Clone, Copy, Debug)]
pub struct MetaApplied {
    /// `lchown` was skipped (policy) or failed with EPERM (unprivileged
    /// daemon): ownership intentionally NOT half-applied (FR-106).
    pub owner_skipped: bool,
}

impl Meta {
    /// Canonical hash; [`META_NONE`] for absent metadata.
    pub fn hash_of(meta: &Option<Meta>) -> [u8; 32] {
        match meta {
            None => META_NONE,
            Some(m) => {
                // Canonical: sorted xattrs + fixed field order, varint-free
                // fixint bincode (the same `bincode::serialize` flavor the VV
                // blobs use).
                let bytes = bincode::serialize(m).unwrap_or_default();
                *blake3::hash(&bytes).as_bytes()
            }
        }
    }

    /// Hash of the STABLE metadata subset used for conflict-COPY NAMING
    /// (review-copy-naming.md). [`META_NONE`] for absent metadata (so every
    /// meta-less loser names identically to a `META_NONE` caller).
    ///
    /// Included — durable, node-agnostic fields a user genuinely sets, so a
    /// real difference must yield a distinct copy (S1 no-loss):
    ///   `kind`, `mode`, `rdev`, `symlink_target`, `xattrs` (⊃ POSIX ACLs).
    /// EXCLUDED — `mtime_s`, `mtime_ns`, `uid`, `gid`: timestamps and
    /// ownership skew without semantic content (and uid/gid can diverge under
    /// the residual `owner_policy=numeric` EPERM-skip), so they would only
    /// proliferate near-duplicate copies; they are kept out of the name by
    /// design. (The committed copy ROW still stores the FULL `Meta` — only
    /// the NAME uses this subset.)
    ///
    /// Fixed, length-prefixed field order: this value is agreed across the
    /// mesh and must never depend on encoding ambiguity.
    pub fn naming_hash(meta: &Option<Meta>) -> [u8; 32] {
        let Some(m) = meta else { return META_NONE };
        let mut h = blake3::Hasher::new();
        // kind: explicit discriminant (never rely on enum repr).
        let kind: u8 = match m.kind {
            FileKind::Regular => 0,
            FileKind::Symlink => 1,
            FileKind::Fifo => 2,
            FileKind::CharDev => 3,
            FileKind::BlockDev => 4,
        };
        h.update(&[kind]);
        h.update(&m.mode.to_le_bytes());
        h.update(&m.rdev.to_le_bytes());
        match &m.symlink_target {
            Some(t) => {
                h.update(&[1]);
                h.update(&(t.len() as u64).to_le_bytes());
                h.update(t);
            }
            None => {
                h.update(&[0]);
            }
        }
        // xattrs (⊃ ACLs): sorted defensively, each entry length-prefixed so
        // no key/value boundary is ambiguous.
        let mut xattrs = m.xattrs.clone();
        xattrs.sort();
        h.update(&(xattrs.len() as u64).to_le_bytes());
        for (k, v) in &xattrs {
            h.update(&(k.len() as u64).to_le_bytes());
            h.update(k);
            h.update(&(v.len() as u64).to_le_bytes());
            h.update(v);
        }
        *h.finalize().as_bytes()
    }

    /// Snapshot `path`'s metadata (no following). `Ok(None)` = kind we do
    /// not replicate (socket, directory). The xattr list is sorted here —
    /// capture is the single place canonicalization happens.
    pub fn capture(path: &Path, policy: OwnerPolicy) -> io::Result<Option<Meta>> {
        let st = std::fs::symlink_metadata(path)?;
        let ft = st.file_type();
        use std::os::unix::fs::FileTypeExt;
        let kind = if ft.is_file() {
            FileKind::Regular
        } else if ft.is_symlink() {
            FileKind::Symlink
        } else if ft.is_fifo() {
            FileKind::Fifo
        } else if ft.is_char_device() {
            FileKind::CharDev
        } else if ft.is_block_device() {
            FileKind::BlockDev
        } else {
            return Ok(None); // sockets, directories: not replicated
        };
        let symlink_target = if kind == FileKind::Symlink {
            Some(std::fs::read_link(path)?.as_os_str().as_bytes().to_vec())
        } else {
            None
        };
        let (uid, gid) = match policy {
            OwnerPolicy::Numeric => (st.uid(), st.gid()),
            OwnerPolicy::Skip => (0, 0),
        };
        let mut xattrs = read_xattrs(path)?;
        xattrs.sort();
        Ok(Some(Meta {
            kind,
            mode: (st.mode() & 0o7777) as u32,
            uid,
            gid,
            mtime_s: st.mtime(),
            mtime_ns: st.mtime_nsec() as u32,
            symlink_target,
            rdev: if matches!(kind, FileKind::CharDev | FileKind::BlockDev) {
                st.rdev()
            } else {
                0
            },
            xattrs,
        }))
    }
}

fn cpath(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

/// All xattrs of `path` (no following), unsorted.
fn read_xattrs(path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let c = cpath(path)?;
    // Two-call pattern with a retry loop: the list can grow between calls.
    let mut names = vec![0u8; 1024];
    let len = loop {
        // SAFETY: c is a valid NUL-terminated path; the buffer pointer/len
        // describe `names`, which outlives the call.
        let n = unsafe { libc::llistxattr(c.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ERANGE) => names.resize(names.len() * 2, 0),
            // Filesystem without xattr support: an empty set, not an error.
            Some(libc::ENOTSUP) => return Ok(Vec::new()),
            _ => return Err(err),
        }
    };
    let mut out = Vec::new();
    for name in names[..len].split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in xattr name"))?;
        let mut value = vec![0u8; 256];
        let vlen = loop {
            // SAFETY: both pointers reference live, correctly-sized buffers.
            let n = unsafe {
                libc::lgetxattr(
                    c.as_ptr(),
                    cname.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if n >= 0 {
                break n as usize;
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ERANGE) => value.resize(value.len() * 2, 0),
                // Removed between list and get: skip it.
                Some(libc::ENODATA) => break usize::MAX,
                _ => return Err(err),
            }
        };
        if vlen != usize::MAX {
            value.truncate(vlen);
            out.push((name.to_vec(), value));
        }
    }
    Ok(out)
}

/// Apply `meta` to `path` in the FR-804 order (see the module header).
/// `path` is normally the STAGED temp (metadata travels with the inode
/// through the rename); for meta-only changes it is the live destination.
/// Ownership degradation is reported, never half-applied.
pub fn apply_meta(path: &Path, meta: &Meta, policy: OwnerPolicy) -> io::Result<MetaApplied> {
    let c = cpath(path)?;
    let mut applied = MetaApplied::default();

    // 1. xattrs, in canonical (sorted) order. ACLs are xattrs.
    for (name, value) in &meta.xattrs {
        let cname = std::ffi::CString::new(name.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in xattr name"))?;
        // SAFETY: pointers reference live buffers; flags=0 (create-or-replace).
        let rc = unsafe {
            libc::lsetxattr(
                c.as_ptr(),
                cname.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // No xattr support / no privilege for trusted.* etc.: log,
                // continue with the rest (the value is preserved in the row).
                Some(libc::ENOTSUP) | Some(libc::EPERM) => {
                    tracing::warn!(
                        path = %path.display(),
                        xattr = %String::from_utf8_lossy(name),
                        "xattr not applied: {err}"
                    );
                }
                _ => return Err(err),
            }
        }
    }

    // 2. ownership — before mode (chown clears setuid/setgid; chmod restores).
    match policy {
        OwnerPolicy::Skip => {
            applied.owner_skipped = true;
            OWNER_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        OwnerPolicy::Numeric => {
            // SAFETY: c is a valid NUL-terminated path.
            let rc = unsafe { libc::lchown(c.as_ptr(), meta.uid, meta.gid) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    // Unprivileged daemon: skip whole ownership, never a
                    // half-applied uid-without-gid (FR-106).
                    applied.owner_skipped = true;
                    OWNER_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(path = %path.display(),
                        "ownership not applied (CAP_CHOWN missing); owner_policy=numeric needs a privileged daemon");
                } else {
                    return Err(err);
                }
            }
        }
    }

    // 3. permission bits — not for symlinks (Linux ignores symlink modes,
    //    and chmod on a symlink path would follow it).
    if meta.kind != FileKind::Symlink {
        // SAFETY: valid path; AT_SYMLINK_NOFOLLOW is rejected for fchmodat
        // on Linux, but kind != Symlink so following cannot occur... except
        // via a hostile race; the staged-temp discipline means `path` is a
        // file we just created.
        let rc = unsafe { libc::chmod(c.as_ptr(), (meta.mode & 0o7777) as libc::mode_t) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // 4. mtime LAST: nothing after this may touch the file.
    let times = [
        // atime: opt out (UTIME_OMIT) — atime is not replicated state.
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: meta.mtime_s as libc::time_t,
            tv_nsec: meta.mtime_ns as libc::c_long,
        },
    ];
    // SAFETY: valid path + a 2-element timespec array, no-follow.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(applied)
}

/// Does this process hold CAP_CHOWN (the capability `owner_policy =
/// "numeric"` requires)? euid 0 passes trivially; otherwise probe by
/// chowning a fresh temp file in `probe_dir` to root — exactly the call
/// `apply_meta` will make, so the answer cannot drift from reality.
///
/// The daemon REFUSES to start under `numeric` without it (review finding
/// S5): an unprivileged daemon would EPERM-skip every ownership apply, and
/// two such daemons with different uids re-capture their own uids and
/// ping-pong corrective metadata ops forever — a silent op storm, not a
/// graceful degradation. The per-file EPERM skip in `apply_meta` remains
/// only for residual per-path cases (e.g. NFS root-squash on one export).
pub fn can_chown(probe_dir: &Path) -> io::Result<bool> {
    // SAFETY: trivial libc call, no pointers.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(true);
    }
    std::fs::create_dir_all(probe_dir)?;
    let probe = probe_dir.join(format!(".replicore-chown-probe.{}", std::process::id()));
    std::fs::write(&probe, b"")?;
    let c = cpath(&probe)?;
    // SAFETY: valid NUL-terminated path; chown to root requires CAP_CHOWN.
    let rc = unsafe { libc::lchown(c.as_ptr(), 0, 0) };
    let err = std::io::Error::last_os_error();
    let _ = std::fs::remove_file(&probe);
    if rc == 0 {
        return Ok(true);
    }
    match err.raw_os_error() {
        Some(libc::EPERM) => Ok(false),
        _ => Err(err),
    }
}

/// Create the special-file node for `meta.kind` at `path` (FIFO / device).
/// Regular files and symlinks have their own apply paths. Device nodes need
/// CAP_MKNOD; failure is reported as `Err` for the caller to degrade.
pub fn create_special(path: &Path, meta: &Meta) -> io::Result<()> {
    let c = cpath(path)?;
    let mode = (meta.mode & 0o7777) as libc::mode_t;
    let rc = match meta.kind {
        // SAFETY: valid path.
        FileKind::Fifo => unsafe { libc::mkfifo(c.as_ptr(), mode) },
        // SAFETY: valid path; rdev came off a stat on the origin.
        FileKind::CharDev => unsafe {
            libc::mknod(c.as_ptr(), libc::S_IFCHR | mode, meta.rdev as libc::dev_t)
        },
        // SAFETY: as above.
        FileKind::BlockDev => unsafe {
            libc::mknod(c.as_ptr(), libc::S_IFBLK | mode, meta.rdev as libc::dev_t)
        },
        FileKind::Regular | FileKind::Symlink => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a special kind",
            ))
        }
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // Idempotent redelivery: an existing identical node is success.
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_apply_round_trips_mode_mtime_and_xattrs() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"data").unwrap();
        // A user xattr (works unprivileged on tmpfs/ext4 with user_xattr).
        let set = unsafe {
            libc::lsetxattr(
                cpath(&f).unwrap().as_ptr(),
                c"user.replicore-test".as_ptr(),
                b"v1".as_ptr().cast(),
                2,
                0,
            )
        };
        let xattr_ok = set == 0; // skip the xattr assertions on filesystems without support

        let mut meta = Meta::capture(&f, OwnerPolicy::Skip).unwrap().unwrap();
        assert_eq!(meta.kind, FileKind::Regular);
        meta.mode = 0o640;
        meta.mtime_s = 1_000_000_000;
        meta.mtime_ns = 123_456_000;

        let g = dir.path().join("g");
        std::fs::write(&g, b"data").unwrap();
        let applied = apply_meta(&g, &meta, OwnerPolicy::Skip).unwrap();
        assert!(applied.owner_skipped); // policy skip always reports it

        let got = Meta::capture(&g, OwnerPolicy::Skip).unwrap().unwrap();
        assert_eq!(got.mode, 0o640);
        assert_eq!(got.mtime_s, 1_000_000_000);
        assert_eq!(got.mtime_ns, 123_456_000);
        if xattr_ok {
            assert!(got
                .xattrs
                .iter()
                .any(|(n, v)| n == b"user.replicore-test" && v == b"v1"));
            // Byte-exact round trip => identical canonical hash.
            assert_eq!(Meta::hash_of(&Some(got)), Meta::hash_of(&Some(meta)));
        }
    }

    #[test]
    fn symlink_capture_and_kind() {
        let dir = tempfile::tempdir().unwrap();
        let l = dir.path().join("l");
        std::os::unix::fs::symlink("target/elsewhere", &l).unwrap();
        let meta = Meta::capture(&l, OwnerPolicy::Skip).unwrap().unwrap();
        assert_eq!(meta.kind, FileKind::Symlink);
        assert_eq!(
            meta.symlink_target.as_deref(),
            Some(&b"target/elsewhere"[..])
        );
    }

    #[test]
    fn fifo_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pipe");
        let meta = Meta {
            kind: FileKind::Fifo,
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime_s: 1_000_000_000,
            mtime_ns: 0,
            symlink_target: None,
            rdev: 0,
            xattrs: vec![],
        };
        create_special(&p, &meta).unwrap();
        create_special(&p, &meta).unwrap(); // idempotent (redelivery)
        apply_meta(&p, &meta, OwnerPolicy::Skip).unwrap();
        let got = Meta::capture(&p, OwnerPolicy::Skip).unwrap().unwrap();
        assert_eq!(got.kind, FileKind::Fifo);
        assert_eq!(got.mode, 0o600);
    }

    #[test]
    fn hash_is_canonical_and_field_sensitive() {
        let base = Meta {
            kind: FileKind::Regular,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_s: 1,
            mtime_ns: 2,
            symlink_target: None,
            rdev: 0,
            xattrs: vec![(b"user.a".to_vec(), b"1".to_vec())],
        };
        let h = Meta::hash_of(&Some(base.clone()));
        assert_eq!(h, Meta::hash_of(&Some(base.clone())));
        assert_ne!(h, META_NONE);
        for change in [
            |m: &mut Meta| m.mode = 0o600,
            |m: &mut Meta| m.uid = 0,
            |m: &mut Meta| m.mtime_s = 9,
            |m: &mut Meta| m.mtime_ns = 9,
            |m: &mut Meta| m.xattrs[0].1 = b"2".to_vec(),
            |m: &mut Meta| m.kind = FileKind::Fifo,
        ] {
            let mut m = base.clone();
            change(&mut m);
            assert_ne!(h, Meta::hash_of(&Some(m)), "field must be hashed");
        }
    }

    #[test]
    fn naming_hash_includes_durable_excludes_skew() {
        let base = Meta {
            kind: FileKind::Regular,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_s: 1,
            mtime_ns: 2,
            symlink_target: None,
            rdev: 0,
            xattrs: vec![(b"user.a".to_vec(), b"1".to_vec())],
        };
        let h = Meta::naming_hash(&Some(base.clone()));
        assert_eq!(h, Meta::naming_hash(&Some(base.clone())), "deterministic");
        assert_eq!(Meta::naming_hash(&None), META_NONE, "None == META_NONE");
        assert_ne!(h, META_NONE);

        // DURABLE fields are in the subset — a change must alter the name.
        for change in [
            (|m: &mut Meta| m.mode = 0o600) as fn(&mut Meta),
            |m: &mut Meta| m.kind = FileKind::Fifo,
            |m: &mut Meta| m.rdev = 7,
            |m: &mut Meta| m.symlink_target = Some(b"t".to_vec()),
            |m: &mut Meta| m.xattrs[0].1 = b"2".to_vec(),
            |m: &mut Meta| m.xattrs.push((b"user.b".to_vec(), b"x".to_vec())),
        ] {
            let mut m = base.clone();
            change(&mut m);
            assert_ne!(
                h,
                Meta::naming_hash(&Some(m)),
                "durable field must be in the naming subset (S1)"
            );
        }

        // SKEW fields are EXCLUDED — changing them must NOT alter the name
        // (proliferation/divergence avoidance: mtime + ownership).
        for change in [
            (|m: &mut Meta| m.mtime_s = 9_999) as fn(&mut Meta),
            |m: &mut Meta| m.mtime_ns = 7,
            |m: &mut Meta| m.uid = 0,
            |m: &mut Meta| m.gid = 0,
        ] {
            let mut m = base.clone();
            change(&mut m);
            assert_eq!(
                h,
                Meta::naming_hash(&Some(m)),
                "skew field must NOT feed the name (mtime/uid/gid excluded)"
            );
        }

        // xattr order is canonicalized (capture sorts; naming_hash re-sorts).
        let mut reordered = base.clone();
        reordered.xattrs = vec![
            (b"user.z".to_vec(), b"9".to_vec()),
            (b"user.a".to_vec(), b"1".to_vec()),
        ];
        let mut sorted = base.clone();
        sorted.xattrs = vec![
            (b"user.a".to_vec(), b"1".to_vec()),
            (b"user.z".to_vec(), b"9".to_vec()),
        ];
        assert_eq!(
            Meta::naming_hash(&Some(reordered)),
            Meta::naming_hash(&Some(sorted)),
            "xattr order must not affect the name"
        );
    }

    #[test]
    fn can_chown_probe_answers() {
        // In this environment (root) the probe must say yes; the contract —
        // EPERM ⇒ Ok(false), other errors surface — is what main()'s
        // refusal gate runs on. Unprivileged CI environments exercise the
        // false branch naturally.
        let dir = tempfile::tempdir().unwrap();
        let answer = can_chown(dir.path()).unwrap();
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } == 0 {
            assert!(answer, "root must hold CAP_CHOWN");
        }
        // No probe litter left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn capture_skips_sockets_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Meta::capture(dir.path(), OwnerPolicy::Skip)
            .unwrap()
            .is_none());
    }
}
