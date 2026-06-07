//! watch.rs — change detection via fanotify FID reporting (FR-102).
//!
//! Three tiers, probed at startup, best first:
//!
//! 1. **FID + FAN_RENAME** (kernel ≥ 5.17): a FILESYSTEM mark with
//!    `FAN_REPORT_DFID_NAME` delivers create/delete/rename/attrib/close-write
//!    with (parent directory handle, name) — renames arrive as ONE event with
//!    both ends, feeding the identity-preserving rename path (FR-205).
//! 2. **FID without FAN_RENAME** (kernel ≥ 5.9): `FAN_MOVED_FROM`/`_TO`
//!    degrade to delete+create observations (correct, not identity-
//!    preserving — the rename arrives as two ops).
//! 3. **Legacy** (older kernels): the M1 mount mark with `FAN_CLOSE_WRITE`
//!    only; create/delete/rename remain the scanner's job.
//!
//! In every tier the periodic scanner stays AUTHORITATIVE (FR-103/104 and
//! docs/DEPLOYMENT-NFS.md — never weaken the rescan on the assumption that
//! fanotify catches everything): the watcher is the low-latency path, the
//! scan is the correctness backstop. `FAN_Q_OVERFLOW` wakes a targeted
//! rescan. Directory events are not subscribed (no `FAN_ONDIR`) — a moved
//! directory surfaces through the scanner as per-child changes; dir lifecycle
//! is a SEAM.
//!
//! Self-event hygiene: our own applies stage under `TMP_SUFFIX` names and
//! publish via rename — the watcher drops tmp-path events, reports the
//! publish-rename as a plain Write of the destination, and ingest's
//! suppression entries (registered before every mutation, FR-902) swallow
//! the rest.
//!
//! Requires CAP_SYS_ADMIN; tier 1/2 resolution additionally uses
//! `open_by_handle_at` (CAP_DAC_READ_SEARCH — implied by running the daemon
//! as root, which fanotify already demands). Runs a blocking read loop; call
//! it on its own thread.

use anyhow::{Context, Result};
use std::ffi::CString;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use crate::ingest::LocalEvent;
use crate::TMP_SUFFIX;

pub fn run(
    dir: &Path,
    tx: tokio::sync::mpsc::Sender<LocalEvent>,
    rescan: Arc<tokio::sync::Notify>,
) -> Result<()> {
    match Fid::init(dir) {
        Ok(fid) => {
            tracing::info!(
                dir = %dir.display(),
                renames = fid.rename_events,
                "fanotify armed: FID reporting (FR-102)"
            );
            fid.run(dir, tx, rescan)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "fanotify FID mode unavailable (kernel < 5.9?); falling back to \
                 close-write-only watch — create/delete/rename ride the scanner"
            );
            run_legacy(dir, tx, rescan)
        }
    }
}

/// The FID-mode watcher: fanotify fd + a mount fd anchoring
/// `open_by_handle_at` resolution.
struct Fid {
    fan: i32,
    mount_fd: i32,
    /// Tier 1: the kernel delivers `FAN_RENAME` (both ends in one event).
    rename_events: bool,
}

impl Drop for Fid {
    fn drop(&mut self) {
        // SAFETY: fds owned by this struct, closed exactly once here.
        unsafe {
            libc::close(self.fan);
            libc::close(self.mount_fd);
        }
    }
}

impl Fid {
    fn init(dir: &Path) -> Result<Fid> {
        // SAFETY: plain syscall, flags are constants.
        let fan = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fan < 0 {
            return Err(std::io::Error::last_os_error())
                .context("fanotify_init(FAN_REPORT_DFID_NAME)");
        }
        let cpath = CString::new(dir.as_os_str().as_bytes()).context("path has interior NUL")?;
        // Anchor for open_by_handle_at: any fd on the watched filesystem.
        // SAFETY: valid NUL-terminated path; flags are constants.
        let mount_fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if mount_fd < 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: fan was opened above and is not used after this.
            unsafe { libc::close(fan) };
            return Err(e).context("open(share dir)");
        }

        // Directory-entry events need a FILESYSTEM mark (mount marks do not
        // deliver them). Try the tier-1 mask (with FAN_RENAME) first.
        // NB: FAN_Q_OVERFLOW is delivered unconditionally and is NOT a
        // valid mark mask bit (EINVAL) — never add it here.
        const BASE: u64 =
            libc::FAN_CLOSE_WRITE | libc::FAN_ATTRIB | libc::FAN_CREATE | libc::FAN_DELETE;
        let mark = |mask: u64| -> i32 {
            // SAFETY: fan/mount path are valid; constants otherwise.
            unsafe {
                libc::fanotify_mark(
                    fan,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    mask,
                    libc::AT_FDCWD,
                    cpath.as_ptr(),
                )
            }
        };
        let rename_events = if mark(BASE | libc::FAN_RENAME) == 0 {
            true
        } else if mark(BASE | libc::FAN_MOVED_FROM | libc::FAN_MOVED_TO) == 0 {
            false // tier 2: kernel < 5.17
        } else {
            let e = std::io::Error::last_os_error();
            // SAFETY: both fds opened above, not used after this.
            unsafe {
                libc::close(fan);
                libc::close(mount_fd);
            }
            return Err(e).context("fanotify_mark(FILESYSTEM, dirent events)");
        };
        Ok(Fid {
            fan,
            mount_fd,
            rename_events,
        })
    }

    fn run(
        self,
        dir: &Path,
        tx: tokio::sync::mpsc::Sender<LocalEvent>,
        rescan: Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        // Info records carry variable-length handles + names: read big.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: buf outlives the call; len is its real size.
            let n =
                unsafe { libc::read(self.fan, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e).context("read(fanotify)");
            }
            let n = n as usize;
            let mut off = 0usize;
            let meta_sz = size_of::<libc::fanotify_event_metadata>();
            while n - off >= meta_sz {
                // SAFETY: bounds-checked above. read_unaligned because a
                // Vec<u8> allocation guarantees no alignment — the structs
                // are copied out, never referenced in place.
                let meta = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr().add(off) as *const libc::fanotify_event_metadata
                    )
                };
                let ev_len = meta.event_len as usize;
                if ev_len < meta_sz || off + ev_len > n {
                    break; // malformed / truncated; never spin
                }
                if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                    tracing::warn!("fanotify queue overflow; triggering targeted rescan (FR-104)");
                    rescan.notify_one();
                }
                // FID events carry no fd; paths come from the info records.
                let ev = self.parse_event(&buf[off..off + ev_len], meta_sz);
                for event in self.dispatch(dir, meta.mask, ev) {
                    // blocking_send applies backpressure (FR-1106) onto the
                    // kernel read loop, which is the behavior we want.
                    if tx.blocking_send(event).is_err() {
                        return Ok(()); // receiver gone; shutting down
                    }
                }
                off += ev_len;
            }
        }
    }

    /// Paths a single event names: (the object, rename-old, rename-new).
    fn parse_event(&self, event: &[u8], meta_sz: usize) -> EventPaths {
        let mut out = EventPaths::default();
        let mut off = meta_sz;
        let hdr_sz = size_of::<libc::fanotify_event_info_header>();
        while event.len() - off >= hdr_sz {
            // SAFETY: bounds-checked; copied out unaligned (plain bytes).
            let hdr = unsafe {
                std::ptr::read_unaligned(
                    event.as_ptr().add(off) as *const libc::fanotify_event_info_header
                )
            };
            let len = hdr.len as usize;
            if len < hdr_sz || off + len > event.len() {
                break; // malformed record; stop parsing this event
            }
            match hdr.info_type {
                libc::FAN_EVENT_INFO_TYPE_DFID_NAME => {
                    out.path = self.resolve_dfid_name(&event[off..off + len]);
                }
                libc::FAN_EVENT_INFO_TYPE_OLD_DFID_NAME => {
                    out.old = self.resolve_dfid_name(&event[off..off + len]);
                }
                libc::FAN_EVENT_INFO_TYPE_NEW_DFID_NAME => {
                    out.new = self.resolve_dfid_name(&event[off..off + len]);
                }
                _ => {} // fid-only records etc.: not needed
            }
            off += len;
        }
        out
    }

    /// Decode one `fanotify_event_info_fid` record with a trailing name:
    /// header ‖ fsid ‖ file_handle{handle_bytes, handle_type, f_handle[..]} ‖
    /// NUL-terminated name — resolve the parent-directory handle and join.
    fn resolve_dfid_name(&self, rec: &[u8]) -> Option<PathBuf> {
        let fid_sz = size_of::<libc::fanotify_event_info_fid>(); // hdr + fsid
        let fh_fixed = size_of::<libc::c_uint>() + size_of::<libc::c_int>();
        if rec.len() < fid_sz + fh_fixed {
            return None;
        }
        // SAFETY: bounds-checked; the file_handle's fixed head is two ints.
        let handle_bytes = u32::from_ne_bytes(rec[fid_sz..fid_sz + 4].try_into().ok()?) as usize;
        let name_off = fid_sz + fh_fixed + handle_bytes;
        if name_off >= rec.len() {
            return None;
        }
        let name_bytes = &rec[name_off..];
        let name_end = name_bytes.iter().position(|&b| b == 0)?;
        let name = std::ffi::OsStr::from_bytes(&name_bytes[..name_end]);

        // SAFETY: the pointer references the kernel-written file_handle in
        // our buffer (fixed head + handle_bytes payload, bounds-checked);
        // open_by_handle_at only reads it.
        let dirfd = unsafe {
            libc::open_by_handle_at(
                self.mount_fd,
                rec.as_ptr().add(fid_sz) as *mut libc::file_handle,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_PATH,
            )
        };
        if dirfd < 0 {
            // ESTALE: the directory vanished between event and resolve — the
            // scanner pass owns whatever happened there.
            return None;
        }
        let dir = std::fs::read_link(format!("/proc/self/fd/{dirfd}")).ok();
        // SAFETY: dirfd opened above, closed exactly once.
        unsafe { libc::close(dirfd) };
        let dir = dir?;
        if name == "." {
            Some(dir) // event on the directory itself
        } else {
            Some(dir.join(name))
        }
    }

    /// Turn one event's mask + paths into ingest events, filtering our own
    /// staging temps and anything outside the share.
    fn dispatch(&self, share: &Path, mask: u64, ev: EventPaths) -> Vec<LocalEvent> {
        let mut out = Vec::new();
        let inside = |p: &PathBuf| p.starts_with(share) && !is_tmp(p);
        let rel = |p: &PathBuf| {
            p.strip_prefix(share)
                .ok()
                .and_then(|r| r.to_str())
                .map(str::to_string)
        };

        if mask & libc::FAN_RENAME != 0 {
            match (ev.old.filter(inside), ev.new.filter(inside)) {
                (Some(old), Some(new)) => {
                    if is_tmp(&old) {
                        // Our own publish rename (stage → dest): a plain
                        // write of the destination; suppression swallows it.
                        out.push(LocalEvent::Write(new));
                    } else if let Some(from) = rel(&old) {
                        out.push(LocalEvent::Rename { from, to: new });
                    }
                }
                // Half outside the share: the inside half is a delete or
                // an appearance respectively.
                (Some(old), None) => {
                    if let Some(from) = rel(&old) {
                        out.push(LocalEvent::Delete(from));
                    }
                }
                (None, Some(new)) => out.push(LocalEvent::Write(new)),
                (None, None) => {}
            }
            return out;
        }

        if mask & (libc::FAN_DELETE | libc::FAN_MOVED_FROM) != 0 {
            if let Some(gone) = ev.path.clone().filter(inside).and_then(|p| rel(&p)) {
                out.push(LocalEvent::Delete(gone));
            }
        }
        if mask & (libc::FAN_CREATE | libc::FAN_CLOSE_WRITE | libc::FAN_ATTRIB | libc::FAN_MOVED_TO)
            != 0
        {
            if let Some(p) = ev.path.filter(inside) {
                out.push(LocalEvent::Write(p));
            }
        }
        out
    }
}

#[derive(Default)]
struct EventPaths {
    path: Option<PathBuf>,
    old: Option<PathBuf>,
    new: Option<PathBuf>,
}

/// The M1 fallback: mount mark, FAN_CLOSE_WRITE only, fd-based resolution.
fn run_legacy(
    dir: &Path,
    tx: tokio::sync::mpsc::Sender<LocalEvent>,
    rescan: Arc<tokio::sync::Notify>,
) -> Result<()> {
    // SAFETY: plain syscall, constant flags.
    let fan = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fan < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed (needs CAP_SYS_ADMIN / privileged container)");
    }

    let cpath = CString::new(dir.as_os_str().as_bytes()).context("path has interior NUL")?;
    // SAFETY: valid fd + NUL-terminated path.
    let rc = unsafe {
        libc::fanotify_mark(
            fan,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            libc::FAN_CLOSE_WRITE,
            libc::AT_FDCWD,
            cpath.as_ptr(),
        )
    };
    if rc < 0 {
        // SAFETY: fan opened above, unused after.
        unsafe { libc::close(fan) };
        return Err(std::io::Error::last_os_error()).context("fanotify_mark failed");
    }

    tracing::info!(dir = %dir.display(), "fanotify armed on mount (legacy close-write mode)");

    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: buf outlives the call; len is its real size.
        let n = unsafe { libc::read(fan, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // SAFETY: fan opened above.
            unsafe { libc::close(fan) };
            return Err(e).context("read(fanotify) failed");
        }
        if n == 0 {
            continue;
        }

        let mut off: isize = 0;
        let meta_sz = size_of::<libc::fanotify_event_metadata>() as isize;
        while (n as isize) - off >= meta_sz {
            // SAFETY: we just bounds-checked that a full metadata struct fits.
            let meta =
                unsafe { &*(buf.as_ptr().offset(off) as *const libc::fanotify_event_metadata) };
            let ev_len = meta.event_len as isize;
            if ev_len < meta_sz {
                break; // malformed / truncated; avoid an infinite loop
            }

            if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                tracing::warn!("fanotify queue overflow; triggering targeted rescan (FR-104)");
                rescan.notify_one();
            }

            if meta.fd >= 0 {
                if let Some(path) = resolve_fd(meta.fd) {
                    if path.starts_with(dir)
                        && !is_tmp(&path)
                        && tx.blocking_send(LocalEvent::Write(path)).is_err()
                    {
                        // SAFETY: both fds are live here, closed once.
                        unsafe { libc::close(meta.fd) };
                        unsafe { libc::close(fan) };
                        return Ok(()); // receiver gone; shut down
                    }
                }
                // SAFETY: the kernel handed us this fd with the event.
                unsafe { libc::close(meta.fd) };
            }

            off += ev_len;
        }
    }
}

/// Resolve the event fd to a filesystem path via /proc/self/fd/<n>.
fn resolve_fd(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

fn is_tmp(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains(TMP_SUFFIX))
        .unwrap_or(false)
}
