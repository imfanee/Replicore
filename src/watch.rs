//! watch.rs — change detection via fanotify (E1, minimal).
//!
//! M0 scope: catch "a file was written and closed" using FAN_CLOSE_WRITE on a
//! MOUNT mark, resolve the path through /proc/self/fd, and hand it upstream.
//!
//! Why a MOUNT mark and FAN_CLOSE_WRITE: classic fd-style fanotify events do not
//! report create/delete/rename — those require FID reporting (FAN_REPORT_FID /
//! FAN_REPORT_DFID_NAME, kernel >= 5.1/5.9), which is the Phase 1 upgrade
//! (FR-102). For write-once IVR recordings, close-after-write is exactly the
//! signal we want, so M0 leans on it deliberately.
//!
//! Requires CAP_SYS_ADMIN. Runs a blocking read loop; call it on its own thread.

use anyhow::{Context, Result};
use std::ffi::CString;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::TMP_SUFFIX;

pub fn run(dir: &Path, tx: tokio::sync::mpsc::Sender<PathBuf>) -> Result<()> {
    // Initialize fanotify in notification class; events carry an fd to the object.
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

    // Mark the whole mount for close-after-write. We filter to `dir` below; a
    // per-subtree FID mark replaces this broad mark in Phase 1.
    let cpath = CString::new(dir.as_os_str().as_bytes()).context("path has interior NUL")?;
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
        unsafe { libc::close(fan) };
        return Err(std::io::Error::last_os_error()).context("fanotify_mark failed");
    }

    eprintln!("[watch] fanotify armed on mount of {}", dir.display());

    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fan, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
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

            if meta.fd >= 0 {
                if let Some(path) = resolve_fd(meta.fd) {
                    if path.starts_with(dir) && !is_tmp(&path) {
                        // blocking_send applies backpressure (FR-1106) onto the
                        // kernel read loop, which is the behavior we want.
                        if tx.blocking_send(path).is_err() {
                            unsafe { libc::close(meta.fd) };
                            unsafe { libc::close(fan) };
                            return Ok(()); // receiver gone; shut down
                        }
                    }
                }
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
