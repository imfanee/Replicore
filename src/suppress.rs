//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! suppress.rs — apply-suppression set, the second mandatory half of loop
//! prevention (FR-902; FR-901 VV dedup is the other half — BOTH are required).
//!
//! Before the apply path mutates the filesystem because of a *remote* op, it
//! registers the expected outcome here. When the watcher or scanner then
//! observes that same outcome, the event is swallowed instead of becoming a
//! spurious outbound op. Entries are single-shot (consumed on match) and
//! TTL-swept so a failed apply cannot permanently mask a future legitimate
//! local change.
//!
//! Concurrency note: this is a short-lived leaf cache guarded by a `Mutex`,
//! not shared state-machine logic — the message-passing convention targets the
//! op-log/decision core, which lives behind the store thread.
//!
//! Clock note (reviewer checklist): the `Instant` below is MONOTONIC time used
//! only to garbage-collect stale entries. It never participates in any apply
//! or ordering decision (FR-301).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// We are about to publish content with this hash at the path.
    Write([u8; 32]),
    /// We are about to unlink the path.
    Delete,
}

struct Entry {
    kind: Kind,
    at: Instant,
}

/// Shared suppression set, keyed by share-relative path. Cheap to clone.
///
/// One entry per path: applies for a given path are serialized by the receive
/// loop, and under partitioned write ownership a remote apply and a local
/// write to the same path do not race (and if they do, a non-matching hash
/// correctly passes through — see `check_write`).
#[derive(Clone, Default)]
pub struct Suppressor(Arc<Mutex<HashMap<String, Entry>>>);

impl Suppressor {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A poisoned lock only means another thread panicked mid-insert; the
        // map stays structurally valid and the worst case is one extra or one
        // missing suppression entry — both already tolerated (TTL sweep / VV
        // no-op filter). Recover instead of propagating the panic.
        match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Call immediately before staging a remote write for `rel`.
    pub fn register_write(&self, rel: &str, hash: [u8; 32]) {
        self.lock().insert(
            rel.to_string(),
            Entry {
                kind: Kind::Write(hash),
                at: Instant::now(),
            },
        );
    }

    /// Call immediately before unlinking `rel` for a remote delete.
    pub fn register_delete(&self, rel: &str) {
        self.lock().insert(
            rel.to_string(),
            Entry {
                kind: Kind::Delete,
                at: Instant::now(),
            },
        );
    }

    /// Should a locally-observed write of `hash` at `rel` be swallowed?
    /// Consumes the entry on match. A different hash does NOT match — a
    /// genuine newer local write must propagate even if it raced our apply.
    pub fn check_write(&self, rel: &str, hash: &[u8; 32]) -> bool {
        let mut map = self.lock();
        match map.get(rel) {
            Some(Entry {
                kind: Kind::Write(expected),
                ..
            }) if expected == hash => {
                map.remove(rel);
                true
            }
            _ => false,
        }
    }

    /// Should a locally-observed disappearance of `rel` be swallowed?
    /// Consumes the entry on match.
    pub fn check_delete(&self, rel: &str) -> bool {
        let mut map = self.lock();
        match map.get(rel) {
            Some(Entry {
                kind: Kind::Delete, ..
            }) => {
                map.remove(rel);
                true
            }
            _ => false,
        }
    }

    /// Reap entries older than `ttl` (orphans from failed applies, or applies
    /// whose event the watcher never delivered). Call periodically; choose a
    /// TTL of several quiescence windows.
    pub fn sweep(&self, ttl: Duration) {
        self.lock().retain(|_, e| e.at.elapsed() < ttl);
    }

    /// Number of pending entries (tests / metrics seam).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_match_is_single_shot() {
        let s = Suppressor::new();
        s.register_write("a/b", [1; 32]);
        assert!(s.check_write("a/b", &[1; 32]));
        // Consumed: a second identical event is NOT suppressed (the no-op
        // filter downstream handles it instead).
        assert!(!s.check_write("a/b", &[1; 32]));
    }

    #[test]
    fn different_hash_passes_through_and_keeps_entry() {
        let s = Suppressor::new();
        s.register_write("a/b", [1; 32]);
        // A genuine local overwrite that raced our apply: must propagate.
        assert!(!s.check_write("a/b", &[2; 32]));
        // The original entry is still there for the real apply event.
        assert!(s.check_write("a/b", &[1; 32]));
    }

    #[test]
    fn delete_and_write_entries_do_not_cross_match() {
        let s = Suppressor::new();
        s.register_delete("gone");
        assert!(!s.check_write("gone", &[0; 32]));
        assert!(s.check_delete("gone"));
        assert!(!s.check_delete("gone")); // single-shot

        s.register_write("w", [3; 32]);
        assert!(!s.check_delete("w"));
    }

    #[test]
    fn sweep_reaps_only_expired() {
        let s = Suppressor::new();
        s.register_write("old", [1; 32]);
        std::thread::sleep(Duration::from_millis(30));
        s.register_write("new", [2; 32]);
        s.sweep(Duration::from_millis(20));
        assert!(!s.check_write("old", &[1; 32])); // reaped
        assert!(s.check_write("new", &[2; 32])); // kept
    }
}
