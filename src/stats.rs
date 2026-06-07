//! stats.rs — shared transfer/reconcile counters (FR-1102; the integration
//! tests' dedup / no-retransfer / resume assertions read these via /healthz).
//!
//! # Backpressure inventory (FR-1106 — the complete list; every buffer in the
//! daemon is bounded, and the durable oplog is the only "queue" allowed to
//! grow, because it grows on disk):
//!
//! | buffer                        | bound                          | what slows |
//! |-------------------------------|--------------------------------|------------|
//! | events channel (watch+scan)   | mpsc(1024)                     | watcher `blocking_send` → kernel queue → FAN_Q_OVERFLOW → targeted rescan; scanner awaits |
//! | store command channel         | mpsc(256)                      | all store callers await |
//! | push path (ops to a peer)     | none needed — reads the DB in `PUSH_BATCH`es; QUIC flow control parks `write_all` | ops wait in SQLite, memory stays O(batch) |
//! | per-file chunk fetches        | Semaphore(per_file_chunk_concurrency) × max_chunk_bytes | the transfer task |
//! | concurrent file transfers     | Semaphore(max_concurrent_transfers), engine-wide | subscriptions + reconcile leaf applies |
//! | serve streams (per conn)      | Semaphore(serve_concurrency); chunk bodies stream via `tokio::io::copy` (no whole-chunk buffer) | the hammering peer |
//! | reconcile descent             | serial per session + paginated TreeReq | the session stream |
//! | `watch_latest`                | watch channel (latest value)   | n/a |

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Default, Debug)]
pub struct Stats {
    /// Chunks fetched from peers and inserted into the CAS (misses only —
    /// CAS hits never fetch, which is what the dedup/no-retransfer/resume
    /// integration assertions count on).
    pub chunks_fetched: AtomicU64,
    pub chunks_served: AtomicU64,
    /// Chunk payload bytes received / served (not framing).
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub manifests_fetched: AtomicU64,
    pub reconcile_runs: AtomicU64,
    /// Files currently in the fetch+assemble pipeline (gauge).
    pub inflight_transfers: AtomicI64,
    /// Concurrent-version detections (FR-303): bumped at every site that keeps
    /// local and records the remote as concurrent. Surfaced by
    /// `replicorectl conflicts` until M3 adds conflict copies.
    pub conflicts: AtomicU64,
    /// Chunks a fetch skipped because the CAS already held them (the cache
    /// hit rate's numerator, FR-1101).
    pub chunks_cache_hits: AtomicU64,
    /// Free-space guard activations (FR-1107): transfers paused to protect
    /// the reserve.
    pub freespace_trips: AtomicU64,
    /// Reconcile sessions that resolved at least one conflict (FR-305).
    pub apply_errors: AtomicU64,
}

impl Stats {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn gauge_inc(gauge: &AtomicI64) {
        gauge.fetch_add(1, Ordering::Relaxed);
    }

    pub fn gauge_dec(gauge: &AtomicI64) {
        gauge.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    pub fn get_gauge(gauge: &AtomicI64) -> i64 {
        gauge.load(Ordering::Relaxed)
    }
}
