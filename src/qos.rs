//! qos.rs — bandwidth limiting and free-space safety (FR-1103/1104/1107).
//!
//! ## Token buckets (debt model)
//!
//! Hand-rolled (the stack is locked; a tokio-friendly bucket is small): a
//! bucket holds a signed token balance refilled at `rate` bytes/sec. An
//! `acquire(n)` always debits immediately and then sleeps until the balance
//! would be non-negative — so any `n` (even above one second of rate) is
//! admitted, and the AVERAGE rate converges on the configured cap. Burst is
//! bounded by the capacity clamp. `rate = 0` means unlimited.
//!
//! Composition: a transfer acquires from the GLOBAL bucket and then from its
//! PEER bucket — both caps hold simultaneously (FR-1103). Each node enforces
//! its own configured caps on both directions independently (serve-side
//! egress and fetch-side ingress), like rsync/syncthing: QUIC pacing is
//! congestion control, not policy, and is NOT a substitute.
//!
//! ## Priority lanes (FR-1104)
//!
//! Control/metadata frames are never throttled (they are tiny and ride
//! separate streams). Chunk payloads are split into two lanes: `Priority`
//! (small assets — prompts, configs) and `Bulk` (large transfers). Bulk
//! acquisitions yield while ANY priority acquisition is waiting, so a small
//! file never queues behind a recording backlog. Approximate strict
//! priority; starvation of bulk is impossible once the priority queue
//! drains.
//!
//! ## Schedule (FR-1103)
//!
//! `[[bandwidth.schedule]]` rules select rates by local wall-clock time of
//! day — the ONE legitimate wall-clock use in this codebase: it is operator
//! policy, never causality. The engine re-evaluates periodically and retunes
//! the buckets atomically; `replicorectl bandwidth set` overrides at runtime
//! (until the next schedule tick or reload).
//!
//! ## Free-space guard (FR-1107)
//!
//! `free_space_for` answers "how many bytes may we add while keeping the
//! configured reserve?" via statvfs. The engine refuses to START transfers
//! that would breach the reserve and trips the existing pause gate; an
//! auto-prober resumes when space recovers (operator pauses are never
//! auto-resumed).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

use crate::vv::NodeId;

/// Which queue a chunk payload rides (FR-1104).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Small assets / metadata-adjacent payloads: never queue behind bulk.
    Priority,
    /// Large content transfers.
    Bulk,
}

struct BucketState {
    /// Bytes/sec; 0 = unlimited.
    rate: u64,
    /// Signed balance: negative = debt already admitted, sleep it off.
    tokens: f64,
    last: Instant,
}

/// One debt-model token bucket. Cheap to share.
pub struct TokenBucket {
    state: Mutex<BucketState>,
}

impl TokenBucket {
    pub fn new(rate: u64) -> TokenBucket {
        TokenBucket {
            state: Mutex::new(BucketState {
                rate,
                tokens: 0.0,
                last: Instant::now(),
            }),
        }
    }

    pub fn set_rate(&self, rate: u64) {
        let mut s = self.state.lock().expect("bucket lock poisoned");
        // Refill at the OLD rate up to now, then switch — no retro-pricing.
        Self::refill(&mut s);
        s.rate = rate;
        if rate == 0 {
            s.tokens = 0.0; // unlimited: forgive any debt
        }
    }

    pub fn rate(&self) -> u64 {
        self.state.lock().expect("bucket lock poisoned").rate
    }

    fn refill(s: &mut BucketState) {
        let now = Instant::now();
        let dt = now.duration_since(s.last).as_secs_f64();
        s.last = now;
        if s.rate == 0 {
            s.tokens = 0.0;
            return;
        }
        // Burst clamp: at most one second of credit accumulates.
        s.tokens = (s.tokens + dt * s.rate as f64).min(s.rate as f64);
    }

    /// Debit `n` bytes and wait out any resulting debt. Returns immediately
    /// when unlimited.
    pub async fn acquire(&self, n: u64) {
        let wait = {
            let mut s = self.state.lock().expect("bucket lock poisoned");
            Self::refill(&mut s);
            if s.rate == 0 {
                return;
            }
            s.tokens -= n as f64;
            if s.tokens >= 0.0 {
                return;
            }
            Duration::from_secs_f64(-s.tokens / s.rate as f64)
        };
        tokio::time::sleep(wait).await;
    }
}

/// The engine's limiter: global ∩ per-peer buckets + the priority gate.
pub struct Limiter {
    global: TokenBucket,
    per_peer_rate: AtomicU64,
    peers: Mutex<HashMap<NodeId, std::sync::Arc<TokenBucket>>>,
    /// Number of Priority acquisitions currently in flight: Bulk yields
    /// while this is non-zero.
    priority_waiting: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl Limiter {
    pub fn new(global_bps: u64, per_peer_bps: u64) -> Limiter {
        Limiter {
            global: TokenBucket::new(global_bps),
            per_peer_rate: AtomicU64::new(per_peer_bps),
            peers: Mutex::new(HashMap::new()),
            priority_waiting: AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Retune both caps atomically (schedule tick, reload, `bandwidth set`).
    pub fn set_rates(&self, global_bps: u64, per_peer_bps: u64) {
        self.global.set_rate(global_bps);
        self.per_peer_rate.store(per_peer_bps, Ordering::Relaxed);
        let peers = self.peers.lock().expect("limiter lock poisoned");
        for bucket in peers.values() {
            bucket.set_rate(per_peer_bps);
        }
    }

    pub fn rates(&self) -> (u64, u64) {
        (
            self.global.rate(),
            self.per_peer_rate.load(Ordering::Relaxed),
        )
    }

    fn peer_bucket(&self, peer: &NodeId) -> std::sync::Arc<TokenBucket> {
        let mut peers = self.peers.lock().expect("limiter lock poisoned");
        peers
            .entry(*peer)
            .or_insert_with(|| {
                std::sync::Arc::new(TokenBucket::new(self.per_peer_rate.load(Ordering::Relaxed)))
            })
            .clone()
    }

    /// Admit `n` bytes of chunk payload to/from `peer` on `lane`.
    pub async fn acquire(&self, lane: Lane, peer: &NodeId, n: u64) {
        match lane {
            Lane::Priority => {
                self.priority_waiting.fetch_add(1, Ordering::SeqCst);
                let bucket = self.peer_bucket(peer);
                self.global.acquire(n).await;
                bucket.acquire(n).await;
                self.priority_waiting.fetch_sub(1, Ordering::SeqCst);
                self.notify.notify_waiters();
            }
            Lane::Bulk => {
                // Yield to in-flight priority traffic before debiting.
                while self.priority_waiting.load(Ordering::SeqCst) > 0 {
                    self.notify.notified().await;
                }
                let bucket = self.peer_bucket(peer);
                self.global.acquire(n).await;
                bucket.acquire(n).await;
            }
        }
    }
}

/// One time-of-day schedule rule (FR-1103). Local time; "all"/"weekday"/
/// "weekend" or explicit 3-letter day names; HH:MM bounds, overnight ranges
/// (start > end) wrap midnight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleRule {
    pub days: Vec<String>,
    /// Minutes since midnight, inclusive.
    pub start_min: u16,
    /// Minutes since midnight, exclusive.
    pub end_min: u16,
    pub global_bps: u64,
    pub per_peer_bps: u64,
}

impl ScheduleRule {
    fn day_matches(&self, weekday: u8) -> bool {
        // 0 = Sunday … 6 = Saturday (struct tm convention).
        const NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
        self.days.iter().any(|d| match d.as_str() {
            "all" => true,
            "weekday" => (1..=5).contains(&weekday),
            "weekend" => weekday == 0 || weekday == 6,
            name => NAMES.get(weekday as usize) == Some(&name),
        })
    }

    fn time_matches(&self, minute_of_day: u16) -> bool {
        if self.start_min <= self.end_min {
            (self.start_min..self.end_min).contains(&minute_of_day)
        } else {
            // Overnight: e.g. 22:00–06:00.
            minute_of_day >= self.start_min || minute_of_day < self.end_min
        }
    }
}

/// Pick the rates for (weekday, minute-of-day): the FIRST matching rule wins,
/// else the base rates. Pure — the caller supplies the clock reading (the
/// engine's schedule tick uses localtime; tests pass fixed values).
pub fn active_rates(
    rules: &[ScheduleRule],
    base: (u64, u64),
    weekday: u8,
    minute_of_day: u16,
) -> (u64, u64) {
    for r in rules {
        if r.day_matches(weekday) && r.time_matches(minute_of_day) {
            return (r.global_bps, r.per_peer_bps);
        }
    }
    base
}

/// Local (weekday, minute-of-day) — the one legitimate wall-clock read:
/// schedule policy, never causality.
pub fn local_clock() -> (u8, u16) {
    // SAFETY: localtime_r with valid pointers; tm is plain data out.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return (0, 0); // clock trouble: fall back to base rates
        }
        (tm.tm_wday as u8, (tm.tm_hour * 60 + tm.tm_min) as u16)
    }
}

/// Bytes available above the configured reserve on `path`'s filesystem
/// (FR-1107). `Err` is reported by the caller; a failing statvfs must never
/// silently disable the guard.
pub fn available_above_reserve(
    path: &Path,
    reserve_bytes: u64,
    reserve_percent: f64,
) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    // SAFETY: valid path; statvfs fills the zeroed struct on success.
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::statvfs(c.as_ptr(), &mut sv) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let frsize = if sv.f_frsize > 0 {
        sv.f_frsize
    } else {
        sv.f_bsize
    } as u64;
    let avail = sv.f_bavail as u64 * frsize;
    let total = sv.f_blocks as u64 * frsize;
    let reserve = reserve_bytes.max((total as f64 * (reserve_percent / 100.0)) as u64);
    Ok(avail.saturating_sub(reserve))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap is honored on AVERAGE: admitting 10 × 100KB at 1MB/s must
    /// take ~1 second (debt model: first acquire is instant).
    #[tokio::test(start_paused = true)]
    async fn bucket_paces_to_the_configured_rate() {
        let b = TokenBucket::new(1_000_000);
        let t0 = tokio::time::Instant::now();
        for _ in 0..10 {
            b.acquire(100_000).await;
        }
        let elapsed = t0.elapsed();
        // 1 MB at 1 MB/s ≈ 1s (minus the initial burst credit of ≤ 1s…
        // tokens start at 0, so the full debt is slept off).
        assert!(
            elapsed >= Duration::from_millis(800) && elapsed <= Duration::from_millis(1300),
            "paced 1MB at 1MB/s in {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_rate_is_unlimited() {
        let b = TokenBucket::new(0);
        let t0 = tokio::time::Instant::now();
        for _ in 0..1000 {
            b.acquire(10_000_000).await;
        }
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn retune_applies_to_subsequent_acquires() {
        let b = TokenBucket::new(1_000);
        b.acquire(1_000).await; // debit at the slow rate
        b.set_rate(0);
        let t0 = tokio::time::Instant::now();
        b.acquire(10_000_000).await; // unlimited now (debt forgiven)
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn global_and_peer_caps_both_hold() {
        // Global 2 MB/s, per-peer 1 MB/s: a single peer is held to 1 MB/s.
        let l = Limiter::new(2_000_000, 1_000_000);
        let peer = [1u8; 16];
        let t0 = tokio::time::Instant::now();
        for _ in 0..10 {
            l.acquire(Lane::Bulk, &peer, 100_000).await;
        }
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(800),
            "per-peer cap not enforced: {elapsed:?}"
        );
    }

    #[test]
    fn schedule_selects_first_matching_rule() {
        let rules = vec![
            ScheduleRule {
                days: vec!["weekday".into()],
                start_min: 9 * 60,
                end_min: 17 * 60,
                global_bps: 100,
                per_peer_bps: 50,
            },
            ScheduleRule {
                days: vec!["all".into()],
                start_min: 22 * 60,
                end_min: 6 * 60, // overnight wrap
                global_bps: 0,
                per_peer_bps: 0,
            },
        ];
        let base = (1000, 500);
        // Tuesday 10:00 → business-hours rule.
        assert_eq!(active_rates(&rules, base, 2, 10 * 60), (100, 50));
        // Tuesday 23:00 → overnight rule (unlimited).
        assert_eq!(active_rates(&rules, base, 2, 23 * 60), (0, 0));
        // Sunday 03:00 → overnight wrap matches before-end side.
        assert_eq!(active_rates(&rules, base, 0, 3 * 60), (0, 0));
        // Saturday noon → no rule: base.
        assert_eq!(active_rates(&rules, base, 6, 12 * 60), (1000, 500));
    }

    #[test]
    fn free_space_guard_reads_a_real_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let free = available_above_reserve(dir.path(), 0, 0.0).unwrap();
        assert!(free > 0, "tempdir filesystem reports zero space");
        // An absurd reserve swallows everything.
        let none = available_above_reserve(dir.path(), u64::MAX, 0.0).unwrap();
        assert_eq!(none, 0);
    }
}
