//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! peer.rs — liveness registry, shared connection pool, jittered backoff
//! (FR-602/603, FR-1102).
//!
//! `ConnRegistry` is what makes multi-source fetch possible: BOTH the dial
//! loops (outbound subscriptions) and the accept loop (inbound) register
//! their live `quinn::Connection`s here, and the chunk/manifest fetchers
//! borrow ANY of them — "fetch from any peer that has it" (FR-403) without an
//! advertisement protocol. `quinn::Connection` is an Arc handle; cloning and
//! opening ephemeral bi-streams from multiple borrowers is the intended QUIC
//! usage.
//!
//! Clock note: `last_reconcile_unix` is observability metadata for /healthz,
//! never an input to any replication decision (FR-301 untouched).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;

use crate::vv::NodeId;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    Disconnected,
    Dialing,
    Reconciling,
    Live,
    Backoff,
}

impl PeerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerState::Disconnected => "disconnected",
            PeerState::Dialing => "dialing",
            PeerState::Reconciling => "reconciling",
            PeerState::Live => "live",
            PeerState::Backoff => "backoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PeerStatus {
    pub state: PeerState,
    pub last_reconcile_unix: i64,
    pub last_reconcile_ok: bool,
}

impl Default for PeerStatus {
    fn default() -> Self {
        PeerStatus {
            state: PeerState::Disconnected,
            last_reconcile_unix: 0,
            last_reconcile_ok: false,
        }
    }
}

fn read_lock<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}
fn write_lock<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

/// Per-peer liveness/anti-entropy status, surfaced by /healthz. Leaf cache
/// (same Mutex-convention rationale as the suppression set).
#[derive(Clone, Default)]
pub struct PeerRegistry(Arc<RwLock<HashMap<NodeId, PeerStatus>>>);

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_state(&self, peer: NodeId, state: PeerState) {
        write_lock(&self.0).entry(peer).or_default().state = state;
    }

    pub fn note_reconcile(&self, peer: NodeId, ok: bool) {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut map = write_lock(&self.0);
        let entry = map.entry(peer).or_default();
        entry.last_reconcile_unix = unix;
        entry.last_reconcile_ok = ok;
    }

    pub fn get(&self, peer: &NodeId) -> PeerStatus {
        read_lock(&self.0).get(peer).copied().unwrap_or_default()
    }

    /// Sorted snapshot for the health endpoint.
    pub fn snapshot(&self) -> Vec<(NodeId, PeerStatus)> {
        let mut v: Vec<_> = read_lock(&self.0).iter().map(|(k, s)| (*k, *s)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
}

/// Live connections by peer, shared between subscriptions, fetchers, and
/// reconcile sessions. A peer can hold BOTH its inbound and its outbound
/// connection at once (each side dials the other in the full mesh), so we keep
/// ALL of them per peer — either direction serves ephemeral streams equally
/// well, and on membership removal we must close every one of them
/// ([`ConnRegistry::close_all`]). Tracking only one would leave the other
/// direction (and the dialer side's detached serve task) alive after a removal.
#[derive(Clone, Default)]
pub struct ConnRegistry(Arc<RwLock<HashMap<NodeId, Vec<quinn::Connection>>>>);

impl ConnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection to `peer`. Idempotent per connection (dedup by
    /// `stable_id`), so a re-registration of the same conn does not duplicate.
    pub fn insert(&self, peer: NodeId, conn: quinn::Connection) {
        let mut map = write_lock(&self.0);
        let conns = map.entry(peer).or_default();
        if !conns.iter().any(|c| c.stable_id() == conn.stable_id()) {
            conns.push(conn);
        }
    }

    /// Remove exactly THIS connection (by `stable_id`) when its task exits — a
    /// concurrent connection to the same peer (the other direction, or a
    /// reconnection) is left untouched.
    pub fn remove_if_same(&self, peer: &NodeId, conn: &quinn::Connection) {
        let mut map = write_lock(&self.0);
        if let Some(conns) = map.get_mut(peer) {
            conns.retain(|c| c.stable_id() != conn.stable_id());
            if conns.is_empty() {
                map.remove(peer);
            }
        }
    }

    /// One representative connection for `peer`, if any.
    pub fn get(&self, peer: &NodeId) -> Option<quinn::Connection> {
        read_lock(&self.0)
            .get(peer)
            .and_then(|v| v.first().cloned())
    }

    /// Close EVERY connection to `peer` and forget them (FR-1307 removal). The
    /// `quinn` close propagates to all clones, so both the inbound `inbound_io`
    /// task and the outbound side's detached `serve_streams` task unblock and
    /// exit — there is no lingering data channel to a removed node.
    pub fn close_all(&self, peer: &NodeId, code: quinn::VarInt, reason: &[u8]) {
        if let Some(conns) = write_lock(&self.0).remove(peer) {
            for conn in conns {
                conn.close(code, reason);
            }
        }
    }

    /// Every live peer with ONE representative connection each — per-peer
    /// fan-out (gossip / control-plane status / resync).
    pub fn all(&self) -> Vec<(NodeId, quinn::Connection)> {
        read_lock(&self.0)
            .iter()
            .filter_map(|(k, v)| v.first().map(|c| (*k, c.clone())))
            .collect()
    }

    /// Fetch candidates: `origin_first` (the node most likely to hold the
    /// content) followed by every other live connection — ALL connections, so a
    /// peer reachable on two links offers two fetch sources.
    pub fn candidates(&self, origin_first: &NodeId) -> Vec<(NodeId, quinn::Connection)> {
        let map = read_lock(&self.0);
        let mut out: Vec<(NodeId, quinn::Connection)> = Vec::new();
        if let Some(conns) = map.get(origin_first) {
            out.extend(conns.iter().map(|c| (*origin_first, c.clone())));
        }
        for (k, conns) in map.iter() {
            if k != origin_first {
                out.extend(conns.iter().map(|c| (*k, c.clone())));
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        read_lock(&self.0).len()
    }

    pub fn is_empty(&self) -> bool {
        read_lock(&self.0).is_empty()
    }
}

const BACKOFF_FLOOR: Duration = Duration::from_millis(250);
const BACKOFF_CAP: Duration = Duration::from_secs(15);
const BACKOFF_BASE_MS: u64 = 500;

/// Full-jitter exponential backoff (FR-602; reviewer item "bounded and
/// jittered — no thundering herd on flap"): uniform in
/// `[FLOOR, min(CAP, BASE·2^attempt)]`.
pub fn jittered_backoff(attempt: u32) -> Duration {
    let cap_ms = BACKOFF_BASE_MS
        .saturating_mul(1u64.checked_shl(attempt.min(20)).unwrap_or(u64::MAX))
        .min(BACKOFF_CAP.as_millis() as u64);
    let jittered = Duration::from_millis(fastrand::u64(0..=cap_ms));
    jittered.clamp(BACKOFF_FLOOR, BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_capped() {
        for attempt in 0..32 {
            for _ in 0..50 {
                let d = jittered_backoff(attempt);
                assert!(d >= BACKOFF_FLOOR, "{d:?} under floor at {attempt}");
                assert!(d <= BACKOFF_CAP, "{d:?} over cap at {attempt}");
                // Early attempts stay under the exponential envelope.
                if attempt == 0 {
                    assert!(d.as_millis() as u64 <= BACKOFF_BASE_MS.max(250));
                }
            }
        }
    }

    #[test]
    fn backoff_is_actually_jittered() {
        let samples: std::collections::HashSet<u128> =
            (0..100).map(|_| jittered_backoff(10).as_millis()).collect();
        // 100 draws over a 15s range: a fixed (unjittered) backoff would
        // collapse to 1 distinct value; require real spread.
        assert!(samples.len() > 20, "only {} distinct values", samples.len());
    }

    #[test]
    fn peer_registry_states_and_snapshot() {
        let reg = PeerRegistry::new();
        let a = [1u8; 16];
        let b = [2u8; 16];
        assert_eq!(reg.get(&a).state, PeerState::Disconnected);
        reg.set_state(a, PeerState::Live);
        reg.set_state(b, PeerState::Dialing);
        reg.note_reconcile(a, true);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].0, a); // sorted
        assert_eq!(snap[0].1.state, PeerState::Live);
        assert!(snap[0].1.last_reconcile_ok);
        assert!(snap[0].1.last_reconcile_unix > 0);
        assert_eq!(snap[1].1.state, PeerState::Dialing);
    }
}
