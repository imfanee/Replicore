//! join.rs — node join lifecycle (FR-1309/1310/1311).
//!
//! A node moves `Joining → Syncing → Active` as it bootstraps against the
//! cluster. The transport already serves a node's OWN namespace immediately and
//! gates each inbound link behind a reconcile (FR-702); this tracker layers the
//! *node-level* readiness signal on top, for `replicorectl status` and gossip.
//!
//! ## Promotion rule (LAW, the reachable-only rule)
//!
//! `Syncing → Active` once every expected peer's initial directed pull gate has
//! either **completed** or is currently **unreachable**. Unreachable peers do
//! not block promotion ("unreachable = pending") — a node cannot be held back by
//! a dead peer — and a fully-isolated node promotes vacuously (it has reconciled
//! with everyone it can reach: no one). Promotion is **monotonic**: once Active,
//! later gate churn (a reconnect's fresh gate, a peer going unreachable) never
//! regresses it. The bidirectional requirement (FR-1310) is satisfied by the two
//! directed pull gates — each side runs its own tracker over its own links.
//!
//! Lifecycle is persisted in the store `meta` table so a restart that was Active
//! comes back Active rather than flapping to Joining before its first reconcile.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};

use crate::oplog::Store;
use crate::vv::NodeId;

const META_LIFECYCLE: &str = "join_lifecycle";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Lifecycle {
    /// Started; no peer's initial gate has completed yet.
    Joining,
    /// At least one peer reached/gated, but not all expected peers are settled.
    Syncing,
    /// Every reachable expected peer's initial gate completed (FR-1311).
    Active,
}

impl Lifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Joining => "joining",
            Lifecycle::Syncing => "syncing",
            Lifecycle::Active => "active",
        }
    }

    fn from_str(s: &str) -> Option<Lifecycle> {
        match s {
            "joining" => Some(Lifecycle::Joining),
            "syncing" => Some(Lifecycle::Syncing),
            "active" => Some(Lifecycle::Active),
            _ => None,
        }
    }
}

struct Inner {
    expected: HashSet<NodeId>,
    completed: HashSet<NodeId>,
    unreachable: HashSet<NodeId>,
    lifecycle: Lifecycle,
}

impl Inner {
    /// Recompute lifecycle from the gate sets and publish if it advanced.
    /// Monotonic: never steps back from Active. Returns the (possibly new)
    /// lifecycle when it changed, so the caller can persist it.
    fn recompute(&mut self, tx: &watch::Sender<Lifecycle>) -> Option<Lifecycle> {
        if self.lifecycle == Lifecycle::Active {
            return None; // monotonic — later gate churn never regresses
        }
        let all_settled = self
            .expected
            .iter()
            .all(|p| self.completed.contains(p) || self.unreachable.contains(p));
        // Promote to Active when every expected peer has either completed its
        // gate or is unreachable. INTENDED edge case (reachable-only rule): a
        // fully-isolated node — no expected peers, or every one unreachable —
        // promotes vacuously, because it HAS reconciled with everyone it can
        // reach (no one). It still re-reconciles on each later reconnect, and
        // promotion is monotonic, so this never masks a missed sync.
        let next = if self.expected.is_empty() || all_settled {
            Lifecycle::Active
        } else if !self.completed.is_empty() || !self.unreachable.is_empty() {
            Lifecycle::Syncing
        } else {
            Lifecycle::Joining
        };
        if next != self.lifecycle {
            self.lifecycle = next;
            let _ = tx.send(next);
            Some(next)
        } else {
            None
        }
    }
}

/// Cheap-to-clone handle to the node's join lifecycle.
#[derive(Clone)]
pub struct JoinTracker {
    inner: Arc<Mutex<Inner>>,
    state: watch::Receiver<Lifecycle>,
    publish: watch::Sender<Lifecycle>,
    store: Store,
}

impl JoinTracker {
    /// `expected` is the set of peers whose initial gate gates promotion —
    /// typically the configured/rostered peers at boot.
    pub fn new(store: Store, expected: impl IntoIterator<Item = NodeId>) -> JoinTracker {
        let expected: HashSet<NodeId> = expected.into_iter().collect();
        let initial = if expected.is_empty() {
            Lifecycle::Active // standalone node is immediately ready
        } else {
            Lifecycle::Joining
        };
        let (publish, state) = watch::channel(initial);
        JoinTracker {
            inner: Arc::new(Mutex::new(Inner {
                expected,
                completed: HashSet::new(),
                unreachable: HashSet::new(),
                lifecycle: initial,
            })),
            state,
            publish,
            store,
        }
    }

    /// Restore a persisted Active lifecycle (call once at startup, before the
    /// dial loops spawn). A node that was Active before a restart stays Active.
    pub async fn restore(&self) {
        if let Ok(Some(s)) = self.store.get_meta(META_LIFECYCLE).await {
            if Lifecycle::from_str(&s) == Some(Lifecycle::Active) {
                let mut inner = self.inner.lock().await;
                inner.lifecycle = Lifecycle::Active;
                let _ = self.publish.send(Lifecycle::Active);
            }
        }
    }

    /// A peer's initial directed pull gate completed. Clears any unreachable
    /// mark and may promote the node.
    pub async fn note_gate_complete(&self, peer: NodeId) {
        let changed = {
            let mut inner = self.inner.lock().await;
            inner.unreachable.remove(&peer);
            inner.completed.insert(peer);
            inner.recompute(&self.publish)
        };
        self.persist(changed).await;
    }

    /// A peer is currently unreachable (dial failing). It stops blocking
    /// promotion but is NOT counted as synced.
    pub async fn note_unreachable(&self, peer: NodeId) {
        let changed = {
            let mut inner = self.inner.lock().await;
            if inner.completed.contains(&peer) {
                return; // already synced once; a later blip doesn't un-sync it
            }
            inner.unreachable.insert(peer);
            inner.recompute(&self.publish)
        };
        self.persist(changed).await;
    }

    /// Replace the expected-peer set after a membership change (M2.5 dynamic
    /// peers). Re-evaluates promotion; never regresses from Active.
    pub async fn set_expected(&self, expected: impl IntoIterator<Item = NodeId>) {
        let changed = {
            let mut inner = self.inner.lock().await;
            inner.expected = expected.into_iter().collect();
            inner.recompute(&self.publish)
        };
        self.persist(changed).await;
    }

    pub fn lifecycle(&self) -> Lifecycle {
        *self.state.borrow()
    }

    /// Watch lifecycle changes (gossip/status surface it).
    pub fn subscribe(&self) -> watch::Receiver<Lifecycle> {
        self.state.clone()
    }

    async fn persist(&self, changed: Option<Lifecycle>) {
        if let Some(l) = changed {
            // Best-effort: a failed write only means a restart may re-sync,
            // which is safe (reconcile is idempotent). Never panic the daemon.
            if let Err(e) = self.store.set_meta(META_LIFECYCLE, l.as_str()).await {
                tracing::warn!(error = %e, "failed to persist join lifecycle");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn store() -> Store {
        Store::open(Path::new(":memory:"), nid(0)).unwrap()
    }

    #[tokio::test]
    async fn standalone_is_active_immediately() {
        let t = JoinTracker::new(store(), []);
        assert_eq!(t.lifecycle(), Lifecycle::Active);
    }

    #[tokio::test]
    async fn promotes_only_after_all_expected_gates() {
        let t = JoinTracker::new(store(), [nid(1), nid(2)]);
        assert_eq!(t.lifecycle(), Lifecycle::Joining);
        t.note_gate_complete(nid(1)).await;
        assert_eq!(t.lifecycle(), Lifecycle::Syncing);
        t.note_gate_complete(nid(2)).await;
        assert_eq!(t.lifecycle(), Lifecycle::Active);
    }

    #[tokio::test]
    async fn unreachable_peer_does_not_block_promotion() {
        let t = JoinTracker::new(store(), [nid(1), nid(2)]);
        t.note_gate_complete(nid(1)).await;
        t.note_unreachable(nid(2)).await;
        assert_eq!(t.lifecycle(), Lifecycle::Active);
    }

    #[tokio::test]
    async fn active_never_regresses() {
        let t = JoinTracker::new(store(), [nid(1)]);
        t.note_gate_complete(nid(1)).await;
        assert_eq!(t.lifecycle(), Lifecycle::Active);
        // A later reconnect's churn must not knock it out of Active.
        t.note_unreachable(nid(1)).await;
        assert_eq!(t.lifecycle(), Lifecycle::Active);
    }

    #[tokio::test]
    async fn lifecycle_persists_active_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.db");
        {
            let s = Store::open(&db, nid(0)).unwrap();
            let t = JoinTracker::new(s, [nid(1)]);
            t.note_gate_complete(nid(1)).await;
            assert_eq!(t.lifecycle(), Lifecycle::Active);
        }
        // Reopen: a node that was Active comes back Active before any reconcile.
        let s = Store::open(&db, nid(0)).unwrap();
        let t = JoinTracker::new(s, [nid(1)]);
        assert_eq!(t.lifecycle(), Lifecycle::Joining); // before restore
        t.restore().await;
        assert_eq!(t.lifecycle(), Lifecycle::Active);
    }
}
