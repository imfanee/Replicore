//! replica.rs — in-memory simulation harness for the correctness core.
//!
//! Drives the REAL store (`:memory:` SQLite — same schema, transactions, and
//! idempotency table as production), the REAL `decide` logic, and the REAL
//! local-ingest semantics, with only the filesystem effect abstracted behind
//! [`ApplyEffect`]. Property tests use this to prove convergence under
//! reordered/duplicated delivery without touching disk or network.
//!
//! This is a test harness, but it lives in the lib so integration tests and
//! future fuzzers can share it; production code never constructs a `Replica`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::conflict::{self, Version, META_NONE};
use crate::decide::{decide, Decision};
use crate::oplog::{LocalChange, ReconciledRow, ResolveOutcome, Store, StoreError};
use crate::proto::{OpRecord, OpType};
use crate::state::FileRow;
use crate::vv::NodeId;

/// The filesystem effect of an applied op, abstracted. Content is represented
/// by its hash — the harness never needs real bytes.
pub trait ApplyEffect {
    fn write(&mut self, path: &str, hash: [u8; 32]);
    fn delete(&mut self, path: &str);
}

/// Trivial in-memory "filesystem": path → content hash.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct FakeFs(pub BTreeMap<String, [u8; 32]>);

impl ApplyEffect for FakeFs {
    fn write(&mut self, path: &str, hash: [u8; 32]) {
        self.0.insert(path.to_string(), hash);
    }
    fn delete(&mut self, path: &str) {
        self.0.remove(path);
    }
}

/// The remote side of a conflict, as carried by a live op.
fn op_version(op: &OpRecord) -> Version {
    Version {
        tombstone: op.op_type == OpType::Delete,
        content_hash: op.content_hash,
        meta_hash: META_NONE,
        mode: op.mode,
        size: op.size,
        vv: op.vv.clone(),
        uuid: op.uuid,
    }
}

/// A rename op's SOURCE-path effect: a tombstone with the op's lineage.
fn rename_source_version(op: &OpRecord) -> Version {
    Version {
        tombstone: true,
        content_hash: None,
        meta_hash: META_NONE,
        mode: 0,
        size: 0,
        vv: op.vv.clone(),
        uuid: op.uuid,
    }
}

/// One simulated node: real store + decision logic, fake fs.
pub struct Replica {
    pub node_id: NodeId,
    pub store: Store,
    pub fs: FakeFs,
}

impl Replica {
    pub fn new(node_id: NodeId) -> Result<Self, StoreError> {
        Ok(Replica {
            node_id,
            store: Store::open(Path::new(":memory:"), node_id)?,
            fs: FakeFs::default(),
        })
    }

    /// A local application writes `content` at `path`: mutate the fake fs,
    /// then run the real ingest append (VV increment + no-op filter).
    /// Returns the emitted op, or `None` if it was a causal no-op.
    pub async fn local_write(
        &mut self,
        path: &str,
        content: &[u8],
    ) -> Result<Option<OpRecord>, StoreError> {
        let hash = *blake3::hash(content).as_bytes();
        self.fs.write(path, hash);
        self.store
            .append_local(LocalChange {
                path: path.to_string(),
                op_type: OpType::Write,
                mode: 0o644,
                size: content.len() as u64,
                content_hash: Some(hash),
                manifest: None,
            })
            .await
    }

    /// A local application deletes `path`.
    pub async fn local_delete(&mut self, path: &str) -> Result<Option<OpRecord>, StoreError> {
        self.fs.delete(path);
        self.store
            .append_local(LocalChange {
                path: path.to_string(),
                op_type: OpType::Delete,
                mode: 0o644,
                size: 0,
                content_hash: None,
                manifest: None,
            })
            .await
    }

    /// The full receive path for one remote op (minus real bytes/network):
    /// idempotency fast path → decide → fs effect → durable apply_remote
    /// (which re-validates the decision in the committing tx). Returns the
    /// EFFECTIVE decision (`None` = duplicate, dropped). On a downgrade the
    /// fake fs is repaired from the committed row, mirroring production.
    ///
    /// M3 (FR-303): a Concurrent op is RESOLVED, not skipped — the rows
    /// commit through `resolve_rows` first, then `apply_remote` records the
    /// op (a crash between the two is healed on redelivery: the merged row
    /// dominates the op, so it records as Ignore).
    pub async fn receive(&mut self, op: &OpRecord) -> Result<Option<Decision>, StoreError> {
        if self.store.has_applied(op.op_id).await? {
            return Ok(None); // already durably handled: would just re-ack
        }
        let local = self.store.load_file(&op.path).await?;
        let decision = decide(local.as_ref(), &op.vv);
        if decision == Decision::Apply {
            match op.op_type {
                OpType::Write => {
                    if let Some(hash) = op.content_hash {
                        self.fs.write(&op.path, hash);
                    }
                }
                OpType::Delete => self.fs.delete(&op.path),
                OpType::Rename => {
                    if let Some(hash) = op.content_hash {
                        self.fs.write(&op.path, hash);
                    }
                    // Source file goes only if the op dominates the source
                    // row (mirrors materialize + the committing tx).
                    if let Some(old_rel) = &op.path_old {
                        let old_local = self.store.load_file(old_rel).await?;
                        if decide(old_local.as_ref(), &op.vv) == Decision::Apply {
                            self.fs.delete(old_rel);
                        }
                    }
                }
            }
        }
        if decision == Decision::Concurrent {
            self.resolve_conflict(&op.path, op_version(op)).await?;
        }
        let effective = self.store.apply_remote(op.clone(), decision).await?;
        if decision == Decision::Apply && effective != Decision::Apply {
            // Repair the clobber from the committed row (production runs
            // merkle::restore_local_content here)...
            match self.store.load_file(&op.path).await? {
                Some(row) if !row.tombstone => {
                    if let Some(hash) = row.content_hash {
                        self.fs.write(&op.path, hash);
                    }
                }
                _ => self.fs.delete(&op.path),
            }
            // ...and then RESOLVE: the downgrade means a local write landed
            // concurrently during the (simulated) fetch — the second
            // Concurrent site gets the same treatment as the first.
            if effective == Decision::Concurrent {
                self.resolve_conflict(&op.path, op_version(op)).await?;
            }
        }
        // A rename's SECOND path-effect (the source) was decided per-path in
        // the same transaction; repair / resolve whatever did not dominate
        // (mirrors process_remote_op's post-step).
        if op.op_type == OpType::Rename && decision != Decision::Quarantined {
            if let Some(old_rel) = &op.path_old {
                let old_local = self.store.load_file(old_rel).await?;
                match decide(old_local.as_ref(), &op.vv) {
                    Decision::Ignore | Decision::Apply => self.sync_fs_from_row(old_rel).await?,
                    Decision::Concurrent => {
                        self.sync_fs_from_row(old_rel).await?;
                        self.resolve_conflict(old_rel, rename_source_version(op))
                            .await?;
                    }
                    Decision::Quarantined => {}
                }
            }
        }
        Ok(Some(effective))
    }

    /// The harness analogue of `merkle::restore_local_content`: make the fake
    /// fs agree with the committed row for `path`.
    async fn sync_fs_from_row(&mut self, path: &str) -> Result<(), StoreError> {
        match self.store.load_file(path).await? {
            Some(row) if !row.tombstone => {
                if let Some(hash) = row.content_hash {
                    self.fs.write(path, hash);
                }
            }
            _ => self.fs.delete(path),
        }
        Ok(())
    }

    /// A local application moves `old` to `new`: mutate the fake fs, then run
    /// the real identity-preserving rename append (FR-205).
    pub async fn local_rename(
        &mut self,
        old: &str,
        new: &str,
    ) -> Result<Option<OpRecord>, StoreError> {
        if let Some(hash) = self.fs.0.get(old).copied() {
            self.fs.delete(old);
            self.fs.write(new, hash);
        }
        self.store.append_local_rename(old, new).await
    }

    /// The conflict-resolution loop every Concurrent site runs (net.rs mirrors
    /// this against the real fs): ask the store for the authoritative plan
    /// (an empty staging never matches, so round one returns `Stale` carrying
    /// it), stage its contents, then commit. Bounded: each retry consumes
    /// fresh state, and absent new local writes the second round commits.
    async fn resolve_conflict(&mut self, path: &str, remote: Version) -> Result<(), StoreError> {
        let mut plan = Vec::new();
        for _ in 0..5 {
            // Production stages the plan's contents on disk HERE (loser fetch
            // + stage→fsync→verify→rename + suppression). The harness's fs
            // effect is applied after the commit instead — same end state at
            // every quiesced assertion point.
            match self.store.resolve_rows(path, remote.clone(), plan).await? {
                ResolveOutcome::Resolved => {
                    break;
                }
                ResolveOutcome::Stale { plan: fresh } => plan = fresh,
                ResolveOutcome::NotConcurrent(_) | ResolveOutcome::Unresolvable => return Ok(()),
            }
        }
        // Mirror the committed rows into the fake fs (production already
        // staged them pre-commit).
        for row in self.store.all_files().await? {
            if row.path == path || row.path.contains(conflict::COPY_MARKER) {
                match row.content_hash {
                    Some(h) if !row.tombstone => self.fs.write(&row.path, h),
                    _ => self.fs.delete(&row.path),
                }
            }
        }
        Ok(())
    }

    /// One anti-entropy pass: ingest every row of a remote snapshot (what the
    /// Merkle reconcile delivers leaf-by-leaf). Applies dominating rows,
    /// resolves concurrent ones — the path that hands conflict copies to a
    /// node that never witnessed the conflict on the op plane.
    pub async fn reconcile_from(&mut self, rows: &[FileRow]) -> Result<(), StoreError> {
        for r in rows {
            let local = self.store.load_file(&r.path).await?;
            match decide(local.as_ref(), &r.vv) {
                Decision::Apply => {
                    let effective = self
                        .store
                        .reconcile_upsert(ReconciledRow {
                            path: r.path.clone(),
                            content_hash: r.content_hash,
                            mode: r.mode,
                            size: r.size,
                            vv: r.vv.clone(),
                            tombstone: r.tombstone,
                            uuid: r.uuid,
                        })
                        .await?;
                    if effective == Decision::Apply {
                        match r.content_hash {
                            Some(h) if !r.tombstone => self.fs.write(&r.path, h),
                            _ => self.fs.delete(&r.path),
                        }
                    }
                }
                Decision::Concurrent => {
                    self.resolve_conflict(&r.path, Version::from_row(r)).await?;
                }
                Decision::Ignore | Decision::Quarantined => {}
            }
        }
        Ok(())
    }

    /// Materialized state: path → (content_hash, tombstone, vv). Two
    /// converged replicas have identical snapshots.
    pub async fn snapshot(&self) -> Result<Vec<FileRow>, StoreError> {
        self.store.all_files().await
    }

    /// Invariant: the (fake) filesystem holds exactly the live rows of the
    /// index with matching content. Call after any quiesced point.
    pub async fn assert_fs_matches_index(&self) -> Result<(), StoreError> {
        let rows = self.snapshot().await?;
        let live: BTreeMap<String, [u8; 32]> = rows
            .into_iter()
            .filter(|r| !r.tombstone)
            .filter_map(|r| r.content_hash.map(|h| (r.path, h)))
            .collect();
        assert_eq!(
            self.fs.0,
            live,
            "fs and materialized index diverged on node {:02x?}",
            &self.node_id[..2]
        );
        Ok(())
    }
}
