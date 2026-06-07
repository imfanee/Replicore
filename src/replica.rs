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

use crate::decide::{decide, Decision};
use crate::oplog::{LocalChange, Store, StoreError};
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
            }
        }
        let effective = self.store.apply_remote(op.clone(), decision).await?;
        if decision == Decision::Apply && effective != Decision::Apply {
            // Repair the clobber from the committed row (production runs
            // merkle::restore_local_content here).
            match self.store.load_file(&op.path).await? {
                Some(row) if !row.tombstone => {
                    if let Some(hash) = row.content_hash {
                        self.fs.write(&op.path, hash);
                    }
                }
                _ => self.fs.delete(&op.path),
            }
        }
        Ok(Some(effective))
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
