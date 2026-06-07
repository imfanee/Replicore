//! merkle.rs — Merkle-tree anti-entropy (FR-701/702/703).
//!
//! Leaf = `blake3(path ‖ 0x00 ‖ tombstone ‖ content_hash ‖ vv)` — metadata
//! beyond the tombstone flag is deliberately EXCLUDED (mode/size fidelity is
//! M3; hashing fields we do not reconcile would make trees differ forever).
//! Directory nodes hash their sorted children. Two replicas in the same
//! causal state therefore have identical roots, tombstones included.
//!
//! The tree is built per session from the `files` index (db rows only — no
//! file I/O), O(files) locally; **network descent is O(differences)**: a
//! subtree whose hash matches is pruned, never entered. `ReconcileReport`
//! counts the descent so tests can PROVE the pruning (reviewer item).
//! // SEAM(M3): persistent incremental subtree hashes make local build
//! O(changes) too.
//!
//! Sessions are pull-based and one-directional: the initiator fetches what it
//! lacks; the responder mutates nothing. Both sides of a link each run their
//! own pull, which converges the pair (the dominated side adopts; Equal
//! no-ops; Concurrent is RESOLVED deterministically — winner + conflict
//! copies through `Store::resolve_rows`, M3 FR-303). Applies go through
//! `decide()` + `Store::reconcile_upsert`/`resolve_rows` (state plane: files
//! rows only, never op cursors) with suppression registered like any apply,
//! so a reconcile session can run concurrently with the live op stream: the
//! single store thread linearizes, VV merges are idempotent, and whichever
//! path lands a dominating vector first turns the other into an Ignore.
//! Reconcile is also what hands conflict-copy rows to a node that never
//! witnessed the conflict on the op plane (its causal successor arrived
//! first) — the resolution backstop.

use std::collections::BTreeMap;
use std::path::Path;

use crate::apply::{apply_assembled, apply_delete, ApplyError};
use crate::chunk::{Cas, Manifest};
use crate::conflict::{PlannedRow, Version, META_NONE};
use crate::decide::{decide, Decision};
use crate::fetch::FetchError;
use crate::oplog::{ReconciledRow, ResolveOutcome, Store, StoreError};
use crate::proto::{ProtoError, WireChild};
use crate::state::FileRow;
use crate::suppress::Suppressor;
use crate::vv::VersionVector;

#[derive(thiserror::Error, Debug)]
pub enum ReconcileError {
    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),
    #[error("fetch: {0}")]
    Fetch(#[from] FetchError),
    #[error("task join: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("session violation: {0}")]
    Violation(&'static str),
    #[error("session closed")]
    Closed,
}

/// A leaf failure that retrying THIS session cannot fix (hostile path,
/// content gone everywhere, lying manifest): skip the leaf, keep the session.
/// Everything else aborts the session (a later session resumes).
fn leaf_error_is_skippable(e: &ReconcileError) -> bool {
    match e {
        ReconcileError::Apply(ApplyError::UnsafePath(_)) => true,
        ReconcileError::Apply(ApplyError::HashMismatch(_)) => true,
        ReconcileError::Fetch(f) => f.is_permanent(),
        ReconcileError::Violation(_) => true,
        _ => false,
    }
}

/// Merkle leaf hash. Pure; field-sensitivity is unit-tested.
pub fn leaf_hash(row: &FileRow) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(row.path.as_bytes());
    h.update(&[0x00]);
    h.update(&[row.tombstone as u8]);
    h.update(row.content_hash.as_ref().unwrap_or(&[0u8; 32]));
    // BTreeMap-backed VV: bincode encoding is deterministic.
    if let Ok(vv) = bincode::serialize(&row.vv) {
        h.update(&vv);
    }
    *h.finalize().as_bytes()
}

type Children = BTreeMap<String, ([u8; 32], bool)>;

/// Prefix tree over '/'-separated paths with bottom-up directory hashes.
pub struct MerkleTree {
    /// dir prefix ("" = root) → sorted children (name → (hash, is_dir)).
    dirs: BTreeMap<String, Children>,
    leaves: BTreeMap<String, FileRow>,
    root: [u8; 32],
}

fn split_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn join_prefix(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

impl MerkleTree {
    /// Build from index rows (any order; `all_files` happens to sort).
    pub fn build(rows: Vec<FileRow>) -> MerkleTree {
        let mut dirs: BTreeMap<String, Children> = BTreeMap::new();
        dirs.insert(String::new(), Children::new());
        let mut leaves = BTreeMap::new();

        for row in rows {
            let lh = leaf_hash(&row);
            let (parent, name) = split_parent(&row.path);
            dirs.entry(parent.to_string())
                .or_default()
                .insert(name.to_string(), (lh, false));
            // Ensure the ancestor chain exists with dir placeholders.
            let mut dir = parent.to_string();
            while !dir.is_empty() {
                let (up, name) = split_parent(&dir);
                let entry = dirs
                    .entry(up.to_string())
                    .or_default()
                    .entry(name.to_string())
                    .or_insert(([0u8; 32], true));
                entry.1 = true;
                dir = up.to_string();
            }
            leaves.insert(row.path.clone(), row);
        }

        // Bottom-up: reverse-lexicographic visits "a/b" before "a" before "".
        let prefixes: Vec<String> = dirs.keys().cloned().collect();
        for prefix in prefixes.iter().rev() {
            let hash = Self::hash_children(&dirs[prefix.as_str()]);
            if prefix.is_empty() {
                let mut tree = MerkleTree {
                    dirs,
                    leaves,
                    root: hash,
                };
                tree.root = hash;
                return tree;
            }
            let (up, name) = split_parent(prefix);
            if let Some(entry) = dirs.get_mut(up).and_then(|c| c.get_mut(name)) {
                entry.0 = hash;
            }
        }
        // rows was empty: only the root exists.
        let root = Self::hash_children(&dirs[""]);
        MerkleTree { dirs, leaves, root }
    }

    fn hash_children(children: &Children) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (name, (hash, is_dir)) in children {
            h.update(name.as_bytes());
            h.update(&[0x01, *is_dir as u8]);
            h.update(hash);
        }
        *h.finalize().as_bytes()
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn leaf(&self, path: &str) -> Option<&FileRow> {
        self.leaves.get(path)
    }

    pub fn children(&self, prefix: &str) -> Option<&Children> {
        self.dirs.get(prefix)
    }

    /// One page of a directory's children, sorted, strictly after
    /// `after_name`. Returns `(page, more)`.
    pub fn children_page(
        &self,
        prefix: &str,
        after_name: &str,
        limit: usize,
    ) -> (Vec<WireChild>, bool) {
        let Some(children) = self.dirs.get(prefix) else {
            return (Vec::new(), false);
        };
        let mut page = Vec::with_capacity(limit.min(children.len()));
        let mut iter = children
            .range::<String, _>((
                std::ops::Bound::Excluded(after_name.to_string()),
                std::ops::Bound::Unbounded,
            ))
            .peekable();
        while page.len() < limit {
            let Some((name, (hash, is_dir))) = iter.next() else {
                return (page, false);
            };
            page.push(WireChild {
                name: name.clone(),
                hash: *hash,
                is_dir: *is_dir,
            });
        }
        (page, iter.peek().is_some())
    }
}

/// What the puller learns about one remote leaf.
#[derive(Clone, Debug)]
pub struct RemoteLeaf {
    pub tombstone: bool,
    pub content_hash: Option<[u8; 32]>,
    pub vv: VersionVector,
    pub mode: u32,
    pub size: u64,
    pub uuid: Option<[u8; 16]>,
}

/// Session transport, abstracted so the convergence property test can drive
/// `reconcile_pull` with two in-memory replicas and no QUIC. Stable since
/// 1.75 (async fn in trait); used generically only.
#[allow(async_fn_in_trait)]
pub trait ReconcileTransport {
    async fn root(&mut self) -> Result<[u8; 32], ReconcileError>;
    /// FULL child list of a remote directory (impl paginates internally).
    async fn children(&mut self, prefix: &str) -> Result<Vec<WireChild>, ReconcileError>;
    async fn leaf(&mut self, path: &str) -> Result<Option<RemoteLeaf>, ReconcileError>;
    /// Make `content_hash`'s chunks present in `cas` and return the manifest
    /// (QUIC impl: multi-source fetch; test impl: copy across).
    async fn ensure_content(
        &mut self,
        content_hash: [u8; 32],
        cas: &Cas,
    ) -> Result<Manifest, ReconcileError>;
}

/// Everything a leaf apply needs.
pub struct ReconcileCtx<'a> {
    pub store: &'a Store,
    pub cas: &'a Cas,
    pub share: &'a Path,
    pub suppress: &'a Suppressor,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct ReconcileReport {
    /// Remote directory listings requested — THE O(diff) descent metric.
    pub tree_reqs: u64,
    pub leaves_compared: u64,
    pub applied: u64,
    /// Concurrent leaves RESOLVED this session: winner + copies committed
    /// through `resolve_rows` (FR-303).
    pub resolved_conflicts: u64,
    /// Concurrent leaves detected but NOT resolved this session (staging
    /// failed, retries exhausted under local-write interference): local state
    /// kept, a later session retries.
    pub skipped_concurrent: u64,
    /// Permanently unmaterializable leaves (hostile path / content gone):
    /// logged, skipped, left for a superseding op or a later session.
    pub skipped_damaged: u64,
}

/// The pull driver: descend differing subtrees of the remote tree, decide
/// each differing leaf, fetch+apply where the remote dominates. Serial
/// descent (bounded by definition); chunk parallelism lives inside
/// `ensure_content`.
pub async fn reconcile_pull<T: ReconcileTransport>(
    local: &MerkleTree,
    remote: &mut T,
    ctx: &ReconcileCtx<'_>,
) -> Result<ReconcileReport, ReconcileError> {
    let mut report = ReconcileReport::default();

    let remote_root = remote.root().await?;
    if remote_root == local.root() {
        return Ok(report); // O(1): in sync, descend nowhere
    }

    let empty = Children::new();
    let mut queue: Vec<String> = vec![String::new()];
    while let Some(prefix) = queue.pop() {
        report.tree_reqs += 1;
        let remote_children = remote.children(&prefix).await?;
        let local_children = local.children(&prefix).unwrap_or(&empty);
        for child in remote_children {
            match local_children.get(&child.name) {
                // THE pruning rule: identical hash = identical subtree/leaf.
                Some((local_hash, _)) if *local_hash == child.hash => {}
                _ if child.is_dir => queue.push(join_prefix(&prefix, &child.name)),
                _ => {
                    let path = join_prefix(&prefix, &child.name);
                    handle_leaf(&path, remote, ctx, &mut report).await?;
                }
            }
        }
        // Children we have that the remote lacks: nothing to PULL — if our
        // copy is genuinely newer the peer's own pull (other direction)
        // fetches it; if it was deleted there, a tombstone leaf exists and
        // was handled above.
    }
    Ok(report)
}

async fn handle_leaf<T: ReconcileTransport>(
    path: &str,
    remote: &mut T,
    ctx: &ReconcileCtx<'_>,
    report: &mut ReconcileReport,
) -> Result<(), ReconcileError> {
    report.leaves_compared += 1;
    let Some(rleaf) = remote.leaf(path).await? else {
        return Ok(()); // raced away under the responder's snapshot
    };
    let local_row = ctx.store.load_file(path).await?;
    match decide(local_row.as_ref(), &rleaf.vv) {
        Decision::Ignore | Decision::Quarantined => Ok(()),
        Decision::Concurrent => {
            // FR-303: resolve, don't skip — winner + conflict copies through
            // the committing transaction. This is also how copy rows reach a
            // node that never witnessed the conflict on the op plane.
            match resolve_concurrent_leaf(path, &rleaf, remote, ctx).await {
                Ok(true) => report.resolved_conflicts += 1,
                Ok(false) => report.skipped_concurrent += 1,
                Err(e) if leaf_error_is_skippable(&e) => {
                    report.skipped_damaged += 1;
                    tracing::error!(path, error = %e,
                        "reconcile: conflict copy unmaterializable; skipping");
                }
                Err(e) => return Err(e),
            }
            Ok(())
        }
        Decision::Apply => match apply_remote_leaf(path, &rleaf, remote, ctx).await {
            // The committing re-check inside reconcile_upsert may downgrade
            // a stale Apply (a concurrent local write landed during the
            // content fetch); the disk clobber was repaired and the conflict
            // RESOLVED inside apply_remote_leaf.
            Ok(LeafOutcome::Applied) => {
                report.applied += 1;
                Ok(())
            }
            Ok(LeafOutcome::Resolved) => {
                report.resolved_conflicts += 1;
                Ok(())
            }
            Ok(LeafOutcome::Skipped) => {
                report.skipped_concurrent += 1;
                Ok(())
            }
            Err(e) if leaf_error_is_skippable(&e) => {
                report.skipped_damaged += 1;
                tracing::error!(path, error = %e,
                        "reconcile: leaf permanently unmaterializable; skipping");
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}

/// How one leaf apply ended (the Apply-decision path).
enum LeafOutcome {
    Applied,
    /// The committing re-check downgraded to Concurrent and the conflict was
    /// resolved (winner + copies committed).
    Resolved,
    /// Downgraded and resolution did not complete: local kept, retried later.
    Skipped,
}

/// The conflict-resolution loop, reconcile flavor (FR-303): ask the store for
/// the authoritative plan (empty staging never matches), stage its contents
/// on disk through the atomic-apply discipline, commit. `Stale` re-derives
/// under local-write interference; bounded retries. Returns whether the
/// resolution committed. On any non-committed exit every path staged here is
/// restored from its committed row, so no uncommitted content (and no orphan
/// copy the scanner would mint an op for) is left on disk.
async fn resolve_concurrent_leaf<T: ReconcileTransport>(
    path: &str,
    rleaf: &RemoteLeaf,
    remote: &mut T,
    ctx: &ReconcileCtx<'_>,
) -> Result<bool, ReconcileError> {
    let rv = Version {
        tombstone: rleaf.tombstone,
        content_hash: rleaf.content_hash,
        meta_hash: META_NONE,
        mode: rleaf.mode,
        size: rleaf.size,
        vv: rleaf.vv.clone(),
        uuid: rleaf.uuid,
    };
    let mut staged: Vec<PlannedRow> = Vec::new();
    let mut staged_paths: Vec<String> = Vec::new();
    for _ in 0..4 {
        match ctx
            .store
            .resolve_rows(path, rv.clone(), std::mem::take(&mut staged))
            .await?
        {
            ResolveOutcome::Resolved => {
                tracing::info!(path, "reconcile: conflict resolved (FR-303)");
                return Ok(true);
            }
            ResolveOutcome::NotConcurrent(_) => {
                restore_paths(ctx, &staged_paths).await;
                return Ok(false);
            }
            ResolveOutcome::Unresolvable => {
                tracing::error!(
                    path,
                    "reconcile: conflict copy chain too deep; keeping local"
                );
                restore_paths(ctx, &staged_paths).await;
                return Ok(false);
            }
            ResolveOutcome::Stale { plan } => {
                for row in &plan {
                    match stage_planned_row(row, remote, ctx).await {
                        Ok(true) => staged_paths.push(row.path.clone()),
                        Ok(false) => {}
                        Err(e) => {
                            restore_paths(ctx, &staged_paths).await;
                            return Err(e);
                        }
                    }
                }
                staged = plan;
            }
        }
    }
    tracing::warn!(
        path,
        "reconcile: resolution retries exhausted under local writes; later session retries"
    );
    restore_paths(ctx, &staged_paths).await;
    Ok(false)
}

/// Stage one planned row's content on disk (stage→fsync→verify→rename +
/// suppression — the only apply discipline). Content comes from the local
/// manifest + CAS when we hold it (local writes chunk into the CAS at
/// ingest), else from the session transport. Returns whether the disk was
/// touched (an already-current path needs no staging).
async fn stage_planned_row<T: ReconcileTransport>(
    row: &PlannedRow,
    remote: &mut T,
    ctx: &ReconcileCtx<'_>,
) -> Result<bool, ReconcileError> {
    if row.tombstone {
        let share = ctx.share.to_path_buf();
        let rel = row.path.clone();
        let suppress = ctx.suppress.clone();
        tokio::task::spawn_blocking(move || apply_delete(&share, &rel, &suppress)).await??;
        return Ok(true);
    }
    let Some(hash) = row.content_hash else {
        return Err(ReconcileError::Violation("live planned row without hash"));
    };
    // Already current on disk (e.g. the winner is the local content): the
    // commit only moves the row's VV.
    if let Some(cur) = ctx.store.load_row(&row.path).await? {
        if !cur.tombstone && cur.content_hash == Some(hash) {
            return Ok(false);
        }
    }
    let manifest = match ctx.store.manifest_for(hash).await? {
        Some(m) => m,
        None => {
            let m = remote.ensure_content(hash, ctx.cas).await?;
            // Persist the structure: a committed copy row must be SERVABLE
            // (peers pull copy rows via reconcile — that is how copies reach
            // nodes that never witnessed the conflict). Idempotent.
            ctx.store.put_manifest(m.clone()).await?;
            m
        }
    };
    let share = ctx.share.to_path_buf();
    let rel = row.path.clone();
    let mode = row.mode;
    let suppress = ctx.suppress.clone();
    let cas = ctx.cas.clone();
    tokio::task::spawn_blocking(move || {
        apply_assembled(&share, &rel, mode, &hash, &manifest, &cas, &suppress)
    })
    .await??;
    Ok(true)
}

/// Restore every path in `paths` from its committed row — the repair for
/// staged-but-not-committed resolution content.
async fn restore_paths(ctx: &ReconcileCtx<'_>, paths: &[String]) {
    for p in paths {
        restore_local_content(ctx.store, ctx.cas, ctx.share, ctx.suppress, p).await;
    }
}

async fn apply_remote_leaf<T: ReconcileTransport>(
    path: &str,
    rleaf: &RemoteLeaf,
    remote: &mut T,
    ctx: &ReconcileCtx<'_>,
) -> Result<LeafOutcome, ReconcileError> {
    let effective;
    if rleaf.tombstone {
        let share = ctx.share.to_path_buf();
        let rel = path.to_string();
        let suppress = ctx.suppress.clone();
        tokio::task::spawn_blocking(move || apply_delete(&share, &rel, &suppress)).await??;
        effective = ctx
            .store
            .reconcile_upsert(ReconciledRow {
                path: path.to_string(),
                content_hash: None,
                mode: rleaf.mode,
                size: 0,
                vv: rleaf.vv.clone(),
                tombstone: true,
                uuid: rleaf.uuid,
            })
            .await?;
    } else {
        let hash = rleaf
            .content_hash
            .ok_or(ReconcileError::Violation("live leaf without content hash"))?;
        let manifest = remote.ensure_content(hash, ctx.cas).await?;
        {
            let share = ctx.share.to_path_buf();
            let rel = path.to_string();
            let mode = rleaf.mode;
            let suppress = ctx.suppress.clone();
            let cas = ctx.cas.clone();
            tokio::task::spawn_blocking(move || {
                apply_assembled(&share, &rel, mode, &hash, &manifest, &cas, &suppress)
            })
            .await??;
        }
        effective = ctx
            .store
            .reconcile_upsert(ReconciledRow {
                path: path.to_string(),
                content_hash: Some(hash),
                mode: rleaf.mode,
                size: rleaf.size,
                vv: rleaf.vv.clone(),
                tombstone: false,
                uuid: rleaf.uuid,
            })
            .await?;
    }
    if effective == Decision::Apply {
        return Ok(LeafOutcome::Applied);
    }
    // Stale decision: the unlink/rename above clobbered a concurrent local
    // write — put the committed local state back on disk, then RESOLVE the
    // conflict the downgrade just proved (the second reconcile Concurrent
    // site gets the same FR-303 treatment as the first).
    tracing::warn!(
        path,
        ?effective,
        "reconcile: concurrent local write landed during fetch; restoring and resolving"
    );
    restore_local_content(ctx.store, ctx.cas, ctx.share, ctx.suppress, path).await;
    if effective == Decision::Concurrent
        && resolve_concurrent_leaf(path, rleaf, remote, ctx).await?
    {
        return Ok(LeafOutcome::Resolved);
    }
    Ok(LeafOutcome::Skipped)
}

/// Re-materialize `path`'s on-disk content from the LOCAL committed row —
/// the repair for a stale-decision downgrade, where a remote rename/unlink
/// already clobbered a concurrent local write before the committing
/// re-check caught it. Live row → re-assemble from its manifest + the CAS
/// (local writes chunk into the CAS at ingest, so the bytes are present);
/// tombstone/absent row → ensure the file is gone. Failures are logged, not
/// fatal: the skip is already durably recorded and the scanner remains the
/// convergence backstop.
pub(crate) async fn restore_local_content(
    store: &Store,
    cas: &Cas,
    share: &Path,
    suppress: &Suppressor,
    path: &str,
) {
    let row = match store.load_file(path).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(path, error = %e, "restore: cannot load local row");
            return;
        }
    };
    match row {
        Some(local) if !local.tombstone => {
            let Some(hash) = local.content_hash else {
                tracing::error!(path, "restore: live row without content hash");
                return;
            };
            let manifest = match store.manifest_for(hash).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    tracing::error!(path, "restore: local manifest missing; scanner will heal");
                    return;
                }
                Err(e) => {
                    tracing::error!(path, error = %e, "restore: manifest lookup failed");
                    return;
                }
            };
            let share = share.to_path_buf();
            let rel = path.to_string();
            let mode = local.mode;
            let suppress = suppress.clone();
            let cas = cas.clone();
            let result = tokio::task::spawn_blocking(move || {
                apply_assembled(&share, &rel, mode, &hash, &manifest, &cas, &suppress)
            })
            .await;
            match result {
                Ok(Ok(())) => tracing::info!(path, "restored local content after clobber"),
                Ok(Err(e)) => tracing::error!(path, error = %e, "restore: assembly failed"),
                Err(e) => tracing::error!(path, error = %e, "restore: task failed"),
            }
        }
        // Local state is "deleted" (tombstone) or unknown: the file must
        // not exist.
        _ => {
            let share = share.to_path_buf();
            let rel = path.to_string();
            let suppress = suppress.clone();
            let result =
                tokio::task::spawn_blocking(move || apply_delete(&share, &rel, &suppress)).await;
            match result {
                Ok(Ok(())) => tracing::info!(path, "restored local absence after clobber"),
                Ok(Err(e)) => tracing::error!(path, error = %e, "restore: delete failed"),
                Err(e) => tracing::error!(path, error = %e, "restore: task failed"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vv::NodeId;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn row(path: &str, hash: u8, tombstone: bool, vva: u64) -> FileRow {
        FileRow {
            path: path.into(),
            content_hash: if tombstone { None } else { Some([hash; 32]) },
            mode: 0o644,
            size: 1,
            tombstone,
            vv: [(nid(1), vva)].into_iter().collect(),
            uuid: None,
        }
    }

    #[test]
    fn leaf_hash_is_sensitive_to_every_causal_field_only() {
        let base = row("a/b", 1, false, 1);
        assert_eq!(leaf_hash(&base), leaf_hash(&base.clone()));
        let mut other = base.clone();
        other.path = "a/c".into();
        assert_ne!(leaf_hash(&base), leaf_hash(&other));
        let mut other = base.clone();
        other.content_hash = Some([2; 32]);
        assert_ne!(leaf_hash(&base), leaf_hash(&other));
        let mut other = base.clone();
        other.tombstone = true;
        assert_ne!(leaf_hash(&base), leaf_hash(&other));
        let mut other = base.clone();
        other.vv = [(nid(1), 2u64)].into_iter().collect();
        assert_ne!(leaf_hash(&base), leaf_hash(&other));
        // Mode/size are NOT hashed (M3 fidelity — no reconcile flap).
        let mut other = base.clone();
        other.mode = 0o600;
        other.size = 999;
        assert_eq!(leaf_hash(&base), leaf_hash(&other));
    }

    #[test]
    fn identical_states_have_identical_roots() {
        let rows = vec![
            row("a/x", 1, false, 1),
            row("a/y", 2, true, 2),
            row("z", 3, false, 1),
        ];
        let t1 = MerkleTree::build(rows.clone());
        let t2 = MerkleTree::build(rows);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn any_leaf_change_changes_the_root_and_only_its_subtree() {
        let mut rows = vec![
            row("a/x", 1, false, 1),
            row("a/y", 2, false, 1),
            row("b/z", 3, false, 1),
        ];
        let before = MerkleTree::build(rows.clone());
        rows[0] = row("a/x", 9, false, 2);
        let after = MerkleTree::build(rows);

        assert_ne!(before.root(), after.root());
        // Subtree "b" untouched: its hash is identical (the pruning basis).
        let b_before = before.children("").unwrap().get("b").unwrap();
        let b_after = after.children("").unwrap().get("b").unwrap();
        assert_eq!(b_before, b_after);
        // Subtree "a" differs.
        let a_before = before.children("").unwrap().get("a").unwrap();
        let a_after = after.children("").unwrap().get("a").unwrap();
        assert_ne!(a_before.0, a_after.0);
    }

    #[test]
    fn children_pagination_walks_everything() {
        let rows: Vec<FileRow> = (0..25)
            .map(|i| row(&format!("d/f{i:02}"), i, false, 1))
            .collect();
        let tree = MerkleTree::build(rows);
        let mut all = Vec::new();
        let mut after = String::new();
        loop {
            let (page, more) = tree.children_page("d", &after, 7);
            assert!(page.len() <= 7);
            all.extend(page.iter().map(|c| c.name.clone()));
            if !more {
                break;
            }
            after = all.last().expect("non-empty page").clone();
        }
        assert_eq!(all.len(), 25);
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted);
    }

    #[test]
    fn empty_tree_has_a_root() {
        let t = MerkleTree::build(Vec::new());
        let t2 = MerkleTree::build(Vec::new());
        assert_eq!(t.root(), t2.root());
    }
}
