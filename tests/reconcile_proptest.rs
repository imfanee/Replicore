//! Anti-entropy property test (M2 exit criterion: divergent replicas — one
//! node fed ops the other missed — reconcile to identical state with no data
//! loss) plus the O(diff) descent-count proof (reviewer item).
//!
//! Drives the REAL `reconcile_pull` (real :memory: stores, real CAS, real
//! share directories and atomic applies) through an in-test transport that
//! answers tree/leaf/content queries directly from the other node — no QUIC,
//! so proptest can hammer it.

use std::path::PathBuf;

use proptest::prelude::*;
use replicore::chunk::{chunk_file_into_cas, Cas, ChunkParams, Manifest};
use replicore::merkle::{
    reconcile_pull, MerkleTree, ReconcileCtx, ReconcileError, ReconcileTransport, RemoteLeaf,
};
use replicore::oplog::{LocalChange, Store};
use replicore::proto::{OpType, WireChild};
use replicore::suppress::Suppressor;
use replicore::vv::NodeId;

const NODE_A: NodeId = [0xaa; 16];
const NODE_B: NodeId = [0xbb; 16];
const PARAMS: ChunkParams = ChunkParams {
    min: 4096,
    avg: 16 * 1024,
    max: 64 * 1024,
};

struct Node {
    _dir: tempfile::TempDir,
    share: PathBuf,
    store: Store,
    cas: Cas,
    suppress: Suppressor,
}

impl Node {
    fn new(id: NodeId) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let cas = Cas::open(&dir.path().join("cas")).unwrap();
        let store = Store::open(std::path::Path::new(":memory:"), id).unwrap();
        Node {
            _dir: dir,
            share,
            store,
            cas,
            suppress: Suppressor::new(),
        }
    }

    /// A real local write: file on disk, chunks in CAS, op + manifest in the
    /// store — exactly what ingest produces.
    async fn local_write(&self, rel: &str, content: &[u8]) {
        let abs = self.share.join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, content).unwrap();
        let manifest = chunk_file_into_cas(&abs, &PARAMS, &self.cas).unwrap();
        self.store
            .append_local(LocalChange {
                path: rel.to_string(),
                op_type: OpType::Write,
                mode: 0o644,
                size: content.len() as u64,
                content_hash: Some(manifest.content_hash),
                meta: None,
                manifest: Some(manifest),
            })
            .await
            .unwrap();
    }

    async fn local_delete(&self, rel: &str) {
        let _ = std::fs::remove_file(self.share.join(rel));
        self.store
            .append_local(LocalChange {
                path: rel.to_string(),
                op_type: OpType::Delete,
                mode: 0,
                size: 0,
                content_hash: None,
                meta: None,
                manifest: None,
            })
            .await
            .unwrap();
    }
}

/// Answers session queries straight out of the source node.
struct TestTransport<'a> {
    tree: MerkleTree,
    src: &'a Node,
}

impl ReconcileTransport for TestTransport<'_> {
    async fn root(&mut self) -> Result<[u8; 32], ReconcileError> {
        Ok(self.tree.root())
    }

    async fn children(&mut self, prefix: &str) -> Result<Vec<WireChild>, ReconcileError> {
        let (children, more) = self.tree.children_page(prefix, "", usize::MAX);
        assert!(!more);
        Ok(children)
    }

    async fn leaf(&mut self, path: &str) -> Result<Option<RemoteLeaf>, ReconcileError> {
        Ok(self.tree.leaf(path).map(|row| RemoteLeaf {
            tombstone: row.tombstone,
            content_hash: row.content_hash,
            vv: row.vv.clone(),
            mode: row.mode,
            size: row.size,
            uuid: row.uuid,
            meta: row.meta.clone(),
        }))
    }

    async fn ensure_content(
        &mut self,
        content_hash: [u8; 32],
        cas: &Cas,
    ) -> Result<Manifest, ReconcileError> {
        let manifest = self
            .src
            .store
            .manifest_for(content_hash)
            .await?
            .ok_or(replicore::fetch::FetchError::Unavailable)?;
        for entry in &manifest.chunks {
            if !cas.has(&entry.hash) {
                let bytes = self
                    .src
                    .cas
                    .read(&entry.hash) // verified read
                    .map_err(replicore::fetch::FetchError::Cas)?;
                cas.put_verified(&entry.hash, &bytes) // verified store
                    .map_err(replicore::fetch::FetchError::Cas)?;
            }
        }
        Ok(manifest)
    }
}

/// One pull session: `dst` pulls what it lacks from `src`.
async fn pull(dst: &Node, src: &Node) -> replicore::merkle::ReconcileReport {
    let local = MerkleTree::build(dst.store.all_files().await.unwrap());
    let mut transport = TestTransport {
        tree: MerkleTree::build(src.store.all_files().await.unwrap()),
        src,
    };
    let ctx = ReconcileCtx {
        store: &dst.store,
        cas: &dst.cas,
        share: &dst.share,
        suppress: &dst.suppress,
        policy: replicore::metadata::OwnerPolicy::Skip,
    };
    reconcile_pull(&local, &mut transport, &ctx).await.unwrap()
}

/// Both shares must hold exactly the live rows, byte-verified.
async fn assert_fs_consistent(node: &Node) {
    for row in node.store.all_files().await.unwrap() {
        let abs = node.share.join(&row.path);
        if row.tombstone {
            assert!(!abs.exists(), "tombstoned {} still on disk", row.path);
        } else {
            let data = std::fs::read(&abs).expect("live row missing on disk");
            assert_eq!(
                *blake3::hash(&data).as_bytes(),
                row.content_hash.expect("live row without hash"),
                "content mismatch at {}",
                row.path
            );
        }
    }
}

#[derive(Clone, Debug)]
enum Action {
    Write(u8),
    Delete,
}

fn arb_script() -> impl Strategy<Value = Vec<(usize, Action)>> {
    proptest::collection::vec(
        (
            0usize..4,
            prop_oneof![
                3 => (0u8..8).prop_map(Action::Write),
                1 => Just(Action::Delete),
            ],
        ),
        0..8,
    )
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Divergent replicas (NEITHER ever received the other's ops — total
    /// partition) reconcile to identical state, both directions, no loss.
    #[test]
    fn divergent_replicas_reconcile_to_identical_state(
        script_a in arb_script(),
        script_b in arb_script(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().build().expect("rt");
        rt.block_on(async {
            let a = Node::new(NODE_A);
            let b = Node::new(NODE_B);

            // Partitioned write ownership; zero live delivery (worst case —
            // anti-entropy is the only propagation path).
            for (idx, action) in &script_a {
                let path = format!("a/p{idx}");
                match action {
                    Action::Write(c) => a.local_write(&path, &[*c; 100]).await,
                    Action::Delete => a.local_delete(&path).await,
                }
            }
            for (idx, action) in &script_b {
                let path = format!("b/p{idx}");
                match action {
                    Action::Write(c) => b.local_write(&path, &[*c; 100]).await,
                    Action::Delete => b.local_delete(&path).await,
                }
            }

            // Heal: each side pulls what it lacks (FR-703).
            pull(&a, &b).await;
            pull(&b, &a).await;

            // Converged: identical materialized state (tombstones included)...
            let snap_a = a.store.all_files().await.unwrap();
            let snap_b = b.store.all_files().await.unwrap();
            prop_assert_eq!(&snap_a, &snap_b);
            // ...the filesystems agree with the index, byte-verified...
            assert_fs_consistent(&a).await;
            assert_fs_consistent(&b).await;
            // ...and a second round finds NOTHING to do (stability).
            let r1 = pull(&a, &b).await;
            let r2 = pull(&b, &a).await;
            prop_assert_eq!(r1.tree_reqs, 0); // identical roots: O(1) no-op
            prop_assert_eq!(r2.tree_reqs, 0);
            Ok(())
        })?;
    }
}

/// The reviewer item: descent must be O(differences), not O(files). With one
/// differing leaf among 2000 files in 20 directories, the puller may touch
/// only the root and the one differing directory — never the other 19.
#[tokio::test]
async fn descent_is_proportional_to_diff_not_corpus() {
    let a = Node::new(NODE_A);
    let b = Node::new(NODE_B);

    // Identical corpus on both sides — built as ops on A then mirrored onto
    // B via a full pull (cheapest way to share VVs exactly).
    for i in 0..2000 {
        a.local_write(&format!("d{:02}/f{i:04}", i % 20), &[(i % 251) as u8; 64])
            .await;
    }
    let first = pull(&b, &a).await;
    assert_eq!(first.applied, 2000);

    // In sync: O(1) — roots match, zero descent.
    let insync = pull(&b, &a).await;
    assert_eq!(insync.tree_reqs, 0);
    assert_eq!(insync.leaves_compared, 0);

    // ONE leaf changes on A.
    a.local_write("d07/f0707", b"changed!").await;
    let healed = pull(&b, &a).await;
    assert_eq!(healed.applied, 1);
    assert_eq!(
        healed.leaves_compared, 1,
        "compared more leaves than differed"
    );
    assert!(
        healed.tree_reqs <= 3,
        "descent touched {} directories for a 1-leaf diff in a 2000-file corpus",
        healed.tree_reqs
    );
}

/// Concurrent overlap across a partition heals with a DETERMINISTIC
/// resolution (M3, FR-303): the first pull resolves winner + conflict copy;
/// the second side adopts the merged rows; both end byte-identical with zero
/// loss.
#[tokio::test]
async fn reconcile_resolves_concurrent_identically() {
    let a = Node::new(NODE_A);
    let b = Node::new(NODE_B);
    a.local_write("shared/p", b"version A").await;
    b.local_write("shared/p", b"version B").await;

    let hash_a = *blake3::hash(b"version A").as_bytes();
    let hash_b = *blake3::hash(b"version B").as_bytes();
    let (win, lose): (&[u8], _) = if hash_a > hash_b {
        (b"version A", hash_b)
    } else {
        (b"version B", hash_a)
    };
    let copy_rel = replicore::conflict::copy_path_for("shared/p", &lose);

    // A's pull witnesses the conflict and resolves it.
    let ra = pull(&a, &b).await;
    assert_eq!(ra.resolved_conflicts, 1);
    assert_eq!(ra.skipped_concurrent, 0);
    // B's pull then sees A's merged winner row (dominating) and the copy row:
    // plain applies, no second resolution.
    let rb = pull(&b, &a).await;
    assert_eq!(rb.resolved_conflicts, 0);
    assert_eq!(rb.skipped_concurrent, 0);
    assert_eq!(rb.applied, 2);

    // Byte-identical state, including the copy row and its name.
    let snap_a = a.store.all_files().await.unwrap();
    let snap_b = b.store.all_files().await.unwrap();
    assert_eq!(snap_a, snap_b);
    assert!(snap_a.iter().any(|r| r.path == copy_rel));
    for node in [&a, &b] {
        assert_eq!(std::fs::read(node.share.join("shared/p")).unwrap(), win);
        let copy_bytes = std::fs::read(node.share.join(&copy_rel)).unwrap();
        assert_eq!(*blake3::hash(&copy_bytes).as_bytes(), lose);
    }
}

/// The stale-decision race, reconcile flavor: handle_leaf decides Apply,
/// then a concurrent local write to the same path lands during the content
/// fetch (injected inside ensure_content), then apply_assembled clobbers the
/// disk and reconcile_upsert runs. The committing re-check must downgrade —
/// and the downgrade must then RESOLVE (M3): deterministic winner, both VVs
/// absorbed, the loser preserved as a conflict copy, the disk matching.
#[tokio::test]
async fn reconcile_resolves_concurrent_local_write_landing_during_fetch() {
    /// Like TestTransport, but lands a local write on `dst` from inside the
    /// content fetch — the exact hazard window.
    struct RacingTransport<'a> {
        tree: MerkleTree,
        src: &'a Node,
        dst: &'a Node,
        injected: std::cell::Cell<bool>,
    }

    impl ReconcileTransport for RacingTransport<'_> {
        async fn root(&mut self) -> Result<[u8; 32], ReconcileError> {
            Ok(self.tree.root())
        }
        async fn children(&mut self, prefix: &str) -> Result<Vec<WireChild>, ReconcileError> {
            let (children, more) = self.tree.children_page(prefix, "", usize::MAX);
            assert!(!more);
            Ok(children)
        }
        async fn leaf(&mut self, path: &str) -> Result<Option<RemoteLeaf>, ReconcileError> {
            Ok(self.tree.leaf(path).map(|row| RemoteLeaf {
                tombstone: row.tombstone,
                content_hash: row.content_hash,
                vv: row.vv.clone(),
                mode: row.mode,
                size: row.size,
                uuid: row.uuid,
                meta: row.meta.clone(),
            }))
        }
        async fn ensure_content(
            &mut self,
            content_hash: [u8; 32],
            cas: &Cas,
        ) -> Result<Manifest, ReconcileError> {
            // THE INTERLEAVE: the local application writes the same path
            // while the session is fetching the remote content.
            if !self.injected.replace(true) {
                self.dst.local_write("race.bin", b"local content X").await;
            }
            let manifest = self
                .src
                .store
                .manifest_for(content_hash)
                .await?
                .ok_or(replicore::fetch::FetchError::Unavailable)?;
            for entry in &manifest.chunks {
                if !cas.has(&entry.hash) {
                    let bytes = self
                        .src
                        .cas
                        .read(&entry.hash)
                        .map_err(replicore::fetch::FetchError::Cas)?;
                    cas.put_verified(&entry.hash, &bytes)
                        .map_err(replicore::fetch::FetchError::Cas)?;
                }
            }
            Ok(manifest)
        }
    }

    let a = Node::new(NODE_A);
    let b = Node::new(NODE_B);
    a.local_write("race.bin", b"remote content R").await;

    let local_tree = MerkleTree::build(b.store.all_files().await.unwrap());
    let mut transport = RacingTransport {
        tree: MerkleTree::build(a.store.all_files().await.unwrap()),
        src: &a,
        dst: &b,
        injected: std::cell::Cell::new(false),
    };
    let ctx = ReconcileCtx {
        store: &b.store,
        cas: &b.cas,
        share: &b.share,
        suppress: &b.suppress,
        policy: replicore::metadata::OwnerPolicy::Skip,
    };
    let report = reconcile_pull(&local_tree, &mut transport, &ctx)
        .await
        .unwrap();

    // Downgrade caught AND resolved; nothing counted as a plain apply.
    assert_eq!(report.resolved_conflicts, 1);
    assert_eq!(report.skipped_concurrent, 0);
    assert_eq!(report.applied, 0);

    // Deterministic winner, both VV components absorbed — no masking, no
    // loss: the loser survives as the content-derived copy.
    let local_hash = *blake3::hash(b"local content X").as_bytes();
    let remote_hash = *blake3::hash(b"remote content R").as_bytes();
    let (win_data, lose_hash): (&[u8], _) = if local_hash > remote_hash {
        (b"local content X", remote_hash)
    } else {
        (b"remote content R", local_hash)
    };
    let row = b.store.load_file("race.bin").await.unwrap().unwrap();
    assert_eq!(row.content_hash, Some(*blake3::hash(win_data).as_bytes()));
    assert_eq!(row.vv.get(&NODE_A), 1);
    assert_eq!(row.vv.get(&NODE_B), 1);
    let copy_rel = replicore::conflict::copy_path_for("race.bin", &lose_hash);
    let copy_row = b.store.load_file(&copy_rel).await.unwrap().unwrap();
    assert_eq!(copy_row.content_hash, Some(lose_hash));
    // Disk agrees: winner at the path, loser at the copy.
    assert_eq!(std::fs::read(b.share.join("race.bin")).unwrap(), win_data);
    let copy_bytes = std::fs::read(b.share.join(&copy_rel)).unwrap();
    assert_eq!(*blake3::hash(&copy_bytes).as_bytes(), lose_hash);
}

/// Tombstones propagate via reconcile and stale content cannot resurrect.
#[tokio::test]
async fn reconcile_propagates_tombstones() {
    let a = Node::new(NODE_A);
    let b = Node::new(NODE_B);
    a.local_write("a/doomed", b"short-lived").await;
    pull(&b, &a).await; // B now has the live file
    assert!(b.share.join("a/doomed").exists());

    a.local_delete("a/doomed").await;
    pull(&b, &a).await; // B pulls the tombstone
    assert!(!b.share.join("a/doomed").exists());
    let row = b.store.load_file("a/doomed").await.unwrap().unwrap();
    assert!(row.tombstone);

    // Reverse pull must NOT resurrect from B's (stale) chunk store.
    let ra = pull(&a, &b).await;
    assert_eq!(ra.applied, 0);
    assert!(!a.share.join("a/doomed").exists());
}
