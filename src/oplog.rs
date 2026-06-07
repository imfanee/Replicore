//! oplog.rs — durable, WAL-backed operation log and store thread (FR-201/202,
//! FR-801/802).
//!
//! One dedicated OS thread owns the SQLite connection; everything else talks
//! to it over a command channel (message-passing per CLAUDE.md — `Connection`
//! is also `!Sync`). A single writer makes the crash-safety transaction
//! ordering trivially auditable: every durable promise an ack makes is one
//! `COMMIT` (`synchronous=FULL`, so the WAL is fsynced) that happens **before**
//! the ack frame is sent.
//!
//! Sequencing: `oplog.seq` is this store's arrival order (rowid). Each op also
//! carries `origin_seq`, the *origin node's* gap-free monotonic counter —
//! that is what peer cursors and acks speak. For our own ops we assign
//! `origin_seq = MAX(origin_seq among our ops) + 1`.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::{mpsc, oneshot, watch};

use crate::chunk::Manifest;
use crate::conflict::{self, PlannedRow, Version};
use crate::decide::{decide, Decision, LocalFile};
use crate::proto::{op_id, OpRecord, OpType};
use crate::state::{self, FileRow, LiveFile};
use crate::vv::NodeId;

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("version-vector blob corrupt: {0}")]
    VvCodec(#[source] bincode::Error),
    #[error("database corrupt: bad {0}")]
    Corrupt(&'static str),
    #[error("store thread unavailable")]
    Gone,
}

/// A local mutation observed by the watcher/scanner, before it becomes an op.
#[derive(Clone, Debug)]
pub struct LocalChange {
    pub path: String,
    pub op_type: OpType,
    pub mode: u32,
    pub size: u64,
    /// BLAKE3 of the new content; `None` for deletes.
    pub content_hash: Option<[u8; 32]>,
    /// Chunk manifest built while hashing (FR-402); persisted in the SAME
    /// transaction as the op so a local op and its manifest are atomically
    /// durable. `None` for deletes.
    pub manifest: Option<Manifest>,
}

/// A row learned via anti-entropy (state plane). Applying one merges the VV
/// and upserts `files` ONLY — no oplog row, no `applied` entry, no cursor
/// movement. That separation is what keeps reconcile from ever disturbing
/// the live-op resume/ack machinery.
#[derive(Clone, Debug)]
pub struct ReconciledRow {
    pub path: String,
    pub content_hash: Option<[u8; 32]>,
    pub mode: u32,
    pub size: u64,
    /// The REMOTE vector; the store merges it with the local row's inside
    /// the transaction (no TOCTOU).
    pub vv: crate::vv::VersionVector,
    pub tombstone: bool,
}

/// Outcome of a [`Store::resolve_rows`] attempt — the conflict-path analogue
/// of the effective decision `apply_remote` returns.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ResolveOutcome {
    /// The staged plan still matched under the committing transaction: winner
    /// row and copy rows are durable. The caller's staged disk state is now
    /// the truth.
    Resolved,
    /// The fresh row is no longer concurrent with the remote version (e.g.
    /// reconcile merged another node's resolution meanwhile). NOTHING was
    /// committed; the caller repairs any staged disk state from the rows
    /// (`Ignore`-shaped) or re-routes (`Apply`-shaped).
    NotConcurrent(Decision),
    /// Still concurrent, but the rows changed since the caller planned (a
    /// local write landed during the loser fetch — the stale-decision hazard
    /// on the conflict path) or a copy-path collision surfaced. NOTHING was
    /// committed. `plan` is the authoritative re-derivation: stage its
    /// contents and retry.
    Stale { plan: Vec<PlannedRow> },
    /// The copy chain exceeded [`conflict::MAX_COPY_DEPTH`]. Nothing was
    /// committed; the conflict stays detected-but-unresolved (the M1 posture)
    /// and reconcile retries later. Operators see it via the conflict log.
    Unresolvable,
}

enum StoreCmd {
    AppendLocal {
        change: LocalChange,
        reply: oneshot::Sender<Result<Option<OpRecord>, StoreError>>,
    },
    ResolveRows {
        path: String,
        remote: Box<Version>,
        staged: Vec<PlannedRow>,
        reply: oneshot::Sender<Result<ResolveOutcome, StoreError>>,
    },
    LoadRow {
        path: String,
        reply: oneshot::Sender<Result<Option<FileRow>, StoreError>>,
    },
    ApplyRemote {
        op: Box<OpRecord>,
        decision: Decision,
        reply: oneshot::Sender<Result<Decision, StoreError>>,
    },
    LoadFile {
        path: String,
        reply: oneshot::Sender<Result<Option<LocalFile>, StoreError>>,
    },
    HasApplied {
        op_id: [u8; 32],
        reply: oneshot::Sender<Result<bool, StoreError>>,
    },
    OpsSince {
        origin: NodeId,
        after_seq: i64,
        limit: u32,
        reply: oneshot::Sender<Result<Vec<OpRecord>, StoreError>>,
    },
    RecvCursor {
        peer: NodeId,
        reply: oneshot::Sender<Result<i64, StoreError>>,
    },
    AdvanceAck {
        peer: NodeId,
        up_to_seq: i64,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    LastAcked {
        peer: NodeId,
        reply: oneshot::Sender<Result<i64, StoreError>>,
    },
    LiveFiles {
        reply: oneshot::Sender<Result<Vec<LiveFile>, StoreError>>,
    },
    AllFiles {
        reply: oneshot::Sender<Result<Vec<FileRow>, StoreError>>,
    },
    PathForHash {
        hash: [u8; 32],
        reply: oneshot::Sender<Result<Option<String>, StoreError>>,
    },
    OpCount {
        reply: oneshot::Sender<Result<i64, StoreError>>,
    },
    PutManifest {
        manifest: Box<Manifest>,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    ManifestFor {
        content_hash: [u8; 32],
        reply: oneshot::Sender<Result<Option<Manifest>, StoreError>>,
    },
    ReconcileUpsert {
        row: Box<ReconciledRow>,
        reply: oneshot::Sender<Result<Decision, StoreError>>,
    },
    SnapshotForJoin {
        reply: oneshot::Sender<Result<JoinSnapshot, StoreError>>,
    },
    AdvanceRecvCursor {
        peer: NodeId,
        origin: NodeId,
        up_to_seq: i64,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    GetMeta {
        key: String,
        reply: oneshot::Sender<Result<Option<String>, StoreError>>,
    },
    SetMeta {
        key: String,
        value: String,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
}

/// An atomic bootstrap snapshot for a joining/resuming subscriber (FR-1311).
///
/// `rows` is the full index and `frontier` is the per-origin maximum
/// `origin_seq` present in the oplog. Because the store thread serializes every
/// command, both are read in ONE handler with no interleaved append — so the
/// snapshot provably covers exactly the ops with `origin_seq <= frontier[origin]`
/// for each origin. Any op appended AFTER this snapshot is `> frontier` by
/// construction and therefore rides the live stream exactly once (the whole
/// no-loss/no-double-apply guarantee rests on this atomicity).
#[derive(Clone, Debug)]
pub struct JoinSnapshot {
    pub rows: Vec<FileRow>,
    pub frontier: Vec<(NodeId, i64)>,
}

/// Async handle to the store thread. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    tx: mpsc::Sender<StoreCmd>,
    latest: watch::Receiver<i64>,
}

impl Store {
    /// Open (or create) the database, run migrations, and launch the store
    /// thread. `":memory:"` works for tests.
    pub fn open(db_path: &Path, node_id: NodeId) -> Result<Store, StoreError> {
        let conn = Connection::open(db_path)?;
        // WAL for crash-safe append throughput; FULL so COMMIT == fsynced
        // (FR-801: durable before peer acknowledgment). On :memory: the
        // journal_mode pragma reports "memory" — that's fine for tests.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch(
            "PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS oplog (
               seq          INTEGER PRIMARY KEY,
               op_id        BLOB UNIQUE NOT NULL,
               origin       BLOB NOT NULL,
               origin_seq   INTEGER NOT NULL,
               op_type      INTEGER NOT NULL,
               path         TEXT NOT NULL,
               mode         INTEGER NOT NULL,
               size         INTEGER NOT NULL,
               content_hash BLOB,
               vv           BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS oplog_origin ON oplog(origin, origin_seq);
             -- Conflict resolution derives from the path's op history (the
             -- antichain scan in resolve_rows).
             CREATE INDEX IF NOT EXISTS oplog_path ON oplog(path);
             CREATE TABLE IF NOT EXISTS files (
               path         TEXT PRIMARY KEY,
               content_hash BLOB,
               mode         INTEGER NOT NULL,
               size         INTEGER NOT NULL,
               vv           BLOB NOT NULL,
               tombstone    INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS peers (
               node_id        BLOB PRIMARY KEY,
               last_sent_seq  INTEGER NOT NULL DEFAULT 0,
               last_acked_seq INTEGER NOT NULL DEFAULT 0,
               recv_cursor    INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS applied (
               op_id BLOB PRIMARY KEY
             );
             CREATE TABLE IF NOT EXISTS manifests (
               content_hash BLOB PRIMARY KEY,
               chunk_count  INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS manifest_chunks (
               content_hash BLOB NOT NULL,
               idx          INTEGER NOT NULL,
               chunk_hash   BLOB NOT NULL,
               len          INTEGER NOT NULL,
               PRIMARY KEY (content_hash, idx)
             );
             CREATE INDEX IF NOT EXISTS manifest_chunks_by_chunk
               ON manifest_chunks(chunk_hash); -- SEAM(M3): CAS GC refcounts
             CREATE TABLE IF NOT EXISTS peer_cursors (
               peer           BLOB NOT NULL,
               origin         BLOB NOT NULL,
               recv_cursor    INTEGER NOT NULL DEFAULT 0,
               last_acked_seq INTEGER NOT NULL DEFAULT 0,
               PRIMARY KEY (peer, origin)
             );
             -- Small key/value store for daemon-owned scalars (e.g. the
             -- node's join lifecycle). String values keep migrations trivial.
             CREATE TABLE IF NOT EXISTS meta (
               key   TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );",
        )?;

        // One-time idempotent backfill from the M1 single-cursor layout.
        // recv_cursor was keyed (peer == origin); last_acked was "this peer
        // acked OUR ops", i.e. (peer, our node id).
        conn.execute(
            "INSERT OR IGNORE INTO peer_cursors (peer, origin, recv_cursor)
             SELECT node_id, node_id, recv_cursor FROM peers WHERE recv_cursor > 0",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO peer_cursors (peer, origin, last_acked_seq)
             SELECT node_id, ?1, last_acked_seq FROM peers
             WHERE last_acked_seq > 0 AND node_id != ?1",
            [node_id.as_slice()],
        )?;

        let initial_latest = latest_origin_seq(&conn, &node_id)?;
        let (latest_tx, latest_rx) = watch::channel(initial_latest);
        let (cmd_tx, cmd_rx) = mpsc::channel::<StoreCmd>(256);

        std::thread::Builder::new()
            .name("replicore-store".into())
            .spawn(move || run_store(conn, node_id, cmd_rx, latest_tx))
            .map_err(|_| StoreError::Gone)?;

        Ok(Store {
            tx: cmd_tx,
            latest: latest_rx,
        })
    }

    /// Watch the latest locally-appended `origin_seq` (push loops wait on
    /// this instead of polling).
    pub fn watch_latest(&self) -> watch::Receiver<i64> {
        self.latest.clone()
    }

    async fn call<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<R, StoreError>>) -> StoreCmd,
    ) -> Result<R, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(make(reply))
            .await
            .map_err(|_| StoreError::Gone)?;
        rx.await.map_err(|_| StoreError::Gone)?
    }

    /// Turn a local mutation into a durable op: VV increment + oplog append +
    /// files upsert in ONE transaction. Returns `None` when the change is a
    /// causal no-op (content identical, or delete of an unknown/tombstoned
    /// path) — the store-enforced half of loop defense (FR-901).
    pub async fn append_local(&self, change: LocalChange) -> Result<Option<OpRecord>, StoreError> {
        self.call(|reply| StoreCmd::AppendLocal { change, reply })
            .await
    }

    /// Durably record the handling of a remote op and, when the decision
    /// still holds under the committing transaction, materialize it. One
    /// transaction; idempotent on redelivery. MUST be awaited before acking
    /// the op (FR-801).
    ///
    /// Returns the EFFECTIVE decision: an `Apply` computed before a long
    /// fetch is re-validated against the current row and downgraded to
    /// `Concurrent`/`Ignore` if a concurrent local write landed meanwhile —
    /// in that case the caller must repair the on-disk clobber (the rename
    /// already happened) via `merkle::restore_local_content`.
    pub async fn apply_remote(
        &self,
        op: OpRecord,
        decision: Decision,
    ) -> Result<Decision, StoreError> {
        self.call(|reply| StoreCmd::ApplyRemote {
            op: Box::new(op),
            decision,
            reply,
        })
        .await
    }

    pub async fn load_file(&self, path: &str) -> Result<Option<LocalFile>, StoreError> {
        let path = path.to_string();
        self.call(|reply| StoreCmd::LoadFile { path, reply }).await
    }

    /// Idempotency fast path (FR-802): true iff this op id was durably handled.
    pub async fn has_applied(&self, op_id: [u8; 32]) -> Result<bool, StoreError> {
        self.call(|reply| StoreCmd::HasApplied { op_id, reply })
            .await
    }

    /// Ascending `origin_seq` ops originated by `origin`, strictly after
    /// `after_seq` (the peer-resume stream, FR-503).
    pub async fn ops_since(
        &self,
        origin: NodeId,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<OpRecord>, StoreError> {
        self.call(|reply| StoreCmd::OpsSince {
            origin,
            after_seq,
            limit,
            reply,
        })
        .await
    }

    /// Our durable cursor of `peer`'s ops — what Hello advertises as
    /// `resume_from`.
    pub async fn recv_cursor(&self, peer: NodeId) -> Result<i64, StoreError> {
        self.call(|reply| StoreCmd::RecvCursor { peer, reply })
            .await
    }

    /// Record that `peer` durably acked our ops up to `up_to_seq`.
    pub async fn advance_ack(&self, peer: NodeId, up_to_seq: i64) -> Result<(), StoreError> {
        self.call(|reply| StoreCmd::AdvanceAck {
            peer,
            up_to_seq,
            reply,
        })
        .await
    }

    pub async fn last_acked(&self, peer: NodeId) -> Result<i64, StoreError> {
        self.call(|reply| StoreCmd::LastAcked { peer, reply }).await
    }

    /// Scanner diff basis: every live path with expected content/meta.
    pub async fn live_files(&self) -> Result<Vec<LiveFile>, StoreError> {
        self.call(|reply| StoreCmd::LiveFiles { reply }).await
    }

    /// Full index, tombstones included, ordered by path — the convergence
    /// snapshot for tests and the M2 reconciliation seam.
    pub async fn all_files(&self) -> Result<Vec<FileRow>, StoreError> {
        self.call(|reply| StoreCmd::AllFiles { reply }).await
    }

    /// Serve a content-addressed fetch: a live path holding `hash`, if any.
    pub async fn path_for_hash(&self, hash: [u8; 32]) -> Result<Option<String>, StoreError> {
        self.call(|reply| StoreCmd::PathForHash { hash, reply })
            .await
    }

    /// Total oplog rows — used by tests and the quiesce check (no-storm).
    pub async fn op_count(&self) -> Result<i64, StoreError> {
        self.call(|reply| StoreCmd::OpCount { reply }).await
    }

    /// Durably record a manifest's structure (idempotent). The receive path
    /// calls this BEFORE fetching chunks so a crash mid-transfer resumes with
    /// the structure already known.
    pub async fn put_manifest(&self, manifest: Manifest) -> Result<(), StoreError> {
        self.call(|reply| StoreCmd::PutManifest {
            manifest: Box::new(manifest),
            reply,
        })
        .await
    }

    pub async fn manifest_for(
        &self,
        content_hash: [u8; 32],
    ) -> Result<Option<Manifest>, StoreError> {
        self.call(|reply| StoreCmd::ManifestFor {
            content_hash,
            reply,
        })
        .await
    }

    /// Commit a conflict resolution: winner row + conflict-copy rows in ONE
    /// transaction, after RE-DERIVING the plan from the freshly-loaded rows
    /// and comparing it to what the caller staged (the stale-decision
    /// re-check, extended to the conflict path — FR-303 routes through the
    /// same committing discipline as `apply_remote`).
    ///
    /// State-plane only, like [`Store::reconcile_upsert`]: touches `files`
    /// exclusively — no oplog row, no `applied` entry, no cursor movement.
    /// The op-plane record for a live Concurrent op is the unchanged
    /// `apply_remote(op, Concurrent)`; resolution is *derived locally* on
    /// every node that witnesses the conflict and is never itself an op
    /// (reconcile delivers the copy rows to nodes that never witness it).
    ///
    /// The caller must have staged every live row in `staged` on disk
    /// (stage→fsync→verify→rename + suppression) BEFORE this call; on any
    /// non-`Resolved` outcome it repairs the staging.
    pub async fn resolve_rows(
        &self,
        path: &str,
        remote: Version,
        staged: Vec<PlannedRow>,
    ) -> Result<ResolveOutcome, StoreError> {
        let path = path.to_string();
        self.call(|reply| StoreCmd::ResolveRows {
            path,
            remote: Box::new(remote),
            staged,
            reply,
        })
        .await
    }

    /// Full row for one path (size + VV included) — the conflict-resolution
    /// planning view. Read-only.
    pub async fn load_row(&self, path: &str) -> Result<Option<FileRow>, StoreError> {
        let path = path.to_string();
        self.call(|reply| StoreCmd::LoadRow { path, reply }).await
    }

    /// Anti-entropy state apply — see [`ReconciledRow`] for the contract.
    /// Returns the effective decision (re-validated in the committing tx);
    /// on downgrade the caller repairs the disk.
    pub async fn reconcile_upsert(&self, row: ReconciledRow) -> Result<Decision, StoreError> {
        self.call(|reply| StoreCmd::ReconcileUpsert {
            row: Box::new(row),
            reply,
        })
        .await
    }

    /// Atomic (index rows, per-origin op frontier) for a join bootstrap.
    /// See [`JoinSnapshot`] — the atomicity is the whole correctness argument.
    pub async fn snapshot_for_join(&self) -> Result<JoinSnapshot, StoreError> {
        self.call(|reply| StoreCmd::SnapshotForJoin { reply }).await
    }

    /// Durably advance our cursor of `origin`'s ops as seen via `peer` to
    /// `up_to_seq` (monotonic MAX). Called after a reconcile bootstrap so the
    /// subsequent live subscription resumes strictly past the snapshot frontier
    /// instead of re-streaming the bootstrapped history (FR-1311).
    pub async fn advance_recv_cursor(
        &self,
        peer: NodeId,
        origin: NodeId,
        up_to_seq: i64,
    ) -> Result<(), StoreError> {
        self.call(|reply| StoreCmd::AdvanceRecvCursor {
            peer,
            origin,
            up_to_seq,
            reply,
        })
        .await
    }

    /// Read a daemon-owned scalar (e.g. join lifecycle).
    pub async fn get_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        let key = key.to_string();
        self.call(|reply| StoreCmd::GetMeta { key, reply }).await
    }

    /// Persist a daemon-owned scalar (durable before returning).
    pub async fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let key = key.to_string();
        let value = value.to_string();
        self.call(|reply| StoreCmd::SetMeta { key, value, reply })
            .await
    }
}

// ---------------------------------------------------------------------------
// Store thread
// ---------------------------------------------------------------------------

fn run_store(
    mut conn: Connection,
    node_id: NodeId,
    mut rx: mpsc::Receiver<StoreCmd>,
    latest_tx: watch::Sender<i64>,
) {
    while let Some(cmd) = rx.blocking_recv() {
        // A dropped reply receiver just means the caller went away.
        match cmd {
            StoreCmd::AppendLocal { change, reply } => {
                let res = append_local(&mut conn, &node_id, &change);
                if let Ok(Some(op)) = &res {
                    let _ = latest_tx.send(op.origin_seq);
                }
                let _ = reply.send(res);
            }
            StoreCmd::ApplyRemote {
                op,
                decision,
                reply,
            } => {
                let _ = reply.send(apply_remote(&mut conn, &op, decision));
            }
            StoreCmd::LoadFile { path, reply } => {
                let _ = reply.send(state::load_file(&conn, &path));
            }
            StoreCmd::HasApplied { op_id, reply } => {
                let _ = reply.send(has_applied(&conn, &op_id));
            }
            StoreCmd::OpsSince {
                origin,
                after_seq,
                limit,
                reply,
            } => {
                let _ = reply.send(ops_since(&conn, &origin, after_seq, limit));
            }
            StoreCmd::RecvCursor { peer, reply } => {
                let _ = reply.send(cursor_value(&conn, &peer, &peer, "recv_cursor"));
            }
            StoreCmd::AdvanceAck {
                peer,
                up_to_seq,
                reply,
            } => {
                let _ = reply.send(advance_ack(&conn, &peer, &node_id, up_to_seq));
            }
            StoreCmd::LastAcked { peer, reply } => {
                let _ = reply.send(cursor_value(&conn, &peer, &node_id, "last_acked_seq"));
            }
            StoreCmd::PutManifest { manifest, reply } => {
                let _ = reply.send(state::put_manifest(&conn, &manifest));
            }
            StoreCmd::ManifestFor {
                content_hash,
                reply,
            } => {
                let _ = reply.send(state::manifest_for(&conn, &content_hash));
            }
            StoreCmd::ReconcileUpsert { row, reply } => {
                let _ = reply.send(reconcile_upsert(&mut conn, &row));
            }
            StoreCmd::ResolveRows {
                path,
                remote,
                staged,
                reply,
            } => {
                let _ = reply.send(resolve_rows(&mut conn, &path, &remote, &staged));
            }
            StoreCmd::LoadRow { path, reply } => {
                let _ = reply.send(state::load_row(&conn, &path));
            }
            StoreCmd::SnapshotForJoin { reply } => {
                let _ = reply.send(snapshot_for_join(&conn));
            }
            StoreCmd::AdvanceRecvCursor {
                peer,
                origin,
                up_to_seq,
                reply,
            } => {
                let _ = reply.send(advance_recv_cursor(&conn, &peer, &origin, up_to_seq));
            }
            StoreCmd::GetMeta { key, reply } => {
                let _ = reply.send(get_meta(&conn, &key));
            }
            StoreCmd::SetMeta { key, value, reply } => {
                let _ = reply.send(set_meta(&conn, &key, &value));
            }
            StoreCmd::LiveFiles { reply } => {
                let _ = reply.send(state::live_files(&conn));
            }
            StoreCmd::AllFiles { reply } => {
                let _ = reply.send(state::all_files(&conn));
            }
            StoreCmd::PathForHash { hash, reply } => {
                let _ = reply.send(state::path_for_hash(&conn, &hash));
            }
            StoreCmd::OpCount { reply } => {
                let _ = reply.send(op_count(&conn));
            }
        }
    }
    // Channel closed: all handles dropped; the connection closes with us.
}

fn latest_origin_seq(conn: &Connection, origin: &NodeId) -> Result<i64, StoreError> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(origin_seq), 0) FROM oplog WHERE origin = ?1",
        [origin.as_slice()],
        |row| row.get(0),
    )?)
}

fn op_type_to_i64(t: OpType) -> i64 {
    match t {
        OpType::Write => 0,
        OpType::Delete => 1,
    }
}

fn op_type_from_i64(v: i64) -> Result<OpType, StoreError> {
    match v {
        0 => Ok(OpType::Write),
        1 => Ok(OpType::Delete),
        _ => Err(StoreError::Corrupt("oplog.op_type")),
    }
}

fn insert_op(conn: &Connection, op: &OpRecord) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO oplog
           (op_id, origin, origin_seq, op_type, path, mode, size, content_hash, vv)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            op.op_id.as_slice(),
            op.origin.as_slice(),
            op.origin_seq,
            op_type_to_i64(op.op_type),
            op.path,
            op.mode as i64,
            op.size as i64,
            op.content_hash.as_ref().map(|h| h.as_slice()),
            state::encode_vv(&op.vv)?,
        ],
    )?;
    Ok(())
}

/// Local mutation → op, atomically. See [`Store::append_local`].
fn append_local(
    conn: &mut Connection,
    node_id: &NodeId,
    change: &LocalChange,
) -> Result<Option<OpRecord>, StoreError> {
    let tx = conn.transaction()?;
    let local = state::load_file(&tx, &change.path)?;

    // Causal no-op filter (second line of loop defense, FR-901): an applied
    // remote write re-observed by the scanner, or an unchanged file, must not
    // become a new op.
    match change.op_type {
        OpType::Write => {
            if let Some(l) = &local {
                if !l.tombstone && l.content_hash == change.content_hash {
                    return Ok(None);
                }
            }
        }
        OpType::Delete => match &local {
            None => return Ok(None),
            Some(l) if l.tombstone => return Ok(None),
            Some(_) => {}
        },
    }

    let mut vv = local.map(|l| l.vv).unwrap_or_default();
    vv.increment(node_id); // FR-301: local write bumps our component

    let origin_seq = latest_origin_seq(&tx, node_id)? + 1;
    let op = OpRecord {
        op_id: op_id(node_id, origin_seq),
        origin: *node_id,
        origin_seq,
        op_type: change.op_type,
        path: change.path.clone(),
        mode: change.mode,
        size: change.size,
        content_hash: change.content_hash,
        vv: vv.clone(),
    };
    insert_op(&tx, &op)?;
    let tombstone = change.op_type == OpType::Delete;
    state::upsert_file(
        &tx,
        &change.path,
        change.content_hash.as_ref(),
        change.mode,
        change.size,
        &vv,
        tombstone,
    )?;
    // The op and the manifest describing its content are atomically durable
    // together (FR-402: we must be able to serve chunks for our own ops).
    if let Some(manifest) = &change.manifest {
        if Some(manifest.content_hash) != change.content_hash {
            return Err(StoreError::Corrupt("manifest/content_hash mismatch"));
        }
        state::put_manifest(&tx, manifest)?;
    }
    tx.commit()?; // durable before anything is pushed
    Ok(Some(op))
}

/// Remote op handling, all decisions, ONE transaction. See `Store::apply_remote`.
///
/// Crash contract: the caller has already made the *filesystem* change (stage→
/// fsync→rename) when decision is Apply. If we crash before this COMMIT, the
/// op is un-acked and will be redelivered; re-running the fs apply with the
/// same bytes and then this transaction is a true no-op end state (FR-802).
fn apply_remote(
    conn: &mut Connection,
    op: &OpRecord,
    decision: Decision,
) -> Result<Decision, StoreError> {
    let tx = conn.transaction()?;
    let mut effective = decision;

    // Idempotency inside the tx (no TOCTOU): a redelivered op only re-bumps
    // the cursor, never re-mutates files and never re-merges the VV.
    if !has_applied(&tx, &op.op_id)? {
        insert_op(&tx, op)?;
        if decision == Decision::Apply {
            let local = state::load_file(&tx, &op.path)?;
            // RE-VALIDATE under the committing transaction. The caller's
            // decision was computed before a multi-second chunk fetch; a
            // concurrent local write (or reconcile) to this path may have
            // landed since. Trusting the stale Apply would overwrite the
            // newer row AND merge the remote VV over it — making a clobber
            // look causally resolved instead of concurrent. A downgrade is
            // recorded like any skip; the caller repairs the disk.
            // (Never UPGRADE a non-Apply caller decision: its content was
            // never fetched, so there is nothing on disk to ratify.)
            effective = decide(local.as_ref(), &op.vv);
            if effective == Decision::Apply {
                let mut vv = local.map(|l| l.vv).unwrap_or_default();
                vv.merge(&op.vv);
                match op.op_type {
                    OpType::Write => state::upsert_file(
                        &tx,
                        &op.path,
                        op.content_hash.as_ref(),
                        op.mode,
                        op.size,
                        &vv,
                        false,
                    )?,
                    // Tombstone, never a hard delete (FR-204).
                    OpType::Delete => {
                        state::upsert_file(&tx, &op.path, None, op.mode, 0, &vv, true)?
                    }
                }
            }
        }
        // Decision::Ignore / ::Concurrent / ::Quarantined (incl. an Apply
        // downgraded above): the op is recorded (oplog + applied + cursor)
        // but files is untouched — the skip *decision* is what's durable,
        // so restart never re-fetches the op. Quarantined ops leave the
        // local VV behind the origin's, which is exactly what lets a later
        // superseding op apply normally.
        tx.execute(
            "INSERT OR IGNORE INTO applied (op_id) VALUES (?1)",
            [op.op_id.as_slice()],
        )?;
    }

    ensure_cursor_row(&tx, &op.origin, &op.origin)?;
    // The sender streams in ascending origin_seq, so max() tracks the
    // contiguous frontier of what we durably handled. Keyed (peer, origin) —
    // in the full mesh ops arrive from their origin (peer == origin).
    tx.execute(
        "UPDATE peer_cursors SET recv_cursor = MAX(recv_cursor, ?1)
         WHERE peer = ?2 AND origin = ?2",
        params![op.origin_seq, op.origin.as_slice()],
    )?;
    tx.commit()?; // THE durability point — the ack may only be sent after this
    Ok(effective)
}

fn has_applied(conn: &Connection, op_id: &[u8; 32]) -> Result<bool, StoreError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM applied WHERE op_id = ?1",
            [op_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn ops_since(
    conn: &Connection,
    origin: &NodeId,
    after_seq: i64,
    limit: u32,
) -> Result<Vec<OpRecord>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT op_id, origin, origin_seq, op_type, path, mode, size, content_hash, vv
         FROM oplog WHERE origin = ?1 AND origin_seq > ?2
         ORDER BY origin_seq ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![origin.as_slice(), after_seq, limit], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<Vec<u8>>>(7)?,
            row.get::<_, Vec<u8>>(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (op_id_b, origin_b, origin_seq, op_type, path, mode, size, hash, vv_blob) = row?;
        out.push(OpRecord {
            op_id: op_id_b
                .try_into()
                .map_err(|_| StoreError::Corrupt("oplog.op_id"))?,
            origin: origin_b
                .try_into()
                .map_err(|_| StoreError::Corrupt("oplog.origin"))?,
            origin_seq,
            op_type: op_type_from_i64(op_type)?,
            path,
            mode: mode as u32,
            size: size as u64,
            content_hash: hash
                .map(|h| {
                    h.try_into()
                        .map_err(|_| StoreError::Corrupt("oplog.content_hash"))
                })
                .transpose()?,
            vv: state::decode_vv(&vv_blob)?,
        });
    }
    Ok(out)
}

// Per-(peer, origin) cursor rows (relay seam; reconcile never touches these).
// recv_cursor lives at (peer, peer) in the M2 full mesh; a peer's acks of OUR
// ops live at (peer, our node id).

fn ensure_cursor_row(conn: &Connection, peer: &NodeId, origin: &NodeId) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_cursors (peer, origin) VALUES (?1, ?2)",
        params![peer.as_slice(), origin.as_slice()],
    )?;
    Ok(())
}

fn cursor_value(
    conn: &Connection,
    peer: &NodeId,
    origin: &NodeId,
    column: &str,
) -> Result<i64, StoreError> {
    // `column` is a compile-time constant from this module, never user input.
    let sql = format!("SELECT {column} FROM peer_cursors WHERE peer = ?1 AND origin = ?2");
    Ok(conn
        .query_row(&sql, params![peer.as_slice(), origin.as_slice()], |row| {
            row.get(0)
        })
        .optional()?
        .unwrap_or(0))
}

fn advance_ack(
    conn: &Connection,
    peer: &NodeId,
    our_id: &NodeId,
    up_to_seq: i64,
) -> Result<(), StoreError> {
    ensure_cursor_row(conn, peer, our_id)?;
    conn.execute(
        "UPDATE peer_cursors SET last_acked_seq = MAX(last_acked_seq, ?1)
         WHERE peer = ?2 AND origin = ?3",
        params![up_to_seq, peer.as_slice(), our_id.as_slice()],
    )?;
    Ok(())
}

/// State-plane apply for anti-entropy (see [`ReconciledRow`]). One tx:
/// RE-VALIDATE dominance against the current row (the session's decide ran
/// before a long content fetch — same stale-decision hazard as the op path),
/// then merge + upsert only if the remote still dominates. Returns the
/// effective decision so the caller can repair a disk clobber on downgrade.
/// Nothing else — structurally incapable of disturbing op cursors or
/// idempotency.
fn reconcile_upsert(conn: &mut Connection, row: &ReconciledRow) -> Result<Decision, StoreError> {
    let tx = conn.transaction()?;
    let local = state::load_file(&tx, &row.path)?;
    let effective = decide(local.as_ref(), &row.vv);
    if effective == Decision::Apply {
        let mut vv = local.map(|l| l.vv).unwrap_or_default();
        vv.merge(&row.vv);
        state::upsert_file(
            &tx,
            &row.path,
            row.content_hash.as_ref(),
            row.mode,
            row.size,
            &vv,
            row.tombstone,
        )?;
    }
    tx.commit()?;
    Ok(effective)
}

/// The path's op history as resolution candidates — every op ever recorded
/// for `path`, live-stream or local, in arrival order (the antichain scan
/// normalizes order away).
fn ops_as_candidates(conn: &Connection, path: &str) -> Result<Vec<Version>, StoreError> {
    let mut stmt = conn.prepare_cached(
        "SELECT op_type, mode, size, content_hash, vv FROM oplog WHERE path = ?1",
    )?;
    let rows = stmt.query_map([path], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (op_type, mode, size, hash, vv_blob) = row?;
        let tombstone = op_type_from_i64(op_type)? == OpType::Delete;
        out.push(Version {
            tombstone,
            content_hash: hash
                .map(|h| {
                    h.try_into()
                        .map_err(|_| StoreError::Corrupt("oplog.content_hash"))
                })
                .transpose()?,
            meta_hash: conflict::META_NONE,
            mode: mode as u32,
            size: size as u64,
            vv: state::decode_vv(&vv_blob)?,
        });
    }
    Ok(out)
}

/// Conflict resolution, ONE transaction (see [`Store::resolve_rows`]).
///
/// Candidates = the path's op history ∪ {the remote version} ∪ {the current
/// row, only when the ops do not fully explain its VV — e.g. after a join
/// bootstrap, where state arrived without history}. Deriving from the op SET
/// (not the row/op pair) is what makes resolution confluent: max over an
/// antichain is delivery-order-free, and a causally-superseded intermediate
/// is never maximal, so it can never win. When the row IS fully covered by
/// ops it must be excluded — its merged VV would otherwise dominate every op
/// and collapse the derivation back to the non-confluent pairwise contest.
///
/// The committing re-check, conflict flavor: the caller staged disk for a
/// plan derived BEFORE a multi-second loser fetch. The plan is re-derived
/// here from state under the committing transaction; only an exact match
/// commits. A concurrent local write during the fetch changes the derivation
/// (a new op at minimum) and comes back `Stale` with the fresh plan — nothing
/// committed, the caller restages and retries. Trusting the stale plan would
/// clobber the newer write exactly like the stale-Apply hazard `apply_remote`
/// guards against.
fn resolve_rows(
    conn: &mut Connection,
    path: &str,
    remote: &Version,
    staged: &[PlannedRow],
) -> Result<ResolveOutcome, StoreError> {
    let tx = conn.transaction()?;
    let local_row = state::load_row(&tx, path)?;
    let local_lf = local_row.as_ref().map(|r| LocalFile {
        vv: r.vv.clone(),
        tombstone: r.tombstone,
        content_hash: r.content_hash,
        mode: r.mode,
    });
    let decision = decide(local_lf.as_ref(), &remote.vv);
    if decision != Decision::Concurrent {
        return Ok(ResolveOutcome::NotConcurrent(decision));
    }
    // decide(None, _) is Apply, so a Concurrent decision proves the row exists.
    let Some(local_row) = local_row else {
        return Err(StoreError::Corrupt("concurrent decision without a row"));
    };
    let mut candidates = ops_as_candidates(&tx, path)?;
    candidates.push(remote.clone());
    let mut coverage = crate::vv::VersionVector::new();
    for c in &candidates {
        coverage.merge(&c.vv);
    }
    match coverage.compare(&local_row.vv) {
        // Ops (+ remote) fully explain the row: derive from history alone.
        crate::vv::Ord3::Dominates | crate::vv::Ord3::Equal => {}
        // The row embodies history we hold no ops for: it is a candidate.
        _ => candidates.push(Version::from_row(&local_row)),
    }
    let derived = conflict::plan_candidates(path, &candidates, &mut |p| {
        state::load_row(&tx, p).map(|row| row.as_ref().map(Version::from_row))
    })?;
    let Some(derived) = derived else {
        return Ok(ResolveOutcome::Unresolvable);
    };
    if derived != staged {
        return Ok(ResolveOutcome::Stale { plan: derived });
    }
    for row in &derived {
        state::upsert_file(
            &tx,
            &row.path,
            row.content_hash.as_ref(),
            row.mode,
            row.size,
            &row.vv,
            row.tombstone,
        )?;
    }
    tx.commit()?;
    Ok(ResolveOutcome::Resolved)
}

fn op_count(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM oplog", [], |row| row.get(0))?)
}

/// One store-thread turn: the full index plus the per-origin op frontier. No
/// transaction is needed for a consistent read — the store thread runs exactly
/// one command at a time, so no append can interleave between these two queries.
/// See [`JoinSnapshot`].
fn snapshot_for_join(conn: &Connection) -> Result<JoinSnapshot, StoreError> {
    let rows = state::all_files(conn)?;
    let mut stmt = conn.prepare("SELECT origin, MAX(origin_seq) FROM oplog GROUP BY origin")?;
    let mapped = stmt.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut frontier = Vec::new();
    for r in mapped {
        let (origin_b, max_seq) = r?;
        let origin: NodeId = origin_b
            .try_into()
            .map_err(|_| StoreError::Corrupt("oplog.origin"))?;
        frontier.push((origin, max_seq));
    }
    Ok(JoinSnapshot { rows, frontier })
}

/// Monotonic advance of recv_cursor at (peer, origin). Mirrors the cursor bump
/// inside `apply_remote`, but for the post-reconcile join handoff rather than a
/// live op.
fn advance_recv_cursor(
    conn: &Connection,
    peer: &NodeId,
    origin: &NodeId,
    up_to_seq: i64,
) -> Result<(), StoreError> {
    ensure_cursor_row(conn, peer, origin)?;
    conn.execute(
        "UPDATE peer_cursors SET recv_cursor = MAX(recv_cursor, ?1)
         WHERE peer = ?2 AND origin = ?3",
        params![up_to_seq, peer.as_slice(), origin.as_slice()],
    )?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vv::Ord3;

    const NODE_A: NodeId = [0xaa; 16];
    const NODE_B: NodeId = [0xbb; 16];

    fn mem_store(node: NodeId) -> Store {
        Store::open(Path::new(":memory:"), node).expect("open :memory: store")
    }

    fn write_change(path: &str, hash: [u8; 32]) -> LocalChange {
        LocalChange {
            path: path.into(),
            op_type: OpType::Write,
            mode: 0o644,
            size: 3,
            content_hash: Some(hash),
            manifest: None,
        }
    }

    fn delete_change(path: &str) -> LocalChange {
        LocalChange {
            path: path.into(),
            op_type: OpType::Delete,
            mode: 0o644,
            size: 0,
            content_hash: None,
            manifest: None,
        }
    }

    #[tokio::test]
    async fn append_assigns_gapfree_monotonic_origin_seq() {
        let store = mem_store(NODE_A);
        let op1 = store
            .append_local(write_change("x/a", [1; 32]))
            .await
            .unwrap()
            .unwrap();
        let op2 = store
            .append_local(write_change("x/b", [2; 32]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(op1.origin_seq, 1);
        assert_eq!(op2.origin_seq, 2);
        assert_eq!(op1.vv.get(&NODE_A), 1);
        assert_ne!(op1.op_id, op2.op_id);
    }

    #[tokio::test]
    async fn identical_content_is_a_causal_noop() {
        let store = mem_store(NODE_A);
        assert!(store
            .append_local(write_change("x/a", [1; 32]))
            .await
            .unwrap()
            .is_some());
        // Same content re-observed (scanner re-walk, double event): no op.
        assert!(store
            .append_local(write_change("x/a", [1; 32]))
            .await
            .unwrap()
            .is_none());
        // Changed content: new op, VV bumped.
        let op = store
            .append_local(write_change("x/a", [9; 32]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(op.vv.get(&NODE_A), 2);
    }

    #[tokio::test]
    async fn delete_of_unknown_or_tombstoned_path_is_noop() {
        let store = mem_store(NODE_A);
        assert!(store
            .append_local(delete_change("ghost"))
            .await
            .unwrap()
            .is_none());
        store
            .append_local(write_change("x/a", [1; 32]))
            .await
            .unwrap();
        assert!(store
            .append_local(delete_change("x/a"))
            .await
            .unwrap()
            .is_some());
        // Already tombstoned: scanner re-observing the absence is a no-op.
        assert!(store
            .append_local(delete_change("x/a"))
            .await
            .unwrap()
            .is_none());
        let local = store.load_file("x/a").await.unwrap().unwrap();
        assert!(local.tombstone); // row retained (FR-204)
    }

    #[tokio::test]
    async fn apply_remote_is_idempotent_no_vv_double_merge() {
        let store = mem_store(NODE_A);
        let remote = OpRecord {
            op_id: op_id(&NODE_B, 1),
            origin: NODE_B,
            origin_seq: 1,
            op_type: OpType::Write,
            path: "y/z".into(),
            mode: 0o600,
            size: 5,
            content_hash: Some([7; 32]),
            vv: [(NODE_B, 1u64)].into_iter().collect(),
        };
        store
            .apply_remote(remote.clone(), Decision::Apply)
            .await
            .unwrap();
        assert!(store.has_applied(remote.op_id).await.unwrap());
        let after_first = store.load_file("y/z").await.unwrap().unwrap();

        // Redelivery (crash-between-commit-and-ack scenario): true no-op.
        store
            .apply_remote(remote.clone(), Decision::Apply)
            .await
            .unwrap();
        let after_second = store.load_file("y/z").await.unwrap().unwrap();
        assert_eq!(after_first.vv.compare(&after_second.vv), Ord3::Equal);
        assert_eq!(after_first.content_hash, after_second.content_hash);
        assert_eq!(store.op_count().await.unwrap(), 1); // no duplicate row
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn ignored_and_concurrent_ops_still_advance_cursor() {
        let store = mem_store(NODE_A);
        // Local state is ahead.
        store
            .append_local(write_change("p", [1; 32]))
            .await
            .unwrap();
        let stale = OpRecord {
            op_id: op_id(&NODE_B, 1),
            origin: NODE_B,
            origin_seq: 1,
            op_type: OpType::Write,
            path: "p".into(),
            mode: 0o644,
            size: 1,
            content_hash: Some([2; 32]),
            vv: [(NODE_B, 1u64)].into_iter().collect(), // concurrent with ours
        };
        store
            .apply_remote(stale.clone(), Decision::Concurrent)
            .await
            .unwrap();
        // files untouched by the conflict...
        let local = store.load_file("p").await.unwrap().unwrap();
        assert_eq!(local.content_hash, Some([1; 32]));
        assert_eq!(local.vv.get(&NODE_B), 0); // no merge on skip
                                              // ...but the handling is durable: never re-fetched, cursor advanced.
        assert!(store.has_applied(stale.op_id).await.unwrap());
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn ops_since_filters_origin_and_orders() {
        let store = mem_store(NODE_A);
        for i in 0..3u8 {
            store
                .append_local(write_change(&format!("f{i}"), [i; 32]))
                .await
                .unwrap();
        }
        // Interleave a remote op; it must not appear in NODE_A's stream.
        let remote = OpRecord {
            op_id: op_id(&NODE_B, 9),
            origin: NODE_B,
            origin_seq: 9,
            op_type: OpType::Write,
            path: "other".into(),
            mode: 0o644,
            size: 1,
            content_hash: Some([9; 32]),
            vv: [(NODE_B, 1u64)].into_iter().collect(),
        };
        store.apply_remote(remote, Decision::Apply).await.unwrap();

        let ops = store.ops_since(NODE_A, 1, 10).await.unwrap();
        assert_eq!(
            ops.iter().map(|o| o.origin_seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(ops.iter().all(|o| o.origin == NODE_A));
        let limited = store.ops_since(NODE_A, 0, 2).await.unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[tokio::test]
    async fn cursors_persist_and_are_monotonic() {
        let store = mem_store(NODE_A);
        store.advance_ack(NODE_B, 5).await.unwrap();
        store.advance_ack(NODE_B, 3).await.unwrap(); // stale ack: no regress
        assert_eq!(store.last_acked(NODE_B).await.unwrap(), 5);
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn live_files_and_path_for_hash() {
        let store = mem_store(NODE_A);
        store
            .append_local(write_change("keep", [1; 32]))
            .await
            .unwrap();
        store
            .append_local(write_change("gone", [2; 32]))
            .await
            .unwrap();
        store.append_local(delete_change("gone")).await.unwrap();

        let live = store.live_files().await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].path, "keep");
        assert_eq!(
            store.path_for_hash([1; 32]).await.unwrap().as_deref(),
            Some("keep")
        );
        assert_eq!(store.path_for_hash([2; 32]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn watch_latest_tracks_appends() {
        let store = mem_store(NODE_A);
        let rx = store.watch_latest();
        assert_eq!(*rx.borrow(), 0);
        store
            .append_local(write_change("a", [1; 32]))
            .await
            .unwrap();
        store
            .append_local(write_change("b", [2; 32]))
            .await
            .unwrap();
        assert_eq!(*rx.borrow(), 2);
    }

    fn sample_manifest(content: [u8; 32]) -> Manifest {
        Manifest {
            content_hash: content,
            chunks: vec![
                crate::proto::ChunkEntry {
                    hash: [1; 32],
                    len: 100,
                },
                crate::proto::ChunkEntry {
                    hash: [2; 32],
                    len: 50,
                },
            ],
        }
    }

    #[tokio::test]
    async fn manifest_round_trips_and_is_idempotent() {
        let store = mem_store(NODE_A);
        let m = sample_manifest([9; 32]);
        store.put_manifest(m.clone()).await.unwrap();
        store.put_manifest(m.clone()).await.unwrap(); // immutable: no-op
        assert_eq!(store.manifest_for([9; 32]).await.unwrap(), Some(m));
        assert_eq!(store.manifest_for([8; 32]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn append_local_persists_manifest_atomically() {
        let store = mem_store(NODE_A);
        let m = sample_manifest([7; 32]);
        let mut change = write_change("x/file", [7; 32]);
        change.manifest = Some(m.clone());
        store.append_local(change).await.unwrap().unwrap();
        assert_eq!(store.manifest_for([7; 32]).await.unwrap(), Some(m));

        // A manifest that does not match the op's content hash is a caller
        // bug and must poison the whole tx, not half-commit.
        let mut bad = write_change("x/other", [1; 32]);
        bad.manifest = Some(sample_manifest([2; 32]));
        assert!(store.append_local(bad).await.is_err());
        assert!(store.load_file("x/other").await.unwrap().is_none()); // rolled back
    }

    #[tokio::test]
    async fn reconcile_upsert_touches_files_only() {
        let store = mem_store(NODE_A);
        let row = ReconciledRow {
            path: "healed/f".into(),
            content_hash: Some([3; 32]),
            mode: 0o644,
            size: 10,
            vv: [(NODE_B, 2u64)].into_iter().collect(),
            tombstone: false,
        };
        assert_eq!(
            store.reconcile_upsert(row.clone()).await.unwrap(),
            Decision::Apply
        );
        // Re-applying the identical row is Equal under the in-tx re-check:
        // recorded as Ignore, state untouched.
        assert_eq!(
            store.reconcile_upsert(row.clone()).await.unwrap(),
            Decision::Ignore
        );

        let local = store.load_file("healed/f").await.unwrap().unwrap();
        assert_eq!(local.content_hash, Some([3; 32]));
        assert_eq!(local.vv.get(&NODE_B), 2);
        // The state plane NEVER disturbs the op machinery:
        assert_eq!(store.op_count().await.unwrap(), 0); // no oplog row
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 0); // no cursor

        // A CONCURRENT row (each side ahead on a different component) must
        // NOT clobber or merge — the committing re-check downgrades it.
        // (This exact upsert used to merge unconditionally: the masking bug.)
        assert_eq!(
            store
                .reconcile_upsert(ReconciledRow {
                    vv: [(NODE_A, 1u64)].into_iter().collect(),
                    tombstone: true,
                    content_hash: None,
                    ..row.clone()
                })
                .await
                .unwrap(),
            Decision::Concurrent
        );
        let local = store.load_file("healed/f").await.unwrap().unwrap();
        assert!(!local.tombstone, "concurrent tombstone clobbered the row");
        assert_eq!(local.vv.get(&NODE_A), 0); // NOT merged — no masking
        assert_eq!(local.content_hash, Some([3; 32]));

        // A genuinely DOMINATING tombstone still applies, with the merge.
        assert_eq!(
            store
                .reconcile_upsert(ReconciledRow {
                    vv: [(NODE_A, 1u64), (NODE_B, 2u64)].into_iter().collect(),
                    tombstone: true,
                    content_hash: None,
                    ..row
                })
                .await
                .unwrap(),
            Decision::Apply
        );
        let local = store.load_file("healed/f").await.unwrap().unwrap();
        assert!(local.tombstone);
        assert_eq!(local.vv.get(&NODE_A), 1);
        assert_eq!(local.vv.get(&NODE_B), 2); // merged, not lost
    }

    /// THE stale-decision regression (receive path): decide() said Apply,
    /// then a local write to the same path landed during the (long) fetch,
    /// then the commit ran. The committing re-check must downgrade — no
    /// disk-state ratification, no VV masking.
    #[tokio::test]
    async fn apply_remote_downgrades_stale_apply_decision() {
        let store = mem_store(NODE_A);

        // T0: receive path reads local state (absent) and decides Apply.
        let remote = OpRecord {
            op_id: op_id(&NODE_B, 1),
            origin: NODE_B,
            origin_seq: 1,
            op_type: OpType::Write,
            path: "race/p".into(),
            mode: 0o644,
            size: 8,
            content_hash: Some([0xbb; 32]),
            vv: [(NODE_B, 1u64)].into_iter().collect(),
        };
        let stale_local = store.load_file("race/p").await.unwrap();
        let decision = crate::decide::decide(stale_local.as_ref(), &remote.vv);
        assert_eq!(decision, Decision::Apply);

        // T1 (during the "fetch"): a concurrent LOCAL write lands.
        store
            .append_local(write_change("race/p", [0xaa; 32]))
            .await
            .unwrap()
            .unwrap();

        // T2: the commit re-validates and downgrades.
        let effective = store.apply_remote(remote.clone(), decision).await.unwrap();
        assert_eq!(effective, Decision::Concurrent);

        // No clobber, no masking: the row keeps the LOCAL content and the
        // remote VV component was NOT merged.
        let local = store.load_file("race/p").await.unwrap().unwrap();
        assert_eq!(local.content_hash, Some([0xaa; 32]));
        assert_eq!(local.vv.get(&NODE_A), 1);
        assert_eq!(local.vv.get(&NODE_B), 0, "remote VV merged: masking");

        // The op is still durably handled: recorded, cursor advanced,
        // redelivery a pure no-op.
        assert!(store.has_applied(remote.op_id).await.unwrap());
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);
        let again = store.apply_remote(remote, Decision::Apply).await.unwrap();
        assert_eq!(again, Decision::Apply); // already-applied: no mutation either way
        let local = store.load_file("race/p").await.unwrap().unwrap();
        assert_eq!(local.content_hash, Some([0xaa; 32]));
        assert_eq!(local.vv.get(&NODE_B), 0);
    }

    #[tokio::test]
    async fn m1_cursor_layout_backfills_into_peer_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("old.db");
        {
            // Forge an M1-era database: only the old `peers` single-cursor row.
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE peers (
                   node_id BLOB PRIMARY KEY,
                   last_sent_seq INTEGER NOT NULL DEFAULT 0,
                   last_acked_seq INTEGER NOT NULL DEFAULT 0,
                   recv_cursor INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO peers (node_id, last_acked_seq, recv_cursor) VALUES (?1, 7, 9)",
                [NODE_B.as_slice()],
            )
            .unwrap();
        }
        let store = Store::open(&db, NODE_A).unwrap();
        // recv cursor of B's ops migrated to (B, B); B's acks of OUR ops to (B, A).
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 9);
        assert_eq!(store.last_acked(NODE_B).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn snapshot_for_join_is_atomic_and_next_op_exceeds_frontier() {
        let store = mem_store(NODE_A);
        // Two local ops and one remote op from B.
        store
            .append_local(write_change("a", [1; 32]))
            .await
            .unwrap();
        store
            .append_local(write_change("b", [2; 32]))
            .await
            .unwrap();
        let remote = OpRecord {
            op_id: op_id(&NODE_B, 5),
            origin: NODE_B,
            origin_seq: 5,
            op_type: OpType::Write,
            path: "c".into(),
            mode: 0o644,
            size: 1,
            content_hash: Some([3; 32]),
            vv: [(NODE_B, 1u64)].into_iter().collect(),
        };
        store.apply_remote(remote, Decision::Apply).await.unwrap();

        let snap = store.snapshot_for_join().await.unwrap();
        // Frontier is the per-origin max; rows cover exactly what it bounds.
        let mut frontier = snap.frontier.clone();
        frontier.sort();
        assert_eq!(frontier, vec![(NODE_A, 2), (NODE_B, 5)]);
        assert_eq!(snap.rows.len(), 3);

        // The whole point: any op appended AFTER the snapshot is strictly above
        // the frontier it advertised — so it rides the live stream once, never
        // double-applied against the bootstrap (FR-1311).
        let next = store
            .append_local(write_change("d", [4; 32]))
            .await
            .unwrap()
            .unwrap();
        let a_frontier = snap.frontier.iter().find(|(o, _)| *o == NODE_A).unwrap().1;
        assert!(
            next.origin_seq > a_frontier,
            "next op did not exceed frontier"
        );
    }

    #[tokio::test]
    async fn advance_recv_cursor_is_monotonic() {
        let store = mem_store(NODE_A);
        store.advance_recv_cursor(NODE_B, NODE_B, 7).await.unwrap();
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 7);
        // A stale bootstrap frontier must never rewind a further-along cursor.
        store.advance_recv_cursor(NODE_B, NODE_B, 3).await.unwrap();
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 7);
        store.advance_recv_cursor(NODE_B, NODE_B, 9).await.unwrap();
        assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 9);
    }

    #[tokio::test]
    async fn meta_round_trips_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("m.db");
        {
            let store = Store::open(&db, NODE_A).unwrap();
            assert_eq!(store.get_meta("k").await.unwrap(), None);
            store.set_meta("k", "active").await.unwrap();
            store.set_meta("k", "syncing").await.unwrap(); // upsert
            assert_eq!(
                store.get_meta("k").await.unwrap().as_deref(),
                Some("syncing")
            );
        }
        let store = Store::open(&db, NODE_A).unwrap();
        assert_eq!(
            store.get_meta("k").await.unwrap().as_deref(),
            Some("syncing")
        );
    }

    #[tokio::test]
    async fn durable_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.db");
        {
            let store = Store::open(&db, NODE_A).unwrap();
            store
                .append_local(write_change("x", [1; 32]))
                .await
                .unwrap();
            store.advance_ack(NODE_B, 1).await.unwrap();
        } // handles dropped -> store thread exits, connection closes
        let store = Store::open(&db, NODE_A).unwrap();
        let ops = store.ops_since(NODE_A, 0, 10).await.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(store.last_acked(NODE_B).await.unwrap(), 1);
        assert_eq!(*store.watch_latest().borrow(), 1); // resumes the counter
                                                       // Next append continues the sequence, no reuse.
        let op = store
            .append_local(write_change("y", [2; 32]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(op.origin_seq, 2);
    }
}
