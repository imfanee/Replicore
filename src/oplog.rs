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

use crate::decide::{Decision, LocalFile};
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
}

enum StoreCmd {
    AppendLocal {
        change: LocalChange,
        reply: oneshot::Sender<Result<Option<OpRecord>, StoreError>>,
    },
    ApplyRemote {
        op: Box<OpRecord>,
        decision: Decision,
        reply: oneshot::Sender<Result<(), StoreError>>,
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
             );",
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

    /// Durably record the handling of a remote op (any decision) and, when
    /// `Decision::Apply`, materialize it. One transaction; idempotent on
    /// redelivery. MUST be awaited before acking the op (FR-801).
    pub async fn apply_remote(&self, op: OpRecord, decision: Decision) -> Result<(), StoreError> {
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
                let _ = reply.send(peer_cursor(&conn, &peer, "recv_cursor"));
            }
            StoreCmd::AdvanceAck {
                peer,
                up_to_seq,
                reply,
            } => {
                let _ = reply.send(advance_ack(&conn, &peer, up_to_seq));
            }
            StoreCmd::LastAcked { peer, reply } => {
                let _ = reply.send(peer_cursor(&conn, &peer, "last_acked_seq"));
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
) -> Result<(), StoreError> {
    let tx = conn.transaction()?;

    // Idempotency inside the tx (no TOCTOU): a redelivered op only re-bumps
    // the cursor, never re-mutates files and never re-merges the VV.
    if !has_applied(&tx, &op.op_id)? {
        insert_op(&tx, op)?;
        if decision == Decision::Apply {
            let local = state::load_file(&tx, &op.path)?;
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
                OpType::Delete => state::upsert_file(&tx, &op.path, None, op.mode, 0, &vv, true)?,
            }
        }
        // Decision::Ignore / ::Concurrent / ::Quarantined: the op is recorded
        // (oplog + applied + cursor) but files is untouched — the skip
        // *decision* is what's durable, so restart never re-fetches the op.
        // Quarantined ops leave the local VV behind the origin's, which is
        // exactly what lets a later superseding op apply normally.
        tx.execute(
            "INSERT OR IGNORE INTO applied (op_id) VALUES (?1)",
            [op.op_id.as_slice()],
        )?;
    }

    ensure_peer(&tx, &op.origin)?;
    // The sender streams in ascending origin_seq, so max() tracks the
    // contiguous frontier of what we durably handled.
    tx.execute(
        "UPDATE peers SET recv_cursor = MAX(recv_cursor, ?1) WHERE node_id = ?2",
        params![op.origin_seq, op.origin.as_slice()],
    )?;
    tx.commit()?; // THE durability point — the ack may only be sent after this
    Ok(())
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

fn ensure_peer(conn: &Connection, peer: &NodeId) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO peers (node_id) VALUES (?1)",
        [peer.as_slice()],
    )?;
    Ok(())
}

fn peer_cursor(conn: &Connection, peer: &NodeId, column: &str) -> Result<i64, StoreError> {
    // `column` is a compile-time constant from this module, never user input.
    let sql = format!("SELECT {column} FROM peers WHERE node_id = ?1");
    Ok(conn
        .query_row(&sql, [peer.as_slice()], |row| row.get(0))
        .optional()?
        .unwrap_or(0))
}

fn advance_ack(conn: &Connection, peer: &NodeId, up_to_seq: i64) -> Result<(), StoreError> {
    ensure_peer(conn, peer)?;
    conn.execute(
        "UPDATE peers
         SET last_acked_seq = MAX(last_acked_seq, ?1),
             last_sent_seq  = MAX(last_sent_seq,  ?1)
         WHERE node_id = ?2",
        params![up_to_seq, peer.as_slice()],
    )?;
    Ok(())
}

fn op_count(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM oplog", [], |row| row.get(0))?)
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
        }
    }

    fn delete_change(path: &str) -> LocalChange {
        LocalChange {
            path: path.into(),
            op_type: OpType::Delete,
            mode: 0o644,
            size: 0,
            content_hash: None,
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
