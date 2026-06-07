//! state.rs — materialized current-state index per path (FR-203/204).
//!
//! Row-level helpers over the `files` table. These run **only inside the store
//! thread** (`oplog.rs`), within its transactions — there is no public async
//! surface here, which keeps every connection access single-threaded and every
//! mutation inside an explicit transaction.
//!
//! Tombstones: a deleted path keeps its row (`tombstone=1`) with the version
//! vector that includes the delete — rows are never hard-deleted in M1.
//! GC is M2 (after all peers ack + safety window). // SEAM(M2): tombstone GC

use rusqlite::{params, Connection, OptionalExtension};

use crate::chunk::Manifest;
use crate::decide::LocalFile;
use crate::metadata::Meta;
use crate::oplog::StoreError;
use crate::proto::ChunkEntry;
use crate::vv::VersionVector;

/// A live (non-tombstoned) row, as the scanner sees the index.
#[derive(Clone, Debug)]
pub struct LiveFile {
    pub path: String,
    pub content_hash: Option<[u8; 32]>,
    pub mode: u32,
    pub size: u64,
}

pub(crate) fn encode_vv(vv: &VersionVector) -> Result<Vec<u8>, StoreError> {
    bincode::serialize(vv).map_err(StoreError::VvCodec)
}

pub(crate) fn decode_vv(blob: &[u8]) -> Result<VersionVector, StoreError> {
    bincode::deserialize(blob).map_err(StoreError::VvCodec)
}

fn blob32(blob: Vec<u8>, what: &'static str) -> Result<[u8; 32], StoreError> {
    blob.try_into().map_err(|_| StoreError::Corrupt(what))
}

/// Load the decision-relevant state for one path (`None` = never seen).
pub(crate) fn load_file(conn: &Connection, path: &str) -> Result<Option<LocalFile>, StoreError> {
    let row = conn
        .query_row(
            "SELECT content_hash, vv, tombstone, mode FROM files WHERE path = ?1",
            [path],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(hash, vv_blob, tombstone, mode)| {
        Ok(LocalFile {
            vv: decode_vv(&vv_blob)?,
            tombstone,
            content_hash: hash.map(|h| blob32(h, "files.content_hash")).transpose()?,
            mode: mode as u32,
        })
    })
    .transpose()
}

/// Insert or replace the materialized row for `path`. A tombstone is just an
/// upsert with `tombstone=1` and no content hash — the row survives.
#[allow(clippy::too_many_arguments)]
pub(crate) fn upsert_file(
    conn: &Connection,
    path: &str,
    content_hash: Option<&[u8; 32]>,
    mode: u32,
    size: u64,
    vv: &VersionVector,
    tombstone: bool,
    uuid: Option<&[u8; 16]>,
    meta: Option<&Meta>,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO files (path, content_hash, mode, size, vv, tombstone, uuid, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(path) DO UPDATE
         SET content_hash = ?2, mode = ?3, size = ?4, vv = ?5, tombstone = ?6, uuid = ?7,
             meta = ?8",
        params![
            path,
            content_hash.map(|h| h.as_slice()),
            mode as i64,
            size as i64,
            encode_vv(vv)?,
            tombstone,
            uuid.map(|u| u.as_slice()),
            encode_meta(meta)?,
        ],
    )?;
    Ok(())
}

/// Canonical meta blob (bincode of the capture-sorted struct); NULL for none.
pub(crate) fn encode_meta(meta: Option<&Meta>) -> Result<Option<Vec<u8>>, StoreError> {
    meta.map(|m| bincode::serialize(m).map_err(StoreError::VvCodec))
        .transpose()
}

pub(crate) fn decode_meta(blob: Option<Vec<u8>>) -> Result<Option<Meta>, StoreError> {
    blob.map(|b| bincode::deserialize(&b).map_err(StoreError::VvCodec))
        .transpose()
}

/// Every live path with its expected content — the scanner's diff basis.
pub(crate) fn live_files(conn: &Connection) -> Result<Vec<LiveFile>, StoreError> {
    let mut stmt =
        conn.prepare("SELECT path, content_hash, mode, size FROM files WHERE tombstone = 0")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (path, hash, mode, size) = row?;
        out.push(LiveFile {
            path,
            content_hash: hash.map(|h| blob32(h, "files.content_hash")).transpose()?,
            mode: mode as u32,
            size: size as u64,
        });
    }
    Ok(out)
}

/// One row of the full index, tombstones included — the reconciliation /
/// snapshot view (Merkle leaves are hashed from these).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileRow {
    pub path: String,
    pub content_hash: Option<[u8; 32]>,
    /// Carried for state upserts; NOT part of the Merkle leaf hash
    /// (metadata fidelity is M3 — reconcile must not flap on it).
    pub mode: u32,
    pub size: u64,
    pub tombstone: bool,
    pub vv: VersionVector,
    /// Stable per-file identity (FR-205); `None` only transiently before the
    /// open-time migration mints deterministic uuids for pre-v4 rows.
    pub uuid: Option<[u8; 16]>,
    /// Full metadata snapshot (FR-106); `None` for tombstones and pre-v4
    /// rows awaiting their first re-capture.
    pub meta: Option<Meta>,
}

fn blob16(blob: Vec<u8>, what: &'static str) -> Result<[u8; 16], StoreError> {
    blob.try_into().map_err(|_| StoreError::Corrupt(what))
}

/// Load the FULL row for one path (`None` = never seen) — the conflict
/// resolution view: unlike [`load_file`] it carries `size` and is shaped for
/// `conflict::Version`. Read-only.
pub(crate) fn load_row(conn: &Connection, path: &str) -> Result<Option<FileRow>, StoreError> {
    let row = conn
        .query_row(
            "SELECT content_hash, mode, size, tombstone, vv, uuid, meta
             FROM files WHERE path = ?1",
            [path],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(|(hash, mode, size, tombstone, vv_blob, uuid, meta)| {
        Ok(FileRow {
            path: path.to_string(),
            content_hash: hash.map(|h| blob32(h, "files.content_hash")).transpose()?,
            mode: mode as u32,
            size: size as u64,
            tombstone,
            vv: decode_vv(&vv_blob)?,
            uuid: uuid.map(|u| blob16(u, "files.uuid")).transpose()?,
            meta: decode_meta(meta)?,
        })
    })
    .transpose()
}

/// One-time v4 migration: assign `mint(path)` to every row whose uuid is
/// NULL. `mint` must be a pure function of the path (every node migrates
/// independently and the results must agree). Idempotent.
pub(crate) fn backfill_uuids(
    conn: &Connection,
    mint: fn(&str) -> [u8; 16],
) -> Result<(), StoreError> {
    let paths: Vec<String> = {
        let mut stmt = conn.prepare("SELECT path FROM files WHERE uuid IS NULL")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for path in &paths {
        conn.execute(
            "UPDATE files SET uuid = ?1 WHERE path = ?2",
            params![mint(path).as_slice(), path],
        )?;
    }
    Ok(())
}

/// Every row, live and tombstoned, ordered by path.
pub(crate) fn all_files(conn: &Connection) -> Result<Vec<FileRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT path, content_hash, mode, size, tombstone, vv, uuid, meta
         FROM files ORDER BY path",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, bool>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Option<Vec<u8>>>(6)?,
            row.get::<_, Option<Vec<u8>>>(7)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (path, hash, mode, size, tombstone, vv_blob, uuid, meta) = row?;
        out.push(FileRow {
            path,
            content_hash: hash.map(|h| blob32(h, "files.content_hash")).transpose()?,
            mode: mode as u32,
            size: size as u64,
            tombstone,
            vv: decode_vv(&vv_blob)?,
            uuid: uuid.map(|u| blob16(u, "files.uuid")).transpose()?,
            meta: decode_meta(meta)?,
        });
    }
    Ok(out)
}

/// Persist a manifest's structure (idempotent — manifests are immutable,
/// keyed by the whole-file hash they reconstruct).
pub(crate) fn put_manifest(conn: &Connection, m: &Manifest) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO manifests (content_hash, chunk_count) VALUES (?1, ?2)",
        params![m.content_hash.as_slice(), m.chunks.len() as i64],
    )?;
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO manifest_chunks (content_hash, idx, chunk_hash, len)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for (idx, c) in m.chunks.iter().enumerate() {
        stmt.execute(params![
            m.content_hash.as_slice(),
            idx as i64,
            c.hash.as_slice(),
            c.len as i64,
        ])?;
    }
    Ok(())
}

/// Load a manifest's structure; verifies the row count is complete.
pub(crate) fn manifest_for(
    conn: &Connection,
    content_hash: &[u8; 32],
) -> Result<Option<Manifest>, StoreError> {
    let count: Option<i64> = conn
        .query_row(
            "SELECT chunk_count FROM manifests WHERE content_hash = ?1",
            [content_hash.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(count) = count else {
        return Ok(None);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT chunk_hash, len FROM manifest_chunks WHERE content_hash = ?1 ORDER BY idx",
    )?;
    let rows = stmt.query_map([content_hash.as_slice()], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut chunks = Vec::with_capacity(count as usize);
    for row in rows {
        let (hash, len) = row?;
        chunks.push(ChunkEntry {
            hash: blob32(hash, "manifest_chunks.chunk_hash")?,
            len: len as u32,
        });
    }
    if chunks.len() as i64 != count {
        // A PARTIAL manifest — the `manifests` row says `count` but fewer
        // chunk rows are present. This is the residue of a crash mid-persist
        // (pre-fix `put_manifest` was non-atomic). Treat it as ABSENT, not a
        // hard corruption: the caller re-fetches the (immutable,
        // content-addressed) manifest from a peer and the now-atomic
        // re-`put_manifest` fills the missing rows (INSERT OR IGNORE),
        // self-healing the partial instead of wedging the node forever.
        tracing::warn!(
            content = %hex::encode(&content_hash[..4]),
            have = chunks.len(),
            want = count,
            "partial manifest (crash residue); treating as absent to re-fetch"
        );
        return Ok(None);
    }
    Ok(Some(Manifest {
        content_hash: *content_hash,
        chunks,
    }))
}

/// Resolve a content hash to some live path holding it (serves peer fetches,
/// FR-401: transfer is content-addressed).
pub(crate) fn path_for_hash(
    conn: &Connection,
    hash: &[u8; 32],
) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT path FROM files WHERE content_hash = ?1 AND tombstone = 0 LIMIT 1",
            [hash.as_slice()],
            |row| row.get(0),
        )
        .optional()?)
}
