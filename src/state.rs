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

use crate::decide::LocalFile;
use crate::oplog::StoreError;
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
            "SELECT content_hash, vv, tombstone FROM files WHERE path = ?1",
            [path],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(hash, vv_blob, tombstone)| {
        Ok(LocalFile {
            vv: decode_vv(&vv_blob)?,
            tombstone,
            content_hash: hash.map(|h| blob32(h, "files.content_hash")).transpose()?,
        })
    })
    .transpose()
}

/// Insert or replace the materialized row for `path`. A tombstone is just an
/// upsert with `tombstone=1` and no content hash — the row survives.
pub(crate) fn upsert_file(
    conn: &Connection,
    path: &str,
    content_hash: Option<&[u8; 32]>,
    mode: u32,
    size: u64,
    vv: &VersionVector,
    tombstone: bool,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO files (path, content_hash, mode, size, vv, tombstone)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(path) DO UPDATE
         SET content_hash = ?2, mode = ?3, size = ?4, vv = ?5, tombstone = ?6",
        params![
            path,
            content_hash.map(|h| h.as_slice()),
            mode as i64,
            size as i64,
            encode_vv(vv)?,
            tombstone,
        ],
    )?;
    Ok(())
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
