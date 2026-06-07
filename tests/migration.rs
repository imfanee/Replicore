//! v3 → v4 store migration (FR-205): the uuid/path_old columns are added to
//! pre-existing databases at open, and identities minted for old rows are a
//! pure function of the PATH — two nodes migrating independently MUST mint
//! identical uuids, or identity (and the leaf hash, once uuid joins it in
//! the metadata phase) diverges mesh-wide forever.
//!
//! The legacy database is forged with raw SQL here, OUTSIDE src/ — the
//! write-path grep-gate forbids files-table SQL anywhere but state.rs.

use replicore::oplog::{migration_uuid, Store};
use replicore::vv::{NodeId, VersionVector};

const NODE_A: NodeId = [0xaa; 16];
const NODE_B: NodeId = [0xbb; 16];

fn forge_v3_db(db: &std::path::Path, path: &str) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "CREATE TABLE oplog (
           seq INTEGER PRIMARY KEY, op_id BLOB UNIQUE NOT NULL,
           origin BLOB NOT NULL, origin_seq INTEGER NOT NULL,
           op_type INTEGER NOT NULL, path TEXT NOT NULL,
           mode INTEGER NOT NULL, size INTEGER NOT NULL,
           content_hash BLOB, vv BLOB NOT NULL
         );
         CREATE TABLE files (
           path TEXT PRIMARY KEY, content_hash BLOB,
           mode INTEGER NOT NULL, size INTEGER NOT NULL,
           vv BLOB NOT NULL, tombstone INTEGER NOT NULL DEFAULT 0
         );",
    )
    .unwrap();
    let vv: VersionVector = [(NODE_B, 1u64)].into_iter().collect();
    conn.execute(
        "INSERT INTO files (path, content_hash, mode, size, vv, tombstone)
         VALUES (?1, ?2, 420, 3, ?3, 0)",
        rusqlite::params![path, [7u8; 32].as_slice(), bincode::serialize(&vv).unwrap(),],
    )
    .unwrap();
}

#[tokio::test]
async fn v3_layout_migrates_columns_and_mints_deterministic_uuids() {
    let dir = tempfile::tempdir().unwrap();
    let (db_a, db_b) = (dir.path().join("a.db"), dir.path().join("b.db"));
    forge_v3_db(&db_a, "pre/v3.bin");
    forge_v3_db(&db_b, "pre/v3.bin");

    // Both nodes migrate independently...
    let store_a = Store::open(&db_a, NODE_A).unwrap();
    let store_b = Store::open(&db_b, NODE_B).unwrap();
    let row_a = store_a.load_row("pre/v3.bin").await.unwrap().unwrap();
    let row_b = store_b.load_row("pre/v3.bin").await.unwrap().unwrap();
    // ...and their minted identities AGREE (pure function of the path) —
    // anything node-local in the mint would diverge identity mesh-wide.
    assert_eq!(row_a.uuid, row_b.uuid);
    assert_eq!(row_a.uuid, Some(migration_uuid("pre/v3.bin")));
    // Pre-migration data survives untouched.
    assert_eq!(row_a.content_hash, Some([7u8; 32]));
    assert_eq!(row_a.vv.get(&NODE_B), 1);
    // Re-open: idempotent (no re-mint, no error).
    drop(store_a);
    let store_a = Store::open(&db_a, NODE_A).unwrap();
    let again = store_a.load_row("pre/v3.bin").await.unwrap().unwrap();
    assert_eq!(again.uuid, row_a.uuid);
}
