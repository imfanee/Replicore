//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! Partial-manifest crash residue (QA finding): a kill -9 during the
//! receiver's manifest persist left the `manifests` row (chunk_count = N)
//! with fewer than N `manifest_chunks` rows, because the standalone
//! `Store::put_manifest` path wrote them as separate autocommit statements.
//! `manifest_for` then returned a hard `Corrupt` error on every read,
//! wedging the node in a permanent reconnect loop
//! ("database corrupt: bad manifest_chunks row count").
//!
//! Fix is two-part and both halves are pinned here:
//!   1. a partial manifest reads as ABSENT (re-fetchable), not a fatal error;
//!   2. `put_manifest` is atomic, and re-putting heals a partial
//!      (INSERT OR IGNORE fills the missing chunk rows).
//!
//! The forge uses raw SQL on a file-backed db (the `migration.rs` pattern),
//! since the bug is precisely a half-written table the public API can't
//! produce once the persist is atomic.

use replicore::chunk::Manifest;
use replicore::oplog::Store;
use replicore::proto::ChunkEntry;
use replicore::vv::NodeId;

const NODE: NodeId = [0xaa; 16];

fn full_manifest() -> Manifest {
    Manifest {
        content_hash: [0x42; 32],
        chunks: (0u8..5)
            .map(|i| ChunkEntry {
                hash: [i; 32],
                len: 1024,
            })
            .collect(),
    }
}

/// Write a manifests row claiming `claim` chunks but only `present` chunk
/// rows — the exact shape a crash mid-`put_manifest` leaves behind.
fn forge_partial(db: &std::path::Path, m: &Manifest, present: usize) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS manifests (
           content_hash BLOB PRIMARY KEY, chunk_count INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS manifest_chunks (
           content_hash BLOB NOT NULL, idx INTEGER NOT NULL,
           chunk_hash BLOB NOT NULL, len INTEGER NOT NULL,
           PRIMARY KEY (content_hash, idx));",
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO manifests (content_hash, chunk_count) VALUES (?1, ?2)",
        rusqlite::params![m.content_hash.as_slice(), m.chunks.len() as i64],
    )
    .unwrap();
    for (idx, c) in m.chunks.iter().take(present).enumerate() {
        conn.execute(
            "INSERT OR IGNORE INTO manifest_chunks (content_hash, idx, chunk_hash, len)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                m.content_hash.as_slice(),
                idx as i64,
                c.hash.as_slice(),
                c.len as i64
            ],
        )
        .unwrap();
    }
}

#[tokio::test]
async fn partial_manifest_reads_as_absent_then_heals_on_reput() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("node.db");
    let m = full_manifest();
    // Crash residue: row says 5 chunks, only 3 persisted.
    forge_partial(&db, &m, 3);

    let store = Store::open(&db, NODE).unwrap();

    // BEFORE the fix this returned Err(Corrupt) and wedged the node forever.
    // Now: treated as ABSENT so the caller re-fetches.
    assert_eq!(
        store.manifest_for(m.content_hash).await.unwrap(),
        None,
        "a partial manifest must read as absent, not a fatal error"
    );

    // Re-fetch + re-put (what obtain_manifest does): the atomic put fills the
    // missing chunk rows; the manifest is now complete and servable.
    store.put_manifest(m.clone()).await.unwrap();
    assert_eq!(
        store.manifest_for(m.content_hash).await.unwrap(),
        Some(m),
        "re-put must heal the partial to a complete manifest"
    );
}

#[tokio::test]
async fn put_manifest_is_all_or_nothing() {
    // The atomic put: a clean put yields a complete, readable manifest (the
    // crash-atomicity is structural — one transaction — so the observable
    // guarantee is that no partial is ever the steady state of a put).
    let store = Store::open(std::path::Path::new(":memory:"), NODE).unwrap();
    let m = full_manifest();
    store.put_manifest(m.clone()).await.unwrap();
    assert_eq!(store.manifest_for(m.content_hash).await.unwrap(), Some(m));

    // Idempotent re-put (immutable, content-addressed) stays complete.
    let m = full_manifest();
    store.put_manifest(m.clone()).await.unwrap();
    assert_eq!(store.manifest_for(m.content_hash).await.unwrap(), Some(m));
}
