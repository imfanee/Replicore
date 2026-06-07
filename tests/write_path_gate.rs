//! Grep-gate for the M3 lead invariant (FR-303 / reviewer checklist):
//! conflict resolution introduced NO new write path to the `files` index.
//! Every mutation goes through the store thread's committing transactions —
//! `append_local`, `apply_remote`, `reconcile_upsert`, `resolve_rows` — all
//! in `oplog.rs`, all calling the single `state::upsert_file` helper.
//!
//! Like `intent_never_written.rs`, this is enforced as a source scan in CI,
//! not prose: a new caller of `upsert_file`, or raw SQL touching `files`
//! outside `state.rs`, fails the build gate.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn file_name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

/// `upsert_file` — the one mutation helper — may be defined in `state.rs` and
/// called only from the store thread (`oplog.rs`).
#[test]
fn upsert_file_is_called_only_from_the_store_thread() {
    let mut files = Vec::new();
    rs_files(&src_dir(), &mut files);
    assert!(!files.is_empty(), "found no source files to scan");

    for f in &files {
        let name = file_name(f);
        if name == "state.rs" || name == "oplog.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read source");
        assert!(
            !text.contains("upsert_file"),
            "{}: references upsert_file — a write path to the files index \
             outside the store thread reopens the stale-decision clobber \
             (FR-303 lead invariant)",
            f.display()
        );
    }
}

/// Raw SQL that mutates the `files` table may exist only in `state.rs` —
/// even inside the store thread, mutations route through the one helper.
#[test]
fn files_table_sql_mutations_live_only_in_state_rs() {
    const FORBIDDEN: &[&str] = &[
        "INSERT INTO files",
        "INSERT OR IGNORE INTO files",
        "INSERT OR REPLACE INTO files",
        "REPLACE INTO files",
        "UPDATE files",
        "DELETE FROM files",
    ];
    let mut files = Vec::new();
    rs_files(&src_dir(), &mut files);

    for f in &files {
        if file_name(f) == "state.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read source");
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{}: contains `{needle}` — files-index mutations must go \
                 through state::upsert_file inside a store-thread transaction",
                f.display()
            );
        }
    }
}

/// The committing functions exist where the gate expects them — guards
/// against the invariant rotting into a vacuous scan after a refactor.
#[test]
fn the_whitelisted_committing_functions_exist() {
    let oplog = std::fs::read_to_string(src_dir().join("oplog.rs")).expect("read oplog.rs");
    for needle in [
        "fn append_local(",
        "fn apply_remote(",
        "fn reconcile_upsert(",
        "fn resolve_rows(",
    ] {
        assert!(
            oplog.contains(needle),
            "oplog.rs lost `{needle}` — update the write-path gate consciously, \
             not by accident"
        );
    }
}
