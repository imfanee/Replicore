//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! FR-106 / FR-804 end-to-end: metadata captured by the real ingest pipeline
//! rides the op and is applied byte-exact on the receiving side — through the
//! REAL apply machinery (stage→fsync→verify→meta→rename) against real files.
//!
//! Also pins the two laws around the apply itself:
//! - a metadata-ONLY change (same bytes) emits an op (the no-op filter
//!   compares meta too) and the receiver applies it without re-fetching;
//! - re-capture after apply equals the applied meta — the no-storm law (a
//!   field the apply can't reproduce would re-emit forever).

use std::path::{Path, PathBuf};

use replicore::apply::{apply_meta_only, apply_version};
use replicore::chunk::{chunk_file_into_cas, Cas, ChunkParams};
use replicore::metadata::{FileKind, Meta, OwnerPolicy};
use replicore::suppress::Suppressor;

const PARAMS: ChunkParams = ChunkParams {
    min: 4096,
    avg: 16 * 1024,
    max: 64 * 1024,
};

struct Rig {
    _dir: tempfile::TempDir,
    src: PathBuf,
    dst: PathBuf,
    cas: Cas,
    suppress: Suppressor,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    let cas = Cas::open(&dir.path().join("cas")).unwrap();
    Rig {
        _dir: dir,
        src,
        dst,
        cas,
        suppress: Suppressor::new(),
    }
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    // SAFETY: valid NUL-terminated strings and a live buffer.
    let rc = unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            n.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    rc == 0
}

/// Regular file: content + mode + mtime + xattrs round-trip byte-exact
/// through capture → (simulated wire) → apply_version → re-capture.
#[test]
fn regular_file_meta_round_trips_through_the_apply_path() {
    let r = rig();
    let f = r.src.join("rec.wav");
    let data: Vec<u8> = (0u32..50_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(&f, &data).unwrap();
    std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
    let xattr_ok = set_xattr(&f, "user.replicore", b"fidelity");

    // Origin-side capture + chunking (what ingest does).
    let meta = Meta::capture(&f, OwnerPolicy::Skip).unwrap().unwrap();
    let manifest = chunk_file_into_cas(&f, &PARAMS, &r.cas).unwrap();

    // Receiver-side apply (what materialize does).
    apply_version(
        &r.dst,
        "rec.wav",
        meta.mode,
        Some(&manifest.content_hash),
        Some(&manifest),
        &r.cas,
        Some(&meta),
        OwnerPolicy::Skip,
        &r.suppress,
    )
    .unwrap();

    let out = r.dst.join("rec.wav");
    assert_eq!(std::fs::read(&out).unwrap(), data);
    let got = Meta::capture(&out, OwnerPolicy::Skip).unwrap().unwrap();
    // The no-storm law: re-capture == applied. Byte-exact ⇒ equal hashes.
    assert_eq!(
        Meta::hash_of(&Some(got.clone())),
        Meta::hash_of(&Some(meta.clone())),
        "re-captured meta differs from applied meta: {got:?} vs {meta:?}"
    );
    assert_eq!(got.mode, 0o640);
    assert_eq!((got.mtime_s, got.mtime_ns), (meta.mtime_s, meta.mtime_ns));
    if xattr_ok {
        assert!(got
            .xattrs
            .iter()
            .any(|(n, v)| n == b"user.replicore" && v == b"fidelity"));
    }
}

/// Symlinks replicate by target bytes, never followed, and round-trip.
#[test]
fn symlink_round_trips_without_following() {
    let r = rig();
    let l = r.src.join("link");
    std::os::unix::fs::symlink("../outside/never-read", &l).unwrap();
    let meta = Meta::capture(&l, OwnerPolicy::Skip).unwrap().unwrap();
    assert_eq!(meta.kind, FileKind::Symlink);
    let hash = *blake3::hash(meta.symlink_target.as_deref().unwrap()).as_bytes();

    apply_version(
        &r.dst,
        "link",
        meta.mode,
        Some(&hash),
        None,
        &r.cas,
        Some(&meta),
        OwnerPolicy::Skip,
        &r.suppress,
    )
    .unwrap();

    let out = r.dst.join("link");
    let target = std::fs::read_link(&out).unwrap();
    assert_eq!(target.as_os_str().to_str(), Some("../outside/never-read"));
    // Never followed: the (nonexistent, escaping) target was not created.
    assert!(std::fs::metadata(&out).is_err());
    let got = Meta::capture(&out, OwnerPolicy::Skip).unwrap().unwrap();
    assert_eq!(got.kind, FileKind::Symlink);
    assert_eq!(got.symlink_target, meta.symlink_target);
}

/// FIFOs replicate as nodes with their metadata; idempotent on redelivery.
#[test]
fn fifo_round_trips() {
    let r = rig();
    let p = r.src.join("pipe");
    // mkfifo on the source side.
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let meta = Meta::capture(&p, OwnerPolicy::Skip).unwrap().unwrap();
    assert_eq!(meta.kind, FileKind::Fifo);

    for _ in 0..2 {
        // redelivery is idempotent
        apply_version(
            &r.dst,
            "pipe",
            meta.mode,
            None,
            None,
            &r.cas,
            Some(&meta),
            OwnerPolicy::Skip,
            &r.suppress,
        )
        .unwrap();
    }
    let got = Meta::capture(&r.dst.join("pipe"), OwnerPolicy::Skip)
        .unwrap()
        .unwrap();
    assert_eq!(got.kind, FileKind::Fifo);
    assert_eq!(got.mode, 0o600);
}

/// A metadata-only change (same content) applies in place — no content
/// rewrite, mtime/mode/xattrs updated to the op's values.
#[test]
fn meta_only_apply_updates_attributes_in_place() {
    let r = rig();
    let f = r.dst.join("f");
    std::fs::write(&f, b"unchanged bytes").unwrap();
    let hash = *blake3::hash(b"unchanged bytes").as_bytes();
    let mut meta = Meta::capture(&f, OwnerPolicy::Skip).unwrap().unwrap();
    meta.mode = 0o604;
    meta.mtime_s = 1_111_111_111;
    meta.mtime_ns = 0;

    apply_meta_only(
        &r.dst,
        "f",
        Some(&hash),
        &meta,
        OwnerPolicy::Skip,
        &r.suppress,
    )
    .unwrap();

    let got = Meta::capture(&f, OwnerPolicy::Skip).unwrap().unwrap();
    assert_eq!(got.mode, 0o604);
    assert_eq!(got.mtime_s, 1_111_111_111);
    assert_eq!(std::fs::read(&f).unwrap(), b"unchanged bytes");
    // Suppression was registered for the attribute events this fires.
    assert!(r.suppress.check_write("f", &hash));
}

/// Sparse files stay sparse (FR-106): all-zero regions become holes on the
/// receiving side — allocated blocks stay far below the logical size.
#[test]
fn sparse_files_stay_sparse_through_assembly() {
    use std::os::unix::fs::MetadataExt;
    let r = rig();
    let f = r.src.join("sparse.bin");
    // 8 MiB logical, ~64 KiB of real data at the front and back.
    let file = std::fs::File::create(&f).unwrap();
    file.set_len(8 * 1024 * 1024).unwrap();
    drop(file);
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(&f).unwrap();
        file.write_all(&[0xAB; 32 * 1024]).unwrap();
        file.seek(SeekFrom::End(-(32 * 1024))).unwrap();
        file.write_all(&[0xCD; 32 * 1024]).unwrap();
    }
    let meta = Meta::capture(&f, OwnerPolicy::Skip).unwrap().unwrap();
    let manifest = chunk_file_into_cas(&f, &PARAMS, &r.cas).unwrap();

    apply_version(
        &r.dst,
        "sparse.bin",
        meta.mode,
        Some(&manifest.content_hash),
        Some(&manifest),
        &r.cas,
        Some(&meta),
        OwnerPolicy::Skip,
        &r.suppress,
    )
    .unwrap();

    let out = r.dst.join("sparse.bin");
    let st = std::fs::metadata(&out).unwrap();
    assert_eq!(st.len(), 8 * 1024 * 1024, "logical size preserved");
    // Holes were not inflated: blocks ≪ size (allow generous fs overhead).
    let allocated = st.blocks() * 512;
    assert!(
        allocated < 2 * 1024 * 1024,
        "hole inflation: {allocated} bytes allocated for ~64 KiB of data"
    );
    // And the content is byte-identical (holes read as zeros).
    assert_eq!(
        *blake3::hash(&std::fs::read(&out).unwrap()).as_bytes(),
        manifest.content_hash
    );
}

/// The kind dispatch refuses nonsense (regular content without a manifest).
#[test]
fn apply_version_requires_a_manifest_for_regular_content() {
    let r = rig();
    let meta = Meta {
        kind: FileKind::Regular,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime_s: 0,
        mtime_ns: 0,
        symlink_target: None,
        rdev: 0,
        xattrs: vec![],
    };
    assert!(apply_version(
        &r.dst,
        "f",
        0o644,
        Some(&[1u8; 32]),
        None,
        &r.cas,
        Some(&meta),
        OwnerPolicy::Skip,
        &r.suppress,
    )
    .is_err());
}
