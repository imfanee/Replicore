//! chunk.rs — content-defined chunking + content-addressed store (FR-402/403).
//!
//! Chunk identity is BLAKE3 of the chunk bytes (mandated). A file's manifest
//! is the ordered list of chunk hashes (+ lengths; offsets are prefix sums).
//! Chunks are immutable and idempotent.
//!
//! The CAS is a directory tree (`<cas_dir>/ab/<64-hex>`) of immutable,
//! verified chunk files. **The CAS directory is the single source of truth
//! for chunk presence** (a `stat`); the database holds manifest *structure*.
//! This split makes the post-crash resume question — "do I already have this
//! chunk?" — exactly a `stat` (FR-404): chunks survive a kill because every
//! insert is verify → write tmp → fsync → rename.
//!
//! `Cas::put_verified` is the ONLY path that writes a chunk (the reviewer
//! gate "chunk verification happens BEFORE a chunk is trusted/stored").
//!
//! No GC in M2 — chunks are never deleted. // SEAM(M3): refcounted CAS GC
//! driven by manifest_chunks + tombstone acks.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::proto::ChunkEntry;
use crate::TMP_SUFFIX;

pub type ChunkHash = [u8; 32];

static CAS_STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Ordered chunk list reconstructing one file whose whole-file BLAKE3 is
/// `content_hash` (== the op's / files-row's content_hash).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    pub content_hash: [u8; 32],
    pub chunks: Vec<ChunkEntry>,
}

impl Manifest {
    pub fn total_len(&self) -> u64 {
        self.chunks.iter().map(|c| c.len as u64).sum()
    }
}

/// fastcdc bounds, from config (validated min ≤ avg ≤ max there).
#[derive(Clone, Copy, Debug)]
pub struct ChunkParams {
    pub min: u32,
    pub avg: u32,
    pub max: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum CasError {
    #[error("{ctx} {path}: {source}")]
    Io {
        ctx: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("chunk bytes do not hash to the claimed identity")]
    HashMismatch,
    #[error("chunk {0} missing from the store")]
    Missing(String),
    #[error("chunker: {0}")]
    Chunker(String),
}

fn io_err<'p>(ctx: &'static str, path: &'p Path) -> impl FnOnce(std::io::Error) -> CasError + 'p {
    move |source| CasError::Io {
        ctx,
        path: path.to_path_buf(),
        source,
    }
}

/// The persistent content-addressed chunk store. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Cas {
    root: Arc<PathBuf>,
}

impl Cas {
    /// Open (create if absent) the store root.
    pub fn open(cas_dir: &Path) -> Result<Cas, CasError> {
        std::fs::create_dir_all(cas_dir).map_err(io_err("mkdir", cas_dir))?;
        Ok(Cas {
            root: Arc::new(cas_dir.to_path_buf()),
        })
    }

    /// `<root>/ab/<full 64-hex>` — two-byte fan-out keeps directories small.
    pub fn path_for(&self, h: &ChunkHash) -> PathBuf {
        let hex = hex::encode(h);
        self.root.join(&hex[..2]).join(hex)
    }

    /// Presence = the post-crash resume question (FR-404).
    pub fn has(&self, h: &ChunkHash) -> bool {
        self.path_for(h).is_file()
    }

    /// Crash-safe, idempotent insert. Verifies BLAKE3(bytes) == `h` BEFORE
    /// anything is written; then tmp → fsync → rename (atomic) → the chunk is
    /// trusted. Re-inserting an existing chunk is a no-op.
    pub fn put_verified(&self, h: &ChunkHash, bytes: &[u8]) -> Result<(), CasError> {
        if blake3::hash(bytes).as_bytes() != h {
            return Err(CasError::HashMismatch);
        }
        let dest = self.path_for(h);
        if dest.is_file() {
            return Ok(()); // immutable + verified at first write: done
        }
        let parent = dest.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(parent).map_err(io_err("mkdir", parent))?;
        let tmp = parent.join(format!(
            ".chunk{}.{}.{}",
            TMP_SUFFIX,
            std::process::id(),
            CAS_STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let write = || -> Result<(), CasError> {
            let mut f = std::fs::File::create(&tmp).map_err(io_err("create", &tmp))?;
            f.write_all(bytes).map_err(io_err("write", &tmp))?;
            f.sync_all().map_err(io_err("fsync", &tmp))?;
            std::fs::rename(&tmp, &dest).map_err(io_err("rename", &dest))?;
            if let Ok(dirf) = std::fs::File::open(parent) {
                let _ = dirf.sync_all();
            }
            Ok(())
        };
        write().inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }

    /// Read a chunk back, re-verifying its hash (bit-rot is an error, never
    /// silently served into an assembly).
    ///
    /// SELF-HEALING: a corrupt chunk is UNLINKED before the error returns.
    /// Without this, a bit-rotted chunk wedges every transfer that needs it
    /// forever: the fetch diff sees it as "present" and skips it, assembly
    /// keeps failing, and the transient-retry loop never converges (found by
    /// the reviewer-checklist resume trace). Dropping it makes the next
    /// fetch pass re-fetch a verified copy from a peer.
    pub fn read(&self, h: &ChunkHash) -> Result<Vec<u8>, CasError> {
        let path = self.path_for(h);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CasError::Missing(hex::encode(h)))
            }
            Err(e) => return Err(io_err("read", &path)(e)),
        };
        if blake3::hash(&bytes).as_bytes() != h {
            tracing::error!(chunk = %hex::encode(h),
                "corrupt chunk detected in CAS; dropping for re-fetch");
            let _ = std::fs::remove_file(&path);
            return Err(CasError::HashMismatch);
        }
        Ok(bytes)
    }

    /// Open a chunk for streamed serving. The *receiver* verifies (every
    /// fetch path re-hashes before trusting), so serving streams without a
    /// local re-hash pass.
    pub fn open_reader(&self, h: &ChunkHash) -> Result<(std::fs::File, u64), CasError> {
        let path = self.path_for(h);
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CasError::Missing(hex::encode(h)))
            }
            Err(e) => return Err(io_err("open", &path)(e)),
        };
        let len = f.metadata().map_err(io_err("stat", &path))?.len();
        Ok((f, len))
    }

    /// Remove insert temps orphaned by a kill -9 mid-`put_verified`. Startup
    /// only, before any concurrent insert can stage (same rule as the share
    /// temp sweep).
    pub fn sweep_orphan_temps(&self) -> Result<usize, CasError> {
        let mut removed = 0;
        let mut stack = vec![self.root.as_ref().clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir).map_err(io_err("readdir", &dir))?;
            for entry in entries {
                let entry = entry.map_err(io_err("readdir", &dir))?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(TMP_SUFFIX))
                    && std::fs::remove_file(&path).is_ok()
                {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// (chunk count, total bytes) — health endpoint.
    pub fn stats(&self) -> (u64, u64) {
        let (mut count, mut bytes) = (0u64, 0u64);
        let mut stack = vec![self.root.as_ref().clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = entry.metadata() {
                    count += 1;
                    bytes += meta.len();
                }
            }
        }
        (count, bytes)
    }
}

/// Chunk a local file in ONE read pass: fastcdc v2020 streaming (bounded
/// memory) → per-chunk BLAKE3 → CAS insert → whole-file BLAKE3 accumulated
/// alongside. Returns the manifest. Blocking; call in spawn_blocking.
pub fn chunk_file_into_cas(
    abs: &Path,
    params: &ChunkParams,
    cas: &Cas,
) -> Result<Manifest, CasError> {
    let file = std::fs::File::open(abs).map_err(io_err("open", abs))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let cdc = fastcdc::v2020::StreamCDC::new(
        reader,
        params.min as usize,
        params.avg as usize,
        params.max as usize,
    );

    let mut whole = blake3::Hasher::new();
    let mut chunks = Vec::new();
    for piece in cdc {
        let piece = piece.map_err(|e| CasError::Chunker(e.to_string()))?;
        let hash: ChunkHash = *blake3::hash(&piece.data).as_bytes();
        cas.put_verified(&hash, &piece.data)?;
        whole.update(&piece.data);
        chunks.push(ChunkEntry {
            hash,
            len: piece.data.len() as u32,
        });
    }
    Ok(Manifest {
        content_hash: *whole.finalize().as_bytes(),
        chunks,
    })
}

/// Stream a manifest's chunks out of the CAS into `out`, returning the
/// whole-file BLAKE3 actually written. Each chunk is re-verified by
/// `Cas::read`; a length mismatch against the manifest is an error. The
/// CALLER compares the returned hash against the expected content_hash
/// before any rename (FR-803).
pub fn assemble_from_cas(
    manifest: &Manifest,
    cas: &Cas,
    out: &mut std::fs::File,
) -> Result<[u8; 32], CasError> {
    use std::io::Seek;
    let io = |ctx: &'static str| {
        move |e| CasError::Io {
            ctx,
            path: PathBuf::from("<assembly>"),
            source: e,
        }
    };
    let mut whole = blake3::Hasher::new();
    let mut offset: u64 = 0;
    for entry in &manifest.chunks {
        let bytes = cas.read(&entry.hash)?;
        if bytes.len() as u32 != entry.len {
            return Err(CasError::HashMismatch); // structure lied about length
        }
        // Sparse files stay sparse (FR-106): an all-zero chunk becomes a
        // hole — seek over it instead of writing zeros. The whole-file hash
        // still covers the zeros (holes read back as zeros), so the verify
        // discipline is unchanged.
        if bytes.iter().all(|&b| b == 0) {
            offset += bytes.len() as u64;
            out.seek(std::io::SeekFrom::Start(offset))
                .map_err(io("seek"))?;
        } else {
            out.write_all(&bytes).map_err(io("write"))?;
            offset += bytes.len() as u64;
        }
        whole.update(&bytes);
    }
    // Realize a trailing hole: without this, a file ending in zeros would
    // come out short.
    out.set_len(offset).map_err(io("truncate"))?;
    Ok(*whole.finalize().as_bytes())
}

/// One streamed read of a file to compute (whole_hash, manifest) WITHOUT
/// inserting into the CAS — used by tests and dry runs.
#[cfg(test)]
pub fn chunk_bytes(data: &[u8], params: &ChunkParams) -> Vec<ChunkEntry> {
    fastcdc::v2020::FastCDC::new(
        data,
        params.min as usize,
        params.avg as usize,
        params.max as usize,
    )
    .map(|c| ChunkEntry {
        hash: *blake3::hash(&data[c.offset..c.offset + c.length]).as_bytes(),
        len: c.length as u32,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: ChunkParams = ChunkParams {
        min: 4096,
        avg: 16 * 1024,
        max: 64 * 1024,
    };

    /// Deterministic pseudo-random bytes (xorshift); no rand dep.
    fn noise(len: usize, mut seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            out.extend_from_slice(&seed.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn chunking_is_deterministic() {
        let data = noise(1 << 20, 42);
        let a = chunk_bytes(&data, &P);
        let b = chunk_bytes(&data, &P);
        assert_eq!(a, b);
        assert!(a.len() > 10, "expected many chunks, got {}", a.len());
        assert_eq!(a.iter().map(|c| c.len as usize).sum::<usize>(), data.len());
    }

    #[test]
    fn insertion_only_recuts_locally() {
        let base = noise(1 << 20, 7);
        let mut edited = base.clone();
        edited.insert(512 * 1024, 0xAB); // one byte in the middle

        let a: std::collections::HashSet<ChunkHash> =
            chunk_bytes(&base, &P).iter().map(|c| c.hash).collect();
        let b: std::collections::HashSet<ChunkHash> =
            chunk_bytes(&edited, &P).iter().map(|c| c.hash).collect();
        let shared = a.intersection(&b).count();
        // CDC promise: only the chunks around the edit region change.
        assert!(
            shared >= a.len().saturating_sub(4),
            "edit invalidated too many chunks: {} of {} shared",
            shared,
            a.len()
        );
    }

    #[test]
    fn put_verified_rejects_lying_hash_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let err = cas
            .put_verified(&[0u8; 32], b"not the preimage")
            .unwrap_err();
        assert!(matches!(err, CasError::HashMismatch));
        assert!(!cas.has(&[0u8; 32]));
        let (count, _) = cas.stats();
        assert_eq!(count, 0); // nothing written at all
    }

    #[test]
    fn put_is_idempotent_and_read_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let data = b"immutable chunk";
        let h = *blake3::hash(data).as_bytes();
        cas.put_verified(&h, data).unwrap();
        cas.put_verified(&h, data).unwrap(); // no-op, no error
        assert!(cas.has(&h));
        assert_eq!(cas.read(&h).unwrap(), data);

        // Bit-rot is detected on read, never silently served — and the
        // corrupt chunk is dropped so the next fetch diff re-fetches it
        // instead of wedging in a skip/fail retry loop forever.
        std::fs::write(cas.path_for(&h), b"corrupted!!!!!!").unwrap();
        assert!(matches!(cas.read(&h).unwrap_err(), CasError::HashMismatch));
        assert!(!cas.has(&h), "corrupt chunk must be evicted for re-fetch");
        // The heal: a verified re-insert restores service.
        cas.put_verified(&h, data).unwrap();
        assert_eq!(cas.read(&h).unwrap(), data);
    }

    /// End-to-end shape of the wedge this fix prevents: corrupt chunk ->
    /// assembly fails AND evicts -> the missing-diff now includes it ->
    /// re-fetch -> assembly succeeds.
    #[test]
    fn corrupt_chunk_unwedges_assembly_after_refetch() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path().join("cas").as_path()).unwrap();
        let data = noise(200_000, 11);
        let src = dir.path().join("src");
        std::fs::write(&src, &data).unwrap();
        let manifest = chunk_file_into_cas(&src, &P, &cas).unwrap();
        assert!(manifest.chunks.len() >= 3);

        // Bit-rot one middle chunk.
        let victim = manifest.chunks[1].hash;
        std::fs::write(cas.path_for(&victim), b"rotten").unwrap();

        // Assembly fails ONCE and evicts the bad chunk...
        let mut out = std::fs::File::create(dir.path().join("out1")).unwrap();
        assert!(assemble_from_cas(&manifest, &cas, &mut out).is_err());
        assert!(!cas.has(&victim), "victim must be evicted");

        // ...so the fetch diff would now re-fetch it (simulated re-insert)...
        let start = manifest
            .chunks
            .iter()
            .take(1)
            .map(|c| c.len as usize)
            .sum::<usize>();
        let len = manifest.chunks[1].len as usize;
        cas.put_verified(&victim, &data[start..start + len])
            .unwrap();

        // ...and the retry converges.
        let mut out = std::fs::File::create(dir.path().join("out2")).unwrap();
        let got = assemble_from_cas(&manifest, &cas, &mut out).unwrap();
        assert_eq!(got, manifest.content_hash);
    }

    #[test]
    fn orphan_temp_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let data = b"kept";
        let h = *blake3::hash(data).as_bytes();
        cas.put_verified(&h, data).unwrap();
        // Simulate a kill -9 mid-insert: a stranded temp next to real chunks.
        let stranded = dir
            .path()
            .join("ab")
            .join(format!(".chunk{TMP_SUFFIX}.1.1"));
        std::fs::create_dir_all(stranded.parent().unwrap()).unwrap();
        std::fs::write(&stranded, b"partial").unwrap();

        assert_eq!(cas.sweep_orphan_temps().unwrap(), 1);
        assert!(!stranded.exists());
        assert!(cas.has(&h));
    }

    #[test]
    fn file_round_trips_through_cas() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path().join("cas").as_path()).unwrap();
        let data = noise(3 * 1024 * 1024 + 17, 99);
        let src = dir.path().join("src.bin");
        std::fs::write(&src, &data).unwrap();

        let manifest = chunk_file_into_cas(&src, &P, &cas).unwrap();
        assert_eq!(manifest.content_hash, *blake3::hash(&data).as_bytes());
        assert_eq!(manifest.total_len(), data.len() as u64);
        assert!(manifest.chunks.len() > 10);

        let out_path = dir.path().join("out.bin");
        let mut out = std::fs::File::create(&out_path).unwrap();
        let got = assemble_from_cas(&manifest, &cas, &mut out).unwrap();
        drop(out);
        assert_eq!(got, manifest.content_hash);
        assert_eq!(std::fs::read(&out_path).unwrap(), data);
    }

    #[test]
    fn empty_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path().join("cas").as_path()).unwrap();
        let src = dir.path().join("empty");
        std::fs::write(&src, b"").unwrap();
        let manifest = chunk_file_into_cas(&src, &P, &cas).unwrap();
        assert_eq!(manifest.content_hash, *blake3::hash(b"").as_bytes());

        let mut out = std::fs::File::create(dir.path().join("out")).unwrap();
        let got = assemble_from_cas(&manifest, &cas, &mut out).unwrap();
        assert_eq!(got, manifest.content_hash);
    }

    #[test]
    fn dedup_identical_content_stored_once() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path().join("cas").as_path()).unwrap();
        let data = noise(1 << 20, 5);
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, &data).unwrap();
        std::fs::write(&b, &data).unwrap();

        let ma = chunk_file_into_cas(&a, &P, &cas).unwrap();
        let (count_after_first, bytes_after_first) = cas.stats();
        let mb = chunk_file_into_cas(&b, &P, &cas).unwrap();
        let (count_after_second, bytes_after_second) = cas.stats();

        assert_eq!(ma, mb);
        // FR-402 dedup: the second identical file added NOTHING to the store.
        assert_eq!(count_after_first, count_after_second);
        assert_eq!(bytes_after_first, bytes_after_second);
    }
}
