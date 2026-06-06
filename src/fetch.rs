//! fetch.rs — missing-chunk diff + multi-source parallel fetch + resume
//! (FR-401/403/404).
//!
//! The receiver computes `missing = manifest chunks not in the CAS` (the CAS
//! is the resume state: a chunk that survived a crash is never re-fetched),
//! then fetches missing chunks in parallel — bounded by
//! `per_file_chunk_concurrency` — from ANY live connection in the registry,
//! origin first, BitTorrent-style without an advertisement protocol. Every
//! chunk is BLAKE3-verified before it is trusted, and `Cas::put_verified`
//! re-verifies before it is stored. A peer disappearing mid-fetch just moves
//! the remaining chunks to the other candidates.
//!
//! Error classification matters (poison-op handling): "every live peer SAYS
//! it doesn't have it" is permanent (the content was superseded — quarantine
//! and let a newer op or anti-entropy repair); "peers flaked / no peers" is
//! transient (drop the subscription, reconnect, resume).

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::chunk::{Cas, CasError, Manifest};
use crate::oplog::{Store, StoreError};
use crate::peer::ConnRegistry;
use crate::proto::{
    read_msg, write_msg, ChunkEntry, ChunkReq, ChunkResp, ManifestReq, ManifestResp, ProtoError,
    MANIFEST_PAGE, STREAM_TAG_CHUNK, STREAM_TAG_MANIFEST,
};
use crate::stats::Stats;
use crate::vv::NodeId;

/// Backstop against a hostile `total` in ManifestResp: 2^24 chunks ≈ 64 TiB
/// at the 4 MiB max — far beyond any real file, small enough to bound memory.
const MAX_MANIFEST_CHUNKS: u32 = 1 << 24;

#[derive(thiserror::Error, Debug)]
pub enum FetchError {
    /// Every live peer answered "not found" — the content no longer exists
    /// anywhere we can see. PERMANENT: quarantine the op.
    #[error("content unavailable from every live peer")]
    Unavailable,
    /// No live connections at all, or every candidate errored. TRANSIENT.
    #[error("no usable peer connection (all flaked or none live)")]
    NoUsablePeer,
    /// The manifest itself is malformed/hostile. PERMANENT.
    #[error("manifest invalid: {0}")]
    BadManifest(&'static str),
    #[error("chunk store: {0}")]
    Cas(#[from] CasError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("task join: {0}")]
    Join(#[from] tokio::task::JoinError),
}

impl FetchError {
    /// See module docs: should the op be quarantined rather than retried?
    pub fn is_permanent(&self) -> bool {
        matches!(self, FetchError::Unavailable | FetchError::BadManifest(_))
    }
}

/// Limits threaded from config.
#[derive(Clone, Copy, Debug)]
pub struct FetchLimits {
    pub per_file_chunk_concurrency: usize,
    pub max_chunk_bytes: u32,
    pub max_file_bytes: u64,
}

/// Get the manifest for `content_hash`: local db first, then the origin,
/// then any other live peer (paginated). A fetched manifest is validated and
/// durably stored before returning, so a crash mid-transfer resumes with the
/// structure known.
pub async fn obtain_manifest(
    content_hash: [u8; 32],
    store: &Store,
    registry: &ConnRegistry,
    origin: NodeId,
    limits: &FetchLimits,
    stats: &Arc<Stats>,
) -> Result<Manifest, FetchError> {
    if let Some(m) = store.manifest_for(content_hash).await? {
        return Ok(m);
    }
    let candidates = registry.candidates(&origin);
    if candidates.is_empty() {
        return Err(FetchError::NoUsablePeer);
    }
    let mut any_not_found = false;
    for (peer, conn) in candidates {
        match manifest_from_peer(&conn, content_hash, limits).await {
            Ok(Some(m)) => {
                Stats::inc(&stats.manifests_fetched);
                store.put_manifest(m.clone()).await?;
                return Ok(m);
            }
            Ok(None) => any_not_found = true,
            Err(e) => {
                tracing::debug!(peer = %hex::encode(&peer[..4]), error = %e,
                    "manifest fetch attempt failed; trying next peer");
            }
        }
    }
    if any_not_found {
        Err(FetchError::Unavailable)
    } else {
        Err(FetchError::NoUsablePeer)
    }
}

/// Paginated manifest retrieval from one peer, with structural validation.
async fn manifest_from_peer(
    conn: &quinn::Connection,
    content_hash: [u8; 32],
    limits: &FetchLimits,
) -> Result<Option<Manifest>, FetchError> {
    let mut chunks: Vec<ChunkEntry> = Vec::new();
    loop {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|_| FetchError::NoUsablePeer)?;
        send.write_all(&[STREAM_TAG_MANIFEST])
            .await
            .map_err(|_| FetchError::NoUsablePeer)?;
        write_msg(
            &mut send,
            &ManifestReq {
                content_hash,
                offset: chunks.len() as u32,
                count: MANIFEST_PAGE,
            },
        )
        .await
        .map_err(|_| FetchError::NoUsablePeer)?;
        let _ = send.finish();

        let resp: ManifestResp = match read_msg(&mut recv).await {
            Ok(r) => r,
            Err(ProtoError::Closed) => return Err(FetchError::NoUsablePeer),
            Err(_) => return Err(FetchError::NoUsablePeer),
        };
        if !resp.found {
            return Ok(None);
        }
        // Never trust network input: bound and cross-check every field.
        if resp.content_hash != content_hash {
            return Err(FetchError::BadManifest("wrong content_hash"));
        }
        if resp.total > MAX_MANIFEST_CHUNKS {
            return Err(FetchError::BadManifest("absurd chunk count"));
        }
        if resp.chunks.len() as u32 > MANIFEST_PAGE {
            return Err(FetchError::BadManifest("oversized page"));
        }
        for c in &resp.chunks {
            if c.len == 0 || c.len > limits.max_chunk_bytes {
                return Err(FetchError::BadManifest("chunk length out of bounds"));
            }
        }
        let total = resp.total;
        let page_len = resp.chunks.len();
        chunks.extend(resp.chunks);
        if chunks.len() as u32 > total {
            return Err(FetchError::BadManifest("more chunks than total"));
        }
        if chunks.len() as u32 == total {
            break;
        }
        if page_len == 0 {
            return Err(FetchError::BadManifest("empty page before total"));
        }
    }
    let manifest = Manifest {
        content_hash,
        chunks,
    };
    if manifest.total_len() > limits.max_file_bytes {
        return Err(FetchError::BadManifest(
            "total length exceeds max_file_bytes",
        ));
    }
    Ok(Some(manifest))
}

/// Ensure every chunk of `manifest` is present in the CAS, fetching missing
/// ones in parallel from any live peer. Returns once `cas.has()` holds for
/// all of them. Idempotent and resumable (FR-404).
pub async fn fetch_file_chunks(
    manifest: &Manifest,
    cas: &Cas,
    registry: &ConnRegistry,
    origin: NodeId,
    limits: &FetchLimits,
    stats: &Arc<Stats>,
) -> Result<(), FetchError> {
    // Dedup within the manifest (repeated content costs one fetch) and skip
    // everything already present — THE resume step.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let missing: Vec<ChunkEntry> = manifest
        .chunks
        .iter()
        .filter(|c| seen.insert(c.hash) && !cas.has(&c.hash))
        .copied()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    tracing::debug!(
        missing = missing.len(),
        total = manifest.chunks.len(),
        "fetching missing chunks"
    );

    let sem = Arc::new(Semaphore::new(limits.per_file_chunk_concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for entry in missing {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| FetchError::NoUsablePeer)?;
        let cas = cas.clone();
        let registry = registry.clone();
        let limits = *limits;
        let stats = stats.clone();
        tasks.spawn(async move {
            let _permit = permit; // bounds in-flight chunks (FR-1106)
            fetch_one_chunk(entry, &cas, &registry, origin, &limits, &stats).await
        });
    }
    let mut first_err: Option<FetchError> = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // Keep draining so all permits release; remember the most
                // severe error (permanent beats transient for the caller).
                let replace = match (&first_err, &e) {
                    (None, _) => true,
                    (Some(prev), e) => e.is_permanent() && !prev.is_permanent(),
                };
                if replace {
                    first_err = Some(e);
                }
            }
            Err(join) => {
                if first_err.is_none() {
                    first_err = Some(FetchError::Join(join));
                }
            }
        }
    }
    match first_err {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// One chunk: try candidates in order (origin first); verify bytes BEFORE the
/// CAS insert (which re-verifies — belt and braces). A vanished peer is just
/// "try the next one".
async fn fetch_one_chunk(
    entry: ChunkEntry,
    cas: &Cas,
    registry: &ConnRegistry,
    origin: NodeId,
    limits: &FetchLimits,
    stats: &Arc<Stats>,
) -> Result<(), FetchError> {
    if entry.len > limits.max_chunk_bytes {
        return Err(FetchError::BadManifest("chunk length out of bounds"));
    }
    let candidates = registry.candidates(&origin);
    if candidates.is_empty() {
        return Err(FetchError::NoUsablePeer);
    }
    let mut any_not_found = false;
    for (peer, conn) in candidates {
        match chunk_from_peer(&conn, &entry).await {
            Ok(Some(bytes)) => {
                // Verified by chunk_from_peer; put_verified re-checks and is
                // the ONLY path that writes into the store.
                Stats::inc(&stats.chunks_fetched);
                Stats::add(&stats.bytes_in, bytes.len() as u64);
                let cas = cas.clone();
                let hash = entry.hash;
                tokio::task::spawn_blocking(move || cas.put_verified(&hash, &bytes)).await??;
                return Ok(());
            }
            Ok(None) => any_not_found = true,
            Err(e) => {
                tracing::debug!(peer = %hex::encode(&peer[..4]), error = %e,
                    "chunk fetch attempt failed; trying next peer");
            }
        }
    }
    if any_not_found {
        Err(FetchError::Unavailable)
    } else {
        Err(FetchError::NoUsablePeer)
    }
}

/// Wire exchange for one chunk on one connection. `Ok(None)` = peer says
/// not-found. Bytes are length-checked and BLAKE3-verified before returning.
async fn chunk_from_peer(
    conn: &quinn::Connection,
    entry: &ChunkEntry,
) -> Result<Option<Vec<u8>>, FetchError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|_| FetchError::NoUsablePeer)?;
    send.write_all(&[STREAM_TAG_CHUNK])
        .await
        .map_err(|_| FetchError::NoUsablePeer)?;
    write_msg(&mut send, &ChunkReq { hash: entry.hash })
        .await
        .map_err(|_| FetchError::NoUsablePeer)?;
    let _ = send.finish();

    let resp: ChunkResp = read_msg(&mut recv)
        .await
        .map_err(|_| FetchError::NoUsablePeer)?;
    if !resp.found {
        return Ok(None);
    }
    if resp.len != entry.len {
        // Lying peer: treat as a failed candidate, not fatal.
        return Err(FetchError::NoUsablePeer);
    }
    let mut bytes = vec![0u8; resp.len as usize];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|_| FetchError::NoUsablePeer)?;
    // Verify BEFORE the bytes are trusted anywhere (FR-403).
    if blake3::hash(&bytes).as_bytes() != &entry.hash {
        return Err(FetchError::NoUsablePeer); // corrupt/hostile: next peer
    }
    Ok(Some(bytes))
}
