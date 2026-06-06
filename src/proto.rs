//! proto.rs — versioned wire protocol (FR-501/504).
//!
//! Control stream: length-prefixed (`u32` big-endian) bincode frames, one
//! long-lived bidirectional stream per connection carrying op-log records and
//! acks. File bytes never ride the control stream — they go over ephemeral
//! per-file bi-streams (`FetchReq` → `FetchResp` header → raw verified bytes).
//!
//! Hostile-input rules (CLAUDE.md invariant 5): every frame length is checked
//! against a hard cap before allocation, decode failures are errors (never
//! panics), and bincode runs with an explicit byte limit.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::vv::{NodeId, VersionVector};

/// Negotiated in `Hello`; mismatch closes the connection cleanly (FR-504).
/// M2 is a flag-day bump (chunked data plane, frontier Hello, per-origin
/// acks, reconcile sessions): v1 peers are refused. The mesh ships as a unit.
pub const PROTO_VERSION: u16 = 2;

/// ALPN identifier for every QUIC connection. Bumped with PROTO_VERSION so a
/// stale binary fails at the TLS layer, not mid-protocol.
pub const ALPN: &[u8] = b"replicore/2";

/// Hard cap for one control/fetch-header frame. Ops are small (path + vv);
/// anything near this size is hostile or a bug.
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB

/// What kind of mutation an op describes.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpType {
    Write,
    /// Tombstone, never a hard delete on the receiver (FR-204).
    Delete,
}

/// One replicated operation (FR-202): identity, origin, type, path, metadata
/// snapshot, content hash, version vector. `mtime`/xattr fidelity is M3.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OpRecord {
    /// Globally unique: `blake3(origin || origin_seq)` — see [`op_id`].
    pub op_id: [u8; 32],
    pub origin: NodeId,
    /// Origin node's monotonic sequence for this op (resume + ack cursor).
    pub origin_seq: i64,
    pub op_type: OpType,
    /// Path relative to the share root, '/' separators.
    pub path: String,
    /// Unix permission bits (full metadata fidelity is M3, FR-106).
    pub mode: u32,
    pub size: u64,
    /// BLAKE3 of the full content; `None` for deletes.
    pub content_hash: Option<[u8; 32]>,
    /// Per-file version vector at the time of the op (FR-301).
    pub vv: VersionVector,
}

/// Deterministic op identity (idempotency key, FR-802/901).
pub fn op_id(origin: &NodeId, origin_seq: i64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(origin);
    h.update(&origin_seq.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Control-stream frames.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Frame {
    /// Sent by the dialer. `resume` is the dialer's durable cursor frontier:
    /// one `(origin, cursor)` entry per origin whose ops it wants pushed
    /// ("push me ops with origin_seq > cursor"). In the M2 full mesh the
    /// listener reads only its own entry (it pushes only its own ops); the
    /// full map is the relay/designated-link seam (FR-603). The receiver's
    /// persisted cursor remains the resume authority (FR-503/801).
    Hello {
        proto_version: u16,
        node_id: NodeId,
        resume: Vec<(NodeId, i64)>,
    },
    /// Listener's reply; after this it starts pushing its ops.
    HelloAck {
        proto_version: u16,
        node_id: NodeId,
    },
    OplogPush(OpRecord),
    /// Contiguous per-origin ack: every `origin`-origin op with
    /// `origin_seq <= up_to_seq` is durably handled (persisted **before**
    /// this frame is sent — FR-801). In the M2 full mesh `origin` is always
    /// the pushing peer itself; the field exists for the relay seam.
    OplogAck {
        origin: NodeId,
        up_to_seq: i64,
    },
    /// Reconcile gate (FR-702): the dialer sends this after its anti-entropy
    /// session with the listener completes; the listener pushes NO ops before
    /// receiving it. A restarted node never trusts the live stream unreconciled.
    SubscribeOps,
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

// ---------------------------------------------------------------------------
// Ephemeral bi-streams. The initiator writes one tag byte, then framed
// messages; bulk chunk bytes are raw (never inside a frame).
// ---------------------------------------------------------------------------

pub const STREAM_TAG_CHUNK: u8 = 1;
pub const STREAM_TAG_MANIFEST: u8 = 2;
pub const STREAM_TAG_RECONCILE: u8 = 3;

/// One entry of a file manifest: a chunk's BLAKE3 and its length. Offsets are
/// implicit prefix sums — the ordered list fully determines the file.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkEntry {
    pub hash: [u8; 32],
    pub len: u32,
}

/// "Send me the chunk with this hash" (FR-401/403). Response: `ChunkResp`
/// header, then exactly `len` raw bytes. The receiver verifies BLAKE3 before
/// the chunk is trusted or stored — every path.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ChunkReq {
    pub hash: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ChunkResp {
    pub found: bool,
    pub len: u32,
}

/// Manifest page size: 4096 entries × 36 B ≈ 147 KiB per frame, far under
/// MAX_FRAME. Never raise MAX_FRAME for manifests — paginate.
pub const MANIFEST_PAGE: u32 = 4096;

/// "Send me a page of the manifest for this content hash."
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ManifestReq {
    pub content_hash: [u8; 32],
    pub offset: u32,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ManifestResp {
    pub found: bool,
    pub content_hash: [u8; 32],
    /// Total chunk count of the whole manifest (drives pagination).
    pub total: u32,
    pub chunks: Vec<ChunkEntry>,
}

/// Directory-children page size for reconcile descent. Names are ≤255 bytes
/// on Linux: 512 × ~300 B ≈ 150 KiB worst case per frame.
pub const TREE_PAGE: u32 = 512;

/// One child of a Merkle directory node.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WireChild {
    pub name: String,
    pub hash: [u8; 32],
    pub is_dir: bool,
}

/// Anti-entropy session messages (FR-701/703), request/response on one
/// ephemeral bi-stream. The initiator is the puller; descent only enters
/// subtrees whose hashes differ (O(diff) network cost).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum ReconcileFrame {
    Begin,
    RootIs {
        hash: [u8; 32],
    },
    /// Paginated children of a directory node, sorted by name, strictly after
    /// `after_name` (empty = from the start).
    TreeReq {
        prefix: String,
        after_name: String,
        limit: u32,
    },
    TreeResp {
        children: Vec<WireChild>,
        more: bool,
    },
    LeafReq {
        path: String,
    },
    /// `mode`/`size` ride along for the state upsert but are NOT part of the
    /// Merkle leaf hash (metadata fidelity is M3 — no flap on unreconciled
    /// fields).
    LeafResp {
        found: bool,
        tombstone: bool,
        content_hash: Option<[u8; 32]>,
        vv: VersionVector,
        mode: u32,
        size: u64,
    },
    Done,
}

// -- M1 leftovers, deleted with the chunked receive-path swap ----------------

/// SPIKE/M1-ONLY whole-file fetch; superseded by ChunkReq/ManifestReq.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FetchReq {
    pub hash: [u8; 32],
}

/// SPIKE/M1-ONLY.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FetchResp {
    pub found: bool,
    pub size: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum ProtoError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("encode: {0}")]
    Encode(#[source] bincode::Error),
    #[error("decode: {0}")]
    Decode(#[source] bincode::Error),
    #[error("peer closed the stream")]
    Closed,
}

/// Bincode options used on BOTH ends. `bincode::options()` defaults (varint)
/// differ from the free `bincode::serialize` (fixint) — never mix them.
fn opts() -> impl bincode::Options {
    use bincode::Options;
    bincode::options().with_limit(MAX_FRAME as u64)
}

/// Serialize `msg` and write it as one `u32`-BE-length-prefixed frame.
pub async fn write_msg<S, T>(stream: &mut S, msg: &T) -> Result<(), ProtoError>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    use bincode::Options;
    let body = opts().serialize(msg).map_err(ProtoError::Encode)?;
    if body.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge(body.len()));
    }
    // body.len() <= MAX_FRAME < u32::MAX, so the cast is lossless.
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

/// Read one length-prefixed frame and decode it. Returns `Closed` on a clean
/// EOF at a frame boundary; any other short read is an I/O error.
pub async fn read_msg<S, T>(stream: &mut S) -> Result<T, ProtoError>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    use bincode::Options;
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(ProtoError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::TooLarge(len)); // checked BEFORE allocating
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    opts().deserialize(&body).map_err(ProtoError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op() -> OpRecord {
        let origin = [7u8; 16];
        OpRecord {
            op_id: op_id(&origin, 42),
            origin,
            origin_seq: 42,
            op_type: OpType::Write,
            path: "a/b/c.wav".into(),
            mode: 0o644,
            size: 12345,
            content_hash: Some([9u8; 32]),
            vv: [(origin, 3u64)].into_iter().collect(),
        }
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let frames = vec![
            Frame::Hello {
                proto_version: PROTO_VERSION,
                node_id: [1u8; 16],
                resume: vec![([2u8; 16], 17), ([3u8; 16], 0)],
            },
            Frame::OplogPush(sample_op()),
            Frame::OplogAck {
                origin: [2u8; 16],
                up_to_seq: 42,
            },
            Frame::SubscribeOps,
            Frame::Ping { nonce: 7 },
        ];
        for f in &frames {
            write_msg(&mut a, f).await.unwrap();
        }
        for f in &frames {
            let got: Frame = read_msg(&mut b).await.unwrap();
            assert_eq!(&got, f);
        }
    }

    #[tokio::test]
    async fn fetch_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_msg(&mut a, &FetchReq { hash: [3u8; 32] })
            .await
            .unwrap();
        let got: FetchReq = read_msg(&mut b).await.unwrap();
        assert_eq!(got.hash, [3u8; 32]);
    }

    #[tokio::test]
    async fn oversize_length_rejected_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        use tokio::io::AsyncWriteExt;
        // Claim a 1 GiB frame; reader must bail on the header alone.
        a.write_all(&(1u32 << 30).to_be_bytes()).await.unwrap();
        let err = read_msg::<_, Frame>(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtoError::TooLarge(_)));
    }

    #[tokio::test]
    async fn truncated_stream_is_error_not_panic() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        use tokio::io::AsyncWriteExt;
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(&[0u8; 10]).await.unwrap();
        drop(a); // EOF mid-body
        let err = read_msg::<_, Frame>(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtoError::Io(_)));
    }

    #[tokio::test]
    async fn clean_eof_is_closed() {
        let (a, mut b) = tokio::io::duplex(4096);
        drop(a);
        let err = read_msg::<_, Frame>(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtoError::Closed));
    }

    #[tokio::test]
    async fn garbage_body_is_decode_error() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        use tokio::io::AsyncWriteExt;
        a.write_all(&4u32.to_be_bytes()).await.unwrap();
        a.write_all(&[0xff; 4]).await.unwrap();
        let err = read_msg::<_, Frame>(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtoError::Decode(_)));
    }

    #[tokio::test]
    async fn v2_stream_messages_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1 << 21);
        write_msg(&mut a, &ChunkReq { hash: [5; 32] })
            .await
            .unwrap();
        let got: ChunkReq = read_msg(&mut b).await.unwrap();
        assert_eq!(got.hash, [5; 32]);

        let mreq = ManifestReq {
            content_hash: [6; 32],
            offset: 4096,
            count: MANIFEST_PAGE,
        };
        write_msg(&mut a, &mreq).await.unwrap();
        assert_eq!(read_msg::<_, ManifestReq>(&mut b).await.unwrap(), mreq);

        let frames = vec![
            ReconcileFrame::Begin,
            ReconcileFrame::RootIs { hash: [7; 32] },
            ReconcileFrame::TreeReq {
                prefix: "a/b".into(),
                after_name: "c".into(),
                limit: TREE_PAGE,
            },
            ReconcileFrame::TreeResp {
                children: vec![WireChild {
                    name: "c.wav".into(),
                    hash: [8; 32],
                    is_dir: false,
                }],
                more: true,
            },
            ReconcileFrame::LeafReq {
                path: "a/b/c".into(),
            },
            ReconcileFrame::LeafResp {
                found: true,
                tombstone: false,
                content_hash: Some([9; 32]),
                vv: [([7u8; 16], 3u64)].into_iter().collect(),
                mode: 0o644,
                size: 123,
            },
            ReconcileFrame::Done,
        ];
        for f in &frames {
            write_msg(&mut a, f).await.unwrap();
        }
        for f in &frames {
            assert_eq!(&read_msg::<_, ReconcileFrame>(&mut b).await.unwrap(), f);
        }
    }

    #[tokio::test]
    async fn worst_case_pages_stay_under_max_frame() {
        // A full manifest page of 4096 entries...
        let resp = ManifestResp {
            found: true,
            content_hash: [1; 32],
            total: u32::MAX,
            chunks: vec![
                ChunkEntry {
                    hash: [0xff; 32],
                    len: u32::MAX,
                };
                MANIFEST_PAGE as usize
            ],
        };
        let (mut a, mut b) = tokio::io::duplex(1 << 21);
        write_msg(&mut a, &resp).await.unwrap(); // would error with TooLarge if over
        assert_eq!(read_msg::<_, ManifestResp>(&mut b).await.unwrap(), resp);

        // ...and a full tree page with maximum-length (255 B) names.
        let resp = ReconcileFrame::TreeResp {
            children: vec![
                WireChild {
                    name: "x".repeat(255),
                    hash: [0xff; 32],
                    is_dir: false,
                };
                TREE_PAGE as usize
            ],
            more: true,
        };
        write_msg(&mut a, &resp).await.unwrap();
        assert_eq!(read_msg::<_, ReconcileFrame>(&mut b).await.unwrap(), resp);
    }

    #[test]
    fn op_id_is_deterministic_and_distinct() {
        let a = op_id(&[1u8; 16], 1);
        assert_eq!(a, op_id(&[1u8; 16], 1));
        assert_ne!(a, op_id(&[1u8; 16], 2));
        assert_ne!(a, op_id(&[2u8; 16], 1));
    }
}
