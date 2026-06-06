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
pub const PROTO_VERSION: u16 = 1;

/// ALPN identifier for every QUIC connection.
pub const ALPN: &[u8] = b"replicore/1";

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
    /// Sent by the dialer. `resume_from` is the dialer's durable cursor of the
    /// listener's ops ("push me your ops with origin_seq > this"). The
    /// receiver's persisted cursor is the resume authority (FR-503/801).
    Hello {
        proto_version: u16,
        node_id: NodeId,
        resume_from: i64,
    },
    /// Listener's reply; after this it starts pushing its ops.
    HelloAck {
        proto_version: u16,
        node_id: NodeId,
    },
    OplogPush(OpRecord),
    /// Contiguous ack: every op with `origin_seq <= up_to_seq` is durably
    /// handled (persisted **before** this frame is sent — FR-801).
    OplogAck {
        up_to_seq: i64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

/// Opens an ephemeral bi-stream: "send me the content with this hash".
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FetchReq {
    pub hash: [u8; 32],
}

/// Header on the fetch response stream; `size` raw bytes follow when `found`.
/// The receiver verifies BLAKE3 over the bytes before using them.
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
                resume_from: 17,
            },
            Frame::OplogPush(sample_op()),
            Frame::OplogAck { up_to_seq: 42 },
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

    #[test]
    fn op_id_is_deterministic_and_distinct() {
        let a = op_id(&[1u8; 16], 1);
        assert_eq!(a, op_id(&[1u8; 16], 1));
        assert_ne!(a, op_id(&[1u8; 16], 2));
        assert_ne!(a, op_id(&[2u8; 16], 1));
    }
}
