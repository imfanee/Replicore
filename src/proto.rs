//! proto.rs — minimal wire format for the M0 spike.
//!
//! Phase 1+ will replace this single self-describing message with the versioned,
//! length-prefixed control protocol from the RSD (HELLO / OPLOG_PUSH / MANIFEST /
//! CHUNK_REQ / CHUNK_DATA / WANT / TREE_NODE). For M0 we ship one whole file per
//! QUIC uni-stream as a single bincoded message. Fine for write-once recordings;
//! large files get chunked streaming in Phase 2 (FR-402/403).

use serde::{Deserialize, Serialize};

/// ALPN identifier negotiated on every QUIC connection. Bumping this is the
/// crude M0 stand-in for FR-504 protocol-version negotiation.
pub const ALPN: &[u8] = b"replicore/0";

/// One file, whole, with just enough metadata for an atomic, verified apply.
#[derive(Serialize, Deserialize, Debug)]
pub struct FileMsg {
    /// Path relative to the share root, using '/' separators.
    pub rel_path: String,
    /// Unix mode bits (permissions). Full metadata fidelity (uid/gid/xattr/ACL)
    /// is Phase 3 (FR-106); M0 carries mode only.
    pub mode: u32,
    /// BLAKE3 of `data`, verified on the receiver before the atomic rename.
    pub hash: [u8; 32],
    /// File contents.
    pub data: Vec<u8>,
}
