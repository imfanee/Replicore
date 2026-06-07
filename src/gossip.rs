//! gossip.rs — lean SWIM-style roster dissemination (FR-1304).
//!
//! Membership changes are admin-signed entries; gossip just spreads them. The
//! exchange is **push-pull on a digest**: the initiator sends its roster
//! digest; if it matches the responder's, both are converged and nothing more
//! moves (the steady-state cost is one round trip of 32 bytes each way). On a
//! mismatch the two sides swap full roster snapshots and each merges the
//! other's through [`Membership::merge_signed`] — so every entry is
//! re-verified against the local admin key on receipt (announcement is not
//! authorization; a peer relaying entries cannot forge or alter them).
//!
//! Convergence is free: the roster merge is a join over a semilattice, so
//! exchanging full snapshots in either order, any number of times, lands both
//! replicas on the identical converged roster. Anti-entropy gossip therefore
//! needs no acks or ordering — only that mismatched peers eventually talk.
//!
//! SEAM: indirect ping-req (SWIM's failure-detector fan-out) is deferred; it
//! only matters off a full mesh. QUIC keep-alive + the dial supervisor already
//! detect dead connections here.

use serde::{Deserialize, Serialize};

use crate::membership::{Membership, MergeOutcome, SignedEntry};
use crate::proto::{read_msg, write_msg, ProtoError, STREAM_TAG_ROSTER};

#[derive(thiserror::Error, Debug)]
pub enum GossipError {
    #[error("transport: {0}")]
    Proto(#[from] ProtoError),
    #[error("connection: {0}")]
    Conn(#[from] quinn::ConnectionError),
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
}

/// Wire frames for one roster exchange. `Entries` is bounded by `MAX_FRAME` at
/// the transport (a hostile peer cannot make us allocate unboundedly), and
/// every entry is signature-checked on merge.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum GossipFrame {
    /// Initiator → responder: "here is my whole-roster digest."
    Digest { digest: [u8; 32] },
    /// Responder → initiator: digests matched; nothing to exchange.
    InSync,
    /// A full roster snapshot (winners incl. tombstones).
    Entries(Vec<SignedEntry>),
}

/// How many entries a single exchange admitted (verified + advanced state).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GossipReport {
    pub applied: usize,
}

/// Merge a batch of received entries, counting those that advanced state.
/// Forged or stale entries are silently dropped (merge_signed re-verifies).
/// A node without an admin key cannot merge anything (returns 0).
fn merge_batch(membership: &Membership, entries: Vec<SignedEntry>) -> usize {
    let mut applied = 0;
    for e in entries {
        if let Ok(MergeOutcome::Applied) = membership.merge_signed(e) {
            applied += 1;
        }
    }
    applied
}

/// Initiator side: open a tagged stream and run one exchange over `conn`.
/// No-op (Ok) when this node has no admin key — it has no roster to converge.
pub async fn gossip_once(
    membership: &Membership,
    conn: &quinn::Connection,
) -> Result<GossipReport, GossipError> {
    if !membership.has_admin_key() {
        return Ok(GossipReport::default());
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&[STREAM_TAG_ROSTER]).await?;

    write_msg(
        &mut send,
        &GossipFrame::Digest {
            digest: membership.roster_digest(),
        },
    )
    .await?;

    let applied = match read_msg::<_, GossipFrame>(&mut recv).await? {
        GossipFrame::InSync => 0,
        GossipFrame::Entries(theirs) => {
            // Pull their entries, then push ours so both converge.
            let applied = merge_batch(membership, theirs);
            write_msg(
                &mut send,
                &GossipFrame::Entries(membership.roster_snapshot()),
            )
            .await?;
            applied
        }
        GossipFrame::Digest { .. } => 0, // responder never re-sends a digest
    };
    let _ = send.finish();
    Ok(GossipReport { applied })
}

/// Responder side (dispatched from the ROSTER stream tag).
pub async fn serve_roster(
    membership: &Membership,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), GossipError> {
    match read_msg::<_, GossipFrame>(&mut recv).await? {
        GossipFrame::Digest { digest } => {
            if digest == membership.roster_digest() {
                write_msg(&mut send, &GossipFrame::InSync).await?;
            } else {
                // Push ours, then pull theirs and merge.
                write_msg(
                    &mut send,
                    &GossipFrame::Entries(membership.roster_snapshot()),
                )
                .await?;
                if let GossipFrame::Entries(theirs) = read_msg::<_, GossipFrame>(&mut recv).await? {
                    merge_batch(membership, theirs);
                }
            }
        }
        _ => return Ok(()), // protocol noise: drop the stream
    }
    let _ = send.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{generate_admin_key, sign_entry, AdminPubKey, AdminSecret, EntryKind};
    use crate::config::Config;
    use crate::vv::NodeId;
    use std::path::PathBuf;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn admin() -> (AdminSecret, AdminPubKey) {
        let (doc, pk) = generate_admin_key().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.sk");
        std::fs::write(&p, &doc).unwrap();
        let sk = AdminSecret::load(&p).unwrap();
        std::mem::forget(dir);
        (sk, pk)
    }

    fn entry(sk: &AdminSecret, node: u8, fp: u8, epoch: u64, kind: EntryKind) -> SignedEntry {
        let n = nid(node);
        let a = format!("10.0.0.{node}:7000").parse().unwrap();
        let f = [fp; 32];
        let sig = sign_entry(sk, &n, &a, &f, epoch, kind);
        SignedEntry {
            node_id: n,
            addr: a,
            fingerprint: f,
            epoch,
            kind,
            sig,
        }
    }

    fn membership_with(pk: AdminPubKey, roster_path: PathBuf) -> Membership {
        let mut cfg = Config::from_toml_str(
            r#"
            node_id   = "000102030405060708090a0b0c0d0e0f"
            listen    = "10.0.0.1:7000"
            share_dir = "/srv/a"
            db_path   = "/var/lib/replicore/a.db"
            cert_path = "/etc/replicore/a.cert.pem"
            key_path  = "/etc/replicore/a.key.pem"
            "#,
        )
        .unwrap();
        cfg.admin_pubkey = Some(pk);
        cfg.roster_path = roster_path;
        Membership::load(&cfg).unwrap()
    }

    #[test]
    fn merge_batch_converges_and_rejects_forgeries() {
        let (sk, pk) = admin();
        let dir = tempfile::tempdir().unwrap();
        let m = membership_with(pk, dir.path().join("r.json"));

        // A forged entry (signed by a DIFFERENT admin) interleaved with good
        // ones must be dropped while the good ones still apply.
        let (forger, _) = admin();
        let batch = vec![
            entry(&sk, 2, 2, 1, EntryKind::Add),
            entry(&forger, 9, 9, 1, EntryKind::Add), // forgery
            entry(&sk, 3, 3, 1, EntryKind::Add),
        ];
        assert_eq!(merge_batch(&m, batch.clone()), 2);
        assert_eq!(m.effective_peers().len(), 2); // node 9 never entered

        // Re-merging is idempotent (the join's defining property).
        assert_eq!(merge_batch(&m, batch), 0);
        assert_eq!(m.effective_peers().len(), 2);
    }
}
