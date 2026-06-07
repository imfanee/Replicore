//! membership.rs — the agent-owned roster (mandate 2, FR-1302/1303/1306).
//!
//! ## What this is (own the honest semantics)
//!
//! This is **NOT** a general OR-Set. It is an **epoch-versioned last-writer-wins
//! membership register**: exactly one winning [`SignedEntry`] per `node_id`,
//! chosen by a total order over `(epoch, rank(kind), content_hash)`. That order
//! is a join-semilattice — `merge` is commutative, associative, and idempotent —
//! so replicas that have seen the same set of entries converge to a
//! byte-identical roster regardless of arrival order or duplication. That is
//! exactly what FR-1303 ("membership converges, never diverges") demands; we do
//! not need OR-Set add/remove-tag bookkeeping because a node is a single keyed
//! register, not an arbitrary growing set.
//!
//! ## Merge rule (LAW)
//!
//! For a given `node_id`, the winner is the entry maximising
//! `(epoch, rank(kind), content_hash)` where:
//!   - `rank(Remove) = 1 > rank(Add) = 0` — at equal epoch a Remove beats an Add
//!     (anti-resurrection: a stale lower/equal-epoch Add can never displace a
//!     tombstone);
//!   - `content_hash = blake3(canonical_entry_bytes)` — the deterministic
//!     tie-break. It is hashed over the **canonical bytes, NEVER the signature**:
//!     signatures from different admin sessions over identical content differ,
//!     and ordering by them would diverge rosters across nodes.
//!
//! Tombstones (winning Removes) are retained forever. Re-adding a removed node
//! is an explicit higher-epoch Add ([`Roster::next_epoch_for`] returns `max+1`).
//!
//! ## Trust (mandate 3)
//!
//! [`Roster::merge_entry`] is the SINGLE insertion choke point and ALWAYS
//! verifies the signature against the supplied admin pubkey before the entry can
//! touch state. Announcement is not authorization: gossip, control-plane
//! `member add/remove`, on-connect push, and roster-file load all funnel through
//! here, so every node independently re-verifies every entry against its own
//! intent's `admin_pubkey`. A compromised peer holds no admin secret and so can
//! forge nothing.
//!
//! ## Persistence (FR-1302)
//!
//! The roster is daemon-owned and lives at `roster_path` (default
//! `<db>.roster.json`), serialised with serde_json and saved atomically
//! (tmp → fsync → rename → fsync dir). The daemon NEVER writes the intent file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::admin::{canonical_entry_bytes, verify_entry, AdminPubKey, EntryKind};
use crate::config::{Config, Peer};
use crate::vv::NodeId;

#[derive(thiserror::Error, Debug)]
pub enum RosterError {
    #[error("{ctx}: {source}")]
    Io {
        ctx: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("roster file is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// One admin-signed membership mutation. Serde form is the on-disk / on-wire
/// representation; the signature and hash are always computed over
/// [`canonical_entry_bytes`], not this serde encoding.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedEntry {
    #[serde(with = "hex16")]
    pub node_id: NodeId,
    pub addr: SocketAddr,
    #[serde(with = "hex32")]
    pub fingerprint: [u8; 32],
    pub epoch: u64,
    pub kind: EntryKind,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

impl SignedEntry {
    /// The bytes the signature covers and the tie-break hash is taken over.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_entry_bytes(
            &self.node_id,
            &self.addr,
            &self.fingerprint,
            self.epoch,
            self.kind,
        )
    }

    fn content_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// The total-order key. Larger wins. Tuple ordering is lexicographic:
    /// epoch dominates, then Remove-over-Add at equal epoch, then content hash.
    fn order_key(&self) -> (u64, u8, [u8; 32]) {
        let rank = match self.kind {
            EntryKind::Add => 0,
            EntryKind::Remove => 1,
        };
        (self.epoch, rank, self.content_hash())
    }

    fn verify(&self, pk: &AdminPubKey) -> bool {
        verify_entry(
            pk,
            &self.node_id,
            &self.addr,
            &self.fingerprint,
            self.epoch,
            self.kind,
            &self.sig,
        )
    }
}

/// Outcome of feeding one entry through the choke point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MergeOutcome {
    /// Entry verified and became (or already was) the winner — state advanced.
    Applied,
    /// Entry verified but is stale or a tie with the current winner — ignored.
    Superseded,
    /// Signature did not verify against the admin pubkey — rejected, not stored.
    Rejected,
}

/// The converged set of membership winners, one per node_id (Adds and tombstoned
/// Removes alike). `BTreeMap` keying gives a deterministic iteration order for
/// the digest without an extra sort.
#[derive(Clone, Default, Debug)]
pub struct Roster {
    entries: BTreeMap<NodeId, SignedEntry>,
}

impl Roster {
    pub fn new() -> Roster {
        Roster {
            entries: BTreeMap::new(),
        }
    }

    /// THE single insertion choke point (LAW). Verifies the signature against
    /// `pk` first; then applies the merge rule. Returns whether state advanced.
    pub fn merge_entry(&mut self, entry: SignedEntry, pk: &AdminPubKey) -> MergeOutcome {
        if !entry.verify(pk) {
            return MergeOutcome::Rejected;
        }
        match self.entries.get(&entry.node_id) {
            Some(cur) if cur.order_key() >= entry.order_key() => MergeOutcome::Superseded,
            _ => {
                self.entries.insert(entry.node_id, entry);
                MergeOutcome::Applied
            }
        }
    }

    /// The winning entry for a node, if any (Add or Remove).
    pub fn get(&self, node_id: &NodeId) -> Option<&SignedEntry> {
        self.entries.get(node_id)
    }

    /// Members whose current winner is an Add (the live membership).
    pub fn effective_members(&self) -> impl Iterator<Item = &SignedEntry> {
        self.entries.values().filter(|e| e.kind == EntryKind::Add)
    }

    /// Every winner including tombstones — what gets persisted and gossiped.
    pub fn all_entries(&self) -> impl Iterator<Item = &SignedEntry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Epoch to use when an admin issues the NEXT mutation for `node_id`:
    /// strictly above the current winner so the new entry can win (a re-add
    /// after a Remove must clear the tombstone's epoch). 1 for an unknown node.
    pub fn next_epoch_for(&self, node_id: &NodeId) -> u64 {
        self.entries.get(node_id).map(|e| e.epoch + 1).unwrap_or(1)
    }

    /// Order-independent fingerprint of the whole roster (gossip digest). Equal
    /// digests ⇒ identical converged state. Built from canonical bytes in
    /// node_id order — never from serde or signatures.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"replicore-roster-digest-v1\0");
        for entry in self.entries.values() {
            hasher.update(&entry.canonical_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Load from disk, re-verifying every entry against the CURRENT admin
    /// pubkey. Entries that fail verification are dropped (key rotation evicts
    /// entries signed by a retired admin key) and reported in the count.
    /// A missing file is an empty roster, not an error.
    pub fn load(path: &Path, pk: &AdminPubKey) -> Result<(Roster, usize), RosterError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Roster::new(), 0)),
            Err(source) => {
                return Err(RosterError::Io {
                    ctx: "read roster",
                    source,
                })
            }
        };
        let disk: Vec<SignedEntry> = serde_json::from_slice(&bytes)?;
        let mut roster = Roster::new();
        let mut dropped = 0usize;
        for entry in disk {
            // Funnel through the choke point so load can never admit anything
            // gossip/control couldn't. Duplicate/stale rows merge harmlessly.
            if roster.merge_entry(entry, pk) == MergeOutcome::Rejected {
                dropped += 1;
            }
        }
        Ok((roster, dropped))
    }

    /// Persist atomically: write a sibling temp, fsync it, rename over the
    /// target, fsync the directory. Never leaves a torn roster on a crash.
    pub fn save(&self, path: &Path) -> Result<(), RosterError> {
        let entries: Vec<&SignedEntry> = self.entries.values().collect();
        let json = serde_json::to_vec_pretty(&entries)?;

        let tmp = tmp_sibling(path);
        write_fsync(&tmp, &json).map_err(|source| RosterError::Io {
            ctx: "write roster temp",
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| RosterError::Io {
            ctx: "rename roster",
            source,
        })?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fsync_dir(dir).map_err(|source| RosterError::Io {
                ctx: "fsync roster dir",
                source,
            })?;
        }
        Ok(())
    }
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn write_fsync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

// serde helpers — fixed-width byte arrays as hex strings (serde's blanket array
// impls stop at 32, and hex keeps the JSON human-auditable).
mod hex16 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

// ---------------------------------------------------------------------------
// Membership — the runtime handle over the roster + derived views
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum MembershipError {
    #[error("no [trust] admin_pubkey configured; membership changes are refused")]
    NoAdminKey,
    #[error(transparent)]
    Roster(#[from] RosterError),
}

/// The agent-owned membership state, shared across the engine, supervisor,
/// gossip, and control plane. Cheap to clone (all state behind `Arc`).
///
/// Three derived views are kept in lockstep and recomputed on every change:
/// - `roster` — the converged signed entries (persisted).
/// - `effective` — `seeds ∪ roster Adds − roster Removes`, the dial targets.
/// - `allowlist` — the effective peers' fingerprints, read PER HANDSHAKE by the
///   TLS verifiers (a removed peer is locked out without rebuilding the QUIC
///   endpoint).
///
/// `RwLock` (std, not tokio) is deliberate: every critical section is a quick
/// in-memory read/swap with no `.await` held, and the TLS verifier that reads
/// `allowlist` is a synchronous rustls callback.
///
/// All mutable state lives behind a single `Arc<Inner>` so a `config reload`
/// (which swaps seeds/admin key and re-verifies the roster) is visible through
/// every clone — the running verifiers, supervisor, and gossip all observe it.
#[derive(Clone)]
pub struct Membership {
    inner: Arc<Inner>,
}

struct Inner {
    our_node_id: NodeId,
    admin_pubkey: RwLock<Option<AdminPubKey>>,
    roster_path: RwLock<PathBuf>,
    seeds: RwLock<Vec<Peer>>,
    roster: RwLock<Roster>,
    effective: RwLock<HashMap<NodeId, Peer>>,
    allowlist: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Bumped on every applied change; the supervisor watches it.
    changed: watch::Sender<u64>,
}

impl Membership {
    /// Build from intent config: load+re-verify the roster from disk under the
    /// configured admin key, then compute the effective set and allowlist.
    /// A roster signed by a now-rotated key is dropped on load (reported).
    pub fn load(cfg: &Config) -> Result<Membership, MembershipError> {
        let roster = load_roster(cfg)?;
        let (changed, _) = watch::channel(0);
        let m = Membership {
            inner: Arc::new(Inner {
                our_node_id: cfg.node_id,
                admin_pubkey: RwLock::new(cfg.admin_pubkey.clone()),
                roster_path: RwLock::new(cfg.roster_path.clone()),
                seeds: RwLock::new(cfg.peers.clone()),
                roster: RwLock::new(roster),
                effective: RwLock::new(HashMap::new()),
                allowlist: Arc::new(RwLock::new(HashSet::new())),
                changed,
            }),
        };
        m.recompute();
        Ok(m)
    }

    /// Recompute `effective` and `allowlist` from `seeds` + the roster.
    /// Seeds first, then roster Adds override and Removes drop — signed intent
    /// beats a static seed; a signed Remove evicts even a seeded node.
    fn recompute(&self) {
        let mut eff: HashMap<NodeId, Peer> = HashMap::new();
        for seed in self.inner.seeds.read().expect("seeds lock").iter() {
            eff.insert(seed.node_id, seed.clone());
        }
        {
            let roster = self.inner.roster.read().expect("roster lock");
            for entry in roster.all_entries() {
                if entry.node_id == self.inner.our_node_id {
                    continue; // never dial or pin ourselves
                }
                match entry.kind {
                    EntryKind::Add => {
                        eff.insert(
                            entry.node_id,
                            Peer {
                                node_id: entry.node_id,
                                addr: entry.addr,
                                fingerprint: entry.fingerprint,
                            },
                        );
                    }
                    EntryKind::Remove => {
                        eff.remove(&entry.node_id);
                    }
                }
            }
        }
        let allow: HashSet<[u8; 32]> = eff.values().map(|p| p.fingerprint).collect();
        *self.inner.effective.write().expect("effective lock") = eff;
        *self.inner.allowlist.write().expect("allowlist lock") = allow;
    }

    /// Persist the roster atomically (daemon-owned file; the intent file is
    /// never touched). Snapshots under the lock, writes outside it.
    fn persist(&self) -> Result<(), RosterError> {
        let snapshot = self.inner.roster.read().expect("roster lock").clone();
        let path = self.inner.roster_path.read().expect("path lock").clone();
        snapshot.save(&path)
    }

    /// THE mutation entry point for control/gossip/on-connect push: verify and
    /// merge one signed entry, then (if state advanced) recompute the views,
    /// persist, and notify the supervisor. Returns the merge outcome.
    pub fn merge_signed(&self, entry: SignedEntry) -> Result<MergeOutcome, MembershipError> {
        let outcome = {
            let pk_guard = self.inner.admin_pubkey.read().expect("admin lock");
            let pk = pk_guard.as_ref().ok_or(MembershipError::NoAdminKey)?;
            self.inner
                .roster
                .write()
                .expect("roster lock")
                .merge_entry(entry, pk)
        };
        if outcome == MergeOutcome::Applied {
            self.recompute();
            self.persist()?;
            self.inner.changed.send_modify(|v| *v = v.wrapping_add(1));
        }
        Ok(outcome)
    }

    /// Re-apply intent on `config reload` (FR-1406): swap seeds + admin key,
    /// re-verify the roster under the (possibly rotated) key, recompute. The
    /// caller has already validated the candidate, so this cannot half-apply.
    pub fn apply_reload(&self, cfg: &Config) -> Result<(), MembershipError> {
        let roster = load_roster(cfg)?;
        *self.inner.admin_pubkey.write().expect("admin lock") = cfg.admin_pubkey.clone();
        *self.inner.roster_path.write().expect("path lock") = cfg.roster_path.clone();
        *self.inner.seeds.write().expect("seeds lock") = cfg.peers.clone();
        *self.inner.roster.write().expect("roster lock") = roster;
        self.recompute();
        self.inner.changed.send_modify(|v| *v = v.wrapping_add(1));
        Ok(())
    }

    /// The current dial targets (effective members minus ourselves).
    pub fn effective_peers(&self) -> Vec<Peer> {
        self.inner
            .effective
            .read()
            .expect("effective lock")
            .values()
            .cloned()
            .collect()
    }

    /// Shared fingerprint allowlist handle for the TLS verifiers (read live).
    pub fn allowlist_handle(&self) -> Arc<RwLock<HashSet<[u8; 32]>>> {
        self.inner.allowlist.clone()
    }

    /// Map an authenticated cert fingerprint to its effective peer.
    pub fn peer_by_fingerprint(&self, fp: &[u8; 32]) -> Option<Peer> {
        self.inner
            .effective
            .read()
            .expect("effective lock")
            .values()
            .find(|p| &p.fingerprint == fp)
            .cloned()
    }

    /// Every roster winner (Adds + tombstones) — gossip payload / status.
    pub fn roster_snapshot(&self) -> Vec<SignedEntry> {
        self.inner
            .roster
            .read()
            .expect("roster lock")
            .all_entries()
            .cloned()
            .collect()
    }

    pub fn roster_digest(&self) -> [u8; 32] {
        self.inner.roster.read().expect("roster lock").digest()
    }

    pub fn next_epoch_for(&self, node_id: &NodeId) -> u64 {
        self.inner
            .roster
            .read()
            .expect("roster lock")
            .next_epoch_for(node_id)
    }

    /// True iff a trust anchor is configured (dynamic membership enabled).
    pub fn has_admin_key(&self) -> bool {
        self.inner
            .admin_pubkey
            .read()
            .expect("admin lock")
            .is_some()
    }

    /// Watch for membership changes (the supervisor reconciles dial loops).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }
}

/// Load + re-verify the roster under the config's admin key (empty if none).
fn load_roster(cfg: &Config) -> Result<Roster, MembershipError> {
    match &cfg.admin_pubkey {
        Some(pk) => {
            let (r, dropped) = Roster::load(&cfg.roster_path, pk)?;
            if dropped > 0 {
                tracing::warn!(dropped, "dropped roster entries failing admin-key verify");
            }
            Ok(r)
        }
        // No trust anchor: static-peer mode. The roster file is ignored (we
        // cannot verify it); only seeds form the mesh.
        None => Ok(Roster::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{generate_admin_key, sign_entry, AdminSecret};

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        format!("10.0.0.1:{port}").parse().unwrap()
    }

    fn make(
        sk: &AdminSecret,
        node: u8,
        port: u16,
        fp: u8,
        epoch: u64,
        kind: EntryKind,
    ) -> SignedEntry {
        let n = nid(node);
        let a = addr(port);
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

    fn admin() -> (AdminSecret, AdminPubKey) {
        let (doc, pk) = generate_admin_key().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.sk");
        std::fs::write(&p, &doc).unwrap();
        // Leak the tempdir for the test's lifetime by keeping the key bytes.
        let sk = AdminSecret::load(&p).unwrap();
        std::mem::forget(dir);
        (sk, pk)
    }

    #[test]
    fn add_then_remove_then_stale_add_never_resurrects() {
        let (sk, pk) = admin();
        let mut r = Roster::new();
        assert_eq!(r.next_epoch_for(&nid(1)), 1);

        assert_eq!(
            r.merge_entry(make(&sk, 1, 7000, 1, 1, EntryKind::Add), &pk),
            MergeOutcome::Applied
        );
        assert_eq!(r.effective_members().count(), 1);

        let remove_epoch = r.next_epoch_for(&nid(1));
        assert_eq!(remove_epoch, 2);
        assert_eq!(
            r.merge_entry(make(&sk, 1, 7000, 1, 2, EntryKind::Remove), &pk),
            MergeOutcome::Applied
        );
        assert_eq!(r.effective_members().count(), 0);

        // A replayed Add at the original (lower) epoch must not bring it back.
        assert_eq!(
            r.merge_entry(make(&sk, 1, 7000, 1, 1, EntryKind::Add), &pk),
            MergeOutcome::Superseded
        );
        // Even an Add at the SAME epoch as the Remove loses (Remove outranks).
        assert_eq!(
            r.merge_entry(make(&sk, 1, 7000, 1, 2, EntryKind::Add), &pk),
            MergeOutcome::Superseded
        );
        assert_eq!(r.effective_members().count(), 0);

        // A genuine re-add at a higher epoch wins.
        let re = r.next_epoch_for(&nid(1));
        assert_eq!(re, 3);
        assert_eq!(
            r.merge_entry(make(&sk, 1, 7000, 1, 3, EntryKind::Add), &pk),
            MergeOutcome::Applied
        );
        assert_eq!(r.effective_members().count(), 1);
    }

    #[test]
    fn forged_signature_never_enters() {
        let (sk, _pk) = admin();
        let (_, other_pk) = generate_admin_key().unwrap();
        let mut r = Roster::new();
        // Signed by the real admin but verified against a different anchor.
        let entry = make(&sk, 1, 7000, 1, 1, EntryKind::Add);
        assert_eq!(r.merge_entry(entry, &other_pk), MergeOutcome::Rejected);
        assert!(r.is_empty());
    }

    #[test]
    fn merge_is_order_independent_and_idempotent() {
        let (sk, pk) = admin();
        let entries = vec![
            make(&sk, 1, 7000, 1, 1, EntryKind::Add),
            make(&sk, 2, 7000, 2, 1, EntryKind::Add),
            make(&sk, 1, 7000, 1, 2, EntryKind::Remove),
            make(&sk, 3, 7000, 3, 1, EntryKind::Add),
            make(&sk, 2, 7001, 2, 3, EntryKind::Add), // re-add node 2 elsewhere
        ];

        // Forward, reversed, and with every entry applied twice → same digest.
        let mut a = Roster::new();
        for e in &entries {
            a.merge_entry(e.clone(), &pk);
        }
        let mut b = Roster::new();
        for e in entries.iter().rev() {
            b.merge_entry(e.clone(), &pk);
        }
        let mut c = Roster::new();
        for e in entries.iter().chain(entries.iter()) {
            c.merge_entry(e.clone(), &pk);
        }
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest(), c.digest());
    }

    #[test]
    fn persistence_round_trip_reverifies() {
        let (sk, pk) = admin();
        let mut r = Roster::new();
        r.merge_entry(make(&sk, 1, 7000, 1, 1, EntryKind::Add), &pk);
        r.merge_entry(make(&sk, 2, 7000, 2, 1, EntryKind::Add), &pk);
        r.merge_entry(make(&sk, 2, 7000, 2, 2, EntryKind::Remove), &pk);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roster.json");
        r.save(&path).unwrap();

        let (loaded, dropped) = Roster::load(&path, &pk).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(loaded.digest(), r.digest());

        // Under a rotated admin key, none of the on-disk entries verify.
        let (_, rotated) = generate_admin_key().unwrap();
        let (loaded2, dropped2) = Roster::load(&path, &rotated).unwrap();
        assert_eq!(dropped2, 2); // node1 add + node2 tombstone
        assert!(loaded2.is_empty());
    }

    #[test]
    fn missing_roster_file_is_empty() {
        let (_, pk) = admin();
        let (r, dropped) =
            Roster::load(Path::new("/nonexistent/replicore.roster.json"), &pk).unwrap();
        assert!(r.is_empty());
        assert_eq!(dropped, 0);
    }

    // --- Membership runtime handle ---

    fn cfg_with(pk: Option<AdminPubKey>, roster_path: PathBuf, seeds: Vec<Peer>) -> Config {
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
        cfg.admin_pubkey = pk;
        cfg.roster_path = roster_path;
        cfg.peers = seeds;
        cfg
    }

    fn peer(node: u8, port: u16, fp: u8) -> Peer {
        Peer {
            node_id: nid(node),
            addr: addr(port),
            fingerprint: [fp; 32],
        }
    }

    #[test]
    fn membership_seeds_only_with_no_roster() {
        let dir = tempfile::tempdir().unwrap();
        let seeds = vec![peer(1, 7000, 1), peer(2, 7000, 2)];
        let m = Membership::load(&cfg_with(None, dir.path().join("r.json"), seeds)).unwrap();
        assert_eq!(m.effective_peers().len(), 2);
        let allow = m.allowlist_handle();
        let allow = allow.read().unwrap();
        assert!(allow.contains(&[1; 32]) && allow.contains(&[2; 32]));
    }

    #[tokio::test]
    async fn membership_add_then_remove_updates_views_and_persists() {
        let (sk, pk) = admin();
        let dir = tempfile::tempdir().unwrap();
        let rpath = dir.path().join("r.json");
        // Seed node 1; admin-add node 2, then admin-remove the SEED node 1.
        let m = Membership::load(&cfg_with(
            Some(pk.clone()),
            rpath.clone(),
            vec![peer(1, 7000, 1)],
        ))
        .unwrap();

        let add2 = make(&sk, 2, 7000, 2, 1, EntryKind::Add);
        assert_eq!(m.merge_signed(add2).unwrap(), MergeOutcome::Applied);
        // Effective now has both; allowlist gained node 2's fingerprint.
        assert_eq!(m.effective_peers().len(), 2);
        assert!(m.allowlist_handle().read().unwrap().contains(&[2; 32]));
        assert!(m.peer_by_fingerprint(&[2; 32]).is_some());

        // A signed Remove evicts the SEED (signed intent beats a static seed).
        let rm1 = make(
            &sk,
            1,
            7000,
            1,
            m.next_epoch_for(&nid(1)),
            EntryKind::Remove,
        );
        assert_eq!(m.merge_signed(rm1).unwrap(), MergeOutcome::Applied);
        let eff = m.effective_peers();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].node_id, nid(2));
        // Allowlist no longer admits the removed seed.
        assert!(!m.allowlist_handle().read().unwrap().contains(&[1; 32]));

        // Persisted: a fresh load reproduces the same effective set.
        let m2 = Membership::load(&cfg_with(Some(pk), rpath, vec![peer(1, 7000, 1)])).unwrap();
        assert_eq!(m2.effective_peers().len(), 1);
        assert!(!m2.allowlist_handle().read().unwrap().contains(&[1; 32]));
    }

    #[test]
    fn membership_refuses_changes_without_admin_key() {
        let (sk, _) = admin();
        let dir = tempfile::tempdir().unwrap();
        let m = Membership::load(&cfg_with(None, dir.path().join("r.json"), vec![])).unwrap();
        let entry = make(&sk, 2, 7000, 2, 1, EntryKind::Add);
        assert!(matches!(
            m.merge_signed(entry),
            Err(MembershipError::NoAdminKey)
        ));
    }

    #[tokio::test]
    async fn membership_change_notifies_subscribers() {
        let (sk, pk) = admin();
        let dir = tempfile::tempdir().unwrap();
        let m = Membership::load(&cfg_with(Some(pk), dir.path().join("r.json"), vec![])).unwrap();
        let rx = m.subscribe();
        m.merge_signed(make(&sk, 2, 7000, 2, 1, EntryKind::Add))
            .unwrap();
        assert!(rx.has_changed().unwrap());
    }
}
