//! Membership control-plane integration tests (M2.5 AC 8–12), exercised with
//! real in-process engines over localhost QUIC — no netns rig, so these run in
//! plain `cargo test`. Each test drives the SAME code paths the operator does:
//! it signs entries with the cluster admin key and feeds them through
//! `Membership::merge_signed` (exactly what the control plane does on
//! `replicorectl member add/remove`), then watches the supervisor + gossip
//! converge the mesh.
//!
//!   AC8  dynamic_add_brings_a_node_into_the_data_path
//!   AC9  signed_remove_locks_a_node_out
//!   AC10 gossip_propagates_an_add_to_a_third_node
//!   AC11 forged_membership_change_is_rejected
//!   AC12 removing_one_node_does_not_disrupt_another_link

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use replicore::admin::{generate_admin_key, sign_entry, AdminPubKey, AdminSecret, EntryKind};
use replicore::chunk::{Cas, Manifest};
use replicore::config::{Config, Peer};
use replicore::membership::{Membership, MergeOutcome, SignedEntry};
use replicore::net::{generate_identity, Engine};
use replicore::oplog::{LocalChange, Store};
use replicore::proto::{ChunkEntry, OpType};
use replicore::suppress::Suppressor;
use replicore::vv::NodeId;

/// Grab a free UDP port (QUIC is UDP). Small TOCTOU window, fine for tests.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn nid(b: u8) -> NodeId {
    let mut id = [0u8; 16];
    id[0] = b;
    id
}

/// The cluster admin keypair, shared by all nodes' intent files; the secret is
/// held only here (as `replicorectl` would).
struct Admin {
    sk: AdminSecret,
    pk: AdminPubKey,
}

fn admin() -> Admin {
    let (doc, pk) = generate_admin_key().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("admin.sk");
    std::fs::write(&p, &doc).unwrap();
    let sk = AdminSecret::load(&p).unwrap();
    std::mem::forget(dir);
    Admin { sk, pk }
}

struct Node {
    id: NodeId,
    addr: SocketAddr,
    fingerprint: [u8; 32],
    engine: Arc<Engine>,
    store: Store,
    cas: Cas,
    _dir: tempfile::TempDir,
}

impl Node {
    /// Build and START a node (engine.run spawned): listening, dialing, gossiping.
    fn start(id: NodeId, pk: &AdminPubKey, seeds: &[&Node]) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let ident = generate_identity().unwrap();
        let cert_path = dir.path().join("c.pem");
        let key_path = dir.path().join("k.pem");
        std::fs::write(&cert_path, &ident.cert_pem).unwrap();
        std::fs::write(&key_path, &ident.key_pem).unwrap();
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let mut cfg = Config::from_toml_str(
            r#"
            node_id   = "000102030405060708090a0b0c0d0e0f"
            listen    = "127.0.0.1:1"
            share_dir = "/tmp"
            db_path   = "/tmp/x.db"
            cert_path = "/tmp/c.pem"
            key_path  = "/tmp/k.pem"
            "#,
        )
        .unwrap();
        cfg.node_id = id;
        cfg.listen = addr;
        cfg.share_dir = share;
        cfg.db_path = dir.path().join("db");
        cfg.cas_dir = dir.path().join("cas");
        cfg.cert_path = cert_path;
        cfg.key_path = key_path;
        cfg.roster_path = dir.path().join("roster.json");
        cfg.control_socket = dir.path().join("ctl.sock");
        cfg.admin_pubkey = Some(pk.clone());
        cfg.reconcile_interval_secs = 1;
        cfg.peers = seeds
            .iter()
            .map(|s| Peer {
                node_id: s.id,
                addr: s.addr,
                fingerprint: s.fingerprint,
            })
            .collect();

        let store = Store::open(&cfg.db_path, id).unwrap();
        let cas = Cas::open(&cfg.cas_dir).unwrap();
        let membership = Membership::load(&cfg).unwrap();
        let engine = Engine::new(
            cfg,
            store.clone(),
            Suppressor::new(),
            cas.clone(),
            membership,
        );
        tokio::spawn(engine.clone().run());

        Node {
            id,
            addr,
            fingerprint: ident.fingerprint,
            engine,
            store,
            cas,
            _dir: dir,
        }
    }

    /// What `replicorectl member add <node> ...` does: sign an Add for `target`
    /// at THIS node's roster and merge it (gossip then spreads it).
    fn admin_add(&self, admin: &Admin, target: &Node) -> MergeOutcome {
        self.submit(
            admin,
            target.id,
            target.addr,
            target.fingerprint,
            EntryKind::Add,
        )
    }

    fn admin_remove(&self, admin: &Admin, target: &Node) -> MergeOutcome {
        self.submit(
            admin,
            target.id,
            target.addr,
            target.fingerprint,
            EntryKind::Remove,
        )
    }

    fn submit(
        &self,
        admin: &Admin,
        node: NodeId,
        addr: SocketAddr,
        fp: [u8; 32],
        kind: EntryKind,
    ) -> MergeOutcome {
        let m = self.engine.membership();
        let epoch = m.next_epoch_for(&node);
        let sig = sign_entry(&admin.sk, &node, &addr, &fp, epoch, kind);
        let entry = SignedEntry {
            node_id: node,
            addr,
            fingerprint: fp,
            epoch,
            kind,
            sig,
        };
        m.merge_signed(entry).unwrap()
    }

    /// Stage a local write (CAS + manifest + op) the way ingest would, so it
    /// replicates to subscribers.
    async fn write(&self, rel: &str, data: &[u8]) {
        let hash = *blake3::hash(data).as_bytes();
        self.cas.put_verified(&hash, data).unwrap();
        let manifest = Manifest {
            content_hash: hash,
            chunks: vec![ChunkEntry {
                hash,
                len: data.len() as u32,
            }],
        };
        self.store
            .append_local(LocalChange {
                path: rel.into(),
                op_type: OpType::Write,
                mode: 0o644,
                size: data.len() as u64,
                content_hash: Some(hash),
                meta: None,
                manifest: Some(manifest),
            })
            .await
            .unwrap();
    }

    /// True once `rel` is present (non-tombstone) in this node's index.
    async fn has(&self, rel: &str, hash: [u8; 32]) -> bool {
        self.store
            .load_file(rel)
            .await
            .unwrap()
            .is_some_and(|l| !l.tombstone && l.content_hash == Some(hash))
    }
}

/// Poll `cond` up to ~30s — generous because the whole test suite runs in
/// parallel and the join flow (gate reconcile + bootstrap + subscribe) is
/// CPU-starved under full-suite load. Positive assertions only.
async fn eventually<F, Fut>(cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    eventually_for(cond, 600).await
}

/// Bounded variant for NEGATIVE assertions ("X must not happen"): a breach
/// shows within a couple of seconds here; a short window keeps the suite
/// fast without weakening the check.
async fn never_within<F, Fut>(cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    eventually_for(cond, 120).await
}

async fn eventually_for<F, Fut>(mut cond: F, ticks: u32) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..ticks {
        if cond().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn h(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// AC8: a node not in anyone's seeds joins the data path once admin-added.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_add_brings_a_node_into_the_data_path() {
    let admin = admin();
    // A has no seeds; C is seeded with A so it can bootstrap-contact it. A does
    // NOT know C until the admin adds it.
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a]);

    // Before the add, A must not admit C (not in the allowlist).
    a.write("pre.txt", b"before").await;
    assert!(
        !never_within(|| c.has("pre.txt", h(b"before"))).await,
        "C replicated before being added — trust gate breached"
    );

    // Admin-add C at A (as `replicorectl member add` would).
    assert_eq!(a.admin_add(&admin, &c), MergeOutcome::Applied);

    // Now A's writes reach C.
    a.write("post.txt", b"after").await;
    assert!(
        eventually(|| c.has("post.txt", h(b"after"))).await,
        "C did not replicate after being dynamically added"
    );
}

/// AC9: a signed Remove evicts a node from the data path and locks it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_remove_locks_a_node_out() {
    let admin = admin();
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a]);
    a.admin_add(&admin, &c);

    a.write("one.txt", b"one").await;
    assert!(
        eventually(|| c.has("one.txt", h(b"one"))).await,
        "join failed"
    );

    // Remove C.
    assert_eq!(a.admin_remove(&admin, &c), MergeOutcome::Applied);
    assert!(
        !a.engine
            .membership()
            .effective_peers()
            .iter()
            .any(|p| p.node_id == c.id),
        "C still effective after removal"
    );

    // A write after the removal must NOT reach C (it is locked out of TLS).
    a.write("two.txt", b"two").await;
    assert!(
        !never_within(|| c.has("two.txt", h(b"two"))).await,
        "removed node still received data"
    );
}

/// AC10: an add at one node propagates to a third node via gossip (rosters
/// converge to the same digest), and the third node brings it into its view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_propagates_an_add_to_a_third_node() {
    let admin = admin();
    // B and C are seeded with A so they can bootstrap-contact it; admin-adding
    // them at A makes A admit them, forming the connections gossip rides.
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let b = Node::start(nid(0xB), &admin.pk, &[&a]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a, &b]);

    // Add BOTH at A. B is connected to A (its add admits it); it must then learn
    // about C purely through gossip — C is never added at B.
    assert_eq!(a.admin_add(&admin, &b), MergeOutcome::Applied);
    assert_eq!(a.admin_add(&admin, &c), MergeOutcome::Applied);

    let bm = b.engine.membership();
    let am = a.engine.membership();
    assert!(
        eventually(|| {
            let same = bm.roster_digest() == am.roster_digest();
            async move { same }
        })
        .await,
        "B's roster never converged with A's via gossip"
    );
    assert!(
        bm.effective_peers().iter().any(|p| p.node_id == c.id),
        "B did not learn C through gossip"
    );
}

/// AC11: a forged entry (signed by a non-admin key) is rejected and never
/// enters the roster — announcement is not authorization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_membership_change_is_rejected() {
    let cluster = admin();
    let forger = admin(); // a DIFFERENT admin key
    let admin = cluster;
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let victim = Node::start(nid(0xC), &admin.pk, &[&a]);

    // Sign C's add with the WRONG key and submit it at A.
    let outcome = a.submit(
        &forger,
        victim.id,
        victim.addr,
        victim.fingerprint,
        EntryKind::Add,
    );
    assert_eq!(outcome, MergeOutcome::Rejected);
    assert!(
        a.engine.membership().effective_peers().is_empty(),
        "forged entry entered the roster"
    );
}

/// AC12: removing one node does not disrupt an unrelated link — an A↔B
/// transfer keeps flowing while C is removed, and local writes never block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_one_node_does_not_disrupt_another_link() {
    let admin = admin();
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let b = Node::start(nid(0xB), &admin.pk, &[&a]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a]);
    a.admin_add(&admin, &b);
    a.admin_add(&admin, &c);

    // Establish A→B replication.
    a.write("before.txt", b"before").await;
    assert!(
        eventually(|| b.has("before.txt", h(b"before"))).await,
        "A→B link never came up"
    );

    // Remove C; A→B must keep working.
    assert_eq!(a.admin_remove(&admin, &c), MergeOutcome::Applied);
    a.write("after.txt", b"after").await;
    assert!(
        eventually(|| b.has("after.txt", h(b"after"))).await,
        "A→B link disrupted by C's removal"
    );
}

/// Poll that `cond` stays false for ~`iters`*50ms (a negative assertion that
/// something does NOT happen within a window).
async fn stays_false<F, Fut>(iters: u32, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..iters {
        if cond().await {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// Item 1 / Item 2: an ALREADY-established node, connected in BOTH directions,
/// has EVERY connection severed after a signed Remove. This asserts the teardown
/// invariant DIRECTLY — the registry holds zero connections for the removed node
/// and every connection A held to it is locally closed — instead of polling for
/// replication to quiesce. The data-plane race (which direction won the single
/// registry slot) is gone: `close_all` closes all of them, and we check the
/// connection objects, not whether a write happened to propagate. The
/// deterministic TLS guarantee for RECONNECT is pinned separately in the net.rs
/// unit test `removed_peer_handshake_is_refused`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_connection_severed_on_removal() {
    let admin = admin();
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a]);
    a.admin_add(&admin, &c);

    // Precondition: A holds BOTH connections to C (it dials C and C dials A), so
    // there are two directions to sever. (Poll to reach this known state — the
    // assertions below do not depend on replication timing.)
    let conns_to_c = || {
        a.engine
            .conn_registry()
            .candidates(&c.id)
            .into_iter()
            .filter(|(id, _)| *id == c.id)
            .map(|(_, conn)| conn)
            .collect::<Vec<_>>()
    };
    assert!(
        eventually(|| {
            let n = conns_to_c().len();
            async move { n >= 2 }
        })
        .await,
        "both directions never established (need two connections to sever)"
    );
    let captured = conns_to_c();
    assert!(captured.len() >= 2, "expected >=2 connections to C");

    // Remove C.
    assert_eq!(a.admin_remove(&admin, &c), MergeOutcome::Applied);

    // Deterministic assertion 1: the registry holds ZERO connections for C
    // (close_all removed the key). Poll only for the supervisor to run the
    // teardown — the asserted state itself is exact, not a propagation guess.
    assert!(
        eventually(|| {
            let gone = a.engine.conn_registry().get(&c.id).is_none();
            async move { gone }
        })
        .await,
        "registry still holds a connection to the removed node"
    );

    // Deterministic assertion 2: EVERY connection A held to C was locally closed
    // by the teardown — both directions, including the dialer side's detached
    // serve task's connection. `closed()` resolves once the conn is closed.
    for conn in captured {
        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("a connection to the removed node was never closed");
        assert!(
            matches!(reason, quinn::ConnectionError::LocallyClosed),
            "connection to removed node not locally closed: {reason:?}"
        );
    }
}

/// Item 2: after removal a node cannot re-establish — the verifier reads the
/// LIVE allowlist, so C's fingerprint is gone and C never returns to Live
/// despite its dial loop retrying. (The literal TLS-rejection assertion lives in
/// the net.rs unit test `removed_peer_handshake_is_refused`; quinn does not
/// surface the peer's TLS alert to the app layer here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_refused_after_removal() {
    let admin = admin();
    let a = Node::start(nid(0xA), &admin.pk, &[]);
    let c = Node::start(nid(0xC), &admin.pk, &[&a]);
    a.admin_add(&admin, &c);

    // C reaches Live toward A.
    assert!(
        eventually(|| {
            let live =
                c.engine.peer_registry().get(&a.id).state == replicore::peer::PeerState::Live;
            async move { live }
        })
        .await,
        "C never reached Live toward A"
    );

    assert_eq!(a.admin_remove(&admin, &c), MergeOutcome::Applied);

    // (a) The exact state the per-handshake verifier reads: C's fp is gone.
    assert!(
        !a.engine
            .membership()
            .allowlist_handle()
            .read()
            .unwrap()
            .contains(&c.fingerprint),
        "removed node's fingerprint still in A's live TLS allowlist"
    );

    // (b) Wait for teardown, then assert C stays out of the data path: it never
    // returns to Live toward A and A never re-registers a connection to it,
    // even though C's dial loop keeps retrying.
    assert!(
        eventually(|| {
            let down =
                c.engine.peer_registry().get(&a.id).state != replicore::peer::PeerState::Live;
            async move { down }
        })
        .await,
        "C never dropped from Live after removal"
    );
    assert!(
        stays_false(80, || {
            let relive = c.engine.peer_registry().get(&a.id).state
                == replicore::peer::PeerState::Live
                || a.engine.conn_registry().get(&c.id).is_some();
            async move { relive }
        })
        .await,
        "removed node re-established a connection to A"
    );
}
