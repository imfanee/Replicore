//! net.rs — QUIC transport with mutual TLS and pinned peer certificates
//! (FR-501/504, FR-1001/1002). Built on quinn so we never hand-roll a UDP
//! reliability/congestion layer (NFR-C2).
//!
//! # Trust model: pure pinning
//!
//! Every node has a self-signed certificate. A connection is accepted — in
//! BOTH directions — only if the peer's certificate DER hashes (SHA-256) to a
//! fingerprint in the configured allowlist. Hostname and validity-period
//! checks are deliberately NOT performed: there is no CA and no DNS identity
//! on the private VPN these nodes inhabit, and expiry checks would couple the
//! data path to wall-clock sanity (which FR-301 forbids for correctness paths)
//! without adding security beyond the pin. Do not "fix" this by re-enabling
//! WebPKI verification; rotation happens by editing the allowlist.
//!
//! # Connection topology (2 nodes, both dial — the subscribe model)
//!
//! Each node listens AND dials every configured peer:
//! - **My outbound connection to P** is my subscription: my `Hello` carries
//!   `resume_from` (my durable cursor of P's ops), P pushes its ops from
//!   there, I ack after each durable commit, and I open ephemeral bi-streams
//!   on this connection to fetch content P advertised.
//! - **My inbound connection from P** is the mirror: I push my ops, receive
//!   acks, and serve fetches.
//!
//! Each op stream rides exactly one connection, so there is no dial-race to
//! dedupe; resume authority is always the receiver's persisted cursor.
//! // SEAM(M2): mesh > 2 nodes reuses this pairwise scheme per peer link.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::apply::{apply_assembled, apply_delete, ApplyError};
use crate::chunk::Cas;
use crate::config::{Config, Peer};
use crate::decide::{decide, Decision};
use crate::fetch::FetchError;
use crate::membership::Membership;
use crate::merkle::{
    reconcile_pull, MerkleTree, ReconcileCtx, ReconcileError, ReconcileReport, ReconcileTransport,
    RemoteLeaf,
};
use crate::oplog::{Store, StoreError};
use crate::peer::{jittered_backoff, ConnRegistry, PeerRegistry, PeerState};
use crate::proto::{
    read_msg, write_msg, ChunkReq, ChunkResp, Frame, ManifestReq, ManifestResp, OpRecord, OpType,
    ProtoError, ReconcileFrame, ALPN, MANIFEST_PAGE, PROTO_VERSION, STREAM_TAG_CHUNK,
    STREAM_TAG_MANIFEST, STREAM_TAG_RECONCILE, STREAM_TAG_ROSTER, TREE_PAGE,
};
use crate::stats::Stats;
use crate::suppress::Suppressor;
use crate::vv::NodeId;

/// Ops pushed per batch between cursor reads.
const PUSH_BATCH: u32 = 64;

#[derive(thiserror::Error, Debug)]
pub enum NetError {
    #[error("identity: {0}")]
    Identity(String),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("stream write: {0}")]
    StreamWrite(#[from] quinn::WriteError),
    #[error("stream read: {0}")]
    StreamRead(#[from] quinn::ReadExactError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("task join: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("peer presented no certificate")]
    NoPeerCert,
    #[error("peer certificate fingerprint not in allowlist")]
    UnknownPeer,
    #[error("peer node id does not match the identity its certificate pins")]
    PeerIdentityMismatch,
    #[error("incompatible protocol version {0}")]
    Version(u16),
    #[error("protocol violation: {0}")]
    Violation(&'static str),
    #[error("peer reports content unavailable for requested hash")]
    ContentUnavailable,
    #[error("file size exceeds max_file_bytes")]
    TooBig,
    #[error("fetch: {0}")]
    Fetch(#[from] FetchError),
    #[error("reconcile: {0}")]
    Reconcile(#[from] ReconcileError),
}

// ---------------------------------------------------------------------------
// Identity: generation, loading, fingerprinting
// ---------------------------------------------------------------------------

/// SHA-256 over the certificate DER — the pinned identity (FR-1002). The
/// `gen-cert` output and the runtime verifiers MUST hash the same bytes.
pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Freshly generated self-signed node identity (the `gen-cert` subcommand).
pub struct GeneratedIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: [u8; 32],
}

pub fn generate_identity() -> Result<GeneratedIdentity, NetError> {
    let key = rcgen::KeyPair::generate()?;
    // No SANs: identity is the key/cert pin, not a name.
    let params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let cert = params.self_signed(&key)?;
    Ok(GeneratedIdentity {
        fingerprint: cert_fingerprint(cert.der()),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Load this node's cert + key PEMs from disk.
pub fn load_identity(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), NetError> {
    let read = |p: &Path| -> Result<Vec<u8>, NetError> {
        std::fs::read(p).map_err(|e| NetError::Identity(format!("read {}: {e}", p.display())))
    };
    let cert = rustls_pemfile::certs(&mut read(cert_path)?.as_slice())
        .next()
        .ok_or_else(|| NetError::Identity(format!("no certificate in {}", cert_path.display())))?
        .map_err(|e| NetError::Identity(format!("parse {}: {e}", cert_path.display())))?;
    let key = rustls_pemfile::private_key(&mut read(key_path)?.as_slice())
        .map_err(|e| NetError::Identity(format!("parse {}: {e}", key_path.display())))?
        .ok_or_else(|| NetError::Identity(format!("no private key in {}", key_path.display())))?;
    Ok((cert, key))
}

// ---------------------------------------------------------------------------
// Pinning verifiers (replace M0's deleted accept-anything spike verifier —
// FR-1001/1002)
// ---------------------------------------------------------------------------

/// The live fingerprint allowlist, shared with [`Membership`]. Read on EVERY
/// handshake (not snapshotted at endpoint-build time) so a signed membership
/// change locks a peer out — or lets one in — without rebuilding the endpoint.
type Allowlist = Arc<StdRwLock<HashSet<[u8; 32]>>>;

/// Pick a uniformly random connection for periodic anti-entropy gossip.
fn pick_random(conns: &[(NodeId, quinn::Connection)]) -> Option<&(NodeId, quinn::Connection)> {
    if conns.is_empty() {
        None
    } else {
        conns.get(fastrand::usize(..conns.len()))
    }
}

fn pin_ok(allow: &Allowlist, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
    let fp = cert_fingerprint(end_entity.as_ref());
    if allow.read().expect("allowlist lock").contains(&fp) {
        Ok(())
    } else {
        Err(rustls::Error::General(
            "peer certificate fingerprint not in allowlist".into(),
        ))
    }
}

/// Client-side: accept the server cert iff its fingerprint is pinned.
#[derive(Debug)]
struct PinnedServerVerifier {
    allow: Allowlist,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime, // unused by design: pure pinning, no expiry check
    ) -> Result<ServerCertVerified, rustls::Error> {
        pin_ok(&self.allow, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server-side: REQUIRE a client cert and accept iff its fingerprint is
/// pinned. An unlisted peer fails the TLS handshake and never reaches the
/// protocol layer (exit criterion 5).
#[derive(Debug)]
struct PinnedClientVerifier {
    allow: Allowlist,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true // no anonymous peers, ever
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[] // no CA hints: pins, not PKI
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime, // unused by design: pure pinning, no expiry check
    ) -> Result<ClientCertVerified, rustls::Error> {
        pin_ok(&self.allow, end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The replication transport: one QUIC endpoint serving both roles, wired to
/// the store, the share, and the suppression set.
pub struct Engine {
    cfg: Arc<Config>,
    store: Store,
    suppress: Suppressor,
    /// The content-addressed chunk store (serves and receives chunks).
    cas: Cas,
    /// Live connections (inbound AND outbound) for multi-source fetch.
    conns: ConnRegistry,
    /// Liveness/anti-entropy status for /healthz.
    peers_reg: PeerRegistry,
    /// Transfer/reconcile counters for /healthz and the mesh tests.
    stats: Arc<Stats>,
    /// Engine-wide bound on concurrent file transfers (FR-1106).
    transfers: Arc<tokio::sync::Semaphore>,
    /// Node join lifecycle (FR-1311): Joining → Syncing → Active.
    join: crate::join::JoinTracker,
    /// Dynamic membership: roster + effective peers + live TLS allowlist.
    membership: Membership,
    /// Operator pause gate (FR-1404): when set, push and new transfers wait;
    /// in-flight transfers finish. Resume wakes the waiters.
    paused: Arc<std::sync::atomic::AtomicBool>,
    resume_notify: Arc<tokio::sync::Notify>,
}

impl Engine {
    pub fn new(
        cfg: Config,
        store: Store,
        suppress: Suppressor,
        cas: Cas,
        membership: Membership,
    ) -> Arc<Engine> {
        let transfers = Arc::new(tokio::sync::Semaphore::new(
            cfg.max_concurrent_transfers.max(1),
        ));
        // Promotion is gated on the CURRENT effective set, not just the seeds.
        let expected = membership.effective_peers().into_iter().map(|p| p.node_id);
        let join = crate::join::JoinTracker::new(store.clone(), expected);
        Arc::new(Engine {
            cfg: Arc::new(cfg),
            store,
            suppress,
            cas,
            conns: ConnRegistry::new(),
            peers_reg: PeerRegistry::new(),
            stats: Arc::new(Stats::default()),
            transfers,
            join,
            membership,
            paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            resume_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// The node's join lifecycle handle (status/gossip surface it).
    pub fn join_tracker(&self) -> crate::join::JoinTracker {
        self.join.clone()
    }

    /// The membership handle (control plane / gossip operate through it).
    pub fn membership(&self) -> Membership {
        self.membership.clone()
    }

    // -- control-plane accessors (FR-1401–1408) -----------------------------

    pub fn conflicts(&self) -> u64 {
        Stats::get(&self.stats.conflicts)
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        self.resume_notify.notify_waiters();
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Park while paused (the push loop and new transfers call this). In-flight
    /// transfers already past this gate run to completion.
    async fn await_unpaused(&self) {
        while self.paused.load(Ordering::Acquire) {
            self.resume_notify.notified().await;
        }
    }

    /// Local self-status (also the CTLQUERY mesh reply).
    pub fn local_status(&self) -> crate::control::NodeStatus {
        crate::control::NodeStatus {
            node_id: hex::encode(self.cfg.node_id),
            lifecycle: self.join.lifecycle().as_str().to_string(),
            effective_members: self.membership.effective_peers().len(),
            live_peers: self.conns.len(),
            conflicts: self.conflicts(),
            inflight_transfers: Stats::get_gauge(&self.stats.inflight_transfers),
            paused: self.is_paused(),
            roster_digest: hex::encode(self.membership.roster_digest()),
            proto_version: PROTO_VERSION,
        }
    }

    /// `status` (and `status --all`, which fans out over the mesh, FR-1407).
    pub async fn status_report(&self, all: bool) -> crate::control::StatusReport {
        let local = self.local_status();
        let mut peers = Vec::new();
        if all {
            for (id, conn) in self.conns.all() {
                let status = self.query_peer_status(&conn).await;
                peers.push(crate::control::PeerStatusEntry {
                    node_id: hex::encode(id),
                    reachable: status.is_some(),
                    status,
                });
            }
        }
        crate::control::StatusReport { local, peers }
    }

    /// Ask one peer for its status over a CTLQUERY stream, 3s timeout — a dead
    /// or slow peer is marked unreachable rather than hanging the operator.
    async fn query_peer_status(
        &self,
        conn: &quinn::Connection,
    ) -> Option<crate::control::NodeStatus> {
        let fut = async {
            let (mut send, mut recv) = conn.open_bi().await.ok()?;
            send.write_all(&[crate::proto::STREAM_TAG_CTLQUERY])
                .await
                .ok()?;
            send.finish().ok()?;
            read_msg::<_, crate::control::NodeStatus>(&mut recv)
                .await
                .ok()
        };
        tokio::time::timeout(Duration::from_secs(3), fut)
            .await
            .ok()
            .flatten()
    }

    pub fn member_views(&self) -> Vec<crate::control::MemberView> {
        self.membership
            .roster_snapshot()
            .into_iter()
            .map(|e| crate::control::MemberView {
                node_id: hex::encode(e.node_id),
                addr: e.addr.to_string(),
                fingerprint: hex::encode(e.fingerprint),
                epoch: e.epoch,
                kind: match e.kind {
                    crate::admin::EntryKind::Add => "add",
                    crate::admin::EntryKind::Remove => "remove",
                }
                .to_string(),
            })
            .collect()
    }

    /// The current addr/fingerprint for a known member (for signing a Remove).
    pub fn member_addr_fp(&self, node: &NodeId) -> (Option<String>, Option<String>) {
        self.membership
            .effective_peers()
            .into_iter()
            .find(|p| &p.node_id == node)
            .map(|p| (Some(p.addr.to_string()), Some(hex::encode(p.fingerprint))))
            .unwrap_or((None, None))
    }

    pub fn peer_views(&self) -> Vec<crate::control::PeerView> {
        let connected: HashSet<NodeId> = self.conns.all().into_iter().map(|(id, _)| id).collect();
        self.peers_reg
            .snapshot()
            .into_iter()
            .map(|(id, st)| crate::control::PeerView {
                node_id: hex::encode(id),
                state: st.state.as_str().to_string(),
                connected: connected.contains(&id),
            })
            .collect()
    }

    pub async fn lag_views(&self) -> Vec<crate::control::LagView> {
        let our_latest = *self.store.watch_latest().borrow();
        let mut out = Vec::new();
        for peer in self.membership.effective_peers() {
            let recv_cursor = self.store.recv_cursor(peer.node_id).await.unwrap_or(0);
            let last_acked = self.store.last_acked(peer.node_id).await.unwrap_or(0);
            out.push(crate::control::LagView {
                node_id: hex::encode(peer.node_id),
                recv_cursor,
                last_acked,
                our_latest,
            });
        }
        out
    }

    pub fn transfers_view(&self) -> crate::control::TransfersView {
        crate::control::TransfersView {
            inflight: Stats::get_gauge(&self.stats.inflight_transfers),
            chunks_fetched: Stats::get(&self.stats.chunks_fetched),
            chunks_served: Stats::get(&self.stats.chunks_served),
            bytes_in: Stats::get(&self.stats.bytes_in),
            bytes_out: Stats::get(&self.stats.bytes_out),
        }
    }

    pub fn version_view(&self) -> crate::control::VersionView {
        crate::control::VersionView {
            node_id: hex::encode(self.cfg.node_id),
            proto_version: PROTO_VERSION,
            pkg_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn config_diff(&self, candidate: &Config) -> Vec<crate::config::ConfigChange> {
        self.cfg.diff(candidate)
    }

    /// Atomic config reload (FR-1406): apply the HOT membership view from the
    /// candidate; restart-required fields are reported but not applied. The
    /// candidate was already validated by the caller, so this cannot half-apply.
    pub fn reload(
        &self,
        candidate: &Config,
    ) -> Result<Vec<crate::config::ConfigChange>, crate::membership::MembershipError> {
        let changes = self.cfg.diff(candidate);
        self.membership.apply_reload(candidate)?;
        Ok(changes)
    }

    /// On-demand anti-entropy (FR-1405): reconcile now with `node` (or every
    /// live link). Returns how many links were reconciled.
    pub async fn resync(self: &Arc<Engine>, node: Option<NodeId>) -> usize {
        let eff: HashMap<NodeId, Peer> = self
            .membership
            .effective_peers()
            .into_iter()
            .map(|p| (p.node_id, p))
            .collect();
        let mut count = 0;
        for (id, conn) in self.conns.all() {
            if node.is_some_and(|n| n != id) {
                continue;
            }
            if let Some(peer) = eff.get(&id) {
                if self.reconcile_with(&conn, peer).await.is_ok() {
                    count += 1;
                }
            }
        }
        count
    }

    /// Build the dual-role endpoint: server config (require + pin client
    /// certs) bound to `cfg.listen`, default client config (present our cert,
    /// pin server certs).
    pub fn build_endpoint(&self) -> Result<quinn::Endpoint, NetError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = load_identity(&self.cfg.cert_path, &self.cfg.key_path)?;
        // The live allowlist — shared with Membership and read per handshake.
        let allow = self.membership.allowlist_handle();

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        // WAN tuning (FR-502): quinn's default 1.25 MiB stream window cannot
        // fill a long-fat pipe (BDP at 150 ms RTT × 100 Mbit ≈ 2 MiB), and
        // chunk transfers run several streams in parallel. Size the windows
        // for chunk_max × per-file concurrency with headroom.
        transport.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));
        transport.receive_window(quinn::VarInt::from_u32(64 * 1024 * 1024));
        transport.send_window(64 * 1024 * 1024);
        let transport = Arc::new(transport);

        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(Arc::new(PinnedClientVerifier {
                allow: allow.clone(),
                provider: provider.clone(),
            }))
            .with_single_cert(vec![cert.clone()], key.clone_key())?;
        server_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls)
                .map_err(|e| NetError::Identity(format!("quic server config: {e}")))?,
        ));
        server_cfg.transport_config(transport.clone());

        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier { allow, provider }))
            .with_client_auth_cert(vec![cert], key)?;
        client_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls)
                .map_err(|e| NetError::Identity(format!("quic client config: {e}")))?,
        ));
        client_cfg.transport_config(transport);

        let mut endpoint = quinn::Endpoint::server(server_cfg, self.cfg.listen)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
    }

    /// Run the transport forever: accept loop + one dial loop per peer.
    pub async fn run(self: Arc<Engine>) -> Result<(), NetError> {
        // A node that was Active before a restart resumes Active (it will still
        // re-reconcile on each reconnect — that never regresses it).
        self.join.restore().await;
        let endpoint = self.build_endpoint()?;
        // The accept loop runs in the background; the supervisor owns dialing,
        // spawning and tearing down per-peer loops as membership changes.
        tokio::spawn({
            let engine = self.clone();
            let ep = endpoint.clone();
            async move {
                if let Err(e) = engine.accept_loop(ep).await {
                    tracing::error!(error = %e, "accept loop ended");
                }
            }
        });
        tokio::spawn(self.clone().gossip_driver());
        self.supervise(endpoint).await
    }

    /// Drive roster gossip (FR-1304): on every local membership change, push to
    /// ALL live peers immediately so an admin's add/remove propagates fast;
    /// between changes, anti-entropy with ONE random live peer every ~1.5s to
    /// heal anything missed. A node with no admin key has no roster to spread.
    async fn gossip_driver(self: Arc<Engine>) {
        if !self.membership.has_admin_key() {
            return;
        }
        let mut changes = self.membership.subscribe();
        let mut tick = tokio::time::interval(Duration::from_millis(1500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let conns = self.conns.all();
                    if let Some((_, conn)) = pick_random(&conns) {
                        if let Err(e) = crate::gossip::gossip_once(&self.membership, conn).await {
                            tracing::debug!(error = %e, "periodic gossip failed");
                        }
                    }
                }
                changed = changes.changed() => {
                    if changed.is_err() {
                        return; // membership dropped: shutting down
                    }
                    // Immediate push to everyone currently connected.
                    for (_, conn) in self.conns.all() {
                        if let Err(e) = crate::gossip::gossip_once(&self.membership, &conn).await {
                            tracing::debug!(error = %e, "change-push gossip failed");
                        }
                    }
                }
            }
        }
    }

    /// Reconcile the set of running dial loops to the effective membership,
    /// re-running whenever the roster changes (FR-1304/1307, zero-downtime).
    ///
    /// Removal teardown order is LAW: the fingerprint is evicted from the TLS
    /// allowlist by `Membership` the instant the signed Remove merges — BEFORE
    /// this supervisor wakes — so a reconnect can never race the gap. Here we
    /// only (1) abort the dial task and (2) close + deregister the connection.
    async fn supervise(self: Arc<Engine>, endpoint: quinn::Endpoint) -> Result<(), NetError> {
        use tokio::task::JoinHandle;
        let mut tasks: HashMap<NodeId, (Peer, JoinHandle<()>)> = HashMap::new();
        let mut changes = self.membership.subscribe();
        loop {
            let desired: HashMap<NodeId, Peer> = self
                .membership
                .effective_peers()
                .into_iter()
                .map(|p| (p.node_id, p))
                .collect();

            // Spawn new members; restart a member whose addr/fingerprint moved
            // (a higher-epoch re-add) or whose task has exited.
            for (id, peer) in &desired {
                let needs_spawn = match tasks.get(id) {
                    Some((existing, h)) => {
                        h.is_finished()
                            || existing.addr != peer.addr
                            || existing.fingerprint != peer.fingerprint
                    }
                    None => true,
                };
                if needs_spawn {
                    if let Some((_, h)) = tasks.remove(id) {
                        h.abort();
                    }
                    let engine = self.clone();
                    let ep = endpoint.clone();
                    let p = peer.clone();
                    let h = tokio::spawn(async move { engine.dial_loop(ep, p).await });
                    tasks.insert(*id, (peer.clone(), h));
                }
            }

            // Tear down members no longer in the effective set.
            let removed: Vec<NodeId> = tasks
                .keys()
                .filter(|id| !desired.contains_key(*id))
                .cloned()
                .collect();
            for id in removed {
                if let Some((_, h)) = tasks.remove(&id) {
                    h.abort(); // stop reconnects (the dial loop would respin)
                }
                // Close EVERY connection to the removed node — both directions,
                // including the dialer side's detached serve task — not just the
                // single registry slot. The fingerprint is already out of the
                // TLS allowlist (recompute, before this fires), so nothing can
                // re-establish; close_all severs what is already open.
                self.conns.close_all(&id, 0u32.into(), b"membership-remove");
                self.peers_reg.set_state(id, PeerState::Disconnected);
                tracing::info!(
                    node = %hex::encode(&id[..4]),
                    "peer removed from mesh; dial loop aborted and all connections severed"
                );
            }

            // Keep join-lifecycle promotion gated on the live effective set.
            self.join.set_expected(desired.keys().cloned()).await;

            if changes.changed().await.is_err() {
                return Ok(()); // membership handle dropped: shutting down
            }
        }
    }

    // -- inbound ------------------------------------------------------------

    async fn accept_loop(self: Arc<Engine>, endpoint: quinn::Endpoint) -> Result<(), NetError> {
        tracing::info!(listen = %self.cfg.listen, "accepting peer connections");
        while let Some(incoming) = endpoint.accept().await {
            let engine = self.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                match engine.handle_inbound(incoming).await {
                    Ok(()) => tracing::info!(%remote, "inbound connection closed"),
                    Err(e) => tracing::warn!(%remote, error = %e, "inbound connection ended"),
                }
            });
        }
        Ok(())
    }

    /// Inbound = the peer's subscription to OUR ops: handshake, then push ops
    /// from its `resume_from`, absorb acks, serve content fetches.
    async fn handle_inbound(self: &Arc<Engine>, incoming: quinn::Incoming) -> Result<(), NetError> {
        let conn = incoming.await?;
        let peer = self.identify(&conn)?; // bind connection -> configured peer

        // Authenticated inbound connections serve multi-source fetch too.
        let peer_id = peer.node_id;
        self.conns.insert(peer_id, conn.clone());
        let result = self.inbound_io(conn.clone(), peer).await;
        self.conns.remove_if_same(&peer_id, &conn);
        result
    }

    async fn inbound_io(
        self: &Arc<Engine>,
        conn: quinn::Connection,
        peer: Peer,
    ) -> Result<(), NetError> {
        // The dialer opens the control stream and speaks first.
        let (mut ctl_send, mut ctl_recv) = conn.accept_bi().await?;
        match read_msg::<_, Frame>(&mut ctl_recv).await? {
            Frame::Hello {
                proto_version,
                node_id,
                resume: _, // resume is now authoritative in SubscribeOps, post-reconcile
            } => {
                if proto_version != PROTO_VERSION {
                    return Err(NetError::Version(proto_version));
                }
                // Announcement is not authorization — and not identity either:
                // the node id claimed in Hello must be the one whose pinned
                // cert authenticated this connection.
                if node_id != peer.node_id {
                    return Err(NetError::PeerIdentityMismatch);
                }
            }
            _ => return Err(NetError::Violation("expected Hello")),
        };
        write_msg(
            &mut ctl_send,
            &Frame::HelloAck {
                proto_version: PROTO_VERSION,
                node_id: self.cfg.node_id,
            },
        )
        .await?;
        // THE responder side of the anti-entropy gate (FR-702): serve
        // ephemeral streams NOW — the dialer's gating reconcile session
        // arrives on one — but push NO ops until SubscribeOps. The resume
        // point comes from SubscribeOps (after the dialer reconciled), so the
        // bootstrapped history is never re-streamed (FR-1311). We push only our
        // own ops, so only our entry of the frontier map matters.
        let resume_from = {
            let serve = self.serve_streams(conn.clone());
            tokio::pin!(serve);
            let gate = async {
                loop {
                    match read_msg::<_, Frame>(&mut ctl_recv).await {
                        Ok(Frame::SubscribeOps { resume }) => {
                            return Ok(resume
                                .iter()
                                .find(|(origin, _)| origin == &self.cfg.node_id)
                                .map(|(_, cursor)| *cursor)
                                .unwrap_or(0));
                        }
                        Ok(Frame::Ping { nonce: _ }) => {}
                        Ok(_) => {
                            return Err(NetError::Violation("control frame before SubscribeOps"))
                        }
                        Err(ProtoError::Closed) => {
                            return Err(NetError::Violation("closed before SubscribeOps"))
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            };
            tokio::select! {
                r = &mut serve => return r, // connection ended during the gate
                g = gate => g?,
            }
        };
        tracing::info!(
            peer = %hex::encode(&peer.node_id[..4]),
            resume_from,
            "peer reconciled and subscribed to our ops"
        );

        // The pushed frontier: highest origin_seq actually streamed on THIS
        // connection. Acks are validated against it — a peer must not be able
        // to ack ops it was never sent (last_acked_seq feeds tombstone GC in
        // M3; an inflated ack there means premature GC and resurrection risk).
        let sent_frontier = Arc::new(AtomicI64::new(resume_from));

        let push = self.push_ops(ctl_send, resume_from, sent_frontier.clone());
        let acks = self.absorb_acks(ctl_recv, peer.node_id, sent_frontier);
        let fetches = self.serve_streams(conn.clone());
        tokio::select! {
            r = push => r,
            r = acks => r,
            r = fetches => r,
        }
    }

    /// Stream our ops in ascending origin_seq, starting after `resume_from`,
    /// waking on new local appends.
    async fn push_ops(
        &self,
        mut ctl_send: quinn::SendStream,
        resume_from: i64,
        sent_frontier: Arc<AtomicI64>,
    ) -> Result<(), NetError> {
        let mut latest = self.store.watch_latest();
        let mut cursor = resume_from;
        loop {
            // Pause gate (FR-1404): hold outbound replication while paused.
            self.await_unpaused().await;
            let ops = self
                .store
                .ops_since(self.cfg.node_id, cursor, PUSH_BATCH)
                .await?;
            tracing::debug!(cursor, count = ops.len(), "push_ops poll");
            if ops.is_empty() {
                // Nothing new: sleep until the next local append.
                if latest.changed().await.is_err() {
                    return Ok(()); // store gone: shutting down
                }
                continue;
            }
            for op in ops {
                cursor = op.origin_seq;
                write_msg(&mut ctl_send, &Frame::OplogPush(op)).await?;
                // Publish after the frame is written: an honest ack can only
                // arrive after the peer received it, i.e. after this store.
                sent_frontier.store(cursor, Ordering::Release);
            }
        }
    }

    /// Absorb a subscriber's acks; persist last_acked_seq (FR-503 resume +
    /// the eventual tombstone-GC input). // SEAM(M2): GC reads last_acked_seq
    async fn absorb_acks(
        &self,
        mut ctl_recv: quinn::RecvStream,
        peer: NodeId,
        sent_frontier: Arc<AtomicI64>,
    ) -> Result<(), NetError> {
        loop {
            match read_msg::<_, Frame>(&mut ctl_recv).await {
                Ok(Frame::OplogAck { origin, up_to_seq }) => {
                    // M2 full mesh: only our own ops ride this connection, so
                    // only acks for our origin are meaningful.
                    if origin != self.cfg.node_id {
                        return Err(NetError::Violation("ack for an origin we did not push"));
                    }
                    // Never trust network input: an ack is only meaningful up
                    // to what we pushed on this connection. Beyond that is a
                    // lying or broken peer — drop it rather than let it
                    // inflate last_acked_seq.
                    if up_to_seq > sent_frontier.load(Ordering::Acquire) {
                        return Err(NetError::Violation("ack beyond the pushed frontier"));
                    }
                    self.store.advance_ack(peer, up_to_seq).await?;
                }
                Ok(Frame::Ping { nonce: _ }) => {} // QUIC keep-alive covers liveness; tolerate
                Ok(_) => return Err(NetError::Violation("unexpected frame on ack path")),
                Err(ProtoError::Closed) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Serve ephemeral bi-streams (chunk / manifest / reconcile) on a
    /// connection. The per-connection semaphore is the FR-1106 fix for M1's
    /// unbounded spawn-per-stream: a peer hammering us with streams waits for
    /// a slot instead of growing our task count without limit.
    async fn serve_streams(self: &Arc<Engine>, conn: quinn::Connection) -> Result<(), NetError> {
        let slots = Arc::new(tokio::sync::Semaphore::new(
            self.cfg.serve_concurrency.max(1),
        ));
        loop {
            let (send, recv) = conn.accept_bi().await?;
            let permit = match slots.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return Ok(()), // semaphore closed: shutting down
            };
            let engine = self.clone();
            tokio::spawn(async move {
                let _permit = permit; // held for the stream's lifetime
                if let Err(e) = engine.serve_one_stream(send, recv).await {
                    tracing::debug!(error = %e, "serve stream ended");
                }
            });
        }
    }

    /// Dispatch one ephemeral stream by its leading tag byte.
    async fn serve_one_stream(
        &self,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<(), NetError> {
        let mut tag = [0u8; 1];
        recv.read_exact(&mut tag).await?;
        match tag[0] {
            STREAM_TAG_CHUNK => self.serve_chunk(send, recv).await,
            STREAM_TAG_MANIFEST => self.serve_manifest(send, recv).await,
            STREAM_TAG_RECONCILE => self.serve_reconcile(send, recv).await,
            STREAM_TAG_ROSTER => crate::gossip::serve_roster(&self.membership, send, recv)
                .await
                .map_err(|e| {
                    tracing::debug!(error = %e, "roster gossip serve ended");
                    NetError::Violation("roster gossip")
                }),
            crate::proto::STREAM_TAG_CTLQUERY => self.serve_ctlquery(send).await,
            _ => Err(NetError::Violation("unknown stream tag")),
        }
    }

    /// Answer a `status --all` fan-out query: write our local NodeStatus.
    async fn serve_ctlquery(&self, mut send: quinn::SendStream) -> Result<(), NetError> {
        write_msg(&mut send, &self.local_status()).await?;
        let _ = send.finish();
        Ok(())
    }

    /// Responder side of an anti-entropy session: answer root/tree/leaf
    /// queries from a per-session snapshot of the index. Mutates nothing —
    /// the puller does all applying on its own side.
    async fn serve_reconcile(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<(), NetError> {
        // One atomic snapshot: the tree we serve AND the op frontier it covers
        // are read in a single store turn, so the frontier we advertise in
        // RootIs is exactly the boundary of what this tree reflects (FR-1311).
        let snap = self.store.snapshot_for_join().await?;
        let frontier = snap.frontier;
        let tree = MerkleTree::build(snap.rows);
        loop {
            match read_msg::<_, ReconcileFrame>(&mut recv).await {
                Ok(ReconcileFrame::Begin) => {
                    write_msg(
                        &mut send,
                        &ReconcileFrame::RootIs {
                            hash: tree.root(),
                            frontier: frontier.clone(),
                        },
                    )
                    .await?;
                }
                Ok(ReconcileFrame::TreeReq {
                    prefix,
                    after_name,
                    limit,
                }) => {
                    let (children, more) =
                        tree.children_page(&prefix, &after_name, limit.min(TREE_PAGE) as usize);
                    write_msg(&mut send, &ReconcileFrame::TreeResp { children, more }).await?;
                }
                Ok(ReconcileFrame::LeafReq { path }) => {
                    let resp = match tree.leaf(&path) {
                        Some(row) => ReconcileFrame::LeafResp {
                            found: true,
                            tombstone: row.tombstone,
                            content_hash: row.content_hash,
                            vv: row.vv.clone(),
                            mode: row.mode,
                            size: row.size,
                        },
                        None => ReconcileFrame::LeafResp {
                            found: false,
                            tombstone: false,
                            content_hash: None,
                            vv: crate::vv::VersionVector::new(),
                            mode: 0,
                            size: 0,
                        },
                    };
                    write_msg(&mut send, &resp).await?;
                }
                Ok(ReconcileFrame::Done) | Err(ProtoError::Closed) => return Ok(()),
                Ok(_) => return Err(NetError::Violation("unexpected reconcile frame")),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Stream one chunk out of the CAS in bounded copies (never a whole-chunk
    /// buffer — serving memory is O(copy buffer) per stream, FR-1106). The
    /// RECEIVER verifies; CAS files are immutable and were verified at insert.
    async fn serve_chunk(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<(), NetError> {
        let req: ChunkReq = read_msg(&mut recv).await?;
        let opened = {
            let cas = self.cas.clone();
            tokio::task::spawn_blocking(move || cas.open_reader(&req.hash)).await?
        };
        match opened {
            Ok((file, len)) if len <= self.cfg.chunk_max_bytes as u64 => {
                write_msg(
                    &mut send,
                    &ChunkResp {
                        found: true,
                        len: len as u32,
                    },
                )
                .await?;
                let mut reader = tokio::fs::File::from_std(file);
                tokio::io::copy(&mut reader, &mut send)
                    .await
                    .map_err(NetError::Io)?;
                Stats::inc(&self.stats.chunks_served);
                Stats::add(&self.stats.bytes_out, len);
            }
            _ => {
                // Absent (or absurd on disk): the fetcher tries another peer.
                write_msg(
                    &mut send,
                    &ChunkResp {
                        found: false,
                        len: 0,
                    },
                )
                .await?;
            }
        }
        let _ = send.finish();
        Ok(())
    }

    /// Serve one page of a manifest from the db (structure truth).
    async fn serve_manifest(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<(), NetError> {
        let req: ManifestReq = read_msg(&mut recv).await?;
        let resp = match self.store.manifest_for(req.content_hash).await? {
            Some(m) => {
                let total = m.chunks.len() as u32;
                let start = (req.offset as usize).min(m.chunks.len());
                let count = (req.count.min(MANIFEST_PAGE) as usize).min(m.chunks.len() - start);
                ManifestResp {
                    found: true,
                    content_hash: req.content_hash,
                    total,
                    chunks: m.chunks[start..start + count].to_vec(),
                }
            }
            None => ManifestResp {
                found: false,
                content_hash: req.content_hash,
                total: 0,
                chunks: Vec::new(),
            },
        };
        write_msg(&mut send, &resp).await?;
        let _ = send.finish();
        Ok(())
    }

    // -- outbound -----------------------------------------------------------

    /// Maintain our subscription to `peer`'s ops forever, reconnecting with
    /// bounded, jittered backoff (FR-602 — no thundering herd on flap).
    async fn dial_loop(self: Arc<Engine>, endpoint: quinn::Endpoint, peer: Peer) {
        let mut attempt: u32 = 0;
        loop {
            self.peers_reg.set_state(peer.node_id, PeerState::Dialing);
            match self.subscribe_once(&endpoint, &peer, &mut attempt).await {
                Ok(()) => tracing::info!(addr = %peer.addr, "subscription closed; reconnecting"),
                Err(e) => {
                    // A peer we cannot complete a gate with is unreachable for
                    // join-lifecycle purposes — it must not pin us in Syncing
                    // forever (the reachable-only promotion rule, FR-1311). A
                    // peer that already completed its gate stays counted.
                    self.join.note_unreachable(peer.node_id).await;
                    tracing::warn!(addr = %peer.addr, error = %e, "subscription failed; reconnecting")
                }
            }
            self.peers_reg.set_state(peer.node_id, PeerState::Backoff);
            tokio::time::sleep(jittered_backoff(attempt)).await;
            attempt = attempt.saturating_add(1);
        }
    }

    /// One subscription session: connect, Hello/HelloAck, the anti-entropy
    /// gate, then apply pushed ops in order, acking after each durable commit.
    async fn subscribe_once(
        self: &Arc<Engine>,
        endpoint: &quinn::Endpoint,
        peer: &Peer,
        attempt: &mut u32,
    ) -> Result<(), NetError> {
        // The server name is irrelevant under pinning but required by the API.
        let conn = endpoint.connect(peer.addr, "replicore")?.await?;

        // Belt and braces: the default verifier pinned *some* allowlisted
        // cert; bind this connection to THIS peer's fingerprint.
        let fp = self.peer_fingerprint(&conn)?;
        if fp != peer.fingerprint {
            return Err(NetError::PeerIdentityMismatch);
        }

        // Authenticated: make this connection borrowable for multi-source
        // fetch, and guarantee deregistration on every exit path below.
        //
        // The registry keeps ONE connection per peer (last insert wins), and
        // the peer's fetches may arrive on EITHER its inbound connection or
        // this outbound one — so the dialer side must serve ephemeral
        // streams too. (Without this, a request stream opened toward a
        // dialer-only endpoint sits unaccepted forever and wedges the peer's
        // receive path — found as a 3-node startup race.)
        self.conns.insert(peer.node_id, conn.clone());
        let serve = tokio::spawn({
            let engine = self.clone();
            let conn = conn.clone();
            async move {
                if let Err(e) = engine.serve_streams(conn).await {
                    tracing::debug!(error = %e, "outbound-side serving ended");
                }
            }
        });
        let result = self.subscription_io(&conn, peer, attempt).await;
        serve.abort();
        self.conns.remove_if_same(&peer.node_id, &conn);
        self.peers_reg
            .set_state(peer.node_id, PeerState::Disconnected);
        result
    }

    async fn subscription_io(
        self: &Arc<Engine>,
        conn: &quinn::Connection,
        peer: &Peer,
        attempt: &mut u32,
    ) -> Result<(), NetError> {
        let (mut ctl_send, mut ctl_recv) = conn.open_bi().await?;
        let resume_from = self.store.recv_cursor(peer.node_id).await?;
        write_msg(
            &mut ctl_send,
            &Frame::Hello {
                proto_version: PROTO_VERSION,
                node_id: self.cfg.node_id,
                // Frontier map; in the M2 full mesh the only meaningful entry
                // is the peer's own origin (FR-603 relay seam carries more).
                resume: vec![(peer.node_id, resume_from)],
            },
        )
        .await?;
        match read_msg::<_, Frame>(&mut ctl_recv).await? {
            Frame::HelloAck {
                proto_version,
                node_id,
            } => {
                if proto_version != PROTO_VERSION {
                    return Err(NetError::Version(proto_version));
                }
                if node_id != peer.node_id {
                    return Err(NetError::PeerIdentityMismatch);
                }
            }
            _ => return Err(NetError::Violation("expected HelloAck")),
        }
        *attempt = 0; // handshake succeeded: reset the backoff schedule

        // THE anti-entropy gate (FR-702, reviewer item): a (re)started node
        // reconciles with the peer BEFORE trusting its live op stream. The
        // responder pushes nothing until it sees SubscribeOps.
        self.peers_reg
            .set_state(peer.node_id, PeerState::Reconciling);
        let frontier = match self.reconcile_with(conn, peer).await {
            Ok((report, frontier)) => {
                self.peers_reg.note_reconcile(peer.node_id, true);
                tracing::info!(
                    peer = %hex::encode(&peer.node_id[..4]),
                    tree_reqs = report.tree_reqs,
                    applied = report.applied,
                    concurrent = report.skipped_concurrent,
                    damaged = report.skipped_damaged,
                    "reconcile session complete"
                );
                frontier
            }
            Err(e) => {
                self.peers_reg.note_reconcile(peer.node_id, false);
                return Err(e);
            }
        };

        // Join handoff (FR-1311): the bootstrap above reflects the responder's
        // ops up to `frontier`. Durably advance our cursor of the peer's ops to
        // it (monotonic MAX, so a stale snapshot never rewinds a further-along
        // live cursor) and resume the live stream strictly past it. The
        // responder reads the resume from SubscribeOps, NOT the pre-gate Hello,
        // so a fresh joiner (Hello cursor 0) does not re-stream all of history.
        //
        // Crash table — kill -9 the joiner at each point; every row is
        // no-loss AND no-double-apply on the next session (which always begins
        // with a fresh reconcile):
        //   1. mid-pull               — cursor unadvanced; re-pull is cheap
        //                               (Merkle prunes already-equal subtrees).
        //   2. post-leaves/pre-cursor — bootstrapped rows are durable; cursor
        //                               still 0, so the live stream would re-send
        //                               ops ≤ frontier — but each is deduped by
        //                               the `applied` table / Equal-VV Ignore.
        //   3. post-cursor/pre-subscribe — cursor durably at frontier; next
        //                               session resumes past it. No re-stream.
        //   4. post-subscribe/pre-op  — same as 3; the responder simply restarts
        //                               pushing from the resumed cursor.
        //   5. post-op/pre-ack        — op is durably handled before the ack
        //                               (apply_remote commits first); redelivery
        //                               is an idempotent no-op (FR-802).
        // Ops landing on the peer AFTER the snapshot are > frontier by
        // construction, so they ride the live stream exactly once.
        let peer_frontier = frontier
            .iter()
            .find(|(origin, _)| origin == &peer.node_id)
            .map(|(_, seq)| *seq)
            .unwrap_or(0);
        let new_cursor = peer_frontier.max(resume_from);
        if new_cursor > resume_from {
            self.store
                .advance_recv_cursor(peer.node_id, peer.node_id, new_cursor)
                .await?;
        }
        write_msg(
            &mut ctl_send,
            &Frame::SubscribeOps {
                resume: vec![(peer.node_id, new_cursor)],
            },
        )
        .await?;
        self.peers_reg.set_state(peer.node_id, PeerState::Live);
        // The directed pull gate for THIS link is complete — note it for join
        // lifecycle promotion (FR-1310 bidirectional = the two directed gates).
        self.join.note_gate_complete(peer.node_id).await;
        // On-connect roster gossip (FR-1304): converge membership immediately
        // with this peer rather than waiting for the periodic tick. One
        // exchange converges both sides (the merge is a join).
        if let Err(e) = crate::gossip::gossip_once(&self.membership, conn).await {
            tracing::debug!(peer = %hex::encode(&peer.node_id[..4]), error = %e, "on-connect gossip failed");
        }
        tracing::info!(
            peer = %hex::encode(&peer.node_id[..4]),
            resume_from = new_cursor,
            "subscribed to peer ops"
        );

        // Periodic anti-entropy on this link (FR-702 timer); aborted with
        // the subscription.
        let periodic = tokio::spawn({
            let engine = self.clone();
            let conn = conn.clone();
            let peer = peer.clone();
            let interval = Duration::from_secs(engine.cfg.reconcile_interval_secs.max(1));
            async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if conn.close_reason().is_some() {
                        return;
                    }
                    match engine.reconcile_with(&conn, &peer).await {
                        Ok((report, _frontier)) => {
                            engine.peers_reg.note_reconcile(peer.node_id, true);
                            tracing::debug!(
                                peer = %hex::encode(&peer.node_id[..4]),
                                applied = report.applied,
                                "periodic reconcile complete"
                            );
                        }
                        Err(e) => {
                            engine.peers_reg.note_reconcile(peer.node_id, false);
                            tracing::warn!(
                                peer = %hex::encode(&peer.node_id[..4]),
                                error = %e,
                                "periodic reconcile failed"
                            );
                        }
                    }
                }
            }
        });

        let result = async {
            loop {
                match read_msg::<_, Frame>(&mut ctl_recv).await {
                    Ok(Frame::OplogPush(op)) => {
                        let seq = op.origin_seq;
                        tracing::debug!(seq, "op received");
                        if op.origin != peer.node_id {
                            // Full-mesh peers push only their own ops;
                            // forwarding arrives with the relay policy
                            // (FR-603 seam).
                            return Err(NetError::Violation("op origin is not the pushing peer"));
                        }
                        self.process_remote_op(conn, op).await?;
                        // Durably handled (COMMIT above) — only now may we ack.
                        write_msg(
                            &mut ctl_send,
                            &Frame::OplogAck {
                                origin: peer.node_id,
                                up_to_seq: seq,
                            },
                        )
                        .await?;
                    }
                    Ok(Frame::Ping { nonce }) => {
                        write_msg(&mut ctl_send, &Frame::Pong { nonce }).await?;
                    }
                    Ok(_) => return Err(NetError::Violation("unexpected frame on op stream")),
                    Err(ProtoError::Closed) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
        }
        .await;
        periodic.abort();
        result
    }

    /// The receive path for one pushed op. Order is load-bearing (crash
    /// safety, see oplog_crash.rs): idempotency fast path → decide → fetch
    /// bytes → atomic fs apply (suppression registered inside) → ONE durable
    /// store commit. The caller acks only after this returns.
    async fn process_remote_op(
        &self,
        conn: &quinn::Connection,
        op: OpRecord,
    ) -> Result<(), NetError> {
        if self.store.has_applied(op.op_id).await? {
            return Ok(()); // redelivery after a crash: just re-ack
        }
        let local = self.store.load_file(&op.path).await?;
        let mut decision = decide(local.as_ref(), &op.vv);
        tracing::debug!(seq = op.origin_seq, ?decision, "op decision");
        if decision == Decision::Apply {
            match self.materialize(conn, &op, local.as_ref()).await {
                Ok(()) => {}
                // PERMANENT failure: retrying this op can never succeed, and
                // erroring out would reconnect-loop the whole subscription on
                // one poison op (a pinned-peer DoS) — or, in the honest case,
                // stall behind content the origin has since overwritten while
                // the superseding op waits right behind it. Quarantine: record
                // durably as handled-without-apply and let the stream advance.
                Err(e) if is_permanent(&e) => {
                    tracing::error!(
                        path = %op.path,
                        origin = %hex::encode(&op.origin[..4]),
                        seq = op.origin_seq,
                        error = %e,
                        "op cannot be materialized; quarantining (a superseding op or rescan repairs)"
                    );
                    decision = Decision::Quarantined;
                }
                // Transient (I/O, stream, store): drop the connection; the
                // dial loop reconnects and resumes from the durable cursor.
                Err(e) => return Err(e),
            }
        }
        if decision == Decision::Concurrent {
            // Detected, durably recorded as skipped, surfaced to operators.
            // TODO(M3): deterministic winner + conflict copy (FR-303/304).
            Stats::inc(&self.stats.conflicts);
            tracing::warn!(
                path = %op.path,
                origin = %hex::encode(&op.origin[..4]),
                "concurrent versions detected; keeping local (resolution is M3)"
            );
        }
        // THE durability point (fsynced WAL commit). Ack happens after.
        // The store RE-VALIDATES an Apply under the committing transaction:
        // if a concurrent local write landed during the (multi-second) fetch
        // window, the decision comes back downgraded and the rename that
        // already hit the disk must be repaired from the local row.
        let path = op.path.clone();
        let origin = op.origin;
        let effective = self.store.apply_remote(op, decision).await?;
        if decision == Decision::Apply && effective != Decision::Apply {
            // The committing re-check downgraded a stale Apply to Concurrent —
            // the second Concurrent site (FR-303 counter).
            Stats::inc(&self.stats.conflicts);
            tracing::warn!(
                path = %path,
                origin = %hex::encode(&origin[..4]),
                ?effective,
                "concurrent local write landed during transfer; restoring local content, remote recorded (resolution is M3)"
            );
            crate::merkle::restore_local_content(
                &self.store,
                &self.cas,
                &self.cfg.share_dir,
                &self.suppress,
                &path,
            )
            .await;
        }
        Ok(())
    }

    /// Execute the filesystem side of a `Decision::Apply` over the chunked
    /// data plane: manifest (db → origin → any peer) → missing-chunk fetch
    /// into the CAS (parallel, resumable) → streamed atomic assembly.
    async fn materialize(
        &self,
        _conn: &quinn::Connection,
        op: &OpRecord,
        local: Option<&crate::decide::LocalFile>,
    ) -> Result<(), NetError> {
        match op.op_type {
            OpType::Write => {
                let hash = op
                    .content_hash
                    .ok_or(NetError::Violation("write op without content hash"))?;
                // Transfer only what we lack (FR-401): skip the fetch when
                // the live local content already matches.
                let have = local.is_some_and(|l| !l.tombstone && l.content_hash == Some(hash));
                if !have {
                    if op.size > self.cfg.max_file_bytes {
                        return Err(NetError::TooBig);
                    }
                    // Pause gate (FR-1404): do not START a new transfer while
                    // paused; in-flight ones (past this point) finish.
                    self.await_unpaused().await;
                    // Engine-wide transfer bound (FR-1106): total in-flight
                    // bytes <= transfers x per-file concurrency x chunk max.
                    let _transfer_permit = self
                        .transfers
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| NetError::Violation("transfer limiter closed"))?;
                    Stats::gauge_inc(&self.stats.inflight_transfers);
                    let result = self.fetch_and_assemble(op, hash).await;
                    Stats::gauge_dec(&self.stats.inflight_transfers);
                    result?;
                }
            }
            OpType::Delete => {
                let share = self.cfg.share_dir.clone();
                let rel = op.path.clone();
                let suppress = self.suppress.clone();
                tokio::task::spawn_blocking(move || apply_delete(&share, &rel, &suppress))
                    .await??;
            }
        }
        Ok(())
    }

    /// Manifest -> missing chunks -> CAS -> streamed atomic assembly.
    async fn fetch_and_assemble(&self, op: &OpRecord, hash: [u8; 32]) -> Result<(), NetError> {
        let limits = self.fetch_limits();
        // Multi-source: candidates come from the shared registry, origin
        // first — not just this subscription's connection.
        let manifest = crate::fetch::obtain_manifest(
            hash,
            &self.store,
            &self.conns,
            op.origin,
            &limits,
            &self.stats,
        )
        .await?;
        crate::fetch::fetch_file_chunks(
            &manifest,
            &self.cas,
            &self.conns,
            op.origin,
            &limits,
            &self.stats,
        )
        .await?;
        let share = self.cfg.share_dir.clone();
        let rel = op.path.clone();
        let mode = op.mode;
        let suppress = self.suppress.clone();
        let cas = self.cas.clone();
        // fsync-heavy: keep it off the async runtime.
        tokio::task::spawn_blocking(move || {
            apply_assembled(&share, &rel, mode, &hash, &manifest, &cas, &suppress)
        })
        .await??;
        Ok(())
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    pub fn peer_registry(&self) -> PeerRegistry {
        self.peers_reg.clone()
    }

    pub fn conn_registry(&self) -> ConnRegistry {
        self.conns.clone()
    }

    fn fetch_limits(&self) -> crate::fetch::FetchLimits {
        crate::fetch::FetchLimits {
            per_file_chunk_concurrency: self.cfg.per_file_chunk_concurrency,
            max_chunk_bytes: self.cfg.chunk_max_bytes,
            max_file_bytes: self.cfg.max_file_bytes,
        }
    }

    /// Run one pull-based anti-entropy session against `peer` over a fresh
    /// tagged bi-stream on `conn` (FR-701/703). Returns the report and the
    /// per-origin op frontier the responder's snapshot covered (FR-1311) — the
    /// initial subscribe uses the frontier for the live-stream handoff;
    /// periodic reconciles ignore it.
    async fn reconcile_with(
        &self,
        conn: &quinn::Connection,
        peer: &Peer,
    ) -> Result<(ReconcileReport, Vec<(NodeId, i64)>), NetError> {
        let rows = self.store.all_files().await?;
        let local = MerkleTree::build(rows);
        let (mut send, recv) = conn.open_bi().await?;
        send.write_all(&[STREAM_TAG_RECONCILE]).await?;
        let mut transport = QuicReconcile {
            send,
            recv,
            engine: self,
            peer: peer.node_id,
            frontier: Vec::new(),
        };
        let ctx = ReconcileCtx {
            store: &self.store,
            cas: &self.cas,
            share: &self.cfg.share_dir,
            suppress: &self.suppress,
        };
        let report = reconcile_pull(&local, &mut transport, &ctx).await?;
        let _ = write_msg(&mut transport.send, &ReconcileFrame::Done).await;
        let _ = transport.send.finish();
        Stats::inc(&self.stats.reconcile_runs);
        Ok((report, transport.frontier))
    }

    // -- helpers ------------------------------------------------------------

    fn peer_fingerprint(&self, conn: &quinn::Connection) -> Result<[u8; 32], NetError> {
        let certs = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or(NetError::NoPeerCert)?;
        let first = certs.first().ok_or(NetError::NoPeerCert)?;
        Ok(cert_fingerprint(first.as_ref()))
    }

    /// Map an authenticated inbound connection to its EFFECTIVE peer. Using the
    /// dynamic membership (not the static intent) means a removed peer — evicted
    /// from the effective set and the allowlist — is rejected here even on the
    /// off chance it cleared the TLS layer mid-removal.
    fn identify(&self, conn: &quinn::Connection) -> Result<Peer, NetError> {
        let fp = self.peer_fingerprint(conn)?;
        self.membership
            .peer_by_fingerprint(&fp)
            .ok_or(NetError::UnknownPeer)
    }
}

/// QUIC implementation of the reconcile transport: framed RPCs on one tagged
/// bi-stream. Content fetches go MULTI-SOURCE through the engine's registry
/// (the session peer is just the origin hint) — a big file discovered via
/// reconcile still fans its chunks out across every live connection.
struct QuicReconcile<'a> {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    engine: &'a Engine,
    peer: NodeId,
    /// Captured from `RootIs` on the first `root()` call: the per-origin op
    /// frontier the served snapshot covers. `reconcile_with` reads it after a
    /// successful pull to advance the recv cursor (FR-1311).
    frontier: Vec<(NodeId, i64)>,
}

impl QuicReconcile<'_> {
    async fn rpc(&mut self, req: &ReconcileFrame) -> Result<ReconcileFrame, ReconcileError> {
        write_msg(&mut self.send, req).await?;
        read_msg(&mut self.recv).await.map_err(Into::into)
    }
}

impl ReconcileTransport for QuicReconcile<'_> {
    async fn root(&mut self) -> Result<[u8; 32], ReconcileError> {
        match self.rpc(&ReconcileFrame::Begin).await? {
            ReconcileFrame::RootIs { hash, frontier } => {
                self.frontier = frontier;
                Ok(hash)
            }
            _ => Err(ReconcileError::Violation("expected RootIs")),
        }
    }

    async fn children(
        &mut self,
        prefix: &str,
    ) -> Result<Vec<crate::proto::WireChild>, ReconcileError> {
        let mut out = Vec::new();
        let mut after = String::new();
        // Never trust network input: a count cap alone still lets a hostile
        // responder feed multi-GB of long names across pages — track BYTES
        // accumulated, not just entries, and reject non-filesystem names.
        let mut budget_bytes: usize = 32 * 1024 * 1024;
        loop {
            let resp = self
                .rpc(&ReconcileFrame::TreeReq {
                    prefix: prefix.to_string(),
                    after_name: after.clone(),
                    limit: TREE_PAGE,
                })
                .await?;
            match resp {
                ReconcileFrame::TreeResp { children, more } => {
                    if children.len() as u32 > TREE_PAGE {
                        return Err(ReconcileError::Violation("oversized tree page"));
                    }
                    if more && children.is_empty() {
                        return Err(ReconcileError::Violation("empty page with more=true"));
                    }
                    for c in &children {
                        if c.name.is_empty() || c.name.len() > 255 {
                            // Linux NAME_MAX: anything else is hostile.
                            return Err(ReconcileError::Violation("child name out of bounds"));
                        }
                        budget_bytes = budget_bytes.checked_sub(c.name.len() + 33).ok_or(
                            ReconcileError::Violation("directory listing exceeds budget"),
                        )?;
                    }
                    if let Some(last) = children.last() {
                        after = last.name.clone();
                    }
                    out.extend(children);
                    if !more {
                        return Ok(out);
                    }
                }
                _ => return Err(ReconcileError::Violation("expected TreeResp")),
            }
        }
    }

    async fn leaf(&mut self, path: &str) -> Result<Option<RemoteLeaf>, ReconcileError> {
        match self
            .rpc(&ReconcileFrame::LeafReq {
                path: path.to_string(),
            })
            .await?
        {
            ReconcileFrame::LeafResp { found: false, .. } => Ok(None),
            ReconcileFrame::LeafResp {
                found: true,
                tombstone,
                content_hash,
                vv,
                mode,
                size,
            } => Ok(Some(RemoteLeaf {
                tombstone,
                content_hash,
                vv,
                mode,
                size,
            })),
            _ => Err(ReconcileError::Violation("expected LeafResp")),
        }
    }

    async fn ensure_content(
        &mut self,
        content_hash: [u8; 32],
        cas: &Cas,
    ) -> Result<crate::chunk::Manifest, ReconcileError> {
        let limits = self.engine.fetch_limits();
        let manifest = crate::fetch::obtain_manifest(
            content_hash,
            &self.engine.store,
            &self.engine.conns,
            self.peer,
            &limits,
            &self.engine.stats,
        )
        .await?;
        crate::fetch::fetch_file_chunks(
            &manifest,
            cas,
            &self.engine.conns,
            self.peer,
            &limits,
            &self.engine.stats,
        )
        .await?;
        Ok(manifest)
    }
}

/// Would retrying this op ever succeed? `true` = quarantine it (record as
/// handled, advance the stream); `false` = transient, drop the connection and
/// let the dial loop resume from the durable cursor.
fn is_permanent(e: &NetError) -> bool {
    match e {
        // Malformed/hostile op fields, or bytes that can never verify.
        NetError::Violation(_) => true,
        // The origin no longer holds this content — a superseding op for the
        // path is behind it in the stream (or anti-entropy repairs).
        NetError::ContentUnavailable => true,
        // Exceeds OUR configured cap; redelivery cannot shrink it.
        NetError::TooBig => true,
        // Path escapes are rejected per CLAUDE.md invariant 5, permanently.
        NetError::Apply(ApplyError::UnsafePath(_)) => true,
        // The chunks individually verified but their composition does not
        // hash to the op's content: the manifest lied. Retrying re-fetches
        // the same manifest.
        NetError::Apply(ApplyError::HashMismatch(_)) => true,
        // Fetch layer's own classification (unavailable-everywhere / hostile
        // manifest are permanent; flaked peers are not).
        NetError::Fetch(f) => f.is_permanent(),
        // Everything else (I/O, store, stream, join) is worth a retry.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::oplog::LocalChange;
    use std::net::SocketAddr;

    fn test_config(
        node_id: NodeId,
        listen: SocketAddr,
        dir: &Path,
        ident: &GeneratedIdentity,
        peers: Vec<(NodeId, SocketAddr, [u8; 32])>,
    ) -> Config {
        let cert_path = dir.join(format!("{}.cert.pem", hex::encode(&node_id[..2])));
        let key_path = dir.join(format!("{}.key.pem", hex::encode(&node_id[..2])));
        std::fs::write(&cert_path, &ident.cert_pem).unwrap();
        std::fs::write(&key_path, &ident.key_pem).unwrap();
        Config {
            node_id,
            listen,
            share_dir: dir.to_path_buf(),
            db_path: dir.join("db"),
            cas_dir: dir.join("cas"),
            cert_path,
            key_path,
            health_listen: None,
            admin_pubkey: None,
            roster_path: dir.join("roster.json"),
            control_socket: dir.join("ctl.sock"),
            peers: peers
                .into_iter()
                .map(|(node_id, addr, fingerprint)| crate::config::Peer {
                    node_id,
                    addr,
                    fingerprint,
                })
                .collect(),
            quiesce_ms: 50,
            scan_interval_secs: 1,
            reconcile_interval_secs: 300,
            max_file_bytes: 1024 * 1024,
            chunk_min_bytes: 4096,
            chunk_avg_bytes: 16 * 1024,
            chunk_max_bytes: 64 * 1024,
            per_file_chunk_concurrency: 4,
            max_concurrent_transfers: 4,
            serve_concurrency: 8,
        }
    }

    fn engine_on(
        dir: &Path,
        node_id: NodeId,
        ident: &GeneratedIdentity,
        peers: Vec<(NodeId, SocketAddr, [u8; 32])>,
    ) -> Arc<Engine> {
        let cfg = test_config(node_id, "127.0.0.1:0".parse().unwrap(), dir, ident, peers);
        let store = Store::open(Path::new(":memory:"), node_id).unwrap();
        let cas = Cas::open(&cfg.cas_dir.join(hex::encode(&node_id[..2]))).unwrap();
        let membership = crate::membership::Membership::load(&cfg).unwrap();
        Engine::new(cfg, store, Suppressor::new(), cas, membership)
    }

    /// Append a local write WITH its chunks in the engine's CAS and the
    /// manifest in its store — what ingest does in production, so the chunked
    /// fetch path can serve it.
    async fn append_served(engine: &Arc<Engine>, rel: &str, data: &[u8]) -> OpRecord {
        let hash = *blake3::hash(data).as_bytes();
        engine.cas.put_verified(&hash, data).unwrap();
        let manifest = crate::chunk::Manifest {
            content_hash: hash,
            chunks: vec![crate::proto::ChunkEntry {
                hash,
                len: data.len() as u32,
            }],
        };
        engine
            .store
            .append_local(LocalChange {
                path: rel.into(),
                op_type: OpType::Write,
                mode: 0o644,
                size: data.len() as u64,
                content_hash: Some(hash),
                manifest: Some(manifest),
            })
            .await
            .unwrap()
            .unwrap()
    }

    /// Admin-keyed engine + a signed Add for `member`, so its fingerprint is in
    /// the live allowlist. Returns (engine, admin secret) for further churn.
    fn admin_engine_with_member(
        dir: &Path,
        node_id: NodeId,
        ident: &GeneratedIdentity,
        member: NodeId,
        member_addr: SocketAddr,
        member_fp: [u8; 32],
    ) -> (Arc<Engine>, crate::admin::AdminSecret) {
        let (doc, pk) = crate::admin::generate_admin_key().unwrap();
        let kp = dir.join(format!("admin-{}.sk", hex::encode(&node_id[..2])));
        std::fs::write(&kp, &doc).unwrap();
        let sk = crate::admin::AdminSecret::load(&kp).unwrap();

        let mut cfg = test_config(node_id, "127.0.0.1:0".parse().unwrap(), dir, ident, vec![]);
        cfg.admin_pubkey = Some(pk);
        cfg.roster_path = dir.join(format!("roster-{}.json", hex::encode(&node_id[..2])));
        let store = Store::open(Path::new(":memory:"), node_id).unwrap();
        let cas = Cas::open(&cfg.cas_dir.join(hex::encode(&node_id[..2]))).unwrap();
        let mem = crate::membership::Membership::load(&cfg).unwrap();
        let engine = Engine::new(cfg, store, Suppressor::new(), cas, mem);

        let add = signed_entry(
            &sk,
            member,
            member_addr,
            member_fp,
            1,
            crate::admin::EntryKind::Add,
        );
        assert_eq!(
            engine.membership().merge_signed(add).unwrap(),
            crate::membership::MergeOutcome::Applied
        );
        (engine, sk)
    }

    fn signed_entry(
        sk: &crate::admin::AdminSecret,
        node: NodeId,
        addr: SocketAddr,
        fp: [u8; 32],
        epoch: u64,
        kind: crate::admin::EntryKind,
    ) -> crate::membership::SignedEntry {
        let sig = crate::admin::sign_entry(sk, &node, &addr, &fp, epoch, kind);
        crate::membership::SignedEntry {
            node_id: node,
            addr,
            fingerprint: fp,
            epoch,
            kind,
            sig,
        }
    }

    /// THE removal-locks-out pin (FR-1307): the TLS verifiers read the LIVE
    /// allowlist per handshake, so once an admin-signed Remove evicts a node's
    /// fingerprint, a fresh handshake from that node is refused at TLS — even
    /// though it handshook fine moments earlier. A refactor that snapshotted the
    /// allowlist at endpoint-build time would regress this test.
    #[tokio::test]
    async fn removed_peer_handshake_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_c = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const C: NodeId = [0xc; 16];
        let c_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // A: admin-keyed, with C admitted (its fp is in A's live allowlist).
        let (engine_a, admin_sk) =
            admin_engine_with_member(dir.path(), A, &id_a, C, c_addr, id_c.fingerprint);
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();

        // Report each server-side handshake outcome (authoritative for client
        // auth under TLS 1.3 — the client may finish before the server rejects).
        let (res_tx, mut res_rx) = tokio::sync::mpsc::channel(4);
        let accept = tokio::spawn({
            let ep = ep_a.clone();
            async move {
                while let Some(incoming) = ep.accept().await {
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(incoming.await.map(|_| ())).await;
                    });
                }
            }
        });

        // C dials A; C pins A (A seeded into C's allowlist).
        let engine_c = engine_on(dir.path(), C, &id_c, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_c = engine_c.build_endpoint().unwrap();

        // Round 1 — C is a member: the server-side handshake succeeds.
        let _ = ep_c.connect(addr_a, "replicore").unwrap().await;
        let r1 = res_rx.recv().await.unwrap();
        assert!(r1.is_ok(), "member C was refused before removal: {r1:?}");

        // Admin-remove C: its fp leaves the SAME live allowlist Arc the already-
        // built endpoint's verifier reads.
        let next = engine_a.membership().next_epoch_for(&C);
        let rm = signed_entry(
            &admin_sk,
            C,
            c_addr,
            id_c.fingerprint,
            next,
            crate::admin::EntryKind::Remove,
        );
        assert_eq!(
            engine_a.membership().merge_signed(rm).unwrap(),
            crate::membership::MergeOutcome::Applied
        );

        // Round 2 — a FRESH handshake from the now-removed C is refused at TLS.
        let _ = ep_c.connect(addr_a, "replicore").unwrap().await;
        let r2 = res_rx.recv().await.unwrap();
        assert!(
            r2.is_err(),
            "removed peer completed a TLS handshake (allowlist not consulted live, \
             or session resumption bypassed client-auth): {r2:?}"
        );

        accept.abort();
    }

    #[test]
    fn generated_identity_round_trips_through_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ident = generate_identity().unwrap();
        let cert_path = dir.path().join("c.pem");
        let key_path = dir.path().join("k.pem");
        std::fs::write(&cert_path, &ident.cert_pem).unwrap();
        std::fs::write(&key_path, &ident.key_pem).unwrap();
        let (cert, _key) = load_identity(&cert_path, &key_path).unwrap();
        // The fingerprint printed by gen-cert is what verifiers compute.
        assert_eq!(cert_fingerprint(cert.as_ref()), ident.fingerprint);
    }

    #[tokio::test]
    async fn pinned_cert_accepted_unlisted_cert_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        let id_x = generate_identity().unwrap(); // NOT in anyone's allowlist

        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];
        const X: NodeId = [0xc; 16];

        // A pins only B.
        let engine_a = engine_on(
            dir.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        // Report each server-side handshake outcome. In TLS 1.3 the CLIENT
        // can finish before the server validates the client cert, so the
        // authoritative accept/reject signal for inbound peers is here.
        let (res_tx, mut res_rx) = tokio::sync::mpsc::channel(4);
        let accept = tokio::spawn({
            let ep = ep_a.clone();
            async move {
                while let Some(incoming) = ep.accept().await {
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(incoming.await).await;
                    });
                }
            }
        });

        // B (pinned by A, pins A): both sides must succeed.
        let engine_b = engine_on(dir.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let conn_b = ep_b.connect(addr_a, "replicore").unwrap().await;
        assert!(conn_b.is_ok(), "pinned peer rejected: {conn_b:?}");
        let server_conn = res_rx
            .recv()
            .await
            .unwrap()
            .expect("server rejected the pinned peer");
        // The server can bind the connection to B's pinned identity.
        assert_eq!(
            engine_a.peer_fingerprint(&server_conn).unwrap(),
            id_b.fingerprint
        );

        // X (unlisted at A): the server MUST fail the handshake (exit
        // criterion 5), and the client side must end up unusable.
        let engine_x = engine_on(dir.path(), X, &id_x, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_x = engine_x.build_endpoint().unwrap();
        let conn_x = ep_x.connect(addr_a, "replicore").unwrap().await;
        let server_side = res_rx.recv().await.unwrap();
        assert!(server_side.is_err(), "server accepted an unlisted peer");
        if let Ok(conn) = conn_x {
            // Client finished first; the server's rejection closes it now
            // with a TLS bad_certificate crypto error.
            let err = conn.closed().await;
            assert!(
                matches!(
                    err,
                    quinn::ConnectionError::TransportError(_)
                        | quinn::ConnectionError::ConnectionClosed(_)
                ),
                "expected a TLS rejection, got {err:?}"
            );
        }

        accept.abort();
    }

    #[tokio::test]
    async fn poison_op_is_quarantined_and_stream_advances() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];

        // Full inbound handling on A (push + acks + fetch serving).
        let engine_a = engine_on(
            dir_a.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        tokio::spawn({
            let engine = engine_a.clone();
            async move {
                while let Some(incoming) = ep_a.accept().await {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        let _ = engine.handle_inbound(incoming).await;
                    });
                }
            }
        });

        // B subscribes for real and reaches Live against an EMPTY A, so its
        // initial reconcile bootstrap is a no-op and the ops below ride the
        // LIVE op stream (this is the path whose quarantine we are testing —
        // the frontier handoff means a pre-existing op would instead be
        // bootstrapped via reconcile, exercising a different code path).
        let engine_b = engine_on(dir_b.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let peer_a = engine_b.cfg.peers[0].clone();
        tokio::spawn({
            let engine = engine_b.clone();
            async move {
                let mut attempt: u32 = 0;
                let _ = engine.subscribe_once(&ep_b, &peer_a, &mut attempt).await;
            }
        });
        let mut live = false;
        for _ in 0..200 {
            if engine_b.peers_reg.get(&A).state == PeerState::Live {
                live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(live, "B never reached Live against empty A");

        // Op 1 is poison: the path escapes the share — its chunks are served
        // fine, but apply_assembled rejects the path (UnsafePath, permanent).
        // Op 2 is a normal write queued right behind it — the liveness
        // property under test is that op 2 still arrives over the live stream.
        append_served(&engine_a, "../evil", b"poison").await;
        std::fs::write(dir_a.path().join("good.txt"), b"fine").unwrap();
        append_served(&engine_a, "good.txt", b"fine").await;

        // The good op behind the poison op must land.
        let mut applied = false;
        for _ in 0..200 {
            if engine_b
                .store
                .load_file("good.txt")
                .await
                .unwrap()
                .is_some_and(|l| !l.tombstone)
            {
                applied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(applied, "stream stalled behind the poison op");
        assert_eq!(
            std::fs::read(dir_b.path().join("good.txt")).unwrap(),
            b"fine"
        );

        // The poison op was durably quarantined: handled, cursor advanced
        // past it, no file index entry materialized, nothing escaped the
        // share root.
        assert!(engine_b
            .store
            .has_applied(crate::proto::op_id(&A, 1))
            .await
            .unwrap());
        assert_eq!(engine_b.store.recv_cursor(A).await.unwrap(), 2);
        assert!(engine_b.store.load_file("../evil").await.unwrap().is_none());
        assert!(!dir_b.path().parent().unwrap().join("evil").exists());

        // Positive ack-frontier case: legitimate acks still advance.
        let mut acked = false;
        for _ in 0..200 {
            if engine_a.store.last_acked(B).await.unwrap() == 2 {
                acked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(acked, "legitimate acks did not advance last_acked_seq");
    }

    /// The join frontier (FR-1311): a node bootstraps a peer's existing ops via
    /// the reconcile snapshot, advances its recv cursor to that snapshot's
    /// frontier, and then streams ONLY live ops past the frontier — none of the
    /// bootstrapped history is re-streamed (no double apply), and a disconnect
    /// after the handoff resumes from the advanced cursor (crash points
    /// post-cursor / post-subscribe). New ops still flow after the resume.
    #[tokio::test]
    async fn join_frontier_bootstraps_then_streams_live_without_redelivery() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];

        let engine_a = engine_on(
            dir_a.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        tokio::spawn({
            let engine = engine_a.clone();
            async move {
                while let Some(incoming) = ep_a.accept().await {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        let _ = engine.handle_inbound(incoming).await;
                    });
                }
            }
        });

        // A already holds three ops BEFORE B ever connects — these must arrive
        // via the reconcile bootstrap, not the live op stream.
        for (i, name) in ["one", "two", "three"].iter().enumerate() {
            std::fs::write(dir_a.path().join(name), format!("v{i}")).unwrap();
            append_served(&engine_a, name, format!("v{i}").as_bytes()).await;
        }

        let engine_b = engine_on(dir_b.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let peer_a = engine_b.cfg.peers[0].clone();

        // First session: connect, reconcile-bootstrap, reach Live, then we tear
        // it down (simulating a disconnect right after the handoff).
        let sess = tokio::spawn({
            let engine = engine_b.clone();
            let ep = ep_b.clone();
            let peer = peer_a.clone();
            async move {
                let mut attempt = 0;
                let _ = engine.subscribe_once(&ep, &peer, &mut attempt).await;
            }
        });
        let mut live = false;
        for _ in 0..200 {
            if engine_b.peers_reg.get(&A).state == PeerState::Live {
                live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(live, "B never reached Live");

        // Bootstrapped: all three files converged, the cursor jumped to the
        // snapshot frontier (3), and NONE of A's ops are in `applied` — proof
        // they came through reconcile, not a re-stream of history.
        for name in ["one", "two", "three"] {
            assert!(engine_b.store.load_file(name).await.unwrap().is_some());
        }
        assert_eq!(engine_b.store.recv_cursor(A).await.unwrap(), 3);
        assert!(!engine_b
            .store
            .has_applied(crate::proto::op_id(&A, 1))
            .await
            .unwrap());
        assert!(!engine_b
            .store
            .has_applied(crate::proto::op_id(&A, 3))
            .await
            .unwrap());

        // A NEW op on the SAME live session rides the op stream (> frontier):
        // recorded in `applied`, cursor to 4 — no overlap with the bootstrap.
        std::fs::write(dir_a.path().join("four"), b"v3").unwrap();
        append_served(&engine_a, "four", b"v3").await; // origin_seq 4, live
        let mut got_four = false;
        for _ in 0..200 {
            if engine_b
                .store
                .has_applied(crate::proto::op_id(&A, 4))
                .await
                .unwrap()
            {
                got_four = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            got_four,
            "live op past the frontier did not arrive via the op path"
        );
        assert_eq!(engine_b.store.recv_cursor(A).await.unwrap(), 4);
        assert_eq!(std::fs::read(dir_b.path().join("four")).unwrap(), b"v3");

        // Resume after a disconnect (crash points 3/4): tear the session down,
        // reconnect, append another op. Convergence holds and the cursor only
        // ever advances — it is never rewound below the durable frontier,
        // however the op is delivered (live stream or the reconnect's reconcile).
        sess.abort();
        let _ = sess.await;
        tokio::spawn({
            let engine = engine_b.clone();
            let ep = ep_b.clone();
            async move {
                let mut attempt = 0;
                let _ = engine.subscribe_once(&ep, &peer_a, &mut attempt).await;
            }
        });
        std::fs::write(dir_a.path().join("five"), b"v4").unwrap();
        append_served(&engine_a, "five", b"v4").await; // origin_seq 5
        let mut got_five = false;
        for _ in 0..200 {
            if std::fs::read(dir_b.path().join("five")).is_ok_and(|d| d == b"v4") {
                got_five = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(got_five, "op after resume did not arrive");
        assert_eq!(engine_b.store.recv_cursor(A).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn fetch_survives_dead_peer_and_classifies_unavailable() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];
        const GHOST: NodeId = [0xd; 16]; // "origin" whose connection is dead

        // A serves chunk/manifest streams (no subscription needed).
        let engine_a = engine_on(
            dir_a.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        tokio::spawn({
            let ep = ep_a.clone();
            let engine = engine_a.clone();
            async move {
                while let Some(incoming) = ep.accept().await {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let _ = engine.serve_streams(conn).await;
                        }
                    });
                }
            }
        });

        // Content lives on A.
        let data = b"multi-source chunk";
        let op = append_served(&engine_a, "x.bin", data).await;
        let hash = op.content_hash.unwrap();

        // B holds TWO registry entries: a dead connection (the "origin",
        // vanished mid-fetch) and the live one to A.
        let engine_b = engine_on(dir_b.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let live = ep_b.connect(addr_a, "replicore").unwrap().await.unwrap();
        let dead = ep_b.connect(addr_a, "replicore").unwrap().await.unwrap();
        dead.close(0u32.into(), b"gone");
        engine_b.conns.insert(GHOST, dead);
        engine_b.conns.insert(A, live);

        // Origin-first ordering hits the dead conn first; the fetch must
        // fall through to A and land the chunk in B's CAS (FR-403).
        let limits = engine_b.fetch_limits();
        let manifest = crate::fetch::obtain_manifest(
            hash,
            &engine_b.store,
            &engine_b.conns,
            GHOST,
            &limits,
            &engine_b.stats,
        )
        .await
        .expect("manifest via the surviving peer");
        crate::fetch::fetch_file_chunks(
            &manifest,
            &engine_b.cas,
            &engine_b.conns,
            GHOST,
            &limits,
            &engine_b.stats,
        )
        .await
        .expect("chunks via the surviving peer");
        assert!(engine_b.cas.has(&hash));

        // A hash nobody holds: every live peer answers not-found, which is
        // the PERMANENT classification (quarantine), not a retry loop.
        let err = crate::fetch::obtain_manifest(
            [0x42; 32],
            &engine_b.store,
            &engine_b.conns,
            GHOST,
            &limits,
            &engine_b.stats,
        )
        .await
        .unwrap_err();
        assert!(err.is_permanent(), "expected permanent, got {err:?}");
    }

    /// THE stale-decision race, end to end over real sockets: a remote
    /// Apply for path P whose transfer is delayed (deterministically, by
    /// draining B's `transfers` semaphore — acquired inside materialize
    /// AFTER decide), with a local write to P landing during the delay.
    /// The committing re-check must record Concurrent, and the on-disk
    /// clobber from the already-performed rename must be repaired from the
    /// local row. No committed state may be lost.
    #[tokio::test]
    async fn concurrent_local_write_during_transfer_is_not_clobbered() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];

        let engine_a = engine_on(
            dir_a.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        tokio::spawn({
            let engine = engine_a.clone();
            async move {
                while let Some(incoming) = ep_a.accept().await {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        let _ = engine.handle_inbound(incoming).await;
                    });
                }
            }
        });

        // B subscribes (gate reconcile runs against an empty A — fast).
        let engine_b = engine_on(dir_b.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let peer_a = engine_b.cfg.peers[0].clone();
        tokio::spawn({
            let engine = engine_b.clone();
            async move {
                let mut attempt: u32 = 0;
                let _ = engine.subscribe_once(&ep_b, &peer_a, &mut attempt).await;
            }
        });
        // Let the subscription reach Live.
        let mut live = false;
        for _ in 0..100 {
            if engine_b.peers_reg.get(&A).state == PeerState::Live {
                live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(live, "subscription never reached Live");

        // Drain B's transfer permits: the next materialize will park AFTER
        // decide(), holding a stale Apply — the exact hazard window.
        let gate = engine_b
            .transfers
            .clone()
            .acquire_many_owned(engine_b.cfg.max_concurrent_transfers as u32)
            .await
            .unwrap();

        // A writes the racing remote op (content R).
        let remote_op = append_served(&engine_a, "race.bin", b"remote content R").await;
        // Give B time to receive the push, decide Apply, and park.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The concurrent LOCAL write on B (content X): file + chunks + op.
        let local_data = b"local content X";
        let local_hash = *blake3::hash(local_data).as_bytes();
        std::fs::write(dir_b.path().join("race.bin"), local_data).unwrap();
        append_served(&engine_b, "race.bin", local_data).await;

        // Release the window: fetch + assemble (the rename clobbers the
        // disk!) + the committing re-check + the repair.
        drop(gate);

        // The remote op must end durably handled (stream advanced)...
        let mut handled = false;
        for _ in 0..200 {
            if engine_b.store.has_applied(remote_op.op_id).await.unwrap() {
                handled = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(handled, "remote op never durably handled");
        assert_eq!(engine_b.store.recv_cursor(A).await.unwrap(), 1);

        // ...as Concurrent: the row keeps the LOCAL content and the remote
        // VV component was NOT merged (no causal masking).
        let row = engine_b.store.load_file("race.bin").await.unwrap().unwrap();
        assert_eq!(row.content_hash, Some(local_hash), "row clobbered");
        assert_eq!(row.vv.get(&A), 0, "remote VV merged: clobber masked");
        assert_eq!(row.vv.get(&B), 1);

        // And the DISK was repaired back to the local content.
        let mut repaired = false;
        for _ in 0..100 {
            if std::fs::read(dir_b.path().join("race.bin"))
                .is_ok_and(|d| d == local_data.as_slice())
            {
                repaired = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(repaired, "disk clobber was not repaired to local content");

        // The stream continues past the conflict: a later op still lands.
        std::fs::write(dir_a.path().join("after.txt"), b"flows").unwrap();
        append_served(&engine_a, "after.txt", b"flows").await;
        let mut flowed = false;
        for _ in 0..200 {
            if std::fs::read(dir_b.path().join("after.txt")).is_ok_and(|d| d == b"flows") {
                flowed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(flowed, "stream did not continue after the conflict");
    }

    #[tokio::test]
    async fn ack_beyond_pushed_frontier_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];

        let engine_a = engine_on(
            dir.path(),
            A,
            &id_a,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_a = engine_a.build_endpoint().unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        let (res_tx, mut res_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn({
            let engine = engine_a.clone();
            async move {
                while let Some(incoming) = ep_a.accept().await {
                    let engine = engine.clone();
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(engine.handle_inbound(incoming).await).await;
                    });
                }
            }
        });

        // A pinned-but-lying peer: valid handshake, then an ack for ops it
        // was never sent (A's oplog is empty; frontier == resume_from == 0).
        let engine_b = engine_on(dir.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let conn = ep_b.connect(addr_a, "replicore").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        write_msg(
            &mut send,
            &Frame::Hello {
                proto_version: PROTO_VERSION,
                node_id: B,
                resume: vec![(A, 0)],
            },
        )
        .await
        .unwrap();
        let _hello_ack: Frame = read_msg(&mut recv).await.unwrap();
        // Pass the reconcile gate (a lying peer can skip the session and
        // claim it is done — that is fine, the gate protects the DIALER).
        write_msg(
            &mut send,
            &Frame::SubscribeOps {
                resume: vec![(A, 0)],
            },
        )
        .await
        .unwrap();
        write_msg(
            &mut send,
            &Frame::OplogAck {
                origin: A,
                up_to_seq: 999_999,
            },
        )
        .await
        .unwrap();

        let result = res_rx.recv().await.unwrap();
        assert!(
            matches!(&result, Err(NetError::Violation(m)) if m.contains("frontier")),
            "expected frontier violation, got {result:?}"
        );
        // The inflated ack must not have been persisted.
        assert_eq!(engine_a.store.last_acked(B).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn rejects_server_whose_cert_is_not_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let id_a = generate_identity().unwrap();
        let id_b = generate_identity().unwrap();
        let id_evil = generate_identity().unwrap();

        const A: NodeId = [0xa; 16];
        const B: NodeId = [0xb; 16];

        // "Evil" server: presents a cert B does NOT pin, but pins B itself
        // (so the client-cert side would pass).
        let engine_evil = engine_on(
            dir.path(),
            A,
            &id_evil,
            vec![(B, "127.0.0.1:1".parse().unwrap(), id_b.fingerprint)],
        );
        let ep_evil = engine_evil.build_endpoint().unwrap();
        let addr_evil = ep_evil.local_addr().unwrap();
        let accept = tokio::spawn({
            let ep = ep_evil.clone();
            async move {
                while let Some(incoming) = ep.accept().await {
                    tokio::spawn(async move {
                        let _ = incoming.await;
                    });
                }
            }
        });

        // B pins only the REAL A; dialing the evil server must fail in OUR
        // verifier (client side pin).
        let engine_b = engine_on(dir.path(), B, &id_b, vec![(A, addr_evil, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let conn = ep_b.connect(addr_evil, "replicore").unwrap().await;
        assert!(conn.is_err(), "unpinned server was accepted");

        accept.abort();
    }
}
