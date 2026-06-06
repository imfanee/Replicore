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

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::apply::{apply_delete, apply_write, ApplyError};
use crate::config::{Config, Peer};
use crate::decide::{decide, Decision};
use crate::oplog::{Store, StoreError};
use crate::proto::{
    read_msg, write_msg, FetchReq, FetchResp, Frame, OpRecord, OpType, ProtoError, ALPN,
    PROTO_VERSION,
};
use crate::suppress::Suppressor;
use crate::vv::NodeId;

/// Ops pushed per batch between cursor reads.
const PUSH_BATCH: u32 = 64;
const RECONNECT_MIN: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(15);

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

fn pin_ok(allow: &HashSet<[u8; 32]>, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
    if allow.contains(&cert_fingerprint(end_entity.as_ref())) {
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
    allow: HashSet<[u8; 32]>,
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
    allow: HashSet<[u8; 32]>,
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
}

impl Engine {
    pub fn new(cfg: Config, store: Store, suppress: Suppressor) -> Arc<Engine> {
        Arc::new(Engine {
            cfg: Arc::new(cfg),
            store,
            suppress,
        })
    }

    /// Build the dual-role endpoint: server config (require + pin client
    /// certs) bound to `cfg.listen`, default client config (present our cert,
    /// pin server certs).
    pub fn build_endpoint(&self) -> Result<quinn::Endpoint, NetError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = load_identity(&self.cfg.cert_path, &self.cfg.key_path)?;
        let allow: HashSet<[u8; 32]> = self.cfg.pinned_fingerprints().into_iter().collect();

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
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
        let endpoint = self.build_endpoint()?;
        for peer in self.cfg.peers.clone() {
            let engine = self.clone();
            let ep = endpoint.clone();
            tokio::spawn(async move { engine.dial_loop(ep, peer).await });
        }
        self.accept_loop(endpoint).await
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

        // The dialer opens the control stream and speaks first.
        let (mut ctl_send, mut ctl_recv) = conn.accept_bi().await?;
        let resume_from = match read_msg::<_, Frame>(&mut ctl_recv).await? {
            Frame::Hello {
                proto_version,
                node_id,
                resume,
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
                // M2 full mesh: we push only our own ops, so only our entry
                // of the frontier map matters. The rest is the relay seam.
                resume
                    .iter()
                    .find(|(origin, _)| origin == &self.cfg.node_id)
                    .map(|(_, cursor)| *cursor)
                    .unwrap_or(0)
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
        tracing::info!(
            peer = %hex::encode(&peer.node_id[..4]),
            resume_from,
            "peer subscribed to our ops"
        );

        // The pushed frontier: highest origin_seq actually streamed on THIS
        // connection. Acks are validated against it — a peer must not be able
        // to ack ops it was never sent (last_acked_seq feeds tombstone GC in
        // M2; an inflated ack there means premature GC and resurrection risk).
        let sent_frontier = Arc::new(AtomicI64::new(resume_from));

        let push = self.push_ops(ctl_send, resume_from, sent_frontier.clone());
        let acks = self.absorb_acks(ctl_recv, peer.node_id, sent_frontier);
        let fetches = self.serve_fetches(conn.clone());
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
            let ops = self
                .store
                .ops_since(self.cfg.node_id, cursor, PUSH_BATCH)
                .await?;
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

    /// Serve ephemeral bi-stream content fetches on an inbound connection.
    async fn serve_fetches(self: &Arc<Engine>, conn: quinn::Connection) -> Result<(), NetError> {
        loop {
            let (send, recv) = conn.accept_bi().await?;
            let engine = self.clone();
            tokio::spawn(async move {
                if let Err(e) = engine.serve_one_fetch(send, recv).await {
                    tracing::debug!(error = %e, "fetch stream ended");
                }
            });
        }
    }

    async fn serve_one_fetch(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<(), NetError> {
        let req: FetchReq = read_msg(&mut recv).await?;
        // Resolve hash -> live path -> bytes, re-verifying the hash: the file
        // may have changed since it was indexed. Never serve unverified bytes.
        let data = match self.store.path_for_hash(req.hash).await? {
            Some(rel) => {
                let abs = self.cfg.share_dir.join(&rel);
                match tokio::fs::read(&abs).await {
                    Ok(data)
                        if data.len() as u64 <= self.cfg.max_file_bytes
                            && *blake3::hash(&data).as_bytes() == req.hash =>
                    {
                        Some(data)
                    }
                    Ok(_) => None,  // changed underfoot or oversized
                    Err(_) => None, // raced a delete
                }
            }
            None => None,
        };
        match data {
            Some(data) => {
                write_msg(
                    &mut send,
                    &FetchResp {
                        found: true,
                        size: data.len() as u64,
                    },
                )
                .await?;
                send.write_all(&data).await?;
            }
            None => {
                write_msg(
                    &mut send,
                    &FetchResp {
                        found: false,
                        size: 0,
                    },
                )
                .await?;
            }
        }
        let _ = send.finish();
        Ok(())
    }

    // -- outbound -----------------------------------------------------------

    /// Maintain our subscription to `peer`'s ops forever, reconnecting with
    /// backoff (FR-602-lite; full liveness detection is M2).
    async fn dial_loop(self: Arc<Engine>, endpoint: quinn::Endpoint, peer: Peer) {
        let mut backoff = RECONNECT_MIN;
        loop {
            match self.subscribe_once(&endpoint, &peer, &mut backoff).await {
                Ok(()) => tracing::info!(addr = %peer.addr, "subscription closed; reconnecting"),
                Err(e) => {
                    tracing::warn!(addr = %peer.addr, error = %e, "subscription failed; reconnecting")
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RECONNECT_MAX);
        }
    }

    /// One subscription session: connect, Hello/HelloAck, then apply pushed
    /// ops in order, acking after each durable commit.
    async fn subscribe_once(
        &self,
        endpoint: &quinn::Endpoint,
        peer: &Peer,
        backoff: &mut Duration,
    ) -> Result<(), NetError> {
        // The server name is irrelevant under pinning but required by the API.
        let conn = endpoint.connect(peer.addr, "replicore")?.await?;

        // Belt and braces: the default verifier pinned *some* allowlisted
        // cert; bind this connection to THIS peer's fingerprint.
        let fp = self.peer_fingerprint(&conn)?;
        if fp != peer.fingerprint {
            return Err(NetError::PeerIdentityMismatch);
        }

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
        tracing::info!(
            peer = %hex::encode(&peer.node_id[..4]),
            resume_from,
            "subscribed to peer ops"
        );
        *backoff = RECONNECT_MIN; // handshake succeeded: reset

        loop {
            match read_msg::<_, Frame>(&mut ctl_recv).await {
                Ok(Frame::OplogPush(op)) => {
                    let seq = op.origin_seq;
                    if op.origin != peer.node_id {
                        // Full-mesh peers push only their own ops; forwarding
                        // arrives with the relay policy (FR-603 seam).
                        return Err(NetError::Violation("op origin is not the pushing peer"));
                    }
                    self.process_remote_op(&conn, op).await?;
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
            tracing::warn!(
                path = %op.path,
                origin = %hex::encode(&op.origin[..4]),
                "concurrent versions detected; keeping local (resolution is M3)"
            );
        }
        // THE durability point (fsynced WAL commit). Ack happens after.
        self.store.apply_remote(op, decision).await?;
        Ok(())
    }

    /// Execute the filesystem side of a `Decision::Apply`.
    async fn materialize(
        &self,
        conn: &quinn::Connection,
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
                    let data = fetch_bytes(conn, hash, self.cfg.max_file_bytes).await?;
                    let share = self.cfg.share_dir.clone();
                    let rel = op.path.clone();
                    let mode = op.mode;
                    let suppress = self.suppress.clone();
                    // fsync-heavy: keep it off the async runtime.
                    tokio::task::spawn_blocking(move || {
                        apply_write(&share, &rel, mode, &hash, &data, &suppress)
                    })
                    .await??;
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

    // -- helpers ------------------------------------------------------------

    fn peer_fingerprint(&self, conn: &quinn::Connection) -> Result<[u8; 32], NetError> {
        let certs = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or(NetError::NoPeerCert)?;
        let first = certs.first().ok_or(NetError::NoPeerCert)?;
        Ok(cert_fingerprint(first.as_ref()))
    }

    /// Map an authenticated inbound connection to its configured peer.
    fn identify(&self, conn: &quinn::Connection) -> Result<Peer, NetError> {
        let fp = self.peer_fingerprint(conn)?;
        self.cfg
            .peer_by_fingerprint(&fp)
            .cloned()
            .ok_or(NetError::UnknownPeer)
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
        // path is behind it in the stream (or M2 anti-entropy repairs).
        NetError::ContentUnavailable => true,
        // Exceeds OUR configured cap; redelivery cannot shrink it.
        NetError::TooBig => true,
        // Path escapes are rejected per CLAUDE.md invariant 5, permanently.
        NetError::Apply(ApplyError::UnsafePath(_)) => true,
        // Everything else (I/O, store, stream, join) is worth a retry.
        _ => false,
    }
}

/// Fetch `hash`'s bytes over an ephemeral bi-stream, verified before return.
async fn fetch_bytes(
    conn: &quinn::Connection,
    hash: [u8; 32],
    max_bytes: u64,
) -> Result<Vec<u8>, NetError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &FetchReq { hash }).await?;
    let _ = send.finish();
    let resp: FetchResp = read_msg(&mut recv).await?;
    if !resp.found {
        return Err(NetError::ContentUnavailable);
    }
    if resp.size > max_bytes {
        return Err(NetError::TooBig);
    }
    let mut data = vec![0u8; resp.size as usize];
    recv.read_exact(&mut data).await?;
    // Verify BEFORE the bytes are used anywhere (FR-403 spirit; apply_write
    // re-verifies what lands on disk).
    if *blake3::hash(&data).as_bytes() != hash {
        return Err(NetError::Violation("fetched bytes do not match hash"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
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
        Engine::new(cfg, store, Suppressor::new())
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

        // Op 1 is poison: the path escapes the share AND its content is not
        // fetchable. Op 2 is a normal write queued right behind it — the
        // liveness property under test is that op 2 still arrives.
        use crate::oplog::LocalChange;
        engine_a
            .store
            .append_local(LocalChange {
                path: "../evil".into(),
                op_type: OpType::Write,
                mode: 0o644,
                size: 6,
                content_hash: Some(*blake3::hash(b"poison").as_bytes()),
            })
            .await
            .unwrap()
            .unwrap();
        std::fs::write(dir_a.path().join("good.txt"), b"fine").unwrap();
        engine_a
            .store
            .append_local(LocalChange {
                path: "good.txt".into(),
                op_type: OpType::Write,
                mode: 0o644,
                size: 4,
                content_hash: Some(*blake3::hash(b"fine").as_bytes()),
            })
            .await
            .unwrap()
            .unwrap();

        // B subscribes for real.
        let engine_b = engine_on(dir_b.path(), B, &id_b, vec![(A, addr_a, id_a.fingerprint)]);
        let ep_b = engine_b.build_endpoint().unwrap();
        let peer_a = engine_b.cfg.peers[0].clone();
        tokio::spawn({
            let engine = engine_b.clone();
            async move {
                let mut backoff = RECONNECT_MIN;
                let _ = engine.subscribe_once(&ep_b, &peer_a, &mut backoff).await;
            }
        });

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
