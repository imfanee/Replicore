//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! health.rs — hand-rolled HTTP/1.1 health + metrics endpoint (FR-1102/1101).
//!
//! `GET /healthz` returns a JSON snapshot: per-peer state + cursors, transfer
//! counters, CAS stats, queue gauges. `GET /metrics` exposes the same state
//! (plus per-peer lag, cache hit rate, conflicts, guard trips, owner skips)
//! in Prometheus text format — built at scrape time from the live atomics
//! via a transient registry, so no double bookkeeping exists. Everything
//! else is a 404; requests over 8 KiB are rejected (bound every buffer —
//! even on localhost). Bind `health_listen` to a management interface: both
//! endpoints are intentionally unauthenticated, Prometheus-style.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::chunk::Cas;
use crate::ingest::LocalEvent;
use crate::oplog::Store;
use crate::peer::{ConnRegistry, PeerRegistry};
use crate::stats::Stats;
use crate::vv::NodeId;

const MAX_REQUEST: usize = 8 * 1024;

/// Cheap-to-clone handles the endpoint reads from.
#[derive(Clone)]
pub struct HealthCtx {
    pub node_id: NodeId,
    pub stats: Arc<Stats>,
    pub peers: PeerRegistry,
    pub conns: ConnRegistry,
    pub cas: Cas,
    pub store: Store,
    pub configured_peers: Vec<NodeId>,
    /// Held only to gauge the events queue depth; never sent on.
    pub events_tx: mpsc::Sender<LocalEvent>,
}

/// Bind and serve forever. One task per connection; requests are bounded and
/// connections closed after one response.
pub async fn serve(listen: SocketAddr, ctx: HealthCtx) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "health endpoint listening");
    loop {
        let (mut sock, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(&mut sock, &ctx).await {
                tracing::debug!(error = %e, "health request failed");
            }
        });
    }
}

/// Generic over the socket so tests can drive it with an in-memory duplex.
pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
    ctx: &HealthCtx,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut n = 0;
    loop {
        if n == buf.len() {
            return respond(
                sock,
                "431 Request Header Fields Too Large",
                "application/json",
                "{}",
            )
            .await;
        }
        let read = sock.read(&mut buf[n..]).await?;
        if read == 0 {
            return Ok(()); // peer went away mid-request
        }
        n += read;
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let request_line = head.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    match (request_line.starts_with("GET "), path) {
        (true, "/healthz") => {
            let body = render(ctx).await;
            respond(sock, "200 OK", "application/json", &body).await
        }
        (true, "/metrics") => {
            let body = render_metrics(ctx).await;
            respond(
                sock,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
            )
            .await
        }
        _ => {
            respond(
                sock,
                "404 Not Found",
                "application/json",
                "{\"error\":\"not found\"}",
            )
            .await
        }
    }
}

async fn respond<S: AsyncWrite + Unpin>(
    sock: &mut S,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await?;
    sock.flush().await
}

async fn render(ctx: &HealthCtx) -> String {
    let mut peers_json = Vec::new();
    for peer in &ctx.configured_peers {
        let status = ctx.peers.get(peer);
        let recv_cursor = ctx.store.recv_cursor(*peer).await.unwrap_or(0);
        let last_acked = ctx.store.last_acked(*peer).await.unwrap_or(0);
        peers_json.push(format!(
            "{{\"node_id\":\"{}\",\"state\":\"{}\",\"connected\":{},\"last_reconcile_unix\":{},\"last_reconcile_ok\":{},\"recv_cursor\":{},\"last_acked_seq\":{}}}",
            hex::encode(peer),
            status.state.as_str(),
            ctx.conns.get(peer).is_some(),
            status.last_reconcile_unix,
            status.last_reconcile_ok,
            recv_cursor,
            last_acked,
        ));
    }

    // CAS stats walk the store directory: keep it off the runtime.
    let cas = ctx.cas.clone();
    let (cas_chunks, cas_bytes) = tokio::task::spawn_blocking(move || cas.stats())
        .await
        .unwrap_or((0, 0));

    let events_queued = ctx
        .events_tx
        .max_capacity()
        .saturating_sub(ctx.events_tx.capacity());
    let op_count = ctx.store.op_count().await.unwrap_or(-1);

    format!(
        "{{\"node_id\":\"{}\",\"peers\":[{}],\"counters\":{{\"chunks_fetched\":{},\"chunks_served\":{},\"bytes_in\":{},\"bytes_out\":{},\"manifests_fetched\":{},\"reconcile_runs\":{},\"inflight_transfers\":{}}},\"cas\":{{\"chunks\":{},\"bytes\":{}}},\"queues\":{{\"events_queued\":{},\"live_conns\":{}}},\"oplog_rows\":{}}}",
        hex::encode(ctx.node_id),
        peers_json.join(","),
        Stats::get(&ctx.stats.chunks_fetched),
        Stats::get(&ctx.stats.chunks_served),
        Stats::get(&ctx.stats.bytes_in),
        Stats::get(&ctx.stats.bytes_out),
        Stats::get(&ctx.stats.manifests_fetched),
        Stats::get(&ctx.stats.reconcile_runs),
        Stats::get_gauge(&ctx.stats.inflight_transfers),
        cas_chunks,
        cas_bytes,
        events_queued,
        ctx.conns.len(),
        op_count,
    )
}

/// Prometheus text exposition (FR-1101), built at scrape time from the live
/// atomics: counters, gauges, per-peer lag, cache hit rate inputs, conflict
/// count, free-space guard trips, ownership-apply skips.
async fn render_metrics(ctx: &HealthCtx) -> String {
    use prometheus::{Encoder, IntCounter, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
    let r = Registry::new();
    let counter = |name: &str, help: &str, v: u64| {
        if let Ok(c) = IntCounter::new(format!("replicore_{name}"), help.to_string()) {
            c.inc_by(v);
            let _ = r.register(Box::new(c));
        }
    };
    let gauge = |name: &str, help: &str, v: i64| {
        if let Ok(g) = IntGauge::new(format!("replicore_{name}"), help.to_string()) {
            g.set(v);
            let _ = r.register(Box::new(g));
        }
    };
    counter(
        "chunks_fetched_total",
        "Chunks fetched from peers (CAS misses)",
        Stats::get(&ctx.stats.chunks_fetched),
    );
    counter(
        "chunks_cache_hits_total",
        "Chunks a fetch skipped because the CAS held them (FR-1101 cache hit rate)",
        Stats::get(&ctx.stats.chunks_cache_hits),
    );
    counter(
        "chunks_served_total",
        "Chunks served to peers",
        Stats::get(&ctx.stats.chunks_served),
    );
    counter(
        "bytes_in_total",
        "Chunk payload bytes received",
        Stats::get(&ctx.stats.bytes_in),
    );
    counter(
        "bytes_out_total",
        "Chunk payload bytes served",
        Stats::get(&ctx.stats.bytes_out),
    );
    counter(
        "manifests_fetched_total",
        "Manifests fetched from peers",
        Stats::get(&ctx.stats.manifests_fetched),
    );
    counter(
        "reconcile_runs_total",
        "Anti-entropy sessions completed",
        Stats::get(&ctx.stats.reconcile_runs),
    );
    counter(
        "conflicts_total",
        "Concurrent-version detections (FR-303/305)",
        Stats::get(&ctx.stats.conflicts),
    );
    counter(
        "freespace_guard_trips_total",
        "Transfer pauses to protect the free-space reserve (FR-1107)",
        Stats::get(&ctx.stats.freespace_trips),
    );
    counter(
        "apply_errors_total",
        "Op materializations quarantined permanently",
        Stats::get(&ctx.stats.apply_errors),
    );
    counter(
        "meta_owner_skips_total",
        "Ownership applies skipped (policy or missing CAP_CHOWN, FR-106)",
        crate::metadata::owner_skips(),
    );
    gauge(
        "inflight_transfers",
        "Files in the fetch+assemble pipeline",
        Stats::get_gauge(&ctx.stats.inflight_transfers),
    );
    gauge(
        "events_queued",
        "Watcher/scanner events waiting for ingest",
        ctx.events_tx
            .max_capacity()
            .saturating_sub(ctx.events_tx.capacity()) as i64,
    );
    gauge(
        "live_connections",
        "Connected peers",
        ctx.conns.len() as i64,
    );
    gauge(
        "oplog_rows",
        "Total op-log rows",
        ctx.store.op_count().await.unwrap_or(-1),
    );

    // Per-peer replication lag (FR-1101): cursor of their ops we hold, and
    // the highest of OUR ops they have acked.
    if let Ok(lag) = IntGaugeVec::new(
        Opts::new(
            "replicore_peer_recv_cursor",
            "Highest origin_seq of this peer's ops durably handled here",
        ),
        &["peer"],
    ) {
        for peer in &ctx.configured_peers {
            let v = ctx.store.recv_cursor(*peer).await.unwrap_or(0);
            lag.with_label_values(&[&hex::encode(peer)]).set(v);
        }
        let _ = r.register(Box::new(lag));
    }
    if let Ok(acked) = IntGaugeVec::new(
        Opts::new(
            "replicore_peer_acked_seq",
            "Highest of our origin_seq this peer has durably acked",
        ),
        &["peer"],
    ) {
        for peer in &ctx.configured_peers {
            let v = ctx.store.last_acked(*peer).await.unwrap_or(0);
            acked.with_label_values(&[&hex::encode(peer)]).set(v);
        }
        let _ = r.register(Box::new(acked));
    }

    let mut out = Vec::new();
    let _ = TextEncoder::new().encode(&r.gather(), &mut out);
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ctx() -> (tempfile::TempDir, HealthCtx) {
        let dir = tempfile::tempdir().unwrap();
        let (events_tx, _events_rx) = mpsc::channel(8);
        let ctx = HealthCtx {
            node_id: [0xaa; 16],
            stats: Arc::new(Stats::default()),
            peers: PeerRegistry::new(),
            conns: ConnRegistry::new(),
            cas: Cas::open(&dir.path().join("cas")).unwrap(),
            store: Store::open(Path::new(":memory:"), [0xaa; 16]).unwrap(),
            configured_peers: vec![[0xbb; 16]],
            events_tx,
        };
        (dir, ctx)
    }

    async fn roundtrip(request: &[u8]) -> String {
        let (_dir, ctx) = ctx();
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move { handle(&mut server, &ctx).await });
        client.write_all(request).await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_json_snapshot() {
        let resp = roundtrip(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("\"node_id\":\"aaaa"));
        assert!(resp.contains("\"chunks_fetched\":0"));
        assert!(resp.contains("\"peers\":[{\"node_id\":\"bbbb"));
        assert!(resp.contains("\"state\":\"disconnected\""));
        assert!(resp.contains("\"cas\":{\"chunks\":0,\"bytes\":0}"));
    }

    #[tokio::test]
    async fn metrics_exposes_prometheus_text() {
        let resp = roundtrip(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("text/plain"));
        assert!(resp.contains("# TYPE replicore_chunks_fetched_total counter"));
        assert!(resp.contains("replicore_conflicts_total 0"));
        assert!(resp.contains("replicore_freespace_guard_trips_total 0"));
        assert!(resp.contains("replicore_peer_recv_cursor{peer=\"bbbb"));
    }

    #[tokio::test]
    async fn other_paths_are_404() {
        let resp = roundtrip(b"GET /secrets HTTP/1.1\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        let resp = roundtrip(b"POST /healthz HTTP/1.1\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    }

    #[tokio::test]
    async fn oversized_request_is_rejected() {
        let mut req = b"GET /healthz HTTP/1.1\r\n".to_vec();
        req.extend(vec![b'x'; MAX_REQUEST]); // never reaches CRLFCRLF
        let resp = roundtrip(&req).await;
        assert!(resp.starts_with("HTTP/1.1 431"), "{resp}");
    }
}
