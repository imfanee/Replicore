//! config.rs — declarative node configuration (FR-1201, FR-601).
//!
//! One TOML file per node: identity, listen address, share root, state-store
//! path, TLS material, and the static peer list with pinned certificate
//! fingerprints (FR-1002). Unknown keys are rejected so typos fail fast
//! (FR-1202).
//!
//! ```toml
//! node_id   = "6f1d…32 hex chars…"          # 16-byte stable identity
//! listen    = "10.123.0.1:7000"
//! share_dir = "/srv/replicore/a"
//! db_path   = "/var/lib/replicore/a.db"
//! cert_path = "/etc/replicore/a.cert.pem"
//! key_path  = "/etc/replicore/a.key.pem"
//!
//! [[peers]]
//! node_id     = "…32 hex…"
//! addr        = "10.123.0.2:7000"
//! fingerprint = "…64 hex…"                  # SHA-256 of the peer's cert DER
//! ```

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::vv::NodeId;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse: {0}")]
    Toml(#[from] Box<toml::de::Error>),
    #[error("node_id must be 32 hex chars (16 bytes), got {0:?}")]
    BadNodeId(String),
    #[error("fingerprint for peer {peer} must be 64 hex chars (SHA-256), got {got:?}")]
    BadFingerprint { peer: String, got: String },
    #[error("node_id {0} appears more than once (peer duplicating us or another peer)")]
    DuplicateNode(String),
    #[error("share_dir is not an existing directory: {0}")]
    BadShareDir(PathBuf),
    #[error("{what} must not live inside share_dir (it would be watched, hashed every scan, and replicated): {path}")]
    PathInsideShare { what: &'static str, path: PathBuf },
    #[error(
        "chunk sizes must satisfy 4096 <= min <= avg <= max <= 64 MiB (got {min}/{avg}/{max})"
    )]
    BadChunkSizes { min: u32, avg: u32, max: u32 },
}

/// Validated runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub node_id: NodeId,
    pub listen: SocketAddr,
    pub share_dir: PathBuf,
    pub db_path: PathBuf,
    /// Content-addressed chunk store root (FR-402). Defaults to
    /// `<db_path>.cas`. Must live outside the share. No GC in M2 —
    /// SEAM(M3): refcounted CAS GC via manifest_chunks.
    pub cas_dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Health endpoint bind address (FR-1102); absent = disabled.
    pub health_listen: Option<SocketAddr>,
    pub peers: Vec<Peer>,
    /// Per-path quiescence window before a local write becomes an op (FR-105).
    pub quiesce_ms: u64,
    /// Periodic scanner cadence; the rescan is the correctness backstop.
    pub scan_interval_secs: u64,
    /// Periodic anti-entropy cadence per peer (FR-702).
    pub reconcile_interval_secs: u64,
    /// Upper bound for a single replicated file.
    pub max_file_bytes: u64,
    /// fastcdc bounds (FR-402). `chunk_max_bytes` is also the wire guard for
    /// a single chunk transfer.
    pub chunk_min_bytes: u32,
    pub chunk_avg_bytes: u32,
    pub chunk_max_bytes: u32,
    /// In-flight chunk fetches within one file transfer (FR-403).
    pub per_file_chunk_concurrency: usize,
    /// Concurrent file transfers across all subscriptions (FR-1106).
    pub max_concurrent_transfers: usize,
    /// Concurrent serve streams we grant each peer connection (FR-1106).
    pub serve_concurrency: usize,
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// SHA-256 of the peer's certificate DER — the mTLS pin (FR-1002).
    pub fingerprint: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    node_id: String,
    listen: SocketAddr,
    share_dir: PathBuf,
    db_path: PathBuf,
    #[serde(default)]
    cas_dir: Option<PathBuf>,
    cert_path: PathBuf,
    key_path: PathBuf,
    #[serde(default)]
    health_listen: Option<SocketAddr>,
    #[serde(default)]
    peers: Vec<RawPeer>,
    #[serde(default = "default_quiesce_ms")]
    quiesce_ms: u64,
    #[serde(default = "default_scan_interval_secs")]
    scan_interval_secs: u64,
    #[serde(default = "default_reconcile_interval_secs")]
    reconcile_interval_secs: u64,
    #[serde(default = "default_max_file_bytes")]
    max_file_bytes: u64,
    #[serde(default = "default_chunk_min_bytes")]
    chunk_min_bytes: u32,
    #[serde(default = "default_chunk_avg_bytes")]
    chunk_avg_bytes: u32,
    #[serde(default = "default_chunk_max_bytes")]
    chunk_max_bytes: u32,
    #[serde(default = "default_per_file_chunk_concurrency")]
    per_file_chunk_concurrency: usize,
    #[serde(default = "default_max_concurrent_transfers")]
    max_concurrent_transfers: usize,
    #[serde(default = "default_serve_concurrency")]
    serve_concurrency: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    node_id: String,
    addr: SocketAddr,
    fingerprint: String,
}

fn default_quiesce_ms() -> u64 {
    300
}
fn default_scan_interval_secs() -> u64 {
    5
}
fn default_reconcile_interval_secs() -> u64 {
    300
}
fn default_max_file_bytes() -> u64 {
    64 * 1024 * 1024
}
fn default_chunk_min_bytes() -> u32 {
    256 * 1024
}
fn default_chunk_avg_bytes() -> u32 {
    1024 * 1024
}
fn default_chunk_max_bytes() -> u32 {
    4 * 1024 * 1024
}
fn default_per_file_chunk_concurrency() -> usize {
    6
}
fn default_max_concurrent_transfers() -> usize {
    8
}
fn default_serve_concurrency() -> usize {
    16
}

fn parse_node_id(s: &str) -> Result<NodeId, ConfigError> {
    let bytes = hex::decode(s).map_err(|_| ConfigError::BadNodeId(s.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| ConfigError::BadNodeId(s.to_string()))
}

fn parse_fingerprint(peer: &str, s: &str) -> Result<[u8; 32], ConfigError> {
    let err = || ConfigError::BadFingerprint {
        peer: peer.to_string(),
        got: s.to_string(),
    };
    let bytes = hex::decode(s).map_err(|_| err())?;
    bytes.try_into().map_err(|_| err())
}

impl Config {
    /// Parse and semantically validate a TOML document. Does not touch the
    /// filesystem — `load` adds those checks.
    pub fn from_toml_str(text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(Box::new)?;
        let node_id = parse_node_id(&raw.node_id)?;

        let mut peers = Vec::with_capacity(raw.peers.len());
        let mut seen = vec![node_id];
        for rp in &raw.peers {
            let pid = parse_node_id(&rp.node_id)?;
            if seen.contains(&pid) {
                return Err(ConfigError::DuplicateNode(rp.node_id.clone()));
            }
            seen.push(pid);
            peers.push(Peer {
                node_id: pid,
                addr: rp.addr,
                fingerprint: parse_fingerprint(&rp.node_id, &rp.fingerprint)?,
            });
        }

        if raw.chunk_min_bytes < 4096
            || raw.chunk_min_bytes > raw.chunk_avg_bytes
            || raw.chunk_avg_bytes > raw.chunk_max_bytes
            || raw.chunk_max_bytes > 64 * 1024 * 1024
        {
            return Err(ConfigError::BadChunkSizes {
                min: raw.chunk_min_bytes,
                avg: raw.chunk_avg_bytes,
                max: raw.chunk_max_bytes,
            });
        }

        // Default CAS root: sibling of the db (e.g. /var/lib/replicore/a.db
        // -> /var/lib/replicore/a.cas).
        let cas_dir = raw
            .cas_dir
            .unwrap_or_else(|| raw.db_path.with_extension("cas"));

        Ok(Config {
            node_id,
            listen: raw.listen,
            share_dir: raw.share_dir,
            db_path: raw.db_path,
            cas_dir,
            cert_path: raw.cert_path,
            key_path: raw.key_path,
            health_listen: raw.health_listen,
            peers,
            quiesce_ms: raw.quiesce_ms,
            scan_interval_secs: raw.scan_interval_secs,
            reconcile_interval_secs: raw.reconcile_interval_secs,
            max_file_bytes: raw.max_file_bytes,
            chunk_min_bytes: raw.chunk_min_bytes,
            chunk_avg_bytes: raw.chunk_avg_bytes,
            chunk_max_bytes: raw.chunk_max_bytes,
            per_file_chunk_concurrency: raw.per_file_chunk_concurrency,
            max_concurrent_transfers: raw.max_concurrent_transfers,
            serve_concurrency: raw.serve_concurrency,
        })
    }

    /// Read, parse, validate, and check filesystem preconditions: fail fast at
    /// startup with a precise diagnostic (FR-1202).
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg = Self::from_toml_str(&text)?;
        if !cfg.share_dir.is_dir() {
            return Err(ConfigError::BadShareDir(cfg.share_dir));
        }
        // Canonical share root: the watcher resolves event paths through
        // /proc and must prefix-match against the real path.
        cfg.share_dir = cfg
            .share_dir
            .canonicalize()
            .map_err(|source| ConfigError::Io {
                path: cfg.share_dir.clone(),
                source,
            })?;
        // The state db, cert, and key must not live inside the share: they
        // would be scanned, hashed every cycle, and replicated to peers
        // (the key!). Fail fast (FR-1202).
        for (what, path) in [
            ("db_path", &cfg.db_path),
            ("cas_dir", &cfg.cas_dir),
            ("cert_path", &cfg.cert_path),
            ("key_path", &cfg.key_path),
        ] {
            let effective = path.canonicalize().unwrap_or_else(|_| path.clone());
            if effective.starts_with(&cfg.share_dir) {
                return Err(ConfigError::PathInsideShare {
                    what,
                    path: path.clone(),
                });
            }
        }
        Ok(cfg)
    }

    /// Fingerprint allowlist for the TLS verifiers (FR-1002).
    pub fn pinned_fingerprints(&self) -> Vec<[u8; 32]> {
        self.peers.iter().map(|p| p.fingerprint).collect()
    }

    /// Find the configured peer whose pinned fingerprint matches `fp`.
    pub fn peer_by_fingerprint(&self, fp: &[u8; 32]) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.fingerprint == fp)
    }

    pub fn peer_by_node_id(&self, id: &NodeId) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.node_id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        node_id   = "000102030405060708090a0b0c0d0e0f"
        listen    = "10.0.0.1:7000"
        share_dir = "/srv/a"
        db_path   = "/var/lib/replicore/a.db"
        cert_path = "/etc/replicore/a.cert.pem"
        key_path  = "/etc/replicore/a.key.pem"

        [[peers]]
        node_id     = "101112131415161718191a1b1c1d1e1f"
        addr        = "10.0.0.2:7000"
        fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "#;

    #[test]
    fn parses_valid_config_with_defaults() {
        let cfg = Config::from_toml_str(GOOD).unwrap();
        assert_eq!(cfg.node_id[0], 0x00);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].fingerprint, [0xaa; 32]);
        assert_eq!(cfg.quiesce_ms, 300);
        assert_eq!(cfg.scan_interval_secs, 5);
        assert_eq!(cfg.max_file_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn m2_defaults_and_cas_derivation() {
        let cfg = Config::from_toml_str(GOOD).unwrap();
        assert_eq!(cfg.cas_dir, PathBuf::from("/var/lib/replicore/a.cas"));
        assert_eq!(cfg.health_listen, None);
        assert_eq!(cfg.reconcile_interval_secs, 300);
        assert_eq!(
            (
                cfg.chunk_min_bytes,
                cfg.chunk_avg_bytes,
                cfg.chunk_max_bytes
            ),
            (256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
        );
        assert_eq!(cfg.per_file_chunk_concurrency, 6);
        assert_eq!(cfg.max_concurrent_transfers, 8);
        assert_eq!(cfg.serve_concurrency, 16);

        // Top-level keys must precede [[peers]] in TOML.
        let text = GOOD.replace(
            "[[peers]]",
            "cas_dir = \"/data/cas\"\nhealth_listen = \"127.0.0.1:8800\"\n[[peers]]",
        );
        let cfg = Config::from_toml_str(&text).unwrap();
        assert_eq!(cfg.cas_dir, PathBuf::from("/data/cas"));
        assert_eq!(cfg.health_listen, Some("127.0.0.1:8800".parse().unwrap()));
    }

    #[test]
    fn rejects_inverted_chunk_sizes() {
        let text = GOOD.replace(
            "[[peers]]",
            "chunk_min_bytes = 2097152\nchunk_avg_bytes = 1048576\n[[peers]]",
        );
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::BadChunkSizes { .. })
        ));
    }

    #[test]
    fn rejects_bad_node_id() {
        let text = GOOD.replace("000102030405060708090a0b0c0d0e0f", "zz");
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::BadNodeId(_))
        ));
    }

    #[test]
    fn rejects_short_fingerprint() {
        let text = GOOD.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "abcd",
        );
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::BadFingerprint { .. })
        ));
    }

    #[test]
    fn rejects_peer_with_our_node_id() {
        let text = GOOD.replace(
            "101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
        );
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::DuplicateNode(_))
        ));
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = format!("{GOOD}\nbogus_knob = 7\n");
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn load_rejects_db_inside_share() {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let text = format!(
            r#"
            node_id   = "000102030405060708090a0b0c0d0e0f"
            listen    = "10.0.0.1:7000"
            share_dir = "{share}"
            db_path   = "{share}/state.db"
            cert_path = "/etc/replicore/a.cert.pem"
            key_path  = "/etc/replicore/a.key.pem"
            "#,
            share = share.display()
        );
        let cfg_path = dir.path().join("replicore.toml");
        std::fs::write(&cfg_path, text).unwrap();
        assert!(matches!(
            Config::load(&cfg_path),
            Err(ConfigError::PathInsideShare {
                what: "db_path",
                ..
            })
        ));
    }

    #[test]
    fn lookup_helpers() {
        let cfg = Config::from_toml_str(GOOD).unwrap();
        assert!(cfg.peer_by_fingerprint(&[0xaa; 32]).is_some());
        assert!(cfg.peer_by_fingerprint(&[0xbb; 32]).is_none());
        assert_eq!(cfg.pinned_fingerprints(), vec![[0xaa; 32]]);
    }
}
