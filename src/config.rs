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
}

/// Validated runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub node_id: NodeId,
    pub listen: SocketAddr,
    pub share_dir: PathBuf,
    pub db_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub peers: Vec<Peer>,
    /// Per-path quiescence window before a local write becomes an op (FR-105).
    pub quiesce_ms: u64,
    /// Periodic scanner cadence; the rescan is the correctness backstop.
    pub scan_interval_secs: u64,
    /// Upper bound for a single fetched file (whole-file transfer is M1;
    /// chunking lands in M2, FR-402).
    pub max_file_bytes: u64,
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
    cert_path: PathBuf,
    key_path: PathBuf,
    #[serde(default)]
    peers: Vec<RawPeer>,
    #[serde(default = "default_quiesce_ms")]
    quiesce_ms: u64,
    #[serde(default = "default_scan_interval_secs")]
    scan_interval_secs: u64,
    #[serde(default = "default_max_file_bytes")]
    max_file_bytes: u64,
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
fn default_max_file_bytes() -> u64 {
    64 * 1024 * 1024
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

        Ok(Config {
            node_id,
            listen: raw.listen,
            share_dir: raw.share_dir,
            db_path: raw.db_path,
            cert_path: raw.cert_path,
            key_path: raw.key_path,
            peers,
            quiesce_ms: raw.quiesce_ms,
            scan_interval_secs: raw.scan_interval_secs,
            max_file_bytes: raw.max_file_bytes,
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
