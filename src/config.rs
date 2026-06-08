//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
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

use crate::admin::AdminPubKey;
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
    #[error("[trust] admin_pubkey must be 64 hex chars (Ed25519), got {0:?}")]
    BadAdminPubkey(String),
    #[error("set either [[peers]] or [[seed_peers]], not both (they are aliases)")]
    PeersAndSeedPeers,
    #[error("{0}")]
    Invalid(String),
}

/// Bandwidth limits + time-of-day schedule (FR-1103/1104). `0` = unlimited.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BandwidthCfg {
    pub global_bps: u64,
    pub per_peer_bps: u64,
    /// Files at or under this size ride the priority lane (FR-1104).
    /// Default 256 KiB.
    pub small_asset_bytes: u64,
    pub schedule: Vec<crate::qos::ScheduleRule>,
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
    /// Cluster membership trust anchor (FR-1305). Absent = no dynamic
    /// membership: roster mutations cannot be admitted (static `[[peers]]`
    /// still works for M2-style fixed meshes).
    pub admin_pubkey: Option<AdminPubKey>,
    /// Agent-owned roster file (FR-1302). Default `<db_path>.roster.json`.
    /// The daemon owns this exclusively; it NEVER writes the intent file.
    pub roster_path: PathBuf,
    /// Operator control socket (UDS). Default `<db_path>.sock`.
    pub control_socket: PathBuf,
    /// The seed peer list (FR-601). `[[peers]]` is canonical; `[[seed_peers]]`
    /// is an accepted alias. Dynamically-learned members live in the roster,
    /// never here.
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
    /// Ownership replication policy (FR-106). MUST be uniform across the
    /// mesh — it changes what metadata captures record, hence every meta
    /// hash. `numeric` (default) replicates uid/gid and needs CAP_CHOWN;
    /// `skip` leaves files owned by the daemon.
    pub owner_policy: crate::metadata::OwnerPolicy,
    /// Bandwidth policy (FR-1103/1104). HOT-reloadable.
    pub bandwidth: BandwidthCfg,
    /// Free-space guard (FR-1107): never let replication take the
    /// filesystem below max(reserve_bytes, reserve_percent of capacity).
    /// HOT-reloadable. Default: 256 MiB.
    pub reserve_bytes: u64,
    pub reserve_percent: f64,
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
    trust: Option<RawTrust>,
    #[serde(default)]
    roster_path: Option<PathBuf>,
    #[serde(default)]
    control_socket: Option<PathBuf>,
    // `peers` and `seed_peers` are aliases; at most one may be set (we can't
    // use serde alias because we must reject *both* being present).
    #[serde(default)]
    peers: Option<Vec<RawPeer>>,
    #[serde(default)]
    seed_peers: Option<Vec<RawPeer>>,
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
    #[serde(default = "default_owner_policy")]
    owner_policy: String,
    #[serde(default)]
    bandwidth: RawBandwidth,
    #[serde(default = "default_reserve_bytes")]
    reserve_bytes: u64,
    #[serde(default)]
    reserve_percent: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    node_id: String,
    addr: SocketAddr,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    admin_pubkey: String,
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
fn default_owner_policy() -> String {
    "numeric".into()
}

fn default_reserve_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_small_asset_bytes() -> u64 {
    256 * 1024
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBandwidth {
    #[serde(default)]
    global_bps: u64,
    #[serde(default)]
    per_peer_bps: u64,
    #[serde(default = "default_small_asset_bytes")]
    small_asset_bytes: u64,
    #[serde(default)]
    schedule: Vec<RawScheduleRule>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScheduleRule {
    days: Vec<String>,
    /// "HH:MM", inclusive.
    start: String,
    /// "HH:MM", exclusive; start > end wraps midnight.
    end: String,
    #[serde(default)]
    global_bps: u64,
    #[serde(default)]
    per_peer_bps: u64,
}

impl Default for RawBandwidth {
    fn default() -> RawBandwidth {
        // Mirrors the serde field defaults — an ABSENT [bandwidth] table and
        // an empty one must parse identically.
        RawBandwidth {
            global_bps: 0,
            per_peer_bps: 0,
            small_asset_bytes: default_small_asset_bytes(),
            schedule: Vec::new(),
        }
    }
}

fn parse_hhmm(s: &str) -> Option<u16> {
    let (h, m) = s.split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    (h < 24 && m < 60).then_some(h * 60 + m)
}

fn validate_schedule(
    raw: Vec<RawScheduleRule>,
) -> Result<Vec<crate::qos::ScheduleRule>, ConfigError> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        for d in &r.days {
            if !matches!(
                d.as_str(),
                "all"
                    | "weekday"
                    | "weekend"
                    | "sun"
                    | "mon"
                    | "tue"
                    | "wed"
                    | "thu"
                    | "fri"
                    | "sat"
            ) {
                return Err(ConfigError::Invalid(format!(
                    "bandwidth.schedule: unknown day \"{d}\""
                )));
            }
        }
        let start_min = parse_hhmm(&r.start).ok_or_else(|| {
            ConfigError::Invalid(format!("bandwidth.schedule: bad start \"{}\"", r.start))
        })?;
        let end_min = parse_hhmm(&r.end).ok_or_else(|| {
            ConfigError::Invalid(format!("bandwidth.schedule: bad end \"{}\"", r.end))
        })?;
        out.push(crate::qos::ScheduleRule {
            days: r.days,
            start_min,
            end_min,
            global_bps: r.global_bps,
            per_peer_bps: r.per_peer_bps,
        });
    }
    Ok(out)
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

        // [[peers]] and [[seed_peers]] are aliases; reject setting both.
        let raw_peers = match (raw.peers, raw.seed_peers) {
            (Some(_), Some(_)) => return Err(ConfigError::PeersAndSeedPeers),
            (Some(p), None) | (None, Some(p)) => p,
            (None, None) => Vec::new(),
        };

        let mut peers = Vec::with_capacity(raw_peers.len());
        let mut seen = vec![node_id];
        for rp in &raw_peers {
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
        let roster_path = raw
            .roster_path
            .unwrap_or_else(|| raw.db_path.with_extension("roster.json"));
        let control_socket = raw
            .control_socket
            .unwrap_or_else(|| raw.db_path.with_extension("sock"));

        let admin_pubkey = match &raw.trust {
            Some(t) => Some(
                AdminPubKey::from_hex(&t.admin_pubkey)
                    .map_err(|_| ConfigError::BadAdminPubkey(t.admin_pubkey.clone()))?,
            ),
            None => None,
        };

        Ok(Config {
            node_id,
            listen: raw.listen,
            share_dir: raw.share_dir,
            db_path: raw.db_path,
            cas_dir,
            cert_path: raw.cert_path,
            key_path: raw.key_path,
            health_listen: raw.health_listen,
            admin_pubkey,
            roster_path,
            control_socket,
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
            bandwidth: BandwidthCfg {
                global_bps: raw.bandwidth.global_bps,
                per_peer_bps: raw.bandwidth.per_peer_bps,
                small_asset_bytes: raw.bandwidth.small_asset_bytes,
                schedule: validate_schedule(raw.bandwidth.schedule)?,
            },
            reserve_bytes: raw.reserve_bytes,
            reserve_percent: if (0.0..=95.0).contains(&raw.reserve_percent) {
                raw.reserve_percent
            } else {
                return Err(ConfigError::Invalid(format!(
                    "reserve_percent must be within 0..=95, got {}",
                    raw.reserve_percent
                )));
            },
            owner_policy: match raw.owner_policy.as_str() {
                "numeric" => crate::metadata::OwnerPolicy::Numeric,
                "skip" => crate::metadata::OwnerPolicy::Skip,
                other => {
                    return Err(ConfigError::Invalid(format!(
                        "owner_policy must be \"numeric\" or \"skip\", got \"{other}\""
                    )))
                }
            },
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
            ("roster_path", &cfg.roster_path),
            ("control_socket", &cfg.control_socket),
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

    /// Classified difference between this (running) config and a `candidate`,
    /// for `replicorectl config diff` (FR-1406). Only the seed list and the
    /// trust anchor are HOT (applied by a `config reload` recomputing
    /// membership); every other field is honestly RESTART-REQUIRED — we never
    /// pretend a change took effect when it did not.
    pub fn diff(&self, candidate: &Config) -> Vec<ConfigChange> {
        let mut out = Vec::new();
        let mut note = |field: &'static str, hot: bool, old: String, new: String| {
            if old != new {
                out.push(ConfigChange {
                    field,
                    hot,
                    old,
                    new,
                });
            }
        };

        // HOT — reload recomputes the membership view.
        note(
            "admin_pubkey",
            true,
            self.admin_pubkey
                .as_ref()
                .map(|k| k.to_hex())
                .unwrap_or_default(),
            candidate
                .admin_pubkey
                .as_ref()
                .map(|k| k.to_hex())
                .unwrap_or_default(),
        );
        note(
            "peers",
            true,
            fmt_peers(&self.peers),
            fmt_peers(&candidate.peers),
        );
        // HOT — reload retunes the live token buckets / guard threshold.
        note(
            "bandwidth",
            true,
            format!("{:?}", self.bandwidth),
            format!("{:?}", candidate.bandwidth),
        );
        note(
            "reserve",
            true,
            format!("{}B/{}%", self.reserve_bytes, self.reserve_percent),
            format!(
                "{}B/{}%",
                candidate.reserve_bytes, candidate.reserve_percent
            ),
        );

        // RESTART-REQUIRED — bound at boot; reload cannot move them.
        note(
            "node_id",
            false,
            hex::encode(self.node_id),
            hex::encode(candidate.node_id),
        );
        note(
            "listen",
            false,
            self.listen.to_string(),
            candidate.listen.to_string(),
        );
        note(
            "share_dir",
            false,
            disp(&self.share_dir),
            disp(&candidate.share_dir),
        );
        note(
            "db_path",
            false,
            disp(&self.db_path),
            disp(&candidate.db_path),
        );
        note(
            "cas_dir",
            false,
            disp(&self.cas_dir),
            disp(&candidate.cas_dir),
        );
        note(
            "cert_path",
            false,
            disp(&self.cert_path),
            disp(&candidate.cert_path),
        );
        note(
            "key_path",
            false,
            disp(&self.key_path),
            disp(&candidate.key_path),
        );
        note(
            "roster_path",
            false,
            disp(&self.roster_path),
            disp(&candidate.roster_path),
        );
        note(
            "control_socket",
            false,
            disp(&self.control_socket),
            disp(&candidate.control_socket),
        );
        note(
            "health_listen",
            false,
            self.health_listen
                .map(|a| a.to_string())
                .unwrap_or_default(),
            candidate
                .health_listen
                .map(|a| a.to_string())
                .unwrap_or_default(),
        );
        out
    }
}

/// One classified field change from [`Config::diff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigChange {
    pub field: &'static str,
    /// True if a `config reload` applies it live; false = restart required.
    pub hot: bool,
    pub old: String,
    pub new: String,
}

fn disp(p: &Path) -> String {
    p.display().to_string()
}

fn fmt_peers(peers: &[Peer]) -> String {
    let mut lines: Vec<String> = peers
        .iter()
        .map(|p| {
            format!(
                "{}@{}#{}",
                hex::encode(p.node_id),
                p.addr,
                hex::encode(p.fingerprint)
            )
        })
        .collect();
    lines.sort(); // order-independent comparison
    lines.join(",")
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
    fn m3_bandwidth_reserve_and_owner_policy_parse() {
        // Defaults: unlimited bandwidth, 256 MiB reserve, numeric ownership.
        let cfg = Config::from_toml_str(GOOD).unwrap();
        assert_eq!(cfg.bandwidth.global_bps, 0);
        assert_eq!(cfg.bandwidth.per_peer_bps, 0);
        assert_eq!(cfg.bandwidth.small_asset_bytes, 256 * 1024);
        assert!(cfg.bandwidth.schedule.is_empty());
        assert_eq!(cfg.reserve_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.owner_policy, crate::metadata::OwnerPolicy::Numeric);

        // Top-level scalars must precede [[peers]] in TOML.
        let full = format!(
            "owner_policy = \"skip\"
        reserve_bytes = 1024
        reserve_percent = 5.0
        {GOOD}
        [bandwidth]
        global_bps = 10000000
        per_peer_bps = 2000000
        small_asset_bytes = 65536

        [[bandwidth.schedule]]
        days = [\"weekday\"]
        start = \"09:00\"
        end = \"17:30\"
        global_bps = 1000000
        per_peer_bps = 500000
        "
        );
        let cfg = Config::from_toml_str(&full).unwrap();
        assert_eq!(cfg.owner_policy, crate::metadata::OwnerPolicy::Skip);
        assert_eq!(cfg.bandwidth.global_bps, 10_000_000);
        assert_eq!(cfg.bandwidth.small_asset_bytes, 65536);
        let rule = &cfg.bandwidth.schedule[0];
        assert_eq!((rule.start_min, rule.end_min), (9 * 60, 17 * 60 + 30));
        assert_eq!(rule.global_bps, 1_000_000);
        assert_eq!((cfg.reserve_bytes, cfg.reserve_percent), (1024, 5.0));

        // Invalids are rejected atomically (FR-1406 discipline).
        for bad in [
            "owner_policy = \"both\"\n{G}",
            "reserve_percent = 99.0\n{G}",
            "{G}\n[[bandwidth.schedule]]\ndays=[\"noday\"]\nstart=\"09:00\"\nend=\"10:00\"",
            "{G}\n[[bandwidth.schedule]]\ndays=[\"all\"]\nstart=\"25:00\"\nend=\"10:00\"",
        ] {
            let toml = bad.replace("{G}", GOOD);
            assert!(
                Config::from_toml_str(&toml).is_err(),
                "accepted invalid: {bad}"
            );
        }
    }

    #[test]
    fn bandwidth_and_reserve_are_hot_in_the_diff() {
        let a = Config::from_toml_str(GOOD).unwrap();
        let mut b = Config::from_toml_str(GOOD).unwrap();
        b.bandwidth.global_bps = 123;
        b.reserve_bytes = 1;
        let changes = a.diff(&b);
        let by_field: std::collections::HashMap<_, _> =
            changes.iter().map(|c| (c.field, c.hot)).collect();
        assert_eq!(by_field.get("bandwidth"), Some(&true));
        assert_eq!(by_field.get("reserve"), Some(&true));
    }

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

    #[test]
    fn m25_path_defaults_and_trust_parse() {
        let cfg = Config::from_toml_str(GOOD).unwrap();
        // Daemon-owned state files default beside the db.
        assert_eq!(
            cfg.roster_path,
            PathBuf::from("/var/lib/replicore/a.roster.json")
        );
        assert_eq!(
            cfg.control_socket,
            PathBuf::from("/var/lib/replicore/a.sock")
        );
        assert!(cfg.admin_pubkey.is_none());

        let text = GOOD.replace(
            "[[peers]]",
            "[trust]\nadmin_pubkey = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n[[peers]]",
        );
        let cfg = Config::from_toml_str(&text).unwrap();
        assert_eq!(cfg.admin_pubkey.unwrap().0, [0xbb; 32]);
    }

    #[test]
    fn rejects_bad_admin_pubkey() {
        let text = GOOD.replace("[[peers]]", "[trust]\nadmin_pubkey = \"nothex\"\n[[peers]]");
        assert!(matches!(
            Config::from_toml_str(&text),
            Err(ConfigError::BadAdminPubkey(_))
        ));
    }

    #[test]
    fn seed_peers_is_an_alias_but_not_both() {
        // [[seed_peers]] alone works and is identical to [[peers]].
        let aliased = GOOD.replace("[[peers]]", "[[seed_peers]]");
        let cfg = Config::from_toml_str(&aliased).unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].fingerprint, [0xaa; 32]);

        // Both present is an error.
        let both = format!(
            "{GOOD}\n[[seed_peers]]\nnode_id = \"202122232425262728292a2b2c2d2e2f\"\naddr = \"10.0.0.3:7000\"\nfingerprint = \"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"\n"
        );
        assert!(matches!(
            Config::from_toml_str(&both),
            Err(ConfigError::PeersAndSeedPeers)
        ));
    }

    #[test]
    fn diff_classifies_hot_vs_restart() {
        let running = Config::from_toml_str(GOOD).unwrap();

        // A changed listen addr is restart-required.
        let cand = Config::from_toml_str(&GOOD.replace("10.0.0.1:7000", "10.0.0.9:7000")).unwrap();
        let d = running.diff(&cand);
        let listen = d.iter().find(|c| c.field == "listen").unwrap();
        assert!(!listen.hot);

        // A changed peer set is hot.
        let cand = Config::from_toml_str(&GOOD.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &"dd".repeat(32),
        ))
        .unwrap();
        let d = running.diff(&cand);
        let peers = d.iter().find(|c| c.field == "peers").unwrap();
        assert!(peers.hot);

        // Identical configs diff to nothing.
        assert!(running.diff(&running).is_empty());
    }
}
