//! Replicore library crate — the replication engine's correctness core.
//!
//! The `replicored` binary (`main.rs`) is a thin wiring layer over these
//! modules. Everything correctness-critical lives here so unit, property, and
//! integration tests can drive it directly.

pub mod admin;
pub mod apply;
pub mod chunk;
pub mod config;
pub mod decide;
pub mod fetch;
pub mod gossip;
pub mod health;
pub mod ingest;
pub mod join;
pub mod membership;
pub mod merkle;
pub mod net;
pub mod oplog;
pub mod peer;
pub mod proto;
pub mod replica;
pub mod scanner;
pub mod state;
pub mod stats;
pub mod suppress;
pub mod vv;
pub mod watch;

/// Substring marking in-progress staged files so the watcher ignores them.
pub const TMP_SUFFIX: &str = ".replicore-tmp";
