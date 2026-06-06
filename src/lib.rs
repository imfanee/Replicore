//! Replicore library crate — the replication engine's correctness core.
//!
//! The `replicored` binary (`main.rs`) is a thin wiring layer over these
//! modules. Everything correctness-critical lives here so unit, property, and
//! integration tests can drive it directly.

pub mod decide;
pub mod vv;
