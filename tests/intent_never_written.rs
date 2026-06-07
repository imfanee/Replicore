//! Grep-gate + runtime gate for invariant FR-1302: the daemon NEVER writes the
//! human-owned intent file (`replicore.toml`). Dynamically-learned membership
//! lives only in the agent-owned roster. This is a non-negotiable invariant, so
//! per CLAUDE.md it is enforced in CI, not left to prose.
//!
//! Two layers:
//!   1. a source scan — no TOML *serialization* exists in the crate, so there
//!      is no code path that could even render an intent file; and
//!   2. a runtime assertion — load a real on-disk intent file, churn membership
//!      (which DOES persist the roster), and prove the intent file is
//!      byte-identical and mtime-unchanged afterward.

use std::path::{Path, PathBuf};

use replicore::admin::{generate_admin_key, sign_entry, AdminSecret, EntryKind};
use replicore::config::Config;
use replicore::membership::{Membership, MergeOutcome, SignedEntry};
use replicore::vv::NodeId;

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Layer 1: the crate must contain NO way to serialize TOML. We read TOML for
/// intent parsing (`toml::from_str`) but writing TOML back is forbidden — its
/// absence means no code can render an intent file, by construction.
#[test]
fn no_toml_serialization_anywhere_in_the_crate() {
    // Any of these would be a route to writing a TOML document.
    const FORBIDDEN: &[&str] = &[
        "toml::to_string",
        "toml::to_string_pretty",
        "toml::to_vec",
        "toml::Serializer",
        "toml::ser",
    ];
    let mut files = Vec::new();
    rs_files(&src_dir(), &mut files);
    assert!(!files.is_empty(), "found no source files to scan");

    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{}: contains `{needle}` — the daemon must never serialize TOML \
                 (it would be able to write the intent file, violating FR-1302)",
                f.display()
            );
        }
    }
}

/// Layer 1b: `Config` must not derive `Serialize` — an intent struct that can
/// serialize is one accidental `fs::write` away from clobbering human config.
#[test]
fn config_struct_does_not_derive_serialize() {
    let text = std::fs::read_to_string(src_dir().join("config.rs")).unwrap();
    // Find the derive line attached to `pub struct Config`.
    let idx = text.find("pub struct Config {").expect("Config struct");
    let preceding = &text[..idx];
    let derive_line = preceding
        .lines()
        .rev()
        .find(|l| l.contains("#[derive("))
        .expect("Config derive line");
    assert!(
        !derive_line.contains("Serialize"),
        "Config derives Serialize ({derive_line:?}) — intent config must not be serializable"
    );
}

/// Layer 2: the real write path. Load an intent file from disk, churn
/// membership (add + remove, which persists the roster each time), and prove the
/// intent file never changed — same bytes, same mtime.
#[test]
fn membership_churn_leaves_the_intent_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let share = root.join("share");
    let state = root.join("state");
    let etc = root.join("etc");
    for d in [&share, &state, &etc] {
        std::fs::create_dir_all(d).unwrap();
    }

    // The cluster admin key: pubkey goes in the intent file; secret stays here.
    let (doc, pk) = generate_admin_key().unwrap();
    let admin_key = etc.join("admin.sk");
    std::fs::write(&admin_key, &doc).unwrap();
    let sk = AdminSecret::load(&admin_key).unwrap();
    // cert/key need not be real for Config::load (it doesn't read them).
    std::fs::write(etc.join("c.pem"), b"").unwrap();
    std::fs::write(etc.join("k.pem"), b"").unwrap();

    let intent = root.join("replicore.toml");
    std::fs::write(
        &intent,
        format!(
            r#"
node_id   = "000102030405060708090a0b0c0d0e0f"
listen    = "127.0.0.1:7000"
share_dir = "{share}"
db_path   = "{state}/node.db"
cas_dir   = "{state}/node.cas"
cert_path = "{etc}/c.pem"
key_path  = "{etc}/k.pem"
roster_path = "{state}/node.roster.json"
control_socket = "{state}/node.sock"

[trust]
admin_pubkey = "{pub}"
"#,
            share = share.display(),
            state = state.display(),
            etc = etc.display(),
            pub = pk.to_hex(),
        ),
    )
    .unwrap();

    let cfg = Config::load(&intent).expect("load intent");

    // Snapshot the intent file BEFORE any daemon activity.
    let before_bytes = std::fs::read(&intent).unwrap();
    let before_hash = blake3::hash(&before_bytes);
    let before_mtime = std::fs::metadata(&intent).unwrap().modified().unwrap();

    // Churn membership through the SAME handle the control plane uses. Each
    // applied change persists the roster (the daemon's only membership writer).
    let m = Membership::load(&cfg).unwrap();
    let target: NodeId = [0x42; 16];
    let addr = "10.0.0.9:7000".parse().unwrap();
    let fp = [0xab; 32];

    let add_epoch = m.next_epoch_for(&target);
    let add = signed(&sk, target, addr, fp, add_epoch, EntryKind::Add);
    assert_eq!(m.merge_signed(add).unwrap(), MergeOutcome::Applied);

    let rm_epoch = m.next_epoch_for(&target);
    let rm = signed(&sk, target, addr, fp, rm_epoch, EntryKind::Remove);
    assert_eq!(m.merge_signed(rm).unwrap(), MergeOutcome::Applied);

    // Positive control: the roster file WAS written, so the churn was real and
    // the unchanged-intent result below is meaningful (not a no-op).
    assert!(
        cfg.roster_path.exists(),
        "roster was not persisted — the churn did nothing, gate is vacuous"
    );

    // The intent file is byte-identical and its mtime never moved.
    let after_bytes = std::fs::read(&intent).unwrap();
    assert_eq!(
        blake3::hash(&after_bytes),
        before_hash,
        "intent file CONTENT changed — the daemon wrote the human-owned config"
    );
    let after_mtime = std::fs::metadata(&intent).unwrap().modified().unwrap();
    assert_eq!(
        after_mtime, before_mtime,
        "intent file mtime moved — something touched the human-owned config"
    );
}

fn signed(
    sk: &AdminSecret,
    node: NodeId,
    addr: std::net::SocketAddr,
    fp: [u8; 32],
    epoch: u64,
    kind: EntryKind,
) -> SignedEntry {
    let sig = sign_entry(sk, &node, &addr, &fp, epoch, kind);
    SignedEntry {
        node_id: node,
        addr,
        fingerprint: fp,
        epoch,
        kind,
        sig,
    }
}
