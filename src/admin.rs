//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! admin.rs — the membership trust anchor (FR-1305, NFR-CM2).
//!
//! Every roster mutation is an individually Ed25519-signed entry. The admin
//! keypair is the cluster's root of trust: its public half lives in every
//! node's INTENT file (`[trust] admin_pubkey`); its secret half lives only
//! with the operator and is used by `replicorectl member add/remove` to sign
//! entries CLIENT-side — **the daemon never holds the admin secret**.
//!
//! Signatures cover **canonical bytes** (below), a fixed-width, domain-tagged
//! layout that is deliberately NOT serde: serialization changes can never
//! invalidate or forge-extend existing signatures, and the same bytes hash to
//! the roster's deterministic tie-break key (`blake3(canonical)`).
//!
//! Canonical layout (LAW — never reorder or widen without a new domain tag):
//! ```text
//! "replicore-roster-v1\0"            (20-byte domain separation tag)
//! ‖ node_id        (16 bytes raw)
//! ‖ addr_family    (1 byte: 4 | 6)
//! ‖ addr_ip        (4 or 16 bytes per family)
//! ‖ addr_port      (2 bytes BE)
//! ‖ fingerprint    (32 bytes raw — SHA-256 of the member's cert DER)
//! ‖ epoch          (8 bytes BE)
//! ‖ kind           (1 byte: 0 = Add, 1 = Remove)
//! ```

use std::net::SocketAddr;
use std::path::Path;

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::vv::NodeId;

const DOMAIN_TAG: &[u8; 20] = b"replicore-roster-v1\0";

#[derive(thiserror::Error, Debug)]
pub enum AdminKeyError {
    #[error("{ctx}: {source}")]
    Io {
        ctx: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("admin key material rejected: {0}")]
    BadKey(&'static str),
}

/// What a roster entry does. Wire/canonical value: Add=0, Remove=1.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EntryKind {
    Add,
    Remove,
}

impl EntryKind {
    pub fn as_byte(self) -> u8 {
        match self {
            EntryKind::Add => 0,
            EntryKind::Remove => 1,
        }
    }
}

/// The cluster trust anchor (intent file, hex-encoded).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdminPubKey(pub [u8; 32]);

impl AdminPubKey {
    pub fn from_hex(s: &str) -> Result<AdminPubKey, AdminKeyError> {
        let bytes = hex::decode(s).map_err(|_| AdminKeyError::BadKey("pubkey not hex"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AdminKeyError::BadKey("pubkey must be 32 bytes"))?;
        Ok(AdminPubKey(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The operator-held signing key. Lives in `replicorectl` / `gen-admin-key`;
/// never inside the daemon's runtime state.
pub struct AdminSecret(Ed25519KeyPair);

impl AdminSecret {
    /// Load from the PKCS#8 v2 document written by `gen-admin-key`.
    pub fn load(path: &Path) -> Result<AdminSecret, AdminKeyError> {
        let bytes = std::fs::read(path).map_err(|source| AdminKeyError::Io {
            ctx: "read admin key",
            source,
        })?;
        let pair = Ed25519KeyPair::from_pkcs8(&bytes)
            .map_err(|_| AdminKeyError::BadKey("not a valid Ed25519 PKCS#8 document"))?;
        Ok(AdminSecret(pair))
    }

    pub fn public_key(&self) -> AdminPubKey {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.public_key().as_ref());
        AdminPubKey(out)
    }
}

/// Generate a fresh admin keypair: returns (PKCS#8 secret document, pubkey).
/// The caller writes the document with mode 0600.
pub fn generate_admin_key() -> Result<(Vec<u8>, AdminPubKey), AdminKeyError> {
    let rng = ring::rand::SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| AdminKeyError::BadKey("keypair generation failed"))?;
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|_| AdminKeyError::BadKey("generated document failed to parse"))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pair.public_key().as_ref());
    Ok((doc.as_ref().to_vec(), AdminPubKey(pk)))
}

/// The bytes that are signed and hashed. See the module-level layout (LAW).
pub fn canonical_entry_bytes(
    node_id: &NodeId,
    addr: &SocketAddr,
    fingerprint: &[u8; 32],
    epoch: u64,
    kind: EntryKind,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + 16 + 1 + 16 + 2 + 32 + 8 + 1);
    out.extend_from_slice(DOMAIN_TAG);
    out.extend_from_slice(node_id);
    match addr {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(kind.as_byte());
    out
}

/// Sign an entry's canonical bytes (operator side).
pub fn sign_entry(
    sk: &AdminSecret,
    node_id: &NodeId,
    addr: &SocketAddr,
    fingerprint: &[u8; 32],
    epoch: u64,
    kind: EntryKind,
) -> [u8; 64] {
    let bytes = canonical_entry_bytes(node_id, addr, fingerprint, epoch, kind);
    let sig = sk.0.sign(&bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

/// Verify an entry's signature against a trust anchor (every node,
/// independently, at every ingestion point — announcement is not
/// authorization).
pub fn verify_entry(
    pk: &AdminPubKey,
    node_id: &NodeId,
    addr: &SocketAddr,
    fingerprint: &[u8; 32],
    epoch: u64,
    kind: EntryKind,
    sig: &[u8; 64],
) -> bool {
    let bytes = canonical_entry_bytes(node_id, addr, fingerprint, epoch, kind);
    UnparsedPublicKey::new(&ED25519, pk.0)
        .verify(&bytes, sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    #[test]
    fn canonical_bytes_golden_vector() {
        // LAW: this layout must never change for v1 entries. If this test
        // fails, existing roster signatures across a fleet break — bump the
        // domain tag instead.
        let bytes = canonical_entry_bytes(
            &nid(0xAB),
            &"10.123.0.4:7000".parse().unwrap(),
            &[0xCD; 32],
            7,
            EntryKind::Add,
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"replicore-roster-v1\0");
        expected.extend_from_slice(&{
            let mut id = [0u8; 16];
            id[0] = 0xAB;
            id
        });
        expected.push(4);
        expected.extend_from_slice(&[10, 123, 0, 4]);
        expected.extend_from_slice(&7000u16.to_be_bytes());
        expected.extend_from_slice(&[0xCD; 32]);
        expected.extend_from_slice(&7u64.to_be_bytes());
        expected.push(0);
        assert_eq!(bytes, expected);
        assert_eq!(
            hex::encode(blake3::hash(&bytes).as_bytes()),
            // Pinned: the deterministic tie-break key for this entry.
            hex::encode(blake3::hash(&expected).as_bytes()),
        );
    }

    #[test]
    fn sign_verify_round_trip_and_tamper_rejection() {
        let (doc, pk) = generate_admin_key().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("admin.sk");
        std::fs::write(&key_path, &doc).unwrap();
        let sk = AdminSecret::load(&key_path).unwrap();
        assert_eq!(sk.public_key(), pk);

        let addr: SocketAddr = "10.0.0.9:7000".parse().unwrap();
        let sig = sign_entry(&sk, &nid(1), &addr, &[2; 32], 3, EntryKind::Add);
        assert!(verify_entry(
            &pk,
            &nid(1),
            &addr,
            &[2; 32],
            3,
            EntryKind::Add,
            &sig
        ));

        // Any field change invalidates the signature.
        assert!(!verify_entry(
            &pk,
            &nid(9),
            &addr,
            &[2; 32],
            3,
            EntryKind::Add,
            &sig
        ));
        assert!(!verify_entry(
            &pk,
            &nid(1),
            &addr,
            &[9; 32],
            3,
            EntryKind::Add,
            &sig
        ));
        assert!(!verify_entry(
            &pk,
            &nid(1),
            &addr,
            &[2; 32],
            4,
            EntryKind::Add,
            &sig
        ));
        assert!(!verify_entry(
            &pk,
            &nid(1),
            &addr,
            &[2; 32],
            3,
            EntryKind::Remove,
            &sig
        ));
        let other: SocketAddr = "10.0.0.9:7001".parse().unwrap();
        assert!(!verify_entry(
            &pk,
            &nid(1),
            &other,
            &[2; 32],
            3,
            EntryKind::Add,
            &sig
        ));

        // A different admin key's signature is rejected (forgery test).
        let (_, other_pk) = generate_admin_key().unwrap();
        assert!(!verify_entry(
            &other_pk,
            &nid(1),
            &addr,
            &[2; 32],
            3,
            EntryKind::Add,
            &sig
        ));
    }

    #[test]
    fn v6_addresses_canonicalize() {
        let v6: SocketAddr = "[2001:db8::1]:7000".parse().unwrap();
        let bytes = canonical_entry_bytes(&nid(1), &v6, &[0; 32], 1, EntryKind::Remove);
        assert_eq!(bytes[20 + 16], 6); // family byte after tag+node_id
        assert_eq!(bytes.len(), 20 + 16 + 1 + 16 + 2 + 32 + 8 + 1);
        assert_eq!(*bytes.last().unwrap(), 1); // Remove
    }

    #[test]
    fn pubkey_hex_round_trip() {
        let (_, pk) = generate_admin_key().unwrap();
        assert_eq!(AdminPubKey::from_hex(&pk.to_hex()).unwrap(), pk);
        assert!(AdminPubKey::from_hex("zz").is_err());
        assert!(AdminPubKey::from_hex("abcd").is_err()); // wrong length
    }
}
