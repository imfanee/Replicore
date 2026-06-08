*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Security Model

## Trust anchors

Replicore has two independent secrets, with two different jobs:

1. **Per-node TLS identity** (`cert_path` / `key_path`) — authenticates a node on
   the data path.
2. **Cluster admin key** (Ed25519, from `gen-admin-key`) — authorizes changes to
   *who is in the cluster*. The public half is pinned in every node's `[trust]`;
   the secret half never touches a daemon.

## Data path: mutual TLS with pinned certificates

All peer traffic is QUIC over **mutual TLS**. A connection is accepted only if the
presenting peer's certificate matches a **pinned allowlist** of SHA-256
certificate fingerprints (the `fingerprint` field in `[[peers]]` / the roster).
There is no CA-chain "anyone with a valid cert" trust; trust is explicit and
per-peer.

> The development-only `AcceptAny` certificate verifier is never compiled into a
> production build. Production is pinned mutual TLS, always.

**Announcement is not authorization.** A node telling the mesh "I exist," or being
vouched for by a peer, grants it nothing. It enters the data path only after its
certificate validates against the pinned trust anchor.

## Control plane: admin-signed membership

`replicorectl member add` / `member remove` construct a membership entry and
**sign it client-side** with the cluster admin secret (`--admin-key`). The daemon
verifies that signature against `[trust].admin_pubkey` before accepting the
change.

Consequences:

- The daemon never holds the admin secret — compromising a node does not give an
  attacker the ability to mint membership changes.
- Keep the admin secret in a secrets manager, off the daemons. Anyone holding it
  can add or remove cluster members. Rotate it by generating a new keypair and
  hot-reloading the new `admin_pubkey` on every node.

The signature is never used as a convergence tie-breaker: the membership merge
tie-break hashes canonical entry bytes, never the signature, so a re-signed
identical entry cannot change the converged result.

## Control socket: local-only, uid-checked

`replicorectl` talks to the daemon over a Unix domain socket (`control_socket`),
not the network. The socket directory is `0700`, the socket `0600`, and the daemon
verifies the connecting process's uid via `SO_PEERCRED`. Only local users with the
right uid can issue control commands; membership-changing commands additionally
require the admin secret.

## Hardening the network surface

- Expose only the `listen` UDP port between nodes; nothing else needs to be
  reachable peer-to-peer.
- Bind `health_listen` (`/healthz`, `/metrics`) to a management or localhost
  interface; it is unauthenticated HTTP — do not expose it publicly.
- The control socket has no network surface by design.

## Input safety

Replicore treats all network input as hostile: it never panics on malformed or
adversarial peer data, bounds every buffer, and rejects path-escape attempts in
replicated paths. Malformed peer data is rejected, not trusted.

## Data-at-rest notes

- The chunk store (`cas_dir`) and op-log (`db_path`) contain replicated content
  and metadata — protect them with filesystem permissions like the data itself.
- Deletes become tombstones and are GC'd only after all peers acknowledge plus a
  safety window; a late write cannot resurrect deleted content.

## Operator checklist

- [ ] Node private keys are `0600`, owned by the daemon user.
- [ ] Every peer fingerprint is pinned and verified against the peer's `gen-cert`.
- [ ] The admin secret is in a secrets manager, not on any daemon host.
- [ ] `admin_pubkey` is identical on every node.
- [ ] `health_listen` is not publicly reachable.
- [ ] The daemon runs as a dedicated unprivileged user (with only `CAP_CHOWN` if
      `owner_policy = numeric`).
