*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Deployment Guide (DevOps / SRE)

How to stand up and operate a production Replicore mesh. For day-2 cluster
administration (membership, monitoring, conflicts) see
[ADMIN-GUIDE.md](ADMIN-GUIDE.md). For NFS-fronted topologies read
[DEPLOYMENT-NFS-RUNBOOK.md](DEPLOYMENT-NFS-RUNBOOK.md) **before** you deploy.

## 1. Requirements

- Linux with **fanotify** (FID reporting) — kernel 5.1+.
- Rust toolchain to build (`cargo`), or a prebuilt `replicored` / `replicorectl`.
- Local block-backed storage for each node's `share_dir`, `db_path`, and
  `cas_dir`. **Never** point `share_dir` at an NFS mount.
- UDP reachability between nodes on each node's `listen` port (QUIC).
- If `owner_policy = "numeric"` (the default): the daemon needs `CAP_CHOWN` or it
  refuses to boot.

Capacity planning: budget for `share_dir` (the live tree) **plus** `cas_dir` (the
chunk store) **plus** the free-space reserve (default 256 MiB). The CAS is
persistent.

## 2. Build

```sh
cargo build --release
# Produces target/release/replicored and target/release/replicorectl
```

Install the two binaries on each node (e.g. `/usr/local/bin`).

## 3. Provision identities (per node, once)

Each node needs a TLS identity. Generate it and record the printed fingerprint —
every other node must pin it.

```sh
replicored gen-cert --out-dir /etc/replicore --name node-a
# writes node-a.cert.pem + node-a.key.pem; prints the SHA-256 cert fingerprint
```

Protect the private key (`0600`, owned by the daemon user).

## 4. Provision the cluster admin key (once, for the whole cluster)

Membership changes are admin-signed. Generate **one** admin keypair, keep the
secret OFF the daemons (it lives wherever admins run `replicorectl member ...`),
and put the public half in every node's `[trust]`.

```sh
replicored gen-admin-key --out /secure/replicore-admin.key   # prints the public key
```

Store the secret in your secrets manager. Anyone holding it can change cluster
membership. See [SECURITY.md](SECURITY.md).

## 5. Write each node's config

Copy `replicore.example.toml` to `/etc/replicore/replicore.toml` and fill it in.
Per [CONFIGURATION.md](CONFIGURATION.md), at minimum set `node_id`, `listen`,
`share_dir`, `db_path`, `cert_path`, `key_path`, the `[trust].admin_pubkey`, and
a `[[peers]]` entry (with pinned `fingerprint`) for each seed peer. Keep
`db_path`/`cas_dir`/keys outside `share_dir`.

Validate before you ship it:

```sh
replicorectl config validate /etc/replicore/replicore.toml
```

(`config validate` checks a file standalone; it does not need a running daemon.)

## 6. Run under systemd

`/etc/systemd/system/replicored.service`:

```ini
[Unit]
Description=Replicore replication agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/replicored run --config /etc/replicore/replicore.toml
Restart=on-failure
RestartSec=5
User=replicore
Group=replicore
# owner_policy=numeric needs CAP_CHOWN; drop everything else:
AmbientCapabilities=CAP_CHOWN
CapabilityBoundingSet=CAP_CHOWN
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/replicore /var/lib/replicore /run/replicore
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now replicored
journalctl -u replicored -f
```

If you set `owner_policy = "skip"`, drop the `CAP_CHOWN` lines.

## 7. Networking / firewall

- Open the `listen` UDP port between all nodes (QUIC is UDP).
- `health_listen` (if set) serves `/healthz` and `/metrics` over HTTP — bind it
  to a management interface or localhost and scrape via your monitoring network;
  do **not** expose it publicly.
- The `replicorectl` control socket is a local Unix socket — no network exposure.

## 8. Bring up the mesh and verify

Start every node, then from any node:

```sh
replicorectl status --all        # fan-out health across the mesh
replicorectl peers               # per-peer connection state
replicorectl members             # roster (node, addr, epoch, kind)
replicorectl lag                 # replication backlog per peer
```

Smoke test: write a file into one node's `share_dir`, confirm it appears on the
others within (scan interval + WAN lag), byte-identical.

## 9. Monitoring

Scrape `http://<node>:<health_port>/metrics` (Prometheus). Alert on: peer
unreachable, growing `lag`, rising `conflicts`, and free-space approaching the
reserve. Liveness/readiness: `GET /healthz` returns JSON.

## 10. Bandwidth / QoS

Shape WAN usage in `[bandwidth]` (see CONFIGURATION.md) or live:

```sh
replicorectl bandwidth                       # show current limits
replicorectl bandwidth set 50m 10m           # 50 MB/s global, 10 MB/s per peer
replicorectl bandwidth set 0 0               # unlimited
```

These are hot — no restart.

## 11. Upgrades (flag-day protocol bump)

The wire protocol is a **flag-day** version (ALPN `replicore/4`). A node running a
different protocol version is refused at the handshake. **Upgrade the whole mesh
as a unit:**

1. Quiesce writes if practical; `replicorectl pause` on each node stops outbound
   replication while local I/O continues.
2. Roll the new binary to every node.
3. Restart each daemon.
4. `replicorectl resume`, then verify with `status --all` and `lag`.

Do not run mixed versions expecting them to interoperate.

## 12. Backups

Back up, per node: the `share_dir` tree (the data), `db_path` + WAL (the op-log /
index), `cas_dir` (the chunk store), the node's cert/key, and the config. The
`share_dir` alone is recoverable data; the db+cas let a restarted node resume
without a full re-sync. The admin secret is backed up separately in your secrets
manager.

## 13. Disaster scenarios

- **Lost a node's db/cas but kept its share_dir:** restart; the node rejoins and
  reconciles via anti-entropy (a full Merkle sync — slower, but correct).
- **Replaced a node's identity:** treat it as a new node — update every peer's
  pinned `fingerprint` (hot reload) and the roster via `member add`.
- **Disk near full:** the free-space guard stops accepting inbound data before
  the disk fills; raise capacity or lower retention, then it resumes.

## 14. Pre-production checklist

- [ ] `config validate` passes on every node's config.
- [ ] `db_path`, `cas_dir`, cert, and key are all outside `share_dir`.
- [ ] Every peer fingerprint is pinned and matches the peer's `gen-cert` output.
- [ ] `owner_policy` is identical on all nodes; if `numeric`, the daemon has
      `CAP_CHOWN` (it started successfully).
- [ ] `admin_pubkey` is the same on every node; the admin secret is off the
      daemons and in a secrets manager.
- [ ] `listen` UDP ports are open between all nodes.
- [ ] `health_listen` is bound to a management/localhost interface, scraped by
      Prometheus, with alerts on peer-down / lag / conflicts / free-space.
- [ ] A write on one node appears byte-identical on the others within the
      expected window.
- [ ] If NFS-fronted: the [NFS runbook](DEPLOYMENT-NFS-RUNBOOK.md) checklist is
      complete.
