*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Management Guide (Cluster Admin)

Day-2 operation of a running Replicore mesh: membership, monitoring, conflicts,
configuration changes, and troubleshooting. For initial install see
[DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md).

All commands here use **`replicorectl`**, which talks to the local daemon over its
Unix domain socket. Run it on the node you want to act on (the socket is
local-only). Read commands accept `--json` for scripting; `status` accepts
`--all` to fan out across the mesh.

## 1. `replicorectl` command reference

### Read / status

| Command | What it shows |
|---|---|
| `status [--all] [--json]` | Node health; `--all` fans out across the mesh. |
| `peers` | Per-peer connection state (connected / unreachable). |
| `members` | The roster: node, addr, epoch, kind. |
| `lag` | Replication backlog per peer (how far behind each peer is). |
| `conflicts` | Count of conflicts recorded (copies produced). |
| `transfers` | In-flight chunk transfers. |
| `version` | Daemon / protocol version. |

### Control

| Command | Effect |
|---|---|
| `pause` | Stop outbound replication. Local I/O continues; ops queue. |
| `resume` | Resume replication. |
| `resync [<node>]` | Force an anti-entropy session (with one node, or all). |
| `bandwidth` | Show current rate limits. |
| `bandwidth set <global> <per_peer>` | Set live limits (`k`/`m`/`g` suffixes; `0` = unlimited). |

### Configuration

| Command | Effect |
|---|---|
| `config validate <file>` | Parse + semantically check a config file. |
| `config diff <file>` | Classify candidate vs running as HOT / RESTART-REQUIRED. |
| `config reload <file>` | Atomically apply (reject-on-invalid; running config untouched on failure). |

### Membership (admin-signed)

| Command | Effect |
|---|---|
| `member add <node_id> <addr> <fingerprint> --admin-key <path>` | Admit a node to the cluster. |
| `member remove <node_id> --admin-key <path>` | Remove a node from the cluster. |

`member add/remove` sign the change **client-side** with the cluster admin secret
(`--admin-key`); the daemon never holds that secret. The signature is verified
against `[trust].admin_pubkey`.

## 2. Adding a node to a live cluster

1. On the new node: `replicored gen-cert --out-dir /etc/replicore --name node-d`
   and note its fingerprint.
2. Configure the new node (it should list existing nodes as seed `[[peers]]`, and
   carry the same `[trust].admin_pubkey`). Start it.
3. From any existing node, an admin admits it:
   ```sh
   replicorectl member add <node-d-id> <node-d-addr> <node-d-fingerprint> \
       --admin-key /secure/replicore-admin.key
   ```
4. The membership change converges across the mesh. The new node bootstraps from
   a snapshot frontier and resumes the live stream without re-streaming history.
5. Verify: `replicorectl members` and `replicorectl status --all`.

**Announcement is not authorization** — the node only enters the data path once
its certificate validates against the trust anchor and the signed membership
change is accepted.

## 3. Removing a node

```sh
replicorectl member remove <node-id> --admin-key /secure/replicore-admin.key
```

Removal severs the node's connections and de-pins its certificate at TLS across
the mesh; the change converges deterministically. **The removed node's already-
replicated data is RETAINED** on the remaining nodes (drop policy is not
automatic). Decommission the removed host separately.

## 4. Monitoring (what to watch)

Scrape Prometheus `/metrics` from each node's `health_listen`. Key signals and
their CLI equivalents:

- **Peer reachability** — `peers`; alert on any peer `UNREACHABLE`.
- **Replication lag** — `lag`; a steadily growing backlog means a node can't keep
  up (bandwidth limit too low, WAN saturated, or a stuck peer).
- **Conflicts** — `conflicts`; a rising count is expected under concurrent
  multi-site writes but a *spike* warrants investigation (see §5).
- **Transfers** — `transfers`; in-flight work.
- **Free space** — alert before it reaches the configured reserve; the guard will
  stop accepting inbound data at the floor.
- **Liveness** — `GET /healthz`.

## 5. Handling conflicts

When two sites write the same path concurrently, Replicore keeps the
deterministic winner in place and writes each loser beside it as a **conflict
copy** (a `*.sync-conflict-*` sibling). This is by design — **no write is lost.**

To reconcile a conflict:

1. `replicorectl conflicts` to see the count; locate the `*.sync-conflict-*`
   files in `share_dir`.
2. Inspect both the live file and the conflict copy.
3. Resolve by choosing/merging into the canonical path and deleting the copy.
   Your deletion replicates like any other change.

Copy names are deterministic and node-agnostic — the same conflict produces the
same copy name on every node, so admins at different sites see identical files.

A conflict *spike* usually means two sites are writing the same namespace. If you
expect single-writer-per-path, enforce a disjoint writable namespace per site
(this is mandatory for NFS-fronted deployments — see the NFS runbook).

## 6. Changing configuration safely

```sh
replicorectl config diff   /etc/replicore/replicore.toml   # see HOT vs RESTART
replicorectl config reload /etc/replicore/replicore.toml   # apply hot changes
```

- **HOT** (no restart): peer set, trust anchor, bandwidth, free-space reserve.
- **RESTART-REQUIRED**: identity, addresses, paths, chunking, intervals,
  concurrency, `owner_policy`. For these, edit the file and restart the daemon.

Reload is atomic: an invalid candidate is rejected and the running config is left
exactly as it was. Remember the daemon never writes `replicore.toml` — you do.

## 7. Routine operations

- **Throttle for a maintenance window:** `bandwidth set <low> <low>`, then `set 0
  0` to restore.
- **Force a heal after suspected divergence:** `resync` (or `resync <node>`).
- **Drain a node before maintenance:** `pause` (local I/O continues, ops queue),
  do the work, `resume`.

## 8. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Daemon won't start, complains about CAP_CHOWN | `owner_policy = numeric` without `CAP_CHOWN` | Grant `CAP_CHOWN` (see systemd unit) or set `owner_policy = "skip"` on **all** nodes. |
| Peer stays `UNREACHABLE` | UDP port blocked, wrong addr, or fingerprint mismatch | Check firewall on the `listen` port; verify `addr`; confirm the pinned `fingerprint` matches the peer's `gen-cert`. |
| New node won't join | Cert not validating, or membership not signed | Confirm `admin_pubkey` matches the admin key used for `member add`; confirm the node's fingerprint is what you pinned. |
| `lag` keeps growing | Bandwidth limit too low / WAN saturated / stuck peer | Raise `bandwidth`; check the peer's health; `resync`. |
| Lots of `*.sync-conflict-*` files | Concurrent writes to the same path across sites | Enforce disjoint writable namespace per site; reconcile existing copies (§5). |
| `config reload` rejected | Invalid candidate | Read the error; `config validate` the file; fix and retry. Running config is untouched. |
| Disk filled toward reserve | Capacity / retention | Free-space guard stops inbound data at the floor; add capacity, then it resumes. |

For deeper internals see [ARCHITECTURE.md](ARCHITECTURE.md); for the security
model see [SECURITY.md](SECURITY.md).
