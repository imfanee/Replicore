*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Configuration Reference

One TOML file per node (`replicore.toml`). It is the **intent** config: it is
human-owned and the daemon **never** writes it. Dynamically-learned membership
lives in a separate daemon-owned roster file (`roster_path`), not here.

A starting template ships as [`replicore.example.toml`](../replicore.example.toml).

Validate and inspect changes without restarting:

```sh
replicorectl config validate /path/to/replicore.toml   # parse + semantic check
replicorectl config diff     /path/to/replicore.toml   # candidate vs running, classified HOT/RESTART
replicorectl config reload   /path/to/replicore.toml   # atomic; rejected wholesale if invalid
```

`config reload` is **atomic**: an invalid candidate is rejected and the running
config is left untouched. Partial application never happens.

## Top-level fields

| Field | Type | Default | Reload | Meaning |
|---|---|---|---|---|
| `node_id` | hex (16 bytes) | — (required) | restart | Stable node identity, forever. |
| `listen` | `ip:port` | — (required) | restart | QUIC/UDP bind address for peer traffic. |
| `share_dir` | path | — (required) | restart | The replicated tree. Must be local block-backed storage, never an NFS mount. |
| `db_path` | path | — (required) | restart | WAL-backed op-log + index. Keep **outside** `share_dir`. |
| `cert_path` | path | — (required) | restart | This node's TLS certificate (PEM). |
| `key_path` | path | — (required) | restart | This node's TLS private key (PEM). |
| `cas_dir` | path | `<db_path>.cas` | restart | Content-addressed chunk store. Keep outside `share_dir`. |
| `health_listen` | `ip:port` | disabled | restart | Serves `GET /healthz` (JSON) and `/metrics` (Prometheus). Absent = off. |
| `roster_path` | path | `<db_path>.roster.json` | restart | Daemon-owned learned-membership roster. |
| `control_socket` | path | `<db_path>.sock` | restart | Unix domain socket for `replicorectl`. Dir `0700`, socket `0600`, uid-checked. |

## `[trust]` — cluster trust anchor

| Field | Type | Default | Reload | Meaning |
|---|---|---|---|---|
| `admin_pubkey` | 64 hex (Ed25519) | absent | **HOT** | Public key that authorizes signed membership changes. Absent = no dynamic membership. |

Changing the trust anchor is hot: a `config reload` recomputes the membership
view live.

## `[[peers]]` — seed / bootstrap peers (alias `[[seed_peers]]`)

The bootstrap list, not the full roster — learned members live in the roster.
The peer set is **HOT**-reloadable.

| Field | Type | Meaning |
|---|---|---|
| `node_id` | hex (16 bytes) | The peer's stable identity. |
| `addr` | `ip:port` | The peer's `listen` address. |
| `fingerprint` | 64 hex | SHA-256 of the peer's certificate DER, as printed by its `gen-cert`. Pin enforced at TLS. |

## Tuning (all restart-required unless noted)

| Field | Default | Meaning |
|---|---|---|
| `quiesce_ms` | `300` | Per-path settle window before a write becomes an op (coalesces rapid writes). |
| `scan_interval_secs` | `5` | Authoritative Merkle rescan cadence. For NFS-exported shares this bounds client-write detection latency. |
| `reconcile_interval_secs` | `300` | Periodic anti-entropy session cadence per peer. |
| `max_file_bytes` | `67108864` (64 MiB) | Single-file size cap. |
| `chunk_min_bytes` | `262144` (256 KiB) | FastCDC lower bound. |
| `chunk_avg_bytes` | `1048576` (1 MiB) | FastCDC target average. |
| `chunk_max_bytes` | `4194304` (4 MiB) | FastCDC upper bound; also the wire-frame guard. |
| `per_file_chunk_concurrency` | `6` | Parallel chunk fetches within one file. |
| `max_concurrent_transfers` | `8` | Engine-wide concurrent transfer bound. |
| `serve_concurrency` | `16` | Serve streams granted per peer connection. |
| `owner_policy` | `"numeric"` | `numeric` replicates uid/gid (requires `CAP_CHOWN` — the daemon refuses to boot without it); `skip` ignores ownership. Set the **same** value mesh-wide. |
| `reserve_bytes` | `268435456` (256 MiB) | Free-space floor (absolute). **HOT**. |
| `reserve_percent` | `0.0` | Free-space floor (fraction of capacity). Effective floor = `max(reserve_bytes, reserve_percent × capacity)`. **HOT**. |

## `[bandwidth]` — QoS / rate shaping (HOT-reloadable)

| Field | Default | Meaning |
|---|---|---|
| `global_bps` | `0` (unlimited) | Engine-wide ceiling, bytes/sec. |
| `per_peer_bps` | `0` (unlimited) | Per-peer ceiling, bytes/sec. |
| `small_asset_bytes` | (see example) | Files at/under this size use the priority (interactive) lane. |
| `schedule` | none | Optional time-of-day rules overriding the ceilings. |

Bandwidth can also be adjusted live without editing the file:
`replicorectl bandwidth set <global> <per_peer>` (suffixes `k`/`m`/`g`; `0` =
unlimited).

## Placement rules enforced at load

- `db_path`, `cert_path`, `key_path`, and `cas_dir` must be **outside**
  `share_dir` — config load rejects them inside (they would otherwise be watched,
  hashed every scan, and replicated).
- `share_dir` must be a real local path.

## What a reload applies vs. what needs a restart

**HOT** (applied live by `config reload`): the peer set (`[[peers]]`), the trust
anchor (`[trust].admin_pubkey`), the bandwidth policy (`[bandwidth]`), and the
free-space reserve (`reserve_bytes` / `reserve_percent`).

**RESTART-REQUIRED** (bound at boot): everything else — identity, addresses,
paths, chunking parameters, intervals, concurrency bounds, and `owner_policy`.
`replicorectl config diff` labels every change so you know before you reload.
