# Replicore — M0 Spike

Phase 0 ("M0 — Spike") of the Replicore development plan. It proves the full
vertical slice end to end: **a file written on the source node appears, intact
and atomically, on the sink node over QUIC.**

This compiles on the stock Ubuntu 24.04 `cargo` (Rust 1.75) and was verified
end-to-end on localhost (text + 200 KB binary, byte-identical on arrival).

## What M0 does

```
  source node                                   sink node
  -----------                                   ---------
  fanotify (FAN_CLOSE_WRITE on the mount)        QUIC server (quinn)
        |  path via /proc/self/fd                      |  accept uni-stream
        v                                              v
  read file + BLAKE3 hash  --- QUIC uni-stream --> verify hash
        |                      (bincoded FileMsg)      |
  open_uni / write / finish                       stage -> fsync -> rename
                                                  (atomic publish)
```

- **E1 (watcher):** fanotify `FAN_CLOSE_WRITE`, mount mark, path resolved through
  `/proc/self/fd`. Deliberately uses close-after-write because that is the right
  signal for write-once recordings.
- **E5 (transport):** QUIC via `quinn` — we never hand-roll UDP reliability
  (NFR-C2). One whole file per uni-stream.
- **E8 (apply):** stage in the destination dir → `fsync` → verify BLAKE3 →
  atomic `rename` → `fsync` parent. A consumer never sees a partial file
  (FR-801/FR-803).

## Prerequisites

- Linux. The watcher needs `CAP_SYS_ADMIN` (run as root or grant the cap), and a
  kernel/container that permits `fanotify_init` + `FAN_MARK_MOUNT`.
- Rust/cargo. On Ubuntu 24.04: `apt-get install -y cargo`. The `time` and
  `blake3` pins in `Cargo.toml` exist only to satisfy that older toolchain;
  drop them on a current Rust.

## Build

```sh
cargo build            # or: cargo build --release
```

## Run

Two terminals (or two hosts; replace the address):

```sh
# sink: receive and apply
sudo ./target/debug/replicored sink   --listen 0.0.0.0:7000 --dir /srv/replicore/in

# source: watch a directory and ship closed files
sudo ./target/debug/replicored source --peer 10.0.0.2:7000  --dir /srv/replicore/out
```

Then write a file into the source's `--dir`; it appears under the sink's `--dir`.

## Smoke test (localhost)

```sh
mkdir -p /tmp/rep_out /tmp/rep_in
./target/debug/replicored sink   --listen 127.0.0.1:7000 --dir /tmp/rep_in  &
./target/debug/replicored source --peer 127.0.0.1:7000   --dir /tmp/rep_out &
sleep 2
echo "hello" > /tmp/rep_out/greeting.txt
sleep 2
cmp /tmp/rep_out/greeting.txt /tmp/rep_in/greeting.txt && echo REPLICATED_OK
```

## What M0 deliberately is NOT (and where it goes next)

M0 is a one-directional, conflict-free, single-file-per-stream slice. The
following are known omissions, each mapped to the requirement that closes it:

| Omission in M0 | Closed by | Requirement |
|---|---|---|
| Insecure client cert verifier (accepts any cert) | Mutual TLS + pinned peer allowlist | FR-1001 / FR-1002 |
| Only catches close-after-write; no create/delete/rename | fanotify FID reporting (`FAN_REPORT_DFID_NAME`) | FR-102 |
| No baseline scan or overflow rescan | Startup scan + targeted rescan | FR-103 / FR-104 |
| One-directional only | Op-log + version vectors + apply-suppression | FR-201 / FR-301 / FR-902 |
| Whole file per message (64 MiB cap) | Content-defined chunking + multi-source fetch | FR-402 / FR-403 |
| Mode only; no uid/gid/xattr/ACL/mtime/symlink/sparse | Full metadata fidelity | FR-106 |
| No reconciliation / self-heal | Merkle anti-entropy | FR-701 |
| No metrics, QoS, admin CLI | Observability + bandwidth scheduler + CLI | FR-1101 / FR-1103 / FR-1105 |

The single most important next step is **Phase 1 / M1**: introduce the op-log and
per-file version vectors, make replication bidirectional, and add
apply-suppression so a two-node mesh does not loop. That converts this spike from
"copies files one way" into the correctness core of Replicore.

## Layout

```
src/
  main.rs    CLI dispatch (sink | source)
  proto.rs   wire message (FileMsg) + ALPN
  watch.rs   fanotify watcher (E1)
  net.rs     QUIC sink + source (E5) and the SPIKE-ONLY cert verifier
  apply.rs   atomic staged apply (E8)
```
