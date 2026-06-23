*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Installation Guide

How to install Replicore on **any Linux distribution**. The prebuilt binaries are
statically linked against musl libc, so a single artifact per CPU architecture
runs on Ubuntu, Debian, RHEL/Rocky/AlmaLinux, Fedora, Alpine, Arch, openSUSE, and
anything else with a recent-enough kernel — no glibc version to match, no
dependencies to install.

This guide gets the two binaries (`replicored`, `replicorectl`) onto a host and
verified. For the full production procedure — identities, configuration,
firewalling, backups, upgrades — follow **[docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md)**
after installing.

> **License.** Replicore is proprietary software (© 2026 Faisal Hanif, all rights
> reserved). Installing or running it requires a license from the Author —
> contact **imfanee@gmail.com**. See [LICENSE](LICENSE) for terms.

---

## 1. Requirements

| Requirement | Detail |
|---|---|
| **OS** | Linux only. Replicore uses `fanotify` for change detection; there is no macOS/Windows build. |
| **Kernel** | **5.9+ recommended** (enables the low-latency `fanotify` FID watcher). 5.1+ works with the periodic Merkle rescanner as the correctness backstop. |
| **Architecture** | `x86_64` (amd64) or `aarch64` (arm64). |
| **Privileges** | The daemon arms a filesystem-wide `fanotify` mark, so it must run as **root** or with the equivalent capability. With the default `owner_policy = "numeric"` it also needs **`CAP_CHOWN`** or it refuses to boot. See [docs/SECURITY.md](docs/SECURITY.md). |
| **Storage** | Local **block-backed** storage for each node's `share_dir`, `db_path`, and `cas_dir`. **Never** point `share_dir` at an NFS mount — see [docs/DEPLOYMENT-NFS-RUNBOOK.md](docs/DEPLOYMENT-NFS-RUNBOOK.md). |
| **Network** | UDP reachability between nodes on each node's `listen` port (the transport is QUIC over UDP). |

Check your kernel and architecture:

```sh
uname -r    # kernel version (want >= 5.9)
uname -m    # x86_64  -> use the x86_64 build
            # aarch64 -> use the aarch64 build
```

---

## 2. Install a prebuilt binary (recommended)

Every [GitHub Release](https://github.com/imfanee/Replicore/releases) attaches a
static tarball per architecture plus a `SHA256SUMS` file.

**1. Pick your version and architecture.**

```sh
VERSION=1.0.0

case "$(uname -m)" in
  x86_64)          ARCH=x86_64-unknown-linux-musl ;;
  aarch64|arm64)   ARCH=aarch64-unknown-linux-musl ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac
TARBALL="replicore-v${VERSION}-${ARCH}.tar.gz"
BASE="https://github.com/imfanee/Replicore/releases/download/v${VERSION}"
```

**2. Download the tarball and the checksums.**

```sh
curl -fLO "${BASE}/${TARBALL}"
curl -fLO "${BASE}/SHA256SUMS"
```

**3. Verify the checksum** (do not skip this):

```sh
sha256sum -c SHA256SUMS --ignore-missing
# expect: replicore-v1.0.0-<arch>.tar.gz: OK
```

**4. Extract and install** the binaries onto your `PATH`:

```sh
tar -xzf "${TARBALL}"
sudo install -m 0755 "replicore-v${VERSION}-${ARCH}/replicored"   /usr/local/bin/
sudo install -m 0755 "replicore-v${VERSION}-${ARCH}/replicorectl" /usr/local/bin/
```

**5. Confirm it runs** (proves the static binary works on your distro):

```sh
replicored version       # -> replicored 1.0.0 (protocol v4)
replicorectl --help 2>&1 | head -1
```

The tarball also contains `README.md`, `CHANGELOG.md`, this guide,
`replicore.example.toml`, and `packaging/replicored.service` for convenience.

---

## 3. Per-distribution notes

The **same static binary** works on every distribution below — these are just the
distro-specific things to be aware of. Install steps are identical to §2.

| Distribution(s) | Notes |
|---|---|
| **Debian / Ubuntu** | Works as-is. `curl`, `tar`, `coreutils` are present on minimal images; otherwise `apt-get install -y curl`. |
| **RHEL / CentOS Stream / Rocky / AlmaLinux** | Works as-is. If SELinux is **enforcing**, give the binary the right context and allow the service to write its data dirs (`restorecon -Rv /srv/replicore`); audit with `ausearch -m avc` if the daemon is denied. |
| **Fedora** | Works as-is (recent kernels — FID watcher fully supported). |
| **Alpine** | Alpine is musl-native, so the static binary is a perfect fit. `apk add curl` if needed; nothing else. |
| **Arch / Manjaro** | Works as-is (rolling kernel — FID watcher fully supported). |
| **openSUSE Leap / Tumbleweed** | Works as-is. On Leap, confirm the kernel is 5.9+ for the low-latency watcher. |
| **Container base images** | Run on the host or a privileged container: `fanotify` filesystem marks need host-level privilege and a real (non-overlay-only) filesystem for the `share_dir`. |

If your kernel is **older than 5.9**, the daemon still runs correctly — it logs
`fanotify FID mode unavailable` and relies on the periodic authoritative
rescanner. Latency to detect local changes rises from "instant" to the scan
interval; replication correctness is unaffected.

---

## 4. Build from source

Use this for an architecture/libc we don't ship, an air-gapped build, or to build
from a specific commit.

**Prerequisites:** a Rust toolchain (1.96+; install via [rustup.rs](https://rustup.rs))
and a C compiler (the bundled SQLite and `ring` compile C). On Debian/Ubuntu:
`sudo apt-get install -y build-essential`.

**Plain build for the host** (dynamically linked against the host libc):

```sh
git clone https://github.com/imfanee/Replicore.git
cd Replicore
cargo build --release
# binaries at target/release/replicored and target/release/replicorectl
sudo install -m 0755 target/release/replicore{d,ctl} /usr/local/bin/
```

**Portable static build** (musl — the same kind of artifact the releases ship):

```sh
rustup target add x86_64-unknown-linux-musl     # or aarch64-unknown-linux-musl
sudo apt-get install -y musl-tools               # provides musl-gcc (Debian/Ubuntu)

scripts/build-release.sh x86_64-unknown-linux-musl
# tarball + SHA256SUMS land in ./dist/
```

`scripts/build-release.sh` strips the binaries, verifies they are statically
linked, and packages a release tarball identical in layout to the published ones.
To cross-compile a different architecture without a matching C toolchain, install
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) and run with
`USE_ZIGBUILD=1` (this is exactly what CI does).

---

## 5. Run it as a service (systemd)

A hardened unit ships in [`packaging/replicored.service`](packaging/replicored.service):

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin replicore || true
sudo install -m 0644 packaging/replicored.service /etc/systemd/system/replicored.service
# edit ExecStart / ReadWritePaths to match your paths, then:
sudo systemctl daemon-reload
sudo systemctl enable --now replicored
journalctl -u replicored -f
```

Before the daemon will do anything useful you must provision a node identity and
write its config. That — plus the capability model, firewalling, and upgrades —
is covered step by step in **[docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md)**.

---

## 6. Verify the install end to end

A quick local smoke that the binary is fully functional on this host:

```sh
replicored version
# generate a throwaway identity (writes node-a.cert.pem / node-a.key.pem)
replicored gen-cert --out-dir /tmp/rc-smoke --name node-a
ls -l /tmp/rc-smoke           # cert + key present, key mode 0600
rm -rf /tmp/rc-smoke
```

If `version` prints and `gen-cert` writes a key pair, the binary is good on your
distribution. Proceed to the deployment guide to stand up a real mesh.

---

## 7. Upgrade and uninstall

**Upgrade:** install the new binaries over the old ones (§2) and restart the
service — `sudo systemctl restart replicored`. The wire protocol is a flag-day
version: upgrade all nodes in a mesh to the same release. Check the
[CHANGELOG](CHANGELOG.md) for any protocol bump before a rolling upgrade.

**Uninstall:**

```sh
sudo systemctl disable --now replicored
sudo rm -f /etc/systemd/system/replicored.service /usr/local/bin/replicored /usr/local/bin/replicorectl
sudo systemctl daemon-reload
# data dirs (share_dir / db_path / cas_dir) are left in place — remove them deliberately.
```

---

## Next steps

- **[docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md)** — provision identities, configure, run a mesh in production.
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — every config field and its default.
- **[docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md)** — day-2 operations with `replicorectl`.
- **[docs/SECURITY.md](docs/SECURITY.md)** — trust model, mutual TLS, the capability/privilege model.
