#!/usr/bin/env bash
# Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
#
# build-release.sh — produce portable, statically-linked Replicore release
# artifacts (one tarball + checksum per target triple).
#
# The binaries are built against musl libc and fully statically linked, so a
# single artifact runs on ANY Linux distribution and version (Ubuntu, Debian,
# RHEL/Rocky/Alma, Fedora, Alpine, Arch, openSUSE, …) with no glibc dependency.
# The only runtime requirement is the Linux kernel itself (fanotify; see
# INSTALL.md for the kernel/capability requirements).
#
# Usage:
#   scripts/build-release.sh [target-triple ...]
#
# Environment:
#   TARGETS   space-separated target triples (overridden by positional args).
#             Default: the musl target for the host architecture.
#   OUTDIR    where tarballs + SHA256SUMS land. Default: ./dist
#   USE_ZIGBUILD=1   use `cargo zigbuild` instead of `cargo build` (lets one
#                    host cross-compile every musl target with no per-arch C
#                    toolchain; what CI uses). Auto-enabled when cargo-zigbuild
#                    is installed and a non-host target is requested.
#
# Examples:
#   scripts/build-release.sh                                   # host arch, static
#   TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl" \
#       USE_ZIGBUILD=1 scripts/build-release.sh                # full release matrix
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(awk -F'"' '/^version *=/{print $2; exit}' Cargo.toml)"
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }

OUTDIR="${OUTDIR:-$REPO_ROOT/dist}"
host_arch="$(uname -m)"
default_target="${host_arch}-unknown-linux-musl"

# Positional args win; else $TARGETS; else the host musl target.
if [ "$#" -gt 0 ]; then
  TARGETS="$*"
else
  TARGETS="${TARGETS:-$default_target}"
fi

# Files bundled alongside the binaries in every tarball.
EXTRA_FILES=(README.md INSTALL.md CHANGELOG.md replicore.example.toml packaging/replicored.service)
[ -f LICENSE ] && EXTRA_FILES+=(LICENSE)

mkdir -p "$OUTDIR"
echo "Replicore release build  version=$VERSION  targets=[$TARGETS]  out=$OUTDIR"

# Strip symbols at the rustc layer so no per-architecture `strip` binary is
# needed (works identically for cross-built aarch64).
export RUSTFLAGS="${RUSTFLAGS:-} -C strip=symbols"

build_one() {
  local target="$1"
  echo "==> building $target"
  rustup target add "$target" >/dev/null 2>&1 || true

  local builder="cargo build"
  if [ "${USE_ZIGBUILD:-0}" = "1" ] || { command -v cargo-zigbuild >/dev/null 2>&1 \
        && [ "$target" != "$default_target" ]; }; then
    builder="cargo zigbuild"
  elif [[ "$target" == x86_64-unknown-linux-musl ]]; then
    # Native musl build on an x86_64 host.
    export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-musl-gcc}"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-musl-gcc}"
  fi

  $builder --release --target "$target" --bins

  local bindir="target/$target/release"
  for b in replicored replicorectl; do
    [ -x "$bindir/$b" ] || { echo "missing $bindir/$b" >&2; exit 1; }
  done

  # Confirm the artifact is genuinely static (a non-static binary defeats the
  # whole "runs on any distro" promise). ldd prints "statically linked" / errors
  # with "not a dynamic executable" for a static binary.
  if ldd "$bindir/replicored" 2>&1 | grep -Eqi 'statically linked|not a dynamic executable'; then
    echo "    static link: OK"
  else
    echo "    WARNING: $target replicored appears dynamically linked:" >&2
    ldd "$bindir/replicored" 2>&1 | sed 's/^/      /' >&2
  fi

  # Stage and tar.
  local name="replicore-v${VERSION}-${target}"
  local stage="$OUTDIR/$name"
  rm -rf "$stage"; mkdir -p "$stage"
  cp "$bindir/replicored" "$bindir/replicorectl" "$stage/"
  for f in "${EXTRA_FILES[@]}"; do [ -e "$f" ] && cp "$f" "$stage/"; done

  tar -C "$OUTDIR" -czf "$OUTDIR/$name.tar.gz" "$name"
  rm -rf "$stage"
  echo "    packaged $OUTDIR/$name.tar.gz"
}

for t in $TARGETS; do build_one "$t"; done

# One checksum file covering every tarball (consumers verify with
# `sha256sum -c SHA256SUMS`).
( cd "$OUTDIR" && sha256sum replicore-v"$VERSION"-*.tar.gz > SHA256SUMS )
echo
echo "Artifacts in $OUTDIR:"
( cd "$OUTDIR" && ls -1 replicore-v"$VERSION"-*.tar.gz SHA256SUMS )
echo
echo "Checksums:"; cat "$OUTDIR/SHA256SUMS"
