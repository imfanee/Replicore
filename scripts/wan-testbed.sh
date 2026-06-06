#!/usr/bin/env bash
# wan-testbed.sh — two-node + emulated-WAN test rig for Replicore.
#
# Creates two Linux network namespaces (rc-a, rc-b) joined by a veth pair, and
# (in WAN mode) shapes the link with tc netem to emulate a high-latency/lossy
# path such as DRC<->Marseille. Lets you run a sink in one namespace and a
# source in the other over a realistic link, on a single host.
#
# Requirements: root, iproute2, and the sch_netem kernel module (present on any
# normal VM kernel; some minimal containers lack it -- this script detects that).
#
# Usage:
#   sudo scripts/wan-testbed.sh up          # build namespaces (+ WAN shaping)
#   sudo scripts/wan-testbed.sh status      # show addresses, qdiscs, ping
#   sudo scripts/wan-testbed.sh sink        # run replicored sink in rc-b (fg)
#   sudo scripts/wan-testbed.sh source      # run replicored source in rc-a (fg)
#   sudo scripts/wan-testbed.sh shell-a     # interactive shell in rc-a
#   sudo scripts/wan-testbed.sh down        # tear everything down
#
# Tunables (env vars, with defaults):
#   MODE=wan|lan   DELAY=75ms   JITTER=10ms   LOSS=1%   RATE=        (e.g. 100mbit)
#   PORT=7000      DIR_A=/srv/replicore/a    DIR_B=/srv/replicore/b
#   BIN=./target/release/replicored
#
# Note: DELAY is one-way and applied on BOTH veth ends, so RTT ~= 2*DELAY.
# 75ms each way => ~150ms RTT.

set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

NS_A=rc-a; NS_B=rc-b
VETH_A=veth-a; VETH_B=veth-b
IP_A=10.123.0.1; IP_B=10.123.0.2; PREFIX=24

MODE=${MODE:-wan}
DELAY=${DELAY:-75ms}
JITTER=${JITTER:-10ms}
LOSS=${LOSS:-1%}
RATE=${RATE:-}
PORT=${PORT:-7000}
DIR_A=${DIR_A:-/srv/replicore/a}
DIR_B=${DIR_B:-/srv/replicore/b}
BIN=${BIN:-./target/release/replicored}

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"; }

netem_available() {
  # Probe by trying to attach netem to loopback in a throwaway namespace.
  ip netns add _rc_probe 2>/dev/null || return 1
  local ok=1
  ip netns exec _rc_probe ip link set lo up 2>/dev/null || true
  if ip netns exec _rc_probe tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    ok=0
  fi
  ip netns del _rc_probe 2>/dev/null || true
  return $ok
}

shape() { # $1 = namespace, $2 = device
  local netem="netem delay ${DELAY} ${JITTER} distribution normal loss ${LOSS}"
  [ -n "$RATE" ] && netem="$netem rate ${RATE}"
  ip netns exec "$1" tc qdisc add dev "$2" root $netem
}

up() {
  need_root
  ip netns list | grep -q "^${NS_A}\b" && die "already up; run 'down' first"

  ip netns add "$NS_A"; ip netns add "$NS_B"
  ip link add "$VETH_A" type veth peer name "$VETH_B"
  ip link set "$VETH_A" netns "$NS_A"
  ip link set "$VETH_B" netns "$NS_B"

  ip netns exec "$NS_A" ip addr add "${IP_A}/${PREFIX}" dev "$VETH_A"
  ip netns exec "$NS_B" ip addr add "${IP_B}/${PREFIX}" dev "$VETH_B"
  for ns in "$NS_A:$VETH_A" "$NS_B:$VETH_B"; do
    ip netns exec "${ns%%:*}" ip link set "${ns##*:}" up
    ip netns exec "${ns%%:*}" ip link set lo up
  done

  if [ "$MODE" = "wan" ]; then
    if netem_available; then
      shape "$NS_A" "$VETH_A"
      shape "$NS_B" "$VETH_B"
      echo "WAN mode: delay=${DELAY}+-${JITTER} loss=${LOSS} rate=${RATE:-unshaped} (RTT ~$(( ${DELAY%ms} * 2 ))ms)"
    else
      echo "WARNING: sch_netem unavailable on this kernel; running LAN-speed (no shaping)." >&2
      echo "         Run on a VM with the netem module for realistic WAN tests." >&2
    fi
  else
    echo "LAN mode: no shaping."
  fi

  mkdir -p "$DIR_A" "$DIR_B"
  echo "up. node-a=${IP_A} (ns ${NS_A}, dir ${DIR_A}); node-b=${IP_B} (ns ${NS_B}, dir ${DIR_B})"
  echo "next: 'sink' in one terminal, 'source' in another."
}

status() {
  need_root
  for ns in "$NS_A" "$NS_B"; do
    echo "== $ns =="
    ip netns exec "$ns" ip -br addr 2>/dev/null || { echo "(absent)"; continue; }
    ip netns exec "$ns" tc qdisc show | sed 's/^/  qdisc: /'
  done
  echo "== connectivity (a -> b) =="
  ip netns exec "$NS_A" ping -c 5 -i 0.3 "$IP_B" 2>&1 | tail -3 || echo "(no link)"
}

run_sink() {
  need_root
  [ -x "$BIN" ] || die "binary not found at $BIN (build with: cargo build --release)"
  echo "sink in ${NS_B} on ${IP_B}:${PORT} -> ${DIR_B}"
  exec ip netns exec "$NS_B" "$BIN" sink --listen "${IP_B}:${PORT}" --dir "$DIR_B"
}

run_source() {
  need_root
  [ -x "$BIN" ] || die "binary not found at $BIN (build with: cargo build --release)"
  echo "source in ${NS_A} watching ${DIR_A} -> peer ${IP_B}:${PORT}"
  exec ip netns exec "$NS_A" "$BIN" source --peer "${IP_B}:${PORT}" --dir "$DIR_A"
}

down() {
  need_root
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  ip netns del _rc_probe 2>/dev/null || true
  echo "down."
}

case "${1:-}" in
  up)       up ;;
  down)     down ;;
  status)   status ;;
  sink)     run_sink ;;
  source)   run_source ;;
  shell-a)  need_root; exec ip netns exec "$NS_A" "${SHELL:-bash}" ;;
  shell-b)  need_root; exec ip netns exec "$NS_B" "${SHELL:-bash}" ;;
  *) echo "usage: $0 {up|down|status|sink|source|shell-a|shell-b}"; exit 1 ;;
esac
