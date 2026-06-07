#!/usr/bin/env bash
# wan-testbed.sh — three-node emulated-WAN test rig for Replicore (M2 mesh).
#
# Creates three Linux network namespaces (rc-a, rc-b, rc-c) joined by a root-
# namespace bridge, and (in WAN mode) shapes each node's egress with tc netem
# to emulate a high-latency/lossy path. Any pair sees ~2*DELAY RTT. The bridge
# carries a root-ns address so the host (and tests) can reach every node's
# health endpoint directly.
#
# Requirements: root, iproute2, sch_netem (detected; falls back to LAN).
#
# Usage:
#   sudo scripts/wan-testbed.sh up          # namespaces + bridge (+ shaping)
#   sudo scripts/wan-testbed.sh status      # addresses, qdiscs, pings
#   sudo scripts/wan-testbed.sh certs       # gen 3 identities + configs
#   sudo scripts/wan-testbed.sh run-a|run-b|run-c   # run a daemon (fg)
#   sudo scripts/wan-testbed.sh shell-a|shell-b|shell-c
#   sudo scripts/wan-testbed.sh down
#
# Tunables (env vars, with defaults):
#   MODE=wan|lan   DELAY=75ms   JITTER=10ms   LOSS=1%   RATE=      (e.g. 100mbit)
#   PORT=7000      HEALTH_PORT=8080
#   DIR_A=/srv/replicore/a  DIR_B=/srv/replicore/b  DIR_C=/srv/replicore/c
#   ETC=/srv/replicore/etc  STATE=/srv/replicore/state
#   BIN=./target/release/replicored
#
# DELAY is applied on each node's egress only, so any pair's RTT ~= 2*DELAY.

set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

BR=br-rc; BR_IP=10.123.0.254; PREFIX=24
NODES=(a b c)
declare -A NS=( [a]=rc-a [b]=rc-b [c]=rc-c )
declare -A IP=( [a]=10.123.0.1 [b]=10.123.0.2 [c]=10.123.0.3 )
declare -A NODE_ID=(
  [a]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  [b]="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  [c]="cccccccccccccccccccccccccccccccc"
)

MODE=${MODE:-wan}
DELAY=${DELAY:-75ms}
JITTER=${JITTER:-10ms}
LOSS=${LOSS:-1%}
RATE=${RATE:-}
PORT=${PORT:-7000}
HEALTH_PORT=${HEALTH_PORT:-8080}
DIR_A=${DIR_A:-/srv/replicore/a}
DIR_B=${DIR_B:-/srv/replicore/b}
DIR_C=${DIR_C:-/srv/replicore/c}
ETC=${ETC:-/srv/replicore/etc}
STATE=${STATE:-/srv/replicore/state}
BIN=${BIN:-./target/release/replicored}
declare -A DIR=( [a]="$DIR_A" [b]="$DIR_B" [c]="$DIR_C" )

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"; }

netem_available() {
  ip netns add _rc_probe 2>/dev/null || return 1
  local ok=1
  ip netns exec _rc_probe ip link set lo up 2>/dev/null || true
  if ip netns exec _rc_probe tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    ok=0
  fi
  ip netns del _rc_probe 2>/dev/null || true
  return $ok
}

shape() { # $1 = namespace, $2 = device (egress shaping inside the ns)
  local netem="netem delay ${DELAY} ${JITTER} distribution normal loss ${LOSS}"
  [ -n "$RATE" ] && netem="$netem rate ${RATE}"
  ip netns exec "$1" tc qdisc add dev "$2" root $netem
}

up() {
  need_root
  ip netns list | grep -q "^rc-a\b" && die "already up; run 'down' first"

  ip link add "$BR" type bridge
  ip addr add "${BR_IP}/${PREFIX}" dev "$BR"
  ip link set "$BR" up

  local shaped=0
  if [ "$MODE" = wan ] && netem_available; then shaped=1; fi

  for n in "${NODES[@]}"; do
    local ns="${NS[$n]}" veth="veth-$n" brv="brv-$n"
    ip netns add "$ns"
    ip link add "$veth" type veth peer name "$brv"
    ip link set "$veth" netns "$ns"
    ip link set "$brv" master "$BR" up
    ip netns exec "$ns" ip addr add "${IP[$n]}/${PREFIX}" dev "$veth"
    ip netns exec "$ns" ip link set "$veth" up
    ip netns exec "$ns" ip link set lo up
    if [ "$shaped" = 1 ]; then shape "$ns" "$veth"; fi
    mkdir -p "${DIR[$n]}"
  done

  if [ "$MODE" = wan ]; then
    if [ "$shaped" = 1 ]; then
      echo "WAN mode: egress delay=${DELAY}+-${JITTER} loss=${LOSS} rate=${RATE:-unshaped} (pairwise RTT ~$(( ${DELAY%ms} * 2 ))ms)"
    else
      echo "WARNING: sch_netem unavailable; running LAN-speed (no shaping)." >&2
    fi
  else
    echo "LAN mode: no shaping."
  fi
  echo "up. a=${IP[a]} b=${IP[b]} c=${IP[c]} (bridge ${BR_IP}; host can reach all nodes)"
}

status() {
  need_root
  for n in "${NODES[@]}"; do
    echo "== ${NS[$n]} =="
    ip netns exec "${NS[$n]}" ip -br addr 2>/dev/null || { echo "(absent)"; continue; }
    ip netns exec "${NS[$n]}" tc qdisc show dev "veth-$n" | sed 's/^/  qdisc: /'
  done
  echo "== connectivity (a -> b, a -> c) =="
  ip netns exec rc-a ping -c 3 -i 0.3 "${IP[b]}" 2>&1 | tail -1 || echo "(no link)"
  ip netns exec rc-a ping -c 3 -i 0.3 "${IP[c]}" 2>&1 | tail -1 || echo "(no link)"
}

# Generate the three node identities and write cross-pinned configs.
gen_certs() {
  need_root
  [ -x "$BIN" ] || die "binary not found at $BIN (build with: cargo build --release)"
  mkdir -p "$ETC" "$STATE" "$DIR_A" "$DIR_B" "$DIR_C"
  declare -A FP
  for n in "${NODES[@]}"; do
    "$BIN" gen-cert --out-dir "$ETC" --name "node-$n" > "$ETC/node-$n.gen"
    FP[$n]=$(awk '/^fingerprint:/{print $2}' "$ETC/node-$n.gen")
  done

  for n in "${NODES[@]}"; do
    {
      cat <<EOF
node_id   = "${NODE_ID[$n]}"
listen    = "${IP[$n]}:${PORT}"
share_dir = "${DIR[$n]}"
db_path   = "$STATE/node-$n.db"
cas_dir   = "$STATE/node-$n.cas"
cert_path = "$ETC/node-$n.cert.pem"
key_path  = "$ETC/node-$n.key.pem"
health_listen = "${IP[$n]}:${HEALTH_PORT}"
EOF
      for p in "${NODES[@]}"; do
        [ "$p" = "$n" ] && continue
        cat <<EOF

[[peers]]
node_id     = "${NODE_ID[$p]}"
addr        = "${IP[$p]}:${PORT}"
fingerprint = "${FP[$p]}"
EOF
      done
    } > "$ETC/node-$n.toml"
  done
  echo "configs written: $ETC/node-{a,b,c}.toml"
  echo "next: 'run-a', 'run-b', 'run-c' in three terminals."
}

run_node() { # $1 = a|b|c
  need_root
  [ -x "$BIN" ] || die "binary not found at $BIN (build with: cargo build --release)"
  [ -f "$ETC/node-$1.toml" ] || die "no config at $ETC/node-$1.toml (run 'certs' first)"
  echo "replicored node-$1 in ${NS[$1]} (config $ETC/node-$1.toml)"
  exec ip netns exec "${NS[$1]}" env RUST_LOG="${RUST_LOG:-info}" "$BIN" run --config "$ETC/node-$1.toml"
}

down() {
  need_root
  for n in "${NODES[@]}"; do ip netns del "${NS[$n]}" 2>/dev/null || true; done
  ip netns del _rc_probe 2>/dev/null || true
  ip link del "$BR" 2>/dev/null || true
  echo "down."
}

case "${1:-}" in
  up)       up ;;
  down)     down ;;
  status)   status ;;
  certs)    gen_certs ;;
  run-a)    run_node a ;;
  run-b)    run_node b ;;
  run-c)    run_node c ;;
  shell-a)  need_root; exec ip netns exec rc-a "${SHELL:-bash}" ;;
  shell-b)  need_root; exec ip netns exec rc-b "${SHELL:-bash}" ;;
  shell-c)  need_root; exec ip netns exec rc-c "${SHELL:-bash}" ;;
  *) echo "usage: $0 {up|down|status|certs|run-a|run-b|run-c|shell-a|shell-b|shell-c}"; exit 1 ;;
esac
