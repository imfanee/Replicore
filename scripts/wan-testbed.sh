#!/usr/bin/env bash
# wan-testbed.sh — four-node emulated-WAN test rig for Replicore (M2 mesh +
# M2.5 dynamic membership: a,b,c are the static trio; d joins dynamically).
#
# Creates Linux network namespaces (rc-a, rc-b, rc-c, rc-d) joined by a root-
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
#   sudo scripts/wan-testbed.sh certs       # gen 4 identities + admin key + configs
#   sudo scripts/wan-testbed.sh run-a|run-b|run-c|run-d   # run a daemon (fg)
#   sudo scripts/wan-testbed.sh add-d|remove-d  # signed dynamic join/leave of d
#   sudo scripts/wan-testbed.sh shell-a|shell-b|shell-c|shell-d
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
# a,b,c form the static M2.5 trio; d is the DYNAMIC-join node — it is admitted
# at runtime via `add-d` (a signed roster add), not by anyone's static peers.
NODES=(a b c d)
STATIC=(a b c)
declare -A NS=( [a]=rc-a [b]=rc-b [c]=rc-c [d]=rc-d )
declare -A IP=( [a]=10.123.0.1 [b]=10.123.0.2 [c]=10.123.0.3 [d]=10.123.0.4 )
declare -A NODE_ID=(
  [a]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  [b]="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  [c]="cccccccccccccccccccccccccccccccc"
  [d]="dddddddddddddddddddddddddddddddd"
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
DIR_D=${DIR_D:-/srv/replicore/d}
ETC=${ETC:-/srv/replicore/etc}
STATE=${STATE:-/srv/replicore/state}
BIN=${BIN:-./target/release/replicored}
RECTL=${RECTL:-./target/release/replicorectl}
ADMIN_KEY="$ETC/admin.sk"
declare -A DIR=( [a]="$DIR_A" [b]="$DIR_B" [c]="$DIR_C" [d]="$DIR_D" )

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
  mkdir -p "$ETC" "$STATE" "$DIR_A" "$DIR_B" "$DIR_C" "$DIR_D"
  declare -A FP
  for n in "${NODES[@]}"; do
    "$BIN" gen-cert --out-dir "$ETC" --name "node-$n" > "$ETC/node-$n.gen"
    FP[$n]=$(awk '/^fingerprint:/{print $2}' "$ETC/node-$n.gen")
  done

  # Cluster trust anchor (FR-1305): one admin keypair. The secret stays on the
  # host (operator side, never in a daemon config); the pubkey goes in every
  # intent file's [trust] block.
  rm -f "$ADMIN_KEY"
  "$BIN" gen-admin-key --out "$ADMIN_KEY" > "$ETC/admin.gen"
  local ADMIN_PUB
  ADMIN_PUB=$(awk '/^admin pubkey:/{print $3}' "$ETC/admin.gen")
  [ -n "$ADMIN_PUB" ] || die "could not parse admin pubkey"

  for n in "${NODES[@]}"; do
    # d is the dynamic-join node: it SEEDS the trio (so it can contact them) but
    # the trio does NOT statically list d — d enters the data path only after a
    # signed `add-d`. The trio statically lists each other (the M2 mesh).
    local seeds=("${STATIC[@]}")
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

[trust]
admin_pubkey = "$ADMIN_PUB"
EOF
      for p in "${seeds[@]}"; do
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
  echo "configs written: $ETC/node-{a,b,c,d}.toml (admin pubkey pinned in [trust])"
  echo "next: run-a/run-b/run-c (the trio), then run-d + 'add-d' to join dynamically."
}

# `replicorectl member add/remove d`, signed client-side with the admin secret.
# The control socket is a filesystem UDS (not net-ns scoped), so this runs in
# the root namespace pointing at node-a's socket.
member_d() { # $1 = add|remove
  need_root
  [ -x "$RECTL" ] || die "replicorectl not built ($RECTL); cargo build --release"
  [ -f "$ADMIN_KEY" ] || die "no admin key at $ADMIN_KEY (run 'certs' first)"
  local sock="$STATE/node-a.sock"
  if [ "$1" = "add" ]; then
    "$RECTL" --socket "$sock" member add \
      "${NODE_ID[d]}" "${IP[d]}:${PORT}" "${FP_D:-$(awk '/^fingerprint:/{print $2}' "$ETC/node-d.gen")}" \
      --admin-key "$ADMIN_KEY"
  else
    "$RECTL" --socket "$sock" member remove "${NODE_ID[d]}" --admin-key "$ADMIN_KEY"
  fi
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
  run-d)    run_node d ;;
  add-d)    member_d add ;;
  remove-d) member_d remove ;;
  shell-a)  need_root; exec ip netns exec rc-a "${SHELL:-bash}" ;;
  shell-b)  need_root; exec ip netns exec rc-b "${SHELL:-bash}" ;;
  shell-c)  need_root; exec ip netns exec rc-c "${SHELL:-bash}" ;;
  shell-d)  need_root; exec ip netns exec rc-d "${SHELL:-bash}" ;;
  *) echo "usage: $0 {up|down|status|certs|run-a|run-b|run-c|run-d|add-d|remove-d|shell-a|shell-b|shell-c|shell-d}"; exit 1 ;;
esac
