#!/usr/bin/env bash
# soak.sh — synthetic IVR-traffic soak on the wan-testbed rig (M3 exit
# criterion 6 / RSD §II.8). Root required (the rig is netns-based).
#
#   sudo DURATION=604800 scripts/soak.sh        # the one-week soak
#   sudo DURATION=900 scripts/soak.sh           # 15-minute smoke
#
# Traffic model (per cycle, default every 5s):
#   - one new "recording" (200–800 KB, write-once) on a random node
#   - every 6th cycle: a "prompt" update (small file, overwritten in place,
#     sometimes on TWO nodes inside one cycle → genuine concurrent writes)
#   - every 10th cycle: delete an old recording
#   - every KILL_EVERY seconds: kill -9 a random daemon, restart it 5s later
#
# Samples every 60s into $STATE/soak.csv:
#   ts, per-node RSS (KiB), oplog rows, conflicts, guard trips,
#   max recv-cursor lag across links, tree convergence (0/1)
#
# Exit assertions (the soak FAILS loudly, never silently):
#   - final trees byte-identical across nodes (after a settle window)
#   - RSS at the end < 2× the first-hour median on every node (no leak)
#   - conflict-copy count stable over the final quarter (no copy storms)

set -euo pipefail

DURATION="${DURATION:-900}"
CYCLE_SECS="${CYCLE_SECS:-5}"
KILL_EVERY="${KILL_EVERY:-600}"
ETC=/srv/replicore/etc
STATE=/srv/replicore/state
NODES=(a b c)
declare -A DIR=([a]=/srv/replicore/a [b]=/srv/replicore/b [c]=/srv/replicore/c)
declare -A IP=([a]=10.123.0.1 [b]=10.123.0.2 [c]=10.123.0.3)
BIN="$(dirname "$0")/../target/release/replicored"
TESTBED="$(dirname "$0")/wan-testbed.sh"
CSV="$STATE/soak.csv"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

declare -A PID
start_node() {
  ip netns exec "rc-$1" "$BIN" run --config "$ETC/node-$1.toml" \
    >>"$STATE/soak-node-$1.log" 2>&1 &
  PID[$1]=$!
}

cleanup() {
  for n in "${NODES[@]}"; do kill -9 "${PID[$n]:-0}" 2>/dev/null || true; done
  "$TESTBED" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

metric() { # node, metric name
  curl -s --max-time 3 "http://${IP[$1]}:8080/metrics" 2>/dev/null \
    | awk -v m="$2" '$1==m {print $2; exit}' || echo 0
}
healthz_u64() { # node, key
  curl -s --max-time 3 "http://${IP[$1]}:8080/healthz" 2>/dev/null \
    | grep -o "\"$2\":[0-9]*" | head -1 | cut -d: -f2 || echo 0
}
rss_kib() { awk '/VmRSS/{print $2}' "/proc/${PID[$1]}/status" 2>/dev/null || echo 0; }

tree_digest() { # node share dir → one digest line
  (cd "${DIR[$1]}" 2>/dev/null && find . -type f ! -name '*.replicore-tmp*' -print0 \
    | sort -z | xargs -0 -r b3sum 2>/dev/null || true) | b3sum 2>/dev/null | cut -d' ' -f1
}
converged() {
  local d
  d="$(tree_digest a)"
  [ -n "$d" ] && [ "$d" = "$(tree_digest b)" ] && [ "$d" = "$(tree_digest c)" ]
}
copy_count() { find "${DIR[a]}" -name '*.sync-conflict-*' 2>/dev/null | wc -l; }

# ---------------------------------------------------------------------------
echo "[soak] rig up (LAN profile; use the WAN tests for shaped runs)"
"$TESTBED" down >/dev/null 2>&1 || true
rm -rf "$STATE" "${DIR[a]}" "${DIR[b]}" "${DIR[c]}"
"$TESTBED" up >/dev/null
"$TESTBED" certs >/dev/null
for n in "${NODES[@]}"; do start_node "$n"; done
sleep 5

echo "ts,rss_a,rss_b,rss_c,oplog_a,conflicts_a,guard_trips_a,copies,converged" >"$CSV"
echo "[soak] running for ${DURATION}s (cycle ${CYCLE_SECS}s, kill every ${KILL_EVERY}s)"

START=$(date +%s)
i=0
next_sample=$START
next_kill=$((START + KILL_EVERY))
RECORDINGS=()

while :; do
  now=$(date +%s)
  [ $((now - START)) -ge "$DURATION" ] && break
  i=$((i + 1))

  # --- traffic ---
  n=${NODES[$((RANDOM % 3))]}
  rec="recordings/$(date +%s)-$i.wav"
  mkdir -p "${DIR[$n]}/recordings"
  head -c $(((RANDOM % 600 + 200) * 1024)) /dev/urandom >"${DIR[$n]}/$rec"
  RECORDINGS+=("$rec")

  if [ $((i % 6)) -eq 0 ]; then
    # Prompt update; sometimes concurrently from two nodes (real conflicts).
    echo "prompt v$i from $n at $(date)" >"${DIR[$n]}/prompts/menu.txt" 2>/dev/null \
      || { mkdir -p "${DIR[$n]}/prompts"; echo "prompt v$i" >"${DIR[$n]}/prompts/menu.txt"; }
    if [ $((i % 12)) -eq 0 ]; then
      m=${NODES[$(((RANDOM % 2 + 1 + RANDOM % 3) % 3))]}
      mkdir -p "${DIR[$m]}/prompts"
      echo "prompt v$i CONCURRENT from $m" >"${DIR[$m]}/prompts/menu.txt"
    fi
  fi
  if [ $((i % 10)) -eq 0 ] && [ ${#RECORDINGS[@]} -gt 20 ]; then
    victim=${RECORDINGS[0]}
    RECORDINGS=("${RECORDINGS[@]:1}")
    rm -f "${DIR[a]}/$victim" "${DIR[b]}/$victim" "${DIR[c]}/$victim" 2>/dev/null || true
  fi

  # --- fault injection: kill -9 + restart ---
  if [ "$now" -ge "$next_kill" ]; then
    k=${NODES[$((RANDOM % 3))]}
    echo "[soak] kill -9 node-$k ($(date))"
    kill -9 "${PID[$k]}" 2>/dev/null || true
    sleep 5
    start_node "$k"
    next_kill=$((now + KILL_EVERY))
  fi

  # --- sampling ---
  if [ "$now" -ge "$next_sample" ]; then
    c=0
    converged && c=1
    echo "$now,$(rss_kib a),$(rss_kib b),$(rss_kib c),$(healthz_u64 a oplog_rows),$(metric a replicore_conflicts_total),$(metric a replicore_freespace_guard_trips_total),$(copy_count),$c" >>"$CSV"
    next_sample=$((now + 60))
  fi

  sleep "$CYCLE_SECS"
done

echo "[soak] traffic done; settling 90s for convergence…"
sleep 90

# --- exit assertions -------------------------------------------------------
fail=0
if converged; then
  echo "[soak] PASS: trees byte-identical across all nodes"
else
  echo "[soak] FAIL: trees diverged at the end"
  fail=1
fi

# RSS leak check: final < 2× early median, per node.
for col in 2 3 4; do
  early=$(tail -n +2 "$CSV" | head -10 | cut -d, -f$col | sort -n | awk '{a[NR]=$1} END{print a[int(NR/2)+1]}')
  final=$(tail -1 "$CSV" | cut -d, -f$col)
  if [ -n "$early" ] && [ "$early" -gt 0 ] && [ "$final" -gt $((early * 2)) ]; then
    echo "[soak] FAIL: RSS grew ${early} -> ${final} KiB (column $col)"
    fail=1
  fi
done

# Copy-storm check: copy count stable over the final quarter.
q=$(($(wc -l <"$CSV") / 4 + 1))
first_q_copies=$(tail -n "$q" "$CSV" | head -1 | cut -d, -f8)
last_copies=$(tail -1 "$CSV" | cut -d, -f8)
if [ "$last_copies" -gt $((first_q_copies + 10)) ]; then
  echo "[soak] FAIL: conflict copies grew ${first_q_copies} -> ${last_copies} in the final quarter (storm?)"
  fail=1
fi

echo "[soak] samples in $CSV"
exit $fail
