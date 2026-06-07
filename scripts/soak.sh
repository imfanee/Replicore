#!/usr/bin/env bash
# soak.sh — synthetic IVR-traffic soak on the wan-testbed rig (M3 exit
# criterion 6 / RSD §II.8). Root required (the rig is netns-based).
#
#   sudo DURATION=604800 scripts/soak.sh        # the one-week soak
#   sudo DURATION=900 scripts/soak.sh           # 15-minute smoke
#
# The soak DECIDES, it does not merely log: it ends with one verdict line
# (also written to $STATE/soak-verdict.txt) —
#   SOAK PASS duration=… rss_a/b/c=…KiB max_lag_spread=… copies=… checkpoints=N/N
#   SOAK FAIL cause=<condition> ts=<unix>
#
# Traffic model (per cycle, default every 5s):
#   - one new "recording" (200–800 KB, write-once) on a random node
#   - every 6th cycle: a "prompt" update (small file, overwritten in place,
#     sometimes on TWO nodes inside one cycle → genuine concurrent writes)
#   - every 10th cycle: delete an old recording
#   - every KILL_EVERY seconds: kill -9 a random daemon, restart it 5s later
#
# Stop-conditions (checked on the hourly tick; any trips an early FAIL):
#   - RSS leak: a node's hourly RSS strictly increasing for 12 CONSECUTIVE
#     hourly samples (a plateau or dip resets the streak — steady-state
#     noise and transient spikes never trip this; only monotone growth does)
#   - unbounded lag: max |oplog_rows(X) − oplog_rows(Y)| across node pairs
#     strictly increasing for 12 consecutive hourly samples (converged nodes
#     equalize row counts — every node stores every op; the count itself
#     grows forever BY DESIGN, append-only log, so only the SPREAD signals)
#   - convergence: an hourly CHECKPOINT pauses traffic and requires
#     byte-identical trees within 5 minutes; 3 consecutive failed
#     checkpoints ⇒ FAIL (one may straddle a large in-flight transfer)
#   - copy bloat: conflict copies > 50% of live files after the first hour,
#     or +50 copies within one hour (the copy-storm signal). Tombstone ROW
#     counts are not externally observable and tombstone GC is an unshipped
#     SEAM — copy bloat and the convergence checkpoint are the observable
#     halves of the GC-misbehavior signal.
#   - process exit: any daemon gone outside the kill-injector's own window
#
# Per-minute CSV: $STATE/soak.csv
# Hourly CSV:     $STATE/soak-hourly.csv

set -euo pipefail

DURATION="${DURATION:-900}"
CYCLE_SECS="${CYCLE_SECS:-5}"
KILL_EVERY="${KILL_EVERY:-600}"
CHECKPOINT_EVERY="${CHECKPOINT_EVERY:-3600}"
CHECKPOINT_WAIT="${CHECKPOINT_WAIT:-300}"
MONO_WINDOW="${MONO_WINDOW:-12}"   # consecutive hourly samples for leak/lag
ETC=/srv/replicore/etc
STATE=/srv/replicore/state
NODES=(a b c)
declare -A DIR=([a]=/srv/replicore/a [b]=/srv/replicore/b [c]=/srv/replicore/c)
declare -A IP=([a]=10.123.0.1 [b]=10.123.0.2 [c]=10.123.0.3)
BIN="$(dirname "$0")/../target/release/replicored"
TESTBED="$(dirname "$0")/wan-testbed.sh"
CSV="$STATE/soak.csv"
HCSV="$STATE/soak-hourly.csv"
VERDICT="$STATE/soak-verdict.txt"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

# Cross-process rig lock (shared with the integration rig tests): the soak
# and integration_wan share ONE host rig and the /srv/replicore tree. Held
# for the whole run; if a rig test (or another soak) holds it, refuse LOUD
# instead of scribbling each other's share dirs (the root cause of the
# flaky integration_wan findings).
mkdir -p /srv/replicore
exec {RIG_LOCK_FD}>/srv/replicore/.rig.lock
if ! flock -n "$RIG_LOCK_FD"; then
  echo "rig is BUSY: another replicore rig process holds /srv/replicore/.rig.lock; refusing to start"
  exit 1
fi

declare -A PID
start_node() {
  ip netns exec "rc-$1" "$BIN" run --config "$ETC/node-$1.toml" \
    >>"$STATE/soak-node-$1.log" 2>&1 &
  PID[$1]=$!
}

FINISHED=0
cleanup() {
  local code=$?
  # A soak that dies must still leave a verdict: set -e aborts on any
  # unguarded failure, and a week-long run ending in silence is
  # indistinguishable from "still going" (learned the hard way: a teardown
  # race killed a run with no verdict).
  if [ "$FINISHED" = 0 ] && [ ! -s "$VERDICT" ] 2>/dev/null; then
    echo "SOAK FAIL cause=script-aborted-exit-$code ts=$(date +%s)" | tee "$VERDICT" 2>/dev/null || true
  fi
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
live_count() { find "${DIR[a]}" -type f ! -name '*.replicore-tmp*' 2>/dev/null | wc -l; }
lag_spread() {
  local ra rb rc lo hi
  ra=$(healthz_u64 a oplog_rows); rb=$(healthz_u64 b oplog_rows); rc=$(healthz_u64 c oplog_rows)
  lo=$ra; hi=$ra
  for v in "$rb" "$rc"; do
    [ "$v" -lt "$lo" ] && lo=$v
    [ "$v" -gt "$hi" ] && hi=$v
  done
  echo $((hi - lo))
}

fail_soak() { # cause
  FINISHED=1
  local line="SOAK FAIL cause=$1 ts=$(date +%s)"
  echo "$line" | tee "$VERDICT"
  exit 1
}

# ---------------------------------------------------------------------------
echo "[soak] rig up (LAN profile; use the WAN tests for shaped runs)"
"$TESTBED" down >/dev/null 2>&1 || true
rm -rf "$STATE" "${DIR[a]}" "${DIR[b]}" "${DIR[c]}"
"$TESTBED" up >/dev/null
"$TESTBED" certs >/dev/null
for n in "${NODES[@]}"; do start_node "$n"; done
sleep 5

echo "ts,rss_a,rss_b,rss_c,oplog_a,conflicts_a,guard_trips_a,copies,converged" >"$CSV"
echo "ts,rss_a,rss_b,rss_c,lag_spread,copies,live,checkpoint_converged" >"$HCSV"
echo "[soak] ${DURATION}s, cycle ${CYCLE_SECS}s, kill every ${KILL_EVERY}s, checkpoint every ${CHECKPOINT_EVERY}s"

START=$(date +%s)
i=0
next_sample=$START
next_kill=$((START + KILL_EVERY))
next_checkpoint=$((START + CHECKPOINT_EVERY))
RECORDINGS=()
# Stop-condition state.
declare -A RSS_PREV=([a]=0 [b]=0 [c]=0)
declare -A RSS_STREAK=([a]=0 [b]=0 [c]=0)
LAG_PREV=0
LAG_STREAK=0
CKPT_FAILS=0
CKPT_TOTAL=0
CKPT_OK=0
PREV_HOUR_COPIES=0
restarting_until=0

while :; do
  now=$(date +%s)
  [ $((now - START)) -ge "$DURATION" ] && break
  i=$((i + 1))

  # --- liveness: every daemon must be running, except during a planned
  # --- restart window (the kill-injector below sets it).
  if [ "$now" -gt "$restarting_until" ]; then
    for n in "${NODES[@]}"; do
      kill -0 "${PID[$n]}" 2>/dev/null || fail_soak "node-$n-exited-unexpectedly"
    done
  fi

  # --- traffic (only while the target daemon is alive — never scribble a
  # --- dir whose rig has gone out from under us) ---
  n=${NODES[$((RANDOM % 3))]}
  if kill -0 "${PID[$n]:-0}" 2>/dev/null; then
    rec="recordings/$(date +%s)-$i.wav"
    mkdir -p "${DIR[$n]}/recordings" 2>/dev/null || true
    if head -c $(((RANDOM % 600 + 200) * 1024)) /dev/urandom >"${DIR[$n]}/$rec" 2>/dev/null; then
      RECORDINGS+=("$rec")
    else
      echo "[soak] WARN: write failed for ${DIR[$n]}/$rec (transient?)"
    fi
  fi

  if [ $((i % 6)) -eq 0 ]; then
    mkdir -p "${DIR[$n]}/prompts"
    echo "prompt v$i from $n at $(date)" >"${DIR[$n]}/prompts/menu.txt"
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
    restarting_until=$((now + 30))
    kill -9 "${PID[$k]}" 2>/dev/null || true
    sleep 5
    start_node "$k"
    next_kill=$((now + KILL_EVERY))
  fi

  # --- per-minute sampling ---
  if [ "$now" -ge "$next_sample" ]; then
    c=0
    converged && c=1
    echo "$now,$(rss_kib a),$(rss_kib b),$(rss_kib c),$(healthz_u64 a oplog_rows),$(metric a replicore_conflicts_total),$(metric a replicore_freespace_guard_trips_total),$(copy_count),$c" >>"$CSV"
    next_sample=$((now + 60))
  fi

  # --- hourly checkpoint: quiesce, require convergence, evaluate trends ---
  if [ "$now" -ge "$next_checkpoint" ]; then
    CKPT_TOTAL=$((CKPT_TOTAL + 1))
    echo "[soak] checkpoint $CKPT_TOTAL: quiescing writes, waiting for convergence (≤${CHECKPOINT_WAIT}s)…"
    ck=0
    deadline=$((now + CHECKPOINT_WAIT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if converged; then ck=1; break; fi
      sleep 10
    done
    if [ "$ck" -eq 1 ]; then
      CKPT_OK=$((CKPT_OK + 1)); CKPT_FAILS=0
      echo "[soak] checkpoint $CKPT_TOTAL: CONVERGED"
    else
      CKPT_FAILS=$((CKPT_FAILS + 1))
      echo "[soak] checkpoint $CKPT_TOTAL: NOT converged (consecutive fails: $CKPT_FAILS)"
      [ "$CKPT_FAILS" -ge 3 ] && fail_soak "no-reconvergence-3-checkpoints"
    fi

    # Hourly record + monotone-growth streaks.
    spread=$(lag_spread); copies=$(copy_count); live=$(live_count)
    echo "$(date +%s),$(rss_kib a),$(rss_kib b),$(rss_kib c),$spread,$copies,$live,$ck" >>"$HCSV"
    for nn in "${NODES[@]}"; do
      cur=$(rss_kib "$nn")
      if [ "$cur" -gt "${RSS_PREV[$nn]}" ] && [ "${RSS_PREV[$nn]}" -gt 0 ]; then
        RSS_STREAK[$nn]=$(( ${RSS_STREAK[$nn]} + 1 ))
      else
        RSS_STREAK[$nn]=0
      fi
      RSS_PREV[$nn]=$cur
      [ "${RSS_STREAK[$nn]}" -ge "$MONO_WINDOW" ] && fail_soak "rss-monotonic-growth-node-$nn-${MONO_WINDOW}h"
    done
    if [ "$spread" -gt "$LAG_PREV" ] && [ "$LAG_PREV" -gt 0 ]; then
      LAG_STREAK=$((LAG_STREAK + 1))
    else
      LAG_STREAK=0
    fi
    LAG_PREV=$spread
    [ "$LAG_STREAK" -ge "$MONO_WINDOW" ] && fail_soak "lag-spread-monotonic-growth-${MONO_WINDOW}h"
    # Copy bloat: ratio after the first hour, or a storm within one hour.
    if [ "$CKPT_TOTAL" -ge 1 ] && [ "$live" -gt 0 ] && [ $((copies * 2)) -gt "$live" ]; then
      fail_soak "copy-bloat-ratio-${copies}-of-${live}"
    fi
    if [ $((copies - PREV_HOUR_COPIES)) -gt 50 ]; then
      fail_soak "copy-storm-+$((copies - PREV_HOUR_COPIES))-in-one-hour"
    fi
    PREV_HOUR_COPIES=$copies
    next_checkpoint=$(( $(date +%s) + CHECKPOINT_EVERY ))
  fi

  sleep "$CYCLE_SECS"
done

echo "[soak] traffic done; settling 90s for final convergence…"
sleep 90

# --- final verdict -----------------------------------------------------------
converged || fail_soak "final-trees-diverged"

# Final leak sanity (in addition to the streak rule): end RSS < 2× early median.
for nn in "${NODES[@]}"; do
  col=$(case $nn in a) echo 2;; b) echo 3;; c) echo 4;; esac)
  early=$(tail -n +2 "$CSV" | head -10 | cut -d, -f"$col" | sort -n | awk '{a[NR]=$1} END{print a[int(NR/2)+1]}')
  final=$(tail -1 "$CSV" | cut -d, -f"$col")
  if [ -n "$early" ] && [ "$early" -gt 0 ] && [ "$final" -gt $((early * 2)) ]; then
    fail_soak "rss-grew-${early}-to-${final}KiB-node-$nn"
  fi
done

line="SOAK PASS duration=$(( $(date +%s) - START ))s rss_a=$(rss_kib a)KiB rss_b=$(rss_kib b)KiB rss_c=$(rss_kib c)KiB max_lag_spread=$(lag_spread) copies=$(copy_count) live=$(live_count) checkpoints=${CKPT_OK}/${CKPT_TOTAL}"
echo "$line" | tee "$VERDICT"
echo "[soak] per-minute: $CSV  hourly: $HCSV"
exit 0
