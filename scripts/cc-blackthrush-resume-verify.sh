#!/usr/bin/env bash
# cc/BlackThrush — disk-recovery resume verification for the stdio membrane/lock campaign.
#
# Operationalizes tests/artifacts/perf/cc-blackthrush-disk-recovery-resume-checklist.md:
# one command does the disk gate -> build-verify the 9 unverified byte-identical levers
# -> run every authored head-to-head bench in order. Run ONLY after the DISK-LOW /
# no-cargo directive has lifted.
#
# Usage:  bash scripts/cc-blackthrush-resume-verify.sh
#   (set RCH=0 to run the cargo commands locally instead of via `rch exec`.)
set -uo pipefail

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.rch-targets/frankenlibc-cc}"
export CARGO_TARGET_DIR
RCH="${RCH:-1}"
run() { if [ "$RCH" = "1" ]; then rch exec -- "$@"; else "$@"; fi; }

echo "== Step 0: disk gate =="
df -h /data / || true
echo "If disk is still ~98% used / tight, STOP — do not run cargo (see directive)."
echo

echo "== Step 1: build-verify the 9 byte-identical levers (deployed config) =="
run cargo build -p frankenlibc-abi --release || { echo "BUILD FAILED — a code-only lever does not compile; fix before benching."; exit 1; }
echo "== Step 1b: lib unit tests (cfg(test) path — fast-paths disabled; expect ~202/0) =="
run cargo test -p frankenlibc-abi --lib || echo "WARN: lib tests failed — investigate."
echo

echo "== Step 2: head-to-head benches (record fl-vs-glibc in docs/NEGATIVE_EVIDENCE.md) =="
# snprintf %s in-process A/B links NO fl symbols -> NO abi-bench feature.
run cargo bench -p frankenlibc-bench --bench snprintf_s_strict_ab_bench
# All others need the abi-bench feature (call fl symbols + dlmopen host glibc).
for B in \
  stdio_glibc_baseline_bench \
  fputs_glibc_bench \
  strftime_glibc_bench \
  inet_pton_glibc_bench \
  readdir_glibc_bench \
  sscanf_glibc_bench \
  stdio_mt_contention_bench
do
  echo "--- bench: $B ---"
  run cargo bench -p frankenlibc-bench --features abi-bench --bench "$B"
done
echo

cat <<'NEXT'
== Step 3: after benches, update docs/NEGATIVE_EVIDENCE.md PENDING -> WIN/NEUTRAL/LOSS ==
Then implement the deferred levers (need cargo + conformance), in priority order:
  1. fallback_remaining range-filter (BYTE-IDENTICAL source fix; Miri/loom/conformance)
  2. registry()-lock refactor (bd-hqo6b6/bd-baifnq; the MT contention bench quantifies payoff)
  3. strict-gated c_str_bytes / scanf format+input scans (printf/scanf conformance)
KEEP/REVERT rule: pure lock-skips stay even if single-thread ~0-gain (MT-contention value);
do NOT re-apply the reverted fputs/printf scan_c_str_len->scan_c_string swaps (semantic change).
NEXT
