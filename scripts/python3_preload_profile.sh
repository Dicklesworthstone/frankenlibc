#!/usr/bin/env bash
# python3_preload_profile.sh - [bd-35hjg.1] Python3 preload profiling harness
#
# Captures perf/strace profiles of python3 under LD_PRELOAD in:
#   - baseline (no LD_PRELOAD)
#   - strict mode (FRANKENLIBC_MODE=strict)
#   - hardened mode (FRANKENLIBC_MODE=hardened)
#
# Handles timeout/abort scenarios common when preload causes hangs.
# Outputs deterministic top-N hot-symbol lists for regression detection.
# Artifact: target/perf/python3_preload_profile/<trace-id>/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/perf/python3_preload_profile"
TRACE_ID_RAW="${FRANKENLIBC_PYTHON3_PRELOAD_PROFILE_TRACE_ID:-bd-35hjg.1-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
TRACE_ID="${TRACE_ID_RAW//[^A-Za-z0-9_.-]/_}"
OUT_DIR="${OUT_ROOT}/${TRACE_ID}"
TOP_N="${TOP_N:-20}"
PERF_FREQ="${PERF_FREQ:-997}"
TIMEOUT_SEC="${TIMEOUT_SEC:-5}"
WORKLOAD_SCRIPT='print("done")'

# Human-readable workload description. Summary generation below JSON-encodes
# every string field before embedding it in the heredoc.
WORKLOAD_DESC="python3 -c '${WORKLOAD_SCRIPT}'"

LIB_CANDIDATES=(
  "${FRANKENLIBC_LIB:-}"
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "${CARGO_TARGET_DIR:-/data/tmp/cargo-target}/release/libfrankenlibc_abi.so"
)

find_lib() {
  for c in "${LIB_CANDIDATES[@]}"; do
    [[ -n "$c" && -f "$c" ]] && { echo "$c"; return 0; }
  done
  return 1
}

die() { echo "ERROR: $*" >&2; exit 1; }

require_positive_integer() {
  local name="$1" value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ || "${value}" =~ ^0+$ ]]; then
    die "${name} must be a positive integer, got '${value}'"
  fi
}

json_string() {
  python3 - "$1" <<'PY'
import json
import sys

print(json.dumps(sys.argv[1]))
PY
}

require_positive_integer "TOP_N" "${TOP_N}"
require_positive_integer "PERF_FREQ" "${PERF_FREQ}"
require_positive_integer "TIMEOUT_SEC" "${TIMEOUT_SEC}"

command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v perf >/dev/null 2>&1 || die "perf not found"

LIB_PATH="$(find_lib)" || die "libfrankenlibc_abi.so not found; build with: RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- cargo build -p frankenlibc-abi --release"

mkdir -p "${OUT_DIR}"
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

declare -A PROFILE_RESULTS

capture_profile() {
  local label="$1"
  local ld_preload="${2:-}"
  local mode_env="${3:-}"
  local perf_data="${OUT_DIR}/${label}.perf.data"
  local symbols_txt="${OUT_DIR}/${label}.symbols.txt"
  local strace_txt="${OUT_DIR}/${label}.strace.txt"
  local timing_txt="${OUT_DIR}/${label}.timing.txt"

  log "Profiling: ${label}"

  local env_cmd=()
  [[ -n "${ld_preload}" ]] && env_cmd+=(LD_PRELOAD="${ld_preload}")
  [[ -n "${mode_env}" ]] && env_cmd+=(FRANKENLIBC_MODE="${mode_env}")

  local start_ns end_ns elapsed_ms exit_code=0 signal_name=""

  start_ns=$(date +%s%N)

  if [[ -z "${ld_preload}" ]]; then
    if timeout "${TIMEOUT_SEC}" perf record -F "${PERF_FREQ}" -g -o "${perf_data}" -- python3 -c "${WORKLOAD_SCRIPT}" >/dev/null 2>&1; then
      exit_code=0
    else
      exit_code=$?
    fi
  else
    if timeout "${TIMEOUT_SEC}" perf record -F "${PERF_FREQ}" -g -o "${perf_data}" -- env "${env_cmd[@]}" python3 -c "${WORKLOAD_SCRIPT}" >/dev/null 2>&1; then
      exit_code=0
    else
      exit_code=$?
    fi
  fi

  end_ns=$(date +%s%N)
  elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  case $exit_code in
    0)   signal_name="success" ;;
    124) signal_name="timeout" ;;
    134) signal_name="SIGABRT" ;;
    139) signal_name="SIGSEGV" ;;
    *)   signal_name="exit_${exit_code}" ;;
  esac

  echo "elapsed_ms=${elapsed_ms}" > "${timing_txt}"
  echo "exit_code=${exit_code}" >> "${timing_txt}"
  echo "signal=${signal_name}" >> "${timing_txt}"

  log "  Exit: ${signal_name} (${exit_code}) in ${elapsed_ms}ms"

  if [[ -f "${perf_data}" ]] && [[ -s "${perf_data}" ]]; then
    perf report -i "${perf_data}" --stdio --no-children -n --percent-limit 0.01 2>/dev/null \
      | grep -E '^\s+[0-9]+\.[0-9]+%' \
      | head -n "${TOP_N}" \
      | awk '{pct=$1; $1=""; sym=$0; gsub(/^[[:space:]]+/, "", sym); print pct, sym}' \
      > "${symbols_txt}" || true
    local sym_count
    sym_count="$(wc -l < "${symbols_txt}")"
    log "  Captured ${sym_count} symbols via perf"
  else
    echo "# No perf data (${signal_name})" > "${symbols_txt}"
  fi

  if [[ -n "${ld_preload}" ]] && [[ "${exit_code}" -ne 0 ]]; then
    log "  Running strace for syscall breakdown..."
    timeout "${TIMEOUT_SEC}" strace -c -o "${strace_txt}" \
      env "${env_cmd[@]}" python3 -c "${WORKLOAD_SCRIPT}" 2>/dev/null || true
    if [[ -s "${strace_txt}" ]]; then
      local top_syscall
      top_syscall="$(tail -n +3 "${strace_txt}" | head -5 | awk '{print $NF, $1"%"}' | head -1)"
      log "  Top syscall: ${top_syscall}"
    fi
  fi

  PROFILE_RESULTS["${label}_elapsed_ms"]="${elapsed_ms}"
  PROFILE_RESULTS["${label}_exit_code"]="${exit_code}"
  PROFILE_RESULTS["${label}_signal"]="${signal_name}"
}

log "Python3 preload profiling harness"
log "Library: ${LIB_PATH}"
log "Output: ${OUT_DIR}"
log "Timeout: ${TIMEOUT_SEC}s"

capture_profile "baseline" "" ""
capture_profile "strict" "${LIB_PATH}" "strict"
capture_profile "hardened" "${LIB_PATH}" "hardened"

baseline_ms="${PROFILE_RESULTS[baseline_elapsed_ms]}"
strict_ms="${PROFILE_RESULTS[strict_elapsed_ms]}"
hardened_ms="${PROFILE_RESULTS[hardened_elapsed_ms]}"

strict_ratio="N/A"
hardened_ratio="N/A"
if [[ "${baseline_ms}" -gt 0 ]]; then
  strict_ratio="$(echo "scale=1; ${strict_ms} / ${baseline_ms}" | bc 2>/dev/null || echo "N/A")"
  hardened_ratio="$(echo "scale=1; ${hardened_ms} / ${baseline_ms}" | bc 2>/dev/null || echo "N/A")"
fi

extract_ranking() {
  local txt="$1"
  if [[ -f "$txt" ]] && [[ -s "$txt" ]]; then
    awk '{print NR": "$0}' "$txt" | head -n "${TOP_N}"
  else
    echo "# No data"
  fi
}

extract_strace_top() {
  local txt="$1"
  if [[ -f "$txt" ]] && [[ -s "$txt" ]]; then
    tail -n +3 "$txt" | head -10
  else
    echo "# No strace data"
  fi
}

SUMMARY_JSON="${OUT_DIR}/profile_summary.json"
TRACE_ID_JSON="$(json_string "${TRACE_ID}")"
RUN_TS_JSON="$(json_string "${RUN_TS}")"
GIT_COMMIT_JSON="$(json_string "${GIT_COMMIT}")"
LIB_PATH_JSON="$(json_string "${LIB_PATH}")"
WORKLOAD_JSON="$(json_string "${WORKLOAD_DESC}")"
BASELINE_SIGNAL_JSON="$(json_string "${PROFILE_RESULTS[baseline_signal]}")"
STRICT_SIGNAL_JSON="$(json_string "${PROFILE_RESULTS[strict_signal]}")"
HARDENED_SIGNAL_JSON="$(json_string "${PROFILE_RESULTS[hardened_signal]}")"
STRICT_RATIO_JSON="$(json_string "${strict_ratio}")"
HARDENED_RATIO_JSON="$(json_string "${hardened_ratio}")"
cat > "${SUMMARY_JSON}" <<EOF
{
  "meta": {
    "trace_id": ${TRACE_ID_JSON},
    "generated_at": ${RUN_TS_JSON},
    "git_commit": ${GIT_COMMIT_JSON},
    "library_path": ${LIB_PATH_JSON},
    "workload": ${WORKLOAD_JSON},
    "timeout_sec": ${TIMEOUT_SEC},
    "perf_freq": ${PERF_FREQ},
    "top_n": ${TOP_N}
  },
  "profiles": {
    "baseline": {
      "elapsed_ms": ${PROFILE_RESULTS[baseline_elapsed_ms]},
      "exit_code": ${PROFILE_RESULTS[baseline_exit_code]},
      "signal": ${BASELINE_SIGNAL_JSON},
      "symbols_file": "baseline.symbols.txt"
    },
    "strict": {
      "elapsed_ms": ${PROFILE_RESULTS[strict_elapsed_ms]},
      "exit_code": ${PROFILE_RESULTS[strict_exit_code]},
      "signal": ${STRICT_SIGNAL_JSON},
      "slowdown_ratio": ${STRICT_RATIO_JSON},
      "symbols_file": "strict.symbols.txt",
      "strace_file": "strict.strace.txt"
    },
    "hardened": {
      "elapsed_ms": ${PROFILE_RESULTS[hardened_elapsed_ms]},
      "exit_code": ${PROFILE_RESULTS[hardened_exit_code]},
      "signal": ${HARDENED_SIGNAL_JSON},
      "slowdown_ratio": ${HARDENED_RATIO_JSON},
      "symbols_file": "hardened.symbols.txt",
      "strace_file": "hardened.strace.txt"
    }
  },
  "regression_detection": {
    "baseline_ms": ${baseline_ms},
    "strict_ms": ${strict_ms},
    "hardened_ms": ${hardened_ms},
    "strict_slowdown": ${STRICT_RATIO_JSON},
    "hardened_slowdown": ${HARDENED_RATIO_JSON}
  }
}
EOF

log "Summary written to: ${SUMMARY_JSON}"

echo ""
echo "=== Performance Summary ==="
echo "Baseline:  ${baseline_ms}ms (${PROFILE_RESULTS[baseline_signal]})"
echo "Strict:    ${strict_ms}ms (${PROFILE_RESULTS[strict_signal]}) - ${strict_ratio}x baseline"
echo "Hardened:  ${hardened_ms}ms (${PROFILE_RESULTS[hardened_signal]}) - ${hardened_ratio}x baseline"
echo ""
echo "=== Top ${TOP_N} Hot Symbols ==="
echo ""
echo "--- Baseline (no preload) ---"
extract_ranking "${OUT_DIR}/baseline.symbols.txt"
echo ""
echo "--- Strict Mode ---"
extract_ranking "${OUT_DIR}/strict.symbols.txt"
if [[ -f "${OUT_DIR}/strict.strace.txt" ]]; then
  echo ""
  echo "--- Strict Mode Syscall Breakdown ---"
  extract_strace_top "${OUT_DIR}/strict.strace.txt"
fi
echo ""
echo "--- Hardened Mode ---"
extract_ranking "${OUT_DIR}/hardened.symbols.txt"
if [[ -f "${OUT_DIR}/hardened.strace.txt" ]]; then
  echo ""
  echo "--- Hardened Mode Syscall Breakdown ---"
  extract_strace_top "${OUT_DIR}/hardened.strace.txt"
fi
echo ""

log "Done. Artifacts in: ${OUT_DIR}"
log "Key finding: Preload modes show ${strict_ratio}x/${hardened_ratio}x slowdown vs baseline"
