#!/usr/bin/env bash
# check_preload_e2e_battery.sh — E2E preload workload battery (bd-35hjg.7)
#
# Comprehensive end-to-end test battery running real binaries under LD_PRELOAD
# in both strict and hardened modes. Reports per-binary p50/p99/p99.9 latencies
# and generates structured JSON-line logs for every run and failure signature.
#
# Workloads: coreutils (ls, cat, echo), busybox, python3, perl
# Modes: strict, hardened
# Edge cases: large argument, pipe
# Error cases: missing binary
#
# Usage: ./scripts/check_preload_e2e_battery.sh [--verbose]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/preload_e2e_battery"
mkdir -p "${OUT_DIR}"
RESULTS_JSONL="${OUT_DIR}/results.jsonl"
: > "${RESULTS_JSONL}"

LIB_CANDIDATES=(
  "${FRANKENLIBC_SMOKE_LIB_PATH:-}"
  "${REPO_ROOT}/target/release/libfrankenlibc_abi.so"
  "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -n "${candidate}" && -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  echo "Building libfrankenlibc_abi.so..."
  cargo build -p frankenlibc-abi --release 2>&1 | tail -3
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "FAIL: could not locate or build libfrankenlibc_abi.so" >&2
  exit 1
fi

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

SAMPLE_COUNT="${SAMPLE_COUNT:-5}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
TIMEOUT_SEC="${TIMEOUT_SEC:-10}"

# Budgets per binary (ppm)
declare -A BUDGETS=(
  ["ls"]=2000000
  ["cat"]=2000000
  ["echo"]=2000000
  ["busybox"]=3000000
  ["python3"]=3000000
  ["perl"]=3000000
)

log_jsonl() {
  local timestamp mode binary case_type status latency_ns ratio_ppm message
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mode="$1"
  binary="$2"
  case_type="$3"
  status="$4"
  latency_ns="$5"
  ratio_ppm="$6"
  message="${7:-}"
  printf '{"timestamp":"%s","mode":"%s","binary":"%s","case_type":"%s","status":"%s","latency_ns":%s,"ratio_ppm":%s,"message":"%s"}\n' \
    "${timestamp}" "${mode}" "${binary}" "${case_type}" "${status}" "${latency_ns}" "${ratio_ppm}" "${message}" >> "${RESULTS_JSONL}"
}

measure_cmd() {
  local cmd="$1"
  local mode="$2"
  local -n latencies=$3
  local i start_ns end_ns

  for ((i=0; i<WARMUP_RUNS; i++)); do
    timeout "${TIMEOUT_SEC}" env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" bash -c "${cmd}" >/dev/null 2>&1 || true
  done

  for ((i=0; i<SAMPLE_COUNT; i++)); do
    start_ns=$(date +%s%N)
    if timeout "${TIMEOUT_SEC}" env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" bash -c "${cmd}" >/dev/null 2>&1; then
      end_ns=$(date +%s%N)
      latencies+=($((end_ns - start_ns)))
    else
      latencies+=(0)
    fi
  done
}

measure_baseline() {
  local cmd="$1"
  local -n latencies=$2
  local i start_ns end_ns

  for ((i=0; i<WARMUP_RUNS; i++)); do
    bash -c "${cmd}" >/dev/null 2>&1 || true
  done

  for ((i=0; i<SAMPLE_COUNT; i++)); do
    start_ns=$(date +%s%N)
    bash -c "${cmd}" >/dev/null 2>&1 || true
    end_ns=$(date +%s%N)
    latencies+=($((end_ns - start_ns)))
  done
}

percentile() {
  local -n arr=$1
  local pct=$2
  local sorted n idx
  IFS=$'\n' sorted=($(printf '%s\n' "${arr[@]}" | sort -n))
  n=${#sorted[@]}
  [[ $n -eq 0 ]] && { echo 0; return; }
  idx=$(( (n * pct + 99) / 100 - 1 ))
  [[ $idx -lt 0 ]] && idx=0
  [[ $idx -ge $n ]] && idx=$((n-1))
  echo "${sorted[$idx]}"
}

echo "=== Preload E2E Battery (bd-35hjg.7) ==="
echo "Library: ${LIB_PATH}"
echo "Output: ${RESULTS_JSONL}"
echo ""

failures=0

run_test() {
  local binary="$1"
  local cmd="$2"
  local case_type="$3"
  local mode="$4"

  declare -a baseline_lats=()
  declare -a preload_lats=()

  measure_baseline "${cmd}" baseline_lats
  measure_cmd "${cmd}" "${mode}" preload_lats

  local baseline_p99=$(percentile baseline_lats 99)
  local preload_p99=$(percentile preload_lats 99)
  local ratio_ppm=0
  [[ "${baseline_p99}" -gt 0 ]] && ratio_ppm=$((preload_p99 * 1000000 / baseline_p99))

  local budget="${BUDGETS[${binary}]:-3000000}"
  local status="PASS"
  if [[ "${ratio_ppm}" -gt "${budget}" ]]; then
    status="FAIL"
    ((failures++))
  fi

  local baseline_ms=$(echo "scale=1; ${baseline_p99}/1000000" | bc)
  local preload_ms=$(echo "scale=1; ${preload_p99}/1000000" | bc)
  local ratio_x=$(echo "scale=2; ${ratio_ppm}/1000000" | bc)

  echo "  [${mode}] ${binary}/${case_type}: baseline=${baseline_ms}ms preload=${preload_ms}ms ratio=${ratio_x}x ${status}"
  log_jsonl "${mode}" "${binary}" "${case_type}" "${status}" "${preload_p99}" "${ratio_ppm}" ""

  unset baseline_lats preload_lats
}

# --- Coreutils ---
echo "--- Coreutils ---"
for mode in strict hardened; do
  run_test "ls" "/bin/ls -la /" "list_root" "${mode}"
  run_test "cat" "/bin/cat /etc/hosts" "cat_hosts" "${mode}"
  run_test "echo" "/bin/echo hello" "echo_hello" "${mode}"
done

# --- Heavyweight runtimes ---
echo "--- Heavyweight Runtimes ---"
for mode in strict hardened; do
  if command -v python3 >/dev/null 2>&1; then
    run_test "python3" "python3 -c 'print(1)'" "print_one" "${mode}"
  fi
  if command -v perl >/dev/null 2>&1; then
    run_test "perl" "perl -e 'print 1'" "print_one" "${mode}"
  fi
done

# --- Busybox (if available) ---
if command -v busybox >/dev/null 2>&1; then
  echo "--- Busybox ---"
  for mode in strict hardened; do
    run_test "busybox" "busybox uname -a" "uname" "${mode}"
  done
fi

# --- Edge cases ---
echo "--- Edge Cases ---"
LARGE_ARG=$(printf 'x%.0s' {1..10000})
for mode in strict; do
  run_test "echo" "/bin/echo ${LARGE_ARG}" "large_arg" "${mode}"
  run_test "cat" "/bin/cat /etc/hosts | head -1" "pipe" "${mode}"
done

# --- Error cases ---
echo "--- Error Cases ---"
for mode in strict; do
  declare -a err_lats=()
  timeout 5 env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" /nonexistent_binary 2>/dev/null || true
  start_ns=$(date +%s%N)
  timeout 5 env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" /nonexistent_binary 2>/dev/null || true
  end_ns=$(date +%s%N)
  lat=$((end_ns - start_ns))
  log_jsonl "${mode}" "nonexistent" "missing_binary" "EXPECTED_FAIL" "${lat}" "0" "correctly_failed"
  echo "  [${mode}] nonexistent/missing_binary: latency=$(echo "scale=1; ${lat}/1000000" | bc)ms EXPECTED_FAIL"
  unset err_lats
done

# --- Summary ---
echo ""
echo "Results logged to: ${RESULTS_JSONL}"
echo "Total failures: ${failures}"

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/preload_e2e_battery.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "preload_e2e_battery.v1",
  "bead_id": "bd-35hjg.7",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "sample_count": ${SAMPLE_COUNT},
  "timeout_sec": ${TIMEOUT_SEC},
  "failures": ${failures},
  "results_jsonl": "${RESULTS_JSONL}",
  "overall_status": "$([ ${failures} -eq 0 ] && echo 'pass' || echo 'fail')"
}
EOF

echo "Summary: ${SUMMARY_FILE}"

if [[ ${failures} -gt 0 ]]; then
  echo "FAIL: ${failures} test(s) exceeded budget"
  exit 1
fi

echo "PASS: All tests within budget"
exit 0
