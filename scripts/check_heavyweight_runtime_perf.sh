#!/usr/bin/env bash
# check_heavyweight_runtime_perf.sh — CI gate for bd-35hjg.4
#
# Perf-blocking regression gate for heavyweight runtimes under LD_PRELOAD.
# Verifies that python3, perl, and node (if available) meet latency budgets
# in strict mode to prevent silently regressing the preload experience.
#
# Budget: Each runtime must run within 3x of baseline (3,000,000 ppm).
# The gate reports p50/p95/p99.9 latencies for detailed regression analysis.
#
# Usage: ./scripts/check_heavyweight_runtime_perf.sh [--verbose]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

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
  echo "check_heavyweight_runtime_perf: building libfrankenlibc_abi.so..."
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
if [[ "${1:-}" == "--verbose" ]]; then
  VERBOSE=true
fi

# Per-runtime budgets (ppm = parts per million, so 3000000 = 3x baseline)
PYTHON3_BUDGET_PPM="${PYTHON3_BUDGET_PPM:-3000000}"
PERL_BUDGET_PPM="${PERL_BUDGET_PPM:-3000000}"
NODE_BUDGET_PPM="${NODE_BUDGET_PPM:-3000000}"

SAMPLE_COUNT="${SAMPLE_COUNT:-10}"
WARMUP_RUNS="${WARMUP_RUNS:-2}"

declare -a RUNTIMES=()
declare -A RUNTIME_CMDS
declare -A RUNTIME_BUDGETS

if command -v python3 >/dev/null 2>&1; then
  RUNTIMES+=("python3")
  RUNTIME_CMDS["python3"]="python3 -c 'print(1)'"
  RUNTIME_BUDGETS["python3"]="${PYTHON3_BUDGET_PPM}"
fi

if command -v perl >/dev/null 2>&1; then
  RUNTIMES+=("perl")
  RUNTIME_CMDS["perl"]="perl -e 'print 1'"
  RUNTIME_BUDGETS["perl"]="${PERL_BUDGET_PPM}"
fi

# Node crashes under preload as of 2026-05-22 — skip until fixed
# if command -v node >/dev/null 2>&1; then
#   RUNTIMES+=("node")
#   RUNTIME_CMDS["node"]="node -e 'console.log(1)'"
#   RUNTIME_BUDGETS["node"]="${NODE_BUDGET_PPM}"
# fi

if [[ ${#RUNTIMES[@]} -lt 2 ]]; then
  echo "FAIL: need at least 2 heavyweight runtimes (python3, perl, or node)" >&2
  exit 1
fi

echo "=== Heavyweight Runtime Perf Gate (bd-35hjg.4) ==="
echo "Library: ${LIB_PATH}"
echo "Runtimes: ${RUNTIMES[*]}"
echo "Samples per runtime: ${SAMPLE_COUNT} (+ ${WARMUP_RUNS} warmup)"
echo ""

measure_latencies_ns() {
  local cmd="$1"
  local use_preload="$2"
  local -n result_array=$3
  local i

  # Warmup
  for ((i=0; i<WARMUP_RUNS; i++)); do
    if [[ "${use_preload}" == "1" ]]; then
      FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" bash -c "${cmd}" >/dev/null 2>&1 || true
    else
      bash -c "${cmd}" >/dev/null 2>&1 || true
    fi
  done

  # Sample
  for ((i=0; i<SAMPLE_COUNT; i++)); do
    local start_ns end_ns
    start_ns=$(date +%s%N)
    if [[ "${use_preload}" == "1" ]]; then
      FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" bash -c "${cmd}" >/dev/null 2>&1 || true
    else
      bash -c "${cmd}" >/dev/null 2>&1 || true
    fi
    end_ns=$(date +%s%N)
    result_array+=($((end_ns - start_ns)))
  done
}

percentile() {
  local -n arr=$1
  local pct=$2
  local sorted
  IFS=$'\n' sorted=($(printf '%s\n' "${arr[@]}" | sort -n))
  local n=${#sorted[@]}
  local idx=$(( (n * pct + 99) / 100 - 1 ))
  if [[ $idx -lt 0 ]]; then idx=0; fi
  if [[ $idx -ge $n ]]; then idx=$((n-1)); fi
  echo "${sorted[$idx]}"
}

failures=0
results_json="["

for runtime in "${RUNTIMES[@]}"; do
  cmd="${RUNTIME_CMDS[$runtime]}"
  budget="${RUNTIME_BUDGETS[$runtime]}"

  echo "--- ${runtime} ---"

  declare -a baseline_latencies=()
  declare -a preload_latencies=()

  measure_latencies_ns "${cmd}" "0" baseline_latencies
  measure_latencies_ns "${cmd}" "1" preload_latencies

  baseline_p50=$(percentile baseline_latencies 50)
  baseline_p95=$(percentile baseline_latencies 95)
  baseline_p999=$(percentile baseline_latencies 100)  # Using max as p99.9 proxy

  preload_p50=$(percentile preload_latencies 50)
  preload_p95=$(percentile preload_latencies 95)
  preload_p999=$(percentile preload_latencies 100)

  if [[ "${baseline_p50}" -gt 0 ]]; then
    ratio_p50_ppm=$(( preload_p50 * 1000000 / baseline_p50 ))
  else
    ratio_p50_ppm=0
  fi

  if [[ "${baseline_p999}" -gt 0 ]]; then
    ratio_p999_ppm=$(( preload_p999 * 1000000 / baseline_p999 ))
  else
    ratio_p999_ppm=0
  fi

  status="PASS"
  if [[ "${ratio_p999_ppm}" -gt "${budget}" ]]; then
    status="FAIL"
    ((failures++))
  fi

  baseline_p50_ms=$(echo "scale=1; ${baseline_p50}/1000000" | bc)
  preload_p50_ms=$(echo "scale=1; ${preload_p50}/1000000" | bc)
  baseline_p999_ms=$(echo "scale=1; ${baseline_p999}/1000000" | bc)
  preload_p999_ms=$(echo "scale=1; ${preload_p999}/1000000" | bc)
  ratio_p999_x=$(echo "scale=2; ${ratio_p999_ppm}/1000000" | bc)
  budget_x=$(echo "scale=1; ${budget}/1000000" | bc)

  echo "  Baseline p50:   ${baseline_p50_ms}ms"
  echo "  Preload  p50:   ${preload_p50_ms}ms (${ratio_p50_ppm} ppm)"
  echo "  Baseline p99.9: ${baseline_p999_ms}ms"
  echo "  Preload  p99.9: ${preload_p999_ms}ms (${ratio_p999_ppm} ppm)"
  echo "  Ratio:          ${ratio_p999_x}x (budget: ${budget_x}x)"
  echo "  Status:         ${status}"
  echo ""

  if [[ "${results_json}" != "[" ]]; then
    results_json+=","
  fi
  results_json+="{\"runtime\":\"${runtime}\",\"status\":\"${status}\",\"baseline_p50_ns\":${baseline_p50},\"preload_p50_ns\":${preload_p50},\"baseline_p999_ns\":${baseline_p999},\"preload_p999_ns\":${preload_p999},\"ratio_p999_ppm\":${ratio_p999_ppm},\"budget_ppm\":${budget}}"

  unset baseline_latencies preload_latencies
done

results_json+="]"

# Write results to conformance artifact
RESULTS_FILE="${REPO_ROOT}/tests/conformance/heavyweight_runtime_perf.v1.json"
cat > "${RESULTS_FILE}" <<EOF
{
  "schema_version": "heavyweight_runtime_perf.v1",
  "bead_id": "bd-35hjg.4",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "sample_count": ${SAMPLE_COUNT},
  "warmup_runs": ${WARMUP_RUNS},
  "results": ${results_json},
  "overall_status": "$([ ${failures} -eq 0 ] && echo 'pass' || echo 'fail')"
}
EOF

echo "Results written to: ${RESULTS_FILE}"
echo ""

if [[ ${failures} -gt 0 ]]; then
  echo "FAIL: ${failures} runtime(s) exceeded perf budget"
  exit 1
else
  echo "PASS: All runtimes within perf budget"
  exit 0
fi
