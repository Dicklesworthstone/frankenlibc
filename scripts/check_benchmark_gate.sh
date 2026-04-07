#!/usr/bin/env bash
# check_benchmark_gate.sh — run the Criterion regression gate through rch.
#
# Behavior:
# - validates that the baseline/spec inputs are structurally sound,
# - runs the benchmark regression gate on an rch worker,
# - fails if any benchmark regresses more than 20% from baseline unless the
#   caller overrides FRANKENLIBC_PERF_MAX_REGRESSION_PCT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PERF_BASELINE_CHECK="${ROOT}/scripts/check_perf_baseline.sh"
PERF_GATE_SCRIPT="${ROOT}/scripts/perf_gate.sh"
SYMBOL_LATENCY_BASELINE_CHECK="${ROOT}/scripts/check_symbol_latency_baseline.sh"

MAX_REGRESSION_PCT="${FRANKENLIBC_PERF_MAX_REGRESSION_PCT:-20}"
ALLOW_TARGET_VIOLATION="${FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION:-1}"
SKIP_OVERLOADED="${FRANKENLIBC_PERF_SKIP_OVERLOADED:-1}"
ENABLE_KERNEL_SUITE="${FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE:-0}"
SYMBOL_LATENCY_REPORT="${FRANKENLIBC_SYMBOL_LATENCY_REPORT:-target/conformance/symbol_latency_perf_gate.current.v1.json}"
SYMBOL_LATENCY_EVENT_LOG="${FRANKENLIBC_SYMBOL_LATENCY_EVENT_LOG:-target/conformance/symbol_latency_perf_gate.log.jsonl}"

if ! command -v rch >/dev/null 2>&1; then
    echo "check_benchmark_gate: rch is required" >&2
    exit 2
fi

if [[ ! -x "${PERF_BASELINE_CHECK}" ]]; then
    echo "check_benchmark_gate: baseline validation script is missing or not executable: ${PERF_BASELINE_CHECK}" >&2
    exit 2
fi

if [[ ! -x "${PERF_GATE_SCRIPT}" ]]; then
    echo "check_benchmark_gate: perf gate script is missing or not executable: ${PERF_GATE_SCRIPT}" >&2
    exit 2
fi

if [[ ! -x "${SYMBOL_LATENCY_BASELINE_CHECK}" ]]; then
    echo "check_benchmark_gate: symbol latency baseline script is missing or not executable: ${SYMBOL_LATENCY_BASELINE_CHECK}" >&2
    exit 2
fi

cd "${ROOT}"

echo "=== check_benchmark_gate ==="
echo "root=${ROOT}"
echo "max_regression_pct=${MAX_REGRESSION_PCT}"
echo "allow_target_violation=${ALLOW_TARGET_VIOLATION}"
echo "skip_overloaded=${SKIP_OVERLOADED}"
echo "enable_kernel_suite=${ENABLE_KERNEL_SUITE}"
echo "symbol_latency_report=${SYMBOL_LATENCY_REPORT}"
echo "symbol_latency_event_log=${SYMBOL_LATENCY_EVENT_LOG}"
echo ""

echo "--- validating perf baseline contract ---"
bash "${PERF_BASELINE_CHECK}"
echo ""

echo "--- validating symbol latency artifact + policy-aware perf budget report ---"
FRANKENLIBC_SYMBOL_LATENCY_REPORT="${SYMBOL_LATENCY_REPORT}" \
FRANKENLIBC_SYMBOL_LATENCY_EVENT_LOG="${SYMBOL_LATENCY_EVENT_LOG}" \
bash "${SYMBOL_LATENCY_BASELINE_CHECK}"
echo ""

echo "--- running criterion regression gate via rch ---"
rch exec -- env \
    FRANKENLIBC_PERF_MAX_REGRESSION_PCT="${MAX_REGRESSION_PCT}" \
    FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION="${ALLOW_TARGET_VIOLATION}" \
    FRANKENLIBC_PERF_SKIP_OVERLOADED="${SKIP_OVERLOADED}" \
    FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE="${ENABLE_KERNEL_SUITE}" \
    bash scripts/perf_gate.sh

echo ""
echo "check_benchmark_gate: PASS"
