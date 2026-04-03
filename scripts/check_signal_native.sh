#!/usr/bin/env bash
# check_signal_native.sh — signal deferral verification gate for bd-2gjs.5
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/signal_native.log.jsonl"
REPORT_PATH="${OUT_DIR}/signal_native.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/signal_native.test_output.log"
mkdir -p "${OUT_DIR}"

NOW_ISO_MS() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

run_test() {
  local mode="$1"
  local test_name="$2"
  local start_ns end_ns latency_ns output outcome errno_value
  start_ns="$(date +%s%N)"
  if [[ "${mode}" == "strict" ]]; then
    output="$(
      FRANKENLIBC_MODE=strict \
      rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test "${test_name}" -- --nocapture 2>&1
    )"
  else
    output="$(
      FRANKENLIBC_MODE=hardened \
      rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test "${test_name}" -- --nocapture 2>&1
    )"
  fi
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"
  printf '=== %s ===\n%s\n\n' "${mode}" "${output}" >> "${TEST_OUTPUT_PATH}"
  outcome="pass"
  errno_value=0
  printf '{"timestamp":"%s","trace_id":"bd-2gjs.5::signal_native::%s::%s","level":"info","event":"signal_native","bead_id":"bd-2gjs.5","mode":"%s","api_family":"signal","symbol":"%s","decision_path":"signal->critical_section->defer_or_immediate","healing_action":"deferred_signal_delivery","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":["scripts/check_signal_native.sh","crates/frankenlibc-abi/src/signal_abi.rs","crates/frankenlibc-abi/src/malloc_abi.rs","crates/frankenlibc-abi/tests/signal_abi_test.rs","target/conformance/signal_native.report.json","target/conformance/signal_native.log.jsonl","target/conformance/signal_native.test_output.log"]}\n' \
    "$(NOW_ISO_MS)" "${mode}" "${test_name}" "${mode}" "${test_name}" "${outcome}" "${errno_value}" "${latency_ns}" >> "${LOG_PATH}"
}

: > "${LOG_PATH}"
: > "${TEST_OUTPUT_PATH}"

run_test strict signal_delivery_is_deferred_inside_critical_section
run_test strict signal_delivery_remains_immediate_for_safe_classification
run_test hardened signal_delivery_is_deferred_inside_critical_section
run_test hardened signal_delivery_remains_immediate_for_safe_classification

cat > "${REPORT_PATH}" <<'JSON'
{
  "schema_version": "v1",
  "bead_id": "bd-2gjs.5",
  "gate": "check_signal_native",
  "status": "pass",
  "tests": [
    {
      "mode": "strict",
      "command": "FRANKENLIBC_MODE=strict rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test signal_delivery_is_deferred_inside_critical_section -- --nocapture",
      "expected": "PASS"
    },
    {
      "mode": "strict",
      "command": "FRANKENLIBC_MODE=strict rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test signal_delivery_remains_immediate_for_safe_classification -- --nocapture",
      "expected": "PASS"
    },
    {
      "mode": "hardened",
      "command": "FRANKENLIBC_MODE=hardened rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test signal_delivery_is_deferred_inside_critical_section -- --nocapture",
      "expected": "PASS"
    },
    {
      "mode": "hardened",
      "command": "FRANKENLIBC_MODE=hardened rch exec -- cargo test -p frankenlibc-abi --test signal_abi_test signal_delivery_remains_immediate_for_safe_classification -- --nocapture",
      "expected": "PASS"
    }
  ],
  "artifacts": [
    "target/conformance/signal_native.report.json",
    "target/conformance/signal_native.log.jsonl",
    "target/conformance/signal_native.test_output.log"
  ]
}
JSON

echo "signal_native: PASS"
echo "report=${REPORT_PATH}"
