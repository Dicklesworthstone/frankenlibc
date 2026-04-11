#!/usr/bin/env bash
# check_setjmp_native.sh — native x86_64 setjmp/sigsetjmp smoke for bd-zh1y.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BIN_DIR="${OUT_DIR}/setjmp_native_bins"
REPORT="${OUT_DIR}/setjmp_native.report.json"
LOG="${OUT_DIR}/setjmp_native.log.jsonl"
TEST_LOG="${OUT_DIR}/setjmp_native.test_output.log"
RUN_ID="setjmp-native-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${BIN_DIR}"

TARGET_DIR="$(
  cargo metadata --format-version 1 --no-deps \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])'
)"
if [[ -z "${TARGET_DIR}" ]]; then
  echo "FAIL: cargo metadata did not return a target_directory" >&2
  exit 1
fi
BUILD_TARGET_DIR="${ROOT}/target"
LIB="${TARGET_DIR}/release/libfrankenlibc_abi.so"
BUILD_LIB="${BUILD_TARGET_DIR}/release/libfrankenlibc_abi.so"

echo "[setjmp-native] building release ABI library via rch" >"${TEST_LOG}"
rch exec -- env CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" cargo build -p frankenlibc-abi --release \
  >>"${TEST_LOG}" 2>&1

if [[ ! -f "${LIB}" && -f "${BUILD_LIB}" ]]; then
  mkdir -p "$(dirname "${LIB}")"
  cp "${BUILD_LIB}" "${LIB}"
fi

if [[ ! -f "${LIB}" ]]; then
  echo "FAIL: expected release library missing at ${LIB}" >&2
  cat "${TEST_LOG}" >&2
  exit 1
fi

cc -std=c11 -O2 "${ROOT}/tests/integration/fixture_setjmp_edges.c" \
  -o "${BIN_DIR}/fixture_setjmp_edges.bin"
cc -std=c11 -O2 "${ROOT}/tests/integration/fixture_setjmp_nested.c" \
  -o "${BIN_DIR}/fixture_setjmp_nested.bin"

now_iso_ms() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log_row() {
  local scenario_id="$1"
  local mode="$2"
  local outcome="$3"
  local latency_ns="$4"
  local artifact_refs="$5"
  cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-zh1y.2.1::${RUN_ID}::${scenario_id}::${mode}","level":"info","event":"native_setjmp_fixture","bead_id":"bd-zh1y.2.1","stream":"e2e","gate":"check_setjmp_native","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"setjmp","symbol":"setjmp_family","decision_path":"ld_preload>native_x86_64_asm","healing_action":"none","errno":"0","latency_ns":${latency_ns},"outcome":"${outcome}","artifact_refs":${artifact_refs}}
JSON
}

run_case() {
  local name="$1"
  local bin="$2"
  local expected="$3"
  local mode="$4"
  local artifact_refs="$5"
  local start_ns end_ns latency_ns
  start_ns="$(date +%s%N)"
  if [[ "${mode}" == "strict" ]]; then
    output="$(LD_PRELOAD="${LIB}" "${bin}" 2>&1)"
  else
    output="$(FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB}" "${bin}" 2>&1)"
  fi
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"
  printf '%s\n' "${output}" >>"${TEST_LOG}"
  if [[ "${output}" != *"${expected}"* ]]; then
    echo "FAIL: ${name} (${mode}) missing expected output token '${expected}'" >&2
    echo "${output}" >&2
    exit 1
  fi
  emit_log_row "${name}" "${mode}" "pass" "${latency_ns}" "${artifact_refs}"
}

: >"${LOG}"

EDGE_REFS='["scripts/check_setjmp_native.sh","tests/integration/fixture_setjmp_edges.c","target/conformance/setjmp_native.report.json","target/conformance/setjmp_native.log.jsonl","target/conformance/setjmp_native.test_output.log"]'
NESTED_REFS='["scripts/check_setjmp_native.sh","tests/integration/fixture_setjmp_nested.c","target/conformance/setjmp_native.report.json","target/conformance/setjmp_native.log.jsonl","target/conformance/setjmp_native.test_output.log"]'

run_case "fixture_setjmp_edges" "${BIN_DIR}/fixture_setjmp_edges.bin" "fixture_setjmp_edges: PASS" "strict" "${EDGE_REFS}"
run_case "fixture_setjmp_edges" "${BIN_DIR}/fixture_setjmp_edges.bin" "fixture_setjmp_edges: PASS" "hardened" "${EDGE_REFS}"
run_case "fixture_setjmp_nested" "${BIN_DIR}/fixture_setjmp_nested.bin" "fixture_setjmp_nested: PASS" "strict" "${NESTED_REFS}"
run_case "fixture_setjmp_nested" "${BIN_DIR}/fixture_setjmp_nested.bin" "fixture_setjmp_nested: PASS" "hardened" "${NESTED_REFS}"

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-zh1y.2.1",
  "run_id": "${RUN_ID}",
  "library": "target/release/libfrankenlibc_abi.so",
  "checks": {
    "release_build_via_rch": "pass",
    "fixture_setjmp_edges_strict": "pass",
    "fixture_setjmp_edges_hardened": "pass",
    "fixture_setjmp_nested_strict": "pass",
    "fixture_setjmp_nested_hardened": "pass"
  },
  "artifacts": [
    "scripts/check_setjmp_native.sh",
    "tests/integration/fixture_setjmp_edges.c",
    "tests/integration/fixture_setjmp_nested.c",
    "target/conformance/setjmp_native.report.json",
    "target/conformance/setjmp_native.log.jsonl",
    "target/conformance/setjmp_native.test_output.log"
  ]
}
JSON

echo "check_setjmp_native: PASS"
