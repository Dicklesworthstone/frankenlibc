#!/usr/bin/env bash
# check_stdio_native.sh — native stdio globals smoke for bd-zh1y.4
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BIN_DIR="${OUT_DIR}/stdio_native_bins"
REPORT="${OUT_DIR}/stdio_native.report.json"
LOG="${OUT_DIR}/stdio_native.log.jsonl"
TEST_LOG="${OUT_DIR}/stdio_native.test_output.log"
RUN_ID="stdio-native-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${BIN_DIR}"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')"
LIB="${TARGET_DIR}/release/libfrankenlibc_abi.so"

echo "[stdio-native] building release ABI library via rch" >"${TEST_LOG}"
rch exec -- cargo build -p frankenlibc-abi --release >>"${TEST_LOG}" 2>&1

if [[ ! -f "${LIB}" ]]; then
  echo "FAIL: expected release library missing at ${LIB}" >&2
  cat "${TEST_LOG}" >&2
  exit 1
fi

symbol_addr() {
  local symbol="$1"
  nm -D --defined-only "${LIB}" 2>/dev/null | awk -v sym="${symbol}" '
    {
      name = $NF
      sub(/@.*/, "", name)
      if (name == sym) {
        print $1
        exit
      }
    }
  '
}

check_alias_addr() {
  local public_symbol="$1"
  local alias_symbol="$2"
  local public_addr alias_addr
  public_addr="$(symbol_addr "${public_symbol}")"
  alias_addr="$(symbol_addr "${alias_symbol}")"
  if [[ -z "${public_addr}" || -z "${alias_addr}" ]]; then
    echo "FAIL: missing nm symbol(s) for ${public_symbol}/${alias_symbol}" >&2
    nm -D --defined-only "${LIB}" >&2 || true
    exit 1
  fi
  if [[ "${public_addr}" != "${alias_addr}" ]]; then
    echo "FAIL: ${alias_symbol} address ${alias_addr} != ${public_symbol} address ${public_addr}" >&2
    nm -D --defined-only "${LIB}" | grep -E "(${public_symbol}|${alias_symbol})" >&2 || true
    exit 1
  fi
}

check_alias_addr "stdin" "_IO_2_1_stdin_"
check_alias_addr "stdout" "_IO_2_1_stdout_"
check_alias_addr "stderr" "_IO_2_1_stderr_"

cc -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -std=c11 -O2 "${ROOT}/tests/integration/fixture_stdio_printf.c" \
  -o "${BIN_DIR}/fixture_stdio_printf.bin"
cc -D_POSIX_C_SOURCE=200809L -std=c11 -O2 "${ROOT}/tests/integration/fixture_stdio_globals.c" \
  -o "${BIN_DIR}/fixture_stdio_globals.bin"

now_iso_ms() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log_row() {
  local scenario_id="$1"
  local mode="$2"
  local stream="$3"
  local outcome="$4"
  local latency_ns="$5"
  local artifact_refs="$6"
  cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-zh1y.4::${RUN_ID}::${scenario_id}::${mode}::${stream}","level":"info","event":"native_stdio_fixture","bead_id":"bd-zh1y.4","stream":"${stream}","gate":"check_stdio_native","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"stdio","symbol":"stdio_globals","decision_path":"ld_preload>native_stdio_globals","healing_action":"none","errno":"0","latency_ns":${latency_ns},"outcome":"${outcome}","artifact_refs":${artifact_refs}}
JSON
}

run_case() {
  local name="$1"
  local bin="$2"
  local mode="$3"
  local expected_stdout="$4"
  local expected_stderr="$5"
  local artifact_refs="$6"
  local stdout_file stderr_file output start_ns end_ns latency_ns env_prefix=()

  stdout_file="${OUT_DIR}/${name}.${mode}.stdout.log"
  stderr_file="${OUT_DIR}/${name}.${mode}.stderr.log"
  start_ns="$(date +%s%N)"
  if [[ "${mode}" == "strict" ]]; then
    LD_PRELOAD="${LIB}" "${bin}" >"${stdout_file}" 2>"${stderr_file}"
  else
    FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB}" "${bin}" >"${stdout_file}" 2>"${stderr_file}"
  fi
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"

  cat "${stdout_file}" >>"${TEST_LOG}"
  cat "${stderr_file}" >>"${TEST_LOG}"

  if [[ -n "${expected_stdout}" ]] && ! grep -Fq "${expected_stdout}" "${stdout_file}"; then
    echo "FAIL: ${name} (${mode}) missing stdout token '${expected_stdout}'" >&2
    cat "${stdout_file}" >&2
    exit 1
  fi
  if [[ -n "${expected_stderr}" ]] && ! grep -Fq "${expected_stderr}" "${stderr_file}"; then
    echo "FAIL: ${name} (${mode}) missing stderr token '${expected_stderr}'" >&2
    cat "${stderr_file}" >&2
    exit 1
  fi

  emit_log_row "${name}" "${mode}" "stdio" "pass" "${latency_ns}" "${artifact_refs}"
}

: >"${LOG}"

COMMON_REFS='["scripts/check_stdio_native.sh","tests/integration/fixture_stdio_printf.c","tests/integration/fixture_stdio_globals.c","target/conformance/stdio_native.report.json","target/conformance/stdio_native.log.jsonl","target/conformance/stdio_native.test_output.log"]'

run_case "fixture_stdio_printf" "${BIN_DIR}/fixture_stdio_printf.bin" "strict" "fixture_stdio_printf: PASS" "" "${COMMON_REFS}"
run_case "fixture_stdio_printf" "${BIN_DIR}/fixture_stdio_printf.bin" "hardened" "fixture_stdio_printf: PASS" "" "${COMMON_REFS}"
run_case "fixture_stdio_globals" "${BIN_DIR}/fixture_stdio_globals.bin" "strict" "fixture_stdio_globals: PASS" "stderr-immediate" "${COMMON_REFS}"
run_case "fixture_stdio_globals" "${BIN_DIR}/fixture_stdio_globals.bin" "hardened" "fixture_stdio_globals: PASS" "stderr-immediate" "${COMMON_REFS}"

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-zh1y.4",
  "run_id": "${RUN_ID}",
  "library": "target/release/libfrankenlibc_abi.so",
  "checks": {
    "release_build_via_rch": "pass",
    "nm_stdio_alias_addresses": "pass",
    "fixture_stdio_printf_strict": "pass",
    "fixture_stdio_printf_hardened": "pass",
    "fixture_stdio_globals_strict": "pass",
    "fixture_stdio_globals_hardened": "pass"
  },
  "artifacts": [
    "scripts/check_stdio_native.sh",
    "tests/integration/fixture_stdio_printf.c",
    "tests/integration/fixture_stdio_globals.c",
    "target/conformance/stdio_native.report.json",
    "target/conformance/stdio_native.log.jsonl",
    "target/conformance/stdio_native.test_output.log"
  ]
}
JSON

echo "check_stdio_native: PASS"
