#!/usr/bin/env bash
# check_stdio_native.sh — native stdio globals smoke for bd-zh1y.4
set -euo pipefail

GNU_ONLY=0
GLOBALS_ONLY=0
if [[ "$#" -gt 1 ]]; then
  echo "usage: $0 [--gnu-printf|--globals-only]" >&2
  exit 2
fi
if [[ "${1:-}" == "--gnu-printf" ]]; then
  GNU_ONLY=1
elif [[ "${1:-}" == "--globals-only" ]]; then
  GLOBALS_ONLY=1
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [--gnu-printf|--globals-only]" >&2
  exit 2
fi
BEAD_ID="bd-zh1y.4"
if [[ "${GNU_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-rc0923-epic-eeuy4f.34"
elif [[ "${GLOBALS_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-reality-202609-lx578q.6.2.1"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${FRANKENLIBC_STDIO_OUT_DIR:-${ROOT}/target/conformance}"
BIN_DIR="${OUT_DIR}/stdio_native_bins"
REPORT="${OUT_DIR}/stdio_native.report.json"
LOG="${OUT_DIR}/stdio_native.log.jsonl"
TEST_LOG="${OUT_DIR}/stdio_native.test_output.log"
RUN_ID="stdio-native-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${BIN_DIR}"

LIB="${FRANKENLIBC_TEST_LIBRARY:-}"
BUILD_KIND="provided_artifact"
echo "[stdio-native] qualifying native stdio" >"${TEST_LOG}"
if [[ -z "${LIB}" ]]; then
  TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')"
  BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-${TARGET_DIR}}"
  env CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" cargo build -p frankenlibc-abi --release >>"${TEST_LOG}" 2>&1
  LIB="${BUILD_TARGET_DIR}/release/libfrankenlibc_abi.so"
  BUILD_KIND="executed_build"
fi

if [[ ! -f "${LIB}" ]]; then
  echo "FAIL: expected release library missing at ${LIB}" >&2
  cat "${TEST_LOG}" >&2
  exit 1
fi
LIB="$(realpath "${LIB}")"
LIB_SHA256="$(sha256sum "${LIB}" | awk '{print $1}')"

check_pointer_cell() {
  local symbol="$1"
  local pointer_size
  pointer_size="$(( $(getconf LONG_BIT) / 8 ))"
  nm -D --defined-only --print-size "${LIB}" | awk -v sym="${symbol}" -v width="${pointer_size}" '
    {
      name = $NF
      sub(/@.*/, "", name)
      if (name == sym) {
        found++
        size = $2
        sub(/^0+/, "", size)
        if (size == width && $(NF - 1) ~ /^[BD]$/) valid++
      }
    }
    END {
      if (found != 1 || valid != 1) {
        print "FAIL: " sym " must be an exported pointer-sized data object" > "/dev/stderr"
        exit 1
      }
    }
  '
}

check_file_object() {
  local symbol="$1"
  local pointer_size
  pointer_size="$(( $(getconf LONG_BIT) / 8 ))"
  nm -D --defined-only --print-size "${LIB}" | awk -v sym="${symbol}" -v width="${pointer_size}" '
    {
      name = $NF
      sub(/@.*/, "", name)
      if (name == sym) {
        size = $2
        sub(/^0+/, "", size)
        if (size == width) {
          print "FAIL: " sym " must not be a pointer-sized FILE alias" > "/dev/stderr"
          invalid = 1
        }
      }
    }
    END { exit invalid }
  '
}

if [[ "${GNU_ONLY}" -eq 0 ]]; then
  # stdin/out/err are pointer cells. _IO_2_1_* are FILE objects in glibc,
  # not aliases of those cells; the hybrid preload need not export them.
  check_pointer_cell "stdin"
  check_pointer_cell "stdout"
  check_pointer_cell "stderr"
  check_file_object "_IO_2_1_stdin_"
  check_file_object "_IO_2_1_stdout_"
  check_file_object "_IO_2_1_stderr_"
fi

if [[ "${GLOBALS_ONLY}" -eq 0 ]]; then
  cc -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -std=c11 -O2 -Wno-format-truncation "${ROOT}/tests/integration/fixture_stdio_printf.c" \
    -o "${BIN_DIR}/fixture_stdio_printf.bin" -ldl -lm -pthread
fi
if [[ "${GNU_ONLY}" -eq 0 ]]; then
  for style in copy got; do
    link_flags=(-fno-pic -no-pie)
    if [[ "${style}" == got ]]; then
      link_flags=(-fPIC -pie)
    fi
    cc -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -std=c11 -O2 -fno-builtin -Wall -Wextra -Werror \
      "${link_flags[@]}" "${ROOT}/tests/integration/fixture_stdio_globals.c" \
      -o "${BIN_DIR}/fixture_stdio_globals.${style}.bin" -ldl
  done
fi

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
{"timestamp":"$(now_iso_ms)","trace_id":"${BEAD_ID}::${RUN_ID}::${scenario_id}::${mode}::${stream}","level":"info","event":"native_stdio_fixture","bead_id":"${BEAD_ID}","stream":"${stream}","gate":"check_stdio_native","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"stdio","symbol":"stdio_globals","decision_path":"ld_preload>native_stdio_globals","healing_action":"none","errno":"0","latency_ns":${latency_ns},"outcome":"${outcome}","artifact_refs":${artifact_refs}}
JSON
}

run_case() {
  local name="$1"
  local bin="$2"
  local mode="$3"
  local expected_stdout="$4"
  local expected_stderr="$5"
  local artifact_refs="$6"
  local stdout_file stderr_file start_ns end_ns latency_ns

  stdout_file="${OUT_DIR}/${name}.${mode}.stdout.log"
  stderr_file="${OUT_DIR}/${name}.${mode}.stderr.log"
  start_ns="$(date +%s%N)"
  FRANKENLIBC_STDIO_EXPECT_PROVIDER="${LIB}" FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB}" \
    "${bin}" >"${stdout_file}" 2>"${stderr_file}"
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

if [[ "${GLOBALS_ONLY}" -eq 0 ]]; then
  run_case "fixture_stdio_printf" "${BIN_DIR}/fixture_stdio_printf.bin" "strict" "fixture_stdio_printf: PASS" "" "${COMMON_REFS}"
  run_case "fixture_stdio_printf" "${BIN_DIR}/fixture_stdio_printf.bin" "hardened" "fixture_stdio_printf: PASS" "" "${COMMON_REFS}"
fi
if [[ "${GNU_ONLY}" -eq 0 ]]; then
  for style in copy got; do
    name="fixture_stdio_globals.${style}"
    bin="${BIN_DIR}/${name}.bin"
    host_provider="$(env -u LD_PRELOAD ldd "${bin}" | awk '$1 == "libc.so.6" { print $3 }')"
    if [[ ! -f "${host_provider}" ]]; then
      echo "FAIL: cannot identify live GNU stdio provider" >&2
      exit 1
    fi
    env -u LD_PRELOAD -u FRANKENLIBC_MODE FRANKENLIBC_STDIO_EXPECT_PROVIDER="${host_provider}" \
      "${bin}" >"${OUT_DIR}/${name}.host.stdout.log" 2>"${OUT_DIR}/${name}.host.stderr.log"
    for mode in strict hardened; do
      run_case "${name}" "${bin}" "${mode}" "fixture_stdio_globals: PASS" "stderr-immediate" "${COMMON_REFS}"
      if ! cmp -s "${OUT_DIR}/${name}.host.stdout.log" "${OUT_DIR}/${name}.${mode}.stdout.log" || \
         ! cmp -s "${OUT_DIR}/${name}.host.stderr.log" "${OUT_DIR}/${name}.${mode}.stderr.log"; then
        echo "FAIL: ${name} (${mode}) differs from live GNU stdout/stderr" >&2
        exit 1
      fi
    done
  done
fi

if [[ "${GLOBALS_ONLY}" -eq 1 ]]; then
  cat >"${REPORT}" <<JSON
{"schema_version":"v1","scope":"stdio-globals","bead":"${BEAD_ID}","run_id":"${RUN_ID}","library":"${LIB}","library_sha256":"${LIB_SHA256}","build_kind":"${BUILD_KIND}","pointer_cell_symbols":"pass","link_styles":["copy","got"],"candidate_processes":4,"live_GNU_processes":2,"provider_bound_FILE_semantics_strict":"pass","provider_bound_FILE_semantics_hardened":"pass","full_stdio_gate":"not_run"}
JSON
  echo "check_stdio_native --globals-only: PASS (provider-bound FILE semantics in both modes; full stdio gate not run)"
  exit 0
fi

# Live GNU oracle and the exact supplied library execute the same fixture.
# Keep every row and compare both streams; a process exit alone is not proof.
for scenario in gnu-types gnu-size gnu-errors gnu-rounding gnu-double-rounding gnu-unknown gnu-unknown-registered gnu-register gnu-register-wide; do
  oracle_stdout="${OUT_DIR}/${scenario}.host.stdout.log"
  oracle_stderr="${OUT_DIR}/${scenario}.host.stderr.log"
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_TEST_LIBRARY \
    "${BIN_DIR}/fixture_stdio_printf.bin" "--${scenario}" >"${oracle_stdout}" 2>"${oracle_stderr}"
  rows="$(wc -l <"${oracle_stdout}")"
  if [[ "${rows}" -eq 0 ]]; then
    echo "FAIL: empty GNU oracle for ${scenario}" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-unknown* && "${rows}" -ne 3000 ]]; then
    echo "FAIL: incomplete unknown-conversion oracle (${rows}/3000 rows)" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register* ]] &&
     [[ "$(grep -Ec '^reg:complete:(narrow|wide)$' "${oracle_stdout}")" -ne 1 ]]; then
    echo "FAIL: GNU registration oracle did not complete ${scenario}" >&2
    exit 1
  fi
  if [[ "${scenario}" == *rounding ]] &&
     [[ "$(grep -Ec '^round-thread:[0-3]:0$' "${oracle_stdout}")" -ne 4 ]]; then
    echo "FAIL: GNU oracle failed concurrent rounding expectations" >&2
    exit 1
  fi
  for mode in strict hardened; do
    actual_stdout="${OUT_DIR}/${scenario}.${mode}.stdout.log"
    actual_stderr="${OUT_DIR}/${scenario}.${mode}.stderr.log"
    start_ns="$(date +%s%N)"
    FRANKENLIBC_MODE="${mode}" FRANKENLIBC_TEST_LIBRARY="${LIB}" LD_PRELOAD="${LIB}" \
      "${BIN_DIR}/fixture_stdio_printf.bin" "--${scenario}" >"${actual_stdout}" 2>"${actual_stderr}"
    latency_ns="$(( $(date +%s%N) - start_ns ))"
    if ! cmp -s "${oracle_stdout}" "${actual_stdout}" || ! cmp -s "${oracle_stderr}" "${actual_stderr}"; then
      echo "FAIL: ${scenario} (${mode}) differs from live GNU oracle; see ${OUT_DIR}" >&2
      exit 1
    fi
    echo "${scenario} (${mode}): ${rows} live differential rows passed" >>"${TEST_LOG}"
    emit_log_row "${scenario}" "${mode}" "stdio" "pass" "${latency_ns}" "${COMMON_REFS}"
  done
done

# A GNU 2.39 custom/native fallback combination has inconsistent return-count
# accounting. Preserve the exact host and candidate rows rather than hiding
# the mismatch or treating this diagnostic as part of the parity claim.
scenario=gnu-register-combined-fallback
oracle_stdout="${OUT_DIR}/${scenario}.host.stdout.log"
oracle_stderr="${OUT_DIR}/${scenario}.host.stderr.log"
env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_TEST_LIBRARY \
  "${BIN_DIR}/fixture_stdio_printf.bin" "--${scenario}" >"${oracle_stdout}" 2>"${oracle_stderr}"
grep -q '^reg:combined-fallback:' "${oracle_stdout}"
for mode in strict hardened; do
  actual_stdout="${OUT_DIR}/${scenario}.${mode}.stdout.log"
  actual_stderr="${OUT_DIR}/${scenario}.${mode}.stderr.log"
  FRANKENLIBC_MODE="${mode}" FRANKENLIBC_TEST_LIBRARY="${LIB}" LD_PRELOAD="${LIB}" \
    "${BIN_DIR}/fixture_stdio_printf.bin" "--${scenario}" >"${actual_stdout}" 2>"${actual_stderr}"
  cmp -s "${oracle_stderr}" "${actual_stderr}"
  if cmp -s "${oracle_stdout}" "${actual_stdout}"; then
    result=match
  else
    result=return_count_differs
  fi
  echo "${scenario} (${mode}): diagnostic ${result}; exact return-count parity is not claimed" >>"${TEST_LOG}"
  cat "${oracle_stdout}" "${actual_stdout}" >>"${TEST_LOG}"
done

if [[ "${GNU_ONLY}" -eq 1 ]]; then
  cat >"${REPORT}" <<JSON
{"schema_version":"v1","scope":"gnu-printf","bead":"bd-rc0923-epic-eeuy4f.34","run_id":"${RUN_ID}","library":"${LIB}","library_sha256":"${LIB_SHA256}","build_kind":"${BUILD_KIND}","original_printf_cases_per_mode":10,"gnu_live_differential_strict":"pass","gnu_live_differential_hardened":"pass","combined_fallback_return_count":"diagnostic_only"}
JSON
  echo "check_stdio_native --gnu-printf: PASS (GNU callbacks/introspection and 10 original printf cases per mode; full stdio gate not run)"
  exit 0
fi

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-zh1y.4",
  "run_id": "${RUN_ID}",
  "library": "${LIB}",
  "library_sha256": "${LIB_SHA256}",
  "build_kind": "${BUILD_KIND}",
  "checks": {
    "nm_stdio_pointer_cells": "pass",
    "fixture_stdio_printf_strict": "pass",
    "fixture_stdio_printf_hardened": "pass",
    "fixture_stdio_globals_strict": "pass",
    "fixture_stdio_globals_hardened": "pass",
    "gnu_printf_live_differential_strict": "pass",
    "gnu_printf_live_differential_hardened": "pass"
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
