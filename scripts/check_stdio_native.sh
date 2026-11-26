#!/usr/bin/env bash
# check_stdio_native.sh — native stdio globals smoke for bd-zh1y.4
set -euo pipefail

GNU_ONLY=0
GLOBALS_ONLY=0
READ_ERRORS_ONLY=0
WRITE_ERRORS_ONLY=0
POPEN_ONLY=0
FMEMOPEN_ONLY=0
COOKIE_LINES_ONLY=0
INTERNAL_LINES_ONLY=0
LOCKS_ONLY=0
FLUSH_ALL_ONLY=0
EXIT_FLUSH_ONLY=0
if [[ "$#" -gt 1 ]]; then
  echo "usage: $0 [--gnu-printf|--globals-only|--read-errors|--write-errors|--popen|--fmemopen|--cookie-lines|--internal-lines|--locks|--flush-all|--exit-flush]" >&2
  exit 2
fi
if [[ "${1:-}" == "--gnu-printf" ]]; then
  GNU_ONLY=1
elif [[ "${1:-}" == "--globals-only" ]]; then
  GLOBALS_ONLY=1
elif [[ "${1:-}" == "--read-errors" ]]; then
  READ_ERRORS_ONLY=1
elif [[ "${1:-}" == "--write-errors" ]]; then
  WRITE_ERRORS_ONLY=1
elif [[ "${1:-}" == "--popen" ]]; then
  POPEN_ONLY=1
elif [[ "${1:-}" == "--fmemopen" ]]; then
  FMEMOPEN_ONLY=1
elif [[ "${1:-}" == "--cookie-lines" ]]; then
  COOKIE_LINES_ONLY=1
elif [[ "${1:-}" == "--internal-lines" ]]; then
  INTERNAL_LINES_ONLY=1
elif [[ "${1:-}" == "--locks" ]]; then
  LOCKS_ONLY=1
elif [[ "${1:-}" == "--flush-all" ]]; then
  FLUSH_ALL_ONLY=1
elif [[ "${1:-}" == "--exit-flush" ]]; then
  EXIT_FLUSH_ONLY=1
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [--gnu-printf|--globals-only|--read-errors|--write-errors|--popen|--fmemopen|--cookie-lines|--internal-lines|--locks|--flush-all|--exit-flush]" >&2
  exit 2
fi
BEAD_ID="bd-zh1y.4"
if [[ "${GNU_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-rc0923-epic-eeuy4f.34"
elif [[ "${GLOBALS_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-reality-202609-lx578q.6.2.1"
elif [[ "${READ_ERRORS_ONLY}" -eq 1 || "${WRITE_ERRORS_ONLY}" -eq 1 || "${POPEN_ONLY}" -eq 1 || "${COOKIE_LINES_ONLY}" -eq 1 || "${LOCKS_ONLY}" -eq 1 || "${FLUSH_ALL_ONLY}" -eq 1 || "${EXIT_FLUSH_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-reality-202609-lx578q.6.2"
elif [[ "${FMEMOPEN_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-reality-202609-lx578q.7.5"
elif [[ "${INTERNAL_LINES_ONLY}" -eq 1 ]]; then
  BEAD_ID="bd-reality-202609-lx578q.7.40"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${FRANKENLIBC_STDIO_OUT_DIR:-${ROOT}/target/conformance}"
BIN_DIR="${OUT_DIR}/stdio_native_bins"
REPORT="${OUT_DIR}/stdio_native.report.json"
LOG="${OUT_DIR}/stdio_native.log.jsonl"
TEST_LOG="${OUT_DIR}/stdio_native.test_output.log"
RUN_ID="stdio-native-$(date -u +%Y%m%dT%H%M%SZ)-$$"
PRESERVE_SCRATCH_FILES=false
if [[ "${FRANKENLIBC_TEST_PRESERVE_FILES:-}" == 1 ]]; then
  PRESERVE_SCRATCH_FILES=true
fi

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

if [[ "${EXIT_FLUSH_ONLY}" -eq 1 ]]; then
  exit_bin="${BIN_DIR}/fixture_exit_sequence.bin"
  "${CC:-cc}" -std=c11 -O2 -fno-builtin -Wall -Wextra -Werror \
    "${ROOT}/tests/integration/fixture_exit_sequence.c" -ldl -o "${exit_bin}"
  host_provider="$(env -u LD_PRELOAD ldd "${exit_bin}" | awk '$1 == "libc.so.6" { print $3 }')"
  if [[ ! -f "${host_provider}" ]]; then
    echo "FAIL: cannot identify live GNU stdio provider" >&2
    exit 1
  fi
  printf 'stdio-exit:42\n' > "${OUT_DIR}/exit-flush.expected.stdout.log"
  failed=0
  provider_status=0
  env -u LD_PRELOAD -u FRANKENLIBC_MODE \
    timeout --kill-after=2s 20s "${exit_bin}" stdio-return "${LIB}" \
    > "${OUT_DIR}/exit-flush.provider-negative.stdout.log" \
    2> "${OUT_DIR}/exit-flush.provider-negative.stderr.log" || provider_status=$?
  printf '%s\n' "${provider_status}" > "${OUT_DIR}/exit-flush.provider-negative.status"
  if [[ "${provider_status}" -ne 86 || -s "${OUT_DIR}/exit-flush.provider-negative.stdout.log" ]] || \
    ! grep -qx 'fixture-exit-sequence:provider-mismatch:printf' "${OUT_DIR}/exit-flush.provider-negative.stderr.log"; then
    echo "FAIL: omitted-preload exit/stdio provider control" >&2
    failed=1
  fi
  for case in stdio-return stdio-exit stdio-flush-all stdio-flush-stream stdio-closed-stdout; do
    expected_status=0
    if [[ "${case}" == stdio-exit ]]; then expected_status=7; fi
    host_prefix="${OUT_DIR}/exit-flush.${case}.host"
    host_status=0
    env -u LD_PRELOAD -u FRANKENLIBC_MODE \
      timeout --kill-after=2s 20s "${exit_bin}" "${case}" "${host_provider}" \
      > "${host_prefix}.stdout.log" 2> "${host_prefix}.stderr.log" || host_status=$?
    printf '%s\n' "${host_status}" > "${host_prefix}.status"
    if [[ "${host_status}" -ne "${expected_status}" || -s "${host_prefix}.stderr.log" ]] || \
      ! cmp -s "${OUT_DIR}/exit-flush.expected.stdout.log" "${host_prefix}.stdout.log"; then
      echo "FAIL: live GNU exit/stdio case ${case} (status ${host_status})" >&2
      failed=1
    fi
    for mode in strict hardened; do
      prefix="${OUT_DIR}/exit-flush.${case}.${mode}"
      status=0
      timeout --kill-after=2s 20s env LD_PRELOAD="${LIB}" FRANKENLIBC_MODE="${mode}" \
        "${exit_bin}" "${case}" "${LIB}" \
        > "${prefix}.stdout.log" 2> "${prefix}.stderr.log" || status=$?
      printf '%s\n' "${status}" > "${prefix}.status"
      if [[ "${status}" -ne "${expected_status}" || "${status}" -ne "${host_status}" || -s "${prefix}.stderr.log" ]] || \
        ! cmp -s "${host_prefix}.stdout.log" "${prefix}.stdout.log"; then
        echo "FAIL: ${mode} exit/stdio case ${case} (status ${status})" >&2
        failed=1
      fi
    done
  done
  if [[ "${failed}" -ne 0 ]]; then exit 1; fi
  echo "check_stdio_native --exit-flush: PASS (5 live GNU cases, 10 native cases, 1 provider negative)"
  exit 0
fi

if [[ "${READ_ERRORS_ONLY}" -eq 1 || "${WRITE_ERRORS_ONLY}" -eq 1 || "${POPEN_ONLY}" -eq 1 || "${FMEMOPEN_ONLY}" -eq 1 || "${COOKIE_LINES_ONLY}" -eq 1 || "${INTERNAL_LINES_ONLY}" -eq 1 || "${LOCKS_ONLY}" -eq 1 || "${FLUSH_ALL_ONLY}" -eq 1 ]]; then
  error_kind=read
  error_mode=fd-errors
  error_cases=112
  error_option=--read-errors
  if [[ "${WRITE_ERRORS_ONLY}" -eq 1 ]]; then
    error_kind=write
    error_mode=write-errors
    error_cases=78
    error_option=--write-errors
  elif [[ "${POPEN_ONLY}" -eq 1 ]]; then
    error_kind=popen
    error_mode=popen
    error_cases=24
    error_option=--popen
  elif [[ "${FMEMOPEN_ONLY}" -eq 1 ]]; then
    error_kind=fmemopen
    error_mode=fmemopen
    error_cases=22
    error_option=--fmemopen
  elif [[ "${COOKIE_LINES_ONLY}" -eq 1 ]]; then
    error_kind=cookie-lines
    error_mode=cookie-lines
    error_cases=88
    error_option=--cookie-lines
  elif [[ "${INTERNAL_LINES_ONLY}" -eq 1 ]]; then
    error_kind=internal-lines
    error_mode=internal-lines
    error_cases=216
    error_option=--internal-lines
  elif [[ "${LOCKS_ONLY}" -eq 1 ]]; then
    error_kind=locks
    error_mode=locks
    error_cases=203
    error_option=--locks
  elif [[ "${FLUSH_ALL_ONLY}" -eq 1 ]]; then
    error_kind=flush-all
    error_mode=flush-all
    error_cases=9
    error_option=--flush-all
  fi
  error_bin="${BIN_DIR}/fixture_stdio_${error_kind}_errors.bin"
  "${CC:-cc}" -std=c11 -O2 -fno-builtin -Wall -Wextra -Werror \
    "${ROOT}/tests/integration/fixture_stdio.c" -pthread -ldl -o "${error_bin}"
  host_provider="$(env -u LD_PRELOAD ldd "${error_bin}" | awk '$1 == "libc.so.6" { print $3 }')"
  if [[ ! -f "${host_provider}" ]]; then
    echo "FAIL: cannot identify live GNU stdio provider" >&2
    exit 1
  fi
  env -u LD_PRELOAD -u FRANKENLIBC_MODE \
    timeout --kill-after=2s 30s "${error_bin}" "${error_mode}" "${host_provider}" \
    >"${OUT_DIR}/${error_kind}-errors.host.stdout.log" 2>"${OUT_DIR}/${error_kind}-errors.host.stderr.log"
  grep -qx "fixture_stdio ${error_mode}: PASS (${error_cases} cases, 0 failed)" \
    "${OUT_DIR}/${error_kind}-errors.host.stdout.log"
  for mode in strict hardened; do
    timeout --kill-after=2s 30s env LD_PRELOAD="${LIB}" FRANKENLIBC_MODE="${mode}" \
      "${error_bin}" "${error_mode}" "${LIB}" \
      >"${OUT_DIR}/${error_kind}-errors.${mode}.stdout.log" 2>"${OUT_DIR}/${error_kind}-errors.${mode}.stderr.log"
    cmp "${OUT_DIR}/${error_kind}-errors.host.stdout.log" "${OUT_DIR}/${error_kind}-errors.${mode}.stdout.log"
  done
  set +e
  env -u LD_PRELOAD -u FRANKENLIBC_MODE \
    timeout --kill-after=2s 30s "${error_bin}" "${error_mode}" "${LIB}" \
    >"${OUT_DIR}/${error_kind}-errors.provider-negative.stdout.log" \
    2>"${OUT_DIR}/${error_kind}-errors.provider-negative.stderr.log"
  provider_status=$?
  set -e
  if [[ "${provider_status}" -ne 2 ]]; then
    echo "FAIL: omitted-preload provider control returned ${provider_status}, expected 2" >&2
    exit 1
  fi
  grep -q '^FAIL: wrong stdio provider for ' "${OUT_DIR}/${error_kind}-errors.provider-negative.stderr.log"
  if [[ "${WRITE_ERRORS_ONLY}" -eq 1 ]]; then
    # A negative write-hook return violates fopencookie's callback contract.
    # Check bounded failure separately from the valid-program GNU comparison.
    for mode in strict hardened; do
      timeout --kill-after=2s 10s env LD_PRELOAD="${LIB}" FRANKENLIBC_MODE="${mode}" \
        "${error_bin}" cookie-write-invalid "${LIB}" \
        >"${OUT_DIR}/cookie-write-invalid.${mode}.stdout.log" \
        2>"${OUT_DIR}/cookie-write-invalid.${mode}.stderr.log"
      grep -qx 'fixture_stdio cookie-write-invalid: PASS (1 case, 0 failed)' \
        "${OUT_DIR}/cookie-write-invalid.${mode}.stdout.log"
    done
    echo "check_stdio_native --write-errors: PASS (2 malformed-callback bounded-failure cases)"
  fi
  echo "check_stdio_native ${error_option}: PASS (${error_cases} live GNU cases, $((error_cases * 2)) native cases, 1 provider negative)"
  exit 0
fi

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
  nm -D --defined-only --print-size "${LIB}" | awk -v sym="${symbol}" -v lib="${LIB}" '
    {
      name = $NF
      sub(/@.*/, "", name)
      if (name == sym) {
        found = 1
        raw = tolower($2)
        sub(/^0+/, "", raw)
        type = $3
        if (raw != "e0" || type !~ /^[BD]$/) {
          print "FAIL: " sym " expected 224-byte (0xe0) data OBJECT, got size=0x" (raw == "" ? "0" : raw) " type=" type > "/dev/stderr"
          invalid = 1
        }
      }
    }
    END {
      if (!found) {
        print "FAIL: missing exported FILE object " sym " in " lib > "/dev/stderr"
        exit 1
      }
      exit invalid
    }
  '
  # Supported LP64 GNU targets have a 216-byte FILE plus an 8-byte vtable.
  # Hybrid builds use unversioned interposition; the standalone version script
  # assigns GLIBC_2.2.5. Both must export the exact 224-byte GLOBAL object.
  readelf --dyn-syms --wide "${LIB}" | awk -v sym="${symbol}" '
    {
      name = $8
      base = name
      sub(/@.*/, "", base)
      if (base == sym) {
        found++
        version_ok = name == sym || name == sym "@GLIBC_2.2.5" || name == sym "@@GLIBC_2.2.5"
        if ($3 == 224 && $4 == "OBJECT" && $5 == "GLOBAL" && $7 != "UND" && version_ok) valid++
      }
    }
    END {
      if (found != 1 || valid != 1) {
        print "FAIL: " sym " must be a GLOBAL 224-byte FILE object (GLIBC_2.2.5 when versioned)" > "/dev/stderr"
        exit 1
      }
    }
  '
}

if [[ "${GNU_ONLY}" -eq 0 ]]; then
  # stdin/out/err are pointer cells; _IO_2_1_* are 224-byte _IO_FILE_plus
  # data objects exported at GLIBC_2.2.5, and exact-size FILE objects.
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
  "${CXX:-c++}" -D_GNU_SOURCE -std=c++17 -O2 -Wall -Wextra -Werror \
    "${ROOT}/tests/integration/fixture_callback_unwind.cpp" \
    -o "${BIN_DIR}/fixture_callback_unwind.bin" -ldl -pthread
fi
if [[ "${GNU_ONLY}" -eq 0 ]]; then
  for style in copy pie-copy got; do
    link_flags=(-fno-pic -no-pie)
    if [[ "${style}" == got ]]; then
      link_flags=(-fPIC -pie)
    elif [[ "${style}" == pie-copy ]]; then
      link_flags=(-fPIE -pie)
    fi
    cc -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -std=c11 -O2 -fno-builtin -Wall -Wextra -Werror \
      "${link_flags[@]}" "${ROOT}/tests/integration/fixture_stdio_globals.c" \
      -o "${BIN_DIR}/fixture_stdio_globals.${style}.bin" -ldl
    if [[ "${style}" != got ]]; then
      for symbol in _IO_2_1_stdin_ _IO_2_1_stdout_ _IO_2_1_stderr_; do
        readelf --relocs --wide "${BIN_DIR}/fixture_stdio_globals.${style}.bin" \
          | awk -v sym="${symbol}" '$3 ~ /_COPY$/ && index($5, sym) == 1 { found = 1 } END { exit !found }'
      done
    fi
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
  timeout --kill-after=2s 30s env FRANKENLIBC_STDIO_EXPECT_PROVIDER="${LIB}" \
    FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB}" \
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
  for style in copy pie-copy got; do
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
    provider_status=0
    env -u LD_PRELOAD -u FRANKENLIBC_MODE FRANKENLIBC_STDIO_EXPECT_PROVIDER="${LIB}" \
      "${bin}" >"${OUT_DIR}/${name}.provider-negative.stdout.log" \
      2>"${OUT_DIR}/${name}.provider-negative.stderr.log" || provider_status=$?
    if [[ "${provider_status}" -ne 1 ]] ||
       ! grep -q '^FAIL: wrong stdio provider for ' "${OUT_DIR}/${name}.provider-negative.stderr.log"; then
      echo "FAIL: ${name} accepted an omitted-preload provider control" >&2
      exit 1
    fi
  done
fi

if [[ "${GLOBALS_ONLY}" -eq 1 ]]; then
  cat >"${REPORT}" <<JSON
{"schema_version":"v1","scope":"stdio-globals","bead":"${BEAD_ID}","run_id":"${RUN_ID}","library":"${LIB}","library_sha256":"${LIB_SHA256}","build_kind":"${BUILD_KIND}","preserve_scratch_files":${PRESERVE_SCRATCH_FILES},"pointer_cell_symbols":"pass","file_object_symbols":"pass","link_styles":["copy","pie-copy","got"],"candidate_processes":6,"live_GNU_processes":3,"provider_negative_controls":3,"provider_bound_FILE_semantics_strict":"pass","provider_bound_FILE_semantics_hardened":"pass","full_stdio_gate":"not_run"}
JSON
  echo "check_stdio_native --globals-only: PASS (provider-bound FILE semantics in both modes; full stdio gate not run)"
  exit 0
fi

# Live GNU oracle and the exact supplied library execute the same fixture.
# Keep every row and compare both streams; a process exit alone is not proof.
for scenario in gnu-register-query-bounds gnu-register-narrow-bounds gnu-types gnu-size gnu-errors gnu-rounding gnu-double-rounding gnu-unknown gnu-unknown-registered gnu-wide-bounds gnu-wide-locale gnu-precision-spans gnu-register gnu-register-wide gnu-register-wide-bounds gnu-register-limits gnu-register-concurrent; do
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
  if [[ "${scenario}" == gnu-register* ]]; then
    completion=narrow
    if [[ "${scenario}" == gnu-register-wide ]]; then
      completion=wide
    elif [[ "${scenario}" == gnu-register-wide-bounds ]]; then
      completion=wide-bounds
    elif [[ "${scenario}" == gnu-register-limits ]]; then
      completion=limits
    elif [[ "${scenario}" == gnu-register-concurrent ]]; then
      completion=concurrent
    elif [[ "${scenario}" == gnu-register-query-bounds ]]; then
      completion=query-bounds
    elif [[ "${scenario}" == gnu-register-narrow-bounds ]]; then
      completion=narrow-bounds
    fi
    if [[ "$(grep -xc "reg:complete:${completion}" "${oracle_stdout}")" -ne 1 ]]; then
      echo "FAIL: GNU registration oracle did not complete ${scenario}" >&2
      exit 1
    fi
  fi
  if [[ "${scenario}" == gnu-register-limits ]] &&
     [[ "$(grep -c '^reg:limit:' "${oracle_stdout}")" -ne 9 ]]; then
    echo "FAIL: incomplete registration limits oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register-concurrent ]] &&
     [[ "$(grep -Ec '^reg:concurrent:(formatter|mutator):[0-3]:ok$' "${oracle_stdout}")" -ne 6 ]]; then
    echo "FAIL: incomplete registration concurrency oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register-query-bounds ]] &&
     { [[ "$(grep -Ec '^reg:query(-huge)?:' "${oracle_stdout}")" -ne 120 ]] ||
       [[ "${rows}" -ne 121 ]]; }; then
    echo "FAIL: incomplete registration type-query oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register-wide-bounds ]] &&
     [[ "$(grep -c '^reg:wide-bounds:' "${oracle_stdout}")" -ne 80 ]]; then
    echo "FAIL: incomplete wide registration boundary oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register-narrow-bounds ]] &&
     { [[ "$(grep -c '^reg:narrow-bounds:' "${oracle_stdout}")" -ne 112 ]] ||
       [[ "$(grep -c '^reg:narrow-huge:' "${oracle_stdout}")" -ne 8 ]] ||
       [[ "${rows}" -ne 121 ]]; }; then
    echo "FAIL: incomplete narrow registration boundary oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-wide-bounds ]] &&
     { [[ "$(grep -c '^wide:bounds:' "${oracle_stdout}")" -ne 408 ]] ||
       [[ "$(grep -xc 'wide:complete:bounds' "${oracle_stdout}")" -ne 1 ]]; }; then
    echo "FAIL: incomplete ordinary wide boundary oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-wide-locale ]] &&
     { [[ "$(grep -c '^wide:locale:' "${oracle_stdout}")" -ne 400 ]] ||
       [[ "$(grep -xc 'wide:complete:locale' "${oracle_stdout}")" -ne 1 ]]; }; then
    echo "FAIL: incomplete wide locale oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-precision-spans ]] &&
     { [[ "$(grep -c '^precision:span:' "${oracle_stdout}")" -ne 256 ]] ||
       [[ "$(grep -xc 'precision:complete:spans' "${oracle_stdout}")" -ne 1 ]]; }; then
    echo "FAIL: incomplete precision input-span oracle" >&2
    exit 1
  fi
  if [[ "${scenario}" == gnu-register-wide-bounds || "${scenario}" == gnu-register-limits || "${scenario}" == gnu-register-concurrent || "${scenario}" == gnu-register-query-bounds || "${scenario}" == gnu-register-narrow-bounds || "${scenario}" == gnu-wide-bounds || "${scenario}" == gnu-wide-locale || "${scenario}" == gnu-precision-spans ]]; then
    negative_status=0
    env -u LD_PRELOAD -u FRANKENLIBC_MODE FRANKENLIBC_TEST_LIBRARY="${LIB}" \
      "${BIN_DIR}/fixture_stdio_printf.bin" "--${scenario}" \
      >"${OUT_DIR}/${scenario}.wrong-provider.stdout.log" \
      2>"${OUT_DIR}/${scenario}.wrong-provider.stderr.log" || negative_status=$?
    if [[ "${negative_status}" -ne 91 ]] ||
       ! grep -q 'FAIL: wrong provider' "${OUT_DIR}/${scenario}.wrong-provider.stderr.log"; then
      echo "FAIL: wide registration boundary probe accepted the wrong provider" >&2
      exit 1
    fi
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
    echo "${scenario} (${mode}): ${rows} live differential rows passed" | tee -a "${TEST_LOG}"
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

# Foreign C++ exception propagation through all 48 printf/wprintf/fortify/obstack
# entrypoints across render, arginfo and custom-type reader callback boundaries.
scenario=printf-callback-unwind
oracle_stdout="${OUT_DIR}/${scenario}.host.stdout.log"
oracle_stderr="${OUT_DIR}/${scenario}.host.stderr.log"
env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_TEST_LIBRARY \
  "${BIN_DIR}/fixture_callback_unwind.bin" --printf-all >"${oracle_stdout}" 2>"${oracle_stderr}"
if [[ "$(grep -xc 'printf-callback-unwind-all:PASS (142 cases)' "${oracle_stdout}")" -ne 1 ]]; then
  echo "FAIL: GNU printf callback unwind oracle did not complete 142 cases" >&2
  exit 1
fi
unwind_neg_status=0
env -u LD_PRELOAD -u FRANKENLIBC_MODE FRANKENLIBC_TEST_LIBRARY="${LIB}" \
  "${BIN_DIR}/fixture_callback_unwind.bin" --printf snprintf 0 \
  >"${OUT_DIR}/${scenario}.wrong-provider.stdout.log" \
  2>"${OUT_DIR}/${scenario}.wrong-provider.stderr.log" || unwind_neg_status=$?
if [[ "${unwind_neg_status}" -ne 88 ]] ||
   ! grep -q 'printf-callback-unwind: wrong provider' "${OUT_DIR}/${scenario}.wrong-provider.stderr.log"; then
  echo "FAIL: printf callback unwind probe accepted the wrong provider (status=${unwind_neg_status})" >&2
  exit 1
fi
for mode in strict hardened; do
  actual_stdout="${OUT_DIR}/${scenario}.${mode}.stdout.log"
  actual_stderr="${OUT_DIR}/${scenario}.${mode}.stderr.log"
  start_ns="$(date +%s%N)"
  FRANKENLIBC_MODE="${mode}" FRANKENLIBC_TEST_LIBRARY="${LIB}" LD_PRELOAD="${LIB}" \
    "${BIN_DIR}/fixture_callback_unwind.bin" --printf-all >"${actual_stdout}" 2>"${actual_stderr}"
  latency_ns="$(( $(date +%s%N) - start_ns ))"
  if ! cmp -s "${oracle_stdout}" "${actual_stdout}" || ! cmp -s "${oracle_stderr}" "${actual_stderr}"; then
    echo "FAIL: ${scenario} (${mode}) differs from live GNU oracle; see ${OUT_DIR}" >&2
    exit 1
  fi
  echo "${scenario} (${mode}): 142 callback-unwind cases passed" >>"${TEST_LOG}"
  emit_log_row "${scenario}" "${mode}" "stdio" "pass" "${latency_ns}" "${COMMON_REFS}"
done

if [[ "${GNU_ONLY}" -eq 1 ]]; then
  cat >"${REPORT}" <<JSON
{"schema_version":"v1","scope":"gnu-printf","bead":"bd-rc0923-epic-eeuy4f.34","run_id":"${RUN_ID}","library":"${LIB}","library_sha256":"${LIB_SHA256}","build_kind":"${BUILD_KIND}","preserve_scratch_files":${PRESERVE_SCRATCH_FILES},"original_printf_cases_per_mode":11,"ordinary_wide_boundary_cases_per_mode":408,"wide_locale_cases_per_mode":400,"precision_input_span_cases_per_mode":256,"wide_registration_boundary_cases_per_mode":80,"registration_limit_cases_per_mode":12,"registration_concurrent_threads_per_mode":6,"callback_unwind_printf_cases_per_mode":142,"callback_unwind_printf_provider_negative":"pass","wide_registration_boundary_provider_negative":"pass","gnu_live_differential_strict":"pass","gnu_live_differential_hardened":"pass","combined_fallback_return_count":"diagnostic_only"}
JSON
  echo "check_stdio_native --gnu-printf: PASS (GNU callbacks/introspection/limits/concurrency/unwind and 11 original printf cases per mode; full stdio gate not run)"
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
  "preserve_scratch_files": ${PRESERVE_SCRATCH_FILES},
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
