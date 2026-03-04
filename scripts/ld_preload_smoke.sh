#!/usr/bin/env bash
# LD_PRELOAD smoke harness for real binaries under strict + hardened modes.
#
# Runs a curated set of commands and captures deterministic diagnostics for
# any non-zero/timeout outcome.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/ld_preload_smoke"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
BIN_DIR="${RUN_DIR}/bin"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"
STRESS_ITERS="${STRESS_ITERS:-5}"
ENFORCE_PARITY_MODES="${ENFORCE_PARITY_MODES:-strict}"
ENFORCE_PERF_MODES="${ENFORCE_PERF_MODES:-strict}"
PERF_RATIO_MAX_PPM="${PERF_RATIO_MAX_PPM:-2000000}"
VALGRIND_POLICY="${VALGRIND_POLICY:-auto}" # auto|off|required
TRACE_FILE="${RUN_DIR}/trace.jsonl"
CASE_TSV="${RUN_DIR}/abi_compat_cases.tsv"
REPORT_FILE="${RUN_DIR}/abi_compat_report.json"
TROUBLESHOOT_FILE="${RUN_DIR}/startup_troubleshooting.md"
BEAD_ID="${BEAD_ID:-bd-1ah8}"
FAILURE_SIGNATURE_DENYLIST="${FAILURE_SIGNATURE_DENYLIST:-startup_timeout,startup_segv,startup_abort,startup_symbol_lookup_error,startup_loader_missing_library,startup_glibc_version_mismatch,startup_elf_class_mismatch}"

LIB_CANDIDATES=(
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

mkdir -p "${RUN_DIR}" "${BIN_DIR}"
: > "${TRACE_FILE}"
printf 'mode\tlabel\tstatus\tworkload\tstartup_path\tfailure_signature\tsignature_guard_triggered\tparity_required\tparity_pass\tperf_required\tperf_pass\tlatency_ratio_ppm\tbaseline_rc\tpreload_rc\tstdout_match\tstderr_match\tbaseline_latency_ns\tpreload_latency_ns\tvalgrind_checked\tvalgrind_pass\n' > "${CASE_TSV}"

if [[ -z "${LIB_PATH}" ]]; then
  echo "ld_preload_smoke: building frankenlibc-abi release artifact..."
  if ! command -v rch >/dev/null 2>&1; then
    echo "ld_preload_smoke: rch is required for cargo build offload but was not found in PATH" >&2
    exit 2
  fi
  rch exec -- cargo build -p frankenlibc-abi --release
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "ld_preload_smoke: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "ld_preload_smoke: required compiler 'cc' not found" >&2
  exit 2
fi

INTEGRATION_BIN="${BIN_DIR}/link_test"
cc -O2 "${ROOT}/tests/integration/link_test.c" -o "${INTEGRATION_BIN}"

NONTRIVIAL_BIN=""
NONTRIVIAL_DESC=""
if command -v python3 >/dev/null 2>&1; then
  NONTRIVIAL_BIN="python3"
  NONTRIVIAL_DESC="python3 -c 'print(1)'"
elif command -v busybox >/dev/null 2>&1; then
  NONTRIVIAL_BIN="busybox"
  NONTRIVIAL_DESC="busybox uname -a"
else
  echo "ld_preload_smoke: requires python3 or busybox for non-trivial dynamic binary check" >&2
  exit 2
fi

passes=0
fails=0
skips=0

csv_has_token() {
  local needle="$1"
  local csv="$2"
  local raw
  IFS=',' read -r -a raw <<< "${csv}"
  for token in "${raw[@]}"; do
    token="${token//[[:space:]]/}"
    if [[ -n "${token}" && "${token}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

mode_requires_parity() {
  local mode="$1"
  local csv="$2"
  csv_has_token "${mode}" "${csv}"
}

case_workload() {
  local label="$1"
  case "${label}" in
    integration_*|stress_link_*)
      echo "integration"
      ;;
    stress_*)
      echo "stress"
      ;;
    *)
      echo "smoke"
      ;;
  esac
}

case_startup_path() {
  local label="$1"
  case "${label}" in
    integration_*|stress_link_*)
      echo "integration_c_fixture_startup"
      ;;
    python3_*|stress_python_*)
      echo "python_runtime_startup"
      ;;
    busybox_*|sqlite_*|redis_*|nginx_*)
      echo "dynamic_binary_startup"
      ;;
    *)
      echo "coreutils_dynamic_startup"
      ;;
  esac
}

classify_failure_signature() {
  local preload_rc="$1"
  local preload_stderr="$2"
  local parity_required="$3"
  local parity_pass="$4"
  local perf_required="$5"
  local perf_pass="$6"
  local valgrind_checked="$7"
  local valgrind_pass="$8"

  if [[ "${preload_rc}" -eq 124 || "${preload_rc}" -eq 125 ]]; then
    echo "startup_timeout"
    return 0
  fi

  if [[ "${preload_rc}" -ge 128 ]]; then
    local signal_num=$((preload_rc - 128))
    case "${signal_num}" in
      11)
        echo "startup_segv"
        ;;
      6)
        echo "startup_abort"
        ;;
      4)
        echo "startup_illegal_instruction"
        ;;
      7)
        echo "startup_bus_error"
        ;;
      *)
        echo "startup_signal_${signal_num}"
        ;;
    esac
    return 0
  fi

  if [[ "${preload_rc}" -ne 0 ]]; then
    if grep -qi 'symbol lookup error' "${preload_stderr}" 2>/dev/null; then
      echo "startup_symbol_lookup_error"
    elif grep -qi 'cannot open shared object file' "${preload_stderr}" 2>/dev/null; then
      echo "startup_loader_missing_library"
    elif grep -Eqi 'version .*GLIBC_.* not found' "${preload_stderr}" 2>/dev/null; then
      echo "startup_glibc_version_mismatch"
    elif grep -Eqi 'wrong ELF class|ELFCLASS' "${preload_stderr}" 2>/dev/null; then
      echo "startup_elf_class_mismatch"
    elif grep -qi 'undefined symbol' "${preload_stderr}" 2>/dev/null; then
      echo "startup_undefined_symbol"
    else
      echo "startup_exit_nonzero_rc${preload_rc}"
    fi
    return 0
  fi

  if [[ "${parity_required}" -eq 1 && "${parity_pass}" -ne 1 ]]; then
    echo "startup_strict_parity_mismatch"
    return 0
  fi

  if [[ "${perf_required}" -eq 1 && "${perf_pass}" -ne 1 ]]; then
    echo "startup_perf_regression"
    return 0
  fi

  if [[ "${valgrind_checked}" -eq 1 && "${valgrind_pass}" -ne 1 ]]; then
    echo "startup_valgrind_error"
    return 0
  fi

  echo "none"
}

signature_is_guarded() {
  local failure_signature="$1"
  if [[ "${failure_signature}" == "none" ]]; then
    return 1
  fi
  csv_has_token "${failure_signature}" "${FAILURE_SIGNATURE_DENYLIST}"
}

emit_trace() {
  local level="$1"
  local event="$2"
  local mode="$3"
  local label="$4"
  local status="$5"
  local decision_path="${6:-orchestration}"
  local healing_action="${7:-None}"
  local errno_value="${8:-0}"
  local latency_ns="${9:-0}"
  local artifact_refs_json="${10:-[]}"
  local workload="${11:-suite}"
  local startup_path="${12:-orchestration}"
  local failure_signature="${13:-none}"
  local timing_total_ns="${14:-0}"
  local signature_guard_value="${15:-0}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local trace_id="${BEAD_ID}::${RUN_ID}::${mode}::${label}"
  printf '{"timestamp":"%s","trace_id":"%s","level":"%s","event":"%s","bead_id":"%s","run_id":"%s","mode":"%s","case":"%s","status":"%s","api_family":"abi-interposition","symbol":"%s","decision_path":"%s","healing_action":"%s","errno":%s,"latency_ns":%s,"artifact_refs":%s,"workload":"%s","startup_path":"%s","failure_signature":"%s","timing":{"total_ns":%s},"signature_guard_triggered":%s}\n' \
    "${ts}" \
    "${trace_id}" \
    "${level}" \
    "${event}" \
    "${BEAD_ID}" \
    "${RUN_ID}" \
    "${mode}" \
    "${label}" \
    "${status}" \
    "${label}" \
    "${decision_path}" \
    "${healing_action}" \
    "${errno_value}" \
    "${latency_ns}" \
    "${artifact_refs_json}" \
    "${workload}" \
    "${startup_path}" \
    "${failure_signature}" \
    "${timing_total_ns}" \
    "${signature_guard_value}" \
    >> "${TRACE_FILE}"
}

append_case_row() {
  local mode="$1"
  local label="$2"
  local status="$3"
  local workload="$4"
  local startup_path="$5"
  local failure_signature="$6"
  local signature_guard_triggered="$7"
  local parity_required="$8"
  local parity_pass="$9"
  local perf_required="${10}"
  local perf_pass="${11}"
  local latency_ratio_ppm="${12}"
  local baseline_rc="${13}"
  local preload_rc="${14}"
  local stdout_match="${15}"
  local stderr_match="${16}"
  local baseline_latency_ns="${17}"
  local preload_latency_ns="${18}"
  local valgrind_checked="${19}"
  local valgrind_pass="${20}"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${mode}" \
    "${label}" \
    "${status}" \
    "${workload}" \
    "${startup_path}" \
    "${failure_signature}" \
    "${signature_guard_triggered}" \
    "${parity_required}" \
    "${parity_pass}" \
    "${perf_required}" \
    "${perf_pass}" \
    "${latency_ratio_ppm}" \
    "${baseline_rc}" \
    "${preload_rc}" \
    "${stdout_match}" \
    "${stderr_match}" \
    "${baseline_latency_ns}" \
    "${preload_latency_ns}" \
    "${valgrind_checked}" \
    "${valgrind_pass}" \
    >> "${CASE_TSV}"
}

record_failure_bundle() {
  local case_dir="$1"
  local mode="$2"
  local label="$3"
  local rc="$4"
  local failure_signature="$5"
  local workload="$6"
  local startup_path="$7"
  local signature_guard_triggered="$8"

  {
    echo "mode=${mode}"
    echo "case=${label}"
    echo "exit_code=${rc}"
    echo "failure_signature=${failure_signature}"
    echo "workload=${workload}"
    echo "startup_path=${startup_path}"
    echo "signature_guard_triggered=${signature_guard_triggered}"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "lib_path=${LIB_PATH}"
    echo "timeout_seconds=${TIMEOUT_SECONDS}"
    echo "kernel=$(uname -a)"
  } > "${case_dir}/bundle.meta"

  env | sort > "${case_dir}/env.txt"
  cat /proc/self/maps > "${case_dir}/proc_self_maps.txt" || true
}

run_case() {
  local mode="$1"
  local label="$2"
  shift 2
  local case_dir="${RUN_DIR}/${mode}/${label}"
  local workload
  workload="$(case_workload "${label}")"
  local startup_path
  startup_path="$(case_startup_path "${label}")"
  mkdir -p "${case_dir}"

  printf '%q ' "$@" > "${case_dir}/command.shline"
  echo "" >> "${case_dir}/command.shline"

  local baseline_stdout="${case_dir}/baseline.stdout.txt"
  local baseline_stderr="${case_dir}/baseline.stderr.txt"
  local preload_stdout="${case_dir}/stdout.txt"
  local preload_stderr="${case_dir}/stderr.txt"
  local valgrind_stdout="${case_dir}/valgrind.stdout.txt"
  local valgrind_stderr="${case_dir}/valgrind.stderr.txt"

  local baseline_start_ns
  baseline_start_ns="$(date +%s%N)"
  set +e
  timeout "${TIMEOUT_SECONDS}" "$@" > "${baseline_stdout}" 2> "${baseline_stderr}"
  local baseline_rc=$?
  set -e
  local baseline_end_ns
  baseline_end_ns="$(date +%s%N)"
  local baseline_latency_ns=$((baseline_end_ns - baseline_start_ns))

  local preload_start_ns
  preload_start_ns="$(date +%s%N)"
  set +e
  timeout "${TIMEOUT_SECONDS}" \
    env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "$@" \
    > "${preload_stdout}" 2> "${preload_stderr}"
  local preload_rc=$?
  set -e
  local preload_end_ns
  preload_end_ns="$(date +%s%N)"
  local preload_latency_ns=$((preload_end_ns - preload_start_ns))

  printf '%s\n' "${baseline_rc}" > "${case_dir}/baseline.exit_code"
  printf '%s\n' "${preload_rc}" > "${case_dir}/preload.exit_code"
  printf '%s\n' "${baseline_latency_ns}" > "${case_dir}/baseline.latency_ns"
  printf '%s\n' "${preload_latency_ns}" > "${case_dir}/preload.latency_ns"

  local stdout_match=1
  local stderr_match=1
  local compare_baseline_stdout="${baseline_stdout}"
  local compare_preload_stdout="${preload_stdout}"
  if [[ "${label}" == "coreutils_env" ]]; then
    local baseline_stdout_normalized="${case_dir}/baseline.stdout.normalized.txt"
    local preload_stdout_normalized="${case_dir}/stdout.normalized.txt"
    grep -Ev '^(FRANKENLIBC_MODE|LD_PRELOAD)=' "${baseline_stdout}" > "${baseline_stdout_normalized}" || true
    grep -Ev '^(FRANKENLIBC_MODE|LD_PRELOAD)=' "${preload_stdout}" > "${preload_stdout_normalized}" || true
    compare_baseline_stdout="${baseline_stdout_normalized}"
    compare_preload_stdout="${preload_stdout_normalized}"
  fi
  cmp -s "${compare_baseline_stdout}" "${compare_preload_stdout}" || stdout_match=0
  cmp -s "${baseline_stderr}" "${preload_stderr}" || stderr_match=0

  local parity_required=0
  if mode_requires_parity "${mode}" "${ENFORCE_PARITY_MODES}"; then
    parity_required=1
  fi

  local perf_required=0
  if mode_requires_parity "${mode}" "${ENFORCE_PERF_MODES}"; then
    perf_required=1
  fi

  local latency_ratio_ppm=0
  if [[ "${baseline_latency_ns}" -gt 0 ]]; then
    latency_ratio_ppm=$((preload_latency_ns * 1000000 / baseline_latency_ns))
  fi

  local parity_pass=1
  if [[ "${baseline_rc}" -ne "${preload_rc}" || "${stdout_match}" -ne 1 || "${stderr_match}" -ne 1 ]]; then
    parity_pass=0
  fi

  local perf_pass=1
  if [[ "${perf_required}" -eq 1 && "${latency_ratio_ppm}" -gt "${PERF_RATIO_MAX_PPM}" ]]; then
    perf_pass=0
  fi

  local valgrind_checked=0
  local valgrind_pass=1
  local valgrind_rc=0
  if [[ "${mode}" == "strict" && "${label}" != stress_* ]]; then
    case "${VALGRIND_POLICY}" in
      off)
        ;;
      auto|required)
        if command -v valgrind >/dev/null 2>&1; then
          valgrind_checked=1
          set +e
          timeout "${TIMEOUT_SECONDS}" \
            env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" \
            valgrind --error-exitcode=101 --leak-check=full --track-origins=no --quiet "$@" \
            > "${valgrind_stdout}" 2> "${valgrind_stderr}"
          valgrind_rc=$?
          set -e
          if [[ "${valgrind_rc}" -ne 0 ]]; then
            valgrind_pass=0
          fi
        elif [[ "${VALGRIND_POLICY}" == "required" ]]; then
          echo "ld_preload_smoke: VALGRIND_POLICY=required but valgrind is not installed" >&2
          exit 2
        fi
        ;;
      *)
        echo "ld_preload_smoke: invalid VALGRIND_POLICY='${VALGRIND_POLICY}' (expected auto|off|required)" >&2
        exit 2
        ;;
    esac
  fi

  local status="pass"
  if [[ "${preload_rc}" -ne 0 ]]; then
    status="fail"
  elif [[ "${parity_required}" -eq 1 && "${parity_pass}" -ne 1 ]]; then
    status="fail"
  elif [[ "${perf_required}" -eq 1 && "${perf_pass}" -ne 1 ]]; then
    status="fail"
  elif [[ "${valgrind_checked}" -eq 1 && "${valgrind_pass}" -ne 1 ]]; then
    status="fail"
  fi

  local failure_signature
  failure_signature="$(classify_failure_signature \
    "${preload_rc}" \
    "${preload_stderr}" \
    "${parity_required}" \
    "${parity_pass}" \
    "${perf_required}" \
    "${perf_pass}" \
    "${valgrind_checked}" \
    "${valgrind_pass}")"

  local signature_guard_triggered=0
  if signature_is_guarded "${failure_signature}"; then
    signature_guard_triggered=1
    status="fail"
  fi

  local decision_path="baseline_vs_preload"
  if [[ "${preload_rc}" -ne 0 ]]; then
    decision_path="preload_exit_nonzero"
  elif [[ "${parity_required}" -eq 1 && "${parity_pass}" -ne 1 ]]; then
    decision_path="strict_parity_mismatch"
  elif [[ "${perf_required}" -eq 1 && "${perf_pass}" -ne 1 ]]; then
    decision_path="perf_ratio_exceeded"
  elif [[ "${valgrind_checked}" -eq 1 && "${valgrind_pass}" -ne 1 ]]; then
    decision_path="valgrind_error"
  fi
  if [[ "${signature_guard_triggered}" -eq 1 ]]; then
    decision_path="failure_signature_guard"
  fi

  local errno_value=0
  if [[ "${preload_rc}" -ne 0 ]]; then
    errno_value="${preload_rc}"
  fi

  local artifact_refs_json
  artifact_refs_json=$(printf '["%s/%s/baseline.stdout.txt","%s/%s/baseline.stderr.txt","%s/%s/stdout.txt","%s/%s/stderr.txt","%s/%s/command.shline"%s]' \
    "${mode}" "${label}" \
    "${mode}" "${label}" \
    "${mode}" "${label}" \
    "${mode}" "${label}" \
    "${mode}" "${label}" \
    "$([[ "${valgrind_checked}" -eq 1 ]] && printf ',"%s/%s/valgrind.stdout.txt","%s/%s/valgrind.stderr.txt"' "${mode}" "${label}" "${mode}" "${label}")")

  if [[ "${status}" == "pass" ]]; then
    passes=$((passes + 1))
    append_case_row \
      "${mode}" "${label}" "${status}" "${workload}" "${startup_path}" "${failure_signature}" "${signature_guard_triggered}" "${parity_required}" "${parity_pass}" \
      "${perf_required}" "${perf_pass}" "${latency_ratio_ppm}" \
      "${baseline_rc}" "${preload_rc}" "${stdout_match}" "${stderr_match}" \
      "${baseline_latency_ns}" "${preload_latency_ns}" "${valgrind_checked}" "${valgrind_pass}"
    emit_trace "info" "case_pass" "${mode}" "${label}" "${status}" "${decision_path}" "None" "${errno_value}" "${preload_latency_ns}" "${artifact_refs_json}" "${workload}" "${startup_path}" "${failure_signature}" "${preload_latency_ns}" "${signature_guard_triggered}"
    echo "[PASS] mode=${mode} case=${label}"
    return 0
  fi

  fails=$((fails + 1))
  append_case_row \
    "${mode}" "${label}" "${status}" "${workload}" "${startup_path}" "${failure_signature}" "${signature_guard_triggered}" "${parity_required}" "${parity_pass}" \
    "${perf_required}" "${perf_pass}" "${latency_ratio_ppm}" \
    "${baseline_rc}" "${preload_rc}" "${stdout_match}" "${stderr_match}" \
    "${baseline_latency_ns}" "${preload_latency_ns}" "${valgrind_checked}" "${valgrind_pass}"
  emit_trace "error" "case_fail" "${mode}" "${label}" "${status}" "${decision_path}" "None" "${errno_value}" "${preload_latency_ns}" "${artifact_refs_json}" "${workload}" "${startup_path}" "${failure_signature}" "${preload_latency_ns}" "${signature_guard_triggered}"
  if [[ "${signature_guard_triggered}" -eq 1 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (guarded failure signature: ${failure_signature})"
  elif [[ "${preload_rc}" -eq 124 || "${preload_rc}" -eq 125 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (timeout ${TIMEOUT_SECONDS}s)"
  elif [[ "${parity_required}" -eq 1 && "${parity_pass}" -ne 1 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (strict parity mismatch)"
  elif [[ "${perf_required}" -eq 1 && "${perf_pass}" -ne 1 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (perf ratio ${latency_ratio_ppm}ppm > ${PERF_RATIO_MAX_PPM}ppm)"
  elif [[ "${valgrind_checked}" -eq 1 && "${valgrind_pass}" -ne 1 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (valgrind failure rc=${valgrind_rc})"
  else
    echo "[FAIL] mode=${mode} case=${label} (exit ${preload_rc})"
  fi
  record_failure_bundle "${case_dir}" "${mode}" "${label}" "${preload_rc}" "${failure_signature}" "${workload}" "${startup_path}" "${signature_guard_triggered}"
  return 1
}

run_optional_case() {
  local required_binary="$1"
  local mode="$2"
  local label="$3"
  shift 3

  if ! command -v "${required_binary}" >/dev/null 2>&1; then
    local workload
    workload="$(case_workload "${label}")"
    local startup_path
    startup_path="$(case_startup_path "${label}")"
    skips=$((skips + 1))
    append_case_row \
      "${mode}" "${label}" "skip" "${workload}" "${startup_path}" "none" "0" "0" "1" "0" "1" "0" \
      "-1" "-1" "1" "1" \
      "0" "0" "0" "1"
    emit_trace "warn" "case_skip_optional_binary_missing" "${mode}" "${label}" "skip" \
      "optional_binary_missing" "None" "0" "0" "[]" \
      "${workload}" "${startup_path}" "none" "0" "0"
    echo "[SKIP] mode=${mode} case=${label} (missing optional binary: ${required_binary})"
    return 0
  fi

  run_case "${mode}" "${label}" "$@"
}

run_suite_for_mode() {
  local mode="$1"
  local mode_failed=0
  local fixture="${RUN_DIR}/fixture.input.txt"
  cat > "${fixture}" <<'EOF'
charlie
alpha
bravo
alpha
EOF

  run_case "${mode}" "coreutils_ls_tmp" /bin/ls -la /tmp || mode_failed=1
  run_case "${mode}" "coreutils_cat_hosts" /bin/cat /etc/hosts || mode_failed=1
  run_case "${mode}" "coreutils_echo" /bin/echo "frankenlibc_smoke" || mode_failed=1
  run_case "${mode}" "coreutils_env" /usr/bin/env || mode_failed=1
  run_case "${mode}" "integration_link_test" "${INTEGRATION_BIN}" || mode_failed=1
  run_case "${mode}" "coreutils_sort_fixture" /usr/bin/env LC_ALL=C /bin/sort "${fixture}" || mode_failed=1
  run_case "${mode}" "coreutils_wc_fixture" /usr/bin/env LC_ALL=C /usr/bin/wc -l "${fixture}" || mode_failed=1

  if [[ "${NONTRIVIAL_BIN}" == "python3" ]]; then
    run_case "${mode}" "python3_print" python3 -c "print(1)" || mode_failed=1
  else
    run_case "${mode}" "busybox_uname" busybox uname -a || mode_failed=1
  fi

  run_optional_case "busybox" "${mode}" "busybox_help" busybox --help || mode_failed=1
  run_optional_case "sqlite3" "${mode}" "sqlite_memory_select" sqlite3 :memory: "select 41 + 1;" || mode_failed=1
  run_optional_case "redis-cli" "${mode}" "redis_cli_version" redis-cli --version || mode_failed=1
  run_optional_case "nginx" "${mode}" "nginx_version" nginx -v || mode_failed=1

  for i in $(seq 1 "${STRESS_ITERS}"); do
    run_case "${mode}" "stress_link_${i}" "${INTEGRATION_BIN}" || mode_failed=1
    run_case "${mode}" "stress_echo_${i}" /bin/echo "iteration_${i}" || mode_failed=1
    run_case "${mode}" "stress_sort_${i}" /usr/bin/env LC_ALL=C /bin/sort "${fixture}" || mode_failed=1
    if command -v python3 >/dev/null 2>&1; then
      run_case "${mode}" "stress_python_${i}" python3 -c "print(sum(range(100)))" || mode_failed=1
    fi
  done

  return "${mode_failed}"
}

echo "=== LD_PRELOAD smoke ==="
echo "run_dir=${RUN_DIR}"
echo "lib=${LIB_PATH}"
echo "nontrivial=${NONTRIVIAL_DESC}"
echo "timeout_seconds=${TIMEOUT_SECONDS}"
echo "stress_iters=${STRESS_ITERS}"
echo "enforce_parity_modes=${ENFORCE_PARITY_MODES}"
echo "enforce_perf_modes=${ENFORCE_PERF_MODES}"
echo "perf_ratio_max_ppm=${PERF_RATIO_MAX_PPM}"
echo "valgrind_policy=${VALGRIND_POLICY}"

emit_trace "info" "suite_start" "all" "all" "running" \
  "orchestration" "None" "0" "0" "[]" "suite" "orchestration" "none" "0" "0"
overall_failed=0
run_suite_for_mode strict || overall_failed=1
run_suite_for_mode hardened || overall_failed=1
emit_trace "info" "suite_end" "all" "all" "$([[ "${overall_failed}" -eq 0 ]] && echo "pass" || echo "fail")" \
  "orchestration" "None" "0" "0" "[]" "suite" "orchestration" "none" "0" "0"

python3 - <<PY
import csv
import json
from collections import Counter
from pathlib import Path

cases = []
with open("${CASE_TSV}", "r", encoding="utf-8") as fh:
    reader = csv.DictReader(fh, delimiter="\\t")
    for row in reader:
        cases.append(
            {
                "mode": row["mode"],
                "case": row["label"],
                "status": row["status"],
                "workload": row["workload"],
                "startup_path": row["startup_path"],
                "failure_signature": row["failure_signature"],
                "signature_guard_triggered": bool(int(row["signature_guard_triggered"])),
                "parity_required": bool(int(row["parity_required"])),
                "parity_pass": bool(int(row["parity_pass"])),
                "perf_required": bool(int(row["perf_required"])),
                "perf_pass": bool(int(row["perf_pass"])),
                "latency_ratio_ppm": int(row["latency_ratio_ppm"]),
                "baseline_rc": int(row["baseline_rc"]),
                "preload_rc": int(row["preload_rc"]),
                "stdout_match": bool(int(row["stdout_match"])),
                "stderr_match": bool(int(row["stderr_match"])),
                "baseline_latency_ns": int(row["baseline_latency_ns"]),
                "preload_latency_ns": int(row["preload_latency_ns"]),
                "valgrind_checked": bool(int(row["valgrind_checked"])),
                "valgrind_pass": bool(int(row["valgrind_pass"])),
            }
        )

modes = {}
for mode in ("strict", "hardened"):
    mode_cases = [c for c in cases if c["mode"] == mode]
    mode_signature_counts = Counter(
        c["failure_signature"] for c in mode_cases if c["failure_signature"] != "none"
    )
    modes[mode] = {
        "total_cases": len(mode_cases),
        "passes": sum(1 for c in mode_cases if c["status"] == "pass"),
        "fails": sum(1 for c in mode_cases if c["status"] == "fail"),
        "skips": sum(1 for c in mode_cases if c["status"] == "skip"),
        "signature_guard_failures": sum(1 for c in mode_cases if c["signature_guard_triggered"]),
        "strict_parity_failures": sum(
            1
            for c in mode_cases
            if c["parity_required"] and not c["parity_pass"]
        ),
        "perf_failures": sum(
            1
            for c in mode_cases
            if c["perf_required"] and not c["perf_pass"]
        ),
        "valgrind_failures": sum(
            1
            for c in mode_cases
            if c["valgrind_checked"] and not c["valgrind_pass"]
        ),
        "failure_signature_counts": dict(mode_signature_counts),
    }

failure_signature_counts = Counter(
    c["failure_signature"] for c in cases if c["failure_signature"] != "none"
)

payload = {
    "schema_version": "v1",
    "bead_id": "${BEAD_ID}",
    "run_id": "${RUN_ID}",
    "lib_path": "${LIB_PATH}",
    "timeout_seconds": int("${TIMEOUT_SECONDS}"),
    "stress_iters": int("${STRESS_ITERS}"),
    "enforce_parity_modes": [m.strip() for m in "${ENFORCE_PARITY_MODES}".split(",") if m.strip()],
    "enforce_perf_modes": [m.strip() for m in "${ENFORCE_PERF_MODES}".split(",") if m.strip()],
    "perf_ratio_max_ppm": int("${PERF_RATIO_MAX_PPM}"),
    "valgrind_policy": "${VALGRIND_POLICY}",
    "summary": {
        "total_cases": len(cases),
        "passes": int("${passes}"),
        "fails": int("${fails}"),
        "skips": int("${skips}"),
        "signature_guard_failures": sum(1 for c in cases if c["signature_guard_triggered"]),
        "perf_failures": sum(1 for c in cases if c["perf_required"] and not c["perf_pass"]),
        "valgrind_failures": sum(1 for c in cases if c["valgrind_checked"] and not c["valgrind_pass"]),
        "failure_signature_counts": dict(failure_signature_counts),
        "overall_failed": bool(int("${overall_failed}")),
    },
    "modes": modes,
    "cases": cases,
}

Path("${REPORT_FILE}").write_text(json.dumps(payload, indent=2) + "\\n", encoding="utf-8")

denylist = {
    token.strip()
    for token in "${FAILURE_SIGNATURE_DENYLIST}".split(",")
    if token.strip()
}
guidance = {
    "startup_timeout": "Check loader deadlock or unresolved startup path; inspect stderr and command.shline, then rerun the single case with TIMEOUT_SECONDS increased for detail.",
    "startup_segv": "Collect bundle.meta + proc_self_maps.txt, then inspect the failing binary and the interposed symbol path around first faulting call.",
    "startup_abort": "Inspect stderr for panic/assert text and correlate with trace decision_path; this is usually a deterministic contract violation.",
    "startup_symbol_lookup_error": "Verify exported symbols/version script coverage and check stderr for the missing symbol name.",
    "startup_loader_missing_library": "Verify library search path (LD_LIBRARY_PATH/DT_RPATH) and ensure runtime dependencies are present.",
    "startup_glibc_version_mismatch": "Check host glibc symbol version requirements and confirm compatibility with the produced ABI artifact.",
    "startup_elf_class_mismatch": "Validate architecture/bitness alignment between test binary and preload library.",
    "startup_undefined_symbol": "Inspect stderr + symbol tables (nm/readelf) for unresolved symbol ownership.",
    "startup_strict_parity_mismatch": "Inspect baseline/preload stdout+stderr diffs; strict mode must preserve externally visible behavior.",
    "startup_perf_regression": "Inspect latency_ratio_ppm in report and compare against PERF_RATIO_MAX_PPM budget.",
    "startup_valgrind_error": "Open valgrind.stderr.txt and fix reported invalid memory actions before re-running.",
}

failing_cases = [c for c in cases if c["status"] == "fail"]
lines = []
lines.append(f"# Startup Troubleshooting ({'FAIL' if failing_cases else 'PASS'})")
lines.append("")
lines.append(f"- bead_id: ${BEAD_ID}")
lines.append(f"- run_id: ${RUN_ID}")
lines.append(f"- report_json: {Path('${REPORT_FILE}').name}")
lines.append(f"- trace_jsonl: {Path('${TRACE_FILE}').name}")
lines.append(f"- case_tsv: {Path('${CASE_TSV}').name}")
lines.append("")

if not failing_cases:
    lines.append("No startup failures detected in this run.")
else:
    lines.append("## Failure Signature Summary")
    lines.append("")
    for signature, count in sorted(
        failure_signature_counts.items(), key=lambda item: (-item[1], item[0])
    ):
        guarded = "yes" if signature in denylist else "no"
        lines.append(f"- {signature}: {count} case(s), guarded={guarded}")
    lines.append("")
    lines.append("## Guided Triage")
    lines.append("")
    for signature, count in sorted(
        failure_signature_counts.items(), key=lambda item: (-item[1], item[0])
    ):
        affected = [c for c in failing_cases if c["failure_signature"] == signature]
        lines.append(f"### {signature} ({count} case(s))")
        lines.append(
            guidance.get(
                signature,
                "Inspect stderr.txt + bundle.meta + trace.jsonl for the specific case and classify root cause.",
            )
        )
        lines.append("Affected cases:")
        for case in affected[:8]:
            lines.append(
                f"- {case['mode']}/{case['case']} workload={case['workload']} startup_path={case['startup_path']}"
            )
        if len(affected) > 8:
            lines.append(f"- ... and {len(affected) - 8} more case(s)")
        lines.append("")

Path("${TROUBLESHOOT_FILE}").write_text("\\n".join(lines).rstrip() + "\\n", encoding="utf-8")
PY

{
  echo "run_id=${RUN_ID}"
  echo "lib_path=${LIB_PATH}"
  echo "nontrivial=${NONTRIVIAL_DESC}"
  echo "timeout_seconds=${TIMEOUT_SECONDS}"
  echo "stress_iters=${STRESS_ITERS}"
  echo "enforce_parity_modes=${ENFORCE_PARITY_MODES}"
  echo "enforce_perf_modes=${ENFORCE_PERF_MODES}"
  echo "perf_ratio_max_ppm=${PERF_RATIO_MAX_PPM}"
  echo "valgrind_policy=${VALGRIND_POLICY}"
  echo "passes=${passes}"
  echo "fails=${fails}"
  echo "skips=${skips}"
  echo "overall_failed=${overall_failed}"
  echo "report_json=${REPORT_FILE}"
  echo "trace_jsonl=${TRACE_FILE}"
  echo "startup_troubleshooting=${TROUBLESHOOT_FILE}"
} > "${RUN_DIR}/summary.txt"

echo ""
echo "Summary: passes=${passes} fails=${fails} skips=${skips}"
echo "Artifacts: ${RUN_DIR}"
echo "Report: ${REPORT_FILE}"
echo "Startup troubleshooting: ${TROUBLESHOOT_FILE}"

if [[ "${overall_failed}" -ne 0 ]]; then
  echo "ld_preload_smoke: FAILED (see diagnostics bundles under ${RUN_DIR})" >&2
  exit 1
fi

echo "ld_preload_smoke: PASS"
